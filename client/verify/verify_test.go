// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"openwaymark.org/owm/client/verify"
	"openwaymark.org/owm/core"
	"openwaymark.org/owm/internal/testnode"
	"openwaymark.org/owm/trust"
)

// participant is a key the test node knows, mirroring node_test.go's own
// helper of the same name — this package deliberately builds its fixtures
// against a real node over real HTTP, not hand-typed JSON, so a wire-format
// change breaks this test before it breaks a user.
type participant struct {
	key *core.PrivateKey
}

func newParticipant(t *testing.T, n *testnode.Node, label string) *participant {
	t.Helper()
	k, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := n.Keys().Register(context.Background(), k.Public(), label, nil); err != nil {
		t.Fatalf("admit key: %v", err)
	}
	return &participant{key: k}
}

func (p *participant) submit(t *testing.T, n *testnode.Node, typ core.EntryType, subject core.SubjectID, payload string, target *core.EntryRef) core.Digest {
	t.Helper()
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     typ,
		Subject:  subject,
		Issuer:   p.key.Public().ID(),
		IssuedAt: 1_700_000_000_000,
		Target:   target,
	}
	var salt core.Salt
	body := []byte(payload)
	if !e.Type.RefersToEntry() {
		var err error
		salt, err = core.NewSalt()
		if err != nil {
			t.Fatalf("salt: %v", err)
		}
		e.Commitment = core.Commit(salt, body)
	} else {
		body = nil
	}
	se, err := core.SignEntry(p.key, e)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	leaf, err := n.Submit(context.Background(), se, salt, body)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return leaf.EntryID()
}

func subjectFromKey(id core.KeyID) core.SubjectID { return core.SubjectID(id) }

func randomSubject(t *testing.T) core.SubjectID {
	t.Helper()
	var s core.SubjectID
	if _, err := cryptorand.Read(s[:]); err != nil {
		t.Fatalf("random subject: %v", err)
	}
	return s
}

func TestVerifySubject_ValidChain(t *testing.T) {
	n := testnode.New(t)
	farmer := newParticipant(t, n, "farmer")
	shop := newParticipant(t, n, "shop")
	subject := randomSubject(t)

	farmer.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production"}`, nil)
	shop.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"handover"}`, nil)

	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	res, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, subject, verify.Options{})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected OK, got %+v", res)
	}
	if len(res.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(res.Entries))
	}
	for _, e := range res.Entries {
		if e.Status != verify.StatusOK {
			t.Errorf("entry %s: expected ok, got %s (%s)", e.EntryID, e.Status, e.Reason)
		}
	}
	if res.STH == nil {
		t.Fatal("expected a verified STH")
	}
}

func TestVerifySubject_ErasedPayload(t *testing.T) {
	n := testnode.New(t)
	farmer := newParticipant(t, n, "farmer")
	subject := randomSubject(t)
	entryID := farmer.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production"}`, nil)

	if _, err := n.Erase(context.Background(), entryID); err != nil {
		t.Fatalf("erase: %v", err)
	}
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	res, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, subject, verify.Options{})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	// Two entries, not one: erasure appends its own witness entry under the
	// same subject (the tombstone is part of that subject's own history,
	// not a side channel) — this is itself evidence the mechanism works,
	// not a test bug to work around.
	if len(res.Entries) != 2 {
		t.Fatalf("expected 2 entries (original + erasure witness), got %d", len(res.Entries))
	}
	var sawErased, sawWitness bool
	for _, e := range res.Entries {
		switch {
		case e.EntryID == entryID:
			sawErased = e.Status == verify.StatusErased
		case e.Type == core.EntryTypeErasure:
			sawWitness = e.Status == verify.StatusOK
		}
	}
	if !sawErased {
		t.Error("the original entry was not reported as erased")
	}
	if !sawWitness {
		t.Error("the erasure witness itself was not reported ok")
	}
	if !res.OK() {
		t.Fatalf("an erased entry must not count as a failure: %+v", res.Entries)
	}
}

// tamperingFetcher wraps a real Fetcher and corrupts one byte of whichever
// response body contains match, once. Used to prove this package's checks
// actually fail closed against a dishonest or corrupted response — not just
// pass on honest ones, which every one of these tests could do by accident
// if a check were silently skipped.
type tamperingFetcher struct {
	verify.Fetcher
	match string
	done  bool
}

func (f *tamperingFetcher) Fetch(ctx context.Context, u string) ([]byte, error) {
	b, err := f.Fetcher.Fetch(ctx, u)
	if err != nil || f.done || !strings.Contains(u, f.match) {
		return b, err
	}
	f.done = true
	out := append([]byte(nil), b...)
	// Flip a byte roughly in the middle of the body — deep enough inside a
	// base64 field to corrupt the decoded bytes, not just JSON punctuation.
	i := len(out) / 2
	out[i] ^= 0xFF
	return out, nil
}

func TestVerifySubject_TamperedPayload(t *testing.T) {
	n := testnode.New(t)
	farmer := newParticipant(t, n, "farmer")
	subject := randomSubject(t)
	farmer.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production","note":"a payload long enough to survive a flipped byte landing on JSON punctuation without becoming invalid JSON outright, which would just be a different kind of failure than the one this test wants to see"}`, nil)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	f := &tamperingFetcher{Fetcher: verify.HTTPFetcher{}, match: "/payload"}
	res, err := verify.VerifySubject(context.Background(), f, n.Server.URL, subject, verify.Options{})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	if res.OK() {
		t.Fatal("expected a failure, got OK")
	}
	if res.Entries[0].Status != verify.StatusFailed {
		t.Fatalf("expected failed, got %s", res.Entries[0].Status)
	}
}

// leafCorruptingFetcher wraps a real Fetcher and, for the one response that
// carries a subject's history, flips a byte inside the *decoded* leaf bytes
// of the first entry before re-encoding — a well-formed response with wrong
// content, distinct from a response broken at the encoding level. That
// distinction matters: a blind byte flip against the raw JSON far more often
// than not just breaks base64 decoding outright (a different, less
// interesting failure this package should also reject, but not the one this
// test is for) rather than surviving decoding and reaching signature
// verification, which is the path this test wants to exercise.
type leafCorruptingFetcher struct {
	verify.Fetcher
	done bool
}

func (f *leafCorruptingFetcher) Fetch(ctx context.Context, u string) ([]byte, error) {
	b, err := f.Fetcher.Fetch(ctx, u)
	if err != nil || f.done || !strings.Contains(u, "/subjects/") {
		return b, err
	}
	var whole map[string]json.RawMessage
	if json.Unmarshal(b, &whole) != nil {
		return b, err
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(whole["entries"], &entries) != nil || len(entries) == 0 {
		return b, err
	}
	var leaf []byte
	if json.Unmarshal(entries[0]["leaf"], &leaf) != nil || len(leaf) == 0 {
		return b, err
	}
	leaf[len(leaf)/2] ^= 0xFF
	patched, merr := json.Marshal(leaf)
	if merr != nil {
		return b, err
	}
	entries[0]["leaf"] = patched
	entriesJSON, merr := json.Marshal(entries)
	if merr != nil {
		return b, err
	}
	whole["entries"] = entriesJSON
	out, merr := json.Marshal(whole)
	if merr != nil {
		return b, err
	}
	f.done = true
	return out, nil
}

func TestVerifySubject_TamperedLeaf(t *testing.T) {
	n := testnode.New(t)
	farmer := newParticipant(t, n, "farmer")
	subject := randomSubject(t)
	farmer.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production"}`, nil)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	f := &leafCorruptingFetcher{Fetcher: verify.HTTPFetcher{}}
	res, err := verify.VerifySubject(context.Background(), f, n.Server.URL, subject, verify.Options{})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	if res.OK() {
		t.Fatal("expected a failure, got OK")
	}
	if res.Entries[0].Status != verify.StatusFailed {
		t.Fatalf("expected failed, got %s (%s)", res.Entries[0].Status, res.Entries[0].Reason)
	}
}

func TestVerifySubject_PreviousSTHSplitView(t *testing.T) {
	n := testnode.New(t)
	farmer := newParticipant(t, n, "farmer")
	subject := randomSubject(t)
	farmer.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production"}`, nil)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	first, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, subject, verify.Options{})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	forged := *first.STH
	forged.Root[0] ^= 0xFF // same size, different root: exactly A1's split-view shape

	second, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, subject,
		verify.Options{PreviousSTH: &forged})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	if len(second.Findings) == 0 {
		t.Fatal("expected a split-view finding")
	}
}

func TestVerifySubject_TrustLevel(t *testing.T) {
	n := testnode.New(t)
	root := newParticipant(t, n, "accreditation body")
	entity := newParticipant(t, n, "certified producer")
	entityKeyID := entity.key.Public().ID()

	root.submit(t, n, core.EntryTypeAttestation, subjectFromKey(entityKeyID),
		`{"kind":"entity","level":3,"scheme":"iso-17065"}`, nil)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	subject := randomSubject(t)
	entity.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production"}`, nil)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	roots := trust.RootSet{root.key.Public().ID(): trust.Root{ID: root.key.Public().ID(), Name: "root", MaxLevel: trust.LevelState}}
	res, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, subject,
		verify.Options{Roots: roots})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	got, ok := res.TrustLevel[entityKeyID]
	if !ok {
		t.Fatalf("no trust level recomputed for %s", entityKeyID)
	}
	if got != trust.Level(3) {
		t.Fatalf("expected level 3, got %s", got)
	}
}

func TestVerifySubject_RevokedAttestationExcluded(t *testing.T) {
	n := testnode.New(t)
	root := newParticipant(t, n, "accreditation body")
	entity := newParticipant(t, n, "producer")
	entityKeyID := entity.key.Public().ID()

	attID := root.submit(t, n, core.EntryTypeAttestation, subjectFromKey(entityKeyID),
		`{"kind":"entity","level":3,"scheme":"iso-17065"}`, nil)
	root.submit(t, n, core.EntryTypeRevocation, subjectFromKey(entityKeyID), "",
		&core.EntryRef{Entry: attID})
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	subject := randomSubject(t)
	entity.submit(t, n, core.EntryTypeAssertion, subject, `{"event":"production"}`, nil)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	roots := trust.RootSet{root.key.Public().ID(): trust.Root{ID: root.key.Public().ID(), Name: "root", MaxLevel: trust.LevelState}}
	res, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, subject,
		verify.Options{Roots: roots})
	if err != nil {
		t.Fatalf("VerifySubject: %v", err)
	}
	if got := res.TrustLevel[entityKeyID]; got != trust.LevelNone {
		t.Fatalf("expected LevelNone after revocation, got %s", got)
	}
}

func TestVerifySubject_UnknownSubjectIsNotAnError(t *testing.T) {
	n := testnode.New(t)
	// An STH over the empty tree is a valid, ordinary starting point
	// (log.STH's own doc comment) — this issues one so the node has
	// something to answer GET /owm/v1/sth with, isolating the case this
	// test is actually for: a subject with no history is not an error,
	// distinct from a node with no STH at all yet, which is (correctly) a
	// different, harder failure this test is not about.
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}
	res, err := verify.VerifySubject(context.Background(), verify.HTTPFetcher{}, n.Server.URL, randomSubject(t), verify.Options{})
	if err != nil {
		t.Fatalf("an unknown subject with no history is not itself an error: %v", err)
	}
	if len(res.Entries) != 0 {
		t.Fatalf("expected no entries, got %d", len(res.Entries))
	}
	if !res.OK() {
		t.Fatal("no entries and no findings must count as OK")
	}
}

func TestHexRoundTrip(t *testing.T) {
	// Guards the hexRand/randomSubject helper above against ever silently
	// producing an all-zero subject, which core.SubjectID.IsZero-adjacent
	// code elsewhere in the module treats as "forgotten field" — a helper
	// bug here would be a confusing false pass in every other test.
	s := randomSubject(t)
	if hex.EncodeToString(s[:]) == strings.Repeat("0", 64) {
		t.Fatal("randomSubject produced an all-zero subject")
	}
}
