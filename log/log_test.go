// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"openwaymark.org/owm/core"
)

// testEnv is a log with storage, payload store and a clock that advances by one
// millisecond on every call. Identical timestamps would render the ordering
// checks in CheckSTHPair meaningless.
type testEnv struct {
	t     *testing.T
	key   *core.PrivateKey
	st    *MemStorage
	blobs *MemBlobStore
	log   *Log
	clock int64
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return newTestEnvWithKey(t, key)
}

func newTestEnvWithKey(t *testing.T, key *core.PrivateKey) *testEnv {
	t.Helper()
	env := &testEnv{
		t:     t,
		key:   key,
		st:    NewMemStorage(),
		blobs: NewMemBlobStore(),
		clock: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC).UnixMilli(),
	}
	lg, err := New(Options{
		Storage: env.st,
		Signer:  key,
		Blobs:   env.blobs,
		Keys:    mapKeys{key.Public().ID(): key.Public()},
		Now:     env.now,
	})
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	env.log = lg
	return env
}

func (e *testEnv) now() time.Time {
	e.clock++
	return time.UnixMilli(e.clock).UTC()
}

// entry builds a signed assertion entry together with its salt.
func (e *testEnv) entry(subject core.SubjectID, payload []byte) (*core.SignedEntry, core.Salt) {
	e.t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		e.t.Fatalf("salt: %v", err)
	}
	ent := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   e.now().UnixMilli(),
		Issuer:     e.key.Public().ID(),
		Commitment: core.Commit(salt, payload),
	}
	se, err := core.SignEntry(e.key, ent)
	if err != nil {
		e.t.Fatalf("sign entry: %v", err)
	}
	return se, salt
}

// appendN appends n entries for varying subjects.
func (e *testEnv) appendN(ctx context.Context, n int) []*Leaf {
	e.t.Helper()
	out := make([]*Leaf, 0, n)
	for i := 0; i < n; i++ {
		subject, err := core.NewSubjectID()
		if err != nil {
			e.t.Fatalf("subject: %v", err)
		}
		se, salt := e.entry(subject, []byte(fmt.Sprintf("payload-%d", i)))
		leaf, err := e.log.AppendWithPayload(ctx, se, salt, []byte(fmt.Sprintf("payload-%d", i)))
		if err != nil {
			e.t.Fatalf("append %d: %v", i, err)
		}
		out = append(out, leaf)
	}
	return out
}

type mapKeys map[core.KeyID]*core.PublicKey

func (m mapKeys) PublicKey(_ context.Context, id core.KeyID) (*core.PublicKey, error) {
	pub, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("%w: key %s", ErrNotFound, id)
	}
	return pub, nil
}

func TestEmptyTreeRoot(t *testing.T) {
	env := newTestEnv(t)
	root, err := env.log.Root(context.Background())
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	// RFC 6962: the root of the empty tree is SHA-256 over the empty input.
	want := sha256.Sum256(nil)
	if root != core.Digest(want) {
		t.Errorf("empty root = %s, expected %s", root, core.Digest(want))
	}
}

func TestAppendAndInclusion(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	leaves := env.appendN(ctx, 17)

	signed, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if err := signed.Verify(env.key.Public()); err != nil {
		t.Fatalf("STH signature: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	if sth.Size != uint64(len(leaves)) {
		t.Fatalf("tree size = %d, expected %d", sth.Size, len(leaves))
	}
	if sth.Log != env.log.ID() {
		t.Errorf("STH names log %s, expected %s", sth.Log, env.log.ID())
	}

	for i, leaf := range leaves {
		if err := leaf.Verify(env.log.ID(), env.key.Public()); err != nil {
			t.Fatalf("verify leaf %d: %v", i, err)
		}
		hash, err := leaf.Hash()
		if err != nil {
			t.Fatalf("leaf hash %d: %v", i, err)
		}
		p, err := env.log.InclusionProof(ctx, uint64(i), sth.Size)
		if err != nil {
			t.Fatalf("inclusion proof %d: %v", i, err)
		}
		if err := p.Verify(hash, sth); err != nil {
			t.Errorf("inclusion proof %d does not check out: %v", i, err)
		}
	}
}

func TestInclusionProofRejectsWrongLeaf(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	leaves := env.appendN(ctx, 8)
	signed, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	p, err := env.log.InclusionProof(ctx, 3, sth.Size)
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	other, err := leaves[4].Hash()
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}
	if err := p.Verify(other, sth); !errors.Is(err, ErrProofInvalid) {
		t.Errorf("foreign leaf accepted: %v", err)
	}
}

// TestAllSTHsPairwiseConsistent is verification test 1 from the plan: after
// arbitrary sequences of appends and issuances, all STHs ever issued must be
// pairwise consistent. Were that not so, the node would have signed two
// histories.
func TestAllSTHsPairwiseConsistent(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	rnd := rand.New(rand.NewSource(20260801))

	var sths []*STH
	issue := func() {
		signed, err := env.log.IssueSTH(ctx)
		if err != nil {
			t.Fatalf("STH: %v", err)
		}
		if err := signed.Verify(env.key.Public()); err != nil {
			t.Fatalf("STH signature: %v", err)
		}
		sth, err := signed.STH()
		if err != nil {
			t.Fatalf("read STH: %v", err)
		}
		sths = append(sths, sth)
	}

	issue() // the empty tree is witnessed too
	for round := 0; round < 12; round++ {
		env.appendN(ctx, 1+rnd.Intn(4))
		issue()
	}

	for i := 0; i < len(sths); i++ {
		for j := i; j < len(sths); j++ {
			old, cur := sths[i], sths[j]
			p, err := env.log.ConsistencyProof(ctx, old.Size, cur.Size)
			if err != nil {
				t.Fatalf("consistency proof %d->%d: %v", old.Size, cur.Size, err)
			}
			if err := p.Verify(old, cur); err != nil {
				t.Errorf("STHs %d and %d inconsistent (%d->%d): %v",
					i, j, old.Size, cur.Size, err)
			}
			if err := CheckSTHPair(old, cur); err != nil {
				t.Errorf("CheckSTHPair(%d, %d): %v", i, j, err)
			}
		}
	}
}

func TestConsistencyProofRejectsForeignRoot(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.appendN(ctx, 3)
	first, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	env.appendN(ctx, 5)
	second, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	oldSTH, err := first.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	newSTH, err := second.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	p, err := env.log.ConsistencyProof(ctx, oldSTH.Size, newSTH.Size)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	// A single flipped bit in the old root: the proof must no longer check out.
	tampered := *oldSTH
	tampered.Root[0] ^= 0x01
	if err := p.Verify(&tampered, newSTH); !errors.Is(err, ErrProofInvalid) {
		t.Errorf("tampered root accepted: %v", err)
	}
}

// TestSplitViewDetected is verification test 2 from the plan: a node that shows
// two observers different trees must be caught — and caught solely by what it
// signed itself.
func TestSplitViewDetected(t *testing.T) {
	ctx := context.Background()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	// Two logs of the same node — the two views the attacker maintains.
	viewA := newTestEnvWithKey(t, key)
	viewB := newTestEnvWithKey(t, key)
	if viewA.log.ID() != viewB.log.ID() {
		t.Fatalf("views belong to different logs")
	}

	viewA.appendN(ctx, 4)
	viewB.appendN(ctx, 4) // different entries, same count

	signedA, err := viewA.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH A: %v", err)
	}
	signedB, err := viewB.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH B: %v", err)
	}
	// Both signatures are genuine. That is exactly what makes the finding
	// undeniable.
	if err := signedA.Verify(key.Public()); err != nil {
		t.Fatalf("STH A invalid: %v", err)
	}
	if err := signedB.Verify(key.Public()); err != nil {
		t.Fatalf("STH B invalid: %v", err)
	}
	sthA, err := signedA.STH()
	if err != nil {
		t.Fatalf("read STH A: %v", err)
	}
	sthB, err := signedB.STH()
	if err != nil {
		t.Fatalf("read STH B: %v", err)
	}
	if sthA.Size != sthB.Size {
		t.Fatalf("test setup: sizes %d and %d", sthA.Size, sthB.Size)
	}
	if err := CheckSTHPair(sthA, sthB); !errors.Is(err, ErrSplitView) {
		t.Fatalf("split view not detected: %v", err)
	}

	// And the second route to the same finding: the consistency proof of one
	// view does not check out against the root of the other.
	viewA.appendN(ctx, 2)
	later, err := viewA.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	sthLater, err := later.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	p, err := viewA.log.ConsistencyProof(ctx, sthB.Size, sthLater.Size)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if err := p.Verify(sthB, sthLater); !errors.Is(err, ErrProofInvalid) {
		t.Errorf("foreign view accepted as consistent: %v", err)
	}
}

func TestCheckSTHPairShrunk(t *testing.T) {
	logID := core.LogID{1, 2, 3}
	early := &STH{Version: FormatVersion, Log: logID, Size: 9, IssuedAt: 1000, Root: core.Digest{9}}
	late := &STH{Version: FormatVersion, Log: logID, Size: 4, IssuedAt: 2000, Root: core.Digest{4}}
	if err := CheckSTHPair(early, late); !errors.Is(err, ErrShrunk) {
		t.Errorf("shrinking not detected: %v", err)
	}
	// The order of the arguments must not matter.
	if err := CheckSTHPair(late, early); !errors.Is(err, ErrShrunk) {
		t.Errorf("shrinking not detected (swapped): %v", err)
	}
}

func TestCheckSTHPairForeignLog(t *testing.T) {
	a := &STH{Version: FormatVersion, Log: core.LogID{1}, Size: 1, IssuedAt: 1, Root: core.Digest{1}}
	b := &STH{Version: FormatVersion, Log: core.LogID{2}, Size: 1, IssuedAt: 2, Root: core.Digest{2}}
	if err := CheckSTHPair(a, b); !errors.Is(err, ErrLogMismatch) {
		t.Errorf("foreign log not detected: %v", err)
	}
}

func TestCheckReceiptWithheld(t *testing.T) {
	logID := core.LogID{1, 2, 3}
	r := &Receipt{Version: FormatVersion, Log: logID, EntryID: core.Digest{9}, Seq: 5, IssuedAt: 1000, Deadline: 2000, Key: core.KeyID{1}}
	// An STH issued after the deadline whose size has still not passed Seq.
	sth := &STH{Version: FormatVersion, Log: logID, Size: 5, IssuedAt: 3000, Root: core.Digest{1}}
	if err := CheckReceipt(r, sth); !errors.Is(err, ErrWithheld) {
		t.Errorf("withholding not detected: %v", err)
	}
}

func TestCheckReceiptHonoured(t *testing.T) {
	logID := core.LogID{1, 2, 3}
	r := &Receipt{Version: FormatVersion, Log: logID, EntryID: core.Digest{9}, Seq: 5, IssuedAt: 1000, Deadline: 2000, Key: core.KeyID{1}}
	tests := []struct {
		name string
		sth  *STH
	}{
		{"size past seq, before deadline", &STH{Version: FormatVersion, Log: logID, Size: 6, IssuedAt: 1500, Root: core.Digest{1}}},
		{"size past seq, after deadline", &STH{Version: FormatVersion, Log: logID, Size: 6, IssuedAt: 3000, Root: core.Digest{1}}},
		{"size at seq, before deadline", &STH{Version: FormatVersion, Log: logID, Size: 5, IssuedAt: 1500, Root: core.Digest{1}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckReceipt(r, tc.sth); err != nil {
				t.Errorf("false positive: %v", err)
			}
		})
	}
}

func TestCheckReceiptForeignLog(t *testing.T) {
	r := &Receipt{Version: FormatVersion, Log: core.LogID{1}, EntryID: core.Digest{9}, Seq: 5, IssuedAt: 1000, Deadline: 2000, Key: core.KeyID{1}}
	sth := &STH{Version: FormatVersion, Log: core.LogID{2}, Size: 1, IssuedAt: 3000, Root: core.Digest{1}}
	if err := CheckReceipt(r, sth); !errors.Is(err, ErrLogMismatch) {
		t.Errorf("foreign log not detected: %v", err)
	}
}

// newTestEnvWithMaxMergeDelay is newTestEnvWithKey with receipts enabled — a
// separate constructor rather than a parameter on the shared one, so every
// existing test in this file keeps running with receipts off unless it
// explicitly asks for them.
func newTestEnvWithMaxMergeDelay(t *testing.T, mmd time.Duration) *testEnv {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	env := &testEnv{
		t:     t,
		key:   key,
		st:    NewMemStorage(),
		blobs: NewMemBlobStore(),
		clock: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC).UnixMilli(),
	}
	lg, err := New(Options{
		Storage:       env.st,
		Signer:        key,
		Blobs:         env.blobs,
		Keys:          mapKeys{key.Public().ID(): key.Public()},
		Now:           env.now,
		MaxMergeDelay: mmd,
	})
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	env.log = lg
	return env
}

// TestLogIssueReceipt confirms IssueReceipt is fully wired through a real
// log: the receipt names the entry actually appended, the signature
// verifies against the log's own key, and — because this implementation
// appends synchronously — an STH issued right afterwards already satisfies
// the promise, well before the deadline.
func TestLogIssueReceipt(t *testing.T) {
	ctx := context.Background()
	env := newTestEnvWithMaxMergeDelay(t, time.Hour)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt := env.entry(subject, []byte("payload"))
	leaf, err := env.log.AppendWithPayload(ctx, se, salt, []byte("payload"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	signed, err := env.log.IssueReceipt(leaf)
	if err != nil {
		t.Fatalf("issue receipt: %v", err)
	}
	if err := signed.Verify(env.key.Public()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	r, err := signed.Receipt()
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if r.Log != env.log.ID() {
		t.Errorf("log = %s, want %s", r.Log, env.log.ID())
	}
	if r.EntryID != leaf.EntryID() {
		t.Errorf("entry ID mismatch")
	}
	if r.Seq != leaf.Seq {
		t.Errorf("seq = %d, want %d", r.Seq, leaf.Seq)
	}
	if want := time.Hour.Milliseconds(); r.Deadline-r.IssuedAt != want {
		t.Errorf("deadline = %d ms after issuance, want %d", r.Deadline-r.IssuedAt, want)
	}

	signedSTH, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("issue STH: %v", err)
	}
	sth, err := signedSTH.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	if err := CheckReceipt(r, sth); err != nil {
		t.Errorf("an honestly issued STH must satisfy its own receipt: %v", err)
	}
}

func TestLogIssueReceiptDisabledByDefault(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t) // MaxMergeDelay left unset, i.e. 0
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt := env.entry(subject, []byte("payload"))
	leaf, err := env.log.AppendWithPayload(ctx, se, salt, []byte("payload"))
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := env.log.IssueReceipt(leaf); !errors.Is(err, ErrReceiptsDisabled) {
		t.Errorf("receipt issued despite MaxMergeDelay = 0: %v", err)
	}
}

// TestErasure is verification test 3 from the plan: after the erasure the
// payload is not reconstructible even for a small value range, and the
// inclusion proof of the leaf still holds.
func TestErasure(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.appendN(ctx, 5) // neighbours, so the leaf sits in the middle of the tree

	// A value range of a few thousand possibilities — precisely the case in
	// which an unsalted commitment would be inverted straight away.
	const domainSize = 4096
	domain := make([][]byte, domainSize)
	for i := range domain {
		domain[i] = []byte(fmt.Sprintf("farm-%04d", i))
	}
	secret := domain[1234]

	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt := env.entry(subject, secret)
	entryID := se.EntryID()
	leaf, err := env.log.AppendWithPayload(ctx, se, salt, secret)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	env.appendN(ctx, 3)

	beforeSigned, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	before, err := beforeSigned.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	leafHash, err := leaf.Hash()
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}
	beforeProof, err := env.log.InclusionProof(ctx, leaf.Seq, before.Size)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	if err := beforeProof.Verify(leafHash, before); err != nil {
		t.Fatalf("inclusion proof before the erasure: %v", err)
	}
	if got, err := env.log.Payload(ctx, entryID); err != nil || string(got) != string(secret) {
		t.Fatalf("payload before the erasure: %q, %v", got, err)
	}

	// Erase.
	tomb, err := env.log.Erase(ctx, entryID)
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	tombEntry := entryOf(t, tomb)
	if tombEntry.Type != core.EntryTypeErasure {
		t.Errorf("tombstone has type %s", tombEntry.Type)
	}
	if tombEntry.Target == nil || tombEntry.Target.Entry != entryID {
		t.Errorf("tombstone does not point at the erased entry")
	}
	if tombEntry.Target.Log != env.log.ID() {
		t.Errorf("tombstone names log %s, expected %s", tombEntry.Target.Log, env.log.ID())
	}

	// The payload is gone and the state stays provable.
	if _, err := env.log.Payload(ctx, entryID); !errors.Is(err, ErrErased) {
		t.Errorf("payload still retrievable after the erasure: %v", err)
	}
	status, err := env.log.BlobStatus(ctx, entryID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != BlobErased {
		t.Errorf("status = %s, expected erased", status)
	}
	// And it cannot be smuggled back in either.
	if err := env.blobs.Put(ctx, entryID, salt, secret); !errors.Is(err, ErrErased) {
		t.Errorf("erased payload accepted again: %v", err)
	}

	// The dictionary attack over the complete value range. Without the salt the
	// commitment is uniformly distributed over the key space.
	entry := entryOf(t, leaf)
	for _, cand := range domain {
		if core.VerifyCommitment(entry.Commitment, core.Salt{}, cand) {
			t.Fatalf("payload %q recovered from the commitment", cand)
		}
	}
	// Control run: with the salt exactly one candidate matches. The attack
	// fails on the missing salt, not because it would not work at all.
	hits := 0
	for _, cand := range domain {
		if core.VerifyCommitment(entry.Commitment, salt, cand) {
			hits++
		}
	}
	if hits != 1 {
		t.Errorf("control run: %d hits with the salt, expected 1", hits)
	}

	// The heart of the matter: the tree was not touched.
	rootNow, err := env.log.RootAt(ctx, before.Size)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if rootNow != before.Root {
		t.Errorf("root over %d leaves has changed", before.Size)
	}
	if err := beforeSigned.Verify(env.key.Public()); err != nil {
		t.Errorf("old STH invalid after the erasure: %v", err)
	}
	if err := beforeProof.Verify(leafHash, before); err != nil {
		t.Errorf("old inclusion proof invalid after the erasure: %v", err)
	}
	// The leaf itself and its signature stay checkable too — what was erased is
	// the payload, not the witness.
	if err := leaf.Verify(env.log.ID(), env.key.Public()); err != nil {
		t.Errorf("leaf no longer verifiable after the erasure: %v", err)
	}

	// And the tree has grown since then, not shrunk.
	afterSigned, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	after, err := afterSigned.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	p, err := env.log.ConsistencyProof(ctx, before.Size, after.Size)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if err := p.Verify(before, after); err != nil {
		t.Errorf("erasure broke the history: %v", err)
	}
}

func TestEraseIsIdempotent(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt := env.entry(subject, []byte("secret"))
	if _, err := env.log.AppendWithPayload(ctx, se, salt, []byte("secret")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := env.log.Erase(ctx, se.EntryID()); err != nil {
		t.Fatalf("first erasure: %v", err)
	}
	if _, err := env.log.Erase(ctx, se.EntryID()); err != nil {
		t.Fatalf("second erasure: %v", err)
	}
}

func TestEraseRefusesKeyRotation(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	rot := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeKeyRotation,
		Subject:    subject,
		IssuedAt:   env.now().UnixMilli(),
		Issuer:     env.key.Public().ID(),
		Commitment: core.Commit(salt, []byte("new key")),
	}
	se, err := core.SignEntry(env.key, rot)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := env.log.AppendWithPayload(ctx, se, salt, []byte("new key")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := env.log.Erase(ctx, se.EntryID()); !errors.Is(err, ErrNotErasable) {
		t.Errorf("rotation entry erasable: %v", err)
	}
	// And the payload is still there — a refused erasure must not have done
	// anything by halves.
	if status, err := env.log.BlobStatus(ctx, se.EntryID()); err != nil || status != BlobPresent {
		t.Errorf("status = %s, %v; expected present", status, err)
	}
}

func TestAppendWithPayloadRejectsMismatch(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt := env.entry(subject, []byte("genuine"))
	_, err = env.log.AppendWithPayload(ctx, se, salt, []byte("substituted"))
	if !errors.Is(err, ErrCommitment) {
		t.Fatalf("wrong payload accepted: %v", err)
	}
	if size, err := env.log.Size(ctx); err != nil || size != 0 {
		t.Errorf("tree grew despite the rejection: %d, %v", size, err)
	}
	if status, err := env.blobs.Status(ctx, se.EntryID()); err != nil || status != BlobAbsent {
		t.Errorf("payload stored despite the rejection: %s, %v", status, err)
	}
}

func TestAppendRejectsUnknownIssuer(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	stranger, err := core.GenerateKey(core.SigAlgMLDSA44)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	ent := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Subject:    subject,
		IssuedAt:   env.now().UnixMilli(),
		Issuer:     stranger.Public().ID(),
		Commitment: core.Commit(salt, []byte("x")),
	}
	se, err := core.SignEntry(stranger, ent)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := env.log.Append(ctx, se); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown issuer accepted: %v", err)
	}
}

func TestHistoryBySubject(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	env.appendN(ctx, 2)
	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("station-%d", i))
		se, salt := env.entry(subject, payload)
		if _, err := env.log.AppendWithPayload(ctx, se, salt, payload); err != nil {
			t.Fatalf("append: %v", err)
		}
		env.appendN(ctx, 1)
	}
	leaves, err := env.log.History(ctx, subject)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(leaves) != 3 {
		t.Fatalf("history has %d entries, expected 3", len(leaves))
	}
	for i := 1; i < len(leaves); i++ {
		if leaves[i-1].Seq >= leaves[i].Seq {
			t.Errorf("history not ascending: %d before %d", leaves[i-1].Seq, leaves[i].Seq)
		}
	}
}

func TestLogIDFollowsGenesisKey(t *testing.T) {
	env := newTestEnv(t)
	rotated, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	// After a rotation a new key does the signing, but the log identifier stays
	// tied to the genesis key — otherwise every existing reference would point
	// into the void.
	after, err := New(Options{
		Storage: env.st,
		Signer:  rotated,
		Genesis: env.key.Public(),
		Now:     env.now,
	})
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	if after.ID() != env.log.ID() {
		t.Errorf("log ID after the rotation = %s, expected %s", after.ID(), env.log.ID())
	}

	ctx := context.Background()
	signed, err := after.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if err := signed.Verify(rotated.Public()); err != nil {
		t.Errorf("STH of the new key: %v", err)
	}
	if err := signed.Verify(env.key.Public()); err == nil {
		t.Error("STH verifiable with the old key")
	}
}

func TestProofsOutOfRange(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.appendN(ctx, 4)

	if _, err := env.log.InclusionProof(ctx, 4, 4); !errors.Is(err, ErrProofSize) {
		t.Errorf("leaf outside the tree: %v", err)
	}
	if _, err := env.log.InclusionProof(ctx, 0, 9); !errors.Is(err, ErrProofSize) {
		t.Errorf("tree size from the future: %v", err)
	}
	if _, err := env.log.ConsistencyProof(ctx, 3, 2); !errors.Is(err, ErrProofSize) {
		t.Errorf("backwards consistency proof: %v", err)
	}
	if _, err := env.log.RootAt(ctx, 5); !errors.Is(err, ErrProofSize) {
		t.Errorf("root from the future: %v", err)
	}
}

func TestNoBlobStore(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	bare, err := New(Options{Storage: NewMemStorage(), Signer: env.key, Now: env.now})
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	if _, err := bare.Payload(ctx, core.Digest{1}); !errors.Is(err, ErrNoBlobStore) {
		t.Errorf("payload without a blob store: %v", err)
	}
	if _, err := bare.Erase(ctx, core.Digest{1}); !errors.Is(err, ErrNoBlobStore) {
		t.Errorf("erase without a blob store: %v", err)
	}
}

func TestNewRequiresStorageAndSigner(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA44)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := New(Options{Signer: key}); !errors.Is(err, ErrMissingField) {
		t.Errorf("log without storage: %v", err)
	}
	if _, err := New(Options{Storage: NewMemStorage()}); !errors.Is(err, ErrMissingField) {
		t.Errorf("log without a signing key: %v", err)
	}
}

func entryOf(t *testing.T, leaf *Leaf) *core.Entry {
	t.Helper()
	se, err := leaf.SignedEntry()
	if err != nil {
		t.Fatalf("signed entry: %v", err)
	}
	e, err := se.Entry()
	if err != nil {
		t.Fatalf("entry: %v", err)
	}
	return e
}
