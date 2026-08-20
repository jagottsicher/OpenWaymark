// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/trust"
)

// signAttestation builds and signs an attestation entry (OWM-6 §3). Unlike
// participant.sign (node_test.go) it carries no profile: attestations are
// cross-industry infrastructure, not a profile-gated event, and Profile ==
// "" is what makes profiles.Registry.Check a no-op for them.
func (p *participant) signAttestation(t *testing.T, subject core.SubjectID, payload string) (*core.SignedEntry, core.Salt, []byte) {
	t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	body := []byte(payload)
	e := &core.Entry{
		Version:    1,
		Type:       core.EntryTypeAttestation,
		Subject:    subject,
		Issuer:     p.key.Public().ID(),
		Commitment: core.Commit(salt, body),
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(p.key, e)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	return se, salt, body
}

// signRevocation builds and signs a revocation of target, naming subject as
// its own subject — the OWM-6 §6 convention a defeating revocation must
// follow: same subj, same iss as the attestation it revokes.
func (p *participant) signRevocation(t *testing.T, subject core.SubjectID, target core.Digest) *core.SignedEntry {
	t.Helper()
	e := &core.Entry{
		Version: 1,
		Type:    core.EntryTypeRevocation,
		Subject: subject,
		Issuer:  p.key.Public().ID(),
		Target:  &core.EntryRef{Entry: target},
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(p.key, e)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	return se
}

func TestSubmitRejectsMalformedAttestationPayload(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	accreditor := newParticipant(t, n, core.SigAlgMLDSA65, "accreditor")
	subject := newSubject(t)

	se, salt, payload := accreditor.signAttestation(t, subject, `{"kind":"organization","level":4}`)
	entryID := se.EntryID()

	if _, err := n.Submit(ctx, se, salt, payload); !errors.Is(err, trust.ErrPayload) {
		t.Fatalf("%v, expected ErrPayload", err)
	}
	// Unlike a rejected key_rotation payload, which lands in the log even
	// when the after-append step fails, a malformed attestation payload is
	// caught before append — it must not be in the log at all.
	if _, err := n.Log().LeafByEntryID(ctx, entryID); !errors.Is(err, owmlog.ErrNotFound) {
		t.Fatalf("entry ended up in the log despite the rejected payload: %v", err)
	}
}

func TestAttestationEndToEnd(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	a := newAPI(t, n)

	accreditor := newParticipant(t, n, core.SigAlgMLDSA65, "ISO body")
	operator := newParticipant(t, n, core.SigAlgMLDSA65, "Hof Sonnenblick")
	sensorKey := mustKey(t, core.SigAlgMLDSA44)
	if err := n.Keys().Register(ctx, sensorKey.Public(), "cool-77", nil); err != nil {
		t.Fatalf("admit sensor key: %v", err)
	}

	// An entity attestation: the accreditor vouches for the operator.
	se, salt, payload := accreditor.signAttestation(t,
		core.SubjectID(operator.key.Public().ID()),
		`{"kind":"entity","level":4,"scheme":"iso17065","evidence_url":"https://example.org/cert/1"}`)
	a.submit(se, salt, payload)

	// A sensor certificate: the operator vouches for its own sensor.
	se, salt, payload = operator.signAttestation(t,
		core.SubjectID(sensorKey.Public().ID()),
		`{"kind":"sensor","label":"Cold-chain logger, unit TW-7"}`)
	a.submit(se, salt, payload)

	var operatorHistory historyResponse
	a.mustGet("/owm/v1/subjects/"+core.SubjectID(operator.key.Public().ID()).String(), &operatorHistory)
	if operatorHistory.Total != 1 {
		t.Fatalf("operator history has %d entries, want 1", operatorHistory.Total)
	}
	if got := operatorHistory.Entries[0].Decoded.Type; got != "attestation" {
		t.Fatalf("type = %q, want attestation", got)
	}

	var sensorHistory historyResponse
	a.mustGet("/owm/v1/subjects/"+core.SubjectID(sensorKey.Public().ID()).String(), &sensorHistory)
	if sensorHistory.Total != 1 {
		t.Fatalf("sensor history has %d entries, want 1", sensorHistory.Total)
	}

	var pr payloadResponse
	a.mustGet("/owm/v1/entries/"+sensorHistory.Entries[0].EntryID.String()+"/payload", &pr)
	var got struct {
		Kind  string `json:"kind"`
		Label string `json:"label"`
	}
	if err := json.Unmarshal(pr.Payload, &got); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got.Kind != "sensor" || got.Label != "Cold-chain logger, unit TW-7" {
		t.Fatalf("got %+v", got)
	}
}

// TestNodeTrustSourceComputesLevel exercises the one piece of genuinely new
// logic in logSource that no other test touches: reading a node's own log
// back out through trust.Source, including the same-issuer-only revocation
// matching of OWM-6 §6.
func TestNodeTrustSourceComputesLevel(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)

	accreditor := newParticipant(t, n, core.SigAlgMLDSA65, "ISO body")
	other := newParticipant(t, n, core.SigAlgMLDSA65, "unrelated accreditor")
	operator := newParticipant(t, n, core.SigAlgMLDSA65, "Hof Sonnenblick")

	roots := trust.RootSet{
		accreditor.key.Public().ID(): {
			ID:       accreditor.key.Public().ID(),
			Name:     "ISO body",
			MaxLevel: trust.LevelState,
		},
	}

	se, salt, payload := accreditor.signAttestation(t,
		core.SubjectID(operator.key.Public().ID()),
		`{"kind":"entity","level":4,"scheme":"iso17065","evidence_url":"https://example.org/cert/1"}`)
	leaf, err := n.Submit(ctx, se, salt, payload)
	if err != nil {
		t.Fatalf("submit attestation: %v", err)
	}
	entryID := leaf.EntryID()

	lvl, chain, err := trust.Compute(ctx, n.TrustSource(), roots, operator.key.Public().ID())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if lvl != trust.LevelCertified {
		t.Fatalf("level = %s, want %s", lvl, trust.LevelCertified)
	}
	if len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}

	t.Run("a different-issuer revocation does not defeat it", func(t *testing.T) {
		rev := other.signRevocation(t, core.SubjectID(operator.key.Public().ID()), entryID)
		if _, err := n.Submit(ctx, rev, core.Salt{}, nil); err != nil {
			t.Fatalf("submit revocation: %v", err)
		}
		lvl, _, err := trust.Compute(ctx, n.TrustSource(), roots, operator.key.Public().ID())
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		if lvl != trust.LevelCertified {
			t.Fatalf("level = %s, want %s (a different-issuer revocation must not defeat the attestation)", lvl, trust.LevelCertified)
		}
	})

	t.Run("a same-issuer revocation defeats it", func(t *testing.T) {
		rev := accreditor.signRevocation(t, core.SubjectID(operator.key.Public().ID()), entryID)
		if _, err := n.Submit(ctx, rev, core.Salt{}, nil); err != nil {
			t.Fatalf("submit revocation: %v", err)
		}
		lvl, _, err := trust.Compute(ctx, n.TrustSource(), roots, operator.key.Public().ID())
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		if lvl != trust.LevelNone {
			t.Fatalf("level = %s, want %s (a same-issuer revocation must defeat the attestation)", lvl, trust.LevelNone)
		}
	})
}

// TestKeyTrustEndpoint exercises a real two-hop chain through the HTTP
// layer: an accreditation root attests an operator (hop 1), the operator
// attests a sensor (hop 2), and GET /owm/v1/keys/{id}/trust for the sensor
// has to reflect the level and the full two-hop chain.
func TestKeyTrustEndpoint(t *testing.T) {
	ctx := context.Background()

	accreditorKey := mustKey(t, core.SigAlgMLDSA65)
	rootsPath := filepath.Join(t.TempDir(), "trust-roots.json")
	rootsJSON := `[{"id":"` + accreditorKey.Public().ID().String() + `","name":"ISO body","max_level":6}]`
	if err := os.WriteFile(rootsPath, []byte(rootsJSON), 0o600); err != nil {
		t.Fatalf("write trust roots: %v", err)
	}

	cfg := testConfig(t)
	cfg.TrustRootsFile = rootsPath
	n, err := Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	a := newAPI(t, n)

	if err := n.Keys().Register(ctx, accreditorKey.Public(), "ISO body", nil); err != nil {
		t.Fatalf("admit accreditor key: %v", err)
	}
	accreditor := &participant{key: accreditorKey}
	operator := newParticipant(t, n, core.SigAlgMLDSA65, "Hof Sonnenblick")
	sensorKey := mustKey(t, core.SigAlgMLDSA44)
	if err := n.Keys().Register(ctx, sensorKey.Public(), "cool-77", nil); err != nil {
		t.Fatalf("admit sensor key: %v", err)
	}

	se, salt, payload := accreditor.signAttestation(t,
		core.SubjectID(operator.key.Public().ID()),
		`{"kind":"entity","level":4,"scheme":"iso17065","evidence_url":"https://example.org/cert/1"}`)
	a.submit(se, salt, payload)

	se, salt, payload = operator.signAttestation(t,
		core.SubjectID(sensorKey.Public().ID()),
		`{"kind":"sensor","label":"Cold-chain logger, unit TW-7"}`)
	a.submit(se, salt, payload)

	var got trustResponse
	a.mustGet("/owm/v1/keys/"+sensorKey.Public().ID().String()+"/trust", &got)
	if got.Level != int(trust.LevelCertified) {
		t.Fatalf("level = %d, want %d", got.Level, trust.LevelCertified)
	}
	if got.Name != trust.LevelCertified.String() {
		t.Fatalf("level_name = %q, want %q", got.Name, trust.LevelCertified.String())
	}
	if len(got.Chain) != 2 {
		t.Fatalf("chain length = %d, want 2 (root->operator, operator->sensor)", len(got.Chain))
	}
	if got.Chain[0].Issuer != accreditorKey.Public().ID() || got.Chain[0].Kind != "entity" ||
		got.Chain[0].Level == nil || *got.Chain[0].Level != int(trust.LevelCertified) {
		t.Fatalf("chain[0] = %+v", got.Chain[0])
	}
	if got.Chain[1].Issuer != operator.key.Public().ID() || got.Chain[1].Kind != "sensor" || got.Chain[1].Level != nil {
		t.Fatalf("chain[1] = %+v", got.Chain[1])
	}
}

// TestSubmitRejectsConcludedNotSelfIssued exercises the one cross-field rule
// checkAttestationPayload adds beyond payload shape (OWM-9 A15): only the
// keyholder may attributably announce their own participation has ended.
func TestSubmitRejectsConcludedNotSelfIssued(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	claimant := newParticipant(t, n, core.SigAlgMLDSA65, "third party")
	subject := newParticipant(t, n, core.SigAlgMLDSA65, "the entity being claimed about")

	se, salt, payload := claimant.signAttestation(t,
		core.SubjectID(subject.key.Public().ID()),
		`{"kind":"concluded","reason":"discontinued"}`)
	entryID := se.EntryID()

	if _, err := n.Submit(ctx, se, salt, payload); !errors.Is(err, ErrConcludedNotSelfIssued) {
		t.Fatalf("%v, expected ErrConcludedNotSelfIssued", err)
	}
	if _, err := n.Log().LeafByEntryID(ctx, entryID); !errors.Is(err, owmlog.ErrNotFound) {
		t.Fatalf("entry ended up in the log despite the rejected payload: %v", err)
	}
}

// TestConcludedEndToEnd submits a real self-issued kind:"concluded"
// attestation, confirms it is readable back exactly the way A15 needs — the
// same GET /owm/v1/subjects/{id} every other attestation already uses, no
// new endpoint — and confirms it does not alter the issuer's own trust
// level: the fix is a durable, attributable statement, not a claim about
// worthiness.
func TestConcludedEndToEnd(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	a := newAPI(t, n)

	root := newParticipant(t, n, core.SigAlgMLDSA65, "accreditation body")
	entity := newParticipant(t, n, core.SigAlgMLDSA65, "acquired company")
	successor := newParticipant(t, n, core.SigAlgMLDSA65, "acquiring company")

	roots := trust.RootSet{
		root.key.Public().ID(): {ID: root.key.Public().ID(), Name: "root", MaxLevel: trust.LevelState},
	}
	se, salt, payload := root.signAttestation(t,
		core.SubjectID(entity.key.Public().ID()),
		`{"kind":"entity","level":3,"scheme":"trade-register"}`)
	a.submit(se, salt, payload)

	se, salt, payload = entity.signAttestation(t,
		core.SubjectID(entity.key.Public().ID()),
		`{"kind":"concluded","reason":"succeeded","successor":"`+successor.key.Public().ID().String()+`"}`)
	a.submit(se, salt, payload)

	var history historyResponse
	a.mustGet("/owm/v1/subjects/"+core.SubjectID(entity.key.Public().ID()).String(), &history)
	if history.Total != 2 {
		t.Fatalf("history has %d entries, want 2 (the entity attestation and the concluded statement)", history.Total)
	}

	var pr payloadResponse
	a.mustGet("/owm/v1/entries/"+history.Entries[1].EntryID.String()+"/payload", &pr)
	var got struct {
		Kind      string `json:"kind"`
		Reason    string `json:"reason"`
		Successor string `json:"successor"`
	}
	if err := json.Unmarshal(pr.Payload, &got); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got.Kind != "concluded" || got.Reason != "succeeded" || got.Successor != successor.key.Public().ID().String() {
		t.Fatalf("got %+v", got)
	}

	lvl, _, err := trust.Compute(ctx, n.TrustSource(), roots, entity.key.Public().ID())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if lvl != trust.LevelRegister {
		t.Fatalf("level = %s, want %s (the concluded statement must not change the entity's own trust level)", lvl, trust.LevelRegister)
	}
}

// TestBindingEndToEnd is OWM-9 A8's fix, empirically confirming its own
// central design claim: a kind:"binding" attestation needs zero node-side
// changes to accept and serve, and — unlike an entity attestation — its
// Subject is an ordinary product subject, not a key at all.
func TestBindingEndToEnd(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	a := newAPI(t, n)

	tagger := newParticipant(t, n, core.SigAlgMLDSA65, "chip manufacturer")
	product, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}

	se, salt, payload := tagger.signAttestation(t, product, `{"kind":"binding","binding_level":2,"evidence_url":"https://example.org/nfc-spec"}`)
	a.submit(se, salt, payload)

	var history historyResponse
	a.mustGet("/owm/v1/subjects/"+product.String(), &history)
	if history.Total != 1 {
		t.Fatalf("history has %d entries, want 1", history.Total)
	}

	var pr payloadResponse
	a.mustGet("/owm/v1/entries/"+history.Entries[0].EntryID.String()+"/payload", &pr)
	var got struct {
		Kind         string `json:"kind"`
		BindingLevel int    `json:"binding_level"`
	}
	if err := json.Unmarshal(pr.Payload, &got); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if got.Kind != "binding" || got.BindingLevel != 2 {
		t.Fatalf("got %+v", got)
	}

	// The whole point: a binding claim never touches entity trust. The
	// tagger's own entity level stays LevelNone — nobody attested them.
	lvl, _, err := trust.Compute(ctx, n.TrustSource(), trust.RootSet{}, tagger.key.Public().ID())
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	if lvl != trust.LevelNone {
		t.Fatalf("level = %s, want %s (a binding attestation must not affect entity trust)", lvl, trust.LevelNone)
	}
}

func TestLoadTrustRootsMissingFileIsEmpty(t *testing.T) {
	roots, err := loadTrustRoots("")
	if err != nil {
		t.Fatalf("loadTrustRoots(\"\"): %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("got %d roots, want 0", len(roots))
	}

	roots, err = loadTrustRoots("/nonexistent/path/trust-roots.json")
	if err != nil {
		t.Fatalf("loadTrustRoots(missing file): %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("got %d roots, want 0", len(roots))
	}
}
