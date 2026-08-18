// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"encoding/json"
	"errors"
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
