// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"crypto/mlkem"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/seal"
)

// signSealed builds and signs an assertion entry with Profile == "" and a
// seal.Seal-ed payload — mirroring participant.sign (node_test.go), except
// that sign hardcodes Profile: food.ID and this deliberately does not: a
// sealed payload cannot get node-side profile-schema validation (the node
// cannot check content it cannot read), the same Profile == "" convention
// attestation entries already rely on.
func (p *participant) signSealed(t *testing.T, subject core.SubjectID, envelope []byte) (*core.SignedEntry, core.Salt, []byte) {
	t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	e := &core.Entry{
		Version:    1,
		Type:       core.EntryTypeAssertion,
		Subject:    subject,
		Issuer:     p.key.Public().ID(),
		Commitment: core.Commit(salt, envelope),
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(p.key, e)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	return se, salt, envelope
}

// TestSealedPayloadNeedsNoNodeChanges is A14's load-bearing proof, not just
// its assertion: a real node accepts, stores, serves and lets go.Erase erase
// a seal.Seal-ed payload with zero node-side code written for it — every
// mechanism it exercises (Submit, GET .../payload, erasure) already existed
// for an ordinary plaintext assertion.
func TestSealedPayloadNeedsNoNodeChanges(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	a := newAPI(t, n)
	issuer := newParticipant(t, n, core.SigAlgMLDSA65, "farmer")
	subject := newSubject(t)

	buyer, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	stranger, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}

	plaintext := []byte(`{"event":"production","product":{"geo":{"lat":47.8021,"lon":11.0129}},"party":{"name":"Hof Sonnenblick"}}`)
	envelope, err := seal.Seal(plaintext, "eudr.v1", []seal.Recipient{{Hint: "buyer", Key: buyer.EncapsulationKey()}})
	if err != nil {
		t.Fatalf("seal.Seal: %v", err)
	}

	se, salt, payload := issuer.signSealed(t, subject, envelope)
	entryID := se.EntryID()
	if _, err := n.Submit(ctx, se, salt, payload); err != nil {
		t.Fatalf("Submit rejected a sealed payload: %v", err)
	}

	var pr payloadResponse
	a.mustGet("/owm/v1/entries/"+entryID.String()+"/payload", &pr)
	if string(pr.Payload) != string(envelope) {
		t.Fatalf("served payload does not match the sealed envelope byte for byte")
	}

	got, hint, err := seal.Open(pr.Payload, buyer)
	if err != nil {
		t.Fatalf("the intended recipient could not open the served envelope: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted payload = %q, want %q", got, plaintext)
	}
	if hint != "eudr.v1" {
		t.Fatalf("profile hint = %q, want eudr.v1", hint)
	}

	if _, _, err := seal.Open(pr.Payload, stranger); err == nil {
		t.Fatal("a non-recipient's key opened the envelope")
	}

	// Erasure works exactly as it does for any other payload — nothing
	// about it knows or cares that this one happened to be encrypted.
	if _, err := n.Erase(ctx, entryID); err != nil {
		t.Fatalf("erase: %v", err)
	}
	var errBody map[string]any
	code := a.call("GET", a.public+"/owm/v1/entries/"+entryID.String()+"/payload", nil, &errBody)
	if code != 410 {
		t.Fatalf("payload status after erasure = %d, want 410", code)
	}
}
