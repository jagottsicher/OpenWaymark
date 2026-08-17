// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

func TestClientSTH(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	signed := buildSTH(t, key, logID, 3, testDigest("root"), time.Now())

	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(signed)

	gotSigned, gotSTH, err := n.client().STH(context.Background())
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if gotSTH.Size != 3 || gotSTH.Root != testDigest("root") {
		t.Errorf("STH = %+v", gotSTH)
	}
	if string(gotSigned.Signature) != string(signed.Signature) {
		t.Error("the returned SignedSTH does not match what was served")
	}
}

// TestClientSTHIgnoresDecoded proves the "decoded is not proof" rule: a
// server-supplied decoded field that is not even a valid STH object must not
// stop STH from succeeding, because Client never reads that field at all —
// only Signed, independently verified.
func TestClientSTHIgnoresDecoded(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	signed := buildSTH(t, key, logID, 1, testDigest("root"), time.Now())

	type responseWithDecoded struct {
		Signed  *owmlog.SignedSTH `json:"signed"`
		Decoded string            `json:"decoded"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owm/v1/sth":
			writeJSONBody(w, responseWithDecoded{Signed: signed, Decoded: "this is not an STH object at all"})
		case "/owm/v1/keys/" + key.Public().ID().String():
			writeJSONBody(w, fakeKeyResponse{Alg: key.Public().Alg().String(), Public: hex.EncodeToString(key.Public().Bytes())})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	_, gotSTH, err := c.STH(context.Background())
	if err != nil {
		t.Fatalf("STH: %v (a malformed 'decoded' field must be ignored, not fail the call)", err)
	}
	if gotSTH.Size != 1 {
		t.Errorf("STH.Size = %d", gotSTH.Size)
	}
}

func TestClientSTHBadSignature(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	signed := buildSTH(t, key, logID, 1, testDigest("root"), time.Now())
	// Corrupt the signature after the fact — same STH bytes, broken proof of
	// authorship.
	corrupted := *signed
	corrupted.Signature = append([]byte(nil), signed.Signature...)
	corrupted.Signature[0] ^= 0xFF

	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(&corrupted)

	if _, _, err := n.client().STH(context.Background()); err == nil {
		t.Fatal("STH accepted a corrupted signature")
	}
}

func TestClientKeyMismatch(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	other, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	signed := buildSTH(t, key, logID, 1, testDigest("root"), time.Now())

	n := newFakeNode(t)
	n.queueSTH(signed)
	// The server answers every key lookup with a different key than asked
	// for — a bug or an attack, either way Client MUST catch it rather than
	// silently trust the response's own claimed identity.
	n.forceKeyMismatch(other.Public())

	_, _, err = n.client().STH(context.Background())
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("STH = %v, want ErrKeyMismatch", err)
	}
}

func TestClientConsistency(t *testing.T) {
	tl := newTestLog(t)
	tl.appendOne()
	firstSigned := tl.issueSTH()
	first, err := firstSigned.STH()
	if err != nil {
		t.Fatal(err)
	}
	tl.appendOne()
	tl.appendOne()
	secondSigned := tl.issueSTH()
	second, err := secondSigned.STH()
	if err != nil {
		t.Fatal(err)
	}

	proof, err := tl.log.ConsistencyProof(context.Background(), first.Size, second.Size)
	if err != nil {
		t.Fatalf("build consistency proof: %v", err)
	}

	n := newFakeNode(t)
	n.setProof(proof)

	got, err := n.client().Consistency(context.Background(), first, second)
	if err != nil {
		t.Fatalf("Consistency: %v", err)
	}
	if got.OldSize != first.Size || got.NewSize != second.Size {
		t.Errorf("proof = %+v", got)
	}
}

func TestClientConsistencyWrongProof(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	old, err := buildSTH(t, key, logID, 1, testDigest("root-a"), time.Now()).STH()
	if err != nil {
		t.Fatal(err)
	}
	cur, err := buildSTH(t, key, logID, 2, testDigest("root-b"), time.Now().Add(time.Second)).STH()
	if err != nil {
		t.Fatal(err)
	}

	n := newFakeNode(t)
	// A syntactically valid but cryptographically meaningless proof: these
	// two roots were never produced by a real tree, so any path fails to
	// verify against them.
	n.setProof(&owmlog.ConsistencyProof{OldSize: 1, NewSize: 2, Path: []core.Digest{testDigest("garbage")}})

	if _, err := n.client().Consistency(context.Background(), old, cur); !errors.Is(err, owmlog.ErrProofInvalid) {
		t.Errorf("Consistency = %v, want ErrProofInvalid", err)
	}
}
