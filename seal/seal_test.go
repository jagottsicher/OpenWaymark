// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package seal

import (
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"testing"
)

func mustKEMKey(t *testing.T) *mlkem.DecapsulationKey768 {
	t.Helper()
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("generate ML-KEM key: %v", err)
	}
	return dk
}

func TestSealOpenRoundTripSingleRecipient(t *testing.T) {
	dk := mustKEMKey(t)
	plaintext := []byte(`{"event":"production","product":{"geo":{"lat":47.8,"lon":11.0}}}`)

	env, err := Seal(plaintext, "eudr.v1", []Recipient{{Hint: "buyer", Key: dk.EncapsulationKey()}})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, hint, err := Open(env, dk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("plaintext = %q, want %q", got, plaintext)
	}
	if hint != "eudr.v1" {
		t.Errorf("profile hint = %q, want eudr.v1", hint)
	}
}

func TestSealOpenRoundTripMultiRecipient(t *testing.T) {
	buyer := mustKEMKey(t)
	regulator := mustKEMKey(t)
	auditor := mustKEMKey(t)
	plaintext := []byte("a plot's exact coordinates")

	env, err := Seal(plaintext, "", []Recipient{
		{Hint: "buyer", Key: buyer.EncapsulationKey()},
		{Hint: "regulator", Key: regulator.EncapsulationKey()},
		{Hint: "auditor", Key: auditor.EncapsulationKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	for name, dk := range map[string]*mlkem.DecapsulationKey768{"buyer": buyer, "regulator": regulator, "auditor": auditor} {
		t.Run(name, func(t *testing.T) {
			got, _, err := Open(env, dk)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("plaintext = %q, want %q", got, plaintext)
			}
		})
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	addressed := mustKEMKey(t)
	stranger := mustKEMKey(t)

	env, err := Seal([]byte("secret"), "", []Recipient{{Key: addressed.EncapsulationKey()}})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, _, err := Open(env, stranger); !errors.Is(err, ErrNotForYou) {
		t.Errorf("Open with a stranger's key: err = %v, want %v", err, ErrNotForYou)
	}
}

func TestOpenRejectsTamperedContent(t *testing.T) {
	dk := mustKEMKey(t)
	env, err := Seal([]byte("secret"), "", []Recipient{{Key: dk.EncapsulationKey()}})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var w wireEnvelope
	if err := json.Unmarshal(env, &w); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	w.Ciphertext[0] ^= 0xFF
	tampered, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}

	if _, _, err := Open(tampered, dk); err == nil {
		t.Error("Open accepted tampered content")
	}
}

// TestOpenTamperedRecipientDoesNotAffectAnother confirms a corrupted entry
// for recipient A does not prevent recipient B from opening their own,
// untouched entry — the per-recipient wrapping is genuinely independent,
// not a shared secret that one bad entry can poison.
func TestOpenTamperedRecipientDoesNotAffectAnother(t *testing.T) {
	alice := mustKEMKey(t)
	bob := mustKEMKey(t)
	plaintext := []byte("shared content")

	env, err := Seal(plaintext, "", []Recipient{
		{Hint: "alice", Key: alice.EncapsulationKey()},
		{Hint: "bob", Key: bob.EncapsulationKey()},
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	var w wireEnvelope
	if err := json.Unmarshal(env, &w); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	for i := range w.Recipients {
		if w.Recipients[i].Hint == "alice" {
			w.Recipients[i].WrappedKey[0] ^= 0xFF
		}
	}
	tampered, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}

	if _, _, err := Open(tampered, alice); !errors.Is(err, ErrNotForYou) {
		t.Errorf("alice (tampered entry): err = %v, want %v", err, ErrNotForYou)
	}
	got, _, err := Open(tampered, bob)
	if err != nil {
		t.Fatalf("bob (untouched entry) failed to open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("bob's plaintext = %q, want %q", got, plaintext)
	}
}

func TestSealRejectsNoRecipients(t *testing.T) {
	if _, err := Seal([]byte("x"), "", nil); !errors.Is(err, ErrNoRecipients) {
		t.Errorf("err = %v, want %v", err, ErrNoRecipients)
	}
	if _, err := Seal([]byte("x"), "", []Recipient{}); !errors.Is(err, ErrNoRecipients) {
		t.Errorf("err = %v, want %v", err, ErrNoRecipients)
	}
}

func TestSealRejectsNilKey(t *testing.T) {
	if _, err := Seal([]byte("x"), "", []Recipient{{Hint: "no key"}}); !errors.Is(err, ErrEnvelope) {
		t.Errorf("err = %v, want %v", err, ErrEnvelope)
	}
}

func TestOpenRejectsMalformedEnvelope(t *testing.T) {
	dk := mustKEMKey(t)
	cases := []struct {
		name string
		raw  string
	}{
		{"not json", "not json at all"},
		{"empty", ""},
		{"wrong alg", `{"alg":"AES-GCM-only","recipients":[{"kem_ciphertext":"AA=="}],"nonce":"AA==","ciphertext":"AA=="}`},
		{"no recipients", `{"alg":"` + Alg + `","recipients":[],"nonce":"AA==","ciphertext":"AA=="}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := Open([]byte(c.raw), dk); !errors.Is(err, ErrEnvelope) {
				t.Errorf("Open(%q): err = %v, want it to wrap %v", c.raw, err, ErrEnvelope)
			}
		})
	}
}

func TestSealPlaintextNeverAppearsInEnvelope(t *testing.T) {
	dk := mustKEMKey(t)
	secret := []byte("a specific smallholder's exact plot coordinates, name and yield")
	env, err := Seal(secret, "", []Recipient{{Key: dk.EncapsulationKey()}})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(env, secret) {
		t.Error("the plaintext appears verbatim in the sealed envelope")
	}
}
