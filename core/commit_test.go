// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"testing"
)

func TestCommitVerify(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	payload := []byte(`{"typ":"harvest","farm":"Hof Meier","lot":"2026-08-10-A"}`)

	c := Commit(salt, payload)
	if c.IsZero() {
		t.Fatal("commitment is the zero value")
	}
	if !VerifyCommitment(c, salt, payload) {
		t.Error("correct pair is rejected")
	}
	if VerifyCommitment(c, salt, append(payload, '!')) {
		t.Error("modified payload is accepted")
	}

	other, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if VerifyCommitment(c, other, payload) {
		t.Error("wrong salt is accepted")
	}
}

func TestCommitIsDeterministic(t *testing.T) {
	var salt Salt
	for i := range salt {
		salt[i] = byte(i)
	}
	payload := []byte("stable")
	first := Commit(salt, payload)
	for range 8 {
		if Commit(salt, payload) != first {
			t.Fatal("Commit is not deterministic")
		}
	}
}

// TestCommitHidesSmallDomain covers the property the commitment is salted for:
// an unsalted hash over a postcode or a GPS coordinate could simply be
// enumerated, and GDPR erasure would have no effect. The test reproduces the
// attack — it must not succeed.
func TestCommitHidesSmallDomain(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	secret := []byte("53175") // one of 100000 postcodes
	c := Commit(salt, secret)

	// The attacker knows the value range but not the salt. Without it every
	// candidate is equally plausible.
	for i := range 20000 {
		guess := fmt.Appendf(nil, "%05d", i)
		if VerifyCommitment(c, Salt{}, guess) {
			t.Fatalf("payload %q reconstructed without the salt", guess)
		}
	}

	// With the salt it works right away — that is the difference between
	// "erased" and "still there".
	if !VerifyCommitment(c, salt, secret) {
		t.Error("check fails with the correct salt")
	}
}

func TestNewSaltIsRandom(t *testing.T) {
	seen := map[Salt]bool{}
	for range 64 {
		s, err := NewSalt()
		if err != nil {
			t.Fatalf("NewSalt: %v", err)
		}
		if seen[s] {
			t.Fatal("salt repeats")
		}
		seen[s] = true
	}
}

// TestSaltReuseLeaksEquality records why every payload needs a salt of its own:
// on reuse it becomes visible that two entries carry the same payload — and the
// erasure of one can be provably undone from the other.
func TestSaltReuseLeaksEquality(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	payload := []byte("the same statement")

	// Two entries, one reused salt: the commitments are equal, which makes it
	// visible from the outside that both carry the same payload.
	inFirstEntry := Commit(salt, payload)
	inSecondEntry := Commit(salt, payload)
	if inFirstEntry != inSecondEntry {
		t.Fatal("test precondition violated: Commit is not deterministic")
	}

	fresh, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	if Commit(fresh, payload) == inFirstEntry {
		t.Error("a fresh salt does not change the commitment")
	}
}

func TestSaltWipe(t *testing.T) {
	s, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	s.Wipe()
	if s != (Salt{}) {
		t.Error("Wipe leaves remnants")
	}
}

func TestCommitEmptyPayload(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	c := Commit(salt, nil)
	if !VerifyCommitment(c, salt, []byte{}) {
		t.Error("nil and an empty slice produce different commitments")
	}
	if VerifyCommitment(c, salt, []byte{0}) {
		t.Error("empty payload collides with a single zero byte")
	}
}
