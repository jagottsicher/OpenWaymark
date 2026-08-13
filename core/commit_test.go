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
	payload := []byte("stabil")
	first := Commit(salt, payload)
	for range 8 {
		if Commit(salt, payload) != first {
			t.Fatal("Commit is not deterministic")
		}
	}
}

// TestCommitHidesSmallDomain ist die Eigenschaft, wegen der das Commitment
// gesalzen ist: Ein ungesalzener Hash über eine Postleitzahl oder eine
// GPS-Koordinate ließe sich schlicht durchprobieren, und die DSGVO-Löschung
// wäre wirkungslos. Der Test bildet den Angriff nach — er darf nicht aufgehen.
func TestCommitHidesSmallDomain(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	secret := []byte("53175") // eine von 100000 Postleitzahlen
	c := Commit(salt, secret)

	// Der Angreifer kennt den Wertebereich, aber nicht den Salt. Ohne ihn ist
	// jeder Kandidat gleich plausibel.
	for i := range 20000 {
		guess := fmt.Appendf(nil, "%05d", i)
		if VerifyCommitment(c, Salt{}, guess) {
			t.Fatalf("payload %q reconstructed without the salt", guess)
		}
	}

	// Mit dem Salt geht es sofort — das ist der Unterschied zwischen
	// „gelöscht" und „noch da".
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

// TestSaltReuseLeaksEquality hält fest, warum jede Nutzlast einen eigenen Salt
// braucht: Bei Wiederverwendung wird sichtbar, dass zwei Einträge dieselbe
// Nutzlast tragen — und die Löschung des einen ist im anderen nachweisbar
// rückgängig zu machen.
func TestSaltReuseLeaksEquality(t *testing.T) {
	salt, err := NewSalt()
	if err != nil {
		t.Fatalf("NewSalt: %v", err)
	}
	payload := []byte("the same statement")

	// Zwei Einträge, ein wiederverwendeter Salt: Die Commitments sind gleich,
	// und damit ist von außen sichtbar, dass beide dieselbe Nutzlast tragen.
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
