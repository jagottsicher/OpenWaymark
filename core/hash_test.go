// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"strings"
	"testing"
)

func TestDigestTextRoundTrip(t *testing.T) {
	d := hashLabeled("test", []byte("hallo"))
	text, err := d.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if len(text) != 2*DigestSize {
		t.Fatalf("Hexlänge = %d, erwartet %d", len(text), 2*DigestSize)
	}
	got, err := ParseDigest(string(text))
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if got != d {
		t.Errorf("Rückweg ergibt %s, erwartet %s", got, d)
	}
}

func TestParseDigestRejectsMalformed(t *testing.T) {
	for _, s := range []string{
		"",
		"abcd",
		strings.Repeat("0", 2*DigestSize-1),
		strings.Repeat("0", 2*DigestSize+1),
		strings.Repeat("z", 2*DigestSize),
	} {
		if _, err := ParseDigest(s); err == nil {
			t.Errorf("ParseDigest(%q) akzeptiert, erwartet Fehler", s)
		}
	}
}

func TestDigestFromBytesLength(t *testing.T) {
	if _, err := DigestFromBytes(make([]byte, DigestSize)); err != nil {
		t.Errorf("korrekte Länge abgelehnt: %v", err)
	}
	for _, n := range []int{0, 1, DigestSize - 1, DigestSize + 1} {
		if _, err := DigestFromBytes(make([]byte, n)); err == nil {
			t.Errorf("Länge %d akzeptiert, erwartet Fehler", n)
		}
	}
}

// TestHashLabeledIsPrefixFree ist der eigentliche Sinn der Längenpräfixe: Ohne
// sie ließe sich ein Teil des Namensraums in den Wert verschieben, ohne den
// Hash zu ändern. Der Test hält genau das fest.
func TestHashLabeledIsPrefixFree(t *testing.T) {
	a := hashLabeled("l", []byte("ab"), []byte("c"))
	b := hashLabeled("l", []byte("a"), []byte("bc"))
	if a == b {
		t.Error("verschiedene Argumentaufteilungen ergeben denselben Hash")
	}

	// Auch die Bezeichnung selbst muss trennen.
	c := hashLabeled("la", []byte("bc"))
	if c == a || c == b {
		t.Error("Bezeichnung trennt nicht vom ersten Argument")
	}
}

func TestHashLabeledDistinctLabels(t *testing.T) {
	msg := []byte("dieselbe Nachricht")
	seen := map[Digest]string{}
	for _, label := range []string{labelKeyID, labelEntryID, labelSubjectID, labelCommit} {
		d := hashLabeled(label, msg)
		if other, dup := seen[d]; dup {
			t.Fatalf("Bezeichnungen %q und %q kollidieren", label, other)
		}
		seen[d] = label
	}
}

func TestDeriveSubjectIDSeparatesNamespace(t *testing.T) {
	a := DeriveSubjectID("gs1:sgtin", []byte("0614141.812345.6789"))
	b := DeriveSubjectID("owm:batch", []byte("0614141.812345.6789"))
	if a == b {
		t.Error("verschiedene Namensräume ergeben dieselbe Subjekt-ID")
	}
	if a != DeriveSubjectID("gs1:sgtin", []byte("0614141.812345.6789")) {
		t.Error("Ableitung ist nicht deterministisch")
	}
}

func TestNewSubjectIDIsRandom(t *testing.T) {
	seen := map[SubjectID]bool{}
	for range 64 {
		s, err := NewSubjectID()
		if err != nil {
			t.Fatalf("NewSubjectID: %v", err)
		}
		if s.IsZero() {
			t.Fatal("Subjekt-ID ist der Nullwert")
		}
		if seen[s] {
			t.Fatal("Subjekt-ID wiederholt sich")
		}
		seen[s] = true
	}
}
