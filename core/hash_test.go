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
		t.Fatalf("hex length = %d, expected %d", len(text), 2*DigestSize)
	}
	got, err := ParseDigest(string(text))
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if got != d {
		t.Errorf("round trip yields %s, expected %s", got, d)
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
			t.Errorf("ParseDigest(%q) accepted, expected an error", s)
		}
	}
}

func TestDigestFromBytesLength(t *testing.T) {
	if _, err := DigestFromBytes(make([]byte, DigestSize)); err != nil {
		t.Errorf("correct length rejected: %v", err)
	}
	for _, n := range []int{0, 1, DigestSize - 1, DigestSize + 1} {
		if _, err := DigestFromBytes(make([]byte, n)); err == nil {
			t.Errorf("length %d accepted, expected an error", n)
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
		t.Error("different argument splits produce the same hash")
	}

	// Auch die Bezeichnung selbst muss trennen.
	c := hashLabeled("la", []byte("bc"))
	if c == a || c == b {
		t.Error("the label does not separate from the first argument")
	}
}

func TestHashLabeledDistinctLabels(t *testing.T) {
	msg := []byte("the same message")
	seen := map[Digest]string{}
	for _, label := range []string{labelKeyID, labelEntryID, labelSubjectID, labelCommit} {
		d := hashLabeled(label, msg)
		if other, dup := seen[d]; dup {
			t.Fatalf("labels %q and %q collide", label, other)
		}
		seen[d] = label
	}
}

func TestDeriveSubjectIDSeparatesNamespace(t *testing.T) {
	a := DeriveSubjectID("gs1:sgtin", []byte("0614141.812345.6789"))
	b := DeriveSubjectID("owm:batch", []byte("0614141.812345.6789"))
	if a == b {
		t.Error("different namespaces produce the same subject ID")
	}
	if a != DeriveSubjectID("gs1:sgtin", []byte("0614141.812345.6789")) {
		t.Error("derivation is not deterministic")
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
			t.Fatal("subject ID is the zero value")
		}
		if seen[s] {
			t.Fatal("subject ID repeats")
		}
		seen[s] = true
	}
}
