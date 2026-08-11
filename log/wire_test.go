// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"bytes"
	"errors"
	"testing"

	"openwaymark.org/owm/core"
)

func testLeaf(t *testing.T) (*Leaf, *core.PrivateKey) {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("Log-Kennung: %v", err)
	}
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("Salt: %v", err)
	}
	se, err := core.SignEntry(key, &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   1754049600000,
		Issuer:     key.Public().ID(),
		Commitment: core.Commit(salt, []byte("nutzlast")),
	})
	if err != nil {
		t.Fatalf("signieren: %v", err)
	}
	entryBytes, err := se.Encode()
	if err != nil {
		t.Fatalf("kodieren: %v", err)
	}
	return &Leaf{
		Version:  FormatVersion,
		Log:      logID,
		Seq:      7,
		LoggedAt: 1754049601000,
		Entry:    entryBytes,
	}, key
}

func TestLeafRoundTrip(t *testing.T) {
	leaf, key := testLeaf(t)
	b, err := leaf.Encode()
	if err != nil {
		t.Fatalf("kodieren: %v", err)
	}
	got, err := ParseLeaf(b)
	if err != nil {
		t.Fatalf("lesen: %v", err)
	}
	if got.Version != leaf.Version || got.Log != leaf.Log ||
		got.Seq != leaf.Seq || got.LoggedAt != leaf.LoggedAt ||
		!bytes.Equal(got.Entry, leaf.Entry) {
		t.Fatalf("Blatt hat sich beim Umlauf verändert")
	}
	again, err := got.Encode()
	if err != nil {
		t.Fatalf("erneut kodieren: %v", err)
	}
	if !bytes.Equal(b, again) {
		t.Error("Kodierung ist nicht stabil")
	}
	if got.EntryID() != core.EntryIDFromBytes(mustEntryBytes(t, leaf.Entry)) {
		t.Error("Eintragskennung stimmt nicht")
	}
	if err := got.Verify(leaf.Log, key.Public()); err != nil {
		t.Errorf("prüfen: %v", err)
	}
}

func TestLeafVerifyRejectsForeignLog(t *testing.T) {
	leaf, key := testLeaf(t)
	other := leaf.Log
	other[0] ^= 0xff
	if err := leaf.Verify(other, key.Public()); !errors.Is(err, ErrLogMismatch) {
		t.Errorf("fremdes Log akzeptiert: %v", err)
	}
}

func TestLeafVerifyRejectsTamperedEntry(t *testing.T) {
	leaf, key := testLeaf(t)
	// Ein gekipptes Bit in der Signatur des eingebetteten Eintrags. Genau
	// deshalb steht der signierte Eintrag im Blatt und nicht nur seine Kennung.
	tampered := append([]byte(nil), leaf.Entry...)
	tampered[len(tampered)-1] ^= 0x01
	leaf.Entry = tampered
	if err := leaf.Verify(leaf.Log, key.Public()); err == nil {
		t.Error("manipulierte Signatur akzeptiert")
	}
}

func TestLeafRejectsNonCanonical(t *testing.T) {
	leaf, _ := testLeaf(t)
	b, err := leaf.Encode()
	if err != nil {
		t.Fatalf("kodieren: %v", err)
	}
	// a5 = Map mit 5 Paaren, dann Schlüssel 1 und Wert 1 in minimaler Form.
	if len(b) < 3 || b[0] != 0xa5 || b[1] != 0x01 || b[2] != 0x01 {
		t.Fatalf("unerwartete Kodierung: %x", b[:3])
	}
	// Dieselbe Zahl in nicht-minimaler Form (0x18 0x01). CBOR liest das als 1,
	// aber es ist eine zweite Kodierung desselben Blattes — und damit ein
	// zweiter Blatthash für denselben Inhalt.
	noncanon := make([]byte, 0, len(b)+1)
	noncanon = append(noncanon, b[:2]...)
	noncanon = append(noncanon, 0x18, 0x01)
	noncanon = append(noncanon, b[3:]...)

	if _, err := ParseLeaf(noncanon); !errors.Is(err, core.ErrNotCanonical) {
		t.Errorf("nicht-kanonische Kodierung akzeptiert: %v", err)
	}
}

func TestLeafRejectsTrailingData(t *testing.T) {
	leaf, _ := testLeaf(t)
	b, err := leaf.Encode()
	if err != nil {
		t.Fatalf("kodieren: %v", err)
	}
	if _, err := ParseLeaf(append(b, 0x00)); err == nil {
		t.Error("angehängte Bytes akzeptiert")
	}
}

func TestLeafValidate(t *testing.T) {
	base, _ := testLeaf(t)
	tests := []struct {
		name   string
		mutate func(*Leaf)
		want   error
	}{
		{"falsche Version", func(l *Leaf) { l.Version = 2 }, ErrLeafVersion},
		{"ohne Log", func(l *Leaf) { l.Log = core.LogID{} }, ErrMissingField},
		{"ohne Zeitstempel", func(l *Leaf) { l.LoggedAt = 0 }, ErrMissingField},
		{"ohne Eintrag", func(l *Leaf) { l.Entry = nil }, ErrMissingField},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := *base
			tc.mutate(&l)
			if err := l.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, erwartet %v", err, tc.want)
			}
		})
	}
	// Seq 0 ist gültig: Das erste Blatt eines Logs hat die Position 0.
	l := *base
	l.Seq = 0
	if err := l.Validate(); err != nil {
		t.Errorf("Position 0 abgelehnt: %v", err)
	}
}

func TestLeafSizeLimit(t *testing.T) {
	leaf, _ := testLeaf(t)
	leaf.Entry = make([]byte, MaxLeafSize+1)
	for i := range leaf.Entry {
		leaf.Entry[i] = 0x41
	}
	if _, err := leaf.Encode(); !errors.Is(err, ErrLeafSize) {
		t.Errorf("übergroßes Blatt kodiert: %v", err)
	}
	if _, err := ParseLeaf(make([]byte, MaxLeafSize+1)); !errors.Is(err, ErrLeafSize) {
		t.Errorf("übergroße Eingabe gelesen: %v", err)
	}
}

func testSTH(t *testing.T, key *core.PrivateKey) *STH {
	t.Helper()
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("Log-Kennung: %v", err)
	}
	return &STH{
		Version:  FormatVersion,
		Log:      logID,
		Size:     42,
		IssuedAt: 1754049602000,
		Root:     core.Digest{0x11, 0x22, 0x33},
		Key:      key.Public().ID(),
	}
}

func TestSTHRoundTrip(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	sth := testSTH(t, key)
	signed, err := SignSTH(key, sth)
	if err != nil {
		t.Fatalf("signieren: %v", err)
	}
	if err := signed.Verify(key.Public()); err != nil {
		t.Fatalf("prüfen: %v", err)
	}

	b, err := signed.Encode()
	if err != nil {
		t.Fatalf("kodieren: %v", err)
	}
	got, err := ParseSignedSTH(b)
	if err != nil {
		t.Fatalf("lesen: %v", err)
	}
	if err := got.Verify(key.Public()); err != nil {
		t.Fatalf("prüfen nach Umlauf: %v", err)
	}
	inner, err := got.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	if *inner != *sth {
		t.Errorf("STH hat sich beim Umlauf verändert")
	}
	if _, err := ParseSignedSTH(append(b, 0x00)); err == nil {
		t.Error("angehängte Bytes akzeptiert")
	}
}

func TestSTHVerifyRejectsTampering(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	signed, err := SignSTH(key, testSTH(t, key))
	if err != nil {
		t.Fatalf("signieren: %v", err)
	}

	t.Run("Wurzel", func(t *testing.T) {
		bad := &SignedSTH{
			STHBytes:  append([]byte(nil), signed.STHBytes...),
			Alg:       signed.Alg,
			Signature: signed.Signature,
		}
		bad.STHBytes[len(bad.STHBytes)-1] ^= 0x01
		if err := bad.Verify(key.Public()); err == nil {
			t.Error("manipulierter STH akzeptiert")
		}
	})

	t.Run("Signatur", func(t *testing.T) {
		bad := &SignedSTH{
			STHBytes:  signed.STHBytes,
			Alg:       signed.Alg,
			Signature: append([]byte(nil), signed.Signature...),
		}
		bad.Signature[0] ^= 0x01
		if !errors.Is(bad.Verify(key.Public()), ErrBadSignature) {
			t.Error("manipulierte Signatur akzeptiert")
		}
	})

	t.Run("fremder Schlüssel", func(t *testing.T) {
		other, err := core.GenerateKey(core.SigAlgMLDSA65)
		if err != nil {
			t.Fatalf("Schlüssel: %v", err)
		}
		if !errors.Is(signed.Verify(other.Public()), ErrSignerMismatch) {
			t.Error("fremder Schlüssel akzeptiert")
		}
	})

	t.Run("falscher Algorithmus", func(t *testing.T) {
		small, err := core.GenerateKey(core.SigAlgMLDSA44)
		if err != nil {
			t.Fatalf("Schlüssel: %v", err)
		}
		if !errors.Is(signed.Verify(small.Public()), ErrAlgMismatch) {
			t.Error("falscher Algorithmus akzeptiert")
		}
	})
}

func TestSignSTHRejectsForeignSigner(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	other, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	// Der STH nennt key als Unterzeichner, unterschreiben soll other.
	if _, err := SignSTH(other, testSTH(t, key)); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("fremder Unterzeichner akzeptiert: %v", err)
	}
}

func TestSTHValidate(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA44)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	base := testSTH(t, key)
	tests := []struct {
		name   string
		mutate func(*STH)
		want   error
	}{
		{"falsche Version", func(s *STH) { s.Version = 2 }, ErrSTHVersion},
		{"ohne Log", func(s *STH) { s.Log = core.LogID{} }, ErrMissingField},
		{"ohne Zeitstempel", func(s *STH) { s.IssuedAt = 0 }, ErrMissingField},
		{"ohne Wurzel", func(s *STH) { s.Root = core.Digest{} }, ErrMissingField},
		{"ohne Schlüssel", func(s *STH) { s.Key = core.KeyID{} }, ErrMissingField},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := *base
			tc.mutate(&s)
			if err := s.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, erwartet %v", err, tc.want)
			}
		})
	}
	// Der leere Baum ist bezeugbar: Größe 0 ist gültig.
	s := *base
	s.Size = 0
	if err := s.Validate(); err != nil {
		t.Errorf("STH über den leeren Baum abgelehnt: %v", err)
	}
}

func mustEntryBytes(t *testing.T, signed []byte) []byte {
	t.Helper()
	se, err := core.ParseSignedEntry(signed)
	if err != nil {
		t.Fatalf("signierten Eintrag lesen: %v", err)
	}
	return se.EntryBytes
}
