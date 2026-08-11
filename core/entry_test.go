// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// testIssuedAt ist 2026-01-01T00:00:00Z in Millisekunden.
const testIssuedAt int64 = 1767225600000

// fixtureSalt ist ein fester Salt für reproduzierbare Tests. Im Betrieb zieht
// jede Nutzlast einen frischen, siehe NewSalt.
var fixtureSalt = func() Salt {
	var s Salt
	for i := range s {
		s[i] = byte(0xA0 + i)
	}
	return s
}()

func fixtureEntry(k *PrivateKey) *Entry {
	return &Entry{
		Version:    FormatVersion,
		Type:       EntryTypeAssertion,
		Profile:    "owm.food/1",
		Subject:    DeriveSubjectID("owm:batch", []byte("2026-08-10-A")),
		IssuedAt:   testIssuedAt,
		Issuer:     k.Public().ID(),
		Commitment: Commit(fixtureSalt, []byte(`{"typ":"harvest"}`)),
	}
}

func TestEntryTypeStrings(t *testing.T) {
	want := map[EntryType]string{
		EntryTypeAssertion:     "assertion",
		EntryTypeAttestation:   "attestation",
		EntryTypeRevocation:    "revocation",
		EntryTypeKeyRotation:   "key_rotation",
		EntryTypeSensorReading: "sensor_reading",
	}
	for typ, name := range want {
		if !typ.Valid() {
			t.Errorf("%s gilt als ungültig", name)
		}
		if got := typ.String(); got != name {
			t.Errorf("String() = %q, erwartet %q", got, name)
		}
	}
	for _, bad := range []EntryType{0, 6, 255} {
		if bad.Valid() {
			t.Errorf("EntryType(%d) gilt als gültig", uint8(bad))
		}
	}
}

func TestEntryValidate(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x11)
	base := fixtureEntry(k)
	ref := EntryRef{Entry: hashLabeled("test", []byte("vorgänger"))}

	cases := []struct {
		name    string
		mutate  func(*Entry)
		wantErr error
	}{
		{"gültig", func(*Entry) {}, nil},
		{"falsche Version", func(e *Entry) { e.Version = 2 }, ErrVersion},
		{"unbekannter Typ", func(e *Entry) { e.Type = 99 }, ErrEntryType},
		{"Subjekt fehlt", func(e *Entry) { e.Subject = SubjectID{} }, ErrMissingField},
		{"Aussteller fehlt", func(e *Entry) { e.Issuer = KeyID{} }, ErrMissingField},
		{"Zeitpunkt fehlt", func(e *Entry) { e.IssuedAt = 0 }, ErrMissingField},
		{"Zeitpunkt negativ", func(e *Entry) { e.IssuedAt = -1 }, ErrMissingField},
		{"Commitment fehlt", func(e *Entry) { e.Commitment = Commitment{} }, ErrMissingField},
		{"tgt bei assertion", func(e *Entry) { e.Target = &ref }, ErrUnexpectedTgt},
		{"Profil zu lang", func(e *Entry) { e.Profile = strings.Repeat("a", maxProfileLen+1) }, ErrProfile},
		{"Profil mit Großbuchstaben", func(e *Entry) { e.Profile = "OWM.food/1" }, ErrProfile},
		{"Profil mit Leerzeichen", func(e *Entry) { e.Profile = "owm food" }, ErrProfile},
		{"Profil mit Steuerzeichen", func(e *Entry) { e.Profile = "owm\x00food" }, ErrProfile},
		{"leeres Profil", func(e *Entry) { e.Profile = "" }, nil},
		{"Vorgänger ohne Kennung", func(e *Entry) { e.Parents = []EntryRef{{}} }, ErrMissingField},
		{"Vorgänger gültig", func(e *Entry) { e.Parents = []EntryRef{ref} }, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := *base
			c.mutate(&e)
			err := e.Validate()
			switch {
			case c.wantErr == nil && err != nil:
				t.Fatalf("unerwarteter Fehler: %v", err)
			case c.wantErr != nil && !errors.Is(err, c.wantErr):
				t.Fatalf("Fehler = %v, erwartet %v", err, c.wantErr)
			}
		})
	}
}

func TestRevocationRules(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x12)
	ref := EntryRef{Entry: hashLabeled("test", []byte("widerrufener Eintrag"))}

	rev := fixtureEntry(k)
	rev.Type = EntryTypeRevocation
	rev.Profile = ""
	rev.Commitment = Commitment{} // ein Widerruf braucht keine Nutzlast
	rev.Target = &ref
	if err := rev.Validate(); err != nil {
		t.Fatalf("gültiger Widerruf abgelehnt: %v", err)
	}

	without := *rev
	without.Target = nil
	if err := without.Validate(); !errors.Is(err, ErrMissingField) {
		t.Errorf("Widerruf ohne tgt liefert %v, erwartet ErrMissingField", err)
	}

	empty := *rev
	empty.Target = &EntryRef{}
	if err := empty.Validate(); !errors.Is(err, ErrMissingField) {
		t.Errorf("Widerruf mit leerem tgt liefert %v, erwartet ErrMissingField", err)
	}
}

func TestIssuedAtRoundTrip(t *testing.T) {
	var e Entry
	// Millisekundengenauigkeit ist die Auflösung des Formats; feinere Anteile
	// werden abgeschnitten und dürfen nicht zurückkommen.
	want := time.Date(2026, 8, 10, 12, 34, 56, 789_000_000, time.UTC)
	e.SetIssuedAt(want.Add(321 * time.Microsecond))
	if got := e.IssuedAtTime(); !got.Equal(want) {
		t.Errorf("IssuedAtTime = %s, erwartet %s", got, want)
	}
}

func TestSignAndVerifyEntry(t *testing.T) {
	for _, alg := range testAlgs {
		k := keyFromSeedByte(t, alg, 0x13)
		e := fixtureEntry(k)

		se, err := SignEntry(k, e)
		if err != nil {
			t.Fatalf("%s: SignEntry: %v", alg, err)
		}
		if se.Alg != alg {
			t.Errorf("%s: Alg = %s", alg, se.Alg)
		}
		if err := se.Verify(k.Public()); err != nil {
			t.Errorf("%s: Verify: %v", alg, err)
		}

		got, err := se.Entry()
		if err != nil {
			t.Fatalf("%s: Entry: %v", alg, err)
		}
		if got.Subject != e.Subject || got.Issuer != e.Issuer || got.IssuedAt != e.IssuedAt {
			t.Errorf("%s: Eintrag nach Rückweg abweichend", alg)
		}

		id, err := e.ID()
		if err != nil {
			t.Fatalf("%s: ID: %v", alg, err)
		}
		if se.EntryID() != id {
			t.Errorf("%s: EntryID weicht von Entry.ID ab", alg)
		}
	}
}

// TestEntryIDIgnoresSignature hält die Entscheidung aus OWM-0 §4.3 fest: Die
// Inhaltsadresse deckt den Eintrag ab, nicht die Signatur. Sonst wäre sie bei
// randomisiertem Signieren nicht reproduzierbar.
func TestEntryIDIgnoresSignature(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x14)
	e := fixtureEntry(k)

	a, err := SignEntry(k, e)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	b, err := SignEntry(k, e)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if string(a.Signature) == string(b.Signature) {
		t.Fatal("zwei Signaturen desselben Eintrags sind identisch — Voraussetzung des Tests verletzt")
	}
	if a.EntryID() != b.EntryID() {
		t.Error("Inhaltsadresse hängt von der Signatur ab")
	}
}

func TestSignEntryRejectsForeignIssuer(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x15)
	other := keyFromSeedByte(t, SigAlgMLDSA65, 0x16)

	e := fixtureEntry(other) // iss zeigt auf einen fremden Schlüssel
	if _, err := SignEntry(k, e); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("SignEntry liefert %v, erwartet ErrIssuerMismatch", err)
	}
	if _, err := SignEntry(nil, e); !errors.Is(err, ErrMissingField) {
		t.Errorf("SignEntry(nil) liefert %v, erwartet ErrMissingField", err)
	}
}

// TestVerifyRejectsForeignKey ist die Prüfung, ohne die sich jeder Eintrag mit
// einem beliebigen Schlüssel „bestätigen" ließe.
func TestVerifyRejectsForeignKey(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x17)
	other := keyFromSeedByte(t, SigAlgMLDSA65, 0x18)

	se, err := SignEntry(k, fixtureEntry(k))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if err := se.Verify(other.Public()); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("Verify mit fremdem Schlüssel liefert %v, erwartet ErrIssuerMismatch", err)
	}
	if err := se.Verify(nil); !errors.Is(err, ErrMissingField) {
		t.Errorf("Verify(nil) liefert %v, erwartet ErrMissingField", err)
	}
}

func TestVerifyRejectsAlgMismatch(t *testing.T) {
	k65 := keyFromSeedByte(t, SigAlgMLDSA65, 0x19)
	k44 := keyFromSeedByte(t, SigAlgMLDSA44, 0x1A)

	se, err := SignEntry(k65, fixtureEntry(k65))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if err := se.Verify(k44.Public()); !errors.Is(err, ErrAlgMismatch) {
		t.Errorf("Verify liefert %v, erwartet ErrAlgMismatch", err)
	}
}

func TestVerifyRejectsTamperedSignedEntry(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x1B)
	se, err := SignEntry(k, fixtureEntry(k))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	t.Run("Signatur verändert", func(t *testing.T) {
		bad := *se
		bad.Signature = append([]byte(nil), se.Signature...)
		bad.Signature[7] ^= 0x01
		if err := bad.Verify(k.Public()); !errors.Is(err, ErrBadSignature) {
			t.Errorf("liefert %v, erwartet ErrBadSignature", err)
		}
	})

	t.Run("Eintrag verändert", func(t *testing.T) {
		// Der Zeitstempel wird um eine Millisekunde verschoben. Der Eintrag
		// bleibt strukturell gültig und kanonisch — nur die Signatur passt
		// nicht mehr.
		e := fixtureEntry(k)
		e.IssuedAt++
		other, err := e.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		bad := SignedEntry{EntryBytes: other, Alg: se.Alg, Signature: se.Signature}
		if err := bad.Verify(k.Public()); !errors.Is(err, ErrBadSignature) {
			t.Errorf("liefert %v, erwartet ErrBadSignature", err)
		}
	})
}
