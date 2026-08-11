// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// Von Hand gebaute CBOR-Bausteine. Sie prüfen den Encoder gegen eine zweite,
// unabhängige Implementierung der Kodierregeln — ein Test, der die Bibliothek
// nur gegen sich selbst prüft, würde einen Fehler in ihr nicht bemerken.
func cborHead(major byte, n uint64) []byte {
	mt := major << 5
	switch {
	case n < 24:
		return []byte{mt | byte(n)}
	case n < 1<<8:
		return []byte{mt | 24, byte(n)}
	case n < 1<<16:
		b := []byte{mt | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n < 1<<32:
		b := []byte{mt | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	default:
		b := []byte{mt | 27, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(b[1:], n)
		return b
	}
}

// cborHeadLong erzeugt die 8-Byte-Form auch dort, wo eine kürzere reichen
// würde — also gerade das, was Core Deterministic Encoding verbietet.
func cborHeadLong(major byte, n uint64) []byte {
	b := []byte{major<<5 | 27, 0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint64(b[1:], n)
	return b
}

func cborUint(n uint64) []byte { return cborHead(0, n) }
func cborBstr(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborTstr(s string) []byte { return append(cborHead(3, uint64(len(s))), s...) }
func cborMapN(n uint64) []byte { return cborHead(5, n) }
func cborArrN(n uint64) []byte { return cborHead(4, n) }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// handBuiltEntry baut die kanonische Kodierung des Fixture-Eintrags ohne
// optionale Felder von Hand: Map mit sechs Paaren, Schlüssel aufsteigend.
func handBuiltEntry(e *Entry) []byte {
	return concat(
		cborMapN(6),
		cborUint(1), cborUint(uint64(e.Version)),
		cborUint(2), cborUint(uint64(e.Type)),
		cborUint(4), cborBstr(e.Subject[:]),
		cborUint(5), cborUint(uint64(e.IssuedAt)),
		cborUint(6), cborBstr(e.Issuer[:]),
		cborUint(7), cborBstr(e.Commitment[:]),
	)
}

func minimalEntry(t *testing.T) *Entry {
	t.Helper()
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x21)
	e := fixtureEntry(k)
	e.Profile = "" // optionale Felder bleiben weg
	return e
}

func TestEncodeMatchesHandBuiltCBOR(t *testing.T) {
	e := minimalEntry(t)
	got, err := e.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if want := handBuiltEntry(e); !bytes.Equal(got, want) {
		t.Errorf("Kodierung weicht ab\n  erhalten: %x\n  erwartet: %x", got, want)
	}
}

func TestEncodeOmitsAbsentOptionalFields(t *testing.T) {
	e := minimalEntry(t)
	b, err := e.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// Sechs Paare: kein prof, kein par, kein tgt. Ein null-kodiertes Feld
	// ergäbe eine zweite gültige Kodierung desselben Eintrags.
	if b[0] != 0xA6 {
		t.Errorf("Map-Kopf = %#x, erwartet 0xA6 (sechs Paare)", b[0])
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x22)
	e := fixtureEntry(k)
	e.Parents = []EntryRef{
		{Entry: hashLabeled("t", []byte("a"))},
		{Entry: hashLabeled("t", []byte("b")), Log: hashLabeled("t", []byte("log"))},
	}

	first, err := e.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for range 32 {
		again, err := e.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("Kodierung ist nicht deterministisch")
		}
	}
}

func TestEntryRoundTrip(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x23)
	rev := EntryRef{Entry: hashLabeled("t", []byte("ziel"))}

	cases := map[string]func(*Entry){
		"minimal":       func(e *Entry) { e.Profile = "" },
		"mit Profil":    func(*Entry) {},
		"ein Vorgänger": func(e *Entry) { e.Parents = []EntryRef{{Entry: hashLabeled("t", []byte("p"))}} },
		"Vorgänger mit Log": func(e *Entry) {
			e.Parents = []EntryRef{{Entry: hashLabeled("t", []byte("p")), Log: hashLabeled("t", []byte("l"))}}
		},
		"drei Vorgänger": func(e *Entry) {
			e.Parents = []EntryRef{
				{Entry: hashLabeled("t", []byte("p1"))},
				{Entry: hashLabeled("t", []byte("p2"))},
				{Entry: hashLabeled("t", []byte("p3"))},
			}
		},
		"Widerruf": func(e *Entry) {
			e.Type = EntryTypeRevocation
			e.Profile = ""
			e.Commitment = Commitment{}
			e.Target = &rev
		},
		"Sensormesswert": func(e *Entry) { e.Type = EntryTypeSensorReading },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := fixtureEntry(k)
			mutate(e)

			b, err := e.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, err := ParseEntry(b)
			if err != nil {
				t.Fatalf("ParseEntry: %v", err)
			}
			again, err := got.Encode()
			if err != nil {
				t.Fatalf("erneutes Encode: %v", err)
			}
			if !bytes.Equal(b, again) {
				t.Error("Rückweg ändert die Kodierung")
			}
			if id1, _ := e.ID(); id1 != EntryIDFromBytes(again) {
				t.Error("Inhaltsadresse ändert sich über den Rückweg")
			}
		})
	}
}

// TestParseRejectsNonCanonical ist die Prüfung, ohne die eine gültige Signatur
// an eine abweichend kodierte Fassung desselben Eintrags geheftet werden
// könnte.
func TestParseRejectsNonCanonical(t *testing.T) {
	e := minimalEntry(t)

	cases := map[string][]byte{
		"Schlüssel falsch sortiert": concat(
			cborMapN(6),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"Ganzzahl nicht kürzestmöglich": concat(
			cborMapN(6),
			cborUint(1), cborHeadLong(0, uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"Schlüssel nicht kürzestmöglich": concat(
			cborMapN(6),
			cborHeadLong(0, 1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"leeres Profil ausdrücklich kodiert": concat(
			cborMapN(7),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(3), cborTstr(""),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"leere Vorgängerliste ausdrücklich kodiert": concat(
			cborMapN(7),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
			cborUint(8), cborArrN(0),
		),
	}

	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEntry(b); !errors.Is(err, ErrNotCanonical) {
				t.Errorf("ParseEntry liefert %v, erwartet ErrNotCanonical", err)
			}
		})
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	e := minimalEntry(t)

	cases := map[string][]byte{
		"leer":       {},
		"Bruchstück": {0xA6, 0x01},
		"doppelter Schlüssel": concat(
			cborMapN(7),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"unbekannter Schlüssel": concat(
			cborMapN(7),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
			cborUint(42), cborUint(1),
		),
		"unbestimmte Länge": concat(
			[]byte{0xBF},
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
			[]byte{0xFF},
		),
		"Subjekt zu kurz": concat(
			cborMapN(6),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:16]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"Pflichtfeld fehlt": concat(
			cborMapN(5),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(7), cborBstr(e.Commitment[:]),
		),
		"Anhang nach dem Eintrag": concat(handBuiltEntry(e), []byte{0x00}),
	}

	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEntry(b); err == nil {
				t.Error("Kodierung akzeptiert, erwartet Fehler")
			}
		})
	}
}

func TestSignedEntryRoundTrip(t *testing.T) {
	for _, alg := range testAlgs {
		k := keyFromSeedByte(t, alg, 0x24)
		se, err := SignEntry(k, fixtureEntry(k))
		if err != nil {
			t.Fatalf("%s: SignEntry: %v", alg, err)
		}

		b, err := se.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", alg, err)
		}
		got, err := ParseSignedEntry(b)
		if err != nil {
			t.Fatalf("%s: ParseSignedEntry: %v", alg, err)
		}
		if err := got.Verify(k.Public()); err != nil {
			t.Errorf("%s: Verify nach Rückweg: %v", alg, err)
		}
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("%s: erneutes Encode: %v", alg, err)
		}
		if !bytes.Equal(b, again) {
			t.Errorf("%s: Rückweg ändert die Kodierung", alg)
		}
	}
}

func TestSignedEntryRejectsMalformed(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x25)
	se, err := SignEntry(k, fixtureEntry(k))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	t.Run("unbekannter Algorithmus", func(t *testing.T) {
		bad := concat(
			cborMapN(3),
			cborUint(1), cborBstr(se.EntryBytes),
			cborUint(2), cborUint(99),
			cborUint(3), cborBstr(se.Signature),
		)
		if _, err := ParseSignedEntry(bad); !errors.Is(err, ErrUnknownAlg) {
			t.Errorf("liefert %v, erwartet ErrUnknownAlg", err)
		}
	})

	t.Run("falsche Signaturlänge", func(t *testing.T) {
		bad := concat(
			cborMapN(3),
			cborUint(1), cborBstr(se.EntryBytes),
			cborUint(2), cborUint(uint64(se.Alg)),
			cborUint(3), cborBstr(se.Signature[:100]),
		)
		if _, err := ParseSignedEntry(bad); !errors.Is(err, ErrSigSize) {
			t.Errorf("liefert %v, erwartet ErrSigSize", err)
		}
	})

	t.Run("leerer Eintrag", func(t *testing.T) {
		bad := concat(
			cborMapN(3),
			cborUint(1), cborBstr(nil),
			cborUint(2), cborUint(uint64(se.Alg)),
			cborUint(3), cborBstr(se.Signature),
		)
		if _, err := ParseSignedEntry(bad); !errors.Is(err, ErrMissingField) {
			t.Errorf("liefert %v, erwartet ErrMissingField", err)
		}
	})

	t.Run("Eintrag nicht kanonisch", func(t *testing.T) {
		// Der äußere Umschlag ist kanonisch, der eingebettete Eintrag nicht.
		// Der Fehler darf erst beim Auspacken auffallen, nicht gar nicht.
		e := minimalEntry(t)
		noncanon := concat(
			cborMapN(6),
			cborUint(2), cborUint(uint64(e.Type)),
			cborUint(1), cborUint(uint64(e.Version)),
			cborUint(4), cborBstr(e.Subject[:]),
			cborUint(5), cborUint(uint64(e.IssuedAt)),
			cborUint(6), cborBstr(e.Issuer[:]),
			cborUint(7), cborBstr(e.Commitment[:]),
		)
		bad := SignedEntry{EntryBytes: noncanon, Alg: se.Alg, Signature: se.Signature}
		if _, err := bad.Entry(); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("Entry() liefert %v, erwartet ErrNotCanonical", err)
		}
		if err := bad.Verify(k.Public()); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("Verify liefert %v, erwartet ErrNotCanonical", err)
		}
	})
}

func FuzzParseEntry(f *testing.F) {
	k, err := NewKeyFromSeed(SigAlgMLDSA65, bytes.Repeat([]byte{0x26}, SigAlgMLDSA65.SeedSize()))
	if err != nil {
		f.Fatalf("NewKeyFromSeed: %v", err)
	}
	e := fixtureEntry(k)
	if b, err := e.Encode(); err == nil {
		f.Add(b)
	}
	e.Parents = []EntryRef{{Entry: hashLabeled("t", []byte("p"))}}
	if b, err := e.Encode(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xA0})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseEntry(data)
		if err != nil {
			return
		}
		// Was ParseEntry annimmt, muss kanonisch gewesen sein — sonst gäbe es
		// zu einem Eintrag mehrere gültige Bytefolgen.
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("angenommener Eintrag lässt sich nicht kodieren: %v", err)
		}
		if !bytes.Equal(data, again) {
			t.Fatalf("angenommene Kodierung ist nicht kanonisch\n  Eingabe: %x\n  erneut:  %x", data, again)
		}
	})
}

func FuzzParseSignedEntry(f *testing.F) {
	k, err := NewKeyFromSeed(SigAlgMLDSA44, bytes.Repeat([]byte{0x27}, SigAlgMLDSA44.SeedSize()))
	if err != nil {
		f.Fatalf("NewKeyFromSeed: %v", err)
	}
	if se, err := SignEntry(k, fixtureEntry(k)); err == nil {
		if b, err := se.Encode(); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte{0xA3})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseSignedEntry(data)
		if err != nil {
			return
		}
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("angenommener Umschlag lässt sich nicht kodieren: %v", err)
		}
		if !bytes.Equal(data, again) {
			t.Fatalf("angenommene Kodierung ist nicht kanonisch")
		}
		// Verify darf niemals in Panik geraten, egal was ankommt.
		_ = got.Verify(k.Public())
	})
}
