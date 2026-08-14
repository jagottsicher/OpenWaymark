// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// testIssuedAt is 2026-01-01T00:00:00Z in milliseconds.
const testIssuedAt int64 = 1767225600000

// fixtureSalt is a fixed salt for reproducible tests. In production every
// payload draws a fresh one, see NewSalt.
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
		EntryTypeErasure:       "erasure",
	}
	for typ, name := range want {
		if !typ.Valid() {
			t.Errorf("%s is treated as invalid", name)
		}
		if got := typ.String(); got != name {
			t.Errorf("String() = %q, expected %q", got, name)
		}
	}
	for _, bad := range []EntryType{0, 7, 255} {
		if bad.Valid() {
			t.Errorf("EntryType(%d) is treated as valid", uint8(bad))
		}
	}
}

// TestErasureIsNotRevocation pins down the distinction from OWM-0 §6.1: both
// name a target, but they say different things. If they coincided, every GDPR
// erasure would look like an admission that the statement had been false.
func TestErasureIsNotRevocation(t *testing.T) {
	if EntryTypeErasure == EntryTypeRevocation {
		t.Fatal("erasure and revocation have the same numeric value")
	}
	for _, typ := range []EntryType{EntryTypeRevocation, EntryTypeErasure} {
		if !typ.RefersToEntry() {
			t.Errorf("%s names no target", typ)
		}
	}
	for _, typ := range []EntryType{EntryTypeAssertion, EntryTypeAttestation,
		EntryTypeKeyRotation, EntryTypeSensorReading} {
		if typ.RefersToEntry() {
			t.Errorf("%s names a target but should not", typ)
		}
	}
}

func TestEntryValidate(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x11)
	base := fixtureEntry(k)
	ref := EntryRef{Entry: hashLabeled("test", []byte("parent"))}

	cases := []struct {
		name    string
		mutate  func(*Entry)
		wantErr error
	}{
		{"valid", func(*Entry) {}, nil},
		{"wrong version", func(e *Entry) { e.Version = 2 }, ErrVersion},
		{"unknown type", func(e *Entry) { e.Type = 99 }, ErrEntryType},
		{"subject missing", func(e *Entry) { e.Subject = SubjectID{} }, ErrMissingField},
		{"issuer missing", func(e *Entry) { e.Issuer = KeyID{} }, ErrMissingField},
		{"timestamp missing", func(e *Entry) { e.IssuedAt = 0 }, ErrMissingField},
		{"negative timestamp", func(e *Entry) { e.IssuedAt = -1 }, ErrMissingField},
		{"commitment missing", func(e *Entry) { e.Commitment = Commitment{} }, ErrMissingField},
		{"tgt on assertion", func(e *Entry) { e.Target = &ref }, ErrUnexpectedTgt},
		{"profile too long", func(e *Entry) { e.Profile = strings.Repeat("a", maxProfileLen+1) }, ErrProfile},
		{"profile with upper-case letters", func(e *Entry) { e.Profile = "OWM.food/1" }, ErrProfile},
		{"profile with a space", func(e *Entry) { e.Profile = "owm food" }, ErrProfile},
		{"profile with a control character", func(e *Entry) { e.Profile = "owm\x00food" }, ErrProfile},
		{"empty profile", func(e *Entry) { e.Profile = "" }, nil},
		{"parent without an identifier", func(e *Entry) { e.Parents = []EntryRef{{}} }, ErrMissingField},
		{"parent valid", func(e *Entry) { e.Parents = []EntryRef{ref} }, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := *base
			c.mutate(&e)
			err := e.Validate()
			switch {
			case c.wantErr == nil && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case c.wantErr != nil && !errors.Is(err, c.wantErr):
				t.Fatalf("error = %v, expected %v", err, c.wantErr)
			}
		})
	}
}

// TestParentLimit secures the upper bound in both places: when validating and
// when decoding. The second is the more important one — that is where it is
// decided whether a maliciously large array claims memory before anyone
// rejects it.
func TestParentLimit(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x13)
	ref := EntryRef{Entry: hashLabeled("test", []byte("parent"))}

	atLimit := fixtureEntry(k)
	atLimit.Parents = make([]EntryRef, MaxParents)
	for i := range atLimit.Parents {
		atLimit.Parents[i] = ref
	}
	if err := atLimit.Validate(); err != nil {
		t.Fatalf("exactly MaxParents rejected: %v", err)
	}
	encoded, err := atLimit.Encode()
	if err != nil {
		t.Fatalf("encoding at MaxParents: %v", err)
	}
	if _, err := ParseEntry(encoded); err != nil {
		t.Fatalf("decoding at MaxParents: %v", err)
	}

	over := *atLimit
	over.Parents = append(append([]EntryRef(nil), atLimit.Parents...), ref)
	if err := over.Validate(); !errors.Is(err, ErrTooManyParents) {
		t.Errorf("Validate returns %v, expected ErrTooManyParents", err)
	}
	// Encode directly, past the validation step, to hit the decoding path.
	raw, err := encMode.Marshal(over.toWire())
	if err != nil {
		t.Fatalf("raw encoding: %v", err)
	}
	if _, err := ParseEntry(raw); !errors.Is(err, ErrTooManyParents) {
		t.Errorf("ParseEntry returns %v, expected ErrTooManyParents", err)
	}
}

func TestTargetingEntryRules(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x12)
	ref := EntryRef{Entry: hashLabeled("test", []byte("affected entry"))}

	for _, typ := range []EntryType{EntryTypeRevocation, EntryTypeErasure} {
		t.Run(typ.String(), func(t *testing.T) {
			e := fixtureEntry(k)
			e.Type = typ
			e.Profile = ""
			e.Commitment = Commitment{} // neither needs a payload of its own
			e.Target = &ref
			if err := e.Validate(); err != nil {
				t.Fatalf("valid entry rejected: %v", err)
			}

			without := *e
			without.Target = nil
			if err := without.Validate(); !errors.Is(err, ErrMissingField) {
				t.Errorf("without tgt returns %v, expected ErrMissingField", err)
			}

			empty := *e
			empty.Target = &EntryRef{}
			if err := empty.Validate(); !errors.Is(err, ErrMissingField) {
				t.Errorf("with an empty tgt returns %v, expected ErrMissingField", err)
			}
		})
	}
}

func TestIssuedAtRoundTrip(t *testing.T) {
	var e Entry
	// Millisecond precision is the resolution of the format; finer fractions
	// are truncated and must not come back.
	want := time.Date(2026, 8, 10, 12, 34, 56, 789_000_000, time.UTC)
	e.SetIssuedAt(want.Add(321 * time.Microsecond))
	if got := e.IssuedAtTime(); !got.Equal(want) {
		t.Errorf("IssuedAtTime = %s, expected %s", got, want)
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
			t.Errorf("%s: entry differs after the round trip", alg)
		}

		id, err := e.ID()
		if err != nil {
			t.Fatalf("%s: ID: %v", alg, err)
		}
		if se.EntryID() != id {
			t.Errorf("%s: EntryID differs from Entry.ID", alg)
		}
	}
}

// TestEntryIDIgnoresSignature pins down the decision from OWM-0 §4.3: the
// content address covers the entry, not the signature. Otherwise it would not
// be reproducible under randomised signing.
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
		t.Fatal("two signatures of the same entry are identical - test precondition violated")
	}
	if a.EntryID() != b.EntryID() {
		t.Error("content address depends on the signature")
	}
}

func TestSignEntryRejectsForeignIssuer(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x15)
	other := keyFromSeedByte(t, SigAlgMLDSA65, 0x16)

	e := fixtureEntry(other) // iss points at a foreign key
	if _, err := SignEntry(k, e); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("SignEntry returns %v, expected ErrIssuerMismatch", err)
	}
	if _, err := SignEntry(nil, e); !errors.Is(err, ErrMissingField) {
		t.Errorf("SignEntry(nil) returns %v, expected ErrMissingField", err)
	}
}

// TestVerifyRejectsForeignKey covers the check without which any entry could be
// "confirmed" with an arbitrary key.
func TestVerifyRejectsForeignKey(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x17)
	other := keyFromSeedByte(t, SigAlgMLDSA65, 0x18)

	se, err := SignEntry(k, fixtureEntry(k))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	if err := se.Verify(other.Public()); !errors.Is(err, ErrIssuerMismatch) {
		t.Errorf("Verify with a foreign key returns %v, expected ErrIssuerMismatch", err)
	}
	if err := se.Verify(nil); !errors.Is(err, ErrMissingField) {
		t.Errorf("Verify(nil) returns %v, expected ErrMissingField", err)
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
		t.Errorf("Verify returns %v, expected ErrAlgMismatch", err)
	}
}

func TestVerifyRejectsTamperedSignedEntry(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x1B)
	se, err := SignEntry(k, fixtureEntry(k))
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}

	t.Run("signature modified", func(t *testing.T) {
		bad := *se
		bad.Signature = append([]byte(nil), se.Signature...)
		bad.Signature[7] ^= 0x01
		if err := bad.Verify(k.Public()); !errors.Is(err, ErrBadSignature) {
			t.Errorf("returns %v, expected ErrBadSignature", err)
		}
	})

	t.Run("entry modified", func(t *testing.T) {
		// The timestamp is shifted by one millisecond. The entry stays
		// structurally valid and canonical — only the signature no longer
		// matches.
		e := fixtureEntry(k)
		e.IssuedAt++
		other, err := e.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		bad := SignedEntry{EntryBytes: other, Alg: se.Alg, Signature: se.Signature}
		if err := bad.Verify(k.Public()); !errors.Is(err, ErrBadSignature) {
			t.Errorf("returns %v, expected ErrBadSignature", err)
		}
	})
}
