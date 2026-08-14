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
		t.Fatalf("key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("log ID: %v", err)
	}
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	se, err := core.SignEntry(key, &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   1754049600000,
		Issuer:     key.Public().ID(),
		Commitment: core.Commit(salt, []byte("payload")),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	entryBytes, err := se.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
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
		t.Fatalf("encode: %v", err)
	}
	got, err := ParseLeaf(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got.Version != leaf.Version || got.Log != leaf.Log ||
		got.Seq != leaf.Seq || got.LoggedAt != leaf.LoggedAt ||
		!bytes.Equal(got.Entry, leaf.Entry) {
		t.Fatalf("leaf changed across the round trip")
	}
	again, err := got.Encode()
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	if !bytes.Equal(b, again) {
		t.Error("encoding is not stable")
	}
	if got.EntryID() != core.EntryIDFromBytes(mustEntryBytes(t, leaf.Entry)) {
		t.Error("entry ID does not match")
	}
	if err := got.Verify(leaf.Log, key.Public()); err != nil {
		t.Errorf("verify: %v", err)
	}
}

func TestLeafVerifyRejectsForeignLog(t *testing.T) {
	leaf, key := testLeaf(t)
	other := leaf.Log
	other[0] ^= 0xff
	if err := leaf.Verify(other, key.Public()); !errors.Is(err, ErrLogMismatch) {
		t.Errorf("foreign log accepted: %v", err)
	}
}

func TestLeafVerifyRejectsTamperedEntry(t *testing.T) {
	leaf, key := testLeaf(t)
	// One flipped bit in the signature of the embedded entry. That is exactly
	// why the signed entry sits in the leaf and not merely its identifier.
	tampered := append([]byte(nil), leaf.Entry...)
	tampered[len(tampered)-1] ^= 0x01
	leaf.Entry = tampered
	if err := leaf.Verify(leaf.Log, key.Public()); err == nil {
		t.Error("tampered signature accepted")
	}
}

func TestLeafRejectsNonCanonical(t *testing.T) {
	leaf, _ := testLeaf(t)
	b, err := leaf.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// a5 = map with 5 pairs, then key 1 and value 1 in minimal form.
	if len(b) < 3 || b[0] != 0xa5 || b[1] != 0x01 || b[2] != 0x01 {
		t.Fatalf("unexpected encoding: %x", b[:3])
	}
	// The same number in non-minimal form (0x18 0x01). CBOR reads that as 1,
	// but it is a second encoding of the same leaf — and thereby a second leaf
	// hash for the same content.
	noncanon := make([]byte, 0, len(b)+1)
	noncanon = append(noncanon, b[:2]...)
	noncanon = append(noncanon, 0x18, 0x01)
	noncanon = append(noncanon, b[3:]...)

	if _, err := ParseLeaf(noncanon); !errors.Is(err, core.ErrNotCanonical) {
		t.Errorf("non-canonical encoding accepted: %v", err)
	}
}

func TestLeafRejectsTrailingData(t *testing.T) {
	leaf, _ := testLeaf(t)
	b, err := leaf.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := ParseLeaf(append(b, 0x00)); err == nil {
		t.Error("trailing bytes accepted")
	}
}

func TestLeafValidate(t *testing.T) {
	base, _ := testLeaf(t)
	tests := []struct {
		name   string
		mutate func(*Leaf)
		want   error
	}{
		{"wrong version", func(l *Leaf) { l.Version = 2 }, ErrLeafVersion},
		{"without log", func(l *Leaf) { l.Log = core.LogID{} }, ErrMissingField},
		{"without timestamp", func(l *Leaf) { l.LoggedAt = 0 }, ErrMissingField},
		{"without entry", func(l *Leaf) { l.Entry = nil }, ErrMissingField},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := *base
			tc.mutate(&l)
			if err := l.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, expected %v", err, tc.want)
			}
		})
	}
	// Seq 0 is valid: the first leaf of a log has position 0.
	l := *base
	l.Seq = 0
	if err := l.Validate(); err != nil {
		t.Errorf("position 0 rejected: %v", err)
	}
}

func TestLeafSizeLimit(t *testing.T) {
	leaf, _ := testLeaf(t)
	leaf.Entry = make([]byte, MaxLeafSize+1)
	for i := range leaf.Entry {
		leaf.Entry[i] = 0x41
	}
	if _, err := leaf.Encode(); !errors.Is(err, ErrLeafSize) {
		t.Errorf("oversized leaf encoded: %v", err)
	}
	if _, err := ParseLeaf(make([]byte, MaxLeafSize+1)); !errors.Is(err, ErrLeafSize) {
		t.Errorf("oversized input read: %v", err)
	}
}

func testSTH(t *testing.T, key *core.PrivateKey) *STH {
	t.Helper()
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("log ID: %v", err)
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
		t.Fatalf("key: %v", err)
	}
	sth := testSTH(t, key)
	signed, err := SignSTH(key, sth)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := signed.Verify(key.Public()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	b, err := signed.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := ParseSignedSTH(b)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := got.Verify(key.Public()); err != nil {
		t.Fatalf("verify after the round trip: %v", err)
	}
	inner, err := got.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	if *inner != *sth {
		t.Errorf("STH changed across the round trip")
	}
	if _, err := ParseSignedSTH(append(b, 0x00)); err == nil {
		t.Error("trailing bytes accepted")
	}
}

func TestSTHVerifyRejectsTampering(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	signed, err := SignSTH(key, testSTH(t, key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	t.Run("root", func(t *testing.T) {
		bad := &SignedSTH{
			STHBytes:  append([]byte(nil), signed.STHBytes...),
			Alg:       signed.Alg,
			Signature: signed.Signature,
		}
		bad.STHBytes[len(bad.STHBytes)-1] ^= 0x01
		if err := bad.Verify(key.Public()); err == nil {
			t.Error("tampered STH accepted")
		}
	})

	t.Run("signature", func(t *testing.T) {
		bad := &SignedSTH{
			STHBytes:  signed.STHBytes,
			Alg:       signed.Alg,
			Signature: append([]byte(nil), signed.Signature...),
		}
		bad.Signature[0] ^= 0x01
		if !errors.Is(bad.Verify(key.Public()), ErrBadSignature) {
			t.Error("tampered signature accepted")
		}
	})

	t.Run("foreign key", func(t *testing.T) {
		other, err := core.GenerateKey(core.SigAlgMLDSA65)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		if !errors.Is(signed.Verify(other.Public()), ErrSignerMismatch) {
			t.Error("foreign key accepted")
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		small, err := core.GenerateKey(core.SigAlgMLDSA44)
		if err != nil {
			t.Fatalf("key: %v", err)
		}
		if !errors.Is(signed.Verify(small.Public()), ErrAlgMismatch) {
			t.Error("wrong algorithm accepted")
		}
	})
}

func TestSignSTHRejectsForeignSigner(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	other, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	// The STH names key as its signer, but other is meant to do the signing.
	if _, err := SignSTH(other, testSTH(t, key)); !errors.Is(err, ErrSignerMismatch) {
		t.Errorf("foreign signer accepted: %v", err)
	}
}

func TestSTHValidate(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA44)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	base := testSTH(t, key)
	tests := []struct {
		name   string
		mutate func(*STH)
		want   error
	}{
		{"wrong version", func(s *STH) { s.Version = 2 }, ErrSTHVersion},
		{"without log", func(s *STH) { s.Log = core.LogID{} }, ErrMissingField},
		{"without timestamp", func(s *STH) { s.IssuedAt = 0 }, ErrMissingField},
		{"without root", func(s *STH) { s.Root = core.Digest{} }, ErrMissingField},
		{"without key", func(s *STH) { s.Key = core.KeyID{} }, ErrMissingField},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := *base
			tc.mutate(&s)
			if err := s.Validate(); !errors.Is(err, tc.want) {
				t.Errorf("Validate = %v, expected %v", err, tc.want)
			}
		})
	}
	// The empty tree can be witnessed: size 0 is valid.
	s := *base
	s.Size = 0
	if err := s.Validate(); err != nil {
		t.Errorf("STH over the empty tree rejected: %v", err)
	}
}

func mustEntryBytes(t *testing.T, signed []byte) []byte {
	t.Helper()
	se, err := core.ParseSignedEntry(signed)
	if err != nil {
		t.Fatalf("read signed entry: %v", err)
	}
	return se.EntryBytes
}
