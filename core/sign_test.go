// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"errors"
	"testing"
)

var testAlgs = []SigAlg{SigAlgMLDSA44, SigAlgMLDSA65}

// keyFromSeedByte creates a reproducible test key.
func keyFromSeedByte(t *testing.T, alg SigAlg, b byte) *PrivateKey {
	t.Helper()
	k, err := NewKeyFromSeed(alg, bytes.Repeat([]byte{b}, alg.SeedSize()))
	if err != nil {
		t.Fatalf("NewKeyFromSeed(%s): %v", alg, err)
	}
	return k
}

func TestSigAlgSizes(t *testing.T) {
	// The sizes are given in the specification and are the reason for the two
	// levels — if they change, OWM-0 §3 has to change with them.
	cases := []struct {
		alg      SigAlg
		pub, sig int
	}{
		{SigAlgMLDSA44, 1312, 2420},
		{SigAlgMLDSA65, 1952, 3309},
	}
	for _, c := range cases {
		if got := c.alg.PublicKeySize(); got != c.pub {
			t.Errorf("%s: PublicKeySize = %d, the specification says %d", c.alg, got, c.pub)
		}
		if got := c.alg.SignatureSize(); got != c.sig {
			t.Errorf("%s: SignatureSize = %d, the specification says %d", c.alg, got, c.sig)
		}
	}
}

func TestSigAlgUnknown(t *testing.T) {
	var bad SigAlg = 99
	if bad.Valid() {
		t.Error("unknown algorithm is treated as valid")
	}
	if bad.PublicKeySize() != 0 || bad.SignatureSize() != 0 || bad.SeedSize() != 0 {
		t.Error("unknown algorithm returns non-zero sizes")
	}
	if _, err := GenerateKey(bad); !errors.Is(err, ErrUnknownAlg) {
		t.Errorf("GenerateKey returns %v, expected ErrUnknownAlg", err)
	}
	if _, err := ParsePublicKey(bad, nil); !errors.Is(err, ErrUnknownAlg) {
		t.Errorf("ParsePublicKey returns %v, expected ErrUnknownAlg", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	msg := []byte("a statement about a batch of eggs")
	for _, alg := range testAlgs {
		k, err := GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		sig, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("Sign(%s): %v", alg, err)
		}
		if len(sig) != alg.SignatureSize() {
			t.Errorf("%s: signature length %d, expected %d", alg, len(sig), alg.SignatureSize())
		}
		if !k.Public().Verify(SigContextEntry, msg, sig) {
			t.Errorf("%s: own signature is rejected", alg)
		}
	}
}

// TestSignatureContextSeparation covers the reason for the FIPS 204 context
// strings: an entry signature must never pass as an STH signature.
func TestSignatureContextSeparation(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x01)
	msg := []byte("the same message")
	sig, err := k.Sign(SigContextEntry, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if k.Public().Verify(SigContextSTH, msg, sig) {
		t.Error("entry signature also verifies in the STH context")
	}
	if k.Public().Verify("", msg, sig) {
		t.Error("entry signature also verifies without a context")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x02)
	msg := []byte("unmodified message")
	sig, err := k.Sign(SigContextEntry, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if k.Public().Verify(SigContextEntry, tampered, sig) {
		t.Error("modified message is accepted")
	}

	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x01
	if k.Public().Verify(SigContextEntry, msg, badSig) {
		t.Error("modified signature is accepted")
	}

	if k.Public().Verify(SigContextEntry, msg, sig[:len(sig)-1]) {
		t.Error("truncated signature is accepted")
	}

	other := keyFromSeedByte(t, SigAlgMLDSA65, 0x03)
	if other.Public().Verify(SigContextEntry, msg, sig) {
		t.Error("a foreign key confirms the signature")
	}
}

func TestSignRejectsOverlongContext(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA44, 0x04)
	long := string(bytes.Repeat([]byte("x"), maxSigContext+1))
	if _, err := k.Sign(long, []byte("x")); !errors.Is(err, ErrContextTooLong) {
		t.Errorf("Sign returns %v, expected ErrContextTooLong", err)
	}
	if k.Public().Verify(long, []byte("x"), make([]byte, SigAlgMLDSA44.SignatureSize())) {
		t.Error("Verify accepts an oversized context")
	}
}

func TestKeyFromSeedIsDeterministic(t *testing.T) {
	for _, alg := range testAlgs {
		a := keyFromSeedByte(t, alg, 0x05)
		b := keyFromSeedByte(t, alg, 0x05)
		if !bytes.Equal(a.Public().Bytes(), b.Public().Bytes()) {
			t.Errorf("%s: the same seed produces different keys", alg)
		}
		if a.Public().ID() != b.Public().ID() {
			t.Errorf("%s: the same key produces different identifiers", alg)
		}
		c := keyFromSeedByte(t, alg, 0x06)
		if a.Public().ID() == c.Public().ID() {
			t.Errorf("%s: different seeds produce the same identifier", alg)
		}
	}
}

func TestNewKeyFromSeedRejectsWrongLength(t *testing.T) {
	for _, alg := range testAlgs {
		for _, n := range []int{0, alg.SeedSize() - 1, alg.SeedSize() + 1} {
			if _, err := NewKeyFromSeed(alg, make([]byte, n)); !errors.Is(err, ErrKeySize) {
				t.Errorf("%s: seed length %d returns %v, expected ErrKeySize", alg, n, err)
			}
		}
	}
}

// TestKeyIDBindsAlgorithm records why the algorithm enters the key identifier:
// the same byte string must not yield the same identifier under two schemes.
func TestKeyIDBindsAlgorithm(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, 64)
	if computeKeyID(SigAlgMLDSA44, raw) == computeKeyID(SigAlgMLDSA65, raw) {
		t.Error("the algorithm does not enter the key identifier")
	}
}

func TestParsePublicKeyRoundTrip(t *testing.T) {
	for _, alg := range testAlgs {
		k := keyFromSeedByte(t, alg, 0x07)
		raw := k.Public().Bytes()

		pub, err := ParsePublicKey(alg, raw)
		if err != nil {
			t.Fatalf("%s: ParsePublicKey: %v", alg, err)
		}
		if pub.ID() != k.Public().ID() {
			t.Errorf("%s: identifier differs after the round trip", alg)
		}

		msg := []byte("verified with the parsed key")
		sig, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		if !pub.Verify(SigContextEntry, msg, sig) {
			t.Errorf("%s: parsed key does not verify", alg)
		}
	}
}

func TestParsePublicKeyRejectsWrongLength(t *testing.T) {
	for _, alg := range testAlgs {
		for _, n := range []int{0, alg.PublicKeySize() - 1, alg.PublicKeySize() + 1} {
			if _, err := ParsePublicKey(alg, make([]byte, n)); !errors.Is(err, ErrKeySize) {
				t.Errorf("%s: length %d returns %v, expected ErrKeySize", alg, n, err)
			}
		}
	}
}

// TestPublicKeyBytesIsCopy makes sure the caller cannot change the key under
// us.
func TestPublicKeyBytesIsCopy(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x08)
	raw := k.Public().Bytes()
	raw[0] ^= 0xFF
	if bytes.Equal(raw, k.Public().Bytes()) {
		t.Error("Bytes() hands out the internal buffer")
	}

	buf := k.Public().Bytes()
	pub, err := ParsePublicKey(SigAlgMLDSA65, buf)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	before := pub.ID()
	buf[0] ^= 0xFF
	if pub.ID() != before {
		t.Error("ParsePublicKey keeps the caller's buffer")
	}
}

func TestSignDeterministicIsStable(t *testing.T) {
	msg := []byte("test vectors require reproducible signatures")
	for _, alg := range testAlgs {
		k := keyFromSeedByte(t, alg, 0x09)
		a, err := k.SignDeterministic(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: SignDeterministic: %v", alg, err)
		}
		b, err := k.SignDeterministic(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: SignDeterministic: %v", alg, err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s: deterministic signature is not stable", alg)
		}
		if !k.Public().Verify(SigContextEntry, msg, a) {
			t.Errorf("%s: deterministic signature does not verify", alg)
		}

		// The normal case is randomised; identical signatures here would be a
		// sign that the randomisation is not taking effect.
		r1, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		r2, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		if bytes.Equal(r1, r2) {
			t.Errorf("%s: Sign returns the same signature twice", alg)
		}
	}
}

func TestVerifyNilKey(t *testing.T) {
	var pub *PublicKey
	if pub.Verify(SigContextEntry, []byte("x"), []byte("y")) {
		t.Error("a nil key confirms a signature")
	}
}
