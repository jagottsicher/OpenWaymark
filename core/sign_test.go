// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"errors"
	"testing"
)

var testAlgs = []SigAlg{SigAlgMLDSA44, SigAlgMLDSA65}

// keyFromSeedByte erzeugt einen reproduzierbaren Testschlüssel.
func keyFromSeedByte(t *testing.T, alg SigAlg, b byte) *PrivateKey {
	t.Helper()
	k, err := NewKeyFromSeed(alg, bytes.Repeat([]byte{b}, alg.SeedSize()))
	if err != nil {
		t.Fatalf("NewKeyFromSeed(%s): %v", alg, err)
	}
	return k
}

func TestSigAlgSizes(t *testing.T) {
	// Die Größen stehen in der Spezifikation und sind der Grund für die zwei
	// Stufen — wenn sie sich ändern, muss OWM-0 §3 mitgeändert werden.
	cases := []struct {
		alg      SigAlg
		pub, sig int
	}{
		{SigAlgMLDSA44, 1312, 2420},
		{SigAlgMLDSA65, 1952, 3309},
	}
	for _, c := range cases {
		if got := c.alg.PublicKeySize(); got != c.pub {
			t.Errorf("%s: PublicKeySize = %d, Spezifikation sagt %d", c.alg, got, c.pub)
		}
		if got := c.alg.SignatureSize(); got != c.sig {
			t.Errorf("%s: SignatureSize = %d, Spezifikation sagt %d", c.alg, got, c.sig)
		}
	}
}

func TestSigAlgUnknown(t *testing.T) {
	var bad SigAlg = 99
	if bad.Valid() {
		t.Error("unbekannter Algorithmus gilt als gültig")
	}
	if bad.PublicKeySize() != 0 || bad.SignatureSize() != 0 || bad.SeedSize() != 0 {
		t.Error("unbekannter Algorithmus liefert Größen ungleich null")
	}
	if _, err := GenerateKey(bad); !errors.Is(err, ErrUnknownAlg) {
		t.Errorf("GenerateKey liefert %v, erwartet ErrUnknownAlg", err)
	}
	if _, err := ParsePublicKey(bad, nil); !errors.Is(err, ErrUnknownAlg) {
		t.Errorf("ParsePublicKey liefert %v, erwartet ErrUnknownAlg", err)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	msg := []byte("eine Aussage über eine Charge Eier")
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
			t.Errorf("%s: Signaturlänge %d, erwartet %d", alg, len(sig), alg.SignatureSize())
		}
		if !k.Public().Verify(SigContextEntry, msg, sig) {
			t.Errorf("%s: eigene Signatur wird abgelehnt", alg)
		}
	}
}

// TestSignatureContextSeparation ist der Grund für die FIPS-204-Kontextstrings:
// Eine Eintragssignatur darf niemals als STH-Signatur durchgehen.
func TestSignatureContextSeparation(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x01)
	msg := []byte("dieselbe Nachricht")
	sig, err := k.Sign(SigContextEntry, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if k.Public().Verify(SigContextSTH, msg, sig) {
		t.Error("Eintragssignatur gilt auch im STH-Kontext")
	}
	if k.Public().Verify("", msg, sig) {
		t.Error("Eintragssignatur gilt auch ohne Kontext")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x02)
	msg := []byte("unveränderte Nachricht")
	sig, err := k.Sign(SigContextEntry, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := append([]byte(nil), msg...)
	tampered[0] ^= 0x01
	if k.Public().Verify(SigContextEntry, tampered, sig) {
		t.Error("geänderte Nachricht wird akzeptiert")
	}

	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x01
	if k.Public().Verify(SigContextEntry, msg, badSig) {
		t.Error("geänderte Signatur wird akzeptiert")
	}

	if k.Public().Verify(SigContextEntry, msg, sig[:len(sig)-1]) {
		t.Error("verkürzte Signatur wird akzeptiert")
	}

	other := keyFromSeedByte(t, SigAlgMLDSA65, 0x03)
	if other.Public().Verify(SigContextEntry, msg, sig) {
		t.Error("fremder Schlüssel bestätigt die Signatur")
	}
}

func TestSignRejectsOverlongContext(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA44, 0x04)
	long := string(bytes.Repeat([]byte("x"), maxSigContext+1))
	if _, err := k.Sign(long, []byte("x")); !errors.Is(err, ErrContextTooLong) {
		t.Errorf("Sign liefert %v, erwartet ErrContextTooLong", err)
	}
	if k.Public().Verify(long, []byte("x"), make([]byte, SigAlgMLDSA44.SignatureSize())) {
		t.Error("Verify akzeptiert übergroßen Kontext")
	}
}

func TestKeyFromSeedIsDeterministic(t *testing.T) {
	for _, alg := range testAlgs {
		a := keyFromSeedByte(t, alg, 0x05)
		b := keyFromSeedByte(t, alg, 0x05)
		if !bytes.Equal(a.Public().Bytes(), b.Public().Bytes()) {
			t.Errorf("%s: gleicher Saatwert ergibt verschiedene Schlüssel", alg)
		}
		if a.Public().ID() != b.Public().ID() {
			t.Errorf("%s: gleicher Schlüssel ergibt verschiedene Kennungen", alg)
		}
		c := keyFromSeedByte(t, alg, 0x06)
		if a.Public().ID() == c.Public().ID() {
			t.Errorf("%s: verschiedene Saatwerte ergeben dieselbe Kennung", alg)
		}
	}
}

func TestNewKeyFromSeedRejectsWrongLength(t *testing.T) {
	for _, alg := range testAlgs {
		for _, n := range []int{0, alg.SeedSize() - 1, alg.SeedSize() + 1} {
			if _, err := NewKeyFromSeed(alg, make([]byte, n)); !errors.Is(err, ErrKeySize) {
				t.Errorf("%s: Saatwertlänge %d liefert %v, erwartet ErrKeySize", alg, n, err)
			}
		}
	}
}

// TestKeyIDBindsAlgorithm hält fest, warum der Algorithmus in die
// Schlüsselkennung eingeht: Derselbe Bytestring darf unter zwei Verfahren nicht
// dieselbe Kennung ergeben.
func TestKeyIDBindsAlgorithm(t *testing.T) {
	raw := bytes.Repeat([]byte{0xAB}, 64)
	if computeKeyID(SigAlgMLDSA44, raw) == computeKeyID(SigAlgMLDSA65, raw) {
		t.Error("Algorithmus geht nicht in die Schlüsselkennung ein")
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
			t.Errorf("%s: Kennung nach Rückweg abweichend", alg)
		}

		msg := []byte("geprüft mit dem geparsten Schlüssel")
		sig, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		if !pub.Verify(SigContextEntry, msg, sig) {
			t.Errorf("%s: geparster Schlüssel prüft nicht", alg)
		}
	}
}

func TestParsePublicKeyRejectsWrongLength(t *testing.T) {
	for _, alg := range testAlgs {
		for _, n := range []int{0, alg.PublicKeySize() - 1, alg.PublicKeySize() + 1} {
			if _, err := ParsePublicKey(alg, make([]byte, n)); !errors.Is(err, ErrKeySize) {
				t.Errorf("%s: Länge %d liefert %v, erwartet ErrKeySize", alg, n, err)
			}
		}
	}
}

// TestPublicKeyBytesIsCopy stellt sicher, dass der Aufrufer den Schlüssel nicht
// unter uns verändern kann.
func TestPublicKeyBytesIsCopy(t *testing.T) {
	k := keyFromSeedByte(t, SigAlgMLDSA65, 0x08)
	raw := k.Public().Bytes()
	raw[0] ^= 0xFF
	if bytes.Equal(raw, k.Public().Bytes()) {
		t.Error("Bytes() gibt den internen Puffer heraus")
	}

	buf := k.Public().Bytes()
	pub, err := ParsePublicKey(SigAlgMLDSA65, buf)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	before := pub.ID()
	buf[0] ^= 0xFF
	if pub.ID() != before {
		t.Error("ParsePublicKey behält den Puffer des Aufrufers")
	}
}

func TestSignDeterministicIsStable(t *testing.T) {
	msg := []byte("Testvektoren brauchen reproduzierbare Signaturen")
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
			t.Errorf("%s: deterministische Signatur ist nicht stabil", alg)
		}
		if !k.Public().Verify(SigContextEntry, msg, a) {
			t.Errorf("%s: deterministische Signatur prüft nicht", alg)
		}

		// Der Normalfall ist randomisiert; identische Signaturen wären hier
		// ein Hinweis darauf, dass die Randomisierung nicht greift.
		r1, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		r2, err := k.Sign(SigContextEntry, msg)
		if err != nil {
			t.Fatalf("%s: Sign: %v", alg, err)
		}
		if bytes.Equal(r1, r2) {
			t.Errorf("%s: Sign liefert zweimal dieselbe Signatur", alg)
		}
	}
}

func TestVerifyNilKey(t *testing.T) {
	var pub *PublicKey
	if pub.Verify(SigContextEntry, []byte("x"), []byte("y")) {
		t.Error("nil-Schlüssel bestätigt eine Signatur")
	}
}
