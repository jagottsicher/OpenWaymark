// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"bytes"
	"testing"

	"openwaymark.org/owm/core"
)

// Blätter und STHs kommen von fremden Nodes. Alles, was hier hereinkommt, ist
// Angreifereingabe — und die einzige Zusicherung, die das Format braucht, ist:
// Was angenommen wird, ist kanonisch. Gäbe es zu einem Blatt zwei gültige
// Bytefolgen, gäbe es zwei Blatthashes für denselben Inhalt, und der
// Inklusionsbeweis verlöre seine Aussage.

func fuzzSeedKey(t *testing.F, alg core.SigAlg, fill byte) *core.PrivateKey {
	t.Helper()
	k, err := core.NewKeyFromSeed(alg, bytes.Repeat([]byte{fill}, alg.SeedSize()))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	return k
}

func FuzzParseLeaf(f *testing.F) {
	key := fuzzSeedKey(f, core.SigAlgMLDSA65, 0x31)
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		f.Fatalf("log ID: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		f.Fatalf("salt: %v", err)
	}
	se, err := core.SignEntry(key, &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Subject:    core.SubjectID{0x01},
		IssuedAt:   1754049600000,
		Issuer:     key.Public().ID(),
		Commitment: core.Commit(salt, []byte("x")),
	})
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	entryBytes, err := se.Encode()
	if err != nil {
		f.Fatalf("encode: %v", err)
	}
	leaf := &Leaf{
		Version:  FormatVersion,
		Log:      logID,
		Seq:      3,
		LoggedAt: 1754049601000,
		Entry:    entryBytes,
	}
	if b, err := leaf.Encode(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add([]byte{0xa5})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseLeaf(data)
		if err != nil {
			return
		}
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("accepted leaf cannot be encoded: %v", err)
		}
		if !bytes.Equal(data, again) {
			t.Fatalf("accepted encoding is not canonical")
		}
		// Keine dieser Funktionen darf bei beliebiger Eingabe in Panik geraten.
		_ = got.EntryID()
		_, _ = got.Hash()
		_ = got.Verify(logID, key.Public())
	})
}

func FuzzParseSTH(f *testing.F) {
	key := fuzzSeedKey(f, core.SigAlgMLDSA65, 0x32)
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		f.Fatalf("log ID: %v", err)
	}
	sth := &STH{
		Version:  FormatVersion,
		Log:      logID,
		Size:     9,
		IssuedAt: 1754049602000,
		Root:     core.Digest{0xaa},
		Key:      key.Public().ID(),
	}
	if b, err := sth.Encode(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0xa6})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseSTH(data)
		if err != nil {
			return
		}
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("accepted STH cannot be encoded: %v", err)
		}
		if !bytes.Equal(data, again) {
			t.Fatalf("accepted encoding is not canonical")
		}
		_ = CheckSTHPair(got, sth)
	})
}

func FuzzParseSignedSTH(f *testing.F) {
	key := fuzzSeedKey(f, core.SigAlgMLDSA44, 0x33)
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		f.Fatalf("log ID: %v", err)
	}
	signed, err := SignSTH(key, &STH{
		Version:  FormatVersion,
		Log:      logID,
		Size:     1,
		IssuedAt: 1754049603000,
		Root:     core.Digest{0xbb},
		Key:      key.Public().ID(),
	})
	if err != nil {
		f.Fatalf("sign: %v", err)
	}
	if b, err := signed.Encode(); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0xa3})

	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ParseSignedSTH(data)
		if err != nil {
			return
		}
		again, err := got.Encode()
		if err != nil {
			t.Fatalf("accepted envelope cannot be encoded: %v", err)
		}
		if !bytes.Equal(data, again) {
			t.Fatalf("accepted encoding is not canonical")
		}
		_ = got.Verify(key.Public())
	})
}
