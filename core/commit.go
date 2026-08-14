// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// SaltSize is the length of the payload salt in bytes.
const SaltSize = 32

// Salt is the random value that binds a payload to its commitment.
//
// The salt is a secret and must be handled with the same care as a private key.
// It decides whether an erasure is really final: as long as it survives
// somewhere — in a backup, a replica, a filesystem snapshot — the payload can
// still be proven and is therefore not erased.
type Salt [SaltSize]byte

// NewSalt draws a fresh salt.
//
// Every payload needs its own. A reused salt makes identical payloads
// recognisable across entries, and survives the erasure of one entry inside the
// other.
func NewSalt() (Salt, error) {
	var s Salt
	if _, err := rand.Read(s[:]); err != nil {
		return s, fmt.Errorf("owm: salt: %w", err)
	}
	return s, nil
}

// Wipe overwrites the salt in memory. No substitute for deleting it from the
// blob store, but the right gesture at the end of processing.
func (s *Salt) Wipe() {
	for i := range s {
		s[i] = 0
	}
}

// Commit computes the payload commitment:
//
//	HMAC-SHA-256( key = salt, msg = u8(len(label)) ‖ label ‖ payload )
//
// Binding, because a second payload with the same commitment would require a
// SHA-256 collision. Hiding, because without the salt every payload is equally
// plausible — even with a value range of just a few possibilities. That is
// exactly where an unsalted hash fails: a postcode or a GPS coordinate could
// simply be enumerated.
func Commit(salt Salt, payload []byte) Commitment {
	m := hmac.New(sha256.New, salt[:])
	m.Write([]byte{byte(len(labelCommit))})
	m.Write([]byte(labelCommit))
	m.Write(payload)
	var c Commitment
	m.Sum(c[:0])
	return c
}

// VerifyCommitment checks whether salt and payload match the commitment.
func VerifyCommitment(c Commitment, salt Salt, payload []byte) bool {
	got := Commit(salt, payload)
	return hmac.Equal(c[:], got[:])
}
