// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// DigestSize is the length of every identifier and commitment in bytes.
//
// SHA-256 rather than SHA-384, even though OpenWaymark is otherwise designed to
// be post-quantum secure throughout: 128 bits of collision resistance are
// sufficient against quantum attacks too, and SHA-256 keeps compatibility with
// RFC 6962. Rationale in spec/owm-0-overview.md §3.1.
const DigestSize = sha256.Size

// Labels for domain separation. Every hash value is bound to exactly one
// purpose, so that a value from one context is never valid in another.
const (
	labelKeyID     = "OWM/1 key-id"
	labelEntryID   = "OWM/1 entry-id"
	labelSubjectID = "OWM/1 subject-id"
	labelCommit    = "OWM/1 commit"
	labelLogID     = "OWM/1 log-id"
)

// Digest is a SHA-256 hash value.
type Digest [DigestSize]byte

// KeyID identifies a public key, SubjectID a subject, Commitment a payload held
// off-chain, LogID a log. All four are distinct types rather than aliases, so
// that the compiler catches a mix-up inside an entry — the difference between
// issuer and subject is security relevant and would otherwise go unnoticed.
type (
	KeyID      Digest
	SubjectID  Digest
	Commitment Digest
	LogID      Digest
)

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether the value is uninitialised. A zero value is never
// legitimate in an entry, it is always a forgotten field.
func (d Digest) IsZero() bool { return d == Digest{} }

func (d Digest) MarshalText() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(d)))
	hex.Encode(out, d[:])
	return out, nil
}

func (d *Digest) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(DigestSize) {
		return fmt.Errorf("owm: digest: expected %d hex characters, got %d", hex.EncodedLen(DigestSize), len(text))
	}
	if _, err := hex.Decode(d[:], text); err != nil {
		return fmt.Errorf("owm: digest: %w", err)
	}
	return nil
}

// ParseDigest reads a hex-encoded hash value.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	err := d.UnmarshalText([]byte(s))
	return d, err
}

// DigestFromBytes takes exactly DigestSize bytes into a Digest.
func DigestFromBytes(b []byte) (Digest, error) {
	var d Digest
	if len(b) != DigestSize {
		return d, fmt.Errorf("owm: digest: expected %d bytes, got %d", DigestSize, len(b))
	}
	copy(d[:], b)
	return d, nil
}

func (k KeyID) String() string                { return Digest(k).String() }
func (k KeyID) IsZero() bool                  { return Digest(k).IsZero() }
func (k KeyID) MarshalText() ([]byte, error)  { return Digest(k).MarshalText() }
func (k *KeyID) UnmarshalText(t []byte) error { return (*Digest)(k).UnmarshalText(t) }

func (s SubjectID) String() string                { return Digest(s).String() }
func (s SubjectID) IsZero() bool                  { return Digest(s).IsZero() }
func (s SubjectID) MarshalText() ([]byte, error)  { return Digest(s).MarshalText() }
func (s *SubjectID) UnmarshalText(t []byte) error { return (*Digest)(s).UnmarshalText(t) }

func (c Commitment) String() string                { return Digest(c).String() }
func (c Commitment) IsZero() bool                  { return Digest(c).IsZero() }
func (c Commitment) MarshalText() ([]byte, error)  { return Digest(c).MarshalText() }
func (c *Commitment) UnmarshalText(t []byte) error { return (*Digest)(c).UnmarshalText(t) }

func (l LogID) String() string                { return Digest(l).String() }
func (l LogID) IsZero() bool                  { return Digest(l).IsZero() }
func (l LogID) MarshalText() ([]byte, error)  { return Digest(l).MarshalText() }
func (l *LogID) UnmarshalText(t []byte) error { return (*Digest)(l).UnmarshalText(t) }

// hashLabeled computes
//
//	SHA-256( u8(len(label)) ‖ label ‖ u64be(len(p₁)) ‖ p₁ ‖ … )
//
// The length prefixes make the input prefix-free: no two different argument
// lists produce the same hash input. Without them one could, for instance,
// shift part of a namespace into the value without changing the hash.
func hashLabeled(label string, parts ...[]byte) Digest {
	if len(label) > 255 {
		panic("owm: hashLabeled: label longer than 255 bytes")
	}
	h := sha256.New()
	h.Write([]byte{byte(len(label))})
	h.Write([]byte(label))
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		h.Write(n[:])
		h.Write(p)
	}
	var d Digest
	h.Sum(d[:0])
	return d
}

// DeriveSubjectID derives a subject ID from an identification scheme and an
// identifier, for example from "gs1:sgtin" and an SGTIN.
//
// This is convenient but not a confidentiality measure: anyone who knows the
// namespace and a small value range can guess the ID by enumeration. Where that
// would create linkability, use NewSubjectID instead.
func DeriveSubjectID(namespace string, value []byte) SubjectID {
	return SubjectID(hashLabeled(labelSubjectID, []byte(namespace), value))
}

// NewSubjectID draws a random subject ID that cannot be derived.
func NewSubjectID() (SubjectID, error) {
	var s SubjectID
	if _, err := rand.Read(s[:]); err != nil {
		return s, fmt.Errorf("owm: subject-id: %w", err)
	}
	return s, nil
}
