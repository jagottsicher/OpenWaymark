// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"errors"
	"fmt"
	"time"

	"openwaymark.org/owm/core"
)

var (
	ErrSTHVersion     = errors.New("owm/log: unknown STH version")
	ErrSignerMismatch = errors.New("owm/log: signer does not match the key")
	ErrBadSignature   = errors.New("owm/log: invalid signature")
	ErrAlgMismatch    = errors.New("owm/log: signature algorithm does not match the key")
)

// STH is a Signed Tree Head: a node's witness that its tree had a particular
// size and a particular root at a particular point in time.
//
// This is the only statement a node makes about its log at all — and the only
// one it can be held to. Two STHs from the same node for the same size but with
// different roots are proof of misbehaviour, signed by the node itself.
type STH struct {
	Version uint16     `json:"v"`
	Log     core.LogID `json:"log"`
	Size    uint64     `json:"size"`

	// IssuedAt is the issuance timestamp in milliseconds since the Unix epoch,
	// UTC.
	IssuedAt int64 `json:"ts"`

	Root core.Digest `json:"root"`

	// Key is the identifier of the signing key.
	//
	// It sits inside the signed structure and not in the envelope. Otherwise
	// the statement of who signed could be swapped out unnoticed — which during
	// a key rotation would make it impossible to answer whether the signer was
	// authorised at all.
	Key core.KeyID `json:"key"`
}

type sthWire struct {
	Version  uint16 `cbor:"1,keyasint"`
	Log      []byte `cbor:"2,keyasint"`
	Size     uint64 `cbor:"3,keyasint"`
	IssuedAt int64  `cbor:"4,keyasint"`
	Root     []byte `cbor:"5,keyasint"`
	Key      []byte `cbor:"6,keyasint"`
}

type signedSTHWire struct {
	STH []byte `cbor:"1,keyasint"`
	Alg uint16 `cbor:"2,keyasint"`
	Sig []byte `cbor:"3,keyasint"`
}

// IssuedAtTime returns the issuance timestamp as a time.Time in UTC.
func (s *STH) IssuedAtTime() time.Time { return time.UnixMilli(s.IssuedAt).UTC() }

// Validate checks the structural rules from OWM-2 §4.
//
// Size may be 0: an STH over the empty tree is valid and serves as a founding
// witness. Root must not be empty even then — the empty tree has the root hash
// SHA-256("").
func (s *STH) Validate() error {
	if s.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrSTHVersion, s.Version)
	}
	if s.Log.IsZero() {
		return fmt.Errorf("%w: log", ErrMissingField)
	}
	if s.IssuedAt <= 0 {
		return fmt.Errorf("%w: ts", ErrMissingField)
	}
	if s.Root.IsZero() {
		return fmt.Errorf("%w: root", ErrMissingField)
	}
	if s.Key.IsZero() {
		return fmt.Errorf("%w: key", ErrMissingField)
	}
	return nil
}

// Encode returns the canonical CBOR encoding of the STH.
func (s *STH) Encode() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	b, err := core.MarshalCanonical(&sthWire{
		Version:  s.Version,
		Log:      append([]byte(nil), s.Log[:]...),
		Size:     s.Size,
		IssuedAt: s.IssuedAt,
		Root:     append([]byte(nil), s.Root[:]...),
		Key:      append([]byte(nil), s.Key[:]...),
	})
	if err != nil {
		return nil, fmt.Errorf("owm/log: encode STH: %w", err)
	}
	return b, nil
}

// ParseSTH reads an STH, checking along the way that the input is its canonical
// encoding.
func ParseSTH(b []byte) (*STH, error) {
	var w sthWire
	if err := core.UnmarshalCanonical(b, &w); err != nil {
		return nil, fmt.Errorf("owm/log: read STH: %w", err)
	}
	logID, err := core.DigestFromBytes(w.Log)
	if err != nil {
		return nil, fmt.Errorf("owm/log: STH: log: %w", err)
	}
	root, err := core.DigestFromBytes(w.Root)
	if err != nil {
		return nil, fmt.Errorf("owm/log: STH: root: %w", err)
	}
	key, err := core.DigestFromBytes(w.Key)
	if err != nil {
		return nil, fmt.Errorf("owm/log: STH: key: %w", err)
	}
	s := &STH{
		Version:  w.Version,
		Log:      core.LogID(logID),
		Size:     w.Size,
		IssuedAt: w.IssuedAt,
		Root:     root,
		Key:      core.KeyID(key),
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// SignedSTH is an STH together with its signature.
//
// STHBytes holds the canonical encoding as an opaque byte string. What is
// signed and verified are always exactly those bytes, never a freshly produced
// encoding — the same rule as for the signed entry, for the same reason.
type SignedSTH struct {
	STHBytes  []byte      `json:"sth"`
	Alg       core.SigAlg `json:"alg"`
	Signature []byte      `json:"sig"`
}

// SignSTH encodes the STH canonically and signs it.
func SignSTH(k *core.PrivateKey, s *STH) (*SignedSTH, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: private key", ErrMissingField)
	}
	if s.Key != k.Public().ID() {
		return nil, fmt.Errorf("%w: key=%s, public key=%s", ErrSignerMismatch, s.Key, k.Public().ID())
	}
	b, err := s.Encode()
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(core.SigContextSTH, b)
	if err != nil {
		return nil, err
	}
	return &SignedSTH{STHBytes: b, Alg: k.Alg(), Signature: sig}, nil
}

// STH decodes the embedded STH.
//
// The signature is NOT checked in the process. Anyone who believes an STH
// obtained this way without calling Verify first holds nothing but a server's
// assertion.
func (s *SignedSTH) STH() (*STH, error) { return ParseSTH(s.STHBytes) }

// Verify checks the signature against the given public key, and that the STH
// names exactly this key as its signer.
func (s *SignedSTH) Verify(pub *core.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: public key", ErrMissingField)
	}
	if s.Alg != pub.Alg() {
		return fmt.Errorf("%w: STH %s, key %s", ErrAlgMismatch, s.Alg, pub.Alg())
	}
	sth, err := s.STH()
	if err != nil {
		return err
	}
	if sth.Key != pub.ID() {
		return fmt.Errorf("%w: key=%s, public key=%s", ErrSignerMismatch, sth.Key, pub.ID())
	}
	if !pub.Verify(core.SigContextSTH, s.STHBytes, s.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Encode returns the canonical CBOR encoding of the signed STH.
func (s *SignedSTH) Encode() ([]byte, error) {
	return core.MarshalCanonical(&signedSTHWire{
		STH: s.STHBytes,
		Alg: uint16(s.Alg),
		Sig: s.Signature,
	})
}

// ParseSignedSTH reads a signed STH, checking canonicity at both levels.
func ParseSignedSTH(b []byte) (*SignedSTH, error) {
	var w signedSTHWire
	if err := core.UnmarshalCanonical(b, &w); err != nil {
		return nil, fmt.Errorf("owm/log: signed STH: %w", err)
	}
	s := &SignedSTH{STHBytes: w.STH, Alg: core.SigAlg(w.Alg), Signature: w.Sig}
	if !s.Alg.Valid() {
		return nil, fmt.Errorf("owm/log: signed STH: %w: %d", core.ErrUnknownAlg, w.Alg)
	}
	if len(s.Signature) != s.Alg.SignatureSize() {
		return nil, fmt.Errorf("owm/log: signed STH: %w", core.ErrSigSize)
	}
	if _, err := s.STH(); err != nil {
		return nil, err
	}
	return s, nil
}
