// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Context strings per FIPS 204. They bind a signature to its purpose without
// touching the message itself — an entry signature can therefore never be used
// as an STH signature.
const (
	SigContextEntry   = "OWM/1 entry"
	SigContextSTH     = "OWM/1 sth"
	SigContextReceipt = "OWM/1 receipt"
)

// maxSigContext is the upper bound on ctx mandated by FIPS 204.
const maxSigContext = 255

// SigAlg names a signature scheme. Post-quantum schemes only; no RSA, no ECC,
// no hybrid model.
type SigAlg uint16

const (
	// SigAlgMLDSA44 is meant for sensors and bulk entries: 2420 bytes of
	// signature instead of 3309, which is what tips the scales at high entry
	// counts.
	SigAlgMLDSA44 SigAlg = 1
	// SigAlgMLDSA65 is the default for node and entity keys.
	SigAlgMLDSA65 SigAlg = 2
)

var (
	ErrUnknownAlg     = errors.New("owm: unknown signature algorithm")
	ErrKeySize        = errors.New("owm: wrong key length")
	ErrSigSize        = errors.New("owm: wrong signature length")
	ErrContextTooLong = errors.New("owm: signature context longer than 255 bytes")
)

func (a SigAlg) String() string {
	switch a {
	case SigAlgMLDSA44:
		return "ML-DSA-44"
	case SigAlgMLDSA65:
		return "ML-DSA-65"
	default:
		return fmt.Sprintf("SigAlg(%d)", uint16(a))
	}
}

// ParseSigAlg is the inverse of String.
//
// Needed wherever an algorithm crosses the wire as a name instead of a number
// — the node API does both: STH.alg (log/sth.go) travels as the bare uint16,
// while the key views under /owm/v1/keys/{id} and .well-known/openwaymark
// spell it out as e.g. "ML-DSA-65".
func ParseSigAlg(s string) (SigAlg, error) {
	switch s {
	case "ML-DSA-44":
		return SigAlgMLDSA44, nil
	case "ML-DSA-65":
		return SigAlgMLDSA65, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnknownAlg, s)
	}
}

// Valid reports whether this format version supports the algorithm.
func (a SigAlg) Valid() bool { return a == SigAlgMLDSA44 || a == SigAlgMLDSA65 }

// PublicKeySize is the length of a packed public key in bytes.
func (a SigAlg) PublicKeySize() int {
	switch a {
	case SigAlgMLDSA44:
		return mldsa44.PublicKeySize
	case SigAlgMLDSA65:
		return mldsa65.PublicKeySize
	default:
		return 0
	}
}

// SignatureSize is the length of a signature in bytes.
func (a SigAlg) SignatureSize() int {
	switch a {
	case SigAlgMLDSA44:
		return mldsa44.SignatureSize
	case SigAlgMLDSA65:
		return mldsa65.SignatureSize
	default:
		return 0
	}
}

// SeedSize is the length of the seed for NewKeyFromSeed in bytes.
func (a SigAlg) SeedSize() int {
	switch a {
	case SigAlgMLDSA44:
		return mldsa44.SeedSize
	case SigAlgMLDSA65:
		return mldsa65.SeedSize
	default:
		return 0
	}
}

// PublicKey is an ML-DSA public key together with its identifier.
type PublicKey struct {
	alg SigAlg
	raw []byte
	id  KeyID
	pk  any // *mldsa44.PublicKey or *mldsa65.PublicKey, guaranteed by the constructors
}

// PrivateKey is an ML-DSA private key.
type PrivateKey struct {
	alg SigAlg
	sk  any // *mldsa44.PrivateKey or *mldsa65.PrivateKey
	pub *PublicKey
}

// GenerateKey creates a new key pair from the system random number generator.
func GenerateKey(alg SigAlg) (*PrivateKey, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(alg))
	}
	seed := make([]byte, alg.SeedSize())
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("owm: key generation: %w", err)
	}
	return NewKeyFromSeed(alg, seed)
}

// NewKeyFromSeed derives a key pair deterministically from a seed. Intended for
// test vectors and for schemes that keep the seed safe themselves — not for
// turning a password into a seed.
func NewKeyFromSeed(alg SigAlg, seed []byte) (*PrivateKey, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(alg))
	}
	if len(seed) != alg.SeedSize() {
		return nil, fmt.Errorf("%w: seed expected %d bytes, got %d", ErrKeySize, alg.SeedSize(), len(seed))
	}

	switch alg {
	case SigAlgMLDSA44:
		var s [mldsa44.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa44.NewKeyFromSeed(&s)
		return newPrivateKey(alg, sk, pk, pk.Bytes()), nil
	case SigAlgMLDSA65:
		var s [mldsa65.SeedSize]byte
		copy(s[:], seed)
		pk, sk := mldsa65.NewKeyFromSeed(&s)
		return newPrivateKey(alg, sk, pk, pk.Bytes()), nil
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(alg))
	}
}

func newPrivateKey(alg SigAlg, sk, pk any, raw []byte) *PrivateKey {
	return &PrivateKey{
		alg: alg,
		sk:  sk,
		pub: &PublicKey{alg: alg, raw: raw, id: computeKeyID(alg, raw), pk: pk},
	}
}

// ParsePublicKey reads a packed public key.
func ParsePublicKey(alg SigAlg, raw []byte) (*PublicKey, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(alg))
	}
	if len(raw) != alg.PublicKeySize() {
		return nil, fmt.Errorf("%w: %s expected %d bytes, got %d", ErrKeySize, alg, alg.PublicKeySize(), len(raw))
	}

	// Copy, so that the caller may keep using the buffer afterwards without
	// changing the key under us.
	buf := make([]byte, len(raw))
	copy(buf, raw)

	var pk any
	switch alg {
	case SigAlgMLDSA44:
		k := new(mldsa44.PublicKey)
		if err := k.UnmarshalBinary(buf); err != nil {
			return nil, fmt.Errorf("owm: %s: %w", alg, err)
		}
		pk = k
	case SigAlgMLDSA65:
		k := new(mldsa65.PublicKey)
		if err := k.UnmarshalBinary(buf); err != nil {
			return nil, fmt.Errorf("owm: %s: %w", alg, err)
		}
		pk = k
	}
	return &PublicKey{alg: alg, raw: buf, id: computeKeyID(alg, buf), pk: pk}, nil
}

// computeKeyID computes KeyID = H("OWM/1 key-id", u16be(alg), pubkey).
//
// The algorithm goes into the hash so that the same byte string under two
// schemes does not yield the same identifier.
func computeKeyID(alg SigAlg, raw []byte) KeyID {
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], uint16(alg))
	return KeyID(hashLabeled(labelKeyID, a[:], raw))
}

// DeriveLogID derives the identifier of a log from its genesis key.
//
// Not from the key currently in use: that one changes on rotation, and a log ID
// changing along with it would invalidate every reference to this log ever
// issued. The genesis key never changes, and deriving from it makes the
// identifier self-certifying — anyone holding the key can recompute it without
// consulting a directory.
//
// Which successor keys may sign for this log is answered by the rotation chain
// in the log itself (OWM-3), not by the identifier.
func DeriveLogID(genesis *PublicKey) (LogID, error) {
	if genesis == nil {
		return LogID{}, fmt.Errorf("%w: genesis key", ErrMissingField)
	}
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], uint16(genesis.alg))
	return LogID(hashLabeled(labelLogID, a[:], genesis.raw)), nil
}

// Alg returns the signature scheme of the key.
func (p *PublicKey) Alg() SigAlg { return p.alg }

// ID returns the key identifier.
func (p *PublicKey) ID() KeyID { return p.id }

// Bytes returns a copy of the packed public key.
func (p *PublicKey) Bytes() []byte {
	out := make([]byte, len(p.raw))
	copy(out, p.raw)
	return out
}

// Verify checks a signature against a message and a context.
func (p *PublicKey) Verify(sigContext string, msg, sig []byte) bool {
	if p == nil || len(sig) != p.alg.SignatureSize() || len(sigContext) > maxSigContext {
		return false
	}
	ctx := []byte(sigContext)
	switch k := p.pk.(type) {
	case *mldsa44.PublicKey:
		return mldsa44.Verify(k, msg, ctx, sig)
	case *mldsa65.PublicKey:
		return mldsa65.Verify(k, msg, ctx, sig)
	default:
		return false
	}
}

// Alg returns the signature scheme of the key.
func (k *PrivateKey) Alg() SigAlg { return k.alg }

// Public returns the matching public key.
func (k *PrivateKey) Public() *PublicKey { return k.pub }

// Sign signs a message in randomised ("hedged") mode, which is what FIPS 204
// prescribes by default. This is the normal case: randomisation makes side
// channel and fault attacks harder.
func (k *PrivateKey) Sign(sigContext string, msg []byte) ([]byte, error) {
	return k.sign(sigContext, msg, true)
}

// SignDeterministic signs without randomness and therefore returns the same
// signature for the same input every time. Intended solely for reproducible
// test vectors — in production use Sign.
func (k *PrivateKey) SignDeterministic(sigContext string, msg []byte) ([]byte, error) {
	return k.sign(sigContext, msg, false)
}

func (k *PrivateKey) sign(sigContext string, msg []byte, randomized bool) ([]byte, error) {
	if len(sigContext) > maxSigContext {
		return nil, ErrContextTooLong
	}
	ctx := []byte(sigContext)
	sig := make([]byte, k.alg.SignatureSize())
	switch s := k.sk.(type) {
	case *mldsa44.PrivateKey:
		if err := mldsa44.SignTo(s, msg, ctx, randomized, sig); err != nil {
			return nil, fmt.Errorf("owm: %s: %w", k.alg, err)
		}
	case *mldsa65.PrivateKey:
		if err := mldsa65.SignTo(s, msg, ctx, randomized, sig); err != nil {
			return nil, fmt.Errorf("owm: %s: %w", k.alg, err)
		}
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(k.alg))
	}
	return sig, nil
}
