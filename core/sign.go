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

// Kontextstrings nach FIPS 204. Sie binden eine Signatur an ihren
// Verwendungszweck, ohne die Nachricht selbst anzufassen — eine Eintragssignatur
// ist damit niemals als STH-Signatur verwendbar.
const (
	SigContextEntry = "OWM/1 entry"
	SigContextSTH   = "OWM/1 sth"
)

// maxSigContext ist die von FIPS 204 vorgegebene Obergrenze für ctx.
const maxSigContext = 255

// SigAlg benennt ein Signaturverfahren. Nur Post-Quantum-Verfahren; kein RSA,
// kein ECC, kein Hybridmodell.
type SigAlg uint16

const (
	// SigAlgMLDSA44 ist für Sensoren und Masseneinträge vorgesehen: 2420 Byte
	// Signatur statt 3309, was bei hoher Eintragszahl den Ausschlag gibt.
	SigAlgMLDSA44 SigAlg = 1
	// SigAlgMLDSA65 ist der Standard für Node- und Entitätsschlüssel.
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

// Valid meldet, ob der Algorithmus von dieser Formatversion unterstützt wird.
func (a SigAlg) Valid() bool { return a == SigAlgMLDSA44 || a == SigAlgMLDSA65 }

// PublicKeySize ist die Länge eines gepackten öffentlichen Schlüssels in Byte.
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

// SignatureSize ist die Länge einer Signatur in Byte.
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

// SeedSize ist die Länge des Saatwerts für NewKeyFromSeed in Byte.
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

// PublicKey ist ein öffentlicher ML-DSA-Schlüssel samt seiner Kennung.
type PublicKey struct {
	alg SigAlg
	raw []byte
	id  KeyID
	pk  any // *mldsa44.PublicKey oder *mldsa65.PublicKey, durch die Konstruktoren garantiert
}

// PrivateKey ist ein privater ML-DSA-Schlüssel.
type PrivateKey struct {
	alg SigAlg
	sk  any // *mldsa44.PrivateKey oder *mldsa65.PrivateKey
	pub *PublicKey
}

// GenerateKey erzeugt ein neues Schlüsselpaar aus dem Systemzufallsgenerator.
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

// NewKeyFromSeed leitet ein Schlüsselpaar deterministisch aus einem Saatwert ab.
// Für Testvektoren gedacht und für Verfahren, die den Saatwert selbst sicher
// verwahren — nicht dafür, einen Saatwert aus einem Passwort zu bilden.
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

// ParsePublicKey liest einen gepackten öffentlichen Schlüssel.
func ParsePublicKey(alg SigAlg, raw []byte) (*PublicKey, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(alg))
	}
	if len(raw) != alg.PublicKeySize() {
		return nil, fmt.Errorf("%w: %s expected %d bytes, got %d", ErrKeySize, alg, alg.PublicKeySize(), len(raw))
	}

	// Kopieren, damit der Aufrufer den Puffer danach weiterverwenden darf, ohne
	// den Schlüssel unter uns zu verändern.
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

// computeKeyID berechnet KeyID = H("OWM/1 key-id", u16be(alg), pubkey).
//
// Der Algorithmus geht mit ein, damit derselbe Bytestring unter zwei Verfahren
// nicht dieselbe Kennung ergibt.
func computeKeyID(alg SigAlg, raw []byte) KeyID {
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], uint16(alg))
	return KeyID(hashLabeled(labelKeyID, a[:], raw))
}

// DeriveLogID leitet die Kennung eines Logs aus seinem Gründungsschlüssel ab.
//
// Nicht aus dem jeweils aktuellen Schlüssel: Der wechselt bei einer Rotation,
// und eine mitwechselnde Log-Kennung würde jeden je ausgestellten Verweis auf
// dieses Log ungültig machen. Der Gründungsschlüssel wechselt nie, und die
// Ableitung macht die Kennung selbstzertifizierend — wer den Schlüssel hat,
// kann sie nachrechnen, ohne ein Verzeichnis zu befragen.
//
// Welche Nachfolgeschlüssel für dieses Log signieren dürfen, beantwortet die
// Rotationskette im Log selbst (OWM-3), nicht die Kennung.
func DeriveLogID(genesis *PublicKey) (LogID, error) {
	if genesis == nil {
		return LogID{}, fmt.Errorf("%w: genesis key", ErrMissingField)
	}
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], uint16(genesis.alg))
	return LogID(hashLabeled(labelLogID, a[:], genesis.raw)), nil
}

// Alg liefert das Signaturverfahren des Schlüssels.
func (p *PublicKey) Alg() SigAlg { return p.alg }

// ID liefert die Schlüsselkennung.
func (p *PublicKey) ID() KeyID { return p.id }

// Bytes liefert eine Kopie des gepackten öffentlichen Schlüssels.
func (p *PublicKey) Bytes() []byte {
	out := make([]byte, len(p.raw))
	copy(out, p.raw)
	return out
}

// Verify prüft eine Signatur gegen Nachricht und Kontext.
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

// Alg liefert das Signaturverfahren des Schlüssels.
func (k *PrivateKey) Alg() SigAlg { return k.alg }

// Public liefert den zugehörigen öffentlichen Schlüssel.
func (k *PrivateKey) Public() *PublicKey { return k.pub }

// Sign signiert eine Nachricht randomisiert ("hedged"), wie es FIPS 204 als
// Voreinstellung vorsieht. Das ist der Normalfall: Randomisierung erschwert
// Seitenkanal- und Fehlerangriffe.
func (k *PrivateKey) Sign(sigContext string, msg []byte) ([]byte, error) {
	return k.sign(sigContext, msg, true)
}

// SignDeterministic signiert ohne Zufall und liefert damit zu gleicher Eingabe
// stets dieselbe Signatur. Ausschließlich für reproduzierbare Testvektoren
// gedacht — im Betrieb ist Sign zu verwenden.
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
