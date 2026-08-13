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

// STH ist ein Signed Tree Head: die Bezeugung einer Node, dass ihr Baum zu
// einem bestimmten Zeitpunkt eine bestimmte Größe und eine bestimmte Wurzel
// hatte.
//
// Das ist die einzige Aussage, die eine Node über ihr Log überhaupt macht — und
// die einzige, an der sie sich festhalten lässt. Zwei STHs derselben Node zur
// selben Größe mit verschiedenen Wurzeln sind ein von ihr selbst
// unterschriebener Beweis für Fehlverhalten.
type STH struct {
	Version uint16     `json:"v"`
	Log     core.LogID `json:"log"`
	Size    uint64     `json:"size"`

	// IssuedAt ist der Ausstellungszeitpunkt in Millisekunden seit der
	// Unix-Epoche, UTC.
	IssuedAt int64 `json:"ts"`

	Root core.Digest `json:"root"`

	// Key ist die Kennung des unterzeichnenden Schlüssels.
	//
	// Sie steht innerhalb der signierten Struktur und nicht im Umschlag. Sonst
	// ließe sich die Angabe, wer unterschrieben hat, unbemerkt austauschen — was
	// während einer Schlüsselrotation die Frage unbeantwortbar machte, ob der
	// Unterzeichner überhaupt autorisiert war.
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

// IssuedAtTime liefert den Ausstellungszeitpunkt als time.Time in UTC.
func (s *STH) IssuedAtTime() time.Time { return time.UnixMilli(s.IssuedAt).UTC() }

// Validate prüft die strukturellen Regeln aus OWM-2 §4.
//
// Size darf 0 sein: Ein STH über den leeren Baum ist gültig und dient als
// Gründungsbezeugung. Root darf auch dann nicht leer sein — der leere Baum hat
// den Wurzelhash SHA-256("").
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

// Encode liefert die kanonische CBOR-Kodierung des STH.
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

// ParseSTH liest einen STH und prüft dabei, dass die Eingabe seine kanonische
// Kodierung ist.
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

// SignedSTH ist ein STH mit Signatur.
//
// STHBytes hält die kanonische Kodierung als opaken Bytestring. Signiert und
// geprüft werden immer genau diese Bytes, nie eine neu erzeugte Kodierung —
// dieselbe Regel wie beim signierten Eintrag, aus demselben Grund.
type SignedSTH struct {
	STHBytes  []byte      `json:"sth"`
	Alg       core.SigAlg `json:"alg"`
	Signature []byte      `json:"sig"`
}

// SignSTH kodiert den STH kanonisch und signiert ihn.
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

// STH dekodiert den eingebetteten STH.
//
// Die Signatur wird dabei NICHT geprüft. Wer einem so gewonnenen STH etwas
// glaubt, ohne vorher Verify aufzurufen, hat nichts als die Behauptung eines
// Servers in der Hand.
func (s *SignedSTH) STH() (*STH, error) { return ParseSTH(s.STHBytes) }

// Verify prüft die Signatur gegen den angegebenen öffentlichen Schlüssel und
// dass der STH genau diesen Schlüssel als Unterzeichner nennt.
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

// Encode liefert die kanonische CBOR-Kodierung des signierten STH.
func (s *SignedSTH) Encode() ([]byte, error) {
	return core.MarshalCanonical(&signedSTHWire{
		STH: s.STHBytes,
		Alg: uint16(s.Alg),
		Sig: s.Signature,
	})
}

// ParseSignedSTH liest einen signierten STH und prüft dabei die Kanonizität
// beider Ebenen.
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
