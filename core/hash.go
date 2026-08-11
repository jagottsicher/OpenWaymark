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

// DigestSize ist die Länge aller Kennungen und Commitments in Byte.
//
// SHA-256 und nicht SHA-384, obwohl OpenWaymark sonst durchgängig
// post-quantum-sicher ausgelegt ist: 128 Bit Kollisionsresistenz sind auch
// gegen Quantenangriffe ausreichend, und SHA-256 hält die Kompatibilität zu
// RFC 6962. Begründung in spec/owm-0-overview.md §3.1.
const DigestSize = sha256.Size

// Bezeichnungen zur Domänentrennung. Jeder Hashwert ist an genau einen
// Verwendungszweck gebunden, damit ein Wert aus einem Kontext niemals in einem
// anderen gültig ist.
const (
	labelKeyID     = "OWM/1 key-id"
	labelEntryID   = "OWM/1 entry-id"
	labelSubjectID = "OWM/1 subject-id"
	labelCommit    = "OWM/1 commit"
)

// Digest ist ein SHA-256-Hashwert.
type Digest [DigestSize]byte

// KeyID kennzeichnet einen öffentlichen Schlüssel, SubjectID ein Subjekt,
// Commitment eine off-chain gehaltene Nutzlast. Alle drei sind eigene Typen und
// keine Aliase, damit der Compiler eine Verwechslung im Eintrag aufdeckt — der
// Unterschied zwischen Aussteller und Subjekt ist sicherheitsrelevant und würde
// sich sonst still auswirken.
type (
	KeyID      Digest
	SubjectID  Digest
	Commitment Digest
)

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// IsZero meldet, ob der Wert uninitialisiert ist. Ein Nullwert ist in einem
// Eintrag nie zulässig, sondern immer ein vergessenes Feld.
func (d Digest) IsZero() bool { return d == Digest{} }

func (d Digest) MarshalText() ([]byte, error) {
	out := make([]byte, hex.EncodedLen(len(d)))
	hex.Encode(out, d[:])
	return out, nil
}

func (d *Digest) UnmarshalText(text []byte) error {
	if len(text) != hex.EncodedLen(DigestSize) {
		return fmt.Errorf("owm: digest: erwartet %d Hexzeichen, erhalten %d", hex.EncodedLen(DigestSize), len(text))
	}
	if _, err := hex.Decode(d[:], text); err != nil {
		return fmt.Errorf("owm: digest: %w", err)
	}
	return nil
}

// ParseDigest liest einen hexkodierten Hashwert.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	err := d.UnmarshalText([]byte(s))
	return d, err
}

// DigestFromBytes übernimmt genau DigestSize Byte in einen Digest.
func DigestFromBytes(b []byte) (Digest, error) {
	var d Digest
	if len(b) != DigestSize {
		return d, fmt.Errorf("owm: digest: erwartet %d Byte, erhalten %d", DigestSize, len(b))
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

// hashLabeled berechnet
//
//	SHA-256( u8(len(label)) ‖ label ‖ u64be(len(p₁)) ‖ p₁ ‖ … )
//
// Die Längenpräfixe machen die Eingabe präfixfrei: keine zwei verschiedenen
// Argumentlisten erzeugen denselben Hashinput. Ohne sie ließe sich etwa ein
// Namensraum teilweise in den Wert verschieben, ohne den Hash zu ändern.
func hashLabeled(label string, parts ...[]byte) Digest {
	if len(label) > 255 {
		panic("owm: hashLabeled: Bezeichnung länger als 255 Byte")
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

// DeriveSubjectID leitet eine Subjekt-ID aus Kennzeichnungssystem und
// Bezeichner ab, etwa aus "gs1:sgtin" und einer SGTIN.
//
// Das ist bequem, aber keine Vertraulichkeitsmaßnahme: Wer den Namensraum und
// einen kleinen Wertebereich kennt, kann die ID durchprobieren. Wo das
// Verknüpfbarkeit erzeugen würde, ist NewSubjectID zu verwenden.
func DeriveSubjectID(namespace string, value []byte) SubjectID {
	return SubjectID(hashLabeled(labelSubjectID, []byte(namespace), value))
}

// NewSubjectID zieht eine zufällige, nicht ableitbare Subjekt-ID.
func NewSubjectID() (SubjectID, error) {
	var s SubjectID
	if _, err := rand.Read(s[:]); err != nil {
		return s, fmt.Errorf("owm: subject-id: %w", err)
	}
	return s, nil
}
