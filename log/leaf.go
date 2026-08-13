// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"errors"
	"fmt"
	"time"

	"github.com/transparency-dev/merkle/rfc6962"

	"openwaymark.org/owm/core"
)

// FormatVersion ist die Version des Blatt- und STH-Formats, die dieses Paket
// erzeugt und akzeptiert.
const FormatVersion = 1

// MaxLeafSize begrenzt ein Blatt. Ein Eintrag mit MaxParents Vorgängern und
// ML-DSA-65-Signatur liegt bei rund 72 KiB; 128 KiB lässt Luft, ohne einem
// Angreifer beliebigen Speicher zu überlassen.
const MaxLeafSize = 128 * 1024

var (
	ErrLeafVersion  = errors.New("owm/log: unknown leaf version")
	ErrLeafSize     = errors.New("owm/log: leaf too large")
	ErrMissingField = errors.New("owm/log: missing required field")
	ErrLogMismatch  = errors.New("owm/log: belongs to a different log")
)

// hasher ist die RFC-6962-Baumhashfunktion: SHA-256 mit 0x00 vor Blättern und
// 0x01 vor inneren Knoten.
//
// Das ist eine andere Domänentrennung als die aus OWM-0 §3.3 und ersetzt sie
// hier bewusst — der Vorrang liegt bei der Kompatibilität zur
// CT-Baumkonstruktion. Getrennt wird an der sicherheitskritischen Stelle
// trotzdem: Ein Blatthash kann nie als Knotenhash durchgehen.
var hasher = rfc6962.DefaultHasher

// Leaf ist ein Blatt des Logs.
//
// Es enthält den signierten Eintrag als opaken Bytestring und nicht nur dessen
// Kennung. Die Eintragskennung deckt die Signatur nicht ab (OWM-0 §4.3) — stünde
// nur sie im Blatt, wäre die Signatur nicht Teil des Baums und ließe sich
// nachträglich austauschen, ohne dass ein Inklusionsbeweis es bemerkt.
type Leaf struct {
	Version uint16     `json:"v"`
	Log     core.LogID `json:"log"`

	// Seq ist die Position im Log, beginnend bei 0.
	Seq uint64 `json:"seq"`

	// LoggedAt ist der Zeitpunkt, zu dem die Node den Eintrag aufgenommen hat,
	// in Millisekunden seit der Unix-Epoche, UTC.
	//
	// Nicht zu verwechseln mit dem Ausstellungszeitpunkt im Eintrag: Der ist die
	// Behauptung des Ausstellers, dies die Bezeugung der Node. Dass beide
	// auseinanderfallen dürfen, ist der Punkt — ein rückdatierter Eintrag ist
	// genau daran zu erkennen.
	LoggedAt int64 `json:"ts"`

	// Entry ist die kanonische Kodierung des signierten Eintrags.
	Entry []byte `json:"ent"`
}

// leafWire ist die Drahtform nach OWM-2 §3. Alle Felder sind Pflicht, deshalb
// steht nirgends omitempty — ein weggelassenes Feld wäre eine zweite Kodierung
// desselben Blattes.
type leafWire struct {
	Version  uint16 `cbor:"1,keyasint"`
	Log      []byte `cbor:"2,keyasint"`
	Seq      uint64 `cbor:"3,keyasint"`
	LoggedAt int64  `cbor:"4,keyasint"`
	Entry    []byte `cbor:"5,keyasint"`
}

// LoggedAtTime liefert den Aufnahmezeitpunkt als time.Time in UTC.
func (l *Leaf) LoggedAtTime() time.Time { return time.UnixMilli(l.LoggedAt).UTC() }

// Validate prüft die strukturellen Regeln aus OWM-2 §3.
func (l *Leaf) Validate() error {
	if l.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrLeafVersion, l.Version)
	}
	if l.Log.IsZero() {
		return fmt.Errorf("%w: log", ErrMissingField)
	}
	if l.LoggedAt <= 0 {
		return fmt.Errorf("%w: ts", ErrMissingField)
	}
	if len(l.Entry) == 0 {
		return fmt.Errorf("%w: ent", ErrMissingField)
	}
	return nil
}

// Encode liefert die kanonische CBOR-Kodierung des Blattes.
func (l *Leaf) Encode() ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	b, err := core.MarshalCanonical(&leafWire{
		Version:  l.Version,
		Log:      append([]byte(nil), l.Log[:]...),
		Seq:      l.Seq,
		LoggedAt: l.LoggedAt,
		Entry:    l.Entry,
	})
	if err != nil {
		return nil, fmt.Errorf("owm/log: encode leaf: %w", err)
	}
	if len(b) > MaxLeafSize {
		return nil, fmt.Errorf("%w: %d bytes, allowed %d", ErrLeafSize, len(b), MaxLeafSize)
	}
	return b, nil
}

// ParseLeaf liest ein Blatt und prüft dabei, dass die Eingabe seine kanonische
// Kodierung ist.
func ParseLeaf(b []byte) (*Leaf, error) {
	if len(b) > MaxLeafSize {
		return nil, fmt.Errorf("%w: %d bytes, allowed %d", ErrLeafSize, len(b), MaxLeafSize)
	}
	var w leafWire
	if err := core.UnmarshalCanonical(b, &w); err != nil {
		return nil, fmt.Errorf("owm/log: read leaf: %w", err)
	}
	id, err := core.DigestFromBytes(w.Log)
	if err != nil {
		return nil, fmt.Errorf("owm/log: leaf: log: %w", err)
	}
	l := &Leaf{
		Version:  w.Version,
		Log:      core.LogID(id),
		Seq:      w.Seq,
		LoggedAt: w.LoggedAt,
		Entry:    w.Entry,
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return l, nil
}

// SignedEntry dekodiert den eingebetteten Eintrag. Die Signatur wird dabei
// nicht geprüft; dafür ist Verify da.
func (l *Leaf) SignedEntry() (*core.SignedEntry, error) {
	return core.ParseSignedEntry(l.Entry)
}

// EntryID liefert die Inhaltsadresse des eingebetteten Eintrags.
func (l *Leaf) EntryID() core.Digest {
	return core.EntryIDFromBytes(entryBytesOf(l.Entry))
}

// entryBytesOf holt die Eintragsbytes aus einem signierten Eintrag heraus und
// liefert bei unlesbarer Eingabe einen leeren Schnipsel. Der Aufrufer hat die
// Kodierung an dieser Stelle bereits akzeptiert.
func entryBytesOf(signed []byte) []byte {
	se, err := core.ParseSignedEntry(signed)
	if err != nil {
		return nil
	}
	return se.EntryBytes
}

// Hash liefert den Blatthash nach RFC 6962: SHA-256(0x00 ‖ blatt).
func (l *Leaf) Hash() (core.Digest, error) {
	b, err := l.Encode()
	if err != nil {
		return core.Digest{}, err
	}
	return LeafHashFromBytes(b), nil
}

// LeafHashFromBytes berechnet den Blatthash aus der bereits kanonisch kodierten
// Form.
func LeafHashFromBytes(canonical []byte) core.Digest {
	var d core.Digest
	copy(d[:], hasher.HashLeaf(canonical))
	return d
}

// Verify prüft den eingebetteten Eintrag vollständig: Signatur, Aussteller,
// Struktur — und dass das Blatt zu diesem Log gehört.
//
// Die Log-Prüfung ist kein Beiwerk. Ohne sie ließe sich ein Blatt aus einem
// fremden Log übernehmen und hier als eigenes ausgeben.
func (l *Leaf) Verify(logID core.LogID, pub *core.PublicKey) error {
	if err := l.Validate(); err != nil {
		return err
	}
	if l.Log != logID {
		return fmt.Errorf("%w: leaf names %s, expected %s", ErrLogMismatch, l.Log, logID)
	}
	se, err := l.SignedEntry()
	if err != nil {
		return err
	}
	if err := se.Verify(pub); err != nil {
		return err
	}
	e, err := se.Entry()
	if err != nil {
		return err
	}
	return e.Validate()
}
