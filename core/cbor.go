// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrNotCanonical meldet eine Kodierung, die nicht der kanonischen Form
// entspricht.
var ErrNotCanonical = errors.New("owm: encoding is not canonical")

// encMode ist Core Deterministic Encoding nach RFC 8949 §4.2.1: kürzestmögliche
// Argumente, keine Kodierungen unbestimmter Länge, Map-Schlüssel bytweise
// lexikographisch sortiert.
//
// decMode lehnt alles ab, was zu einer zweiten gültigen Lesart führen könnte:
// doppelte Schlüssel, unbestimmte Längen, Tags, unbekannte Felder. Ein
// Datenformat, das dieselbe Aussage auf mehrere Arten kodieren lässt, hat
// mehrere Inhaltsadressen — und dann trägt eine gültige Signatur plötzlich
// zwei verschiedene Einträge.
var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic("owm: CBOR encoder: " + err.Error())
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   8,
	}.DecMode()
	if err != nil {
		panic("owm: CBOR decoder: " + err.Error())
	}
}

// entryWire ist die Drahtform eines Eintrags: eine CBOR-Map mit
// Ganzzahlschlüsseln. Optionale Felder werden bei Abwesenheit weggelassen und
// nicht als null kodiert — sonst gäbe es zwei Kodierungen desselben Eintrags.
type entryWire struct {
	Version    uint16    `cbor:"1,keyasint"`
	Type       uint8     `cbor:"2,keyasint"`
	Profile    string    `cbor:"3,keyasint,omitempty"`
	Subject    []byte    `cbor:"4,keyasint"`
	IssuedAt   int64     `cbor:"5,keyasint"`
	Issuer     []byte    `cbor:"6,keyasint"`
	Commitment []byte    `cbor:"7,keyasint,omitempty"`
	Parents    []refWire `cbor:"8,keyasint,omitempty"`
	Target     *refWire  `cbor:"9,keyasint,omitempty"`
}

// refWire ist ein Eintragsverweis als CBOR-Array fester Länge 2. Die feste
// Länge vermeidet zwei zulässige Kodierungen desselben Verweises; ein
// unbekanntes Log steht als leerer Bytestring.
type refWire struct {
	_     struct{} `cbor:",toarray"`
	Entry []byte
	Log   []byte
}

// signedEntryWire ist die Drahtform eines signierten Eintrags.
type signedEntryWire struct {
	Entry []byte `cbor:"1,keyasint"`
	Alg   uint16 `cbor:"2,keyasint"`
	Sig   []byte `cbor:"3,keyasint"`
}

func (e *Entry) toWire() *entryWire {
	w := &entryWire{
		Version:  e.Version,
		Type:     uint8(e.Type),
		Profile:  e.Profile,
		Subject:  append([]byte(nil), e.Subject[:]...),
		IssuedAt: e.IssuedAt,
		Issuer:   append([]byte(nil), e.Issuer[:]...),
	}
	if !e.Commitment.IsZero() {
		w.Commitment = append([]byte(nil), e.Commitment[:]...)
	}
	if len(e.Parents) > 0 {
		w.Parents = make([]refWire, len(e.Parents))
		for i, p := range e.Parents {
			w.Parents[i] = *refToWire(p)
		}
	}
	if e.Target != nil {
		w.Target = refToWire(*e.Target)
	}
	return w
}

func refToWire(r EntryRef) *refWire {
	out := &refWire{Entry: append([]byte(nil), r.Entry[:]...), Log: []byte{}}
	if !r.Log.IsZero() {
		out.Log = append([]byte(nil), r.Log[:]...)
	}
	return out
}

func (w *refWire) toRef() (EntryRef, error) {
	var r EntryRef
	entry, err := DigestFromBytes(w.Entry)
	if err != nil {
		return r, fmt.Errorf("owm: reference: entry: %w", err)
	}
	r.Entry = entry
	if len(w.Log) > 0 {
		log, err := DigestFromBytes(w.Log)
		if err != nil {
			return r, fmt.Errorf("owm: reference: log: %w", err)
		}
		r.Log = LogID(log)
	}
	return r, nil
}

func (w *entryWire) toEntry() (*Entry, error) {
	subject, err := DigestFromBytes(w.Subject)
	if err != nil {
		return nil, fmt.Errorf("owm: subj: %w", err)
	}
	issuer, err := DigestFromBytes(w.Issuer)
	if err != nil {
		return nil, fmt.Errorf("owm: iss: %w", err)
	}
	e := &Entry{
		Version:  w.Version,
		Type:     EntryType(w.Type),
		Profile:  w.Profile,
		Subject:  SubjectID(subject),
		IssuedAt: w.IssuedAt,
		Issuer:   KeyID(issuer),
	}
	if len(w.Commitment) > 0 {
		c, err := DigestFromBytes(w.Commitment)
		if err != nil {
			return nil, fmt.Errorf("owm: cmt: %w", err)
		}
		e.Commitment = Commitment(c)
	}
	if len(w.Parents) > 0 {
		// Vor dem Anlegen prüfen, nicht erst in Validate: sonst reserviert ein
		// böswillig großes par-Array den Speicher, bevor jemand es ablehnt.
		if len(w.Parents) > MaxParents {
			return nil, fmt.Errorf("%w: %d, allowed %d", ErrTooManyParents, len(w.Parents), MaxParents)
		}
		e.Parents = make([]EntryRef, len(w.Parents))
		for i := range w.Parents {
			r, err := w.Parents[i].toRef()
			if err != nil {
				return nil, fmt.Errorf("owm: par[%d]: %w", i, err)
			}
			e.Parents[i] = r
		}
	}
	if w.Target != nil {
		r, err := w.Target.toRef()
		if err != nil {
			return nil, fmt.Errorf("owm: tgt: %w", err)
		}
		e.Target = &r
	}
	return e, nil
}

// Encode liefert die kanonische CBOR-Kodierung des Eintrags. Der Eintrag wird
// vorher validiert: ein ungültiger Eintrag soll gar nicht erst eine
// Inhaltsadresse bekommen.
func (e *Entry) Encode() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b, err := encMode.Marshal(e.toWire())
	if err != nil {
		return nil, fmt.Errorf("owm: encode entry: %w", err)
	}
	return b, nil
}

// ParseEntry dekodiert einen Eintrag und weist alles zurück, was nicht der
// kanonischen Form entspricht.
func ParseEntry(b []byte) (*Entry, error) {
	var w entryWire
	if err := decMode.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("owm: decode entry: %w", err)
	}
	if err := checkCanonical(b, &w); err != nil {
		return nil, err
	}
	e, err := w.toEntry()
	if err != nil {
		return nil, err
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

// Encode liefert die kanonische CBOR-Kodierung des signierten Eintrags.
func (s *SignedEntry) Encode() ([]byte, error) {
	if err := s.validateShape(); err != nil {
		return nil, err
	}
	b, err := encMode.Marshal(&signedEntryWire{
		Entry: s.EntryBytes,
		Alg:   uint16(s.Alg),
		Sig:   s.Signature,
	})
	if err != nil {
		return nil, fmt.Errorf("owm: encode signed entry: %w", err)
	}
	return b, nil
}

// ParseSignedEntry dekodiert einen signierten Eintrag. Der eingebettete Eintrag
// bleibt dabei ein opaker Bytestring — dekodiert wird er erst durch Entry(),
// signaturgeprüft durch Verify().
func ParseSignedEntry(b []byte) (*SignedEntry, error) {
	var w signedEntryWire
	if err := decMode.Unmarshal(b, &w); err != nil {
		return nil, fmt.Errorf("owm: decode signed entry: %w", err)
	}
	if err := checkCanonical(b, &w); err != nil {
		return nil, err
	}
	s := &SignedEntry{EntryBytes: w.Entry, Alg: SigAlg(w.Alg), Signature: w.Sig}
	if err := s.validateShape(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SignedEntry) validateShape() error {
	if len(s.EntryBytes) == 0 {
		return fmt.Errorf("%w: e", ErrMissingField)
	}
	if !s.Alg.Valid() {
		return fmt.Errorf("%w: %d", ErrUnknownAlg, uint16(s.Alg))
	}
	if len(s.Signature) != s.Alg.SignatureSize() {
		return fmt.Errorf("%w: %s expected %d bytes, got %d",
			ErrSigSize, s.Alg, s.Alg.SignatureSize(), len(s.Signature))
	}
	return nil
}

// checkCanonical stellt sicher, dass die Eingabe bereits kanonisch kodiert war.
//
// Die Prüfung ist mechanisch — neu kodieren und Bytes vergleichen — und deckt
// jede Abweichung ab: nicht kürzestmögliche Argumente, falsch sortierte
// Schlüssel, explizit kodierte optionale Felder. Ohne sie ließe sich eine
// gültige Signatur an eine abweichend kodierte Fassung desselben Eintrags
// heften.
// MarshalCanonical kodiert einen Wert nach denselben Regeln wie einen Eintrag.
//
// Exportiert, damit andere Pakete — vor allem log/ für Blätter und STHs —
// dieselben Regeln verwenden, statt die Optionen zu kopieren. Zwei Kopien der
// Kodierregeln laufen früher oder später auseinander, und die Folge wäre ein
// Wert, der in einem Paket kanonisch ist und im anderen nicht.
func MarshalCanonical(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// UnmarshalCanonical dekodiert und prüft dabei, dass die Eingabe die kanonische
// Kodierung des Ergebnisses ist.
//
// Die Prüfung ist mechanisch: neu kodieren und Byte für Byte vergleichen. Damit
// gibt es zu jedem Wert genau eine zulässige Kodierung — sonst trüge eine
// gültige Signatur am Ende zwei verschiedene Aussagen.
func UnmarshalCanonical(data []byte, v any) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return err
	}
	return checkCanonical(data, v)
}

func checkCanonical(orig []byte, wire any) error {
	re, err := encMode.Marshal(wire)
	if err != nil {
		return fmt.Errorf("owm: canonicality check: %w", err)
	}
	if !bytes.Equal(orig, re) {
		return ErrNotCanonical
	}
	return nil
}
