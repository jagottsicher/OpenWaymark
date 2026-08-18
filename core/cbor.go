// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ErrNotCanonical reports an encoding that is not in canonical form.
var ErrNotCanonical = errors.New("owm: encoding is not canonical")

// encMode is Core Deterministic Encoding per RFC 8949 §4.2.1: shortest possible
// arguments, no indefinite-length encodings, map keys sorted bytewise in
// lexicographic order.
//
// decMode rejects everything that could yield a second valid reading: duplicate
// keys, indefinite lengths, tags, unknown fields. A data format that lets the
// same statement be encoded in several ways has several content addresses — and
// then one valid signature suddenly covers two different entries.
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

	// Simple values null (22) and undefined (23) are rejected outright,
	// for every field of every wire type, not merely at the top level.
	// Nothing in this format ever legitimately encodes either: an absent
	// optional field is omitted from the map, never present-but-null (see
	// entryWire's own comment on this), and a fixed-length array element
	// such as refWire.Log stands for "no value" as an empty byte string,
	// never as null.
	//
	// Without this, null and Go's nil slice collide: decoding null into a
	// []byte field yields the same nil as decoding an absent field would,
	// and the two are indistinguishable afterwards. checkCanonical below
	// only catches this at the wire-struct level (decode, re-encode the
	// SAME struct, compare) — a nil slice marshals back to null just as
	// faithfully as it was read, so that self-check passes. The break only
	// surfaces one layer up, when the *domain* type (Entry, not entryWire)
	// is re-encoded through its own accessor (refToWire always emits an
	// explicit empty byte string for "no log", never null) — exactly what
	// FuzzParseEntry checks and what caught this. Closing it at the
	// decoder removes the second representation before it can appear at
	// all, instead of trying to detect the mismatch after the fact for
	// every optional field individually.
	simpleValues, err := cbor.NewSimpleValueRegistryFromDefaults(
		cbor.WithRejectedSimpleValue(cbor.SimpleValue(22)), // null
		cbor.WithRejectedSimpleValue(cbor.SimpleValue(23)), // undefined
	)
	if err != nil {
		panic("owm: CBOR decoder: " + err.Error())
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		MaxNestedLevels:   8,
		SimpleValues:      simpleValues,
	}.DecMode()
	if err != nil {
		panic("owm: CBOR decoder: " + err.Error())
	}
}

// entryWire is the wire form of an entry: a CBOR map with integer keys.
// Optional fields are omitted when absent rather than encoded as null —
// otherwise there would be two encodings of the same entry.
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

// refWire is an entry reference as a CBOR array of fixed length 2. The fixed
// length avoids two admissible encodings of the same reference; an unknown log
// is written as an empty byte string.
type refWire struct {
	_     struct{} `cbor:",toarray"`
	Entry []byte
	Log   []byte
}

// signedEntryWire is the wire form of a signed entry.
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
		// Check before allocating, not later in Validate: otherwise a
		// maliciously large par array claims the memory before anyone
		// rejects it.
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

// Encode returns the canonical CBOR encoding of the entry. The entry is
// validated first: an invalid entry should not get a content address in the
// first place.
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

// ParseEntry decodes an entry and rejects everything that is not in canonical
// form.
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

// Encode returns the canonical CBOR encoding of the signed entry.
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

// ParseSignedEntry decodes a signed entry. The embedded entry stays an opaque
// byte string — it is decoded only by Entry() and signature-checked only by
// Verify().
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

// MarshalCanonical encodes a value by the same rules as an entry.
//
// Exported so that other packages — above all log/ for leaves and STHs — use
// the same rules instead of copying the options. Two copies of the encoding
// rules drift apart sooner or later, and the result would be a value that is
// canonical in one package and not in the other.
func MarshalCanonical(v any) ([]byte, error) {
	return encMode.Marshal(v)
}

// UnmarshalCanonical decodes and checks along the way that the input is the
// canonical encoding of the result.
//
// The check is mechanical: re-encode and compare byte for byte. That leaves
// exactly one admissible encoding per value — otherwise a valid signature would
// end up carrying two different statements.
func UnmarshalCanonical(data []byte, v any) error {
	if err := decMode.Unmarshal(data, v); err != nil {
		return err
	}
	return checkCanonical(data, v)
}

// checkCanonical makes sure the input was already encoded canonically.
//
// The check is mechanical — re-encode and compare bytes — and covers every
// deviation: arguments that are not shortest possible, keys in the wrong order,
// optional fields encoded explicitly. Without it, a valid signature could be
// attached to a differently encoded version of the same entry.
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
