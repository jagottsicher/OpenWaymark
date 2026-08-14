// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"fmt"
	"time"
)

// FormatVersion is the version of the entry format this package produces and
// accepts.
const FormatVersion = 1

// EntryType names the kind of statement being made.
type EntryType uint8

const (
	// EntryTypeAssertion is a self-declaration about a subject: production,
	// transport, processing, handover.
	EntryTypeAssertion EntryType = 1
	// EntryTypeAttestation is a statement about another entity or key, such as
	// a certification. The subject is then the key ID of the party being
	// attested.
	EntryTypeAttestation EntryType = 2
	// EntryTypeRevocation withdraws an earlier entry: the statement was wrong
	// or no longer holds.
	EntryTypeRevocation EntryType = 3
	// EntryTypeKeyRotation announces a successor key. The payload carries the
	// new public key and is never erased.
	EntryTypeKeyRotation EntryType = 4
	// EntryTypeSensorReading is an automatically captured measurement, issued
	// by a device key.
	EntryTypeSensorReading EntryType = 5
	// EntryTypeErasure witnesses that the payload and salt of an earlier entry
	// have been deleted — the tombstone left behind by an erasure.
	//
	// Deliberately not a revocation: a revocation is a claim about the world,
	// an erasure is a fact about storage. The statement of the erased entry
	// still stands, only its evidence is gone. Without a type of its own,
	// lawful erasure could not be told apart from malicious withholding
	// (OWM-9 A3).
	EntryTypeErasure EntryType = 6
)

func (t EntryType) String() string {
	switch t {
	case EntryTypeAssertion:
		return "assertion"
	case EntryTypeAttestation:
		return "attestation"
	case EntryTypeRevocation:
		return "revocation"
	case EntryTypeKeyRotation:
		return "key_rotation"
	case EntryTypeSensorReading:
		return "sensor_reading"
	case EntryTypeErasure:
		return "erasure"
	default:
		return fmt.Sprintf("EntryType(%d)", uint8(t))
	}
}

// Valid reports whether this format version supports the type.
func (t EntryType) Valid() bool {
	return t >= EntryTypeAssertion && t <= EntryTypeErasure
}

// RefersToEntry reports whether the type names another entry and therefore has
// to carry tgt.
func (t EntryType) RefersToEntry() bool {
	return t == EntryTypeRevocation || t == EntryTypeErasure
}

// maxProfileLen bounds the profile identifier. It is an identifier, not a
// free-text field.
const maxProfileLen = 64

// MaxParents bounds the number of direct predecessors of an entry.
//
// Without a limit a single entry could tie up arbitrary amounts of memory and
// computation. The value is taken from practice: aggregating a thousand
// individual items onto a pallet is an ordinary supply-chain event, more than a
// thousand direct predecessors in one step is not.
const MaxParents = 1024

// ErrTooManyParents reports that MaxParents was exceeded.
var ErrTooManyParents = errors.New("owm: too many parents")

var (
	ErrVersion        = errors.New("owm: unknown format version")
	ErrEntryType      = errors.New("owm: unknown entry type")
	ErrMissingField   = errors.New("owm: missing required field")
	ErrUnexpectedTgt  = errors.New("owm: tgt is only allowed for revocation and erasure")
	ErrProfile        = errors.New("owm: invalid profile identifier")
	ErrIssuerMismatch = errors.New("owm: issuer does not match the key")
	ErrBadSignature   = errors.New("owm: invalid signature")
	ErrAlgMismatch    = errors.New("owm: signature algorithm does not match the key")
)

// EntryRef points at another entry.
//
// Log is a hint for retrieval and not part of the identity — the same entry can
// live in several logs. If the log is unknown, the field stays empty.
type EntryRef struct {
	Entry Digest `json:"entry"`
	Log   LogID  `json:"log,omitempty"`
}

// Entry is a statement made by an entity about a subject.
//
// The payload does not live here but off-chain; the entry only carries its
// commitment. No field of this type may contain personal data in the clear —
// not even Subject, which is an opaque identifier and not a name, an address or
// a coordinate.
type Entry struct {
	Version  uint16    `json:"v"`
	Type     EntryType `json:"typ"`
	Profile  string    `json:"prof,omitempty"`
	Subject  SubjectID `json:"subj"`
	IssuedAt int64     `json:"iat"` // milliseconds since the Unix epoch, UTC
	Issuer   KeyID     `json:"iss"`

	// Commitment is the salted commitment to the payload. Only revocation and
	// erasure may omit it — neither needs a payload of its own.
	Commitment Commitment `json:"cmt,omitempty"`

	// Parents model the supply chain as a directed acyclic graph. Several
	// parents mean a merge, several entries sharing one parent mean a split.
	// The event semantics on top of that are defined by the profile.
	Parents []EntryRef `json:"par,omitempty"`

	// Target names the entry concerned: for a revocation the entry withdrawn,
	// for an erasure the entry whose payload was deleted.
	Target *EntryRef `json:"tgt,omitempty"`
}

// IssuedAtTime returns the issuance timestamp as a time.Time in UTC.
func (e *Entry) IssuedAtTime() time.Time {
	return time.UnixMilli(e.IssuedAt).UTC()
}

// SetIssuedAt sets the issuance timestamp at millisecond resolution.
func (e *Entry) SetIssuedAt(t time.Time) {
	e.IssuedAt = t.UTC().UnixMilli()
}

// Validate checks the structural rules from spec/owm-0-overview.md §6. Whether
// the content matches the profile is checked by the profile mechanism, not by
// this package.
func (e *Entry) Validate() error {
	if e.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrVersion, e.Version)
	}
	if !e.Type.Valid() {
		return fmt.Errorf("%w: %d", ErrEntryType, uint8(e.Type))
	}
	if e.Subject.IsZero() {
		return fmt.Errorf("%w: subj", ErrMissingField)
	}
	if e.Issuer.IsZero() {
		return fmt.Errorf("%w: iss", ErrMissingField)
	}
	if e.IssuedAt <= 0 {
		return fmt.Errorf("%w: iat", ErrMissingField)
	}
	if err := validateProfile(e.Profile); err != nil {
		return err
	}

	// Revocation and erasure witness need no payload of their own; any other
	// type without a commitment states nothing.
	if e.Commitment.IsZero() && !e.Type.RefersToEntry() {
		return fmt.Errorf("%w: cmt on %s", ErrMissingField, e.Type)
	}

	switch {
	case e.Type.RefersToEntry() && e.Target == nil:
		return fmt.Errorf("%w: tgt on %s", ErrMissingField, e.Type)
	case !e.Type.RefersToEntry() && e.Target != nil:
		return fmt.Errorf("%w: %s", ErrUnexpectedTgt, e.Type)
	}
	if e.Target != nil && e.Target.Entry.IsZero() {
		return fmt.Errorf("%w: tgt.entry", ErrMissingField)
	}
	if len(e.Parents) > MaxParents {
		return fmt.Errorf("%w: %d, allowed %d", ErrTooManyParents, len(e.Parents), MaxParents)
	}
	for i, p := range e.Parents {
		if p.Entry.IsZero() {
			return fmt.Errorf("%w: par[%d].entry", ErrMissingField, i)
		}
	}
	return nil
}

// validateProfile restricts the profile identifier to an identifier character
// set. Otherwise free text, control characters or path names end up there
// sooner or later.
func validateProfile(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxProfileLen {
		return fmt.Errorf("%w: longer than %d characters", ErrProfile, maxProfileLen)
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '/', r == '-', r == '_':
		default:
			return fmt.Errorf("%w: invalid character %q", ErrProfile, r)
		}
	}
	return nil
}

// ID returns the content address of the entry.
//
// The identifier covers the entry, not its signature. That keeps it stable when
// the same entry is signed again or by several parties — ML-DSA signs
// randomised by default, so a signature-dependent identifier would not be
// reproducible.
func (e *Entry) ID() (Digest, error) {
	b, err := e.Encode()
	if err != nil {
		return Digest{}, err
	}
	return EntryIDFromBytes(b), nil
}

// EntryIDFromBytes computes the content address from the already canonically
// encoded form.
func EntryIDFromBytes(canonical []byte) Digest {
	return hashLabeled(labelEntryID, canonical)
}

// SignedEntry is an entry together with its signature.
//
// EntryBytes holds the canonical encoding as an opaque byte string. What is
// signed and verified are always exactly those bytes; a re-encoding that might
// differ never happens. The lesson comes from JWS and COSE, where precisely
// this ambiguity led to security holes.
type SignedEntry struct {
	EntryBytes []byte `json:"e"`
	Alg        SigAlg `json:"alg"`
	Signature  []byte `json:"sig"`
}

// SignEntry encodes the entry canonically and signs it.
//
// The issuer named in the entry must match the key; otherwise the result would
// be an entry that carries a valid signature but cannot be attributed to
// anyone.
func SignEntry(k *PrivateKey, e *Entry) (*SignedEntry, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: private key", ErrMissingField)
	}
	if e.Issuer != k.Public().ID() {
		return nil, fmt.Errorf("%w: iss=%s, key=%s", ErrIssuerMismatch, e.Issuer, k.Public().ID())
	}
	b, err := e.Encode()
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(SigContextEntry, b)
	if err != nil {
		return nil, err
	}
	return &SignedEntry{EntryBytes: b, Alg: k.Alg(), Signature: sig}, nil
}

// Entry decodes the embedded entry, checking its canonicity along the way.
func (s *SignedEntry) Entry() (*Entry, error) {
	return ParseEntry(s.EntryBytes)
}

// EntryID returns the content address of the embedded entry.
func (s *SignedEntry) EntryID() Digest {
	return EntryIDFromBytes(s.EntryBytes)
}

// Verify checks the signature against the given public key.
//
// It explicitly also checks that the issuer named in the entry is the ID of
// that key. Without this check any entry could be "confirmed" with an arbitrary
// key and attribution would be lost.
func (s *SignedEntry) Verify(pub *PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: public key", ErrMissingField)
	}
	if s.Alg != pub.Alg() {
		return fmt.Errorf("%w: entry %s, key %s", ErrAlgMismatch, s.Alg, pub.Alg())
	}
	e, err := s.Entry()
	if err != nil {
		return err
	}
	if e.Issuer != pub.ID() {
		return fmt.Errorf("%w: iss=%s, key=%s", ErrIssuerMismatch, e.Issuer, pub.ID())
	}
	if !pub.Verify(SigContextEntry, s.EntryBytes, s.Signature) {
		return ErrBadSignature
	}
	return nil
}
