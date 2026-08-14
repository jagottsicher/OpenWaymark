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

// FormatVersion is the version of the leaf and STH format this package produces
// and accepts.
const FormatVersion = 1

// MaxLeafSize bounds a leaf. An entry with MaxParents predecessors and an
// ML-DSA-65 signature comes to roughly 72 KiB; 128 KiB leaves headroom without
// handing an attacker arbitrary memory.
const MaxLeafSize = 128 * 1024

var (
	ErrLeafVersion  = errors.New("owm/log: unknown leaf version")
	ErrLeafSize     = errors.New("owm/log: leaf too large")
	ErrMissingField = errors.New("owm/log: missing required field")
	ErrLogMismatch  = errors.New("owm/log: belongs to a different log")
)

// hasher is the RFC 6962 tree hash function: SHA-256 with 0x00 in front of
// leaves and 0x01 in front of interior nodes.
//
// That is a different domain separation from the one in OWM-0 §3.3 and
// deliberately replaces it here — compatibility with the CT tree construction
// takes precedence. Separation still happens where it is security critical: a
// leaf hash can never pass as a node hash.
var hasher = rfc6962.DefaultHasher

// Leaf is a leaf of the log.
//
// It holds the signed entry as an opaque byte string and not merely its
// identifier. The entry identifier does not cover the signature (OWM-0 §4.3) —
// if only the identifier were in the leaf, the signature would not be part of
// the tree and could be swapped out afterwards without an inclusion proof
// noticing.
type Leaf struct {
	Version uint16     `json:"v"`
	Log     core.LogID `json:"log"`

	// Seq is the position in the log, starting at 0.
	Seq uint64 `json:"seq"`

	// LoggedAt is the point in time at which the node accepted the entry, in
	// milliseconds since the Unix epoch, UTC.
	//
	// Not to be confused with the issuance timestamp inside the entry: that one
	// is the issuer's claim, this one is the node's witness. That the two may
	// diverge is the whole point — a backdated entry is recognised by exactly
	// this.
	LoggedAt int64 `json:"ts"`

	// Entry is the canonical encoding of the signed entry.
	Entry []byte `json:"ent"`
}

// leafWire is the wire form per OWM-2 §3. All fields are mandatory, which is
// why omitempty appears nowhere — an omitted field would be a second encoding
// of the same leaf.
type leafWire struct {
	Version  uint16 `cbor:"1,keyasint"`
	Log      []byte `cbor:"2,keyasint"`
	Seq      uint64 `cbor:"3,keyasint"`
	LoggedAt int64  `cbor:"4,keyasint"`
	Entry    []byte `cbor:"5,keyasint"`
}

// LoggedAtTime returns the acceptance timestamp as a time.Time in UTC.
func (l *Leaf) LoggedAtTime() time.Time { return time.UnixMilli(l.LoggedAt).UTC() }

// Validate checks the structural rules from OWM-2 §3.
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

// Encode returns the canonical CBOR encoding of the leaf.
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

// ParseLeaf reads a leaf, checking along the way that the input is its
// canonical encoding.
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

// SignedEntry decodes the embedded entry. The signature is not checked in the
// process; Verify is there for that.
func (l *Leaf) SignedEntry() (*core.SignedEntry, error) {
	return core.ParseSignedEntry(l.Entry)
}

// EntryID returns the content address of the embedded entry.
func (l *Leaf) EntryID() core.Digest {
	return core.EntryIDFromBytes(entryBytesOf(l.Entry))
}

// entryBytesOf pulls the entry bytes out of a signed entry and returns an empty
// slice for unreadable input. The caller has already accepted the encoding at
// this point.
func entryBytesOf(signed []byte) []byte {
	se, err := core.ParseSignedEntry(signed)
	if err != nil {
		return nil
	}
	return se.EntryBytes
}

// Hash returns the leaf hash per RFC 6962: SHA-256(0x00 ‖ leaf).
func (l *Leaf) Hash() (core.Digest, error) {
	b, err := l.Encode()
	if err != nil {
		return core.Digest{}, err
	}
	return LeafHashFromBytes(b), nil
}

// LeafHashFromBytes computes the leaf hash from the already canonically encoded
// form.
func LeafHashFromBytes(canonical []byte) core.Digest {
	var d core.Digest
	copy(d[:], hasher.HashLeaf(canonical))
	return d
}

// Verify checks the embedded entry in full: signature, issuer, structure — and
// that the leaf belongs to this log.
//
// The log check is not incidental. Without it a leaf from a foreign log could
// be taken over and passed off as one's own.
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
