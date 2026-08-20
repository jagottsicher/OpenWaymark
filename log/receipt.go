// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"errors"
	"fmt"
	"time"

	"openwaymark.org/owm/core"
)

// ErrReceiptsDisabled reports that the log was not configured with a
// positive Options.MaxMergeDelay — the node-wide opt-out, the same "zero
// means off" convention Config.RateLimitPerSecond already uses.
var ErrReceiptsDisabled = errors.New("owm/log: receipts are disabled (MaxMergeDelay <= 0)")

// ErrReceiptVersion reports an unknown receipt version.
var ErrReceiptVersion = errors.New("owm/log: unknown receipt version")

// Receipt is a node's signed promise, made at submission time, that a
// specific entry will be included in a tree witnessed by a Signed Tree Head
// no later than Deadline — the Certificate Transparency SCT pattern,
// applied to OWM-9 A3 (withholding).
//
// A node in this project appends synchronously: Append already assigns Seq
// and grows the tree before Submit ever returns. The only thing genuinely
// still owed after a receipt is issued is therefore a *witnessed* tree —
// a signed STH with Size > Seq — not the append itself, which already
// happened. A receipt whose deadline has passed with no such STH is not
// merely suspicious, it is self-contradictory in exactly the sense an STH
// split view is (OWM-9 A1): two things the node itself signed, one of which
// promises what the other never delivered. See CheckReceipt.
type Receipt struct {
	Version uint16     `json:"v"`
	Log     core.LogID `json:"log"`

	// EntryID is the entry this receipt promises to include — computable by
	// the submitter independently, before ever submitting (OWM-0 §4.3): the
	// same identifier that will later appear in the leaf.
	EntryID core.Digest `json:"entry_id"`

	// Seq is the position the entry was actually assigned at append time.
	// Because the log only ever grows and a position, once assigned, is
	// fixed permanently, any later STH with Size > Seq structurally
	// contains this entry — no separate inclusion proof is needed to
	// establish that, only to establish where (CheckReceipt relies on
	// exactly this).
	Seq uint64 `json:"seq"`

	// IssuedAt is when the node accepted the submission, in milliseconds
	// since the Unix epoch, UTC.
	IssuedAt int64 `json:"ts"`

	// Deadline is the latest time, in milliseconds since the Unix epoch,
	// UTC, by which an STH witnessing this entry's inclusion MUST exist.
	// Embedded in the receipt itself rather than left to a separately
	// published policy value, so the receipt is self-contained evidence: a
	// dispute needs nothing beyond this receipt and one later STH, both
	// signed by the same node.
	Deadline int64 `json:"deadline"`

	// Key is the identifier of the signing key, bound inside the signed
	// structure for the same reason as STH.Key: otherwise the statement of
	// who signed could be swapped out unnoticed.
	Key core.KeyID `json:"key"`
}

type receiptWire struct {
	Version  uint16 `cbor:"1,keyasint"`
	Log      []byte `cbor:"2,keyasint"`
	EntryID  []byte `cbor:"3,keyasint"`
	Seq      uint64 `cbor:"4,keyasint"`
	IssuedAt int64  `cbor:"5,keyasint"`
	Deadline int64  `cbor:"6,keyasint"`
	Key      []byte `cbor:"7,keyasint"`
}

type signedReceiptWire struct {
	Receipt []byte `cbor:"1,keyasint"`
	Alg     uint16 `cbor:"2,keyasint"`
	Sig     []byte `cbor:"3,keyasint"`
}

// IssuedAtTime returns the issuance timestamp as a time.Time in UTC.
func (r *Receipt) IssuedAtTime() time.Time { return time.UnixMilli(r.IssuedAt).UTC() }

// DeadlineTime returns the deadline as a time.Time in UTC.
func (r *Receipt) DeadlineTime() time.Time { return time.UnixMilli(r.Deadline).UTC() }

// Validate checks the structural rules.
func (r *Receipt) Validate() error {
	if r.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrReceiptVersion, r.Version)
	}
	if r.Log.IsZero() {
		return fmt.Errorf("%w: log", ErrMissingField)
	}
	if r.EntryID.IsZero() {
		return fmt.Errorf("%w: entry_id", ErrMissingField)
	}
	if r.IssuedAt <= 0 {
		return fmt.Errorf("%w: ts", ErrMissingField)
	}
	if r.Deadline <= r.IssuedAt {
		return fmt.Errorf("%w: deadline", ErrMissingField)
	}
	if r.Key.IsZero() {
		return fmt.Errorf("%w: key", ErrMissingField)
	}
	return nil
}

// Encode returns the canonical CBOR encoding of the receipt.
func (r *Receipt) Encode() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	b, err := core.MarshalCanonical(&receiptWire{
		Version:  r.Version,
		Log:      append([]byte(nil), r.Log[:]...),
		EntryID:  append([]byte(nil), r.EntryID[:]...),
		Seq:      r.Seq,
		IssuedAt: r.IssuedAt,
		Deadline: r.Deadline,
		Key:      append([]byte(nil), r.Key[:]...),
	})
	if err != nil {
		return nil, fmt.Errorf("owm/log: encode receipt: %w", err)
	}
	return b, nil
}

// ParseReceipt reads a receipt, checking along the way that the input is its
// canonical encoding.
func ParseReceipt(b []byte) (*Receipt, error) {
	var w receiptWire
	if err := core.UnmarshalCanonical(b, &w); err != nil {
		return nil, fmt.Errorf("owm/log: read receipt: %w", err)
	}
	logID, err := core.DigestFromBytes(w.Log)
	if err != nil {
		return nil, fmt.Errorf("owm/log: receipt: log: %w", err)
	}
	entryID, err := core.DigestFromBytes(w.EntryID)
	if err != nil {
		return nil, fmt.Errorf("owm/log: receipt: entry_id: %w", err)
	}
	key, err := core.DigestFromBytes(w.Key)
	if err != nil {
		return nil, fmt.Errorf("owm/log: receipt: key: %w", err)
	}
	r := &Receipt{
		Version:  w.Version,
		Log:      core.LogID(logID),
		EntryID:  entryID,
		Seq:      w.Seq,
		IssuedAt: w.IssuedAt,
		Deadline: w.Deadline,
		Key:      core.KeyID(key),
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// SignedReceipt is a Receipt together with its signature.
//
// ReceiptBytes holds the canonical encoding as an opaque byte string. What is
// signed and verified are always exactly those bytes, never a freshly
// produced encoding — the same rule SignedSTH follows, for the same reason.
type SignedReceipt struct {
	ReceiptBytes []byte      `json:"receipt"`
	Alg          core.SigAlg `json:"alg"`
	Signature    []byte      `json:"sig"`
}

// SignReceipt encodes the receipt canonically and signs it.
func SignReceipt(k *core.PrivateKey, r *Receipt) (*SignedReceipt, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: private key", ErrMissingField)
	}
	if r.Key != k.Public().ID() {
		return nil, fmt.Errorf("%w: key=%s, public key=%s", ErrSignerMismatch, r.Key, k.Public().ID())
	}
	b, err := r.Encode()
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(core.SigContextReceipt, b)
	if err != nil {
		return nil, err
	}
	return &SignedReceipt{ReceiptBytes: b, Alg: k.Alg(), Signature: sig}, nil
}

// Receipt decodes the embedded receipt.
//
// The signature is NOT checked in the process. Anyone who believes a receipt
// obtained this way without calling Verify first holds nothing but a
// server's assertion.
func (s *SignedReceipt) Receipt() (*Receipt, error) { return ParseReceipt(s.ReceiptBytes) }

// Verify checks the signature against the given public key, and that the
// receipt names exactly this key as its signer.
func (s *SignedReceipt) Verify(pub *core.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: public key", ErrMissingField)
	}
	if s.Alg != pub.Alg() {
		return fmt.Errorf("%w: receipt %s, key %s", ErrAlgMismatch, s.Alg, pub.Alg())
	}
	r, err := s.Receipt()
	if err != nil {
		return err
	}
	if r.Key != pub.ID() {
		return fmt.Errorf("%w: key=%s, public key=%s", ErrSignerMismatch, r.Key, pub.ID())
	}
	if !pub.Verify(core.SigContextReceipt, s.ReceiptBytes, s.Signature) {
		return ErrBadSignature
	}
	return nil
}

// Encode returns the canonical CBOR encoding of the signed receipt.
func (s *SignedReceipt) Encode() ([]byte, error) {
	return core.MarshalCanonical(&signedReceiptWire{
		Receipt: s.ReceiptBytes,
		Alg:     uint16(s.Alg),
		Sig:     s.Signature,
	})
}

// ParseSignedReceipt reads a signed receipt, checking canonicity at both
// levels.
func ParseSignedReceipt(b []byte) (*SignedReceipt, error) {
	var w signedReceiptWire
	if err := core.UnmarshalCanonical(b, &w); err != nil {
		return nil, fmt.Errorf("owm/log: signed receipt: %w", err)
	}
	s := &SignedReceipt{ReceiptBytes: w.Receipt, Alg: core.SigAlg(w.Alg), Signature: w.Sig}
	if !s.Alg.Valid() {
		return nil, fmt.Errorf("owm/log: signed receipt: %w: %d", core.ErrUnknownAlg, w.Alg)
	}
	if len(s.Signature) != s.Alg.SignatureSize() {
		return nil, fmt.Errorf("owm/log: signed receipt: %w", core.ErrSigSize)
	}
	if _, err := s.Receipt(); err != nil {
		return nil, err
	}
	return s, nil
}
