// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package seal encrypts a payload to one or more chosen recipients — the
// mechanism OWM-9 A14 names and OWM-2 §11 specifies: optional, opt-in
// payload confidentiality, orthogonal to everything else in the protocol.
//
// Nothing outside this package needs to know an envelope is encrypted.
// core.VerifyCommitment already treats a payload as opaque bytes; so does
// node.Submit whenever an entry's Profile is empty — the same no-op path
// attestation entries already use. An encrypted entry is therefore just an
// ordinary entry with Profile == "" and a payload that happens to be one of
// these envelopes instead of profile-shaped JSON. Signature, commitment,
// inclusion proof, erasure, pruning and client-side recomputation all keep
// working unmodified, because none of them ever interpreted payload content
// to begin with.
//
// The one honest tradeoff this package cannot remove: an encrypted entry
// gives up node-side profile-schema validation, because the node cannot
// check content it cannot read. ProfileHint carries which schema the
// decrypted content is meant to satisfy, informational only and never
// verified by anything — the same convention trust.Payload's EvidenceURL
// already uses.
//
// Construction: ML-KEM-768 (crypto/mlkem, FIPS 203) key-encapsulates a
// fresh, random per-recipient wrapping key; that wrapping key AES-256-GCM
// seals a single, random content key shared by every recipient; the content
// key AES-256-GCM seals the actual payload once. Multi-recipient from the
// start — the realistic case this exists for is "the buyer and a regulator
// can both read this", not one reader only.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
)

// Alg identifies this package's one supported construction. Carried in the
// envelope so a future second construction does not have to guess.
const Alg = "ML-KEM-768+AES-256-GCM"

var (
	// ErrNoRecipients reports a Seal call with no recipients — an envelope
	// nobody can open is not a usable envelope.
	ErrNoRecipients = errors.New("owm/seal: at least one recipient is required")
	// ErrEnvelope reports an envelope that is not well-formed JSON in this
	// package's shape.
	ErrEnvelope = errors.New("owm/seal: malformed envelope")
	// ErrNotForYou reports that no recipient entry in the envelope could be
	// opened with the given decapsulation key — either the envelope was not
	// addressed to this key, or it was tampered with. Open deliberately
	// does not distinguish the two: telling them apart would mean leaking
	// which failure mode occurred to whoever is probing, for no benefit to
	// a legitimate caller.
	ErrNotForYou = errors.New("owm/seal: no recipient entry could be opened with this key")
)

// Recipient is one intended reader of a sealed payload.
type Recipient struct {
	// Hint identifies the recipient for whoever reads the envelope later —
	// a core.KeyID hex, an email, anything sender and recipient already
	// agreed on out of band. Purely informational: never validated, and
	// Open does not use it to pick which entry to try — it tries all of
	// them (see Open's own doc comment for why that is the safer design).
	Hint string
	Key  *mlkem.EncapsulationKey768
}

// wireRecipient is one recipient's entry on the wire.
type wireRecipient struct {
	Hint          string `json:"hint,omitempty"`
	KEMCiphertext []byte `json:"kem_ciphertext"`
	WrapNonce     []byte `json:"wrap_nonce"`
	WrappedKey    []byte `json:"wrapped_key"`
}

// wireEnvelope is the envelope's JSON shape — ordinary JSON, not canonical
// CBOR: payload bytes were never canonical-CBOR to begin with (only
// entries, leaves and STHs are), and nothing here needs a second valid
// encoding to be ruled out the way OWM-0 §6.4 requires for those.
type wireEnvelope struct {
	Alg         string          `json:"alg"`
	ProfileHint string          `json:"profile_hint,omitempty"`
	Recipients  []wireRecipient `json:"recipients"`
	Nonce       []byte          `json:"nonce"`
	Ciphertext  []byte          `json:"ciphertext"`
}

// Seal encrypts plaintext for every given recipient. profileHint is carried
// unencrypted and unverified in the envelope (see the package doc comment);
// pass "" if there is none.
func Seal(plaintext []byte, profileHint string, recipients []Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}
	for i, r := range recipients {
		if r.Key == nil {
			return nil, fmt.Errorf("owm/seal: recipient %d: %w", i, ErrEnvelope)
		}
	}

	contentKey := make([]byte, mlkem.SharedKeySize) // 32 bytes, matches AES-256's key size exactly
	defer zero(contentKey)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, fmt.Errorf("owm/seal: generate content key: %w", err)
	}
	nonce, ciphertext, err := gcmSeal(contentKey, plaintext)
	if err != nil {
		return nil, err
	}

	wireRecipients := make([]wireRecipient, len(recipients))
	for i, r := range recipients {
		wrapKey, kemCiphertext := r.Key.Encapsulate()
		wrapNonce, wrappedKey, err := gcmSeal(wrapKey, contentKey)
		zero(wrapKey)
		if err != nil {
			return nil, fmt.Errorf("owm/seal: wrap key for recipient %d: %w", i, err)
		}
		wireRecipients[i] = wireRecipient{
			Hint:          r.Hint,
			KEMCiphertext: kemCiphertext,
			WrapNonce:     wrapNonce,
			WrappedKey:    wrappedKey,
		}
	}

	return json.Marshal(wireEnvelope{
		Alg:         Alg,
		ProfileHint: profileHint,
		Recipients:  wireRecipients,
		Nonce:       nonce,
		Ciphertext:  ciphertext,
	})
}

// Open decrypts an envelope for the holder of dk, trying every recipient
// entry rather than requiring the caller to say which one is theirs.
//
// This is not a convenience shortcut but the correct shape for the
// underlying primitive: FIPS 203 ML-KEM decapsulation offers implicit
// rejection — decapsulating a ciphertext with the wrong key does not error,
// it silently returns a *different*, wrong shared key. Whether a given
// recipient entry was actually addressed to dk is therefore only knowable
// by trying the unwrap and seeing whether the AEAD authentication tag
// checks out; asking the caller to pre-select an entry would just move
// that same trial somewhere less central.
func Open(envelope []byte, dk *mlkem.DecapsulationKey768) (plaintext []byte, profileHint string, err error) {
	var w wireEnvelope
	if err := json.Unmarshal(envelope, &w); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrEnvelope, err)
	}
	if w.Alg != Alg {
		return nil, "", fmt.Errorf("%w: alg %q, want %q", ErrEnvelope, w.Alg, Alg)
	}
	if len(w.Recipients) == 0 {
		return nil, "", fmt.Errorf("%w: no recipients", ErrEnvelope)
	}

	for _, wr := range w.Recipients {
		wrapKey, err := dk.Decapsulate(wr.KEMCiphertext)
		if err != nil {
			// A malformed (wrong-length) KEM ciphertext for this one
			// recipient entry — try the rest rather than failing the
			// whole envelope over another recipient's bad entry.
			continue
		}
		contentKey, err := gcmOpen(wrapKey, wr.WrapNonce, wr.WrappedKey)
		zero(wrapKey)
		if err != nil {
			continue // implicit rejection: the expected outcome for an entry not addressed to dk
		}
		out, err := gcmOpen(contentKey, w.Nonce, w.Ciphertext)
		zero(contentKey)
		if err != nil {
			return nil, "", fmt.Errorf("owm/seal: content did not authenticate: %w", err)
		}
		return out, w.ProfileHint, nil
	}
	return nil, "", ErrNotForYou
}

func gcmSeal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("owm/seal: generate nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, nil), nil
}

func gcmOpen(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("%w: nonce size", ErrEnvelope)
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("owm/seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("owm/seal: %w", err)
	}
	return gcm, nil
}

// zero overwrites b in place. Applied to every ephemeral content and
// wrapping key this package generates, the same "handled with the same
// care as a private key" treatment core.Salt.Wipe already gives the log's
// own salts — no key material outlives the call that used it.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
