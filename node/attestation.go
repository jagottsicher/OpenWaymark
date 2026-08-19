// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"errors"
	"fmt"
	"os"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/trust"
)

// ErrConcludedNotSelfIssued reports a kind:"concluded" attestation whose
// subject is not the issuer's own key.
var ErrConcludedNotSelfIssued = errors.New("owm/node: a concluded attestation must be self-issued")

// checkAttestationPayload parses and validates an attestation payload
// before it is appended (OWM-6 §3).
//
// Rejecting a malformed payload outright is cheaper and cleaner than
// rotation's after-append check (rotation.go): an attestation needs no
// directory mutation to justify deferring the check, so nothing is gained
// by letting a bad one into the log first.
//
// One cross-field rule beyond payload shape: kind:"concluded" MUST be
// self-issued. Only the keyholder can attributably say their own
// participation has ended — anyone else's say-so would be a rumour, not
// evidence — and self-issuance is also what keeps trust.Compute from
// needing any special case for this kind at all (OWM-9 A15): a
// self-referential attestation already contributes nothing, by the same
// cycle handling that already makes a self-attestation harmless.
func checkAttestationPayload(e *core.Entry, payload []byte) error {
	p, err := trust.ParsePayload(payload)
	if err != nil {
		return err
	}
	if p.Kind == trust.KindConcluded && e.Subject != core.SubjectID(e.Issuer) {
		return fmt.Errorf("%w: subject %s, issuer %s", ErrConcludedNotSelfIssued, e.Subject, e.Issuer)
	}
	return nil
}

// loadTrustRoots reads the accreditation root list (OWM-6 §8).
//
// A blank path or a missing file are not errors — both mean the safe empty
// default: no roots recognised, everyone computes to trust level 0 until an
// operator actively configures otherwise.
func loadTrustRoots(path string) (trust.RootSet, error) {
	if path == "" {
		return trust.RootSet{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return trust.RootSet{}, nil
		}
		return nil, fmt.Errorf("owm/node: open trust roots: %w", err)
	}
	defer f.Close()
	roots, err := trust.ParseRoots(f)
	if err != nil {
		return nil, fmt.Errorf("owm/node: trust roots: %w", err)
	}
	return roots, nil
}

// logSource implements trust.Source by walking this node's own log —
// exactly the data any other reader of GET /owm/v1/subjects/{id} already
// sees, nothing more.
type logSource struct{ n *Node }

// AttestationsOf returns every attestation naming subject, with Revoked
// resolved per the same-issuer-only matching policy of OWM-6 §6.
//
// One History call, not two, suffices for the matching: OWM-6 §6 requires
// a defeating revocation to name the same subj as the attestation it
// revokes, so any revocation that could possibly matter already sits in
// the same result set this queries for the attestations themselves.
func (s *logSource) AttestationsOf(ctx context.Context, subject core.KeyID) ([]trust.Attestation, error) {
	leaves, err := s.n.log.History(ctx, core.SubjectID(subject))
	if err != nil {
		return nil, err
	}

	type revocation struct {
		target core.Digest
		issuer core.KeyID
	}
	revoked := make(map[revocation]bool)
	entries := make(map[core.Digest]*core.Entry, len(leaves))
	var attIDs []core.Digest
	for _, leaf := range leaves {
		se, err := leaf.SignedEntry()
		if err != nil {
			return nil, fmt.Errorf("owm/node: attestation source: %w", err)
		}
		e, err := se.Entry()
		if err != nil {
			return nil, fmt.Errorf("owm/node: attestation source: %w", err)
		}
		id := leaf.EntryID()
		entries[id] = e
		switch e.Type {
		case core.EntryTypeAttestation:
			attIDs = append(attIDs, id)
		case core.EntryTypeRevocation:
			if e.Target != nil {
				revoked[revocation{target: e.Target.Entry, issuer: e.Issuer}] = true
			}
		}
	}

	out := make([]trust.Attestation, 0, len(attIDs))
	for _, id := range attIDs {
		e := entries[id]
		payload, err := s.n.log.Payload(ctx, id)
		if err != nil {
			if errors.Is(err, owmlog.ErrErased) {
				// The evidentiary basis is gone under Art. 17 GDPR; the
				// statement still stands (OWM-2 §7) but there is nothing
				// left to recompute a level from — no contribution, the
				// same as an attestation nobody ever issued.
				continue
			}
			return nil, err
		}
		p, err := trust.ParsePayload(payload)
		if err != nil {
			// Submit rejects a malformed payload before it ever reaches
			// the log (checkAttestationPayload); this branch is reachable
			// only by data that predates that check. Skip it rather than
			// failing every other, well-formed attestation in this
			// subject's history over one bad entry.
			continue
		}
		out = append(out, trust.Attestation{
			Entry:   *e,
			Payload: p,
			Revoked: revoked[revocation{target: id, issuer: e.Issuer}],
		})
	}
	return out, nil
}
