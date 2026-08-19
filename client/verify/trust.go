// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"errors"
	"fmt"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/trust"
)

// httpTrustSource implements trust.Source over the public API, mirroring
// node/attestation.go's own logSource — same-issuer-only revocation
// matching (OWM-6 §6), one history fetch per key — but fetching over HTTP
// instead of reading the local log directly.
//
// Known scope limit, stated plainly rather than silently assumed away: every
// fetch in a chain walk goes to the same base URL the top-level VerifySubject
// call was given. An attestation chain that crosses node boundaries (an
// accreditation body attesting an entity from a different node's log) is not
// followed — the chain simply stops there, which trust.Compute treats as "no
// further contribution," the same as a chain with no attestation at all.
// Extending this to follow Options.LogURLs the way VerifySubject itself does
// for parent references is future work, not solved here.
//
// Also unlike VerifySubject's own top-level entries, an attestation's own
// signature and inclusion proof are not re-verified here — only its
// commitment against its fetched payload. Re-verifying every hop of a trust
// chain in full would mean fetching and checking an STH and inclusion proof
// per attestation, not just per top-level entry; the commitment check alone
// already rules out a payload that does not match what was actually
// committed to, which is the failure mode a dishonest *node* (as opposed to
// a dishonest attestation issuer, already covered by the signature check
// baked into commitment-independent trust) could otherwise exploit.
type httpTrustSource struct {
	c *client
}

func (s *httpTrustSource) AttestationsOf(ctx context.Context, subject core.KeyID) ([]trust.Attestation, error) {
	hist, err := s.c.fetchHistory(ctx, core.SubjectID(subject))
	if err != nil {
		return nil, err
	}

	type revocation struct {
		target core.Digest
		issuer core.KeyID
	}
	revoked := map[revocation]bool{}
	type parsed struct {
		id core.Digest
		e  *core.Entry
	}
	var attestations []parsed
	for _, lv := range hist.Entries {
		leaf, err := owmlog.ParseLeaf(lv.Leaf)
		if err != nil {
			return nil, fmt.Errorf("owm/client/verify: trust source: parse leaf: %w", err)
		}
		se, err := leaf.SignedEntry()
		if err != nil {
			return nil, fmt.Errorf("owm/client/verify: trust source: parse entry: %w", err)
		}
		e, err := se.Entry()
		if err != nil {
			return nil, fmt.Errorf("owm/client/verify: trust source: decode entry: %w", err)
		}
		switch e.Type {
		case core.EntryTypeAttestation:
			attestations = append(attestations, parsed{id: leaf.EntryID(), e: e})
		case core.EntryTypeRevocation:
			if e.Target != nil {
				revoked[revocation{target: e.Target.Entry, issuer: e.Issuer}] = true
			}
		}
	}

	out := make([]trust.Attestation, 0, len(attestations))
	for _, a := range attestations {
		salt, payload, err := s.c.fetchPayload(ctx, a.id)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Erased() {
				// The evidentiary basis is gone under Art. 17 GDPR; nothing
				// left to recompute a level from — no contribution, the
				// same as an attestation nobody issued (mirrors
				// node/attestation.go's logSource exactly).
				continue
			}
			return nil, err
		}
		if !core.VerifyCommitment(a.e.Commitment, salt, payload) {
			return nil, fmt.Errorf("owm/client/verify: trust source: attestation %s: payload does not match its commitment", a.id)
		}
		p, err := trust.ParsePayload(payload)
		if err != nil {
			// A malformed payload cannot happen for an entry a compliant
			// node accepted (checkAttestationPayload runs at Submit time),
			// but this source must not assume every node is compliant.
			continue
		}
		out = append(out, trust.Attestation{
			Entry:   *a.e,
			Payload: p,
			Revoked: revoked[revocation{target: a.id, issuer: a.e.Issuer}],
		})
	}
	return out, nil
}
