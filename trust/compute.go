// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"errors"
	"fmt"

	"openwaymark.org/owm/core"
)

// MaxChainDepth bounds how far Compute walks an attestation chain before
// treating whatever remains as "no further contribution" rather than
// failing outright (OWM-6 §6). An adversarial chain being long is not a
// reason to let it deny service to a caller resolving an unrelated key.
const MaxChainDepth = 16

// ErrSource reports a failure reading attestations — distinct from an
// ordinary "this key has no attestations" result, which is not an error.
var ErrSource = errors.New("owm/trust: reading attestations failed")

// Attestation is one kind:"entity" or kind:"sensor" attestation naming a
// given key as its subject.
type Attestation struct {
	Entry   core.Entry
	Payload Payload

	// Revoked reports whether a same-issuer revocation has since defeated
	// this attestation, per the matching policy of OWM-6 §6. Compute relies
	// on the Source to have already resolved this — walking revocations
	// itself would mean two different components independently
	// implementing the same interpretive convention and risking drift.
	Revoked bool
}

// Source supplies the attestations Compute walks.
//
// Compute never fetches anything itself — the same trusted-local-data
// split gossip.Client and discovery draw elsewhere (OWM-9 A11): what a
// caller ends up trusting is exactly, and only, what its own Source
// returns.
type Source interface {
	// AttestationsOf returns every kind:"entity" or kind:"sensor"
	// attestation naming subject as its subject, Revoked already resolved.
	AttestationsOf(ctx context.Context, subject core.KeyID) ([]Attestation, error)
}

// Chain is the sequence of attestations Compute used to justify the level
// it returned, root-side first — for a caller that wants to show its work,
// not just the number.
type Chain []Attestation

// Compute walks attestation entries from id back towards a recognised root
// (OWM-6 §6) and returns the resulting entity trust level together with the
// chain of attestations that justifies it.
//
// Absent any attestation at all, or one that never reaches a root, the
// level is LevelNone and the error is nil: "no evidence" is an entirely
// ordinary result of this computation, not a failure of it.
func Compute(ctx context.Context, src Source, roots RootSet, id core.KeyID) (Level, Chain, error) {
	return compute(ctx, src, roots, id, make(map[core.KeyID]bool), 0)
}

func compute(
	ctx context.Context,
	src Source,
	roots RootSet,
	id core.KeyID,
	visiting map[core.KeyID]bool,
	depth int,
) (Level, Chain, error) {
	// A recognised root is a base case: its level is fixed and no further
	// walking happens, regardless of what it might additionally have been
	// attested by someone else.
	if root, ok := roots[id]; ok {
		return root.MaxLevel, nil, nil
	}
	// Cycle among colluding keys: id is already being resolved further up
	// the call stack. Treated as no contribution, not an error — this is
	// also what makes a self-attestation (iss == subj) harmless without a
	// dedicated check: resolving the issuer immediately hits this branch
	// and contributes level 0, so a self-attestation caps out at
	// min(claimed, 0) == 0 (OWM-6 §6, §9).
	if visiting[id] {
		return LevelNone, nil, nil
	}
	if depth >= MaxChainDepth {
		return LevelNone, nil, nil
	}

	atts, err := src.AttestationsOf(ctx, id)
	if err != nil {
		return LevelNone, nil, fmt.Errorf("%w: %v", ErrSource, err)
	}

	visiting[id] = true
	defer delete(visiting, id)

	best := LevelNone
	var bestChain Chain
	for _, a := range atts {
		if a.Revoked {
			continue
		}
		issuerLevel, issuerChain, err := compute(ctx, src, roots, a.Entry.Issuer, visiting, depth+1)
		if err != nil {
			return LevelNone, nil, err
		}

		var candidate Level
		if a.Payload.Kind == KindSensor {
			// A sensor certificate makes no level claim of its own to cap —
			// it inherits the issuer's computed level directly (OWM-6 §4,
			// §6), not through the min() step below.
			candidate = issuerLevel
		} else {
			candidate = a.Payload.Level
			if issuerLevel < candidate {
				candidate = issuerLevel
			}
		}
		// Several independent attestations only ever help, never hurt
		// (OWM-6 §6 point 4): the key's level is the maximum across all of
		// them, not the last one seen.
		if candidate > best {
			best = candidate
			chain := make(Chain, 0, len(issuerChain)+1)
			chain = append(chain, issuerChain...)
			chain = append(chain, a)
			bestChain = chain
		}
	}
	return best, bestChain, nil
}
