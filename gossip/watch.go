// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"context"
	"errors"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// FindingKind classifies what Watch detected. All three are drawn from
// OWM-2 §9's detection table.
type FindingKind int

const (
	// FindingSplitView is two STHs from the same log, same size, different
	// root — the node signed both itself.
	FindingSplitView FindingKind = iota
	// FindingShrunk is a later STH reporting a smaller tree size than an
	// earlier one.
	FindingShrunk
	// FindingInconsistent is a tree that grew, but the consistency proof
	// between the old and new STH does not verify.
	FindingInconsistent
)

func (k FindingKind) String() string {
	switch k {
	case FindingSplitView:
		return "split_view"
	case FindingShrunk:
		return "shrunk"
	case FindingInconsistent:
		return "inconsistent"
	default:
		return "unknown"
	}
}

// Finding is non-repudiable evidence of a node contradicting itself
// (OWM-2 §9, OWM-9 A1): the node's own signature is on both Previous and
// Current.
type Finding struct {
	Kind     FindingKind
	Log      core.LogID
	Previous *owmlog.SignedSTH
	Current  *owmlog.SignedSTH
	// Proof is the consistency proof that was fetched, set only for
	// FindingInconsistent — kept even though it failed to verify, as part of
	// the evidence.
	Proof *owmlog.ConsistencyProof
	// Err is the underlying error: log.ErrSplitView, log.ErrShrunk,
	// log.ErrProofInvalid or log.ErrProofSize.
	Err error
}

// Event is one successful poll.
type Event struct {
	Signed *owmlog.SignedSTH
	STH    *owmlog.STH
	// Finding is set when this poll's STH contradicts the previous one.
	Finding *Finding
}

// Watch polls c at interval until ctx ends, calling fn once per tick: with a
// non-nil error and a zero Event on a failed poll, or with a populated Event
// and a nil error on success.
//
// A failed poll (network error, malformed response, bad signature) is
// reduced coverage for that cycle, not evidence — it is reported through the
// error argument and retried next tick without discarding the last verified
// STH (OWM-5 §3.4). The same holds for a consistency-proof request that
// fails to fetch (a network error, a pruned old size): no Finding is raised,
// the newly verified STH still becomes the new baseline, and coverage
// resumes on the next tick. Only a consistency proof that was fetched but
// does not verify is as serious a finding as a split view.
//
// State — the last STH seen for this log — lives only for the duration of
// this call; nothing here persists across a restart. Retaining Finding
// evidence across restarts is the caller's job, not this package's (see
// monitor/).
//
// interval <= 0 means "off": Watch blocks on ctx.Done() and never polls,
// the same convention node.RunSTH uses for a disabled STH interval.
func Watch(ctx context.Context, c *Client, interval time.Duration, fn func(Event, error)) error {
	if interval <= 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	// A first poll happens immediately rather than waiting out the first
	// interval — a target should start being observed the moment Watch is
	// asked to, not sit uncovered for up to one whole interval after
	// startup.
	prev, prevSigned := pollOnce(ctx, c, nil, nil, fn)

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			prev, prevSigned = pollOnce(ctx, c, prev, prevSigned, fn)
		}
	}
}

func pollOnce(ctx context.Context, c *Client, prev *owmlog.STH, prevSigned *owmlog.SignedSTH, fn func(Event, error)) (*owmlog.STH, *owmlog.SignedSTH) {
	signed, sth, err := c.STH(ctx)
	if err != nil {
		fn(Event{}, err)
		return prev, prevSigned
	}
	event := Event{Signed: signed, STH: sth}
	if prev != nil {
		event.Finding = compare(ctx, c, prev, prevSigned, sth, signed)
	}
	fn(event, nil)
	return sth, signed
}

// compare checks a newly fetched, verified STH against the last one seen for
// the same log.
func compare(ctx context.Context, c *Client, prev *owmlog.STH, prevSigned *owmlog.SignedSTH, cur *owmlog.STH, curSigned *owmlog.SignedSTH) *Finding {
	if err := owmlog.CheckSTHPair(prev, cur); err != nil {
		kind := FindingSplitView
		if errors.Is(err, owmlog.ErrShrunk) {
			kind = FindingShrunk
		}
		return &Finding{Kind: kind, Log: cur.Log, Previous: prevSigned, Current: curSigned, Err: err}
	}
	if cur.Size <= prev.Size {
		// Same size, same root (CheckSTHPair already ruled out a
		// contradiction), or unreachable per CheckSTHPair's own shrink
		// check — either way there is no growth to prove consistent.
		return nil
	}
	proof, err := c.Consistency(ctx, prev, cur)
	if err != nil {
		if errors.Is(err, owmlog.ErrProofInvalid) || errors.Is(err, owmlog.ErrProofSize) {
			return &Finding{Kind: FindingInconsistent, Log: cur.Log, Previous: prevSigned, Current: curSigned, Proof: proof, Err: err}
		}
		// A fetch failure (network, pruning) is reduced coverage, not
		// evidence — see Watch's doc comment.
		return nil
	}
	return nil
}
