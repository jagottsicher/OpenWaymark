// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"context"
	"errors"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

type watchResult struct {
	event Event
	err   error
}

// runWatch drives Watch with a short interval, collects exactly n results
// (one per tick, in order), then cancels and waits for Watch to return.
func runWatch(t *testing.T, c *Client, n int) []watchResult {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make(chan watchResult, n)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = Watch(ctx, c, 5*time.Millisecond, func(ev Event, err error) {
			select {
			case results <- watchResult{ev, err}:
			default:
			}
		})
	}()

	var got []watchResult
	timeout := time.After(10 * time.Second)
	for len(got) < n {
		select {
		case r := <-results:
			got = append(got, r)
		case <-timeout:
			t.Fatalf("timed out waiting for %d watch results, got %d", n, len(got))
		}
	}
	cancel()
	<-done
	return got
}

func TestWatchDetectsSplitView(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(buildSTH(t, key, logID, 5, testDigest("root-a"), time.Now()))
	n.queueSTH(buildSTH(t, key, logID, 5, testDigest("root-b"), time.Now().Add(time.Second)))

	results := runWatch(t, n.client(), 2)

	if results[0].err != nil || results[0].event.Finding != nil {
		t.Fatalf("first poll = %+v, %v, want no finding", results[0].event, results[0].err)
	}
	f := results[1].event.Finding
	if f == nil {
		t.Fatal("second poll: no finding, want FindingSplitView")
	}
	if f.Kind != FindingSplitView {
		t.Errorf("Kind = %v, want FindingSplitView", f.Kind)
	}
	if f.Previous == nil || f.Current == nil || string(f.Previous.Signature) == string(f.Current.Signature) {
		t.Error("Finding does not hold two distinct signed STHs")
	}
	if !errors.Is(f.Err, owmlog.ErrSplitView) {
		t.Errorf("Err = %v, want ErrSplitView", f.Err)
	}
}

func TestWatchDetectsShrink(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(buildSTH(t, key, logID, 5, testDigest("root-a"), time.Now()))
	n.queueSTH(buildSTH(t, key, logID, 3, testDigest("root-b"), time.Now().Add(time.Second)))

	results := runWatch(t, n.client(), 2)

	f := results[1].event.Finding
	if f == nil {
		t.Fatal("second poll: no finding, want FindingShrunk")
	}
	if f.Kind != FindingShrunk {
		t.Errorf("Kind = %v, want FindingShrunk", f.Kind)
	}
	if !errors.Is(f.Err, owmlog.ErrShrunk) {
		t.Errorf("Err = %v, want ErrShrunk", f.Err)
	}
}

func TestWatchDetectsInconsistentGrowth(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(buildSTH(t, key, logID, 1, testDigest("root-a"), time.Now()))
	n.queueSTH(buildSTH(t, key, logID, 2, testDigest("root-b"), time.Now().Add(time.Second)))
	// A tree grew, but the proof server hands back garbage — never produced
	// by a real tree over these two roots, so it cannot verify.
	n.setProof(&owmlog.ConsistencyProof{OldSize: 1, NewSize: 2, Path: []core.Digest{testDigest("garbage")}})

	results := runWatch(t, n.client(), 2)

	f := results[1].event.Finding
	if f == nil {
		t.Fatal("second poll: no finding, want FindingInconsistent")
	}
	if f.Kind != FindingInconsistent {
		t.Errorf("Kind = %v, want FindingInconsistent", f.Kind)
	}
	if f.Proof == nil {
		t.Error("Finding does not retain the failing proof as evidence")
	}
	if !errors.Is(f.Err, owmlog.ErrProofInvalid) {
		t.Errorf("Err = %v, want ErrProofInvalid", f.Err)
	}
}

// TestWatchToleratesTransientFetchError checks two things at once: a failed
// poll is reported through the error argument rather than stopping Watch,
// and — crucially — the last verified STH survives the failure as the
// baseline for the next comparison. A third poll that contradicts the FIRST
// one only produces a finding if that baseline was actually preserved across
// the failed second poll.
func TestWatchToleratesTransientFetchError(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(buildSTH(t, key, logID, 5, testDigest("root-a"), time.Now()))
	n.queueSTHFailure()
	n.queueSTH(buildSTH(t, key, logID, 5, testDigest("root-b"), time.Now().Add(2*time.Second)))

	results := runWatch(t, n.client(), 3)

	if results[0].err != nil || results[0].event.Finding != nil {
		t.Fatalf("first poll = %+v, %v, want a clean first observation", results[0].event, results[0].err)
	}
	if results[1].err == nil {
		t.Fatal("second poll: no error, want the injected fetch failure")
	}
	f := results[2].event.Finding
	if f == nil {
		t.Fatal("third poll: no finding — the pre-failure baseline was not preserved")
	}
	if f.Kind != FindingSplitView {
		t.Errorf("Kind = %v, want FindingSplitView", f.Kind)
	}
}

// TestWatchToleratesUnavailableConsistencyProof checks the other half of
// OWM-5 §3.4's rule: a tree that grew but whose consistency proof could not
// even be fetched (a pruned old size, a network hiccup) is reduced coverage,
// not evidence — no Finding, and the newer STH still becomes the baseline.
func TestWatchToleratesUnavailableConsistencyProof(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	n := newFakeNode(t)
	n.addKey(key.Public())
	n.queueSTH(buildSTH(t, key, logID, 1, testDigest("root-a"), time.Now()))
	n.queueSTH(buildSTH(t, key, logID, 2, testDigest("root-b"), time.Now().Add(time.Second)))
	n.setProofUnavailable()

	results := runWatch(t, n.client(), 2)

	if results[1].err != nil {
		t.Fatalf("second poll: err = %v, want the STH itself to still be reported", results[1].err)
	}
	if results[1].event.Finding != nil {
		t.Errorf("Finding = %+v, want none: an unfetchable proof is reduced coverage, not evidence", results[1].event.Finding)
	}
	if results[1].event.STH.Size != 2 {
		t.Errorf("STH.Size = %d, want 2 — the newer STH must still become the baseline", results[1].event.STH.Size)
	}
}

func TestWatchDisabledBlocksOnContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	n := newFakeNode(t)
	err := Watch(ctx, n.client(), 0, func(Event, error) {
		t.Fatal("Watch with interval <= 0 must never poll")
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Watch = %v, want context.DeadlineExceeded", err)
	}
}
