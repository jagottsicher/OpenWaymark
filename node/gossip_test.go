// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// syncLogBuffer is a bytes.Buffer safe for concurrent writes from
// RunGossip's background goroutines and reads from the test.
type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func forgeDigest(label string) core.Digest {
	sum := sha256.Sum256([]byte(label))
	d, _ := core.DigestFromBytes(sum[:])
	return d
}

func forgeSTH(t *testing.T, key *core.PrivateKey, logID core.LogID, size uint64, root core.Digest) *owmlog.SignedSTH {
	t.Helper()
	sth := &owmlog.STH{
		Version:  owmlog.FormatVersion,
		Log:      logID,
		Size:     size,
		IssuedAt: time.Now().UnixMilli(),
		Root:     root,
		Key:      key.Public().ID(),
	}
	signed, err := owmlog.SignSTH(key, sth)
	if err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	return signed
}

// hijackSTHServer serves real, except that GET /owm/v1/sth answers with
// whatever setSTH was last called with — every other path, crucially
// GET /owm/v1/keys/{id}, still goes to the real handler. Same technique
// monitor's TestSplitViewEndToEnd uses.
func hijackSTHServer(t *testing.T, real http.Handler) (*httptest.Server, func(*owmlog.SignedSTH)) {
	t.Helper()
	var mu sync.Mutex
	var override *owmlog.SignedSTH

	mux := http.NewServeMux()
	mux.HandleFunc("GET /owm/v1/sth", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		o := override
		mu.Unlock()
		if o == nil {
			real.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(struct {
			Signed *owmlog.SignedSTH `json:"signed"`
		}{o}); err != nil {
			t.Fatalf("encode hijacked STH: %v", err)
		}
	})
	mux.HandleFunc("/", real.ServeHTTP)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, func(s *owmlog.SignedSTH) {
		mu.Lock()
		override = s
		mu.Unlock()
	}
}

// TestRunGossipDetectsSplitView mirrors monitor's TestSplitViewEndToEnd for
// the node's own half of gossip: a partner that starts contradicting itself
// must produce an alarm log line naming it.
func TestRunGossipDetectsSplitView(t *testing.T) {
	dishonest := newTestNode(t)
	logID := dishonest.Log().ID()
	key := dishonest.identity.Key
	srv, setSTH := hijackSTHServer(t, dishonest.PublicHandler())
	setSTH(forgeSTH(t, key, logID, 3, forgeDigest("root-a")))

	var logBuf syncLogBuffer
	orig := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(orig) })

	cfg := testConfig(t)
	cfg.GossipInterval = Duration(10 * time.Millisecond)
	cfg.Partners = []Partner{{Name: "dishonest", BaseURL: srv.URL}}
	n, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.RunGossip(ctx) //nolint:errcheck // observed through ctx cancellation, not the return value
	}()

	// A few polls against sthA alone must not raise anything.
	time.Sleep(60 * time.Millisecond)
	if strings.Contains(logBuf.String(), "ALARM") {
		t.Fatalf("alarm fired before any contradiction was served: %q", logBuf.String())
	}

	setSTH(forgeSTH(t, key, logID, 3, forgeDigest("root-b")))

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logBuf.String(), "ALARM") {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the alarm line, got: %q", logBuf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	if got := logBuf.String(); !strings.Contains(got, "partner=dishonest") {
		t.Errorf("alarm line does not mention the partner: %q", got)
	}
}

func TestRunGossipDisabledWithoutPartners(t *testing.T) {
	n := newTestNode(t)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := n.RunGossip(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RunGossip = %v, want context.DeadlineExceeded", err)
	}
}
