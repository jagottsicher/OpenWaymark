// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/discovery"
	owmlog "openwaymark.org/owm/log"

	"openwaymark.org/owm/internal/testnode"
)

// syncBuffer is a bytes.Buffer safe for concurrent writes from Monitor's
// background goroutines and reads from the test.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
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

// hijackedSTHServer serves a real node's public API, except that
// GET /owm/v1/sth is overridden by whatever setSTH was last called with —
// once set, every other path (crucially GET /owm/v1/keys/{id}) still goes to
// the real handler. This is what lets the forged STHs below carry the node's
// own, genuine signature: only the SERVED VALUE is fabricated, the signing
// key and its directory entry are entirely real.
func hijackedSTHServer(t *testing.T, real http.Handler) (*httptest.Server, func(*owmlog.SignedSTH)) {
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

// appendEntry appends one minimal, validly signed entry directly to a test
// node's log, bypassing node.Submit's profile validation — irrelevant to
// what this test checks (split-view detection), same shortcut log's own
// tests take.
func appendEntry(t *testing.T, n *testnode.Node) {
	t.Helper()
	ctx := context.Background()
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("salt: %v", err)
	}
	payload := []byte("payload")
	key := n.Identity().Key
	ent := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   time.Now().UnixMilli(),
		Issuer:     key.Public().ID(),
		Commitment: core.Commit(salt, payload),
	}
	se, err := core.SignEntry(key, ent)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	if _, err := n.Log().AppendWithPayload(ctx, se, salt, payload); err != nil {
		t.Fatalf("append: %v", err)
	}
}

// waitForFindings polls dir until it holds at least n entries or the timeout
// elapses.
func waitForFindings(t *testing.T, dir string, n int, timeout time.Duration) []os.DirEntry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("read findings dir: %v", err)
		}
		if len(entries) >= n {
			return entries
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d findings in %s, got %d", n, dir, len(entries))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestSplitViewEndToEnd is the most important test in the project (see the
// package README): a monitor watching an honest node and a self-
// contradicting one must stay silent about the first and raise exactly one
// alarm, backed by durable evidence, about the second.
func TestSplitViewEndToEnd(t *testing.T) {
	honest := testnode.New(t)
	appendEntry(t, honest)
	if _, err := honest.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}
	appendEntry(t, honest)
	if _, err := honest.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	dishonest := testnode.New(t)
	logID := dishonest.Log().ID()
	key := dishonest.Identity().Key
	srv, setSTH := hijackedSTHServer(t, dishonest.PublicHandler())
	setSTH(forgeSTH(t, key, logID, 7, forgeDigest("root-a")))

	dir := t.TempDir()
	cfg := Config{
		Targets: []Target{
			{Name: "honest", BaseURL: honest.Server.URL},
			{Name: "dishonest", BaseURL: srv.URL},
		},
		PollInterval: Duration(10 * time.Millisecond),
		FindingsDir:  dir,
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var out, errOut syncBuffer
	m.Out, m.Err = &out, &errOut

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		m.Run(ctx) //nolint:errcheck // observed through ctx cancellation, not the return value
	}()

	// Several polls against sthA alone must produce nothing.
	time.Sleep(80 * time.Millisecond)
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("findings appeared before any contradiction was served: %v", entries)
	}

	// Now the dishonest node starts contradicting itself.
	setSTH(forgeSTH(t, key, logID, 7, forgeDigest("root-b")))

	entries := waitForFindings(t, dir, 1, 5*time.Second)
	cancel()
	<-runDone

	if len(entries) != 1 {
		t.Fatalf("findings = %v, want exactly one", entries)
	}
	raw, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var rec findingFile
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode finding: %v", err)
	}
	if rec.Target != "dishonest" {
		t.Errorf("Target = %q, want %q", rec.Target, "dishonest")
	}
	if rec.Kind != "split_view" {
		t.Errorf("Kind = %q, want split_view", rec.Kind)
	}
	if rec.Log != logID.String() {
		t.Errorf("Log = %q, want %s", rec.Log, logID)
	}

	if got := out.String(); got == "" {
		t.Error("no alarm line was printed")
	} else if !bytes.Contains([]byte(got), []byte("dishonest")) {
		t.Errorf("alarm line does not mention the target: %q", got)
	}
}

func TestMonitorDomainTarget(t *testing.T) {
	n := testnode.New(t)
	if _, err := n.IssueSTH(context.Background()); err != nil {
		t.Fatalf("issue STH: %v", err)
	}

	orig := resolveDomain
	resolveDomain = func(ctx context.Context, domain string, httpClient *http.Client) (*discovery.NodeInfo, error) {
		if domain != "partner.example.com" {
			return nil, fmt.Errorf("unexpected domain %q", domain)
		}
		return &discovery.NodeInfo{Protocol: "OWM/1", BaseURL: n.Server.URL}, nil
	}
	t.Cleanup(func() { resolveDomain = orig })

	dir := t.TempDir()
	cfg := Config{
		Targets:            []Target{{Name: "partner", Domain: "partner.example.com"}},
		PollInterval:       Duration(10 * time.Millisecond),
		RediscoverInterval: Duration(50 * time.Millisecond),
		FindingsDir:        dir,
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var out, errOut syncBuffer
	m.Out, m.Err = &out, &errOut

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	m.Run(ctx) //nolint:errcheck // this test only checks that resolution + polling wired together without error noise

	// A request in flight exactly when the deadline hits is an expected
	// artifact of this test's own shutdown, not a wiring problem — anything
	// else (a resolve failure, an HTTP 404, a decode mismatch) is not.
	for _, line := range strings.Split(strings.TrimSpace(errOut.String()), "\n") {
		if line == "" {
			continue
		}
		if !strings.Contains(line, "context deadline exceeded") && !strings.Contains(line, "context canceled") {
			t.Errorf("unexpected warning: %q", line)
		}
	}
}
