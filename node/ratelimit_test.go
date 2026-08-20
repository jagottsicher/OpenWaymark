// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllowsUpToBurst(t *testing.T) {
	l := newRateLimiter(1, 3)
	for i := 0; i < 3; i++ {
		if !l.allow("a") {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	if l.allow("a") {
		t.Fatal("request beyond burst was allowed")
	}
}

func TestRateLimiterIndependentPerKey(t *testing.T) {
	l := newRateLimiter(1, 1)
	if !l.allow("a") {
		t.Fatal("first request for a denied")
	}
	if l.allow("a") {
		t.Fatal("second request for a (over budget) was allowed")
	}
	if !l.allow("b") {
		t.Fatal("a's exhausted budget affected an unrelated key b")
	}
}

func TestRateLimiterRefillsOverTime(t *testing.T) {
	// A high rate and a short, generous sleep keep this fast without being
	// flaky: at 100 tokens/second, 30ms comfortably yields at least one.
	l := newRateLimiter(100, 1)
	if !l.allow("a") {
		t.Fatal("first request denied")
	}
	if l.allow("a") {
		t.Fatal("second immediate request was allowed")
	}
	time.Sleep(30 * time.Millisecond)
	if !l.allow("a") {
		t.Fatal("request after waiting for refill was still denied")
	}
}

func TestRateLimiterSweepsStaleBuckets(t *testing.T) {
	l := newRateLimiter(1, 1)
	l.buckets["stale"] = &bucket{tokens: 0, last: time.Now().Add(-2 * staleAfter)}
	// Distinct keys: the sweep only triggers once the map genuinely holds
	// more than maxTrackedBuckets entries, not merely after many writes to
	// the same one.
	for i := 0; i < maxTrackedBuckets+1; i++ {
		l.buckets[string(rune(i))] = &bucket{tokens: 1, last: time.Now()}
	}
	l.allow("trigger-a-sweep")
	if _, ok := l.buckets["stale"]; ok {
		t.Fatal("a bucket untouched for longer than staleAfter survived the sweep")
	}
}

func TestSourceKeyStripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := sourceKey(r); got != "203.0.113.7" {
		t.Fatalf("sourceKey = %q, want the address without the port", got)
	}
}

func TestWithRateLimitNilDisables(t *testing.T) {
	h := withRateLimit(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (nil limiter must disable rate limiting entirely)", rec.Code)
	}
}

func TestWithRateLimitReturns429PastBudget(t *testing.T) {
	l := newRateLimiter(1, 2)
	h := withRateLimit(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.1:1"

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 response carries no Retry-After header")
	}
	if ct := rec.Header().Get("Content-Type"); ct == "" {
		t.Error("429 response carries no Content-Type — should be the ordinary JSON error body")
	}
}

// TestPublicAPIRateLimitEndToEnd confirms the wiring through a real node:
// the public API enforces the configured budget, the admin interface never
// does — mirroring TestCORS's own dual confirmation for the same reason,
// an operator's own tooling against the admin interface must never be
// throttled by a mechanism aimed at outside readers.
func TestPublicAPIRateLimitEndToEnd(t *testing.T) {
	cfg := testConfig(t)
	cfg.RateLimitPerSecond = 1
	cfg.RateLimitBurst = 2
	n, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	a := newAPI(t, n)

	for i := 0; i < 2; i++ {
		res, err := http.Get(a.public + "/owm/v1/sth")
		if err != nil {
			t.Fatalf("GET public: %v", err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("request %d rate limited within burst", i)
		}
	}
	res, err := http.Get(a.public + "/owm/v1/sth")
	if err != nil {
		t.Fatalf("GET public: %v", err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 past the configured burst", res.StatusCode)
	}

	// The admin interface is a different budget entirely: it is never
	// wrapped in withRateLimit at all (node/admin.go builds its own
	// handler), so operator tooling hammering it is unaffected regardless
	// of how exhausted the public API's limiter is.
	for i := 0; i < 5; i++ {
		res, err := http.Get(a.admin + "/admin/v1/keys")
		if err != nil {
			t.Fatalf("GET admin: %v", err)
		}
		res.Body.Close()
		if res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("admin request %d was rate limited", i)
		}
	}
}

func TestRateLimitDisabledByDefaultConfigZero(t *testing.T) {
	cfg := testConfig(t)
	cfg.RateLimitPerSecond = 0
	n, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	if n.rateLimiter != nil {
		t.Fatal("RateLimitPerSecond: 0 must disable the limiter (nil), not merely set a zero rate")
	}
}

func TestConfigRejectsNegativeRateLimit(t *testing.T) {
	cfg := testConfig(t)
	cfg.RateLimitPerSecond = -1
	if err := cfg.Check(); err == nil {
		t.Fatal("negative rate_limit_per_second was accepted")
	}
	cfg = testConfig(t)
	cfg.RateLimitBurst = -1
	if err := cfg.Check(); err == nil {
		t.Fatal("negative rate_limit_burst was accepted")
	}
}
