// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// ErrRateLimited reports that a source address has exceeded its request
// budget on the public API (OWM-9 A9, A10).
var ErrRateLimited = errors.New("owm/node: rate limit exceeded")

// rateLimiter is a per-source-address token bucket — the mitigation
// OWM-9 A9 ("communication pattern... timestamps, frequency") and A10
// ("rate limiting on the read API") both name and neither had built yet.
//
// It does not, and cannot, prevent a patient sweep (A10's own residual-risk
// line already says so: "rate limiting raises the cost and the duration of
// a sweep; it does not make the sweep impossible"). What it changes is the
// economics: a bulk enumeration that would otherwise be instant now takes
// minutes to hours, proportional to how much is being swept.
type rateLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens added per second
	burst   float64 // bucket capacity
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// maxTrackedBuckets bounds memory: once exceeded, allow triggers an
// opportunistic sweep of buckets untouched for staleAfter instead of
// growing without limit. A node that runs for months must not accumulate
// one bucket per source address it has ever seen.
const (
	maxTrackedBuckets = 10_000
	staleAfter        = 10 * time.Minute
)

func newRateLimiter(ratePerSecond, burst float64) *rateLimiter {
	return &rateLimiter{rate: ratePerSecond, burst: burst, buckets: map[string]*bucket{}}
}

// allow reports whether a request from key may proceed, consuming one token
// if so. Tokens are computed lazily from elapsed time rather than refilled
// by a background goroutine — the same "no ticker where arithmetic
// suffices" choice the rest of this module already makes.
func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if len(l.buckets) > maxTrackedBuckets {
		l.sweepLocked(now)
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweepLocked removes buckets untouched for staleAfter. Called only past
// maxTrackedBuckets, so a small, steady set of active clients never pays
// for it — only sustained growth does.
func (l *rateLimiter) sweepLocked(now time.Time) {
	for key, b := range l.buckets {
		if now.Sub(b.last) > staleAfter {
			delete(l.buckets, key)
		}
	}
}

// sourceKey extracts the rate-limit key from a request: the connection's
// remote address with the port stripped, never a client-supplied header.
//
// Deliberately not X-Forwarded-For or similar: trusting a header nothing
// authenticates would let a bulk sweep defeat the whole mechanism by
// sending a fresh fake value on every request. The documented cost of that
// choice — see node/README.md — is that every client behind the same
// reverse-proxy connection (OWM-7 §2 already recommends running one) shares
// one bucket, the same way this module already declines to solve
// authentication in application code (AdminHandler's own doc comment:
// "what the operating system and a grown-up proxy can do anyway").
func sourceKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr // no port present — use the address as given
	}
	return host
}

// withRateLimit answers over budget with 429 rather than passing the
// request through. nil limiter (RateLimitPerSecond <= 0 in Config, an
// operator's explicit opt-out — a reverse proxy already rate limiting
// would otherwise double-throttle) disables this wrapper entirely.
func withRateLimit(l *rateLimiter, h http.Handler) http.Handler {
	if l == nil {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(sourceKey(r)) {
			w.Header().Set("Retry-After", "1")
			writeError(w, ErrRateLimited)
			return
		}
		h.ServeHTTP(w, r)
	})
}
