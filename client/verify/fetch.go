// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Fetcher retrieves the body of a GET request.
//
// The same interface runs three ways with three different implementations:
// HTTPFetcher (net/http, this file) for ordinary Go code and tests,
// a fetch()-backed one in the WASM build, and a fake one in this package's
// own tests. VerifySubject and httpTrustSource know nothing about how a byte
// arrives, only that it did — the trusted-local-data/remote-claim split
// gossip.Client already draws elsewhere in this project (OWM-9 A11).
type Fetcher interface {
	// Fetch retrieves url and returns the response body for a 2xx status.
	// A non-2xx status is returned as *APIError, decoded from the node's own
	// error body shape ({"error": "...", "detail": "..."}) where possible.
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// APIError reports a non-2xx response from a node's public API.
type APIError struct {
	StatusCode int
	Code       string // the node's own machine-readable error code, e.g. "erased", "not_found"
	Detail     string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("owm/client/verify: %s (%d): %s", e.Code, e.StatusCode, e.Detail)
	}
	return fmt.Sprintf("owm/client/verify: %s (%d)", e.Code, e.StatusCode)
}

// Erased reports whether this error is the node reporting that an entry's
// payload was lawfully erased under Art. 17 GDPR (HTTP 410, code "erased") —
// the one non-2xx response callers are expected to handle specially rather
// than treat as a failure.
func (e *APIError) Erased() bool { return e.Code == "erased" }

// HTTPFetcher is the default Fetcher, for ordinary (non-WASM) Go code: a CLI
// verifier, tests, or any other caller that has a real net/http.Client.
type HTTPFetcher struct {
	Client *http.Client // nil means http.DefaultClient
}

func (f HTTPFetcher) httpClient() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return http.DefaultClient
}

func (f HTTPFetcher) Fetch(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: build request: %w", err)
	}
	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: %s: %w", u, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: %s: read body: %w", u, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		ae := &APIError{StatusCode: resp.StatusCode}
		var eb struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &eb) == nil {
			ae.Code, ae.Detail = eb.Error, eb.Detail
		}
		return nil, ae
	}
	return body, nil
}
