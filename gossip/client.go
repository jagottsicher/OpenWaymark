// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package gossip fetches, verifies and polls a node's Signed Tree Heads — the
// primitive OWM-5 §3 gossip is built from. It never trusts anything a server
// merely asserts: every STH is checked against a signing key resolved fresh
// from the node's own key directory, and every consistency proof is verified
// against roots taken only from already-verified STHs.
//
// This package is the shared foundation for both targeted partner gossip
// (built into node/) and independent monitoring (monitor/) — the two
// countermeasures OWM-9 A1 calls for. It stays Apache-2.0 and importable on
// its own, in the same spirit as core/ and log/, so a future client-side
// verifier can reuse the exact same checks (OWM-9 §6.1).
package gossip

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// ErrKeyMismatch reports a key resolved from a node's directory whose
// recomputed identifier does not match the one that was asked for.
var ErrKeyMismatch = errors.New("owm/gossip: resolved key does not match the requested key ID")

// Client talks to one node's public API for gossip purposes: fetching and
// verifying its latest STH, resolving the keys it signs with, and fetching
// consistency proofs between two STHs.
type Client struct {
	// BaseURL is the node's base URL, as reported by its own
	// .well-known/openwaymark (see discovery.NodeInfo.BaseURL) or configured
	// directly.
	BaseURL string
	// HTTP is the client used for requests. nil uses http.DefaultClient.
	HTTP *http.Client

	mu   sync.Mutex
	keys map[core.KeyID]*core.PublicKey
}

// NewClient returns a Client for the node at baseURL.
func NewClient(baseURL string) *Client { return &Client{BaseURL: baseURL} }

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) get(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return fmt.Errorf("owm/gossip: %w", err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("owm/gossip: fetch %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("owm/gossip: fetch %s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("owm/gossip: decode %s: %w", path, err)
	}
	return nil
}

// sthResponse mirrors node/server.go's sthResponse. Decoded is deliberately
// not represented here: what is trusted is only ever Signed, verified
// against a key resolved through Key — the same "decoded is not proof" rule
// the rest of the API follows.
type sthResponse struct {
	Signed *owmlog.SignedSTH `json:"signed"`
}

// STH fetches and verifies the node's latest signed tree head (OWM-5 §3.4).
//
// The signing key is resolved fresh through Key on every call rather than
// cached from an earlier discovery step — that is what lets a key rotation
// happen without any coordination with whoever is polling.
func (c *Client) STH(ctx context.Context) (*owmlog.SignedSTH, *owmlog.STH, error) {
	var resp sthResponse
	if err := c.get(ctx, "/owm/v1/sth", &resp); err != nil {
		return nil, nil, err
	}
	if resp.Signed == nil {
		return nil, nil, fmt.Errorf("owm/gossip: %s: no signed STH in response", c.BaseURL)
	}
	sth, err := resp.Signed.STH()
	if err != nil {
		return nil, nil, fmt.Errorf("owm/gossip: %s: %w", c.BaseURL, err)
	}
	pub, err := c.Key(ctx, sth.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("owm/gossip: %s: resolve signing key: %w", c.BaseURL, err)
	}
	if err := resp.Signed.Verify(pub); err != nil {
		return nil, nil, fmt.Errorf("owm/gossip: %s: %w", c.BaseURL, err)
	}
	return resp.Signed, sth, nil
}

// hexBytes decodes the hex-string wire encoding node/server.go uses for raw
// key material.
type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = raw
	return nil
}

type keyResponse struct {
	Alg    string   `json:"alg"`
	Public hexBytes `json:"public"`
}

// Key fetches a public key by identifier from the node's own directory
// (GET /owm/v1/keys/{id}) and recomputes its identifier from the returned
// bytes — the response's own claimed identifier is never trusted, the same
// "decoded is not proof" rule as elsewhere. Results are cached: a key's
// binding to its bytes is immutable once created, so there is nothing to
// refetch.
func (c *Client) Key(ctx context.Context, id core.KeyID) (*core.PublicKey, error) {
	c.mu.Lock()
	if c.keys != nil {
		if pub, ok := c.keys[id]; ok {
			c.mu.Unlock()
			return pub, nil
		}
	}
	c.mu.Unlock()

	var resp keyResponse
	if err := c.get(ctx, "/owm/v1/keys/"+id.String(), &resp); err != nil {
		return nil, err
	}
	alg, err := core.ParseSigAlg(resp.Alg)
	if err != nil {
		return nil, fmt.Errorf("owm/gossip: key %s: %w", id, err)
	}
	pub, err := core.ParsePublicKey(alg, resp.Public)
	if err != nil {
		return nil, fmt.Errorf("owm/gossip: key %s: %w", id, err)
	}
	if pub.ID() != id {
		return nil, fmt.Errorf("%w: asked for %s, got %s", ErrKeyMismatch, id, pub.ID())
	}

	c.mu.Lock()
	if c.keys == nil {
		c.keys = make(map[core.KeyID]*core.PublicKey)
	}
	c.keys[id] = pub
	c.mu.Unlock()
	return pub, nil
}

// Consistency fetches and verifies a consistency proof between two STHs
// whose signatures the caller MUST have already checked (e.g. via STH).
//
// On a verification failure the fetched proof is returned alongside the
// error, not discarded: a proof that was actually served but does not check
// out is itself part of the evidence (OWM-5 §3.4) — the caller decides
// whether to keep it. A proof that could not even be fetched returns nil,
// since there is nothing to keep in that case.
func (c *Client) Consistency(ctx context.Context, old, new *owmlog.STH) (*owmlog.ConsistencyProof, error) {
	if old == nil || new == nil {
		return nil, fmt.Errorf("owm/gossip: %w: sth", owmlog.ErrMissingField)
	}
	var p owmlog.ConsistencyProof
	path := fmt.Sprintf("/owm/v1/proof/consistency?old=%d&new=%d", old.Size, new.Size)
	if err := c.get(ctx, path, &p); err != nil {
		return nil, err
	}
	if err := p.Verify(old, new); err != nil {
		return &p, err
	}
	return &p, nil
}
