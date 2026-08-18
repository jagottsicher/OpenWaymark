// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"openwaymark.org/owm/core"
)

// ErrProtocolMismatch reports a .well-known response whose protocol field is
// not "OWM/1".
var ErrProtocolMismatch = errors.New("owm/discovery: unexpected protocol")

// wellKnownPath is where a node's description is served (OWM-7 §4.1).
const wellKnownPath = "/.well-known/openwaymark"

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

// NodeKey is a key as reported in a node's .well-known description.
type NodeKey struct {
	Alg    string     `json:"alg"`
	ID     core.KeyID `json:"id"`
	Public hexBytes   `json:"public"`
}

// PublicKey recomputes the key from Alg and Public via core.ParsePublicKey,
// which derives the key's identifier from the bytes itself. ID above is
// never used for verification — it is informational only, the same
// "decoded is not proof" rule the rest of the API follows.
func (k NodeKey) PublicKey() (*core.PublicKey, error) {
	alg, err := core.ParseSigAlg(k.Alg)
	if err != nil {
		return nil, err
	}
	return core.ParsePublicKey(alg, k.Public)
}

// Operator describes the body responsible for a node, as reported in its
// description. Mirrors node.Operator's JSON shape without importing the node
// package.
type Operator struct {
	Name    string `json:"name,omitempty"`
	Contact string `json:"contact,omitempty"`
	Privacy string `json:"privacy,omitempty"`
}

// ProfileInfo is one loaded profile, as reported in a node's description.
type ProfileInfo struct {
	ID           string      `json:"id"`
	Title        string      `json:"title,omitempty"`
	SchemaDigest core.Digest `json:"schema_digest"`
	Files        []string    `json:"files"`
}

// NodeInfo is a node's self-description, fetched from
// .well-known/openwaymark (OWM-7 §4.1). It is unauthenticated by design —
// trust rides on TLS to BaseURL, see OWM-5 §2.2. A gossip peer's ongoing STH
// verification does not use Key from here; it resolves the signing key fresh
// on every poll instead (OWM-5 §3.4) so that a rotation needs no
// coordination with this snapshot.
type NodeInfo struct {
	Protocol   string        `json:"protocol"`
	Log        core.LogID    `json:"log"`
	BaseURL    string        `json:"base_url,omitempty"`
	Operator   Operator      `json:"operator"`
	Key        NodeKey       `json:"key"`
	Genesis    NodeKey       `json:"genesis_key"`
	TreeSize   uint64        `json:"tree_size"`
	Profiles   []ProfileInfo `json:"profiles"`
	MaxPayload int64         `json:"max_payload"`
	MaxLeaf    int           `json:"max_leaf"`
	API        string        `json:"api"`
}

// Describe fetches and parses GET {baseURL}/.well-known/openwaymark.
//
// httpClient may be nil, in which case http.DefaultClient is used.
func Describe(ctx context.Context, baseURL string, httpClient *http.Client) (*NodeInfo, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+wellKnownPath, nil)
	if err != nil {
		return nil, fmt.Errorf("owm/discovery: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("owm/discovery: fetch %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("owm/discovery: fetch %s: HTTP %d", baseURL, resp.StatusCode)
	}
	var info NodeInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("owm/discovery: decode %s: %w", baseURL, err)
	}
	if info.Protocol != "OWM/1" {
		return nil, fmt.Errorf("%w: %q", ErrProtocolMismatch, info.Protocol)
	}
	return &info, nil
}

// Resolve is Lookup followed by Describe — the two-step discovery flow
// (OWM-0 §7, OWM-5 §2) in one call.
func Resolve(ctx context.Context, domain string, httpClient *http.Client) (*NodeInfo, error) {
	rec, err := Lookup(ctx, domain)
	if err != nil {
		return nil, err
	}
	return Describe(ctx, rec.NodeURL, httpClient)
}
