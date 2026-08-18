// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Defaults.
const (
	DefaultListen      = "127.0.0.1:8480"
	DefaultAdminListen = "127.0.0.1:8481"
	DefaultDatabase    = "owm.sqlite"
	DefaultIdentity    = "owm-identity.json"

	// DefaultMaxPayload caps a single payload. A supply chain event is a record,
	// not a file attachment: photos, lab reports and certificates belong behind a
	// URL whose hash sits in the payload.
	DefaultMaxPayload = 256 * 1024

	// DefaultSTHInterval is the gap between two Signed Tree Heads.
	//
	// The gap decides how long tampering can stay unnoticed, and each issuance
	// costs one ML-DSA signature. A minute is harmless for a node on Raspberry Pi
	// class hardware and tight enough for an observer.
	DefaultSTHInterval = time.Minute
)

// Partner is a supply chain partner whose log this node gossips with —
// polling its STH so a self-contradiction becomes detectable. Targeted
// partner gossip, not global broadcast (OWM-5 §3.2).
type Partner struct {
	// Name identifies this partner in log lines. Required.
	Name string `json:"name"`
	// BaseURL is the partner's base URL, when known directly. Exactly one of
	// BaseURL and Domain MUST be set.
	BaseURL string `json:"base_url,omitempty"`
	// Domain is resolved via package discovery, once, when gossip with this
	// partner starts.
	Domain string `json:"domain,omitempty"`
}

// Operator describes the responsible body.
//
// Not decoration: in the federated model every operator is the data controller
// for their own data. Whoever wants to file an access or erasure request has to
// be able to find out with whom.
type Operator struct {
	Name    string `json:"name,omitempty"`
	Contact string `json:"contact,omitempty"`
	Privacy string `json:"privacy,omitempty"`
}

// Config configures a node.
type Config struct {
	// Listen is the address of the public API.
	//
	// The default binds to localhost. A node belongs behind a TLS-terminating
	// reverse proxy; reaching out onto the network by itself is not something a
	// program should do unasked.
	Listen string `json:"listen"`

	// AdminListen is the address of the admin interface. It knows no
	// authentication and MUST therefore stay bound locally.
	AdminListen string `json:"admin_listen"`

	// Database is the path of the SQLite file. ":memory:" for tests.
	Database string `json:"database"`

	// Identity is the path of the identity file.
	Identity string `json:"identity"`

	// BaseURL is the externally reachable address of this node, as it appears in
	// the DNS TXT record.
	BaseURL string `json:"base_url,omitempty"`

	// Operator is the responsible body.
	Operator Operator `json:"operator,omitempty"`

	// Profiles names the profiles this node accepts. Empty means: every profile
	// compiled in.
	Profiles []string `json:"profiles,omitempty"`

	// MaxPayload caps a single payload in bytes.
	MaxPayload int64 `json:"max_payload,omitempty"`

	// STHInterval is the gap between two Signed Tree Heads. Zero switches
	// automatic issuance off; the route through the admin interface remains.
	STHInterval Duration `json:"sth_interval,omitempty"`

	// Partners are the supply chain partners this node gossips with
	// (OWM-5 §3.2).
	Partners []Partner `json:"partners,omitempty"`

	// GossipInterval is the gap between two polls of a partner's STH. Zero
	// switches partner gossip off.
	GossipInterval Duration `json:"gossip_interval,omitempty"`
}

// DefaultConfig returns the defaults.
func DefaultConfig() Config {
	return Config{
		Listen:      DefaultListen,
		AdminListen: DefaultAdminListen,
		Database:    DefaultDatabase,
		Identity:    DefaultIdentity,
		MaxPayload:  DefaultMaxPayload,
		STHInterval: Duration(DefaultSTHInterval),
	}
}

// LoadConfig reads a JSON configuration layered over the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("owm/node: read configuration: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// A mistyped field is a setting that has no effect — while the operator
	// believes they have set it.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("owm/node: read configuration: %w", err)
	}
	return cfg, cfg.Check()
}

// Check fills gaps with defaults and checks the rest.
func (c *Config) Check() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Database == "" {
		c.Database = DefaultDatabase
	}
	if c.Identity == "" {
		c.Identity = DefaultIdentity
	}
	if c.MaxPayload <= 0 {
		c.MaxPayload = DefaultMaxPayload
	}
	if c.STHInterval < 0 {
		return fmt.Errorf("owm/node: sth_interval is negative")
	}
	if c.GossipInterval < 0 {
		return fmt.Errorf("owm/node: gossip_interval is negative")
	}
	for i, p := range c.Partners {
		if p.Name == "" {
			return fmt.Errorf("owm/node: partner %d: name is required", i)
		}
		if (p.BaseURL == "") == (p.Domain == "") {
			return fmt.Errorf("owm/node: partner %q: must set exactly one of base_url or domain", p.Name)
		}
	}
	return nil
}

// Duration is a time.Duration that appears in JSON as a string ("5m"). A bare
// number would leave open whether seconds or nanoseconds were meant.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("owm/node: duration expects a string such as \"5m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("owm/node: duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}
