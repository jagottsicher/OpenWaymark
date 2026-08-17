// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Defaults.
const (
	// DefaultPollInterval is the gap between two polls of a target's STH.
	DefaultPollInterval = 5 * time.Minute
	// DefaultRediscoverInterval is how often a Domain target is re-resolved.
	DefaultRediscoverInterval = time.Hour
	// DefaultFindingsDir is where evidence of a detected contradiction is
	// written by default.
	DefaultFindingsDir = "findings"
)

var (
	// ErrTargetAmbiguous reports a target that sets both, or neither, of
	// base_url and domain.
	ErrTargetAmbiguous = errors.New("owm/monitor: target must set exactly one of base_url or domain")
	// ErrTargetName reports a missing or duplicate target name.
	ErrTargetName = errors.New("owm/monitor: target name is required and must be unique")
)

// Target is one node to watch — directly by URL, or by domain, resolved via
// package discovery on RediscoverInterval so a partner's base URL can change
// without editing this file (OWM-5 §2).
type Target struct {
	// Name identifies this target in log lines and findings file names. MUST
	// be non-empty and unique within a Config.
	Name string `json:"name"`
	// BaseURL is the node's base URL, when known directly. Exactly one of
	// BaseURL and Domain MUST be set.
	BaseURL string `json:"base_url,omitempty"`
	// Domain is resolved via discovery.Resolve.
	Domain string `json:"domain,omitempty"`
}

// Config configures a Monitor.
type Config struct {
	Targets []Target `json:"targets,omitempty"`

	// PollInterval is the gap between two polls of a target's STH.
	PollInterval Duration `json:"poll_interval,omitempty"`

	// RediscoverInterval is how often a Domain target is re-resolved.
	// Ignored for BaseURL targets.
	RediscoverInterval Duration `json:"rediscover_interval,omitempty"`

	// FindingsDir is where evidence of a detected contradiction is written,
	// one file per incident. Created if missing.
	FindingsDir string `json:"findings_dir,omitempty"`
}

// DefaultConfig returns the defaults. Targets is empty — a monitor watching
// nothing is a valid, if useless, starting point for "init".
func DefaultConfig() Config {
	return Config{
		PollInterval:       Duration(DefaultPollInterval),
		RediscoverInterval: Duration(DefaultRediscoverInterval),
		FindingsDir:        DefaultFindingsDir,
	}
}

// LoadConfig reads a JSON configuration layered over the defaults.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("owm/monitor: read configuration: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// A mistyped field is a setting that has no effect — while the operator
	// believes they have set it.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("owm/monitor: read configuration: %w", err)
	}
	return cfg, cfg.Check()
}

// Check fills gaps with defaults and validates the rest, including every
// target.
func (c *Config) Check() error {
	if c.PollInterval <= 0 {
		c.PollInterval = Duration(DefaultPollInterval)
	}
	if c.RediscoverInterval <= 0 {
		c.RediscoverInterval = Duration(DefaultRediscoverInterval)
	}
	if c.FindingsDir == "" {
		c.FindingsDir = DefaultFindingsDir
	}
	seen := make(map[string]bool, len(c.Targets))
	for i, t := range c.Targets {
		if t.Name == "" {
			return fmt.Errorf("%w: target %d", ErrTargetName, i)
		}
		if seen[t.Name] {
			return fmt.Errorf("%w: %q", ErrTargetName, t.Name)
		}
		seen[t.Name] = true
		if (t.BaseURL == "") == (t.Domain == "") {
			return fmt.Errorf("%w: %q", ErrTargetAmbiguous, t.Name)
		}
	}
	return nil
}

// Duration is a time.Duration that appears in JSON as a string ("5m") — the
// same wire convention node.Duration uses, kept as a small local copy so this
// package does not import node for one helper type.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("owm/monitor: duration expects a string such as \"5m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("owm/monitor: duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}
