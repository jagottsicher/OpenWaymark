// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package monitor

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigCheckDefaults(t *testing.T) {
	cfg := Config{}
	if err := cfg.Check(); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if cfg.PollInterval.Duration() != DefaultPollInterval {
		t.Errorf("PollInterval = %v", cfg.PollInterval.Duration())
	}
	if cfg.RediscoverInterval.Duration() != DefaultRediscoverInterval {
		t.Errorf("RediscoverInterval = %v", cfg.RediscoverInterval.Duration())
	}
	if cfg.FindingsDir != DefaultFindingsDir {
		t.Errorf("FindingsDir = %q", cfg.FindingsDir)
	}
}

func TestConfigCheckTargets(t *testing.T) {
	cases := []struct {
		name    string
		targets []Target
		wantErr error
	}{
		{"base url only", []Target{{Name: "a", BaseURL: "https://a.example.com"}}, nil},
		{"domain only", []Target{{Name: "a", Domain: "a.example.com"}}, nil},
		{"missing name", []Target{{BaseURL: "https://a.example.com"}}, ErrTargetName},
		{"duplicate name", []Target{
			{Name: "a", BaseURL: "https://a.example.com"},
			{Name: "a", BaseURL: "https://b.example.com"},
		}, ErrTargetName},
		{"neither base url nor domain", []Target{{Name: "a"}}, ErrTargetAmbiguous},
		{"both base url and domain", []Target{{Name: "a", BaseURL: "https://a.example.com", Domain: "a.example.com"}}, ErrTargetAmbiguous},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{Targets: c.targets}
			err := cfg.Check()
			if c.wantErr == nil {
				if err != nil {
					t.Errorf("Check: %v", err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Errorf("Check = %v, want %v", err, c.wantErr)
			}
		})
	}
}

// TestConfigRoundTrip checks that init's output ("owmmonitor init" writes
// exactly this, via DefaultConfig + json.MarshalIndent) can be read straight
// back by LoadConfig.
func TestConfigRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owm-monitor.json")
	cfg := DefaultConfig()
	cfg.Targets = []Target{{Name: "partner", BaseURL: "https://provenance.example.com"}}
	buf, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(got.Targets) != 1 || got.Targets[0].Name != "partner" {
		t.Errorf("Targets = %+v", got.Targets)
	}
	if got.PollInterval != cfg.PollInterval {
		t.Errorf("PollInterval = %v, want %v", got.PollInterval, cfg.PollInterval)
	}
}

func TestConfigUnknownField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owm-monitor.json")
	if err := os.WriteFile(path, []byte(`{"targts":[]}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted an unknown field (a mistyped key would silently do nothing)")
	}
}
