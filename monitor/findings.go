// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package monitor

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	owmlog "openwaymark.org/owm/log"

	"openwaymark.org/owm/gossip"
)

// findingFile is the on-disk form of a gossip.Finding: the evidence itself,
// not a summary of it. Previous and Current are the canonical CBOR encoding
// of the two conflicting SignedSTH, base64-encoded — the exact bytes the
// node signed, re-parseable with log.ParseSignedSTH and re-verifiable
// independently of this file's own integrity.
type findingFile struct {
	Target   string                   `json:"target"`
	Kind     string                   `json:"kind"`
	Log      string                   `json:"log"`
	At       time.Time                `json:"at"`
	Previous string                   `json:"previous"`
	Current  string                   `json:"current"`
	Proof    *owmlog.ConsistencyProof `json:"proof,omitempty"`
	Error    string                   `json:"error"`
}

// WriteFinding persists f as one JSON file in dir, named so a directory
// listing sorts chronologically. dir is created if missing. Returns the path
// written.
func WriteFinding(dir, target string, f gossip.Finding) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("owm/monitor: findings directory: %w", err)
	}

	prev, err := encodeSignedSTH(f.Previous)
	if err != nil {
		return "", fmt.Errorf("owm/monitor: encode previous STH: %w", err)
	}
	cur, err := encodeSignedSTH(f.Current)
	if err != nil {
		return "", fmt.Errorf("owm/monitor: encode current STH: %w", err)
	}
	errText := ""
	if f.Err != nil {
		errText = f.Err.Error()
	}

	rec := findingFile{
		Target:   target,
		Kind:     f.Kind.String(),
		Log:      f.Log.String(),
		At:       time.Now().UTC(),
		Previous: prev,
		Current:  cur,
		Proof:    f.Proof,
		Error:    errText,
	}
	buf, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", fmt.Errorf("owm/monitor: encode finding: %w", err)
	}
	buf = append(buf, '\n')

	name := fmt.Sprintf("%d-%s-%s.json", time.Now().UnixNano(), sanitizeFileName(target), f.Kind)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return "", fmt.Errorf("owm/monitor: write finding: %w", err)
	}
	return path, nil
}

func encodeSignedSTH(s *owmlog.SignedSTH) (string, error) {
	if s == nil {
		return "", nil
	}
	b, err := s.Encode()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// sanitizeFileName keeps a target name (operator-controlled config, not
// protocol data) from doing anything but naming a file in the findings
// directory — no path separators, no "..".
func sanitizeFileName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	if b.Len() == 0 {
		return "target"
	}
	return b.String()
}
