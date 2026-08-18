// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseRoots(t *testing.T) {
	a := testKey(t, 1)
	b := testKey(t, 2)
	raw := `[
		{"id":"` + a.String() + `","name":"Alpha Certification Body","max_level":6},
		{"id":"` + b.String() + `","max_level":4}
	]`
	roots, err := ParseRoots(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseRoots: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("got %d roots, want 2", len(roots))
	}
	if got := roots[a]; got.Name != "Alpha Certification Body" || got.MaxLevel != LevelState {
		t.Errorf("root a = %+v", got)
	}
	if got := roots[b]; got.Name != "" || got.MaxLevel != LevelCertified {
		t.Errorf("root b = %+v", got)
	}
}

func TestParseRootsEmpty(t *testing.T) {
	roots, err := ParseRoots(strings.NewReader(`[]`))
	if err != nil {
		t.Fatalf("ParseRoots: %v", err)
	}
	if len(roots) != 0 {
		t.Errorf("got %d roots, want 0", len(roots))
	}
}

func TestParseRootsRejects(t *testing.T) {
	valid := testKey(t, 1).String()
	cases := []struct {
		name string
		raw  string
	}{
		{"malformed id", `[{"id":"not-hex","max_level":4}]`},
		{"max_level out of range", `[{"id":"` + valid + `","max_level":7}]`},
		{"negative max_level", `[{"id":"` + valid + `","max_level":-1}]`},
		{"unknown field", `[{"id":"` + valid + `","max_level":4,"unexpected":true}]`},
		{"duplicate id", `[{"id":"` + valid + `","max_level":4},{"id":"` + valid + `","max_level":6}]`},
		{"not an array", `{"id":"` + valid + `","max_level":4}`},
		{"not json", `not json at all`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseRoots(strings.NewReader(tc.raw))
			if !errors.Is(err, ErrRoot) {
				t.Errorf("ParseRoots(%q) err = %v, want it to wrap %v", tc.raw, err, ErrRoot)
			}
		})
	}
}

func TestParseRootsFromBytesReader(t *testing.T) {
	// ParseRoots takes an io.Reader, not a path — exercised once against
	// bytes.Reader too, since node/ will feed it an os.File.
	roots, err := ParseRoots(bytes.NewReader([]byte(`[]`)))
	if err != nil {
		t.Fatalf("ParseRoots: %v", err)
	}
	if roots == nil {
		t.Error("got nil RootSet, want a non-nil empty one")
	}
}
