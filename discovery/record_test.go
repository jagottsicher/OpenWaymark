// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"errors"
	"testing"
)

func TestParseRecord(t *testing.T) {
	good := "v=owm1; node=https://provenance.example.com"
	rec, err := ParseRecord(good)
	if err != nil {
		t.Fatalf("ParseRecord(%q): %v", good, err)
	}
	if rec.NodeURL != "https://provenance.example.com" {
		t.Errorf("NodeURL = %q", rec.NodeURL)
	}
}

func TestParseRecordVariants(t *testing.T) {
	cases := []struct {
		name string
		txt  string
	}{
		{"no space after semicolon", "v=owm1;node=https://example.com"},
		{"extra whitespace", "v=owm1 ; node=https://example.com "},
		{"trailing unknown field", "v=owm1; node=https://example.com; key=value"},
		{"node not first extra field", "v=owm1; note=hello; node=https://example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, err := ParseRecord(c.txt)
			if err != nil {
				t.Fatalf("ParseRecord(%q): %v", c.txt, err)
			}
			if rec.NodeURL != "https://example.com" {
				t.Errorf("NodeURL = %q", rec.NodeURL)
			}
		})
	}
}

func TestParseRecordRejects(t *testing.T) {
	cases := []struct {
		name string
		txt  string
	}{
		{"empty", ""},
		{"no tag at all", "node=https://example.com"},
		{"wrong version", "v=owm2; node=https://example.com"},
		{"foreign record at the same name", "v=spf1 include:_spf.example.com ~all"},
		{"tag but no node field", "v=owm1; key=value"},
		{"node value not absolute", "v=owm1; node=/relative/path"},
		{"node value not https", "v=owm1; node=http://example.com"},
		{"node value not a URL at all", "v=owm1; node=not a url"},
		{"node value empty", "v=owm1; node="},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseRecord(c.txt); !errors.Is(err, ErrBadRecord) {
				t.Errorf("ParseRecord(%q) = %v, want ErrBadRecord", c.txt, err)
			}
		})
	}
}

// FuzzParseRecord guards the one place in this package that manually parses
// bytes an attacker can influence: a TXT record's origin is not
// authenticated absent DNSSEC (OWM-5 §2.1), so ParseRecord must never panic
// on adversarial input, only ever return ErrBadRecord or a valid Record.
func FuzzParseRecord(f *testing.F) {
	seeds := []string{
		"v=owm1; node=https://provenance.example.com",
		"v=owm1;node=https://example.com",
		"v=owm1 ; node=https://example.com ; key=value",
		"v=spf1 include:_spf.example.com ~all",
		"",
		"v=owm1",
		"v=owm1;",
		"v=owm1; node=",
		"v=owm1; node=not a url",
		";;;",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, txt string) {
		rec, err := ParseRecord(txt)
		if err != nil {
			if rec != nil {
				t.Fatalf("ParseRecord(%q) returned both a record and an error", txt)
			}
			return
		}
		if rec == nil || rec.NodeURL == "" {
			t.Fatalf("ParseRecord(%q) returned a record with no NodeURL", txt)
		}
	})
}
