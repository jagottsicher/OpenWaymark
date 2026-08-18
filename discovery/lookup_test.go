// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"net"
	"testing"
)

// fakeLookupTXT substitutes the package's DNS resolver for the duration of a
// test, so none of this ever touches real DNS. A name absent from records
// resolves as NXDOMAIN, matching what a real resolver reports for a domain
// that runs no OpenWaymark node at all.
func fakeLookupTXT(t *testing.T, records map[string][]string) {
	t.Helper()
	orig := lookupTXT
	lookupTXT = func(ctx context.Context, name string) ([]string, error) {
		if recs, ok := records[name]; ok {
			return recs, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	t.Cleanup(func() { lookupTXT = orig })
}

func TestLookup(t *testing.T) {
	fakeLookupTXT(t, map[string][]string{
		"_openwaymark.example.com": {"v=owm1; node=https://provenance.example.com"},
	})
	rec, err := Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rec.NodeURL != "https://provenance.example.com" {
		t.Errorf("NodeURL = %q", rec.NodeURL)
	}
}

// TestLookupIgnoresForeignRecord proves the self-identifying-prefix property
// actually works: an unrelated TXT record at the same name must not stop
// resolution.
func TestLookupIgnoresForeignRecord(t *testing.T) {
	fakeLookupTXT(t, map[string][]string{
		"_openwaymark.example.com": {
			"v=spf1 include:_spf.example.com ~all",
			"v=owm1; node=https://provenance.example.com",
		},
	})
	rec, err := Lookup(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if rec.NodeURL != "https://provenance.example.com" {
		t.Errorf("NodeURL = %q", rec.NodeURL)
	}
}

func TestLookupNoRecord(t *testing.T) {
	fakeLookupTXT(t, map[string][]string{})
	if _, err := Lookup(context.Background(), "example.com"); !errors.Is(err, ErrNoRecord) {
		t.Errorf("Lookup = %v, want ErrNoRecord", err)
	}
}

// TestLookupOperationalError checks that a real resolver failure (as opposed
// to "this name does not exist") is reported as itself, not folded into
// ErrNoRecord — a timeout is not the same finding as "no node here."
func TestLookupOperationalError(t *testing.T) {
	orig := lookupTXT
	lookupTXT = func(ctx context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "timeout", Name: name, IsTimeout: true}
	}
	t.Cleanup(func() { lookupTXT = orig })

	_, err := Lookup(context.Background(), "example.com")
	if err == nil || errors.Is(err, ErrNoRecord) {
		t.Errorf("Lookup = %v, want a plain operational error, not ErrNoRecord", err)
	}
}

func TestLookupAmbiguous(t *testing.T) {
	fakeLookupTXT(t, map[string][]string{
		"_openwaymark.example.com": {
			"v=owm1; node=https://a.example.com",
			"v=owm1; node=https://b.example.com",
		},
	})
	if _, err := Lookup(context.Background(), "example.com"); !errors.Is(err, ErrAmbiguousRecord) {
		t.Errorf("Lookup = %v, want ErrAmbiguousRecord", err)
	}
}
