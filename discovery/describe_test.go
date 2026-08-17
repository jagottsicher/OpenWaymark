// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
)

// wellKnownBody builds a canned .well-known/openwaymark JSON body around a
// real key pair, so PublicKey() has genuine bytes to parse.
func wellKnownBody(t *testing.T, protocol string) (string, *core.PrivateKey) {
	t.Helper()
	k, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := k.Public()
	logID, err := core.DeriveLogID(pub)
	if err != nil {
		t.Fatalf("DeriveLogID: %v", err)
	}
	body := fmt.Sprintf(`{
		"protocol": %q,
		"log": %q,
		"base_url": "https://provenance.example.com",
		"operator": {"name": "Test operator", "contact": "mailto:test@example.org"},
		"key": {"alg": "ML-DSA-65", "id": %q, "public": %q},
		"genesis_key": {"alg": "ML-DSA-65", "id": %q, "public": %q},
		"tree_size": 42,
		"profiles": [{"id": "food.v1", "title": "Food", "schema_digest": %q, "files": ["schema.json"]}],
		"max_payload": 262144,
		"max_leaf": 131072,
		"api": "/owm/v1"
	}`, protocol, logID, pub.ID(), hex.EncodeToString(pub.Bytes()), pub.ID(), hex.EncodeToString(pub.Bytes()),
		strings.Repeat("00", 32))
	return body, k
}

func TestDescribe(t *testing.T) {
	body, k := wellKnownBody(t, "OWM/1")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openwaymark" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	info, err := Describe(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if info.Protocol != "OWM/1" {
		t.Errorf("Protocol = %q", info.Protocol)
	}
	if info.TreeSize != 42 {
		t.Errorf("TreeSize = %d", info.TreeSize)
	}
	if len(info.Profiles) != 1 || info.Profiles[0].ID != "food.v1" {
		t.Errorf("Profiles = %+v", info.Profiles)
	}
	pub, err := info.Key.PublicKey()
	if err != nil {
		t.Fatalf("Key.PublicKey: %v", err)
	}
	if pub.ID() != k.Public().ID() {
		t.Error("the recomputed key does not match the key the server signed with")
	}
}

func TestDescribeProtocolMismatch(t *testing.T) {
	body, _ := wellKnownBody(t, "OWM/2")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	if _, err := Describe(context.Background(), srv.URL, nil); !errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("Describe = %v, want ErrProtocolMismatch", err)
	}
}

func TestDescribeMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "{not json")
	}))
	defer srv.Close()

	if _, err := Describe(context.Background(), srv.URL, nil); err == nil {
		t.Fatal("Describe accepted malformed JSON")
	}
}

func TestDescribeBadKeyBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"protocol":"OWM/1","key":{"alg":"ML-DSA-65","public":"deadbeef"}}`)
	}))
	defer srv.Close()

	info, err := Describe(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if _, err := info.Key.PublicKey(); err == nil {
		t.Fatal("PublicKey accepted a key of the wrong length")
	}
}

func TestResolve(t *testing.T) {
	// The record's node= field must be an absolute https URL (OWM-5 §2.1), so
	// this is the one test in the package that needs a TLS server rather than
	// a plain one — using srv.Client(), which is configured to trust the
	// server's self-signed certificate, keeps ParseRecord's https-only rule
	// intact instead of loosening it for the sake of the test.
	body, _ := wellKnownBody(t, "OWM/1")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	fakeLookupTXT(t, map[string][]string{
		"_openwaymark.example.com": {"v=owm1; node=" + srv.URL},
	})

	info, err := Resolve(context.Background(), "example.com", srv.Client())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if info.Protocol != "OWM/1" {
		t.Errorf("Protocol = %q", info.Protocol)
	}
}
