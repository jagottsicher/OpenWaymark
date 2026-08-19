// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package diamonds_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/diamonds"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := diamonds.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, following one rough diamond from a mine
// through grading — at the same time the examples a third-party
// implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-02-01T08:00:00Z",
		"party": {"name": "Kimberley Diamond Mines"},
		"location": {"country": "ZA"},
		"product": {"carat": 3.5, "origin_country": "ZA", "natural": true, "lot": "ROUGH-2026-0201"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-02-02T09:00:00Z",
		"action": "add",
		"container": {"lot": "PARCEL-2026-0202"},
		"children": [{"subject": "` + subjectHex + `"}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-02-05T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "SecureGem Logistics"},
		"from": {"country": "ZA"},
		"to": {"country": "BE"},
		"consignment": "KP-2026-99213"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-02-20T09:00:00Z",
		"process": "cutting",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"carat": 1.8, "natural": true, "name": "Round brilliant"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-02-25T14:00:00Z",
		"from": {"name": "Antwerp Cutting House"},
		"to": {"name": "Luxury Jewelers Intl"},
		"transaction": {"type": "inv", "id": "BE-2026-7710"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-02-22T11:15:00Z",
		"sensor": {"id": "pl-04", "model": "GemScan Pro"},
		"quantity_kind": "photoluminescence",
		"unit": "NM",
		"readings": [{"t": "2026-02-22T11:15:00Z", "v": 737}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-02-23T16:00:00Z",
		"certified": true,
		"standard": "gia-grading",
		"reference": "GIA-2026-4471998"
	}`,
}

func TestValidEvents(t *testing.T) {
	p := load(t)
	for name, payload := range valid {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate([]byte(payload)); err != nil {
				t.Fatalf("valid event rejected: %v", err)
			}
		})
	}
	if len(valid) != 7 {
		t.Fatalf("the profile has seven events, %d are checked", len(valid))
	}
}

func TestInvalidEvents(t *testing.T) {
	p := load(t)
	cases := []struct {
		name    string
		payload string
	}{
		{"unknown event", `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`},
		{"event missing", `{"time":"2026-08-10T06:30:00Z"}`},
		{"time missing", `{"event":"production","product":{"carat":1}}`},
		{"production without a product", `{"event":"production","time":"2026-08-10T06:30:00Z"}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"carat":1},"price":9.9}`},
		{"zero carat", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"carat":0}}`},
		{"origin country in lower case", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"carat":1,"origin_country":"za"}}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"processing without an output", `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"cutting","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"photoluminescence","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"gia-grading"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := p.Validate([]byte(c.payload)); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
}

// A measurement has to be submitted as sensor_reading, everything else —
// including release — as assertion.
func TestEntryTypeRule(t *testing.T) {
	p := load(t)
	cases := []struct {
		event string
		typ   core.EntryType
		ok    bool
	}{
		{"production", core.EntryTypeAssertion, true},
		{"production", core.EntryTypeSensorReading, false},
		{"measurement", core.EntryTypeSensorReading, true},
		{"measurement", core.EntryTypeAssertion, false},
		{"release", core.EntryTypeAssertion, true},
		{"release", core.EntryTypeAttestation, false},
	}
	for _, c := range cases {
		t.Run(c.event+"/"+c.typ.String(), func(t *testing.T) {
			e := &core.Entry{Type: c.typ, Profile: diamonds.ID}
			err := p.Check(e, []byte(valid[c.event]))
			if c.ok && err != nil {
				t.Fatalf("unexpectedly rejected: %v", err)
			}
			if !c.ok {
				if err == nil {
					t.Fatal("unexpectedly accepted")
				}
				if !errors.Is(err, profiles.ErrEntry) {
					t.Fatalf("expected ErrEntry, got %v", err)
				}
			}
		})
	}
}

func TestIDAcceptedByCore(t *testing.T) {
	if err := profiles.CheckID(diamonds.ID); err != nil {
		t.Fatalf("identifier %q: %v", diamonds.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  diamonds.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", diamonds.ID, err)
	}
}

func TestSchemaDigestIsFixed(t *testing.T) {
	a, b := load(t), load(t)
	if a.SchemaDigest() != b.SchemaDigest() {
		t.Fatal("two loads produce different digests")
	}
	// defs, event and seven event schemas.
	if len(a.Files()) != 9 {
		t.Fatalf("expected 9 schema files, got %d", len(a.Files()))
	}
	t.Logf("diamonds.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := diamonds.MustNew(); p.ID() != diamonds.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
