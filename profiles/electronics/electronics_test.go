// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package electronics_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/electronics"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := electronics.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, following memory chips from wafer lot to
// an assembled SSD to end-of-life recycling — at the same time the examples
// a third-party implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-01-10T08:00:00Z",
		"party": {"name": "MemFab Semiconductor"},
		"product": {"part_number": "NAND-512G-A1", "lot": "WL-2026-0110"},
		"quantity": {"value": 50000, "unit": "H87"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-02-01T09:00:00Z",
		"action": "add",
		"container": {"gtin": "04012345678937", "serial": "SSD-99213", "recycled_content_pct": 12.5},
		"children": [{"subject": "` + subjectHex + `", "quantity": {"value": 8, "unit": "H87"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-02-05T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "ChipFreight"},
		"from": {"country": "TW"},
		"to": {"country": "NL"},
		"consignment": "AWB-55219"
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-02-10T14:00:00Z",
		"from": {"name": "MemFab Semiconductor"},
		"to": {"name": "EuroTech Distribution"},
		"transaction": {"type": "desadv", "id": "NL-2026-7710"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-02-12T11:15:00Z",
		"sensor": {"id": "burnin-04", "model": "TestBench 3"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [{"t": "2026-02-12T11:15:00Z", "v": 42.1}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-02-08T16:00:00Z",
		"certified": true,
		"standard": "rohs",
		"reference": "ROHS-2026-4471"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2033-01-10T09:00:00Z",
		"process": "material recovery",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Recovered gold"}}]
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2033-01-15T09:00:00Z",
		"reason": "recycled"
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
	if len(valid) != 8 {
		t.Fatalf("the profile has eight events, %d are checked", len(valid))
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
		{"time missing", `{"event":"production","product":{"name":"x"}}`},
		{"production without a product", `{"event":"production","time":"2026-08-10T06:30:00Z"}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"price":9.9}`},
		{"recycled content over 100", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","recycled_content_pct":150}}`},
		{"negative warranty", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","warranty_months":-1}}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"ce"}`},
		{"processing without an output", `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"shredding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`},
		{"decommission without a reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`},
		{"decommission with an unknown reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"stolen"}`},
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
// including release and decommission — as assertion.
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
		{"decommission", core.EntryTypeAssertion, true},
	}
	for _, c := range cases {
		t.Run(c.event+"/"+c.typ.String(), func(t *testing.T) {
			e := &core.Entry{Type: c.typ, Profile: electronics.ID}
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
	if err := profiles.CheckID(electronics.ID); err != nil {
		t.Fatalf("identifier %q: %v", electronics.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  electronics.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", electronics.ID, err)
	}
}

func TestSchemaDigestIsFixed(t *testing.T) {
	a, b := load(t), load(t)
	if a.SchemaDigest() != b.SchemaDigest() {
		t.Fatal("two loads produce different digests")
	}
	// defs, event and eight event schemas.
	if len(a.Files()) != 10 {
		t.Fatalf("expected 10 schema files, got %d", len(a.Files()))
	}
	t.Logf("electronics.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := electronics.MustNew(); p.ID() != electronics.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
