// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package battery_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/eu/battery"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := battery.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, following one EV battery pack from
// manufacture through a second life — at the same time the examples a
// third-party implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-01-15T08:00:00Z",
		"party": {"name": "VoltCell Manufacturing"},
		"product": {"category": "ev", "chemistry": "li-ion", "unique_identifier": "BATT-2026-99213",
			"capacity_kwh": 75, "carbon_footprint_kg_co2e_per_kwh": 62.5,
			"recycled_content": {"cobalt_pct": 12, "lithium_pct": 4}}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-01-16T09:00:00Z",
		"action": "add",
		"container": {"category": "ev", "unique_identifier": "PACK-2026-77213"},
		"children": [{"subject": "` + subjectHex + `"}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-01-20T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "EuroBattery Logistics"},
		"from": {"country": "DE"},
		"to": {"country": "FR"},
		"consignment": "AWB-33021"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2036-01-10T09:00:00Z",
		"process": "hydrometallurgical recovery",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"chemistry": "recovered cobalt sulfate"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-01-25T14:00:00Z",
		"from": {"name": "VoltCell Manufacturing"},
		"to": {"name": "EuroAuto Assembly"},
		"transaction": {"type": "desadv", "id": "FR-2026-4471"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2028-06-01T11:15:00Z",
		"sensor": {"id": "bms-04", "model": "CellGuard"},
		"quantity_kind": "state_of_health",
		"unit": "P1",
		"readings": [{"t": "2028-06-01T11:15:00Z", "v": 91.2}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-01-22T16:00:00Z",
		"certified": true,
		"standard": "carbon-footprint-verification",
		"reference": "PCF-2026-8821"
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2033-05-01T09:00:00Z",
		"reason": "second_life"
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
		{"time missing", `{"event":"production","product":{"category":"ev"}}`},
		{"production without a product", `{"event":"production","time":"2026-08-10T06:30:00Z"}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"ev"},"price":9.9}`},
		{"unknown category", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"toy"}}`},
		{"negative carbon footprint", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"ev","carbon_footprint_kg_co2e_per_kwh":-1}}`},
		{"recycled content over 100", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"ev","recycled_content":{"cobalt_pct":150}}}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"processing without an output", `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"shredding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"state_of_health","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"carbon-footprint-verification"}`},
		{"decommission without a reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`},
		{"decommission with an unknown reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"lost"}`},
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
			e := &core.Entry{Type: c.typ, Profile: battery.ID}
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
	if err := profiles.CheckID(battery.ID); err != nil {
		t.Fatalf("identifier %q: %v", battery.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  battery.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", battery.ID, err)
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
	t.Logf("eu/battery.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := battery.MustNew(); p.ID() != battery.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
