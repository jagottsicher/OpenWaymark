// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package pharma_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/pharma"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := pharma.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, following one batch from API synthesis to
// dispensing — at the same time the examples a third-party implementation can
// align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-06-01T08:00:00+02:00",
		"party": {"name": "Alpha Pharma Chemicals", "gln": "4012345000101"},
		"location": {"country": "DE"},
		"product": {"name": "Ibuprofen API", "lot": "API-2026-0601", "stage": "api", "coa_ref": "COA-8891"},
		"quantity": {"value": 500, "unit": "KGM"}
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-07-01T09:00:00+02:00",
		"process": "tableting",
		"inputs": [{"subject": "` + subjectHex + `", "product": {"stage": "api"}, "quantity": {"value": 500, "unit": "KGM"}}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Ibuprofen 400mg tablets", "stage": "finished_product", "lot": "FIN-2026-0710"}, "quantity": {"value": 1000000, "unit": "H87"}}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-07-09T16:00:00+02:00",
		"lot": "FIN-2026-0710",
		"certified": true,
		"standard": "eu-gmp-annex16",
		"reference": "REL-2026-4471"
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-07-10T09:00:00+02:00",
		"action": "add",
		"container": {"name": "Case of 100", "gtin": "04012345678920", "lot": "FIN-2026-0710"},
		"children": [{"subject": "` + subjectHex + `", "product": {"stage": "finished_product", "serial": "SN-0001"}, "quantity": {"value": 1, "unit": "H87"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-07-11T07:00:00+02:00",
		"step": "departure",
		"carrier": {"name": "PharmaLog Express"},
		"from": {"gln": "4012345000101"},
		"to": {"gln": "4012345000118"},
		"consignment": "CNSG-55219",
		"conditions": {"temperature_c": {"min": 2, "max": 8}, "max_transit_hours": 24}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-07-11T07:00:00+02:00",
		"sensor": {"id": "cool-91", "model": "TempLog 4"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [
			{"t": "2026-07-11T07:00:00+02:00", "v": 4.1},
			{"t": "2026-07-11T09:00:00+02:00", "v": 4.5}
		]
	}`,
	"storage": `{
		"event": "storage",
		"time": "2026-07-12T10:00:00+02:00",
		"action": "enter",
		"location": {"gln": "4012345000118", "name": "Central Distribution Center"},
		"conditions": {"temperature_c": {"min": 2, "max": 8}}
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-07-15T14:00:00+02:00",
		"from": {"name": "PharmaWholesale Nord", "gln": "4012345000118"},
		"to": {"name": "Apotheke am Markt", "gln": "4012345000125"},
		"transaction": {"type": "desadv", "id": "DE-2026-77410"}
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2026-07-20T11:00:00+02:00",
		"reason": "administered"
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
	if len(valid) != 9 {
		t.Fatalf("the profile has nine events, %d are checked", len(valid))
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
		{"time without a time zone", `{"event":"production","time":"2026-08-10 06:30","product":{"name":"x"}}`},
		{"production without goods", `{"event":"production","time":"2026-08-10T06:30:00Z"}`},
		{"empty goods", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{}}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"price":9.9}`},
		{"unknown stage", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","stage":"raw"}}`},
		{"unknown controlled substance schedule", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","controlled_substance_schedule":"VI"}}`},
		{"field of the wrong event", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"step":"departure"}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"merge","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"subject too short", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"abcd"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"transport with a non-positive max_transit_hours", `{"event":"transport","time":"2026-08-10T06:30:00Z","step":"departure","conditions":{"max_transit_hours":0}}`},
		{"storage without an action", `{"event":"storage","time":"2026-08-10T06:30:00Z","conditions":{"temperature_c":{"min":2,"max":8}}}`},
		{"storage with the wrong action", `{"event":"storage","time":"2026-08-10T06:30:00Z","action":"pause"}`},
		{"processing without an output", `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"grinding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"empty party", `{"event":"handover","time":"2026-08-10T06:30:00Z","to":{}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"measured value as text", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00Z","v":"cold"}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00Z","lot":"L-1"}`},
		{"decommission without a reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`},
		{"decommission with an unknown reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"lost"}`},
		{"coordinate out of range", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"location":{"geo":{"lat":91,"lon":0}}}`},
		{"country code in lower case", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"location":{"country":"de"}}`},
		{"negative quantity", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"quantity":{"value":-1,"unit":"KGM"}}`},
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
// including release and decommission — as assertion. Otherwise a
// hand-written cold chain could later be passed off as device evidence.
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
		{"storage", core.EntryTypeAssertion, true},
		{"handover", core.EntryTypeAttestation, false},
	}
	for _, c := range cases {
		t.Run(c.event+"/"+c.typ.String(), func(t *testing.T) {
			e := &core.Entry{Type: c.typ, Profile: pharma.ID}
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

// The profile identifier has to satisfy the core's rules for the prof field —
// otherwise the profile would load but no entry could be issued with it.
func TestIDAcceptedByCore(t *testing.T) {
	if err := profiles.CheckID(pharma.ID); err != nil {
		t.Fatalf("identifier %q: %v", pharma.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  pharma.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", pharma.ID, err)
	}
}

func TestSchemaDigestIsFixed(t *testing.T) {
	a, b := load(t), load(t)
	if a.SchemaDigest() != b.SchemaDigest() {
		t.Fatal("two loads produce different digests")
	}
	// defs, event and nine event schemas.
	if len(a.Files()) != 11 {
		t.Fatalf("expected 11 schema files, got %d", len(a.Files()))
	}
	t.Logf("pharma.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := pharma.MustNew(); p.ID() != pharma.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
