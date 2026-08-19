// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package eudr_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/eudr"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := eudr.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, following a cocoa harvest from the plot
// through a manufacturer's due diligence statement — at the same time the
// examples a third-party implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-05-01T08:00:00Z",
		"party": {"name": "Cooperative Terre d'Ivoire"},
		"location": {"country": "CI"},
		"product": {"commodity": "cocoa", "lot": "PLOT-2026-0501",
			"geolocation": {"point": {"lat": 6.123456, "lon": -5.654321}},
			"deforestation_free": true},
		"quantity": {"value": 800, "unit": "KGM"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-05-05T09:00:00Z",
		"action": "add",
		"container": {"commodity": "cocoa", "lot": "POOL-2026-0505"},
		"children": [{"subject": "` + subjectHex + `", "quantity": {"value": 800, "unit": "KGM"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-05-10T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "WestAfrica Freight"},
		"from": {"country": "CI"},
		"to": {"country": "NL"},
		"consignment": "CNT-33021"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-05-20T09:00:00Z",
		"process": "fermenting",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"commodity": "cocoa", "name": "Fermented cocoa beans"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-05-25T14:00:00Z",
		"from": {"name": "Cooperative Terre d'Ivoire"},
		"to": {"name": "EuroChocolate Manufacturing"},
		"transaction": {"type": "desadv", "id": "NL-2026-7710"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-05-18T11:15:00Z",
		"sensor": {"id": "moist-04", "model": "GrainProbe"},
		"quantity_kind": "moisture",
		"unit": "P1",
		"readings": [{"t": "2026-05-18T11:15:00Z", "v": 7.2}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-05-22T16:00:00Z",
		"certified": true,
		"standard": "eudr-dds",
		"reference": "DDS-2026-4471",
		"risk_rating": "negligible"
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

func TestValidPolygonGeolocation(t *testing.T) {
	p := load(t)
	payload := `{
		"event": "production",
		"time": "2026-05-01T08:00:00Z",
		"product": {"commodity": "palm_oil",
			"geolocation": {"polygon": [
				{"lat": 1.1, "lon": 101.1},
				{"lat": 1.2, "lon": 101.1},
				{"lat": 1.2, "lon": 101.2}
			]}}
	}`
	if err := p.Validate([]byte(payload)); err != nil {
		t.Fatalf("valid polygon geolocation rejected: %v", err)
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
		{"time missing", `{"event":"production","product":{"commodity":"cocoa"}}`},
		{"production without a product", `{"event":"production","time":"2026-08-10T06:30:00Z"}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"commodity":"cocoa"},"price":9.9}`},
		{"polygon with fewer than three points", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"commodity":"cocoa","geolocation":{"polygon":[{"lat":1,"lon":1},{"lat":2,"lon":2}]}}}`},
		{"latitude out of range", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"commodity":"cocoa","geolocation":{"point":{"lat":91,"lon":0}}}}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"processing without an output", `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"milling","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"moisture","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"eudr-dds"}`},
		{"release with an unknown risk rating", `{"event":"release","time":"2026-08-10T06:30:00Z","certified":true,"risk_rating":"unknown"}`},
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
			e := &core.Entry{Type: c.typ, Profile: eudr.ID}
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
	if err := profiles.CheckID(eudr.ID); err != nil {
		t.Fatalf("identifier %q: %v", eudr.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  eudr.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", eudr.ID, err)
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
	t.Logf("eudr.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := eudr.MustNew(); p.ID() != eudr.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
