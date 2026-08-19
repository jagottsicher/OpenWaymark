// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package meddevice_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/meddevice"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := meddevice.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, spanning both halves of this profile's
// scope — an implant (hip system) and capital equipment (an MRI scanner) —
// at the same time the examples a third-party implementation can align
// itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-02-01T08:00:00+01:00",
		"party": {"name": "OrthoWorks Manufacturing", "srn": "DE-MF-000012345"},
		"product": {"udi_di": "(01)04012345678903", "udi_pi": "(21)SN-778812", "name": "Titanium Hip Stem", "class": "III", "device_type": "hip stem implant"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-02-02T09:00:00+01:00",
		"action": "add",
		"container": {"udi_di": "(01)04012345678927", "name": "Hip System Kit", "device_type": "hip implant system"},
		"children": [{"subject": "` + subjectHex + `", "product": {"udi_pi": "(21)SN-778812"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-02-05T07:00:00+01:00",
		"step": "departure",
		"carrier": {"name": "MedLog Express"},
		"from": {"country": "DE"},
		"to": {"country": "AT"},
		"consignment": "AWB-90210"
	}`,
	"installation": `{
		"event": "installation",
		"time": "2026-02-10T11:30:00+01:00",
		"party": {"name": "Universitätsklinikum Graz"},
		"context": "implant"
	}`,
	"maintenance": `{
		"event": "maintenance",
		"time": "2028-03-01T09:00:00+01:00",
		"party": {"name": "Siemens Healthineers Field Service"},
		"action": "calibration",
		"outcome": "pass",
		"parts_replaced": ["X-ray tube assembly"],
		"reference": "SVC-2028-4471"
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2028-03-01T09:15:00+01:00",
		"sensor": {"id": "mri-14", "model": "QA-Phantom-Sensor"},
		"quantity_kind": "image_quality",
		"unit": "P1",
		"readings": [{"t": "2028-03-01T09:15:00+01:00", "v": 97.4}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-01-28T16:00:00+01:00",
		"certified": true,
		"standard": "mdr-conformity-assessment",
		"reference": "CE-2026-8821"
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2036-06-01T09:00:00+01:00",
		"reason": "explanted"
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

// installation.context covers two different real-world moments with one
// event (spec Sec.5) - both have to validate, not just the implant example
// in the main valid map.
func TestInstallationBothContexts(t *testing.T) {
	p := load(t)
	commission := `{
		"event": "installation",
		"time": "2026-02-12T09:00:00+01:00",
		"party": {"name": "Universitätsklinikum Graz"},
		"context": "commission",
		"qualification": {"iq": true, "oq": true, "pq": true}
	}`
	if err := p.Validate([]byte(commission)); err != nil {
		t.Fatalf("valid commission-context installation rejected: %v", err)
	}
}

func TestInvalidEvents(t *testing.T) {
	p := load(t)
	cases := []struct {
		name    string
		payload string
	}{
		{"unknown event", `{"event":"teleportation","time":"2026-08-10T06:30:00+01:00"}`},
		{"event missing", `{"time":"2026-08-10T06:30:00+01:00"}`},
		{"time missing", `{"event":"production","product":{"name":"x"}}`},
		{"time without a time zone", `{"event":"production","time":"2026-08-10 06:30","product":{"name":"x"}}`},
		{"production without a product", `{"event":"production","time":"2026-08-10T06:30:00+01:00"}`},
		{"empty product", `{"event":"production","time":"2026-08-10T06:30:00+01:00","product":{}}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00+01:00","product":{"name":"x"},"price":9.9}`},
		{"unknown class", `{"event":"production","time":"2026-08-10T06:30:00+01:00","product":{"name":"x","class":"IV"}}`},
		{"patient identifier attempted", `{"event":"installation","time":"2026-08-10T06:30:00+01:00","context":"implant","patient":"Jane Doe"}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00+01:00","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00+01:00","action":"install","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00+01:00","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00+01:00","carrier":{"name":"x"}}`},
		{"installation without a context", `{"event":"installation","time":"2026-08-10T06:30:00+01:00"}`},
		{"installation with an unknown context", `{"event":"installation","time":"2026-08-10T06:30:00+01:00","context":"reuse"}`},
		{"maintenance without an action", `{"event":"maintenance","time":"2026-08-10T06:30:00+01:00","outcome":"pass"}`},
		{"maintenance with an unknown outcome", `{"event":"maintenance","time":"2026-08-10T06:30:00+01:00","action":"calibration","outcome":"maybe"}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00+01:00","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00+01:00","v":1}]}`},
		{"measured value as text", `{"event":"measurement","time":"2026-08-10T06:30:00+01:00","sensor":{"id":"a"},"quantity_kind":"temperature","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00+01:00","v":"cold"}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00+01:00","standard":"iso-13485"}`},
		{"decommission without a reason", `{"event":"decommission","time":"2026-08-10T06:30:00+01:00"}`},
		{"decommission with an unknown reason", `{"event":"decommission","time":"2026-08-10T06:30:00+01:00","reason":"lost"}`},
		{"coordinate out of range", `{"event":"production","time":"2026-08-10T06:30:00+01:00","product":{"name":"x"},"location":{"geo":{"lat":91,"lon":0}}}`},
		{"country code in lower case", `{"event":"transport","time":"2026-08-10T06:30:00+01:00","step":"departure","from":{"country":"de"}}`},
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
// including release, maintenance and decommission — as assertion. Otherwise
// a hand-written service log could later be passed off as sensor evidence.
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
		{"maintenance", core.EntryTypeAssertion, true},
		{"maintenance", core.EntryTypeSensorReading, false},
		{"release", core.EntryTypeAssertion, true},
		{"release", core.EntryTypeAttestation, false},
		{"installation", core.EntryTypeAssertion, true},
		{"decommission", core.EntryTypeAssertion, true},
	}
	for _, c := range cases {
		t.Run(c.event+"/"+c.typ.String(), func(t *testing.T) {
			e := &core.Entry{Type: c.typ, Profile: meddevice.ID}
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
	if err := profiles.CheckID(meddevice.ID); err != nil {
		t.Fatalf("identifier %q: %v", meddevice.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  meddevice.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", meddevice.ID, err)
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
	t.Logf("meddevice.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := meddevice.MustNew(); p.ID() != meddevice.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
