// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package aviation_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/aviation"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := aviation.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events, following one life-limited part from
// manufacture to retirement — at the same time the examples a third-party
// implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2020-03-01T08:00:00Z",
		"party": {"name": "CFM International"},
		"product": {"part_number": "738K001", "serial_number": "SN-88213", "name": "HPT blade",
			"certificate_ref": "8130-2020-441", "approval_type": "poa",
			"life_limited": true, "cycle_limit": 20000, "cycles_used": 0}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2020-03-15T09:00:00Z",
		"action": "install",
		"container": {"part_number": "CFM56-7B", "serial_number": "ENG-7734"},
		"children": [{"subject": "` + subjectHex + `"}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-06-01T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "AeroFreight"},
		"from": {"country": "US"},
		"to": {"country": "DE"},
		"consignment": "AWB-99213"
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-06-05T14:00:00Z",
		"from": {"name": "LeaseCo Aviation"},
		"to": {"name": "Lufthansa Technik"},
		"transaction": {"type": "lease", "id": "LT-2026-771"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-06-10T11:15:00Z",
		"sensor": {"id": "vib-04", "model": "MonitorX"},
		"quantity_kind": "vibration",
		"unit": "MMS",
		"readings": [{"t": "2026-06-10T11:15:00Z", "v": 0.8}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-06-12T16:00:00Z",
		"certified": true,
		"certificate_ref": "8130-2026-9981",
		"cycles_used": 14320
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2028-01-10T09:00:00Z",
		"reason": "life_limit_reached"
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
		{"time missing", `{"event":"production","product":{"name":"x"}}`},
		{"time without a time zone", `{"event":"production","time":"2026-08-10 06:30","product":{"name":"x"}}`},
		{"production without a part", `{"event":"production","time":"2026-08-10T06:30:00Z"}`},
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"price":9.9}`},
		{"unknown approval type", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","approval_type":"self"}}`},
		{"negative cycles used", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","cycles_used":-1}}`},
		{"cycle limit zero", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","cycle_limit":0}}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"vibration","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"release without a certified flag", `{"event":"release","time":"2026-08-10T06:30:00Z","certificate_ref":"x"}`},
		{"decommission without a reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`},
		{"decommission with an unknown reason", `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"melted"}`},
		{"country code in lower case", `{"event":"transport","time":"2026-08-10T06:30:00Z","step":"departure","from":{"country":"de"}}`},
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
			e := &core.Entry{Type: c.typ, Profile: aviation.ID}
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
	if err := profiles.CheckID(aviation.ID); err != nil {
		t.Fatalf("identifier %q: %v", aviation.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  aviation.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", aviation.ID, err)
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
	t.Logf("aviation.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := aviation.MustNew(); p.ID() != aviation.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
