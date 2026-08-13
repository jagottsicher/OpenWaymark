// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package food_test

import (
	"errors"
	"strings"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/food"
)

const subjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := food.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// Ein vollständiger Satz gültiger Ereignisse — zugleich die Beispiele, an denen
// sich eine Fremdimplementierung ausrichten kann.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-08-10T06:30:00+02:00",
		"party": {"name": "Hof Sonnenblick", "gln": "4012345000009"},
		"location": {"country": "DE", "geo": {"lat": 52.5, "lon": 13.4}},
		"product": {"gtin": "04012345678901", "name": "Eier Freiland", "lot": "L-2026-0810"},
		"quantity": {"value": 1000, "unit": "H87"},
		"certifications": [{"scheme": "EU-Bio", "id": "DE-ÖKO-006", "valid_until": "2027-03-31"}]
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-08-10T09:00:00+02:00",
		"action": "add",
		"container": {"name": "Zehnerpackung"},
		"children": [{"subject": "` + subjectHex + `", "quantity": {"value": 10, "unit": "H87"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-08-10T11:15:00+02:00",
		"step": "departure",
		"carrier": {"name": "Kühlspedition Nord"},
		"from": {"gln": "4012345000009"},
		"to": {"gln": "4012345000016"},
		"consignment": "CNSG-77123",
		"conditions": {"temperature_c": {"min": 2, "max": 8}}
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-08-11T08:00:00+02:00",
		"process": "pasteurisieren",
		"inputs": [{"subject": "` + subjectHex + `", "quantity": {"value": 300, "unit": "LTR"}}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Bergkäse"}, "quantity": {"value": 30, "unit": "KGM"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-08-11T14:00:00+02:00",
		"from": {"name": "Molkerei Tal"},
		"to": {"name": "Großhandel Mitte", "gln": "4012345000023"},
		"transaction": {"type": "desadv", "id": "DE-2026-99812"},
		"note": "Teillieferung"
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-08-10T11:15:00+02:00",
		"sensor": {"id": "kuehl-77", "model": "TempLog 3"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [
			{"t": "2026-08-10T11:15:00+02:00", "v": 4.2},
			{"t": "2026-08-10T11:45:00+02:00", "v": 4.6}
		]
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
	if len(valid) != 6 {
		t.Fatalf("the profile has six events, %d are checked", len(valid))
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
		{"unknown field", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"preis":9.9}`},
		{"field of the wrong event", `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"step":"departure"}`},
		{"aggregation without components", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`},
		{"aggregation with the wrong action", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"merge","children":[{"subject":"` + subjectHex + `"}]}`},
		{"subject in upper case", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`},
		{"subject too short", `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"abcd"}]}`},
		{"transport without a step", `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`},
		{"processing without an output", `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"mahlen","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`},
		{"handover without a recipient", `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`},
		{"empty party", `{"event":"handover","time":"2026-08-10T06:30:00Z","to":{}}`},
		{"measurement without a unit", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
		{"measured value as text", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00Z","v":"kalt"}]}`},
		{"unknown quantity", `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"stimmung","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`},
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

// Eine Messung muss als sensor_reading eingereicht werden, alles andere als
// assertion. Sonst ließe sich eine von Hand geschriebene Kühlkette später als
// Gerätebeleg ausgeben.
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
		{"handover", core.EntryTypeAttestation, false},
	}
	for _, c := range cases {
		t.Run(c.event+"/"+c.typ.String(), func(t *testing.T) {
			e := &core.Entry{Type: c.typ, Profile: food.ID}
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

// Die Profilkennung muss den Regeln des Kerns für das Feld prof genügen —
// sonst ließe sich das Profil zwar laden, aber kein Eintrag damit ausstellen.
func TestIDAcceptedByCore(t *testing.T) {
	if err := profiles.CheckID(food.ID); err != nil {
		t.Fatalf("identifier %q: %v", food.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  food.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", food.ID, err)
	}
}

func TestSchemaDigestIsFixed(t *testing.T) {
	a, b := load(t), load(t)
	if a.SchemaDigest() != b.SchemaDigest() {
		t.Fatal("two loads produce different digests")
	}
	// defs, event und sechs Ereignisschemata.
	if len(a.Files()) != 8 {
		t.Fatalf("expected 8 schema files, got %d", len(a.Files()))
	}
	t.Logf("food.v1 schema digest: %s", a.SchemaDigest())
}

func TestMustNew(t *testing.T) {
	if p := food.MustNew(); p.ID() != food.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}
