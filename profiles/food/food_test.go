// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package food_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/food"
	"openwaymark.org/owm/profiles/profiletest"
)

const subjectHex = profiletest.SubjectHex

func load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := food.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

// A complete set of valid events — at the same time the examples a third-party
// implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-08-10T06:30:00+02:00",
		"party": {"name": "Hof Sonnenblick", "gln": "4012345000009"},
		"location": {"country": "DE", "geo": {"lat": 52.5, "lon": 13.4}},
		"product": {"gtin": "04012345678901", "name": "Free-range eggs", "lot": "L-2026-0810"},
		"quantity": {"value": 1000, "unit": "H87"},
		"certifications": [{"scheme": "EU-Bio", "id": "DE-ÖKO-006", "valid_until": "2027-03-31"}]
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-08-10T09:00:00+02:00",
		"action": "add",
		"container": {"name": "Ten-pack"},
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
		"process": "pasteurizing",
		"inputs": [{"subject": "` + subjectHex + `", "quantity": {"value": 300, "unit": "LTR"}}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Bergkäse"}, "quantity": {"value": 30, "unit": "KGM"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-08-11T14:00:00+02:00",
		"from": {"name": "Molkerei Tal"},
		"to": {"name": "Großhandel Mitte", "gln": "4012345000023"},
		"transaction": {"type": "desadv", "id": "DE-2026-99812"},
		"note": "Partial delivery"
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-08-10T11:15:00+02:00",
		"sensor": {"id": "cool-77", "model": "TempLog 3"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [
			{"t": "2026-08-10T11:15:00+02:00", "v": 4.2},
			{"t": "2026-08-10T11:45:00+02:00", "v": 4.6}
		]
	}`,
}

// TestCrossCheckColdChainWithinRange confirms the profile's own valid
// transport/measurement pair — 2 to 8 C promised, readings at 4.2 and 4.6 —
// reports nothing: agreement is silence, not a finding of its own.
func TestCrossCheckColdChainWithinRange(t *testing.T) {
	p := load(t)
	if finding, ok := p.CrossCheck([]byte(valid["transport"]), []byte(valid["measurement"])); ok {
		t.Fatalf("false positive on a cold chain that held: %q", finding)
	}
}

// TestCrossCheckColdChainBreach is OWM-9 A4's own concrete example, built
// out: a temperature logger's readings automatically contradicting a false
// cold-chain claim, found by machine rather than by a human comparing two
// documents by eye.
func TestCrossCheckColdChainBreach(t *testing.T) {
	p := load(t)
	msmt := `{
		"event": "measurement",
		"time": "2026-08-10T11:15:00+02:00",
		"sensor": {"id": "cool-77", "model": "TempLog 3"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [
			{"t": "2026-08-10T11:15:00+02:00", "v": 4.2},
			{"t": "2026-08-10T12:15:00+02:00", "v": 9.1},
			{"t": "2026-08-10T13:15:00+02:00", "v": 9.6}
		]
	}`
	finding, ok := p.CrossCheck([]byte(valid["transport"]), []byte(msmt))
	if !ok {
		t.Fatal("breach not detected")
	}
	if !strings.Contains(finding, "2 of 3") {
		t.Errorf("finding %q does not name the breach count", finding)
	}
}

// TestCrossCheckColdChainUnrelatedClaim confirms a claim that carries no
// temperature range — production, which has nothing to promise a sensor
// could contradict — is silently skipped rather than treated as a breach or
// an error.
func TestCrossCheckColdChainUnrelatedClaim(t *testing.T) {
	p := load(t)
	if finding, ok := p.CrossCheck([]byte(valid["production"]), []byte(valid["measurement"])); ok {
		t.Fatalf("unrelated claim treated as a breach: %q", finding)
	}
}

// TestCrossCheckColdChainMalformed confirms garbage input fails closed —
// silently, not with a panic — on both sides.
func TestCrossCheckColdChainMalformed(t *testing.T) {
	p := load(t)
	if _, ok := p.CrossCheck([]byte("not json"), []byte(valid["measurement"])); ok {
		t.Error("malformed claim treated as a breach")
	}
	if _, ok := p.CrossCheck([]byte(valid["transport"]), []byte("not json")); ok {
		t.Error("malformed measurement treated as a breach")
	}
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          food.ID,
		New:         food.New,
		MustNew:     food.MustNew,
		Valid:       valid,
		Events:      6,
		SensorEvent: food.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                     `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                     `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                      `{"event":"production","product":{"name":"x"}}`,
			"time without a time zone":          `{"event":"production","time":"2026-08-10 06:30","product":{"name":"x"}}`,
			"production without goods":          `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"empty goods":                       `{"event":"production","time":"2026-08-10T06:30:00Z","product":{}}`,
			"unknown field":                     `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"price":9.9}`,
			"field of the wrong event":          `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"step":"departure"}`,
			"aggregation without components":    `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action": `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"merge","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":             `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"subject too short":                 `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"abcd"}]}`,
			"transport without a step":          `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"processing without an output":      `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"grinding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"handover without a recipient":      `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"empty party":                       `{"event":"handover","time":"2026-08-10T06:30:00Z","to":{}}`,
			"measurement without a unit":        `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"measured value as text":            `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00Z","v":"cold"}]}`,
			"unknown quantity":                  `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"mood","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"coordinate out of range":           `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"location":{"geo":{"lat":91,"lon":0}}}`,
			"country code in lower case":        `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"location":{"country":"de"}}`,
			"negative quantity":                 `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"quantity":{"value":-1,"unit":"KGM"}}`,
		},
	})
}
