// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package food is the food profile food.v1 — the first schema profile of
// OpenWaymark.
//
// The events follow GS1 EPCIS 2.0 instead of being invented anew. That is not
// convenience: EPCIS is the language in which trade and logistics already
// describe supply chain events. Whoever builds on it needs no translation layer;
// whoever thinks up their own semantics is stuck with them forever.
//
//	OpenWaymark       EPCIS 2.0
//	production        ObjectEvent, action ADD, bizStep commissioning
//	aggregation       AggregationEvent, action ADD/DELETE
//	transport         ObjectEvent, action OBSERVE, bizStep shipping/receiving
//	processing        TransformationEvent
//	handover          TransactionEvent
//	measurement       sensor values (in EPCIS: sensorElementList)
//
// All six events share a single profile identifier. That is deliberate: were the
// event type to sit in the entry's prof field, it would still be visible after
// an erasure what kind of event it had been. This way all that remains is that
// at some point there was a food event about a subject.
package food

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
)

//go:embed schema/*.json
var schemaFS embed.FS

// ID is the profile identifier as it appears in an entry's prof field.
//
// The version belongs in the identifier because a profile version is immutable:
// changes to the schema appear as food.v2, not as a new food.v1.
const ID = "food.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction  = "production"
	EventAggregation = "aggregation"
	EventTransport   = "transport"
	EventProcessing  = "processing"
	EventHandover    = "handover"
	EventMeasurement = "measurement"
)

// New loads the profile.
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/food: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:         ID,
		Title:      "Food - production, aggregation, transport, processing, handover, measurement",
		FS:         sub,
		Root:       "event.json",
		Rule:       checkEntryType,
		CrossCheck: crossCheckColdChain,
	})
}

// MustNew loads the profile and aborts on error.
//
// Defensible because the schemas are compiled in: an error here means the binary
// was built broken, not that something went wrong at runtime.
func MustNew() *profiles.Profile {
	p, err := New()
	if err != nil {
		panic(err)
	}
	return p
}

// checkEntryType binds the event type to the entry type.
//
// A measurement is not a self-declaration. It comes from a device, is signed by
// a device key and therefore has to be submitted as sensor_reading — otherwise a
// hand-written cold chain could later be passed off as sensor evidence. The JSON
// schema cannot check this because it does not see the entry.
func checkEntryType(e *core.Entry, payload []byte) error {
	var head struct {
		Event string `json:"event"`
	}
	if err := json.Unmarshal(payload, &head); err != nil {
		return fmt.Errorf("no readable event type: %w", err)
	}
	want := core.EntryTypeAssertion
	if head.Event == EventMeasurement {
		want = core.EntryTypeSensorReading
	}
	if e.Type != want {
		return fmt.Errorf("event %q requires entry type %s, but %s was submitted",
			head.Event, want, e.Type)
	}
	return nil
}

// crossCheckColdChain compares a transport event's promised temperature
// range against a linked measurement event's readings — the one concrete
// example OWM-9 A4 names for its "found by machine" mitigation: a
// temperature logger automatically contradicting a false cold-chain claim.
// Runs client-side, not at the node (profiles.CrossCheckFunc).
//
// Silent (ok=false) whenever there is nothing to compare — claim carries no
// temperature range, or msmt carries no readings — rather than treating an
// unrelated pair of entries as a false positive.
func crossCheckColdChain(claim, msmt []byte) (string, bool) {
	var c struct {
		Conditions struct {
			TemperatureC *struct {
				Min float64 `json:"min"`
				Max float64 `json:"max"`
			} `json:"temperature_c"`
		} `json:"conditions"`
	}
	if err := json.Unmarshal(claim, &c); err != nil || c.Conditions.TemperatureC == nil {
		return "", false
	}
	var m struct {
		Readings []struct {
			T string  `json:"t"`
			V float64 `json:"v"`
		} `json:"readings"`
	}
	if err := json.Unmarshal(msmt, &m); err != nil || len(m.Readings) == 0 {
		return "", false
	}

	lo, hi := c.Conditions.TemperatureC.Min, c.Conditions.TemperatureC.Max
	var breaches int
	for _, r := range m.Readings {
		if r.V < lo || r.V > hi {
			breaches++
		}
	}
	if breaches == 0 {
		return "", false
	}
	return fmt.Sprintf("cold chain: %d of %d sensor readings outside the promised %.1f to %.1f C range",
		breaches, len(m.Readings), lo, hi), true
}
