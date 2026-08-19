// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package aviation is the aircraft parts profile aviation.v1.
//
// The industry already runs on exactly this shape by hand — a signed document
// chain from manufacture through every installation, removal, repair and
// overhaul to retirement, built on FAA Form 8130-3 / EASA Form 1 airworthiness
// tags and ATA Spec 2000 ch. 15/16. This profile digitises that chain rather
// than inventing a new one:
//
//	OpenWaymark       Aviation industry equivalent
//	production        First Authorized Release Certificate (POA)
//	aggregation       Installed into, or removed from, a higher assembly
//	transport         Departure or arrival of a shipment
//	handover          ATA Spec 2000 ch. 15, Aircraft Transfer Parts List
//	measurement       Condition-monitoring sensor data
//	release           Part-145 re-certification after repair/overhaul
//	decommission      Life-limit reached, scrapped, lost, destroyed
//
// Every subject is instance-level from production onward: an aircraft part
// always carries its own serial number, unlike food.v1's lot-level default or
// pharma.v1's two-tier model. Full normative specification:
// spec/owm-4-aviation.md.
package aviation

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
const ID = "aviation.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction   = "production"
	EventAggregation  = "aggregation"
	EventTransport    = "transport"
	EventHandover     = "handover"
	EventMeasurement  = "measurement"
	EventRelease      = "release"
	EventDecommission = "decommission"
)

// New loads the profile.
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/aviation: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Aviation - production, aggregation, transport, handover, measurement, release, decommission",
		FS:    sub,
		Root:  "event.json",
		Rule:  checkEntryType,
	})
}

// MustNew loads the profile and aborts on error.
func MustNew() *profiles.Profile {
	p, err := New()
	if err != nil {
		panic(err)
	}
	return p
}

// checkEntryType binds the event type to the entry type.
//
// A measurement is not a self-declaration — it comes from a device and is
// signed by a device key, otherwise a hand-written condition report could
// later be passed off as sensor evidence.
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
