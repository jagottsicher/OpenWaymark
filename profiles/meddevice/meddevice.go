// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package meddevice is the medical device profile meddevice.v1.
//
// Scoped to devices with an individually meaningful life-cycle — implantable
// devices (pacemakers, joint replacements, stents) and capital or reusable
// equipment (imaging systems, surgical equipment) — not disposable Class I
// items such as bandages, which have no per-unit story worth a dedicated
// event chain. Both halves of that scope share the same regulatory backbone,
// EU MDR's UDI/EUDAMED system and its US counterpart, FDA's UDI system/GUDID,
// harmonised internationally through IMDRF — and the same shape: always
// instance-level (spec Sec.3), the way aviation.v1 and vehicle.v1 already are.
//
// Two ideas not present in any prior profile:
//
//	installation  one event for two things MDR treats the same way: a device
//	              implanted in a patient (Art.18 Implant Card) or equipment
//	              commissioned at a facility (IQ/OQ/PQ) — never a patient
//	              identifier, in either case (spec Sec.5).
//	maintenance   ongoing service history as a first-class event, not folded
//	              into release or measurement — a capital device's safety case
//	              rests on this history as much as on any single reading
//	              (spec Sec.6).
//
// Full normative specification: spec/owm-4-meddevice.md.
package meddevice

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
// changes to the schema appear as meddevice.v2, not as a new meddevice.v1.
const ID = "meddevice.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction   = "production"
	EventAggregation  = "aggregation"
	EventTransport    = "transport"
	EventInstallation = "installation"
	EventMaintenance  = "maintenance"
	EventMeasurement  = "measurement"
	EventRelease      = "release"
	EventDecommission = "decommission"
)

// New loads the profile.
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/meddevice: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Medical devices - production, aggregation, transport, installation, maintenance, measurement, release, decommission",
		FS:    sub,
		Root:  "event.json",
		Rule:  checkEntryType,
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
// A measurement comes from a device, is signed by a device key and therefore
// has to be submitted as sensor_reading — otherwise a hand-written reading
// could later be passed off as sensor evidence. The JSON schema cannot check
// this because it does not see the entry. Every other event, including
// release, maintenance and decommission, is an ordinary self-declaration by
// whoever issues it (spec Sec.4, Sec.7).
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
