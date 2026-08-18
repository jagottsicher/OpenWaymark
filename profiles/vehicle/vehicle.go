// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package vehicle is the vehicle profile vehicle.v1 — used cars and
// motorcycles from manufacture through import/export, ownership transfers,
// inspections and end-of-life dismantling, including classic-vehicle
// "matching numbers" provenance as one use of the same mechanism, not a
// separate profile.
//
// A VIN is already a clean, globally unique, mandatory identifier
// (ISO 3779): the subject-granularity question food.v1 and pharma.v1 both
// had to answer non-trivially has a fixed answer here — always instance-level,
// the same as aviation.v1's aircraft parts. Full normative specification:
// spec/owm-4-vehicle.md.
package vehicle

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
const ID = "vehicle.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction   = "production"
	EventAggregation  = "aggregation"
	EventTransport    = "transport"
	EventHandover     = "handover"
	EventMeasurement  = "measurement"
	EventInspection   = "inspection"
	EventProcessing   = "processing"
	EventDecommission = "decommission"
)

// New loads the profile.
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/vehicle: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Vehicle - production, aggregation, transport, handover, measurement, inspection, processing, decommission",
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
// signed by a device key, the strong-evidence path alongside the
// human-witnessed odometer claim inspection and handover can also carry
// (spec Sec.5).
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
