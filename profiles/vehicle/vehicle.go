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
//
// A measurement is not a self-declaration — it comes from a device and is
// signed by a device key, the strong-evidence path alongside the
// human-witnessed odometer claim inspection and handover can also carry
// (spec Sec.5; profiles.LoadEmbedded).
func New() (*profiles.Profile, error) {
	return profiles.LoadEmbedded(ID,
		"Vehicle - production, aggregation, transport, handover, measurement, inspection, processing, decommission",
		schemaFS, EventMeasurement, nil)
}

// MustNew loads the profile and aborts on error.
func MustNew() *profiles.Profile {
	p, err := New()
	if err != nil {
		panic(err)
	}
	return p
}
