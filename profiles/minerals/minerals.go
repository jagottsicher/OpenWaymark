// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package minerals is the raw materials profile minerals.v1 — critical raw
// materials and 3TG minerals (tin, tantalum, tungsten, gold, plus lithium,
// cobalt, nickel, rare earths and copper under the EU's broader
// critical-raw-materials framework) from extraction through smelting/
// refining to a manufacturer.
//
// Built against the OECD Due Diligence Guidance for Responsible Mineral
// Supply Chains' own five-step framework, which concentrates verification at
// smelters and refiners — the control point where materials from many,
// often untraceable, upstream sources converge. No decommission event:
// unlike a device or a vehicle, a mineral batch does not have a life that
// ends — processing already retires an input subject into its output the
// moment it is smelted. Full normative specification:
// spec/owm-4-minerals.md.
package minerals

import (
	"embed"

	"openwaymark.org/owm/profiles"
)

//go:embed schema/*.json
var schemaFS embed.FS

// ID is the profile identifier as it appears in an entry's prof field.
const ID = "minerals.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction  = "production"
	EventAggregation = "aggregation"
	EventTransport   = "transport"
	EventProcessing  = "processing"
	EventHandover    = "handover"
	EventMeasurement = "measurement"
	EventRelease     = "release"
)

// New loads the profile.
//
// EventMeasurement is the only event requiring a sensor_reading entry — a
// measurement is not a self-declaration, it comes from a device and is
// signed by a device key, otherwise a hand-written assay result could
// later be passed off as lab evidence (profiles.LoadEmbedded).
func New() (*profiles.Profile, error) {
	return profiles.LoadEmbedded(ID,
		"Minerals - production, aggregation, transport, processing, handover, measurement, release",
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
