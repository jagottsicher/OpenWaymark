// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package electronics is the electronics profile electronics.v1 — components
// (RAM, SSDs, boards) and finished devices from manufacture through assembly,
// distribution and end-of-life recycling.
//
// Shaped to be expressible against IPC-1782, "Standard for Manufacturing and
// Supply Chain Traceability of Electronic Products" — the electronics
// industry's own EPCIS-equivalent, the same relationship food.v1 has to GS1
// EPCIS 2.0. Two-tier subject granularity, the same shape pharma.v1 already
// established: lot-level for small components (IPC-1782's own M-level
// traceability), instance-level for individually serialized finished
// devices. Full normative specification: spec/owm-4-electronics.md.
package electronics

import (
	"embed"

	"openwaymark.org/owm/profiles"
)

//go:embed schema/*.json
var schemaFS embed.FS

// ID is the profile identifier as it appears in an entry's prof field.
const ID = "electronics.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction   = "production"
	EventAggregation  = "aggregation"
	EventTransport    = "transport"
	EventHandover     = "handover"
	EventMeasurement  = "measurement"
	EventRelease      = "release"
	EventProcessing   = "processing"
	EventDecommission = "decommission"
)

// New loads the profile.
//
// A measurement is not a self-declaration — it comes from a device and is
// signed by a device key, otherwise a hand-written test report could later
// be passed off as sensor evidence (profiles.LoadEmbedded).
func New() (*profiles.Profile, error) {
	return profiles.LoadEmbedded(ID,
		"Electronics - production, aggregation, transport, handover, measurement, release, processing, decommission",
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
