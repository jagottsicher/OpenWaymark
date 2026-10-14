// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package seafood is the seafood profile seafood.v1 — vessel-to-plate:
// catch, processing, distribution, retail.
//
// A close sibling of food.v1, not a from-scratch design: food.v1's own
// production event already names "catch" as an example use, and this
// profile's own production carries the same name and meaning rather than
// inventing a separate concept — each profile still pins its own,
// independently versioned schema (OWM-4 Sec.3, Sec.4.3).
// Targets what the EU's CATCH system and the US Seafood Import Monitoring
// Program (SIMP) both already require against illegal, unreported and
// unregulated (IUU) fishing. Full normative specification:
// spec/owm-4-seafood.md.
package seafood

import (
	"embed"

	"openwaymark.org/owm/profiles"
)

//go:embed schema/*.json
var schemaFS embed.FS

// ID is the profile identifier as it appears in an entry's prof field.
const ID = "seafood.v1"

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
// A measurement is not a self-declaration — it comes from a device and is
// signed by a device key, otherwise a hand-written cold chain could later
// be passed off as sensor evidence (profiles.LoadEmbedded).
func New() (*profiles.Profile, error) {
	return profiles.LoadEmbedded(ID,
		"Seafood - production, aggregation, transport, processing, handover, measurement, release",
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
