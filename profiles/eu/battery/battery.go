// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package battery is the battery profile eu/battery.v1 — portable, LMT, EV,
// industrial and SLI batteries from manufacture through use, second life
// and end-of-life recycling.
//
// The exact identifier CLAUDE.md, README and OWM-4 Sec.2/Sec.14 have
// already used as the namespace-slash example since this project's
// earliest specs — the second profile earmarked from the start, now built.
//
// Built against the EU Battery Regulation ((EU) 2023/1542) and its
// mandatory Digital Battery Passport. Unlike every profile since
// pharma.v1 that dropped decommission because nothing in scope has a life
// that "ends" in a way worth naming, batteries genuinely do end their
// first life in more than one way, and the regulation cares which:
// decommission.reason distinguishes second_life from recycled, destroyed
// and disposed — see spec/owm-4-battery.md Sec.5.
package battery

import (
	"embed"

	"openwaymark.org/owm/profiles"
)

//go:embed schema/*.json
var schemaFS embed.FS

// ID is the profile identifier as it appears in an entry's prof field.
//
// The slash namespaces this as an EU-specific regulatory profile — the
// example OWM-4 Sec.2 itself uses for why the slash is allowed at all.
const ID = "eu/battery.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction   = "production"
	EventAggregation  = "aggregation"
	EventTransport    = "transport"
	EventProcessing   = "processing"
	EventHandover     = "handover"
	EventMeasurement  = "measurement"
	EventRelease      = "release"
	EventDecommission = "decommission"
)

// New loads the profile.
//
// A measurement is not a self-declaration — it comes from a device and is
// signed by a device key, otherwise a hand-written state-of-health report
// could later be passed off as sensor evidence (profiles.LoadEmbedded).
func New() (*profiles.Profile, error) {
	return profiles.LoadEmbedded(ID,
		"Battery - production, aggregation, transport, processing, handover, measurement, release, decommission",
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
