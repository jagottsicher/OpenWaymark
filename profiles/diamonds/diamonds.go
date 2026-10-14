// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package diamonds is the diamonds profile diamonds.v1 — mine through
// cutting/polishing to a retailer. CLAUDE.md's own vision section names
// "diamonds" as a founding example of what this project should demonstrate,
// alongside food and batteries; this profile is that example, concretely.
//
// Built against the Kimberley Process Certification Scheme (rough-diamond
// shipment certification) and the US FTC's mandatory lab-grown disclosure.
// A diamond passes through two distinct third-party certifications — no
// separate mechanism for each: both are release, distinguished by
// standard. No decommission: unlike a device or a vehicle, a polished
// diamond does not have a life that ends. Full normative specification:
// spec/owm-4-diamonds.md.
package diamonds

import (
	"embed"

	"openwaymark.org/owm/profiles"
)

//go:embed schema/*.json
var schemaFS embed.FS

// ID is the profile identifier as it appears in an entry's prof field.
const ID = "diamonds.v1"

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
// signed by a device key, otherwise a hand-written test result could later
// be passed off as sensor evidence (profiles.LoadEmbedded).
func New() (*profiles.Profile, error) {
	return profiles.LoadEmbedded(ID,
		"Diamonds - production, aggregation, transport, processing, handover, measurement, release",
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
