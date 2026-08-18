// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package eudr is the deforestation-free commodities profile eudr.v1 —
// timber, cocoa, coffee, palm oil, soy, rubber and cattle from the
// production plot through processing to a manufacturer or importer.
//
// Named after the regulation, not a single commodity: what unifies these
// otherwise unrelated supply chains is exactly one shared requirement —
// plot-level geolocation proof that production did not cause deforestation
// after a fixed date (the EU Deforestation Regulation, (EU) 2023/1115).
// That requirement, not any one commodity's own processing steps, is this
// profile's center of gravity — see product.geolocation on the production
// event. Full normative specification: spec/owm-4-eudr.md.
package eudr

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
const ID = "eudr.v1"

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
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/eudr: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Deforestation-free commodities - production, aggregation, transport, processing, handover, measurement, release",
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
// signed by a device key, otherwise a hand-written reading could later be
// passed off as sensor evidence.
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
