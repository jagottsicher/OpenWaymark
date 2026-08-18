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
	"encoding/json"
	"fmt"
	"io/fs"

	"openwaymark.org/owm/core"
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
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/minerals: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Minerals - production, aggregation, transport, processing, handover, measurement, release",
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
// signed by a device key, otherwise a hand-written assay result could later
// be passed off as lab evidence.
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
