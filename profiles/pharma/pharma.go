// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package pharma is the pharmaceutical profile pharma.v1.
//
// Structured in parallel to food.v1, and deliberately not reinventing what
// already exists: the event set is shaped to be expressible against GS1 US's
// own published cross-walk from DSCSA to EPCIS/CBV events, the same
// commercial data shape TraceLink, SAP ATTP, rfxcel/Antares Vision and
// Systech already exchange in production. Six of nine events are food.v1's,
// unchanged in shape:
//
//	OpenWaymark       EPCIS 2.0 / regulatory anchor
//	production        ObjectEvent, action ADD, bizStep commissioning (ICH Q7 batch genesis)
//	aggregation       AggregationEvent, action ADD/DELETE
//	transport         ObjectEvent, action OBSERVE, bizStep shipping/receiving (EU GDP)
//	processing        TransformationEvent (ICH Q7: starting material -> intermediate -> API -> finished dose)
//	handover          TransactionEvent (DSCSA T3 trigger; FMD chain of custody)
//	measurement       sensor values (EU GDP temperature monitoring)
//
// Three events are new, each for a specific reason spelled out in
// spec/owm-4-pharma.md, not because the other six were found wanting:
//
//	storage           facility stay, distinct from transport (EU GDP; WHO TRS 961 Annex 9 Supp. 8)
//	release           a Qualified Person's batch certification (ICH Q7 / EU GMP Annex 16)
//	decommission      a serialized unit's life ends (GS1 EPCIS decommissioning bizStep)
//
// Full normative specification: spec/owm-4-pharma.md.
package pharma

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
// changes to the schema appear as pharma.v2, not as a new pharma.v1.
const ID = "pharma.v1"

// The profile's event types, as they appear in the payload's event field.
const (
	EventProduction   = "production"
	EventAggregation  = "aggregation"
	EventTransport    = "transport"
	EventStorage      = "storage"
	EventProcessing   = "processing"
	EventHandover     = "handover"
	EventMeasurement  = "measurement"
	EventRelease      = "release"
	EventDecommission = "decommission"
)

// New loads the profile.
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/pharma: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Pharma - production, aggregation, transport, storage, processing, handover, measurement, release, decommission",
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
// A measurement is not a self-declaration. It comes from a device, is signed by
// a device key and therefore has to be submitted as sensor_reading — otherwise a
// hand-written cold chain could later be passed off as sensor evidence. The JSON
// schema cannot check this because it does not see the entry. Every other event,
// including release and decommission, is an ordinary self-declaration by whoever
// issues it — a QP for release, an administering or destroying entity for
// decommission (spec/owm-4-pharma.md Sec.4).
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
