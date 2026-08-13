// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package food ist das Lebensmittelprofil food.v1 — das erste Schema-Profil
// von OpenWaymark.
//
// Die Ereignisse sind an GS1 EPCIS 2.0 angelehnt statt neu erfunden. Das ist
// keine Bequemlichkeit: EPCIS ist die Sprache, in der Handel und Logistik
// Lieferkettenereignisse ohnehin schon beschreiben. Wer daran anknüpft, braucht
// keine Übersetzungsschicht; wer sich eine eigene Semantik ausdenkt, hat sie
// für immer.
//
//	OpenWaymark       EPCIS 2.0
//	production        ObjectEvent, action ADD, bizStep commissioning
//	aggregation       AggregationEvent, action ADD/DELETE
//	transport         ObjectEvent, action OBSERVE, bizStep shipping/receiving
//	processing        TransformationEvent
//	handover          TransactionEvent
//	measurement       Sensorwerte (in EPCIS: sensorElementList)
//
// Alle sechs Ereignisse teilen sich eine einzige Profilkennung. Das ist
// Absicht: Stünde der Ereignistyp im Feld prof des Eintrags, wäre nach einer
// Löschung immer noch sichtbar, welche Art Ereignis es war. So bleibt nur
// stehen, dass es zu einem Zeitpunkt ein Lebensmittelereignis zu einem Subjekt
// gab.
package food

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

// ID ist die Profilkennung, wie sie im Feld prof eines Eintrags steht.
//
// Die Version gehört in die Kennung, weil eine Profilversion unveränderlich
// ist: Änderungen am Schema erscheinen als food.v2, nicht als neues food.v1.
const ID = "food.v1"

// Die Ereignistypen des Profils, wie sie im Feld event der Nutzlast stehen.
const (
	EventProduction  = "production"
	EventAggregation = "aggregation"
	EventTransport   = "transport"
	EventProcessing  = "processing"
	EventHandover    = "handover"
	EventMeasurement = "measurement"
)

// New lädt das Profil.
func New() (*profiles.Profile, error) {
	sub, err := fs.Sub(schemaFS, "schema")
	if err != nil {
		return nil, fmt.Errorf("owm/profiles/food: embedded schemas: %w", err)
	}
	return profiles.Load(profiles.Options{
		ID:    ID,
		Title: "Food - production, aggregation, transport, processing, handover, measurement",
		FS:    sub,
		Root:  "event.json",
		Rule:  checkEntryType,
	})
}

// MustNew lädt das Profil und bricht bei Fehlern ab.
//
// Vertretbar, weil die Schemata einkompiliert sind: Ein Fehler hier heißt, dass
// das Binary kaputt gebaut wurde, und nicht, dass zur Laufzeit etwas schiefging.
func MustNew() *profiles.Profile {
	p, err := New()
	if err != nil {
		panic(err)
	}
	return p
}

// checkEntryType bindet den Ereignistyp an den Eintragstyp.
//
// Eine Messung ist keine Selbstauskunft. Sie kommt von einem Gerät, wird von
// einem Geräteschlüssel signiert und muss deshalb als sensor_reading eingereicht
// werden — sonst ließe sich eine von Hand geschriebene Kühlkette später als
// Sensorbeleg ausgeben. Das JSON-Schema kann das nicht prüfen, weil es den
// Eintrag nicht sieht.
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
