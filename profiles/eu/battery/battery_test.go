// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package battery_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/eu/battery"
	"openwaymark.org/owm/profiles/profiletest"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following one EV battery pack from
// manufacture through a second life — at the same time the examples a
// third-party implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-01-15T08:00:00Z",
		"party": {"name": "VoltCell Manufacturing"},
		"product": {"category": "ev", "chemistry": "li-ion", "unique_identifier": "BATT-2026-99213",
			"capacity_kwh": 75, "carbon_footprint_kg_co2e_per_kwh": 62.5,
			"recycled_content": {"cobalt_pct": 12, "lithium_pct": 4}}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-01-16T09:00:00Z",
		"action": "add",
		"container": {"category": "ev", "unique_identifier": "PACK-2026-77213"},
		"children": [{"subject": "` + subjectHex + `"}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-01-20T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "EuroBattery Logistics"},
		"from": {"country": "DE"},
		"to": {"country": "FR"},
		"consignment": "AWB-33021"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2036-01-10T09:00:00Z",
		"process": "hydrometallurgical recovery",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"chemistry": "recovered cobalt sulfate"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-01-25T14:00:00Z",
		"from": {"name": "VoltCell Manufacturing"},
		"to": {"name": "EuroAuto Assembly"},
		"transaction": {"type": "desadv", "id": "FR-2026-4471"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2028-06-01T11:15:00Z",
		"sensor": {"id": "bms-04", "model": "CellGuard"},
		"quantity_kind": "state_of_health",
		"unit": "P1",
		"readings": [{"t": "2028-06-01T11:15:00Z", "v": 91.2}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-01-22T16:00:00Z",
		"certified": true,
		"standard": "carbon-footprint-verification",
		"reference": "PCF-2026-8821"
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2033-05-01T09:00:00Z",
		"reason": "second_life"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          battery.ID,
		New:         battery.New,
		MustNew:     battery.MustNew,
		Valid:       valid,
		Events:      8,
		SensorEvent: battery.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                       `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                       `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                        `{"event":"production","product":{"category":"ev"}}`,
			"production without a product":        `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"unknown field":                       `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"ev"},"price":9.9}`,
			"unknown category":                    `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"toy"}}`,
			"negative carbon footprint":           `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"ev","carbon_footprint_kg_co2e_per_kwh":-1}}`,
			"recycled content over 100":           `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"category":"ev","recycled_content":{"cobalt_pct":150}}}`,
			"aggregation without components":      `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action":   `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":               `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"transport without a step":            `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"processing without an output":        `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"shredding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"handover without a recipient":        `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"measurement without a unit":          `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"state_of_health","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"release without a certified flag":    `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"carbon-footprint-verification"}`,
			"decommission without a reason":       `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`,
			"decommission with an unknown reason": `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"lost"}`,
		},
	})
}
