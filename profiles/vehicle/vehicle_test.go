// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package vehicle_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/profiletest"
	"openwaymark.org/owm/profiles/vehicle"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following one car from manufacture to
// dismantling — at the same time the examples a third-party implementation
// can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2018-04-01T08:00:00Z",
		"party": {"name": "Sonnenblick Motors"},
		"product": {"vin": "1HGCM82633A004352", "make": "Sonnenblick", "model": "Tourer", "model_year": 2018, "component_type": "vehicle"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2018-04-01T08:05:00Z",
		"action": "install",
		"children": [{"subject": "` + subjectHex + `", "product": {"serial": "ENG-778213", "component_type": "engine"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-06-01T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "EuroAuto Logistics"},
		"from": {"country": "DE"},
		"to": {"country": "PL"},
		"consignment": "BOL-33021"
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-06-05T14:00:00Z",
		"from": {"name": "Sonnenblick Motors"},
		"to": {"name": "Kowalski Autohandel"},
		"odometer": {"value": 42000, "unit": "km"},
		"transaction": {"type": "sale", "id": "DE-2026-9981"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-06-10T11:15:00Z",
		"sensor": {"id": "telematics-04", "model": "ConnectBox"},
		"quantity_kind": "odometer",
		"unit": "km",
		"readings": [{"t": "2026-06-10T11:15:00Z", "v": 42150}]
	}`,
	"inspection": `{
		"event": "inspection",
		"time": "2026-06-12T16:00:00Z",
		"result": "pass",
		"body": "TÜV Rheinland",
		"reference": "TUV-2026-4471",
		"odometer": {"value": 42200, "unit": "km"}
	}`,
	"processing": `{
		"event": "processing",
		"time": "2032-01-10T09:00:00Z",
		"process": "dismantling",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Recovered steel"}}]
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2032-01-15T09:00:00Z",
		"reason": "scrapped"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          vehicle.ID,
		New:         vehicle.New,
		MustNew:     vehicle.MustNew,
		Valid:       valid,
		Events:      8,
		SensorEvent: vehicle.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                                `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                                `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                                 `{"event":"production","product":{"vin":"1HGCM82633A004352"}}`,
			"production without a product":                 `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"unknown field":                                `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"make":"x"},"price":9.9}`,
			"VIN with a forbidden letter":                  `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"vin":"1HGCM82633AOO4352"}}`,
			"VIN too short":                                `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"vin":"1HGCM8263"}}`,
			"unknown component type":                       `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"component_type":"chassis"}}`,
			"aggregation without components":               `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[]}`,
			"aggregation with the wrong action":            `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":                        `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"transport without a step":                     `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"handover without a recipient":                 `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"handover with an odometer in an unknown unit": `{"event":"handover","time":"2026-08-10T06:30:00Z","to":{"name":"x"},"odometer":{"value":1,"unit":"furlongs"}}`,
			"measurement without a unit":                   `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"odometer","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"inspection without a result":                  `{"event":"inspection","time":"2026-08-10T06:30:00Z","body":"x"}`,
			"inspection with an unknown result":            `{"event":"inspection","time":"2026-08-10T06:30:00Z","result":"maybe"}`,
			"processing without an output":                 `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"crushing","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"decommission without a reason":                `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`,
			"decommission with an unknown reason":          `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"stolen"}`,
		},
	})
}
