// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package pharma_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/pharma"
	"openwaymark.org/owm/profiles/profiletest"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following one batch from API synthesis to
// dispensing — at the same time the examples a third-party implementation can
// align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-06-01T08:00:00+02:00",
		"party": {"name": "Alpha Pharma Chemicals", "gln": "4012345000101"},
		"location": {"country": "DE"},
		"product": {"name": "Ibuprofen API", "lot": "API-2026-0601", "stage": "api", "coa_ref": "COA-8891"},
		"quantity": {"value": 500, "unit": "KGM"}
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-07-01T09:00:00+02:00",
		"process": "tableting",
		"inputs": [{"subject": "` + subjectHex + `", "product": {"stage": "api"}, "quantity": {"value": 500, "unit": "KGM"}}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Ibuprofen 400mg tablets", "stage": "finished_product", "lot": "FIN-2026-0710"}, "quantity": {"value": 1000000, "unit": "H87"}}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-07-09T16:00:00+02:00",
		"lot": "FIN-2026-0710",
		"certified": true,
		"standard": "eu-gmp-annex16",
		"reference": "REL-2026-4471"
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-07-10T09:00:00+02:00",
		"action": "add",
		"container": {"name": "Case of 100", "gtin": "04012345678920", "lot": "FIN-2026-0710"},
		"children": [{"subject": "` + subjectHex + `", "product": {"stage": "finished_product", "serial": "SN-0001"}, "quantity": {"value": 1, "unit": "H87"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-07-11T07:00:00+02:00",
		"step": "departure",
		"carrier": {"name": "PharmaLog Express"},
		"from": {"gln": "4012345000101"},
		"to": {"gln": "4012345000118"},
		"consignment": "CNSG-55219",
		"conditions": {"temperature_c": {"min": 2, "max": 8}, "max_transit_hours": 24}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-07-11T07:00:00+02:00",
		"sensor": {"id": "cool-91", "model": "TempLog 4"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [
			{"t": "2026-07-11T07:00:00+02:00", "v": 4.1},
			{"t": "2026-07-11T09:00:00+02:00", "v": 4.5}
		]
	}`,
	"storage": `{
		"event": "storage",
		"time": "2026-07-12T10:00:00+02:00",
		"action": "enter",
		"location": {"gln": "4012345000118", "name": "Central Distribution Center"},
		"conditions": {"temperature_c": {"min": 2, "max": 8}}
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-07-15T14:00:00+02:00",
		"from": {"name": "PharmaWholesale Nord", "gln": "4012345000118"},
		"to": {"name": "Apotheke am Markt", "gln": "4012345000125"},
		"transaction": {"type": "desadv", "id": "DE-2026-77410"}
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2026-07-20T11:00:00+02:00",
		"reason": "administered"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          pharma.ID,
		New:         pharma.New,
		MustNew:     pharma.MustNew,
		Valid:       valid,
		Events:      9,
		SensorEvent: pharma.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                                   `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                                   `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                                    `{"event":"production","product":{"name":"x"}}`,
			"time without a time zone":                        `{"event":"production","time":"2026-08-10 06:30","product":{"name":"x"}}`,
			"production without goods":                        `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"empty goods":                                     `{"event":"production","time":"2026-08-10T06:30:00Z","product":{}}`,
			"unknown field":                                   `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"price":9.9}`,
			"unknown stage":                                   `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","stage":"raw"}}`,
			"unknown controlled substance schedule":           `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","controlled_substance_schedule":"VI"}}`,
			"field of the wrong event":                        `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"step":"departure"}`,
			"aggregation without components":                  `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action":               `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"merge","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":                           `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"subject too short":                               `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"abcd"}]}`,
			"transport without a step":                        `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"transport with a non-positive max_transit_hours": `{"event":"transport","time":"2026-08-10T06:30:00Z","step":"departure","conditions":{"max_transit_hours":0}}`,
			"storage without an action":                       `{"event":"storage","time":"2026-08-10T06:30:00Z","conditions":{"temperature_c":{"min":2,"max":8}}}`,
			"storage with the wrong action":                   `{"event":"storage","time":"2026-08-10T06:30:00Z","action":"pause"}`,
			"processing without an output":                    `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"grinding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"handover without a recipient":                    `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"empty party":                                     `{"event":"handover","time":"2026-08-10T06:30:00Z","to":{}}`,
			"measurement without a unit":                      `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"measured value as text":                          `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","unit":"CEL","readings":[{"t":"2026-08-10T06:30:00Z","v":"cold"}]}`,
			"release without a certified flag":                `{"event":"release","time":"2026-08-10T06:30:00Z","lot":"L-1"}`,
			"decommission without a reason":                   `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`,
			"decommission with an unknown reason":             `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"lost"}`,
			"coordinate out of range":                         `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"location":{"geo":{"lat":91,"lon":0}}}`,
			"country code in lower case":                      `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"location":{"country":"de"}}`,
			"negative quantity":                               `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"quantity":{"value":-1,"unit":"KGM"}}`,
		},
	})
}
