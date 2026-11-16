// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package seafood_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/profiletest"
	"openwaymark.org/owm/profiles/seafood"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following one catch from the vessel to a
// retailer — at the same time the examples a third-party implementation can
// align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-04-01T06:00:00Z",
		"party": {"name": "F/V Nordstern", "imo": "9876543", "flag": "IS"},
		"location": {"country": "IS"},
		"product": {"species": "COD", "catch_zone": "FAO27", "gear": "trawl", "lot": "CATCH-2026-0401"},
		"quantity": {"value": 4000, "unit": "KGM"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-04-02T09:00:00Z",
		"action": "add",
		"container": {"species": "COD", "lot": "POOL-2026-0402"},
		"children": [{"subject": "` + subjectHex + `", "quantity": {"value": 4000, "unit": "KGM"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-04-02T11:00:00Z",
		"step": "arrival",
		"carrier": {"name": "ColdFreight"},
		"from": {"country": "IS"},
		"to": {"country": "DE"},
		"consignment": "CNT-88213",
		"conditions": {"temperature_c": {"min": -2, "max": 2}}
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-04-03T09:00:00Z",
		"process": "filleting",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"species": "COD", "name": "Cod fillets"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-04-05T14:00:00Z",
		"from": {"name": "Nordsee Processing GmbH"},
		"to": {"name": "Frischfisch Handel"},
		"transaction": {"type": "desadv", "id": "DE-2026-7710"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-04-02T11:15:00Z",
		"sensor": {"id": "cool-12", "model": "TempLog 2"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [{"t": "2026-04-02T11:15:00Z", "v": 0.5}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-04-02T08:00:00Z",
		"certified": true,
		"standard": "eu-catch",
		"reference": "CATCH-2026-9981"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          seafood.ID,
		New:         seafood.New,
		MustNew:     seafood.MustNew,
		Valid:       valid,
		Events:      7,
		SensorEvent: seafood.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                     `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                     `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                      `{"event":"production","product":{"species":"COD"}}`,
			"production without a product":      `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"unknown field":                     `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"species":"COD"},"price":9.9}`,
			"vessel flag in lower case":         `{"event":"production","time":"2026-08-10T06:30:00Z","party":{"name":"x","flag":"is"},"product":{"species":"COD"}}`,
			"aggregation without components":    `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action": `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":             `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"transport without a step":          `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"processing without an output":      `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"filleting","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"handover without a recipient":      `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"measurement without a unit":        `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"release without a certified flag":  `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"eu-catch"}`,
		},
	})
}
