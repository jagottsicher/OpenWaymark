// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package minerals_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/minerals"
	"openwaymark.org/owm/profiles/profiletest"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following tin ore from a mine through
// smelting to a manufacturer — at the same time the examples a third-party
// implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-03-01T08:00:00Z",
		"party": {"name": "Kivu Mining Cooperative"},
		"location": {"country": "CD"},
		"product": {"mineral": "tin", "lot": "ORE-2026-0301"},
		"quantity": {"value": 2000, "unit": "KGM"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-03-10T09:00:00Z",
		"action": "add",
		"container": {"mineral": "tin", "lot": "POOL-2026-0310"},
		"children": [{"subject": "` + subjectHex + `", "quantity": {"value": 2000, "unit": "KGM"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-03-12T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "AfricaFreight"},
		"from": {"country": "CD"},
		"to": {"country": "MY"},
		"consignment": "BOL-77213"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-03-20T09:00:00Z",
		"process": "smelting",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"mineral": "tin", "serial": "SN-99213"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-03-25T14:00:00Z",
		"from": {"name": "Malaysia Smelting Corp"},
		"to": {"name": "EuroElectronics Manufacturing"},
		"transaction": {"type": "export_cert", "id": "MY-2026-4471"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-03-19T11:15:00Z",
		"sensor": {"id": "assay-04", "model": "SpectroLab"},
		"quantity_kind": "purity",
		"unit": "P1",
		"readings": [{"t": "2026-03-19T11:15:00Z", "v": 99.85}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-03-22T16:00:00Z",
		"certified": true,
		"standard": "rmap",
		"reference": "RMAP-2026-8821"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          minerals.ID,
		New:         minerals.New,
		MustNew:     minerals.MustNew,
		Valid:       valid,
		Events:      7,
		SensorEvent: minerals.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                     `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                     `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                      `{"event":"production","product":{"mineral":"gold"}}`,
			"production without a product":      `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"unknown field":                     `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"mineral":"gold"},"price":9.9}`,
			"aggregation without components":    `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action": `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":             `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"transport without a step":          `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"processing without an output":      `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"smelting","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"handover without a recipient":      `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"measurement without a unit":        `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"purity","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"release without a certified flag":  `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"rmap"}`,
			"country code in lower case":        `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"mineral":"gold"},"location":{"country":"cd"}}`,
		},
	})
}
