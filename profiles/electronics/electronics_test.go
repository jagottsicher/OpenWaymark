// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package electronics_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/electronics"
	"openwaymark.org/owm/profiles/profiletest"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following memory chips from wafer lot to
// an assembled SSD to end-of-life recycling — at the same time the examples
// a third-party implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-01-10T08:00:00Z",
		"party": {"name": "MemFab Semiconductor"},
		"product": {"part_number": "NAND-512G-A1", "lot": "WL-2026-0110"},
		"quantity": {"value": 50000, "unit": "H87"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-02-01T09:00:00Z",
		"action": "add",
		"container": {"gtin": "04012345678937", "serial": "SSD-99213", "recycled_content_pct": 12.5},
		"children": [{"subject": "` + subjectHex + `", "quantity": {"value": 8, "unit": "H87"}}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-02-05T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "ChipFreight"},
		"from": {"country": "TW"},
		"to": {"country": "NL"},
		"consignment": "AWB-55219"
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-02-10T14:00:00Z",
		"from": {"name": "MemFab Semiconductor"},
		"to": {"name": "EuroTech Distribution"},
		"transaction": {"type": "desadv", "id": "NL-2026-7710"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-02-12T11:15:00Z",
		"sensor": {"id": "burnin-04", "model": "TestBench 3"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [{"t": "2026-02-12T11:15:00Z", "v": 42.1}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-02-08T16:00:00Z",
		"certified": true,
		"standard": "rohs",
		"reference": "ROHS-2026-4471"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2033-01-10T09:00:00Z",
		"process": "material recovery",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"name": "Recovered gold"}}]
	}`,
	"decommission": `{
		"event": "decommission",
		"time": "2033-01-15T09:00:00Z",
		"reason": "recycled"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          electronics.ID,
		New:         electronics.New,
		MustNew:     electronics.MustNew,
		Valid:       valid,
		Events:      8,
		SensorEvent: electronics.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                       `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                       `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                        `{"event":"production","product":{"name":"x"}}`,
			"production without a product":        `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"unknown field":                       `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x"},"price":9.9}`,
			"recycled content over 100":           `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","recycled_content_pct":150}}`,
			"negative warranty":                   `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"name":"x","warranty_months":-1}}`,
			"aggregation without components":      `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action":   `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":               `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"transport without a step":            `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"handover without a recipient":        `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"measurement without a unit":          `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"temperature","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"release without a certified flag":    `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"ce"}`,
			"processing without an output":        `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"shredding","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"decommission without a reason":       `{"event":"decommission","time":"2026-08-10T06:30:00Z"}`,
			"decommission with an unknown reason": `{"event":"decommission","time":"2026-08-10T06:30:00Z","reason":"stolen"}`,
		},
	})
}
