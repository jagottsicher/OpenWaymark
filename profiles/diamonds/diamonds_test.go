// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package diamonds_test

import (
	"strings"
	"testing"

	"openwaymark.org/owm/profiles/diamonds"
	"openwaymark.org/owm/profiles/profiletest"
)

const subjectHex = profiletest.SubjectHex

// A complete set of valid events, following one rough diamond from a mine
// through grading — at the same time the examples a third-party
// implementation can align itself with.
var valid = map[string]string{
	"production": `{
		"event": "production",
		"time": "2026-02-01T08:00:00Z",
		"party": {"name": "Kimberley Diamond Mines"},
		"location": {"country": "ZA"},
		"product": {"carat": 3.5, "origin_country": "ZA", "natural": true, "lot": "ROUGH-2026-0201"}
	}`,
	"aggregation": `{
		"event": "aggregation",
		"time": "2026-02-02T09:00:00Z",
		"action": "add",
		"container": {"lot": "PARCEL-2026-0202"},
		"children": [{"subject": "` + subjectHex + `"}]
	}`,
	"transport": `{
		"event": "transport",
		"time": "2026-02-05T07:00:00Z",
		"step": "departure",
		"carrier": {"name": "SecureGem Logistics"},
		"from": {"country": "ZA"},
		"to": {"country": "BE"},
		"consignment": "KP-2026-99213"
	}`,
	"processing": `{
		"event": "processing",
		"time": "2026-02-20T09:00:00Z",
		"process": "cutting",
		"inputs": [{"subject": "` + subjectHex + `"}],
		"outputs": [{"subject": "` + subjectHex + `", "product": {"carat": 1.8, "natural": true, "name": "Round brilliant"}}]
	}`,
	"handover": `{
		"event": "handover",
		"time": "2026-02-25T14:00:00Z",
		"from": {"name": "Antwerp Cutting House"},
		"to": {"name": "Luxury Jewelers Intl"},
		"transaction": {"type": "inv", "id": "BE-2026-7710"}
	}`,
	"measurement": `{
		"event": "measurement",
		"time": "2026-02-22T11:15:00Z",
		"sensor": {"id": "pl-04", "model": "GemScan Pro"},
		"quantity_kind": "photoluminescence",
		"unit": "NM",
		"readings": [{"t": "2026-02-22T11:15:00Z", "v": 737}]
	}`,
	"release": `{
		"event": "release",
		"time": "2026-02-23T16:00:00Z",
		"certified": true,
		"standard": "gia-grading",
		"reference": "GIA-2026-4471998"
	}`,
}

func TestProfile(t *testing.T) {
	profiletest.Run(t, profiletest.Suite{
		ID:          diamonds.ID,
		New:         diamonds.New,
		MustNew:     diamonds.MustNew,
		Valid:       valid,
		Events:      7,
		SensorEvent: diamonds.EventMeasurement,
		Invalid: map[string]string{
			"unknown event":                     `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`,
			"event missing":                     `{"time":"2026-08-10T06:30:00Z"}`,
			"time missing":                      `{"event":"production","product":{"carat":1}}`,
			"production without a product":      `{"event":"production","time":"2026-08-10T06:30:00Z"}`,
			"unknown field":                     `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"carat":1},"price":9.9}`,
			"zero carat":                        `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"carat":0}}`,
			"origin country in lower case":      `{"event":"production","time":"2026-08-10T06:30:00Z","product":{"carat":1,"origin_country":"za"}}`,
			"aggregation without components":    `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[]}`,
			"aggregation with the wrong action": `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"install","children":[{"subject":"` + subjectHex + `"}]}`,
			"subject in upper case":             `{"event":"aggregation","time":"2026-08-10T06:30:00Z","action":"add","children":[{"subject":"` + strings.ToUpper(subjectHex) + `"}]}`,
			"transport without a step":          `{"event":"transport","time":"2026-08-10T06:30:00Z","carrier":{"name":"x"}}`,
			"processing without an output":      `{"event":"processing","time":"2026-08-10T06:30:00Z","process":"cutting","inputs":[{"subject":"` + subjectHex + `"}],"outputs":[]}`,
			"handover without a recipient":      `{"event":"handover","time":"2026-08-10T06:30:00Z","from":{"name":"x"}}`,
			"measurement without a unit":        `{"event":"measurement","time":"2026-08-10T06:30:00Z","sensor":{"id":"a"},"quantity_kind":"photoluminescence","readings":[{"t":"2026-08-10T06:30:00Z","v":1}]}`,
			"release without a certified flag":  `{"event":"release","time":"2026-08-10T06:30:00Z","standard":"gia-grading"}`,
		},
	})
}
