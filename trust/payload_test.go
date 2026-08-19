// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"errors"
	"testing"
)

func TestParsePayloadEntity(t *testing.T) {
	p, err := ParsePayload([]byte(`{"kind":"entity","level":4,"scheme":"iso17065","evidence_url":"https://example.org/cert/1"}`))
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	want := Payload{Kind: KindEntity, Level: LevelCertified, Scheme: "iso17065", EvidenceURL: "https://example.org/cert/1"}
	if p != want {
		t.Errorf("got %+v, want %+v", p, want)
	}
}

func TestParsePayloadEntityMinimal(t *testing.T) {
	// scheme and evidence_url are both optional.
	p, err := ParsePayload([]byte(`{"kind":"entity","level":0}`))
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if p.Kind != KindEntity || p.Level != LevelNone {
		t.Errorf("got %+v", p)
	}
}

func TestParsePayloadSensor(t *testing.T) {
	p, err := ParsePayload([]byte(`{"kind":"sensor","label":"Cold-chain logger, unit TW-7"}`))
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	want := Payload{Kind: KindSensor, Label: "Cold-chain logger, unit TW-7"}
	if p != want {
		t.Errorf("got %+v, want %+v", p, want)
	}
}

func TestParsePayloadSensorMinimal(t *testing.T) {
	p, err := ParsePayload([]byte(`{"kind":"sensor"}`))
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if p.Kind != KindSensor || p.Label != "" {
		t.Errorf("got %+v", p)
	}
}

const testSuccessorHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

func TestParsePayloadConcludedSucceeded(t *testing.T) {
	raw := `{"kind":"concluded","reason":"succeeded","successor":"` + testSuccessorHex + `","evidence_url":"https://example.org/merger-notice"}`
	p, err := ParsePayload([]byte(raw))
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if p.Kind != KindConcluded || p.Reason != ReasonSucceeded {
		t.Fatalf("got %+v", p)
	}
	if got := p.Successor.String(); got != testSuccessorHex {
		t.Fatalf("successor = %s, want %s", got, testSuccessorHex)
	}
	if p.EvidenceURL != "https://example.org/merger-notice" {
		t.Fatalf("evidence_url = %q", p.EvidenceURL)
	}
}

func TestParsePayloadConcludedDiscontinued(t *testing.T) {
	p, err := ParsePayload([]byte(`{"kind":"concluded","reason":"discontinued"}`))
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	want := Payload{Kind: KindConcluded, Reason: ReasonDiscontinued}
	if p != want {
		t.Errorf("got %+v, want %+v", p, want)
	}
}

func TestParsePayloadRejects(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"unknown kind", `{"kind":"organization","level":4}`},
		{"entity without level", `{"kind":"entity"}`},
		{"entity with negative level", `{"kind":"entity","level":-1}`},
		{"entity with level above 6", `{"kind":"entity","level":7}`},
		{"sensor with level", `{"kind":"sensor","level":4}`},
		{"sensor with level 0", `{"kind":"sensor","level":0}`},
		{"unknown field", `{"kind":"entity","level":4,"unexpected":true}`},
		{"not an object", `["entity"]`},
		{"empty", ``},
		{"not json", `not json at all`},
		{"concluded without reason", `{"kind":"concluded"}`},
		{"concluded with unknown reason", `{"kind":"concluded","reason":"retired"}`},
		{"concluded succeeded without successor", `{"kind":"concluded","reason":"succeeded"}`},
		{"concluded discontinued with successor", `{"kind":"concluded","reason":"discontinued","successor":"` + testSuccessorHex + `"}`},
		{"concluded with malformed successor", `{"kind":"concluded","reason":"succeeded","successor":"not-hex"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePayload([]byte(tc.raw))
			if !errors.Is(err, ErrPayload) {
				t.Errorf("ParsePayload(%q) err = %v, want it to wrap %v", tc.raw, err, ErrPayload)
			}
		})
	}
}
