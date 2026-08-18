// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrPayload reports an attestation payload that does not match either
// shape defined in OWM-6 §3.
var ErrPayload = errors.New("owm/trust: invalid attestation payload")

// Kind discriminates the two attestation payload shapes (OWM-6 §3).
type Kind string

const (
	KindEntity Kind = "entity"
	KindSensor Kind = "sensor"
)

// Payload is the parsed body of an attestation entry (OWM-6 §3).
//
// Level, Scheme and EvidenceURL are meaningful only for Kind == KindEntity;
// Label only for Kind == KindSensor. ParsePayload enforces the shape that
// split requires; the two never end up populated for the wrong Kind.
type Payload struct {
	Kind        Kind
	Level       Level  // KindEntity only.
	Scheme      string // KindEntity only, informational (OWM-6 §3).
	EvidenceURL string // KindEntity only, informational (OWM-6 §3).
	Label       string // KindSensor only, informational (OWM-6 §3).
}

// wirePayload is the JSON shape on the wire. Level is a *int so that
// "absent" and "explicitly 0" are distinguishable — Payload.Level alone,
// an int, cannot express that difference, and OWM-6 §3 requires telling
// them apart: kind:"entity" needs level present, kind:"sensor" needs it
// absent.
type wirePayload struct {
	Kind        string `json:"kind"`
	Level       *int   `json:"level,omitempty"`
	Scheme      string `json:"scheme,omitempty"`
	EvidenceURL string `json:"evidence_url,omitempty"`
	Label       string `json:"label,omitempty"`
}

// ParsePayload reads and strictly validates an attestation payload per the
// three MUST rules of OWM-6 §3: kind is "entity" or "sensor" and nothing
// else; kind:"entity" requires a valid level (0-6); kind:"sensor" must not
// carry one. An unknown JSON field is also rejected, the same convention
// node.LoadConfig already uses — a mistyped field is a setting that
// silently has no effect.
func ParsePayload(raw []byte) (Payload, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var w wirePayload
	if err := dec.Decode(&w); err != nil {
		return Payload{}, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	switch Kind(w.Kind) {
	case KindEntity:
		if w.Level == nil {
			return Payload{}, fmt.Errorf("%w: kind %q requires level", ErrPayload, w.Kind)
		}
		lvl := Level(*w.Level)
		if !lvl.Valid() {
			return Payload{}, fmt.Errorf("%w: level %d out of range 0-6", ErrPayload, *w.Level)
		}
		return Payload{Kind: KindEntity, Level: lvl, Scheme: w.Scheme, EvidenceURL: w.EvidenceURL}, nil
	case KindSensor:
		if w.Level != nil {
			return Payload{}, fmt.Errorf("%w: kind %q must not carry level", ErrPayload, w.Kind)
		}
		return Payload{Kind: KindSensor, Label: w.Label}, nil
	default:
		return Payload{}, fmt.Errorf("%w: unknown kind %q", ErrPayload, w.Kind)
	}
}
