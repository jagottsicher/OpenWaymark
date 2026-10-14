// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"openwaymark.org/owm/core"
)

// ErrPayload reports an attestation payload that does not match any of the
// shapes defined in OWM-6 §3.
var ErrPayload = errors.New("owm/trust: invalid attestation payload")

// Kind discriminates the three attestation payload shapes (OWM-6 §3).
type Kind string

const (
	KindEntity Kind = "entity"
	KindSensor Kind = "sensor"
	// KindConcluded records that the issuer's own participation under this
	// key has ended — a merger, an acquisition by an already independently
	// operating entity, a voluntary wind-down (OWM-9 A15). Always
	// self-issued: node.checkAttestationPayload rejects one where subj does
	// not name the issuer's own key, which is also what makes it inert to
	// Compute without any special case there — a self-referential
	// attestation is already harmless by construction (see compute.go's
	// cycle handling).
	KindConcluded Kind = "concluded"
	// KindBinding claims a physical-digital binding level (OWM-6 §5) for
	// subj — a product, not an entity: how forgery-resistant is the bit's
	// tie to the thing, printed QR code through PUF-backed chip (OWM-9 A8).
	// Unlike KindEntity this is never walked to a root; its credibility
	// rests entirely on the issuer's own entity trust level, recomputed
	// separately and reported alongside it, never folded into one number
	// (CLAUDE.md §4.3's own "never collapsed" rule, one level down). Inert
	// to Compute for the same structural reason KindConcluded already is:
	// Payload.Level (the field Compute reads) is never set for this kind,
	// so it contributes LevelNone and is never chosen over a real claim —
	// no special case needed there either.
	KindBinding Kind = "binding"
)

// Reason discriminates the two shapes KindConcluded can take (OWM-6 §3).
type Reason string

const (
	// ReasonSucceeded means a different, already independently operating
	// key continues the business — Successor names it.
	ReasonSucceeded Reason = "succeeded"
	// ReasonDiscontinued means participation simply ended, with no
	// successor to point to.
	ReasonDiscontinued Reason = "discontinued"
)

// Valid reports whether r is one of the two reasons OWM-6 §3 defines.
func (r Reason) Valid() bool { return r == ReasonSucceeded || r == ReasonDiscontinued }

// Payload is the parsed body of an attestation entry (OWM-6 §3).
//
// Level, Scheme and EvidenceURL are meaningful only for Kind == KindEntity;
// Label only for Kind == KindSensor; Reason and Successor only for
// Kind == KindConcluded (Successor itself only when Reason ==
// ReasonSucceeded); BindingLevel and EvidenceURL only for Kind ==
// KindBinding. ParsePayload enforces the shape each kind requires; the
// others never end up populated for the wrong one.
type Payload struct {
	Kind         Kind
	Level        Level        // KindEntity only.
	Scheme       string       // KindEntity only, informational (OWM-6 §3).
	EvidenceURL  string       // KindEntity, KindConcluded or KindBinding, informational (OWM-6 §3).
	Label        string       // KindSensor only, informational (OWM-6 §3).
	Reason       Reason       // KindConcluded only.
	Successor    core.KeyID   // KindConcluded + ReasonSucceeded only.
	BindingLevel BindingLevel // KindBinding only.
}

// wirePayload is the JSON shape on the wire. Level, Successor and
// BindingLevel are pointers so that "absent" and "explicitly the zero
// value" are distinguishable — OWM-6 §3 requires telling them apart in
// every case: kind:"entity" needs level present, kind:"sensor" needs it
// absent; reason:"succeeded" needs successor present, reason:"discontinued"
// needs it absent; kind:"binding" needs binding_level present (BindingLow
// is 0, not "absent").
type wirePayload struct {
	Kind         string      `json:"kind"`
	Level        *int        `json:"level,omitempty"`
	Scheme       string      `json:"scheme,omitempty"`
	EvidenceURL  string      `json:"evidence_url,omitempty"`
	Label        string      `json:"label,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	Successor    *core.KeyID `json:"successor,omitempty"`
	BindingLevel *int        `json:"binding_level,omitempty"`
}

// ParsePayload reads and strictly validates an attestation payload per the
// MUST rules of OWM-6 §3: kind is "entity", "sensor", "concluded" or
// "binding" and nothing else; kind:"entity" requires a valid level (0-6);
// kind:"sensor" must not carry one; kind:"concluded" requires a valid
// reason, and a successor exactly when reason is "succeeded", never when it
// is "discontinued"; kind:"binding" requires a valid binding_level (0-3).
// An unknown JSON field is also rejected, the same convention node.LoadConfig
// already uses — a mistyped field is a setting that silently has no effect.
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
	case KindConcluded:
		reason := Reason(w.Reason)
		if !reason.Valid() {
			return Payload{}, fmt.Errorf("%w: unknown reason %q", ErrPayload, w.Reason)
		}
		switch reason {
		case ReasonSucceeded:
			if w.Successor == nil {
				return Payload{}, fmt.Errorf("%w: reason %q requires successor", ErrPayload, reason)
			}
			return Payload{Kind: KindConcluded, Reason: reason, Successor: *w.Successor, EvidenceURL: w.EvidenceURL}, nil
		default: // ReasonDiscontinued
			if w.Successor != nil {
				return Payload{}, fmt.Errorf("%w: reason %q must not carry successor", ErrPayload, reason)
			}
			return Payload{Kind: KindConcluded, Reason: reason, EvidenceURL: w.EvidenceURL}, nil
		}
	case KindBinding:
		if w.BindingLevel == nil {
			return Payload{}, fmt.Errorf("%w: kind %q requires binding_level", ErrPayload, w.Kind)
		}
		lvl := BindingLevel(*w.BindingLevel)
		if !lvl.Valid() {
			return Payload{}, fmt.Errorf("%w: binding_level %d out of range 0-3", ErrPayload, *w.BindingLevel)
		}
		return Payload{Kind: KindBinding, BindingLevel: lvl, EvidenceURL: w.EvidenceURL}, nil
	default:
		return Payload{}, fmt.Errorf("%w: unknown kind %q", ErrPayload, w.Kind)
	}
}
