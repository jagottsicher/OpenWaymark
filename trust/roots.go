// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"openwaymark.org/owm/core"
)

// ErrRoot reports a malformed root list.
var ErrRoot = errors.New("owm/trust: invalid root list")

// Root is one locally recognised accreditation root (OWM-6 §8) — the same
// shape as an entry in a browser's root-CA store: a key, a display name,
// and a ceiling on how high a level that key may vouch for. A root
// recognised only up to MaxLevel cannot back a claim above it just because
// it appears in the list.
type Root struct {
	ID       core.KeyID
	Name     string
	MaxLevel Level
}

// RootSet is a verifier's local, operator-supplied trust anchors, keyed by
// KeyID.
//
// Recognising a root is deliberately not a protocol mechanism (OWM-6 §8):
// automating "any ISO-17065-accredited body is recognised" in code would
// misrepresent what the software actually verifies. The nil/empty RootSet
// is the safe default — level 0 for everyone until an operator actively
// decides otherwise.
type RootSet map[core.KeyID]Root

// wireRoot is the JSON shape of one root list entry.
type wireRoot struct {
	ID       string `json:"id"`
	Name     string `json:"name,omitempty"`
	MaxLevel int    `json:"max_level"`
}

// ParseRoots reads a root list: a JSON array of {id, name, max_level}.
func ParseRoots(r io.Reader) (RootSet, error) {
	var wire []wireRoot
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wire); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRoot, err)
	}
	out := make(RootSet, len(wire))
	for i, w := range wire {
		var id core.KeyID
		if err := id.UnmarshalText([]byte(w.ID)); err != nil {
			return nil, fmt.Errorf("%w: root %d: id: %v", ErrRoot, i, err)
		}
		lvl := Level(w.MaxLevel)
		if !lvl.Valid() {
			return nil, fmt.Errorf("%w: root %d: max_level %d out of range 0-6", ErrRoot, i, w.MaxLevel)
		}
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("%w: root %d: duplicate id %s", ErrRoot, i, id)
		}
		out[id] = Root{ID: id, Name: w.Name, MaxLevel: lvl}
	}
	return out, nil
}
