// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

// ChainTrust is the trust level of an entire supply chain, reported as a
// pair (OWM-6 §7) — entity and binding are not on a shared scale, so they
// are never collapsed into one number.
type ChainTrust struct {
	Entity  Level
	Binding BindingLevel
}

// Aggregate applies the minimum principle (OWM-6 §7): the trust level of a
// chain is the lowest level among every participating entity and every
// physical-digital binding involved, each dimension computed independently.
//
// One weakly verified participant, or one low-grade binding, drags the
// whole chain's reported level on that dimension down to its own — even if
// everything else involved is highly verified.
//
// An empty entities or bindings slice reports LevelNone / BindingLow, the
// safe default for a dimension nobody supplied any evidence for, not "no
// opinion".
func Aggregate(entities []Level, bindings []BindingLevel) ChainTrust {
	out := ChainTrust{Entity: LevelNone, Binding: BindingLow}
	for i, e := range entities {
		if i == 0 || e < out.Entity {
			out.Entity = e
		}
	}
	for i, b := range bindings {
		if i == 0 || b < out.Binding {
			out.Binding = b
		}
	}
	return out
}
