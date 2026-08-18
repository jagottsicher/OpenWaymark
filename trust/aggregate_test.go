// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import "testing"

func TestAggregateMinimumPrinciple(t *testing.T) {
	got := Aggregate(
		[]Level{LevelState, LevelAccredited, LevelDomain},
		[]BindingLevel{BindingVeryHigh, BindingLow, BindingHigh},
	)
	want := ChainTrust{Entity: LevelDomain, Binding: BindingLow}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAggregateSingleParticipant(t *testing.T) {
	got := Aggregate([]Level{LevelCertified}, []BindingLevel{BindingHigh})
	want := ChainTrust{Entity: LevelCertified, Binding: BindingHigh}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAggregateEmptyReportsSafeDefaults(t *testing.T) {
	// Empty is "nobody supplied evidence for this dimension", the safe
	// default (LevelNone / BindingLow) — not some sentinel meaning "no
	// opinion".
	got := Aggregate(nil, nil)
	want := ChainTrust{Entity: LevelNone, Binding: BindingLow}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestAggregateOneEmptyOneNot(t *testing.T) {
	got := Aggregate([]Level{LevelState}, nil)
	want := ChainTrust{Entity: LevelState, Binding: BindingLow}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
