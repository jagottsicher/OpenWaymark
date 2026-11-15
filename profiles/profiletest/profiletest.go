// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package profiletest holds the checks every schema profile has to pass.
//
// Each profile ships its own fixtures — the valid events it documents and the
// malformed ones it has to reject — but the assertions made about them are the
// same for all of them, and were copied verbatim from profile to profile until
// this package existed.
//
// What stays with the profile is the data; what moves here is the checking.
// Every check runs as a named subtest, so a failure still names both the
// profile (through its own package) and the event.
package profiletest

import (
	"errors"
	"maps"
	"slices"
	"testing"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
)

// SubjectHex is the subject identifier the profile fixtures refer to. It is
// an arbitrary 32-byte value in lower-case hex: the profiles only ever check
// its form, never resolve it.
const SubjectHex = "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687"

// entryTypes are all types an entry can carry, so that the entry type rule can
// be checked exhaustively rather than against a hand-picked few.
var entryTypes = []core.EntryType{
	core.EntryTypeAssertion,
	core.EntryTypeAttestation,
	core.EntryTypeRevocation,
	core.EntryTypeKeyRotation,
	core.EntryTypeSensorReading,
	core.EntryTypeErasure,
}

// Suite is everything a profile contributes to the shared checks.
type Suite struct {
	// ID is the profile identifier, e.g. "food.v1".
	ID string
	// New and MustNew are the profile package's two constructors.
	New     func() (*profiles.Profile, error)
	MustNew func() *profiles.Profile

	// Valid maps an event name to a payload the profile has to accept. It
	// doubles as the set of worked examples a third-party implementation can
	// align itself with, which is why Events below is asserted against it: an
	// event added to the profile without an example here is a gap in the
	// documentation, not only in the test.
	Valid map[string]string
	// Events is how many events the profile defines.
	Events int

	// SensorEvent is the one event that comes from a device and therefore has
	// to be submitted as a sensor reading; every other event is an assertion
	// (profiles.LoadEmbedded). Empty when the profile has no such event.
	SensorEvent string

	// Invalid maps the reason a payload is wrong to that payload.
	Invalid map[string]string
}

// Run executes every shared check against s.
func Run(t *testing.T, s Suite) {
	t.Helper()

	t.Run("valid events", func(t *testing.T) { s.validEvents(t) })
	t.Run("invalid events", func(t *testing.T) { s.invalidEvents(t) })
	t.Run("entry type rule", func(t *testing.T) { s.entryTypeRule(t) })
	t.Run("identifier accepted by core", func(t *testing.T) { s.idAcceptedByCore(t) })
	t.Run("schema digest is fixed", func(t *testing.T) { s.schemaDigestIsFixed(t) })
	t.Run("MustNew", func(t *testing.T) { s.mustNew(t) })
}

// load builds the profile, failing the test rather than returning an error:
// every check below needs it, and none of them can say anything useful
// without it.
func (s Suite) load(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := s.New()
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	return p
}

func (s Suite) validEvents(t *testing.T) {
	p := s.load(t)
	for _, name := range sortedKeys(s.Valid) {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate([]byte(s.Valid[name])); err != nil {
				t.Fatalf("valid event rejected: %v", err)
			}
		})
	}
	if len(s.Valid) != s.Events {
		t.Fatalf("the profile has %d events, %d are checked", s.Events, len(s.Valid))
	}
}

func (s Suite) invalidEvents(t *testing.T) {
	p := s.load(t)
	for _, name := range sortedKeys(s.Invalid) {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate([]byte(s.Invalid[name])); err == nil {
				t.Fatal("invalid event accepted")
			}
		})
	}
}

// entryTypeRule checks that each event is bound to exactly one entry type and
// that every other type is turned away. The binding is not a per-profile table
// but the rule profiles.LoadEmbedded installs: the sensor event has to arrive
// as a sensor reading, everything else as an assertion. Otherwise a
// hand-written measurement could later be passed off as device evidence.
func (s Suite) entryTypeRule(t *testing.T) {
	p := s.load(t)
	for _, event := range sortedKeys(s.Valid) {
		want := core.EntryTypeAssertion
		if event == s.SensorEvent {
			want = core.EntryTypeSensorReading
		}
		for _, typ := range entryTypes {
			t.Run(event+"/"+typ.String(), func(t *testing.T) {
				err := p.Check(&core.Entry{Type: typ, Profile: s.ID}, []byte(s.Valid[event]))
				if typ == want {
					if err != nil {
						t.Fatalf("unexpectedly rejected: %v", err)
					}
					return
				}
				if err == nil {
					t.Fatal("unexpectedly accepted")
				}
				if !errors.Is(err, profiles.ErrEntry) {
					t.Fatalf("expected ErrEntry, got %v", err)
				}
			})
		}
	}
}

// idAcceptedByCore guards a failure mode the profile's own schemas would not
// catch: a profile that loads fine but whose identifier the core rejects, so
// that no entry could ever be issued with it.
func (s Suite) idAcceptedByCore(t *testing.T) {
	if err := profiles.CheckID(s.ID); err != nil {
		t.Fatalf("identifier %q: %v", s.ID, err)
	}
	e := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeAssertion,
		Profile:  s.ID,
		Subject:  core.SubjectID{1},
		IssuedAt: 1754800000000,
		Issuer:   core.KeyID{2},
	}
	e.Commitment = core.Commit(core.Salt{}, []byte("x"))
	if err := e.Validate(); err != nil {
		t.Fatalf("core rejects entry with profile %q: %v", s.ID, err)
	}
}

// schemaDigestIsFixed checks that loading twice yields the same digest, and
// that the profile ships exactly the files it should: one defs, one event
// envelope, and one per event.
func (s Suite) schemaDigestIsFixed(t *testing.T) {
	a, b := s.load(t), s.load(t)
	if a.SchemaDigest() != b.SchemaDigest() {
		t.Fatal("two loads produce different digests")
	}
	if want := s.Events + 2; len(a.Files()) != want {
		t.Fatalf("expected %d schema files, got %d", want, len(a.Files()))
	}
	t.Logf("%s schema digest: %s", s.ID, a.SchemaDigest())
}

func (s Suite) mustNew(t *testing.T) {
	if p := s.MustNew(); p.ID() != s.ID {
		t.Fatalf("unexpected identifier %q", p.ID())
	}
}

// sortedKeys keeps subtest order stable across runs; map iteration order
// alone would reshuffle the output of every failing run.
func sortedKeys(m map[string]string) []string {
	return slices.Sorted(maps.Keys(m))
}
