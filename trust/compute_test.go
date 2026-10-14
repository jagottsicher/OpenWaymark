// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"openwaymark.org/owm/core"
)

// testKey derives a deterministic KeyID from a single seed byte. ML-DSA-44
// is used purely because it is the cheaper of the two algorithms to
// generate — nothing here ever signs anything, only the resulting KeyID is
// used.
func testKey(t *testing.T, seed byte) core.KeyID {
	t.Helper()
	k, err := core.NewKeyFromSeed(core.SigAlgMLDSA44, bytes.Repeat([]byte{seed}, core.SigAlgMLDSA44.SeedSize()))
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return k.Public().ID()
}

func entityAtt(issuer core.KeyID, level Level, revoked bool) Attestation {
	return Attestation{
		Entry:   core.Entry{Issuer: issuer},
		Payload: Payload{Kind: KindEntity, Level: level},
		Revoked: revoked,
	}
}

func sensorAtt(issuer core.KeyID) Attestation {
	return Attestation{
		Entry:   core.Entry{Issuer: issuer},
		Payload: Payload{Kind: KindSensor},
	}
}

// fakeSource is a small in-memory Source. It performs no revocation
// matching of its own — each fixture sets Revoked directly on the
// attestation it wants Compute to treat as defeated. The same-issuer-only
// matching policy of OWM-6 §6 is a node/ concern (the real Source
// implementation there); what is tested here is only that Compute itself
// honours whatever Revoked value a Source hands it.
type fakeSource struct {
	atts map[core.KeyID][]Attestation
	err  error // when set, AttestationsOf always fails with this
}

func (f *fakeSource) AttestationsOf(_ context.Context, subject core.KeyID) ([]Attestation, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.atts[subject], nil
}

func TestComputeNoAttestations(t *testing.T) {
	subject := testKey(t, 1)
	src := &fakeSource{atts: map[core.KeyID][]Attestation{}}
	lvl, chain, err := Compute(context.Background(), src, RootSet{}, subject)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelNone {
		t.Errorf("level = %s, want %s", lvl, LevelNone)
	}
	if chain != nil {
		t.Errorf("chain = %v, want nil", chain)
	}
}

func TestComputeRootItself(t *testing.T) {
	root := testKey(t, 1)
	roots := RootSet{root: {ID: root, MaxLevel: LevelAccredited}}
	// A root must short-circuit before ever consulting the Source — a
	// Source that errors if called at all catches a regression here.
	src := &fakeSource{err: errors.New("must not be called for a root")}
	lvl, chain, err := Compute(context.Background(), src, roots, root)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelAccredited {
		t.Errorf("level = %s, want %s", lvl, LevelAccredited)
	}
	if chain != nil {
		t.Errorf("chain = %v, want nil", chain)
	}
}

func TestComputeSingleHopRoot(t *testing.T) {
	root := testKey(t, 1)
	entity := testKey(t, 2)
	roots := RootSet{root: {ID: root, Name: "root", MaxLevel: LevelState}}
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		entity: {entityAtt(root, LevelCertified, false)},
	}}
	lvl, chain, err := Compute(context.Background(), src, roots, entity)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelCertified {
		t.Errorf("level = %s, want %s", lvl, LevelCertified)
	}
	if len(chain) != 1 {
		t.Errorf("chain length = %d, want 1", len(chain))
	}
}

func TestComputeMultiHopCapsAtIssuersOwnLevel(t *testing.T) {
	root := testKey(t, 1)
	a := testKey(t, 2)
	b := testKey(t, 3)
	roots := RootSet{root: {ID: root, MaxLevel: LevelState}}
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		// A's own level is min(claimed 5, root's 6) = 5.
		a: {entityAtt(root, LevelAccredited, false)},
		// B claims level 6 via A, but A itself only ever reached 5 — the
		// claim must be capped at the issuer's own computed level, not at
		// what the issuer merely asserts.
		b: {entityAtt(a, LevelState, false)},
	}}
	lvl, chain, err := Compute(context.Background(), src, roots, b)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelAccredited {
		t.Errorf("level = %s, want %s (capped by issuer's own level, not the claim)", lvl, LevelAccredited)
	}
	if len(chain) != 2 {
		t.Errorf("chain length = %d, want 2", len(chain))
	}
}

func TestComputeRevocation(t *testing.T) {
	root := testKey(t, 1)
	entity := testKey(t, 2)
	roots := RootSet{root: {ID: root, MaxLevel: LevelState}}

	t.Run("a revoked attestation is excluded", func(t *testing.T) {
		src := &fakeSource{atts: map[core.KeyID][]Attestation{
			entity: {entityAtt(root, LevelCertified, true)},
		}}
		lvl, _, err := Compute(context.Background(), src, roots, entity)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if lvl != LevelNone {
			t.Errorf("level = %s, want %s (revoked attestation must not count)", lvl, LevelNone)
		}
	})

	t.Run("an unrevoked attestation still counts even next to a revoked one", func(t *testing.T) {
		// Models the OWM-6 §6 case where a revocation from a different
		// issuer left this attestation's own Revoked flag false: it must
		// count exactly as if no revocation existed at all.
		src := &fakeSource{atts: map[core.KeyID][]Attestation{
			entity: {
				entityAtt(root, LevelCertified, true), // some other, revoked claim
				entityAtt(root, LevelDomain, false),   // this one stands
			},
		}}
		lvl, _, err := Compute(context.Background(), src, roots, entity)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if lvl != LevelDomain {
			t.Errorf("level = %s, want %s (only the unrevoked attestation should count)", lvl, LevelDomain)
		}
	})
}

func TestComputeSelfAttestation(t *testing.T) {
	a := testKey(t, 1)

	t.Run("alone, contributes nothing", func(t *testing.T) {
		src := &fakeSource{atts: map[core.KeyID][]Attestation{
			a: {entityAtt(a, LevelState, false)},
		}}
		lvl, _, err := Compute(context.Background(), src, RootSet{}, a)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if lvl != LevelNone {
			t.Errorf("level = %s, want %s (an unbacked self-attestation must contribute 0)", lvl, LevelNone)
		}
	})

	t.Run("alongside a genuine attestation, adds nothing", func(t *testing.T) {
		root := testKey(t, 2)
		roots := RootSet{root: {ID: root, MaxLevel: LevelState}}
		src := &fakeSource{atts: map[core.KeyID][]Attestation{
			a: {
				entityAtt(a, LevelState, false),        // self-attestation: contributes 0
				entityAtt(root, LevelCertified, false), // genuine: contributes 4
			},
		}}
		lvl, _, err := Compute(context.Background(), src, roots, a)
		if err != nil {
			t.Fatalf("Compute: %v", err)
		}
		if lvl != LevelCertified {
			t.Errorf("level = %s, want %s (genuine attestation wins, self-attestation adds nothing)", lvl, LevelCertified)
		}
	})
}

func TestComputeCycleTerminates(t *testing.T) {
	a := testKey(t, 1)
	b := testKey(t, 2)
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		a: {entityAtt(b, LevelAccredited, false)},
		b: {entityAtt(a, LevelAccredited, false)},
	}}

	done := make(chan struct{})
	var lvl Level
	var err error
	go func() {
		lvl, _, err = Compute(context.Background(), src, RootSet{}, a)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Compute did not terminate on a cycle among colluding keys")
	}
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelNone {
		t.Errorf("level = %s, want %s (an unbacked cycle must contribute 0)", lvl, LevelNone)
	}
}

func TestComputeDepthTruncates(t *testing.T) {
	// A chain of keys longer than Compute is willing to walk, each attested
	// by the next and claiming the top level, with a real root only at the
	// far end. The root must never be reached.
	n := MaxChainDepth + 4
	keys := make([]core.KeyID, n)
	for i := range keys {
		keys[i] = testKey(t, byte(i+1))
	}
	roots := RootSet{keys[n-1]: {ID: keys[n-1], MaxLevel: LevelState}}
	atts := make(map[core.KeyID][]Attestation, n-1)
	for i := 0; i < n-1; i++ {
		atts[keys[i]] = []Attestation{entityAtt(keys[i+1], LevelState, false)}
	}
	src := &fakeSource{atts: atts}

	lvl, _, err := Compute(context.Background(), src, roots, keys[0])
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelNone {
		t.Errorf("level = %s, want %s (a chain longer than MaxChainDepth must truncate to no contribution)", lvl, LevelNone)
	}
}

func TestComputeSensorInheritsOperatorLevelExactly(t *testing.T) {
	root := testKey(t, 1)
	operator := testKey(t, 2)
	sensor := testKey(t, 3)
	roots := RootSet{root: {ID: root, MaxLevel: LevelState}}
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		operator: {entityAtt(root, LevelAccredited, false)},
		sensor:   {sensorAtt(operator)},
	}}
	lvl, _, err := Compute(context.Background(), src, roots, sensor)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelAccredited {
		t.Errorf("level = %s, want %s (a sensor must inherit the operator's level exactly)", lvl, LevelAccredited)
	}
}

func TestComputeSourceErrorPropagates(t *testing.T) {
	subject := testKey(t, 1)
	src := &fakeSource{err: errors.New("boom")}
	_, _, err := Compute(context.Background(), src, RootSet{}, subject)
	if !errors.Is(err, ErrSource) {
		t.Errorf("err = %v, want it to wrap %v", err, ErrSource)
	}
}

// concludedAtt builds a kind:"concluded" attestation the way node/'s own
// checkAttestationPayload requires it: self-issued, subj == iss == who. Two
// things make this the right shape to feed Compute, mirroring what a real
// Source would hand it: the recursive lookup of the issuer (itself) hits the
// cycle guard immediately, and the payload carries no Level for the min()
// step to use — both already true by construction, not asserted here.
func bindingAtt(issuer core.KeyID, level BindingLevel) Attestation {
	return Attestation{
		Entry:   core.Entry{Issuer: issuer},
		Payload: Payload{Kind: KindBinding, BindingLevel: level},
	}
}

func concludedAtt(who core.KeyID, reason Reason, successor core.KeyID) Attestation {
	return Attestation{
		Entry:   core.Entry{Issuer: who, Subject: core.SubjectID(who)},
		Payload: Payload{Kind: KindConcluded, Reason: reason, Successor: successor},
	}
}

// TestComputeConcludedContributesNothing is OWM-9 A15's fix, checked at the
// level that matters: a self-issued kind:"concluded" attestation must never
// be mistaken for an entity-trust claim. No special case for it exists in
// Compute (see compute.go) — this test is what backs that design decision
// with more than an argument in a comment.
func TestComputeConcludedContributesNothing(t *testing.T) {
	subject := testKey(t, 1)
	successor := testKey(t, 2)
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		subject: {concludedAtt(subject, ReasonSucceeded, successor)},
	}}
	lvl, chain, err := Compute(context.Background(), src, RootSet{}, subject)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelNone {
		t.Errorf("level = %s, want %s (a concluded attestation must not raise the level)", lvl, LevelNone)
	}
	if len(chain) != 0 {
		t.Errorf("chain = %+v, want empty (a concluded attestation must never justify a level)", chain)
	}
}

// TestComputeConcludedDoesNotShadowARealAttestation confirms the concluded
// statement is inert alongside a genuine one too, not just alone — Compute
// must still find and use the real attestation from a different issuer.
func TestComputeConcludedDoesNotShadowARealAttestation(t *testing.T) {
	root := testKey(t, 1)
	subject := testKey(t, 2)
	roots := RootSet{root: {ID: root, MaxLevel: LevelState}}
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		subject: {
			concludedAtt(subject, ReasonDiscontinued, core.KeyID{}),
			entityAtt(root, LevelAccredited, false),
		},
	}}
	lvl, chain, err := Compute(context.Background(), src, roots, subject)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelAccredited {
		t.Errorf("level = %s, want %s (the real attestation must still be found)", lvl, LevelAccredited)
	}
	if len(chain) != 1 || chain[0].Payload.Kind != KindEntity {
		t.Errorf("chain = %+v, want exactly the one entity attestation", chain)
	}
}

// TestComputeBindingContributesNothing is OWM-9 A8's fix, checked the same
// way A15's was: a kind:"binding" attestation makes a claim about a
// product's physical-digital binding, not about entity trust, and must
// never be mistaken for one — even a maximal BindingVeryHigh claim must not
// raise the entity level. No special case for it exists in Compute (see
// compute.go and payload.go's own doc comment on KindBinding); this test is
// what backs that design decision with more than an argument in a comment.
func TestComputeBindingContributesNothing(t *testing.T) {
	issuer := testKey(t, 1)
	subject := testKey(t, 2)
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		subject: {bindingAtt(issuer, BindingVeryHigh)},
	}}
	lvl, chain, err := Compute(context.Background(), src, RootSet{}, subject)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelNone {
		t.Errorf("level = %s, want %s (a binding attestation must not raise the entity level)", lvl, LevelNone)
	}
	if len(chain) != 0 {
		t.Errorf("chain = %+v, want empty (a binding attestation must never justify an entity level)", chain)
	}
}

// TestComputeBindingDoesNotShadowARealAttestation mirrors
// TestComputeConcludedDoesNotShadowARealAttestation for the same reason: a
// binding claim sitting alongside a genuine entity attestation must not
// prevent Compute from finding and using the real one.
func TestComputeBindingDoesNotShadowARealAttestation(t *testing.T) {
	root := testKey(t, 1)
	subject := testKey(t, 2)
	roots := RootSet{root: {ID: root, MaxLevel: LevelState}}
	src := &fakeSource{atts: map[core.KeyID][]Attestation{
		subject: {
			bindingAtt(root, BindingLow),
			entityAtt(root, LevelAccredited, false),
		},
	}}
	lvl, chain, err := Compute(context.Background(), src, roots, subject)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if lvl != LevelAccredited {
		t.Errorf("level = %s, want %s (the real attestation must still be found)", lvl, LevelAccredited)
	}
	if len(chain) != 1 || chain[0].Payload.Kind != KindEntity {
		t.Errorf("chain = %+v, want exactly the one entity attestation", chain)
	}
}
