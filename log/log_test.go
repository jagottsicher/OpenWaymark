// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"openwaymark.org/owm/core"
)

// testEnv ist ein Log mit Speicher, Nutzlastspeicher und einer Uhr, die bei
// jedem Aufruf eine Millisekunde weiterläuft. Gleiche Zeitstempel würden die
// Reihenfolgeprüfungen in CheckSTHPair bedeutungslos machen.
type testEnv struct {
	t     *testing.T
	key   *core.PrivateKey
	st    *MemStorage
	blobs *MemBlobStore
	log   *Log
	clock int64
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel erzeugen: %v", err)
	}
	return newTestEnvWithKey(t, key)
}

func newTestEnvWithKey(t *testing.T, key *core.PrivateKey) *testEnv {
	t.Helper()
	env := &testEnv{
		t:     t,
		key:   key,
		st:    NewMemStorage(),
		blobs: NewMemBlobStore(),
		clock: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC).UnixMilli(),
	}
	lg, err := New(Options{
		Storage: env.st,
		Signer:  key,
		Blobs:   env.blobs,
		Keys:    mapKeys{key.Public().ID(): key.Public()},
		Now:     env.now,
	})
	if err != nil {
		t.Fatalf("Log anlegen: %v", err)
	}
	env.log = lg
	return env
}

func (e *testEnv) now() time.Time {
	e.clock++
	return time.UnixMilli(e.clock).UTC()
}

// entry baut einen signierten Assertion-Eintrag samt Salt.
func (e *testEnv) entry(subject core.SubjectID, payload []byte) (*core.SignedEntry, core.Salt) {
	e.t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		e.t.Fatalf("Salt: %v", err)
	}
	ent := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   e.now().UnixMilli(),
		Issuer:     e.key.Public().ID(),
		Commitment: core.Commit(salt, payload),
	}
	se, err := core.SignEntry(e.key, ent)
	if err != nil {
		e.t.Fatalf("Eintrag signieren: %v", err)
	}
	return se, salt
}

// appendN hängt n Einträge zu wechselnden Subjekten an.
func (e *testEnv) appendN(ctx context.Context, n int) []*Leaf {
	e.t.Helper()
	out := make([]*Leaf, 0, n)
	for i := 0; i < n; i++ {
		subject, err := core.NewSubjectID()
		if err != nil {
			e.t.Fatalf("Subjekt: %v", err)
		}
		se, salt := e.entry(subject, []byte(fmt.Sprintf("nutzlast-%d", i)))
		leaf, err := e.log.AppendWithPayload(ctx, se, salt, []byte(fmt.Sprintf("nutzlast-%d", i)))
		if err != nil {
			e.t.Fatalf("anhängen %d: %v", i, err)
		}
		out = append(out, leaf)
	}
	return out
}

type mapKeys map[core.KeyID]*core.PublicKey

func (m mapKeys) PublicKey(_ context.Context, id core.KeyID) (*core.PublicKey, error) {
	pub, ok := m[id]
	if !ok {
		return nil, fmt.Errorf("%w: Schlüssel %s", ErrNotFound, id)
	}
	return pub, nil
}

func TestEmptyTreeRoot(t *testing.T) {
	env := newTestEnv(t)
	root, err := env.log.Root(context.Background())
	if err != nil {
		t.Fatalf("Wurzel: %v", err)
	}
	// RFC 6962: die Wurzel des leeren Baums ist SHA-256 über die leere Eingabe.
	want := sha256.Sum256(nil)
	if root != core.Digest(want) {
		t.Errorf("leere Wurzel = %s, erwartet %s", root, core.Digest(want))
	}
}

func TestAppendAndInclusion(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	leaves := env.appendN(ctx, 17)

	signed, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if err := signed.Verify(env.key.Public()); err != nil {
		t.Fatalf("STH-Signatur: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	if sth.Size != uint64(len(leaves)) {
		t.Fatalf("Baumgröße = %d, erwartet %d", sth.Size, len(leaves))
	}
	if sth.Log != env.log.ID() {
		t.Errorf("STH nennt Log %s, erwartet %s", sth.Log, env.log.ID())
	}

	for i, leaf := range leaves {
		if err := leaf.Verify(env.log.ID(), env.key.Public()); err != nil {
			t.Fatalf("Blatt %d prüfen: %v", i, err)
		}
		hash, err := leaf.Hash()
		if err != nil {
			t.Fatalf("Blatthash %d: %v", i, err)
		}
		p, err := env.log.InclusionProof(ctx, uint64(i), sth.Size)
		if err != nil {
			t.Fatalf("Inklusionsbeweis %d: %v", i, err)
		}
		if err := p.Verify(hash, sth); err != nil {
			t.Errorf("Inklusionsbeweis %d geht nicht auf: %v", i, err)
		}
	}
}

func TestInclusionProofRejectsWrongLeaf(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	leaves := env.appendN(ctx, 8)
	signed, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	p, err := env.log.InclusionProof(ctx, 3, sth.Size)
	if err != nil {
		t.Fatalf("Beweis: %v", err)
	}
	other, err := leaves[4].Hash()
	if err != nil {
		t.Fatalf("Blatthash: %v", err)
	}
	if err := p.Verify(other, sth); !errors.Is(err, ErrProofInvalid) {
		t.Errorf("fremdes Blatt akzeptiert: %v", err)
	}
}

// TestAllSTHsPairwiseConsistent ist Verifikationstest 1 aus dem Plan: Nach
// beliebigen Anhänge- und Ausstellungsfolgen müssen alle je ausgegebenen STHs
// paarweise konsistent sein. Wäre das nicht so, hätte die Node zwei Historien
// unterschrieben.
func TestAllSTHsPairwiseConsistent(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	rnd := rand.New(rand.NewSource(20260801))

	var sths []*STH
	issue := func() {
		signed, err := env.log.IssueSTH(ctx)
		if err != nil {
			t.Fatalf("STH: %v", err)
		}
		if err := signed.Verify(env.key.Public()); err != nil {
			t.Fatalf("STH-Signatur: %v", err)
		}
		sth, err := signed.STH()
		if err != nil {
			t.Fatalf("STH lesen: %v", err)
		}
		sths = append(sths, sth)
	}

	issue() // auch der leere Baum wird bezeugt
	for round := 0; round < 12; round++ {
		env.appendN(ctx, 1+rnd.Intn(4))
		issue()
	}

	for i := 0; i < len(sths); i++ {
		for j := i; j < len(sths); j++ {
			old, cur := sths[i], sths[j]
			p, err := env.log.ConsistencyProof(ctx, old.Size, cur.Size)
			if err != nil {
				t.Fatalf("Konsistenzbeweis %d→%d: %v", old.Size, cur.Size, err)
			}
			if err := p.Verify(old, cur); err != nil {
				t.Errorf("STHs %d und %d inkonsistent (%d→%d): %v",
					i, j, old.Size, cur.Size, err)
			}
			if err := CheckSTHPair(old, cur); err != nil {
				t.Errorf("CheckSTHPair(%d, %d): %v", i, j, err)
			}
		}
	}
}

func TestConsistencyProofRejectsForeignRoot(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.appendN(ctx, 3)
	first, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	env.appendN(ctx, 5)
	second, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	oldSTH, err := first.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	newSTH, err := second.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	p, err := env.log.ConsistencyProof(ctx, oldSTH.Size, newSTH.Size)
	if err != nil {
		t.Fatalf("Konsistenzbeweis: %v", err)
	}
	// Ein einziges gekipptes Bit in der alten Wurzel: der Beweis darf nicht
	// mehr aufgehen.
	tampered := *oldSTH
	tampered.Root[0] ^= 0x01
	if err := p.Verify(&tampered, newSTH); !errors.Is(err, ErrProofInvalid) {
		t.Errorf("manipulierte Wurzel akzeptiert: %v", err)
	}
}

// TestSplitViewDetected ist Verifikationstest 2 aus dem Plan: Eine Node, die
// zwei Beobachtern verschiedene Bäume zeigt, muss auffliegen — und zwar allein
// anhand dessen, was sie selbst unterschrieben hat.
func TestSplitViewDetected(t *testing.T) {
	ctx := context.Background()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	// Zwei Logs derselben Node — die zwei Sichten, die der Angreifer führt.
	viewA := newTestEnvWithKey(t, key)
	viewB := newTestEnvWithKey(t, key)
	if viewA.log.ID() != viewB.log.ID() {
		t.Fatalf("Sichten gehören zu verschiedenen Logs")
	}

	viewA.appendN(ctx, 4)
	viewB.appendN(ctx, 4) // andere Einträge, gleiche Anzahl

	signedA, err := viewA.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH A: %v", err)
	}
	signedB, err := viewB.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH B: %v", err)
	}
	// Beide Signaturen sind echt. Genau das macht den Befund unabstreitbar.
	if err := signedA.Verify(key.Public()); err != nil {
		t.Fatalf("STH A ungültig: %v", err)
	}
	if err := signedB.Verify(key.Public()); err != nil {
		t.Fatalf("STH B ungültig: %v", err)
	}
	sthA, err := signedA.STH()
	if err != nil {
		t.Fatalf("STH A lesen: %v", err)
	}
	sthB, err := signedB.STH()
	if err != nil {
		t.Fatalf("STH B lesen: %v", err)
	}
	if sthA.Size != sthB.Size {
		t.Fatalf("Testaufbau: Größen %d und %d", sthA.Size, sthB.Size)
	}
	if err := CheckSTHPair(sthA, sthB); !errors.Is(err, ErrSplitView) {
		t.Fatalf("Split-View nicht erkannt: %v", err)
	}

	// Und der zweite Weg zum selben Befund: Der Konsistenzbeweis der einen
	// Sicht geht gegen die Wurzel der anderen nicht auf.
	viewA.appendN(ctx, 2)
	later, err := viewA.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	sthLater, err := later.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	p, err := viewA.log.ConsistencyProof(ctx, sthB.Size, sthLater.Size)
	if err != nil {
		t.Fatalf("Konsistenzbeweis: %v", err)
	}
	if err := p.Verify(sthB, sthLater); !errors.Is(err, ErrProofInvalid) {
		t.Errorf("fremde Sicht als konsistent akzeptiert: %v", err)
	}
}

func TestCheckSTHPairShrunk(t *testing.T) {
	logID := core.LogID{1, 2, 3}
	early := &STH{Version: FormatVersion, Log: logID, Size: 9, IssuedAt: 1000, Root: core.Digest{9}}
	late := &STH{Version: FormatVersion, Log: logID, Size: 4, IssuedAt: 2000, Root: core.Digest{4}}
	if err := CheckSTHPair(early, late); !errors.Is(err, ErrShrunk) {
		t.Errorf("Schrumpfen nicht erkannt: %v", err)
	}
	// Reihenfolge der Argumente darf keine Rolle spielen.
	if err := CheckSTHPair(late, early); !errors.Is(err, ErrShrunk) {
		t.Errorf("Schrumpfen nicht erkannt (vertauscht): %v", err)
	}
}

func TestCheckSTHPairForeignLog(t *testing.T) {
	a := &STH{Version: FormatVersion, Log: core.LogID{1}, Size: 1, IssuedAt: 1, Root: core.Digest{1}}
	b := &STH{Version: FormatVersion, Log: core.LogID{2}, Size: 1, IssuedAt: 2, Root: core.Digest{2}}
	if err := CheckSTHPair(a, b); !errors.Is(err, ErrLogMismatch) {
		t.Errorf("fremdes Log nicht erkannt: %v", err)
	}
}

// TestErasure ist Verifikationstest 3 aus dem Plan: Nach der Löschung ist die
// Nutzlast auch bei kleinem Wertebereich nicht rekonstruierbar, und der
// Inklusionsbeweis des Blattes gilt weiter.
func TestErasure(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.appendN(ctx, 5) // Nachbarn, damit das Blatt mitten im Baum liegt

	// Ein Wertebereich aus wenigen tausend Möglichkeiten — genau der Fall, in
	// dem ein ungesalzenes Commitment sofort zurückgerechnet wäre.
	const domainSize = 4096
	domain := make([][]byte, domainSize)
	for i := range domain {
		domain[i] = []byte(fmt.Sprintf("hof-%04d", i))
	}
	secret := domain[1234]

	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	se, salt := env.entry(subject, secret)
	entryID := se.EntryID()
	leaf, err := env.log.AppendWithPayload(ctx, se, salt, secret)
	if err != nil {
		t.Fatalf("anhängen: %v", err)
	}
	env.appendN(ctx, 3)

	beforeSigned, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	before, err := beforeSigned.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	leafHash, err := leaf.Hash()
	if err != nil {
		t.Fatalf("Blatthash: %v", err)
	}
	beforeProof, err := env.log.InclusionProof(ctx, leaf.Seq, before.Size)
	if err != nil {
		t.Fatalf("Inklusionsbeweis: %v", err)
	}
	if err := beforeProof.Verify(leafHash, before); err != nil {
		t.Fatalf("Inklusionsbeweis vor der Löschung: %v", err)
	}
	if got, err := env.log.Payload(ctx, entryID); err != nil || string(got) != string(secret) {
		t.Fatalf("Nutzlast vor der Löschung: %q, %v", got, err)
	}

	// Löschen.
	tomb, err := env.log.Erase(ctx, entryID)
	if err != nil {
		t.Fatalf("löschen: %v", err)
	}
	tombEntry := entryOf(t, tomb)
	if tombEntry.Type != core.EntryTypeErasure {
		t.Errorf("Grabstein hat Typ %s", tombEntry.Type)
	}
	if tombEntry.Target == nil || tombEntry.Target.Entry != entryID {
		t.Errorf("Grabstein verweist nicht auf den gelöschten Eintrag")
	}
	if tombEntry.Target.Log != env.log.ID() {
		t.Errorf("Grabstein nennt Log %s, erwartet %s", tombEntry.Target.Log, env.log.ID())
	}

	// Die Nutzlast ist fort und der Zustand bleibt nachweisbar.
	if _, err := env.log.Payload(ctx, entryID); !errors.Is(err, ErrErased) {
		t.Errorf("Nutzlast nach der Löschung noch abrufbar: %v", err)
	}
	status, err := env.log.BlobStatus(ctx, entryID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status != BlobErased {
		t.Errorf("Status = %s, erwartet erased", status)
	}
	// Und sie lässt sich auch nicht wieder hineinschmuggeln.
	if err := env.blobs.Put(ctx, entryID, salt, secret); !errors.Is(err, ErrErased) {
		t.Errorf("gelöschte Nutzlast wieder annehmbar: %v", err)
	}

	// Der Wörterbuchangriff über den vollständigen Wertebereich. Ohne den Salt
	// ist das Commitment über den Schlüsselraum gleichverteilt.
	entry := entryOf(t, leaf)
	for _, cand := range domain {
		if core.VerifyCommitment(entry.Commitment, core.Salt{}, cand) {
			t.Fatalf("Nutzlast %q aus dem Commitment zurückgerechnet", cand)
		}
	}
	// Gegenprobe: Mit dem Salt geht genau ein Kandidat auf. Der Angriff
	// scheitert am fehlenden Salt, nicht daran, dass er nicht funktionierte.
	hits := 0
	for _, cand := range domain {
		if core.VerifyCommitment(entry.Commitment, salt, cand) {
			hits++
		}
	}
	if hits != 1 {
		t.Errorf("Gegenprobe: %d Treffer mit Salt, erwartet 1", hits)
	}

	// Der Kern der Sache: Der Baum wurde nicht angefasst.
	rootNow, err := env.log.RootAt(ctx, before.Size)
	if err != nil {
		t.Fatalf("Wurzel: %v", err)
	}
	if rootNow != before.Root {
		t.Errorf("Wurzel über %d Blätter hat sich geändert", before.Size)
	}
	if err := beforeSigned.Verify(env.key.Public()); err != nil {
		t.Errorf("alter STH nach der Löschung ungültig: %v", err)
	}
	if err := beforeProof.Verify(leafHash, before); err != nil {
		t.Errorf("alter Inklusionsbeweis nach der Löschung ungültig: %v", err)
	}
	// Auch das Blatt selbst und seine Signatur bleiben prüfbar — gelöscht wurde
	// die Nutzlast, nicht die Bezeugung.
	if err := leaf.Verify(env.log.ID(), env.key.Public()); err != nil {
		t.Errorf("Blatt nach der Löschung nicht mehr prüfbar: %v", err)
	}

	// Und der Baum ist seither gewachsen, nicht geschrumpft.
	afterSigned, err := env.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	after, err := afterSigned.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	p, err := env.log.ConsistencyProof(ctx, before.Size, after.Size)
	if err != nil {
		t.Fatalf("Konsistenzbeweis: %v", err)
	}
	if err := p.Verify(before, after); err != nil {
		t.Errorf("Löschung hat die Historie gebrochen: %v", err)
	}
}

func TestEraseIsIdempotent(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	se, salt := env.entry(subject, []byte("geheim"))
	if _, err := env.log.AppendWithPayload(ctx, se, salt, []byte("geheim")); err != nil {
		t.Fatalf("anhängen: %v", err)
	}
	if _, err := env.log.Erase(ctx, se.EntryID()); err != nil {
		t.Fatalf("erste Löschung: %v", err)
	}
	if _, err := env.log.Erase(ctx, se.EntryID()); err != nil {
		t.Fatalf("zweite Löschung: %v", err)
	}
}

func TestEraseRefusesKeyRotation(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("Salt: %v", err)
	}
	rot := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeKeyRotation,
		Subject:    subject,
		IssuedAt:   env.now().UnixMilli(),
		Issuer:     env.key.Public().ID(),
		Commitment: core.Commit(salt, []byte("neuer Schlüssel")),
	}
	se, err := core.SignEntry(env.key, rot)
	if err != nil {
		t.Fatalf("signieren: %v", err)
	}
	if _, err := env.log.AppendWithPayload(ctx, se, salt, []byte("neuer Schlüssel")); err != nil {
		t.Fatalf("anhängen: %v", err)
	}
	if _, err := env.log.Erase(ctx, se.EntryID()); !errors.Is(err, ErrNotErasable) {
		t.Errorf("Rotationseintrag löschbar: %v", err)
	}
	// Und die Nutzlast liegt noch da — eine abgelehnte Löschung darf nichts
	// halb erledigt haben.
	if status, err := env.log.BlobStatus(ctx, se.EntryID()); err != nil || status != BlobPresent {
		t.Errorf("Status = %s, %v; erwartet present", status, err)
	}
}

func TestAppendWithPayloadRejectsMismatch(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	se, salt := env.entry(subject, []byte("echt"))
	_, err = env.log.AppendWithPayload(ctx, se, salt, []byte("untergeschoben"))
	if !errors.Is(err, ErrCommitment) {
		t.Fatalf("falsche Nutzlast angenommen: %v", err)
	}
	if size, err := env.log.Size(ctx); err != nil || size != 0 {
		t.Errorf("Baum ist trotz Ablehnung gewachsen: %d, %v", size, err)
	}
	if status, err := env.blobs.Status(ctx, se.EntryID()); err != nil || status != BlobAbsent {
		t.Errorf("Nutzlast trotz Ablehnung gespeichert: %s, %v", status, err)
	}
}

func TestAppendRejectsUnknownIssuer(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	stranger, err := core.GenerateKey(core.SigAlgMLDSA44)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("Salt: %v", err)
	}
	ent := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Subject:    subject,
		IssuedAt:   env.now().UnixMilli(),
		Issuer:     stranger.Public().ID(),
		Commitment: core.Commit(salt, []byte("x")),
	}
	se, err := core.SignEntry(stranger, ent)
	if err != nil {
		t.Fatalf("signieren: %v", err)
	}
	if _, err := env.log.Append(ctx, se); !errors.Is(err, ErrNotFound) {
		t.Errorf("unbekannter Aussteller angenommen: %v", err)
	}
}

func TestHistoryBySubject(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	env.appendN(ctx, 2)
	for i := 0; i < 3; i++ {
		payload := []byte(fmt.Sprintf("station-%d", i))
		se, salt := env.entry(subject, payload)
		if _, err := env.log.AppendWithPayload(ctx, se, salt, payload); err != nil {
			t.Fatalf("anhängen: %v", err)
		}
		env.appendN(ctx, 1)
	}
	leaves, err := env.log.History(ctx, subject)
	if err != nil {
		t.Fatalf("Historie: %v", err)
	}
	if len(leaves) != 3 {
		t.Fatalf("Historie hat %d Einträge, erwartet 3", len(leaves))
	}
	for i := 1; i < len(leaves); i++ {
		if leaves[i-1].Seq >= leaves[i].Seq {
			t.Errorf("Historie nicht aufsteigend: %d vor %d", leaves[i-1].Seq, leaves[i].Seq)
		}
	}
}

func TestLogIDFollowsGenesisKey(t *testing.T) {
	env := newTestEnv(t)
	rotated, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	// Nach einer Rotation unterschreibt ein neuer Schlüssel, aber die
	// Log-Kennung bleibt am Gründungsschlüssel hängen — sonst zeigten alle
	// bestehenden Verweise ins Leere.
	after, err := New(Options{
		Storage: env.st,
		Signer:  rotated,
		Genesis: env.key.Public(),
		Now:     env.now,
	})
	if err != nil {
		t.Fatalf("Log anlegen: %v", err)
	}
	if after.ID() != env.log.ID() {
		t.Errorf("Log-Kennung nach Rotation = %s, erwartet %s", after.ID(), env.log.ID())
	}

	ctx := context.Background()
	signed, err := after.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if err := signed.Verify(rotated.Public()); err != nil {
		t.Errorf("STH des neuen Schlüssels: %v", err)
	}
	if err := signed.Verify(env.key.Public()); err == nil {
		t.Error("STH mit dem alten Schlüssel prüfbar")
	}
}

func TestProofsOutOfRange(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	env.appendN(ctx, 4)

	if _, err := env.log.InclusionProof(ctx, 4, 4); !errors.Is(err, ErrProofSize) {
		t.Errorf("Blatt außerhalb des Baums: %v", err)
	}
	if _, err := env.log.InclusionProof(ctx, 0, 9); !errors.Is(err, ErrProofSize) {
		t.Errorf("Baumgröße aus der Zukunft: %v", err)
	}
	if _, err := env.log.ConsistencyProof(ctx, 3, 2); !errors.Is(err, ErrProofSize) {
		t.Errorf("rückwärtiger Konsistenzbeweis: %v", err)
	}
	if _, err := env.log.RootAt(ctx, 5); !errors.Is(err, ErrProofSize) {
		t.Errorf("Wurzel aus der Zukunft: %v", err)
	}
}

func TestNoBlobStore(t *testing.T) {
	ctx := context.Background()
	env := newTestEnv(t)
	bare, err := New(Options{Storage: NewMemStorage(), Signer: env.key, Now: env.now})
	if err != nil {
		t.Fatalf("Log anlegen: %v", err)
	}
	if _, err := bare.Payload(ctx, core.Digest{1}); !errors.Is(err, ErrNoBlobStore) {
		t.Errorf("Payload ohne Blobspeicher: %v", err)
	}
	if _, err := bare.Erase(ctx, core.Digest{1}); !errors.Is(err, ErrNoBlobStore) {
		t.Errorf("Erase ohne Blobspeicher: %v", err)
	}
}

func TestNewRequiresStorageAndSigner(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA44)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	if _, err := New(Options{Signer: key}); !errors.Is(err, ErrMissingField) {
		t.Errorf("Log ohne Speicher: %v", err)
	}
	if _, err := New(Options{Storage: NewMemStorage()}); !errors.Is(err, ErrMissingField) {
		t.Errorf("Log ohne Signaturschlüssel: %v", err)
	}
}

func entryOf(t *testing.T, leaf *Leaf) *core.Entry {
	t.Helper()
	se, err := leaf.SignedEntry()
	if err != nil {
		t.Fatalf("signierter Eintrag: %v", err)
	}
	e, err := se.Entry()
	if err != nil {
		t.Fatalf("Eintrag: %v", err)
	}
	return e
}
