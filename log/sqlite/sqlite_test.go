// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package sqlite

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

type env struct {
	t     *testing.T
	key   *core.PrivateKey
	store *Store
	log   *owmlog.Log
	clock int64
	path  string
}

// newEnv legt ein Log über einer Datei im Testverzeichnis an. Bewusst keine
// :memory:-Datenbank: Der Test soll auch beantworten, ob das Log einen
// Neustart übersteht.
func newEnv(t *testing.T) *env {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("Schlüssel: %v", err)
	}
	e := &env{
		t:     t,
		key:   key,
		clock: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC).UnixMilli(),
		path:  filepath.Join(t.TempDir(), "log.db"),
	}
	e.open()
	return e
}

func (e *env) open() {
	e.t.Helper()
	store, err := Open(context.Background(), e.path)
	if err != nil {
		e.t.Fatalf("öffnen: %v", err)
	}
	e.t.Cleanup(func() { store.Close() })
	lg, err := owmlog.New(owmlog.Options{
		Storage: store,
		Signer:  e.key,
		Blobs:   store,
		Keys:    keys{e.key.Public().ID(): e.key.Public()},
		Now:     e.now,
	})
	if err != nil {
		e.t.Fatalf("Log anlegen: %v", err)
	}
	e.store = store
	e.log = lg
}

// reopen schließt die Datenbank und öffnet sie erneut.
func (e *env) reopen() {
	e.t.Helper()
	if err := e.store.Close(); err != nil {
		e.t.Fatalf("schließen: %v", err)
	}
	e.open()
}

func (e *env) now() time.Time {
	e.clock++
	return time.UnixMilli(e.clock).UTC()
}

func (e *env) append(ctx context.Context, payload []byte) (*owmlog.Leaf, core.Digest) {
	e.t.Helper()
	subject, err := core.NewSubjectID()
	if err != nil {
		e.t.Fatalf("Subjekt: %v", err)
	}
	return e.appendTo(ctx, subject, payload)
}

func (e *env) appendTo(ctx context.Context, subject core.SubjectID, payload []byte) (*owmlog.Leaf, core.Digest) {
	e.t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		e.t.Fatalf("Salt: %v", err)
	}
	se, err := core.SignEntry(e.key, &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   e.now().UnixMilli(),
		Issuer:     e.key.Public().ID(),
		Commitment: core.Commit(salt, payload),
	})
	if err != nil {
		e.t.Fatalf("signieren: %v", err)
	}
	leaf, err := e.log.AppendWithPayload(ctx, se, salt, payload)
	if err != nil {
		e.t.Fatalf("anhängen: %v", err)
	}
	return leaf, se.EntryID()
}

type keys map[core.KeyID]*core.PublicKey

func (k keys) PublicKey(_ context.Context, id core.KeyID) (*core.PublicKey, error) {
	pub, ok := k[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", owmlog.ErrNotFound, id)
	}
	return pub, nil
}

func TestSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	const n = 11
	leaves := make([]*owmlog.Leaf, 0, n)
	for i := 0; i < n; i++ {
		leaf, _ := e.append(ctx, []byte(fmt.Sprintf("nutzlast-%d", i)))
		leaves = append(leaves, leaf)
	}
	signed, err := e.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}

	e.reopen()

	size, err := e.log.Size(ctx)
	if err != nil {
		t.Fatalf("Größe: %v", err)
	}
	if size != n {
		t.Fatalf("nach Neustart %d Blätter, erwartet %d", size, n)
	}
	root, err := e.log.RootAt(ctx, sth.Size)
	if err != nil {
		t.Fatalf("Wurzel: %v", err)
	}
	if root != sth.Root {
		t.Errorf("Wurzel nach Neustart abweichend")
	}
	latest, err := e.log.LatestSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if err := latest.Verify(e.key.Public()); err != nil {
		t.Errorf("STH nach Neustart: %v", err)
	}

	// Beweise gegen den vor dem Neustart ausgestellten STH.
	for i, leaf := range leaves {
		hash, err := leaf.Hash()
		if err != nil {
			t.Fatalf("Blatthash: %v", err)
		}
		p, err := e.log.InclusionProof(ctx, uint64(i), sth.Size)
		if err != nil {
			t.Fatalf("Inklusionsbeweis %d: %v", i, err)
		}
		if err := p.Verify(hash, sth); err != nil {
			t.Errorf("Inklusionsbeweis %d nach Neustart: %v", i, err)
		}
	}

	// Und der Baum wächst weiter, konsistent zur alten Bezeugung.
	e.append(ctx, []byte("nach dem Neustart"))
	nextSigned, err := e.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	next, err := nextSigned.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	cp, err := e.log.ConsistencyProof(ctx, sth.Size, next.Size)
	if err != nil {
		t.Fatalf("Konsistenzbeweis: %v", err)
	}
	if err := cp.Verify(sth, next); err != nil {
		t.Errorf("Historie über den Neustart hinweg gebrochen: %v", err)
	}
}

func TestErasurePersists(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.append(ctx, []byte("nachbar"))
	leaf, entryID := e.append(ctx, []byte("personenbezogen"))
	e.append(ctx, []byte("nachbar"))

	signed, err := e.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	before, err := signed.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	hash, err := leaf.Hash()
	if err != nil {
		t.Fatalf("Blatthash: %v", err)
	}
	p, err := e.log.InclusionProof(ctx, leaf.Seq, before.Size)
	if err != nil {
		t.Fatalf("Inklusionsbeweis: %v", err)
	}

	if _, err := e.log.Erase(ctx, entryID); err != nil {
		t.Fatalf("löschen: %v", err)
	}
	e.reopen()

	if status, err := e.store.Status(ctx, entryID); err != nil || status != owmlog.BlobErased {
		t.Errorf("Status nach Neustart = %s, %v; erwartet erased", status, err)
	}
	if _, err := e.log.Payload(ctx, entryID); !errors.Is(err, owmlog.ErrErased) {
		t.Errorf("Nutzlast nach Neustart abrufbar: %v", err)
	}
	if err := e.store.Put(ctx, entryID, core.Salt{}, []byte("wieder rein")); !errors.Is(err, owmlog.ErrErased) {
		t.Errorf("gelöschte Nutzlast wieder annehmbar: %v", err)
	}
	// Die Bezeugung bleibt: gelöscht wurde die Nutzlast, nicht der Beweis.
	if err := p.Verify(hash, before); err != nil {
		t.Errorf("Inklusionsbeweis nach Löschung und Neustart: %v", err)
	}
	if err := signed.Verify(e.key.Public()); err != nil {
		t.Errorf("alter STH nach Löschung: %v", err)
	}
}

func TestAppendConflict(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.append(ctx, []byte("eins"))

	rec := owmlog.LeafRecord{
		Seq:      0, // die Position ist längst vergeben
		Hash:     core.Digest{1},
		EntryID:  core.Digest{2},
		Subject:  core.SubjectID{3},
		LoggedAt: e.now().UnixMilli(),
		Data:     []byte{0x01},
	}
	if err := e.store.Append(ctx, 0, rec, nil); !errors.Is(err, owmlog.ErrConflict) {
		t.Errorf("veraltete Ausgangsgröße akzeptiert: %v", err)
	}
	rec.Seq = 5
	if err := e.store.Append(ctx, 1, rec, nil); !errors.Is(err, owmlog.ErrLeafConflict) {
		t.Errorf("Blatt mit falscher Position akzeptiert: %v", err)
	}
	if size, err := e.store.Size(ctx); err != nil || size != 1 {
		t.Errorf("Größe = %d, %v; erwartet 1", size, err)
	}
}

func TestLookupsAndNotFound(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("Subjekt: %v", err)
	}
	e.append(ctx, []byte("fremd"))
	var ids []core.Digest
	for i := 0; i < 3; i++ {
		_, id := e.appendTo(ctx, subject, []byte(fmt.Sprintf("station-%d", i)))
		ids = append(ids, id)
		e.append(ctx, []byte("fremd"))
	}

	history, err := e.store.LeavesBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("Subjektsuche: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("Historie hat %d Einträge, erwartet 3", len(history))
	}
	for i := 1; i < len(history); i++ {
		if history[i-1].Seq >= history[i].Seq {
			t.Errorf("Historie nicht aufsteigend")
		}
	}
	for _, id := range ids {
		rec, err := e.store.LeafByEntryID(ctx, id)
		if err != nil {
			t.Fatalf("Eintragssuche: %v", err)
		}
		if rec.EntryID != id {
			t.Errorf("falscher Eintrag geliefert")
		}
	}

	if _, err := e.store.LeafBySeq(ctx, 999); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unbekannte Position: %v", err)
	}
	if _, err := e.store.LeafByEntryID(ctx, core.Digest{0xff}); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unbekannter Eintrag: %v", err)
	}
	if _, err := e.store.STHBySize(ctx, 77); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unbekannte STH-Größe: %v", err)
	}
	if _, _, err := e.store.Get(ctx, core.Digest{0xff}); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unbekannte Nutzlast: %v", err)
	}
	if status, err := e.store.Status(ctx, core.Digest{0xff}); err != nil || status != owmlog.BlobAbsent {
		t.Errorf("Status = %s, %v; erwartet absent", status, err)
	}
}

func TestSTHsAreKept(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	var sths []*owmlog.STH
	for round := 0; round < 5; round++ {
		e.append(ctx, []byte(fmt.Sprintf("runde-%d", round)))
		signed, err := e.log.IssueSTH(ctx)
		if err != nil {
			t.Fatalf("STH: %v", err)
		}
		sth, err := signed.STH()
		if err != nil {
			t.Fatalf("STH lesen: %v", err)
		}
		sths = append(sths, sth)
	}
	e.reopen()

	sizes, err := e.store.STHSizes(ctx)
	if err != nil {
		t.Fatalf("STH-Größen: %v", err)
	}
	if len(sizes) != len(sths) {
		t.Fatalf("%d STHs aufbewahrt, erwartet %d", len(sizes), len(sths))
	}
	// Alle aufbewahrten STHs müssen paarweise konsistent sein — die
	// Eigenschaft, die ein Beobachter überhaupt erst prüfen kann, wenn die Node
	// alte STHs herausgibt.
	for i := range sths {
		for j := i; j < len(sths); j++ {
			p, err := e.log.ConsistencyProof(ctx, sths[i].Size, sths[j].Size)
			if err != nil {
				t.Fatalf("Konsistenzbeweis: %v", err)
			}
			if err := p.Verify(sths[i], sths[j]); err != nil {
				t.Errorf("STHs %d und %d inkonsistent: %v", i, j, err)
			}
			if err := owmlog.CheckSTHPair(sths[i], sths[j]); err != nil {
				t.Errorf("CheckSTHPair(%d, %d): %v", i, j, err)
			}
		}
	}

	// Ein zweiter STH zur selben Größe darf den vorhandenen nicht verdrängen.
	last := sths[len(sths)-1]
	forged := *last
	forged.Root[0] ^= 0xff
	forged.IssuedAt = e.now().UnixMilli()
	signedForged, err := owmlog.SignSTH(e.key, &forged)
	if err != nil {
		t.Fatalf("signieren: %v", err)
	}
	if err := e.store.PutSTH(ctx, forged.Size, signedForged); err != nil {
		t.Fatalf("PutSTH: %v", err)
	}
	kept, err := e.store.STHBySize(ctx, last.Size)
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	keptSTH, err := kept.STH()
	if err != nil {
		t.Fatalf("STH lesen: %v", err)
	}
	if keptSTH.Root != last.Root {
		t.Error("vorhandener STH wurde überschrieben")
	}
}

func TestMemoryDSN(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("öffnen: %v", err)
	}
	defer store.Close()
	if size, err := store.Size(ctx); err != nil || size != 0 {
		t.Errorf("Größe = %d, %v; erwartet 0", size, err)
	}
	if _, err := store.LatestSTH(ctx); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("STH im leeren Log: %v", err)
	}
	if _, err := store.Nodes(ctx, nil); err != nil {
		t.Errorf("leere Knotenabfrage: %v", err)
	}
}
