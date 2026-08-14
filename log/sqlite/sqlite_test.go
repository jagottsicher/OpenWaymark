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

// newEnv creates a log over a file in the test directory. Deliberately not a
// :memory: database: the test is also meant to answer whether the log survives
// a restart.
func newEnv(t *testing.T) *env {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("key: %v", err)
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
		e.t.Fatalf("open: %v", err)
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
		e.t.Fatalf("create log: %v", err)
	}
	e.store = store
	e.log = lg
}

// reopen closes the database and opens it again.
func (e *env) reopen() {
	e.t.Helper()
	if err := e.store.Close(); err != nil {
		e.t.Fatalf("close: %v", err)
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
		e.t.Fatalf("subject: %v", err)
	}
	return e.appendTo(ctx, subject, payload)
}

func (e *env) appendTo(ctx context.Context, subject core.SubjectID, payload []byte) (*owmlog.Leaf, core.Digest) {
	e.t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		e.t.Fatalf("salt: %v", err)
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
		e.t.Fatalf("sign: %v", err)
	}
	leaf, err := e.log.AppendWithPayload(ctx, se, salt, payload)
	if err != nil {
		e.t.Fatalf("append: %v", err)
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
		leaf, _ := e.append(ctx, []byte(fmt.Sprintf("payload-%d", i)))
		leaves = append(leaves, leaf)
	}
	signed, err := e.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}

	e.reopen()

	size, err := e.log.Size(ctx)
	if err != nil {
		t.Fatalf("size: %v", err)
	}
	if size != n {
		t.Fatalf("%d leaves after the restart, expected %d", size, n)
	}
	root, err := e.log.RootAt(ctx, sth.Size)
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	if root != sth.Root {
		t.Errorf("root differs after the restart")
	}
	latest, err := e.log.LatestSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	if err := latest.Verify(e.key.Public()); err != nil {
		t.Errorf("STH after the restart: %v", err)
	}

	// Proofs against the STH issued before the restart.
	for i, leaf := range leaves {
		hash, err := leaf.Hash()
		if err != nil {
			t.Fatalf("leaf hash: %v", err)
		}
		p, err := e.log.InclusionProof(ctx, uint64(i), sth.Size)
		if err != nil {
			t.Fatalf("inclusion proof %d: %v", i, err)
		}
		if err := p.Verify(hash, sth); err != nil {
			t.Errorf("inclusion proof %d after the restart: %v", i, err)
		}
	}

	// And the tree keeps growing, consistent with the old witness.
	e.append(ctx, []byte("after the restart"))
	nextSigned, err := e.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	next, err := nextSigned.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	cp, err := e.log.ConsistencyProof(ctx, sth.Size, next.Size)
	if err != nil {
		t.Fatalf("consistency proof: %v", err)
	}
	if err := cp.Verify(sth, next); err != nil {
		t.Errorf("history broken across the restart: %v", err)
	}
}

func TestErasurePersists(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.append(ctx, []byte("neighbour"))
	leaf, entryID := e.append(ctx, []byte("personal data"))
	e.append(ctx, []byte("neighbour"))

	signed, err := e.log.IssueSTH(ctx)
	if err != nil {
		t.Fatalf("STH: %v", err)
	}
	before, err := signed.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	hash, err := leaf.Hash()
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}
	p, err := e.log.InclusionProof(ctx, leaf.Seq, before.Size)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}

	if _, err := e.log.Erase(ctx, entryID); err != nil {
		t.Fatalf("erase: %v", err)
	}
	e.reopen()

	if status, err := e.store.Status(ctx, entryID); err != nil || status != owmlog.BlobErased {
		t.Errorf("status after the restart = %s, %v; expected erased", status, err)
	}
	if _, err := e.log.Payload(ctx, entryID); !errors.Is(err, owmlog.ErrErased) {
		t.Errorf("payload retrievable after the restart: %v", err)
	}
	if err := e.store.Put(ctx, entryID, core.Salt{}, []byte("clean again")); !errors.Is(err, owmlog.ErrErased) {
		t.Errorf("erased payload accepted again: %v", err)
	}
	// The witness remains: what was erased is the payload, not the proof.
	if err := p.Verify(hash, before); err != nil {
		t.Errorf("inclusion proof after erasure and restart: %v", err)
	}
	if err := signed.Verify(e.key.Public()); err != nil {
		t.Errorf("old STH after the erasure: %v", err)
	}
}

func TestAppendConflict(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.append(ctx, []byte("one"))

	rec := owmlog.LeafRecord{
		Seq:      0, // the position has long been taken
		Hash:     core.Digest{1},
		EntryID:  core.Digest{2},
		Subject:  core.SubjectID{3},
		LoggedAt: e.now().UnixMilli(),
		Data:     []byte{0x01},
	}
	if err := e.store.Append(ctx, 0, rec, nil); !errors.Is(err, owmlog.ErrConflict) {
		t.Errorf("stale base size accepted: %v", err)
	}
	rec.Seq = 5
	if err := e.store.Append(ctx, 1, rec, nil); !errors.Is(err, owmlog.ErrLeafConflict) {
		t.Errorf("leaf with the wrong position accepted: %v", err)
	}
	if size, err := e.store.Size(ctx); err != nil || size != 1 {
		t.Errorf("size = %d, %v; expected 1", size, err)
	}
}

func TestLookupsAndNotFound(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	e.append(ctx, []byte("unrelated"))
	var ids []core.Digest
	for i := 0; i < 3; i++ {
		_, id := e.appendTo(ctx, subject, []byte(fmt.Sprintf("station-%d", i)))
		ids = append(ids, id)
		e.append(ctx, []byte("unrelated"))
	}

	history, err := e.store.LeavesBySubject(ctx, subject)
	if err != nil {
		t.Fatalf("subject lookup: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history has %d entries, expected 3", len(history))
	}
	for i := 1; i < len(history); i++ {
		if history[i-1].Seq >= history[i].Seq {
			t.Errorf("history not ascending")
		}
	}
	for _, id := range ids {
		rec, err := e.store.LeafByEntryID(ctx, id)
		if err != nil {
			t.Fatalf("entry lookup: %v", err)
		}
		if rec.EntryID != id {
			t.Errorf("wrong entry returned")
		}
	}

	if _, err := e.store.LeafBySeq(ctx, 999); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unknown position: %v", err)
	}
	if _, err := e.store.LeafByEntryID(ctx, core.Digest{0xff}); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unknown entry: %v", err)
	}
	if _, err := e.store.STHBySize(ctx, 77); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unknown STH size: %v", err)
	}
	if _, _, err := e.store.Get(ctx, core.Digest{0xff}); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("unknown payload: %v", err)
	}
	if status, err := e.store.Status(ctx, core.Digest{0xff}); err != nil || status != owmlog.BlobAbsent {
		t.Errorf("status = %s, %v; expected absent", status, err)
	}
}

func TestSTHsAreKept(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	var sths []*owmlog.STH
	for round := 0; round < 5; round++ {
		e.append(ctx, []byte(fmt.Sprintf("round-%d", round)))
		signed, err := e.log.IssueSTH(ctx)
		if err != nil {
			t.Fatalf("STH: %v", err)
		}
		sth, err := signed.STH()
		if err != nil {
			t.Fatalf("read STH: %v", err)
		}
		sths = append(sths, sth)
	}
	e.reopen()

	sizes, err := e.store.STHSizes(ctx)
	if err != nil {
		t.Fatalf("STH sizes: %v", err)
	}
	if len(sizes) != len(sths) {
		t.Fatalf("%d STHs retained, expected %d", len(sizes), len(sths))
	}
	// All retained STHs must be pairwise consistent — the property an observer
	// can only check at all if the node hands out old STHs.
	for i := range sths {
		for j := i; j < len(sths); j++ {
			p, err := e.log.ConsistencyProof(ctx, sths[i].Size, sths[j].Size)
			if err != nil {
				t.Fatalf("consistency proof: %v", err)
			}
			if err := p.Verify(sths[i], sths[j]); err != nil {
				t.Errorf("STHs %d and %d inconsistent: %v", i, j, err)
			}
			if err := owmlog.CheckSTHPair(sths[i], sths[j]); err != nil {
				t.Errorf("CheckSTHPair(%d, %d): %v", i, j, err)
			}
		}
	}

	// A second STH for the same size must not displace the existing one.
	last := sths[len(sths)-1]
	forged := *last
	forged.Root[0] ^= 0xff
	forged.IssuedAt = e.now().UnixMilli()
	signedForged, err := owmlog.SignSTH(e.key, &forged)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := e.store.PutSTH(ctx, forged.Size, signedForged); err != nil {
		t.Fatalf("PutSTH: %v", err)
	}
	kept, err := e.store.STHBySize(ctx, last.Size)
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	keptSTH, err := kept.STH()
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	if keptSTH.Root != last.Root {
		t.Error("existing STH was overwritten")
	}
}

func TestMemoryDSN(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()
	if size, err := store.Size(ctx); err != nil || size != 0 {
		t.Errorf("size = %d, %v; expected 0", size, err)
	}
	if _, err := store.LatestSTH(ctx); !errors.Is(err, owmlog.ErrNotFound) {
		t.Errorf("STH in the empty log: %v", err)
	}
	if _, err := store.Nodes(ctx, nil); err != nil {
		t.Errorf("empty node query: %v", err)
	}
}
