// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/transparency-dev/merkle/compact"

	"openwaymark.org/owm/core"
)

// MemStorage hält das Log im Arbeitsspeicher.
//
// Gedacht für Tests und für Beobachter, die ohnehin nichts dauerhaft aufheben.
// Eine Node braucht die SQLite-Anbindung aus dem Unterpaket sqlite.
type MemStorage struct {
	mu     sync.RWMutex
	size   uint64
	leaves []LeafRecord
	nodes  map[compact.NodeID]core.Digest
	sths   map[uint64]*SignedSTH
	latest uint64
	hasSTH bool
}

// NewMemStorage legt einen leeren Speicher an.
func NewMemStorage() *MemStorage {
	return &MemStorage{
		nodes: make(map[compact.NodeID]core.Digest),
		sths:  make(map[uint64]*SignedSTH),
	}
}

var _ Storage = (*MemStorage)(nil)

func (m *MemStorage) Size(context.Context) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.size, nil
}

func (m *MemStorage) Append(_ context.Context, oldSize uint64, leaf LeafRecord, nodes []Node) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.size != oldSize {
		return fmt.Errorf("%w: expected %d, stored %d", ErrConflict, oldSize, m.size)
	}
	if leaf.Seq != oldSize {
		return fmt.Errorf("%w: seq=%d, expected %d", ErrLeafConflict, leaf.Seq, oldSize)
	}
	rec := leaf
	rec.Data = append([]byte(nil), leaf.Data...)
	m.leaves = append(m.leaves, rec)
	for _, n := range nodes {
		m.nodes[compact.NewNodeID(n.Level, n.Index)] = n.Hash
	}
	m.size = oldSize + 1
	return nil
}

func (m *MemStorage) LeafBySeq(_ context.Context, seq uint64) (*LeafRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if seq >= m.size {
		return nil, fmt.Errorf("%w: leaf %d", ErrNotFound, seq)
	}
	return copyRecord(&m.leaves[seq]), nil
}

func (m *MemStorage) LeafByEntryID(_ context.Context, id core.Digest) (*LeafRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i := range m.leaves {
		if m.leaves[i].EntryID == id {
			return copyRecord(&m.leaves[i]), nil
		}
	}
	return nil, fmt.Errorf("%w: entry %s", ErrNotFound, id)
}

func (m *MemStorage) LeavesBySubject(_ context.Context, subject core.SubjectID) ([]LeafRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []LeafRecord
	for i := range m.leaves {
		if m.leaves[i].Subject == subject {
			out = append(out, *copyRecord(&m.leaves[i]))
		}
	}
	return out, nil
}

func (m *MemStorage) Nodes(_ context.Context, ids []compact.NodeID) ([]core.Digest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]core.Digest, len(ids))
	for i, id := range ids {
		h, ok := m.nodes[id]
		if !ok {
			return nil, fmt.Errorf("%w: node (%d,%d)", ErrNotFound, id.Level, id.Index)
		}
		out[i] = h
	}
	return out, nil
}

func (m *MemStorage) PutSTH(_ context.Context, size uint64, s *SignedSTH) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sths[size] = s
	if !m.hasSTH || size >= m.latest {
		m.latest = size
		m.hasSTH = true
	}
	return nil
}

func (m *MemStorage) LatestSTH(context.Context) (*SignedSTH, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.hasSTH {
		return nil, fmt.Errorf("%w: no STH issued yet", ErrNotFound)
	}
	return m.sths[m.latest], nil
}

func (m *MemStorage) STHBySize(_ context.Context, size uint64) (*SignedSTH, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sths[size]
	if !ok {
		return nil, fmt.Errorf("%w: STH over %d leaves", ErrNotFound, size)
	}
	return s, nil
}

// STHSizes liefert die Größen aller abgelegten STHs, aufsteigend. Nützlich für
// Tests und Beobachter, die alle Paare durchprüfen wollen.
func (m *MemStorage) STHSizes() []uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]uint64, 0, len(m.sths))
	for size := range m.sths {
		out = append(out, size)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func copyRecord(r *LeafRecord) *LeafRecord {
	out := *r
	out.Data = append([]byte(nil), r.Data...)
	return &out
}

// MemBlobStore hält Nutzlasten im Arbeitsspeicher.
type MemBlobStore struct {
	mu    sync.RWMutex
	blobs map[core.Digest]*memBlob
}

type memBlob struct {
	salt    core.Salt
	payload []byte
	erased  bool
}

// NewMemBlobStore legt einen leeren Nutzlastspeicher an.
func NewMemBlobStore() *MemBlobStore {
	return &MemBlobStore{blobs: make(map[core.Digest]*memBlob)}
}

var _ BlobStore = (*MemBlobStore)(nil)

func (m *MemBlobStore) Put(_ context.Context, entryID core.Digest, salt core.Salt, payload []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok := m.blobs[entryID]; ok && b.erased {
		// Eine gelöschte Nutzlast wieder hereinzulassen würde die Löschung
		// rückgängig machen. Wer das täte, hätte das Recht auf Löschung
		// technisch umgangen.
		return fmt.Errorf("%w: %s", ErrErased, entryID)
	}
	m.blobs[entryID] = &memBlob{salt: salt, payload: append([]byte(nil), payload...)}
	return nil
}

func (m *MemBlobStore) Get(_ context.Context, entryID core.Digest) (core.Salt, []byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blobs[entryID]
	switch {
	case !ok:
		return core.Salt{}, nil, fmt.Errorf("%w: payload for %s", ErrNotFound, entryID)
	case b.erased:
		return core.Salt{}, nil, fmt.Errorf("%w: %s", ErrErased, entryID)
	}
	return b.salt, append([]byte(nil), b.payload...), nil
}

func (m *MemBlobStore) Erase(_ context.Context, entryID core.Digest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.blobs[entryID]
	if !ok {
		// Der Grabstein soll auch dann gesetzt werden können, wenn hier nie
		// etwas lag: Die Löschung ist dann bereits vollzogen.
		m.blobs[entryID] = &memBlob{erased: true}
		return nil
	}
	b.salt.Wipe()
	for i := range b.payload {
		b.payload[i] = 0
	}
	b.payload = nil
	b.erased = true
	return nil
}

func (m *MemBlobStore) Status(_ context.Context, entryID core.Digest) (BlobStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.blobs[entryID]
	switch {
	case !ok:
		return BlobAbsent, nil
	case b.erased:
		return BlobErased, nil
	}
	return BlobPresent, nil
}
