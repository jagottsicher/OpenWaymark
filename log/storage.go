// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"errors"

	"github.com/transparency-dev/merkle/compact"

	"openwaymark.org/owm/core"
)

var (
	ErrNotFound     = errors.New("owm/log: not found")
	ErrConflict     = errors.New("owm/log: tree size changed in the meantime")
	ErrErased       = errors.New("owm/log: payload has been erased")
	ErrNotErasable  = errors.New("owm/log: this entry type cannot be erased")
	ErrNoBlobStore  = errors.New("owm/log: no payload store configured")
	ErrCommitment   = errors.New("owm/log: payload does not match the commitment")
	ErrLeafConflict = errors.New("owm/log: a leaf with this position already exists")
)

// Node is a node of the Merkle tree.
//
// Level 0 are the leaves. Only complete (perfect) subtrees are stored; the
// incomplete nodes along the right-hand edge are recomputed on demand. A node
// that is complete once never changes again — which is why a single set of
// nodes suffices to issue proofs for every past tree size.
type Node struct {
	Level uint
	Index uint64
	Hash  core.Digest
}

// LeafRecord is a stored leaf together with the fields that are searched on.
//
// EntryID and Subject are derivable from Data and are carried along anyway:
// without them every search would have to decode every leaf.
type LeafRecord struct {
	Seq      uint64
	Hash     core.Digest
	EntryID  core.Digest
	Subject  core.SubjectID
	LoggedAt int64
	Data     []byte
}

// Storage holds leaves, nodes and STHs.
//
// The interface is deliberately narrow and knows nothing of transactions: the
// only operation that has to be atomic is Append, and that one carries its
// expected starting size with it.
type Storage interface {
	// Size returns the current number of leaves.
	Size(ctx context.Context) (uint64, error)

	// Append adds a leaf and the nodes it completes atomically and increases
	// the tree size by one.
	//
	// If the stored size differs from oldSize, the implementation MUST return
	// ErrConflict and write nothing. That is the interface's only concurrency
	// safeguard — and it suffices, because a log only grows in one place.
	Append(ctx context.Context, oldSize uint64, leaf LeafRecord, nodes []Node) error

	// LeafBySeq returns the leaf at the given position.
	LeafBySeq(ctx context.Context, seq uint64) (*LeafRecord, error)

	// LeafByEntryID returns the oldest leaf with this entry identifier. The
	// same entry may have been appended more than once.
	LeafByEntryID(ctx context.Context, id core.Digest) (*LeafRecord, error)

	// LeavesBySubject returns all leaves for a subject, ascending by position.
	// This is the basis of the product history.
	LeavesBySubject(ctx context.Context, subject core.SubjectID) ([]LeafRecord, error)

	// Nodes returns the hashes of the given nodes in the same order. A missing
	// one is ErrNotFound.
	Nodes(ctx context.Context, ids []compact.NodeID) ([]core.Digest, error)

	// PutSTH stores an issued STH.
	//
	// An observer needs old STHs to be able to compare at all; a log that only
	// keeps the most recent one makes itself uncheckable.
	PutSTH(ctx context.Context, size uint64, s *SignedSTH) error

	// LatestSTH returns the most recently issued STH or ErrNotFound.
	LatestSTH(ctx context.Context) (*SignedSTH, error)

	// STHBySize returns an STH for the given tree size or ErrNotFound.
	STHBySize(ctx context.Context, size uint64) (*SignedSTH, error)
}

// BlobStatus describes the state of a payload.
type BlobStatus int

const (
	// BlobAbsent: no payload was ever stored for this entry.
	BlobAbsent BlobStatus = iota
	// BlobPresent: payload and salt are available.
	BlobPresent
	// BlobErased: payload and salt have been deleted. The state remains
	// permanently provable — it is the difference between a lawful erasure and
	// withholding data (OWM-9 A3).
	BlobErased
)

func (s BlobStatus) String() string {
	switch s {
	case BlobAbsent:
		return "absent"
	case BlobPresent:
		return "present"
	case BlobErased:
		return "erased"
	default:
		return "unknown"
	}
}

// BlobStore holds the payloads outside the log.
//
// The salt lives with the blob and is deleted with it. Exactly that makes the
// erasure effective: the commitment in the log is HMAC-SHA-256 with the salt as
// the key — without it the value is uniformly distributed over the key space
// and even a value range of two possibilities can no longer be resolved.
type BlobStore interface {
	// Put stores payload and salt for an entry identifier.
	Put(ctx context.Context, entryID core.Digest, salt core.Salt, payload []byte) error

	// Get returns payload and salt, ErrErased after an erasure, or ErrNotFound
	// if nothing was ever stored.
	Get(ctx context.Context, entryID core.Digest) (core.Salt, []byte, error)

	// Erase deletes payload and salt irrecoverably and records the erasure. A
	// second call is permitted and changes nothing.
	Erase(ctx context.Context, entryID core.Digest) error

	// Status reports the state without reading the data.
	Status(ctx context.Context, entryID core.Digest) (BlobStatus, error)
}
