// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/proof"

	"openwaymark.org/owm/core"
)

// Proofs are not signed and therefore need no canonical format. Their integrity
// follows entirely from whether they check out against a signed root hash or
// not. A tampered proof fails; a proof in a deviating encoding that checks out
// is a valid proof. See OWM-2 §5.3.

var (
	ErrProofSize    = errors.New("owm/log: proof does not match the tree size")
	ErrProofInvalid = errors.New("owm/log: proof does not check out")
	ErrSplitView    = errors.New("owm/log: split view: two roots for the same tree size")
	ErrShrunk       = errors.New("owm/log: tree has shrunk")
)

// InclusionProof shows that a leaf is contained at position LeafIndex in a tree
// of size TreeSize.
type InclusionProof struct {
	LeafIndex uint64        `json:"leaf_index"`
	TreeSize  uint64        `json:"tree_size"`
	Path      []core.Digest `json:"path"`
}

// VerifyAgainstRoot checks the proof against a root hash.
//
// Whoever calls this method directly has to make sure themselves that the root
// hash comes from a checked source. An inclusion proof on its own says nothing
// — it merely computes a root, and that root could have been supplied by the
// attacker. When in doubt, use Verify.
func (p *InclusionProof) VerifyAgainstRoot(leafHash, root core.Digest) error {
	if p.LeafIndex >= p.TreeSize {
		return fmt.Errorf("%w: index %d in a tree of size %d", ErrProofSize, p.LeafIndex, p.TreeSize)
	}
	err := proof.VerifyInclusion(hasher, p.LeafIndex, p.TreeSize,
		leafHash[:], digestsToBytes(p.Path), root[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofInvalid, err)
	}
	return nil
}

// Verify checks the proof against an STH, making sure the proof applies to
// exactly that tree size.
//
// The caller MUST have checked the signature of the STH beforehand.
func (p *InclusionProof) Verify(leafHash core.Digest, sth *STH) error {
	if sth == nil {
		return fmt.Errorf("%w: sth", ErrMissingField)
	}
	if p.TreeSize != sth.Size {
		return fmt.Errorf("%w: proof for %d, STH over %d", ErrProofSize, p.TreeSize, sth.Size)
	}
	return p.VerifyAgainstRoot(leafHash, sth.Root)
}

// ConsistencyProof shows that a tree of size OldSize is a prefix of a tree of
// size NewSize — that is, that between the two only appends happened and
// nothing was changed or removed.
type ConsistencyProof struct {
	OldSize uint64        `json:"old_size"`
	NewSize uint64        `json:"new_size"`
	Path    []core.Digest `json:"path"`
}

// VerifyAgainstRoots checks the proof against two root hashes.
func (p *ConsistencyProof) VerifyAgainstRoots(oldRoot, newRoot core.Digest) error {
	if p.OldSize > p.NewSize {
		return fmt.Errorf("%w: %d > %d", ErrProofSize, p.OldSize, p.NewSize)
	}
	err := proof.VerifyConsistency(hasher, p.OldSize, p.NewSize,
		digestsToBytes(p.Path), oldRoot[:], newRoot[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofInvalid, err)
	}
	return nil
}

// Verify checks the proof between two STHs of the same log.
//
// The caller MUST have checked the signatures of both STHs beforehand. That
// both name the same log is checked by this method — a consistency proof
// between two different logs would be meaningless, and the mix-up is easily
// made.
func (p *ConsistencyProof) Verify(old, new *STH) error {
	if old == nil || new == nil {
		return fmt.Errorf("%w: sth", ErrMissingField)
	}
	if old.Log != new.Log {
		return fmt.Errorf("%w: %s and %s", ErrLogMismatch, old.Log, new.Log)
	}
	if p.OldSize != old.Size || p.NewSize != new.Size {
		return fmt.Errorf("%w: proof %d->%d, STHs %d->%d",
			ErrProofSize, p.OldSize, p.NewSize, old.Size, new.Size)
	}
	return p.VerifyAgainstRoots(old.Root, new.Root)
}

// CheckSTHPair compares two STHs of the same log for contradictions that are
// detectable without a consistency proof.
//
// This is the primitive the independent monitor builds on (OWM-2 §9). It only
// reports what the node signed itself and therefore cannot deny. No finding
// does NOT mean everything is in order — that additionally requires a
// consistency proof between the two.
//
// And the precondition without which the whole thing is worthless: the two STHs
// must come from different observers. A single observer only ever sees one of
// the two histories, and that one is internally consistent.
func CheckSTHPair(a, b *STH) error {
	if a == nil || b == nil {
		return fmt.Errorf("%w: sth", ErrMissingField)
	}
	if a.Log != b.Log {
		return fmt.Errorf("%w: %s and %s", ErrLogMismatch, a.Log, b.Log)
	}
	if a.Size == b.Size && a.Root != b.Root {
		return fmt.Errorf("%w: size %d, roots %s and %s", ErrSplitView, a.Size, a.Root, b.Root)
	}
	// A tree may only grow. The later STH with the smaller size is proof that
	// leaves have disappeared.
	early, late := a, b
	if late.IssuedAt < early.IssuedAt {
		early, late = b, a
	}
	if late.Size < early.Size {
		return fmt.Errorf("%w: from %d to %d", ErrShrunk, early.Size, late.Size)
	}
	return nil
}

func digestsToBytes(ds []core.Digest) [][]byte {
	out := make([][]byte, len(ds))
	for i := range ds {
		out[i] = ds[i][:]
	}
	return out
}

func bytesToDigests(bs [][]byte) ([]core.Digest, error) {
	out := make([]core.Digest, len(bs))
	for i := range bs {
		d, err := core.DigestFromBytes(bs[i])
		if err != nil {
			return nil, fmt.Errorf("owm/log: proof node %d: %w", i, err)
		}
		out[i] = d
	}
	return out, nil
}
