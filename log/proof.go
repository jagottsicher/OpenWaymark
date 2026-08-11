// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/proof"

	"openwaymark.org/owm/core"
)

// Beweise werden nicht signiert und brauchen deshalb kein kanonisches Format.
// Ihre Integrität ergibt sich vollständig daraus, dass sie gegen einen
// signierten Wurzelhash aufgehen oder eben nicht. Ein manipulierter Beweis
// schlägt fehl; ein Beweis in abweichender Kodierung, der aufgeht, ist ein
// gültiger Beweis. Siehe OWM-2 §5.3.

var (
	ErrProofSize    = errors.New("owm/log: Beweis passt nicht zur Baumgröße")
	ErrProofInvalid = errors.New("owm/log: Beweis geht nicht auf")
	ErrSplitView    = errors.New("owm/log: Split-View: zwei Wurzeln zur selben Baumgröße")
	ErrShrunk       = errors.New("owm/log: Baum ist geschrumpft")
)

// InclusionProof belegt, dass ein Blatt an Position LeafIndex in einem Baum der
// Größe TreeSize enthalten ist.
type InclusionProof struct {
	LeafIndex uint64        `json:"leaf_index"`
	TreeSize  uint64        `json:"tree_size"`
	Path      []core.Digest `json:"path"`
}

// VerifyAgainstRoot prüft den Beweis gegen einen Wurzelhash.
//
// Wer diese Methode direkt aufruft, muss selbst dafür sorgen, dass der
// Wurzelhash aus einer geprüften Quelle stammt. Ein Inklusionsbeweis für sich
// allein sagt nichts aus — er rechnet nur eine Wurzel aus, und die könnte der
// Angreifer mitgeliefert haben. Im Zweifel Verify verwenden.
func (p *InclusionProof) VerifyAgainstRoot(leafHash, root core.Digest) error {
	if p.LeafIndex >= p.TreeSize {
		return fmt.Errorf("%w: Index %d in Baum der Größe %d", ErrProofSize, p.LeafIndex, p.TreeSize)
	}
	err := proof.VerifyInclusion(hasher, p.LeafIndex, p.TreeSize,
		leafHash[:], digestsToBytes(p.Path), root[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofInvalid, err)
	}
	return nil
}

// Verify prüft den Beweis gegen einen STH und stellt dabei sicher, dass der
// Beweis für genau dessen Baumgröße gilt.
//
// Der Aufrufer MUSS den STH vorher signaturgeprüft haben.
func (p *InclusionProof) Verify(leafHash core.Digest, sth *STH) error {
	if sth == nil {
		return fmt.Errorf("%w: sth", ErrMissingField)
	}
	if p.TreeSize != sth.Size {
		return fmt.Errorf("%w: Beweis für %d, STH über %d", ErrProofSize, p.TreeSize, sth.Size)
	}
	return p.VerifyAgainstRoot(leafHash, sth.Root)
}

// ConsistencyProof belegt, dass ein Baum der Größe OldSize ein Präfix eines
// Baums der Größe NewSize ist — dass also zwischen beiden nur angehängt und
// nichts geändert oder entfernt wurde.
type ConsistencyProof struct {
	OldSize uint64        `json:"old_size"`
	NewSize uint64        `json:"new_size"`
	Path    []core.Digest `json:"path"`
}

// VerifyAgainstRoots prüft den Beweis gegen zwei Wurzelhashes.
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

// Verify prüft den Beweis zwischen zwei STHs desselben Logs.
//
// Der Aufrufer MUSS beide STHs vorher signaturgeprüft haben. Dass beide
// dasselbe Log nennen, prüft diese Methode — ein Konsistenzbeweis zwischen zwei
// verschiedenen Logs wäre bedeutungslos, und die Verwechslung ist leicht
// gemacht.
func (p *ConsistencyProof) Verify(old, new *STH) error {
	if old == nil || new == nil {
		return fmt.Errorf("%w: sth", ErrMissingField)
	}
	if old.Log != new.Log {
		return fmt.Errorf("%w: %s und %s", ErrLogMismatch, old.Log, new.Log)
	}
	if p.OldSize != old.Size || p.NewSize != new.Size {
		return fmt.Errorf("%w: Beweis %d→%d, STHs %d→%d",
			ErrProofSize, p.OldSize, p.NewSize, old.Size, new.Size)
	}
	return p.VerifyAgainstRoots(old.Root, new.Root)
}

// CheckSTHPair vergleicht zwei STHs desselben Logs auf Widersprüche, die ohne
// Konsistenzbeweis erkennbar sind.
//
// Das ist die Primitive, auf der der unabhängige Monitor aufsetzt (OWM-2 §9).
// Sie meldet nur, was die Node selbst unterschrieben hat und deshalb nicht
// abstreiten kann. Kein Befund bedeutet NICHT, dass alles in Ordnung ist —
// dafür braucht es zusätzlich einen Konsistenzbeweis zwischen beiden.
//
// Und die Vorbedingung, ohne die das Ganze nichts wert ist: Die beiden STHs
// müssen von verschiedenen Beobachtern stammen. Ein einzelner Beobachter sieht
// nur eine der beiden Historien, und die ist in sich stimmig.
func CheckSTHPair(a, b *STH) error {
	if a == nil || b == nil {
		return fmt.Errorf("%w: sth", ErrMissingField)
	}
	if a.Log != b.Log {
		return fmt.Errorf("%w: %s und %s", ErrLogMismatch, a.Log, b.Log)
	}
	if a.Size == b.Size && a.Root != b.Root {
		return fmt.Errorf("%w: Größe %d, Wurzeln %s und %s", ErrSplitView, a.Size, a.Root, b.Root)
	}
	// Ein Baum darf nur wachsen. Der spätere STH mit der kleineren Größe ist
	// ein Beweis, dass Blätter verschwunden sind.
	early, late := a, b
	if late.IssuedAt < early.IssuedAt {
		early, late = b, a
	}
	if late.Size < early.Size {
		return fmt.Errorf("%w: von %d auf %d", ErrShrunk, early.Size, late.Size)
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
			return nil, fmt.Errorf("owm/log: Beweisknoten %d: %w", i, err)
		}
		out[i] = d
	}
	return out, nil
}
