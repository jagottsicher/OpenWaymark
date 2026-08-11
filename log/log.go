// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"

	"openwaymark.org/owm/core"
)

// KeyResolver liefert den öffentlichen Schlüssel zu einer Kennung.
//
// Ohne einen solchen Auflöser kann ein Log die Signatur eines eingereichten
// Eintrags nicht prüfen — es kennt den Aussteller nicht. Eine Node im Betrieb
// MUSS einen setzen. Die Verwaltung der Schlüssel selbst gehört nicht hierher,
// sondern in OWM-3.
type KeyResolver interface {
	PublicKey(ctx context.Context, id core.KeyID) (*core.PublicKey, error)
}

// Options konfiguriert ein Log.
type Options struct {
	// Storage ist Pflicht.
	Storage Storage

	// Signer unterschreibt STHs und Löschbezeugungen. Pflicht.
	Signer *core.PrivateKey

	// Genesis bestimmt die Log-Kennung. Bleibt das Feld leer, wird der
	// öffentliche Schlüssel des Signers verwendet — richtig beim Anlegen eines
	// neuen Logs, falsch nach jeder Schlüsselrotation. Nach einer Rotation MUSS
	// hier weiterhin der ursprüngliche Gründungsschlüssel stehen, sonst
	// wechselt die Log-Kennung mit (OWM-2 §2).
	Genesis *core.PublicKey

	// Blobs hält die Nutzlasten. Ohne diesen Speicher sind
	// AppendWithPayload, Payload und Erase nicht verfügbar.
	Blobs BlobStore

	// Keys prüft die Signaturen eingereichter Einträge. Ist das Feld leer,
	// prüft Append nur die Struktur und akzeptiert Einträge unbekannter
	// Aussteller — brauchbar für Tests, nicht für den Betrieb.
	Keys KeyResolver

	// Now liefert die Zeit. Leer bedeutet time.Now.
	Now func() time.Time
}

// Log führt den Merkle-Baum einer Node.
//
// Alle Methoden sind nebenläufigkeitssicher. Das Anhängen ist serialisiert: Ein
// Log wächst an genau einer Stelle, und zwei gleichzeitige Anhänger würden
// dieselbe Position beanspruchen.
type Log struct {
	id     core.LogID
	signer *core.PrivateKey
	st     Storage
	blobs  BlobStore
	keys   KeyResolver
	rf     *compact.RangeFactory
	now    func() time.Time

	mu sync.Mutex // serialisiert Append
}

// New legt ein Log über dem angegebenen Speicher an.
func New(opts Options) (*Log, error) {
	if opts.Storage == nil {
		return nil, fmt.Errorf("%w: Storage", ErrMissingField)
	}
	if opts.Signer == nil {
		return nil, fmt.Errorf("%w: Signer", ErrMissingField)
	}
	genesis := opts.Genesis
	if genesis == nil {
		genesis = opts.Signer.Public()
	}
	id, err := core.DeriveLogID(genesis)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Log{
		id:     id,
		signer: opts.Signer,
		st:     opts.Storage,
		blobs:  opts.Blobs,
		keys:   opts.Keys,
		rf:     &compact.RangeFactory{Hash: hasher.HashChildren},
		now:    now,
	}, nil
}

// ID liefert die Kennung des Logs.
func (l *Log) ID() core.LogID { return l.id }

// Size liefert die aktuelle Zahl der Blätter.
func (l *Log) Size(ctx context.Context) (uint64, error) { return l.st.Size(ctx) }

// Root liefert den Wurzelhash über den gesamten aktuellen Baum.
func (l *Log) Root(ctx context.Context) (core.Digest, error) {
	size, err := l.st.Size(ctx)
	if err != nil {
		return core.Digest{}, err
	}
	return l.RootAt(ctx, size)
}

// RootAt liefert den Wurzelhash über die ersten size Blätter.
//
// Das geht auch für längst überschrittene Größen, weil vollständige Teilbäume
// unveränderlich sind: Was einmal gespeichert wurde, gilt für jede spätere
// Baumgröße weiter.
func (l *Log) RootAt(ctx context.Context, size uint64) (core.Digest, error) {
	cur, err := l.st.Size(ctx)
	if err != nil {
		return core.Digest{}, err
	}
	if size > cur {
		return core.Digest{}, fmt.Errorf("%w: %d angefragt, Baum hat %d", ErrProofSize, size, cur)
	}
	if size == 0 {
		var d core.Digest
		copy(d[:], hasher.EmptyRoot())
		return d, nil
	}
	r, err := l.rangeAt(ctx, size)
	if err != nil {
		return core.Digest{}, err
	}
	root, err := r.GetRootHash(nil)
	if err != nil {
		return core.Digest{}, fmt.Errorf("owm/log: Wurzel über %d Blätter: %w", size, err)
	}
	return core.DigestFromBytes(root)
}

// rangeAt lädt den kompakten Bereich [0, size) aus dem Speicher.
func (l *Log) rangeAt(ctx context.Context, size uint64) (*compact.Range, error) {
	ids := compact.RangeNodes(0, size, nil)
	hashes, err := l.st.Nodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	r, err := l.rf.NewRange(0, size, digestsToBytes(hashes))
	if err != nil {
		return nil, fmt.Errorf("owm/log: Bereich [0,%d): %w", size, err)
	}
	return r, nil
}

// Append prüft einen signierten Eintrag und hängt ihn an.
func (l *Log) Append(ctx context.Context, se *core.SignedEntry) (*Leaf, error) {
	if se == nil {
		return nil, fmt.Errorf("%w: Eintrag", ErrMissingField)
	}
	entryBytes, err := se.Encode()
	if err != nil {
		return nil, fmt.Errorf("owm/log: Eintrag kodieren: %w", err)
	}
	e, err := l.checkEntry(ctx, se)
	if err != nil {
		return nil, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	size, err := l.st.Size(ctx)
	if err != nil {
		return nil, err
	}
	leaf := &Leaf{
		Version:  FormatVersion,
		Log:      l.id,
		Seq:      size,
		LoggedAt: l.now().UTC().UnixMilli(),
		Entry:    entryBytes,
	}
	leafBytes, err := leaf.Encode()
	if err != nil {
		return nil, err
	}
	leafHash := LeafHashFromBytes(leafBytes)

	r, err := l.rangeAt(ctx, size)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	var visitErr error
	err = r.Append(leafHash[:], func(id compact.NodeID, hash []byte) {
		d, err := core.DigestFromBytes(hash)
		if err != nil {
			visitErr = err
			return
		}
		nodes = append(nodes, Node{Level: id.Level, Index: id.Index, Hash: d})
	})
	if err != nil {
		return nil, fmt.Errorf("owm/log: anhängen: %w", err)
	}
	if visitErr != nil {
		return nil, fmt.Errorf("owm/log: Knotenhash: %w", visitErr)
	}

	rec := LeafRecord{
		Seq:      leaf.Seq,
		Hash:     leafHash,
		EntryID:  se.EntryID(),
		Subject:  e.Subject,
		LoggedAt: leaf.LoggedAt,
		Data:     leafBytes,
	}
	if err := l.st.Append(ctx, size, rec, nodes); err != nil {
		return nil, err
	}
	return leaf, nil
}

// AppendWithPayload hinterlegt die Nutzlast und hängt den Eintrag an.
//
// Die Nutzlast wird vorher gegen das Commitment im Eintrag geprüft. Ohne diese
// Prüfung nähme die Node Daten an, die zu ihrem eigenen Log nicht passen und
// die niemand je verifizieren könnte.
//
// Reihenfolge: erst die Nutzlast ablegen, dann anhängen. Scheitert das
// Anhängen, wird die Nutzlast wieder gelöscht. Andersherum bliebe im
// Fehlerfall ein Eintrag im Baum, dessen Beleg nie eintrifft — und der Baum
// vergisst nicht.
func (l *Log) AppendWithPayload(ctx context.Context, se *core.SignedEntry, salt core.Salt, payload []byte) (*Leaf, error) {
	if l.blobs == nil {
		return nil, ErrNoBlobStore
	}
	if se == nil {
		return nil, fmt.Errorf("%w: Eintrag", ErrMissingField)
	}
	e, err := se.Entry()
	if err != nil {
		return nil, err
	}
	if !core.VerifyCommitment(e.Commitment, salt, payload) {
		return nil, fmt.Errorf("%w: Eintrag %s", ErrCommitment, se.EntryID())
	}
	entryID := se.EntryID()
	if err := l.blobs.Put(ctx, entryID, salt, payload); err != nil {
		return nil, err
	}
	leaf, err := l.Append(ctx, se)
	if err != nil {
		// Aufräumen, damit keine Nutzlast ohne zugehöriges Blatt zurückbleibt.
		// Eine solche Waise wäre unsichtbar gespeicherte Personendatenmenge.
		_ = l.blobs.Erase(ctx, entryID)
		return nil, err
	}
	return leaf, nil
}

// checkEntry prüft Struktur und, sofern ein KeyResolver gesetzt ist, die
// Signatur.
func (l *Log) checkEntry(ctx context.Context, se *core.SignedEntry) (*core.Entry, error) {
	e, err := se.Entry()
	if err != nil {
		return nil, err
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if l.keys == nil {
		return e, nil
	}
	pub, err := l.keys.PublicKey(ctx, e.Issuer)
	if err != nil {
		return nil, fmt.Errorf("owm/log: Aussteller %s: %w", e.Issuer, err)
	}
	if err := se.Verify(pub); err != nil {
		return nil, err
	}
	return e, nil
}

// Leaf liefert das Blatt an der angegebenen Position.
func (l *Log) Leaf(ctx context.Context, seq uint64) (*Leaf, error) {
	rec, err := l.st.LeafBySeq(ctx, seq)
	if err != nil {
		return nil, err
	}
	return ParseLeaf(rec.Data)
}

// LeafByEntryID liefert das Blatt zu einer Eintragskennung.
func (l *Log) LeafByEntryID(ctx context.Context, id core.Digest) (*Leaf, error) {
	rec, err := l.st.LeafByEntryID(ctx, id)
	if err != nil {
		return nil, err
	}
	return ParseLeaf(rec.Data)
}

// History liefert alle Blätter zu einem Subjekt, nach Position aufsteigend.
func (l *Log) History(ctx context.Context, subject core.SubjectID) ([]*Leaf, error) {
	recs, err := l.st.LeavesBySubject(ctx, subject)
	if err != nil {
		return nil, err
	}
	out := make([]*Leaf, 0, len(recs))
	for i := range recs {
		leaf, err := ParseLeaf(recs[i].Data)
		if err != nil {
			return nil, fmt.Errorf("owm/log: Blatt %d: %w", recs[i].Seq, err)
		}
		out = append(out, leaf)
	}
	return out, nil
}

// InclusionProof erzeugt den Inklusionsbeweis für das Blatt an Position seq in
// einem Baum der Größe size.
func (l *Log) InclusionProof(ctx context.Context, seq, size uint64) (*InclusionProof, error) {
	cur, err := l.st.Size(ctx)
	if err != nil {
		return nil, err
	}
	if size > cur {
		return nil, fmt.Errorf("%w: %d angefragt, Baum hat %d", ErrProofSize, size, cur)
	}
	if seq >= size {
		return nil, fmt.Errorf("%w: Blatt %d in Baum der Größe %d", ErrProofSize, seq, size)
	}
	nodes, err := proof.Inclusion(seq, size)
	if err != nil {
		return nil, fmt.Errorf("owm/log: Inklusionsbeweis: %w", err)
	}
	path, err := l.buildPath(ctx, nodes)
	if err != nil {
		return nil, err
	}
	return &InclusionProof{LeafIndex: seq, TreeSize: size, Path: path}, nil
}

// ConsistencyProof erzeugt den Konsistenzbeweis zwischen zwei Baumgrößen.
func (l *Log) ConsistencyProof(ctx context.Context, oldSize, newSize uint64) (*ConsistencyProof, error) {
	cur, err := l.st.Size(ctx)
	if err != nil {
		return nil, err
	}
	if newSize > cur {
		return nil, fmt.Errorf("%w: %d angefragt, Baum hat %d", ErrProofSize, newSize, cur)
	}
	if oldSize > newSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrProofSize, oldSize, newSize)
	}
	// Der leere Baum ist Präfix von allem; RFC 6962 kennt dafür keinen Beweis.
	if oldSize == 0 || oldSize == newSize {
		return &ConsistencyProof{OldSize: oldSize, NewSize: newSize}, nil
	}
	nodes, err := proof.Consistency(oldSize, newSize)
	if err != nil {
		return nil, fmt.Errorf("owm/log: Konsistenzbeweis: %w", err)
	}
	path, err := l.buildPath(ctx, nodes)
	if err != nil {
		return nil, err
	}
	return &ConsistencyProof{OldSize: oldSize, NewSize: newSize, Path: path}, nil
}

// buildPath holt die benötigten Knoten und rechnet die ephemeren Knoten am
// rechten Baumrand nach — gespeichert werden nur vollständige Teilbäume.
func (l *Log) buildPath(ctx context.Context, nodes proof.Nodes) ([]core.Digest, error) {
	hashes, err := l.st.Nodes(ctx, nodes.IDs)
	if err != nil {
		return nil, err
	}
	raw, err := nodes.Rehash(digestsToBytes(hashes), hasher.HashChildren)
	if err != nil {
		return nil, fmt.Errorf("owm/log: Beweispfad: %w", err)
	}
	return bytesToDigests(raw)
}

// IssueSTH stellt einen Signed Tree Head über den aktuellen Baum aus und legt
// ihn ab.
func (l *Log) IssueSTH(ctx context.Context) (*SignedSTH, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	size, err := l.st.Size(ctx)
	if err != nil {
		return nil, err
	}
	root, err := l.RootAt(ctx, size)
	if err != nil {
		return nil, err
	}
	sth := &STH{
		Version:  FormatVersion,
		Log:      l.id,
		Size:     size,
		IssuedAt: l.now().UTC().UnixMilli(),
		Root:     root,
		Key:      l.signer.Public().ID(),
	}
	signed, err := SignSTH(l.signer, sth)
	if err != nil {
		return nil, err
	}
	if err := l.st.PutSTH(ctx, size, signed); err != nil {
		return nil, err
	}
	return signed, nil
}

// LatestSTH liefert den zuletzt ausgestellten STH.
func (l *Log) LatestSTH(ctx context.Context) (*SignedSTH, error) { return l.st.LatestSTH(ctx) }

// Payload liefert die Nutzlast eines Eintrags und prüft sie gegen das
// Commitment im Log.
//
// Die Prüfung ist der Sinn der Sache: Ohne sie wäre die Nutzlast nur das, was
// der Server gerade herausgibt.
func (l *Log) Payload(ctx context.Context, entryID core.Digest) ([]byte, error) {
	if l.blobs == nil {
		return nil, ErrNoBlobStore
	}
	leaf, err := l.LeafByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}
	se, err := leaf.SignedEntry()
	if err != nil {
		return nil, err
	}
	e, err := se.Entry()
	if err != nil {
		return nil, err
	}
	salt, payload, err := l.blobs.Get(ctx, entryID)
	if err != nil {
		return nil, err
	}
	if !core.VerifyCommitment(e.Commitment, salt, payload) {
		return nil, fmt.Errorf("%w: Eintrag %s", ErrCommitment, entryID)
	}
	return payload, nil
}

// Erase löscht Nutzlast und Salt eines Eintrags und hängt eine Löschbezeugung
// an.
//
// Der Baum wird dabei NICHT angefasst. Genau daraus folgt, dass alle je
// ausgestellten STHs und alle je ausgestellten Beweise gültig bleiben — auch
// der Inklusionsbeweis des gelöschten Eintrags. Von außen ist eine Löschung ein
// gewöhnliches Anhängen. Siehe OWM-2 §7.
//
// Zuerst wird gelöscht, dann bezeugt. Scheitert das Anhängen, sind die Daten
// trotzdem fort und die Bezeugung fehlt noch — die harmlose Richtung. Andersherum
// stünde eine Löschbezeugung im Log, während die Daten noch da wären, und das
// Log löge.
func (l *Log) Erase(ctx context.Context, entryID core.Digest) (*Leaf, error) {
	if l.blobs == nil {
		return nil, ErrNoBlobStore
	}
	leaf, err := l.LeafByEntryID(ctx, entryID)
	if err != nil {
		return nil, err
	}
	se, err := leaf.SignedEntry()
	if err != nil {
		return nil, err
	}
	target, err := se.Entry()
	if err != nil {
		return nil, err
	}
	// Ohne die Rotationskette ließen sich alle späteren Signaturen des
	// Ausstellers niemandem mehr zuordnen. Ein öffentlicher Schlüssel ist
	// zudem nichts, was durch Löschen geschützt würde. OWM-2 §7.6.
	if target.Type == core.EntryTypeKeyRotation {
		return nil, fmt.Errorf("%w: %s", ErrNotErasable, target.Type)
	}
	if err := l.blobs.Erase(ctx, entryID); err != nil {
		return nil, err
	}

	tomb := &core.Entry{
		Version:  core.FormatVersion,
		Type:     core.EntryTypeErasure,
		Profile:  target.Profile,
		Subject:  target.Subject,
		IssuedAt: l.now().UTC().UnixMilli(),
		Issuer:   l.signer.Public().ID(),
		Target:   &core.EntryRef{Entry: entryID, Log: l.id},
	}
	signed, err := core.SignEntry(l.signer, tomb)
	if err != nil {
		return nil, err
	}
	return l.Append(ctx, signed)
}

// BlobStatus meldet, ob zu einem Eintrag eine Nutzlast vorliegt, nie eine
// hinterlegt wurde oder sie gelöscht ist.
func (l *Log) BlobStatus(ctx context.Context, entryID core.Digest) (BlobStatus, error) {
	if l.blobs == nil {
		return BlobAbsent, ErrNoBlobStore
	}
	return l.blobs.Status(ctx, entryID)
}
