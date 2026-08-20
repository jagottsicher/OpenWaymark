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

// KeyResolver returns the public key for an identifier.
//
// Without such a resolver a log cannot check the signature of a submitted entry
// — it does not know the issuer. A node in production MUST set one. Managing
// the keys themselves does not belong here but in OWM-3.
type KeyResolver interface {
	PublicKey(ctx context.Context, id core.KeyID) (*core.PublicKey, error)
}

// Options configures a log.
type Options struct {
	// Storage is mandatory.
	Storage Storage

	// Signer signs STHs and erasure witnesses. Mandatory.
	Signer *core.PrivateKey

	// Genesis determines the log identifier. If the field is empty, the
	// signer's public key is used — correct when creating a new log, wrong
	// after any key rotation. After a rotation the original genesis key MUST
	// still be given here, otherwise the log identifier changes with it
	// (OWM-2 §2).
	Genesis *core.PublicKey

	// Blobs holds the payloads. Without this store AppendWithPayload, Payload
	// and Erase are unavailable.
	Blobs BlobStore

	// Keys checks the signatures of submitted entries. If the field is empty,
	// Append only checks the structure and accepts entries from unknown issuers
	// — usable for tests, not for production.
	Keys KeyResolver

	// Now returns the time. Empty means time.Now.
	Now func() time.Time

	// MaxMergeDelay bounds how long IssueReceipt may promise before an
	// accepted entry has to be witnessed in a signed tree (OWM-9 A3). Zero
	// disables receipt issuance entirely — the same "zero means off"
	// convention Config.RateLimitPerSecond already uses elsewhere.
	MaxMergeDelay time.Duration
}

// Log maintains the Merkle tree of a node.
//
// All methods are safe for concurrent use. Appending is serialised: a log grows
// in exactly one place, and two concurrent appenders would claim the same
// position.
type Log struct {
	id            core.LogID
	signer        *core.PrivateKey
	st            Storage
	blobs         BlobStore
	keys          KeyResolver
	rf            *compact.RangeFactory
	now           func() time.Time
	maxMergeDelay time.Duration

	mu sync.Mutex // serialises Append
}

// New creates a log on top of the given storage.
func New(opts Options) (*Log, error) {
	if opts.Storage == nil {
		return nil, fmt.Errorf("%w: storage", ErrMissingField)
	}
	if opts.Signer == nil {
		return nil, fmt.Errorf("%w: signer", ErrMissingField)
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
		id:            id,
		signer:        opts.Signer,
		st:            opts.Storage,
		blobs:         opts.Blobs,
		keys:          opts.Keys,
		rf:            &compact.RangeFactory{Hash: hasher.HashChildren},
		now:           now,
		maxMergeDelay: opts.MaxMergeDelay,
	}, nil
}

// ID returns the identifier of the log.
func (l *Log) ID() core.LogID { return l.id }

// Size returns the current number of leaves.
func (l *Log) Size(ctx context.Context) (uint64, error) { return l.st.Size(ctx) }

// Root returns the root hash over the whole current tree.
func (l *Log) Root(ctx context.Context) (core.Digest, error) {
	size, err := l.st.Size(ctx)
	if err != nil {
		return core.Digest{}, err
	}
	return l.RootAt(ctx, size)
}

// RootAt returns the root hash over the first size leaves.
//
// This works for sizes long since passed as well, because complete subtrees are
// immutable: whatever was stored once still holds for every later tree size.
func (l *Log) RootAt(ctx context.Context, size uint64) (core.Digest, error) {
	cur, err := l.st.Size(ctx)
	if err != nil {
		return core.Digest{}, err
	}
	if size > cur {
		return core.Digest{}, fmt.Errorf("%w: %d requested, tree has %d", ErrProofSize, size, cur)
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
		return core.Digest{}, fmt.Errorf("owm/log: root over %d leaves: %w", size, err)
	}
	return core.DigestFromBytes(root)
}

// rangeAt loads the compact range [0, size) from storage.
func (l *Log) rangeAt(ctx context.Context, size uint64) (*compact.Range, error) {
	ids := compact.RangeNodes(0, size, nil)
	hashes, err := l.st.Nodes(ctx, ids)
	if err != nil {
		return nil, err
	}
	r, err := l.rf.NewRange(0, size, digestsToBytes(hashes))
	if err != nil {
		return nil, fmt.Errorf("owm/log: range [0,%d): %w", size, err)
	}
	return r, nil
}

// Append checks a signed entry and appends it.
func (l *Log) Append(ctx context.Context, se *core.SignedEntry) (*Leaf, error) {
	if se == nil {
		return nil, fmt.Errorf("%w: entry", ErrMissingField)
	}
	entryBytes, err := se.Encode()
	if err != nil {
		return nil, fmt.Errorf("owm/log: encode entry: %w", err)
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
		return nil, fmt.Errorf("owm/log: append: %w", err)
	}
	if visitErr != nil {
		return nil, fmt.Errorf("owm/log: node hash: %w", visitErr)
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

// AppendWithPayload stores the payload and appends the entry.
//
// The payload is checked against the commitment in the entry beforehand.
// Without that check the node would accept data that does not match its own log
// and that nobody could ever verify.
//
// Order: store the payload first, then append. If the append fails, the payload
// is deleted again. The other way round an entry would remain in the tree in
// the error case whose evidence never arrives — and the tree does not forget.
func (l *Log) AppendWithPayload(ctx context.Context, se *core.SignedEntry, salt core.Salt, payload []byte) (*Leaf, error) {
	if l.blobs == nil {
		return nil, ErrNoBlobStore
	}
	if se == nil {
		return nil, fmt.Errorf("%w: entry", ErrMissingField)
	}
	e, err := se.Entry()
	if err != nil {
		return nil, err
	}
	if !core.VerifyCommitment(e.Commitment, salt, payload) {
		return nil, fmt.Errorf("%w: entry %s", ErrCommitment, se.EntryID())
	}
	entryID := se.EntryID()
	if err := l.blobs.Put(ctx, entryID, salt, payload); err != nil {
		return nil, err
	}
	leaf, err := l.Append(ctx, se)
	if err != nil {
		// Clean up so that no payload is left behind without a matching leaf.
		// Such an orphan would be personal data stored invisibly.
		_ = l.blobs.Erase(ctx, entryID)
		return nil, err
	}
	return leaf, nil
}

// checkEntry checks the structure and, if a KeyResolver is set, the signature.
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
		return nil, fmt.Errorf("owm/log: issuer %s: %w", e.Issuer, err)
	}
	if err := se.Verify(pub); err != nil {
		return nil, err
	}
	return e, nil
}

// Leaf returns the leaf at the given position.
func (l *Log) Leaf(ctx context.Context, seq uint64) (*Leaf, error) {
	rec, err := l.st.LeafBySeq(ctx, seq)
	if err != nil {
		return nil, err
	}
	return ParseLeaf(rec.Data)
}

// LeafByEntryID returns the leaf for an entry identifier.
func (l *Log) LeafByEntryID(ctx context.Context, id core.Digest) (*Leaf, error) {
	rec, err := l.st.LeafByEntryID(ctx, id)
	if err != nil {
		return nil, err
	}
	return ParseLeaf(rec.Data)
}

// History returns all leaves for a subject, ascending by position.
func (l *Log) History(ctx context.Context, subject core.SubjectID) ([]*Leaf, error) {
	recs, err := l.st.LeavesBySubject(ctx, subject)
	if err != nil {
		return nil, err
	}
	out := make([]*Leaf, 0, len(recs))
	for i := range recs {
		leaf, err := ParseLeaf(recs[i].Data)
		if err != nil {
			return nil, fmt.Errorf("owm/log: leaf %d: %w", recs[i].Seq, err)
		}
		out = append(out, leaf)
	}
	return out, nil
}

// InclusionProof produces the inclusion proof for the leaf at position seq in a
// tree of size size.
func (l *Log) InclusionProof(ctx context.Context, seq, size uint64) (*InclusionProof, error) {
	cur, err := l.st.Size(ctx)
	if err != nil {
		return nil, err
	}
	if size > cur {
		return nil, fmt.Errorf("%w: %d requested, tree has %d", ErrProofSize, size, cur)
	}
	if seq >= size {
		return nil, fmt.Errorf("%w: leaf %d in a tree of size %d", ErrProofSize, seq, size)
	}
	nodes, err := proof.Inclusion(seq, size)
	if err != nil {
		return nil, fmt.Errorf("owm/log: inclusion proof: %w", err)
	}
	path, err := l.buildPath(ctx, nodes)
	if err != nil {
		return nil, err
	}
	return &InclusionProof{LeafIndex: seq, TreeSize: size, Path: path}, nil
}

// ConsistencyProof produces the consistency proof between two tree sizes.
func (l *Log) ConsistencyProof(ctx context.Context, oldSize, newSize uint64) (*ConsistencyProof, error) {
	cur, err := l.st.Size(ctx)
	if err != nil {
		return nil, err
	}
	if newSize > cur {
		return nil, fmt.Errorf("%w: %d requested, tree has %d", ErrProofSize, newSize, cur)
	}
	if oldSize > newSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrProofSize, oldSize, newSize)
	}
	// The empty tree is a prefix of everything; RFC 6962 has no proof for that.
	if oldSize == 0 || oldSize == newSize {
		return &ConsistencyProof{OldSize: oldSize, NewSize: newSize}, nil
	}
	nodes, err := proof.Consistency(oldSize, newSize)
	if err != nil {
		return nil, fmt.Errorf("owm/log: consistency proof: %w", err)
	}
	path, err := l.buildPath(ctx, nodes)
	if err != nil {
		return nil, err
	}
	return &ConsistencyProof{OldSize: oldSize, NewSize: newSize, Path: path}, nil
}

// buildPath fetches the required nodes and recomputes the ephemeral nodes along
// the right-hand edge of the tree — only complete subtrees are stored.
func (l *Log) buildPath(ctx context.Context, nodes proof.Nodes) ([]core.Digest, error) {
	hashes, err := l.st.Nodes(ctx, nodes.IDs)
	if err != nil {
		return nil, err
	}
	raw, err := nodes.Rehash(digestsToBytes(hashes), hasher.HashChildren)
	if err != nil {
		return nil, fmt.Errorf("owm/log: proof path: %w", err)
	}
	return bytesToDigests(raw)
}

// IssueSTH issues a Signed Tree Head over the current tree and stores it.
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

// LatestSTH returns the most recently issued STH.
func (l *Log) LatestSTH(ctx context.Context) (*SignedSTH, error) { return l.st.LatestSTH(ctx) }

// IssueReceipt issues a signed promise that leaf will be included in a
// witnessed tree — a Signed Tree Head with Size > leaf.Seq — no later than
// MaxMergeDelay after now (OWM-9 A3).
//
// No storage is touched: unlike an STH, a receipt is not something the node
// needs to remember issuing. The submitter holds it, the same way a
// Certificate Transparency client holds its own SCT — presenting it later,
// together with a subsequent STH, is what CheckReceipt is for.
//
// Returns ErrReceiptsDisabled when the log was not configured with a
// positive MaxMergeDelay.
func (l *Log) IssueReceipt(leaf *Leaf) (*SignedReceipt, error) {
	if l.maxMergeDelay <= 0 {
		return nil, ErrReceiptsDisabled
	}
	issuedAt := l.now().UTC().UnixMilli()
	r := &Receipt{
		Version:  FormatVersion,
		Log:      l.id,
		EntryID:  leaf.EntryID(),
		Seq:      leaf.Seq,
		IssuedAt: issuedAt,
		Deadline: issuedAt + l.maxMergeDelay.Milliseconds(),
		Key:      l.signer.Public().ID(),
	}
	return SignReceipt(l.signer, r)
}

// Payload returns the payload of an entry and checks it against the commitment
// in the log.
//
// The check is the whole point: without it the payload would be no more than
// whatever the server happens to hand out.
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
		return nil, fmt.Errorf("%w: entry %s", ErrCommitment, entryID)
	}
	return payload, nil
}

// Erase deletes the payload and salt of an entry and appends an erasure
// witness.
//
// The tree is NOT touched in the process. Exactly that is why all STHs ever
// issued and all proofs ever issued stay valid — including the inclusion proof
// of the erased entry. From the outside an erasure is an ordinary append. See
// OWM-2 §7.
//
// Erasure comes first, the witness second. If the append fails, the data are
// gone anyway and the witness is still missing — the harmless direction. The
// other way round an erasure witness would sit in the log while the data were
// still there, and the log would be lying.
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
	// Without the rotation chain none of the issuer's later signatures could be
	// attributed to anyone any more. A public key is, moreover, not something
	// erasure would protect. OWM-2 §7.6.
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

// BlobStatus reports whether a payload exists for an entry, was never stored,
// or has been erased.
func (l *Log) BlobStatus(ctx context.Context, entryID core.Digest) (BlobStatus, error) {
	if l.blobs == nil {
		return BlobAbsent, ErrNoBlobStore
	}
	return l.blobs.Status(ctx, entryID)
}
