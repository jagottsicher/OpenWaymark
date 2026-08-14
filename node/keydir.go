// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// Errors of the key directory.
var (
	// ErrUnknownKey reports an issuer this node does not know.
	ErrUnknownKey = errors.New("owm/node: unknown key")
	// ErrKeyDisabled reports a disabled key.
	ErrKeyDisabled = errors.New("owm/node: key is disabled")
	// ErrKeyConflict reports an identifier that already points at other bytes.
	ErrKeyConflict = errors.New("owm/node: identifier points at a different key")
)

const keyDirSchema = `
CREATE TABLE IF NOT EXISTS node_keys (
	key_id      BLOB PRIMARY KEY,
	alg         INTEGER NOT NULL,
	public      BLOB    NOT NULL,
	label       TEXT    NOT NULL DEFAULT '',
	added_at    INTEGER NOT NULL,
	disabled_at INTEGER,
	parent      BLOB
) WITHOUT ROWID;
`

// KeyInfo describes one record of the directory.
type KeyInfo struct {
	ID         core.KeyID  `json:"key_id"`
	Alg        core.SigAlg `json:"alg"`
	Label      string      `json:"label,omitempty"`
	AddedAt    int64       `json:"added_at"`
	DisabledAt *int64      `json:"disabled_at,omitempty"`
	Parent     *core.KeyID `json:"parent,omitempty"`
}

// KeyDirectory is a node's key directory.
//
// It answers exactly one question: whose entries does this node accept? That
// makes it the log's admission control — log.Log checks every signature through
// this resolver and turns away everything coming from an unknown issuer.
//
// Only the operator may admit keys, through the admin interface. That is not a
// convenience decision but follows from the federated model: a node is
// authoritative for its own participants and for nobody else. Whoever is not
// listed here has a different node.
type KeyDirectory struct {
	db *sql.DB

	mu    sync.RWMutex
	cache map[core.KeyID]*core.PublicKey
}

var _ owmlog.KeyResolver = (*KeyDirectory)(nil)

// OpenKeyDirectory creates the table if it is missing.
//
// The directory lives in the same database as the log — one file, one backup,
// one state. It does not touch the log's tables.
func OpenKeyDirectory(ctx context.Context, db *sql.DB) (*KeyDirectory, error) {
	if db == nil {
		return nil, errors.New("owm/node: no database")
	}
	if _, err := db.ExecContext(ctx, keyDirSchema); err != nil {
		return nil, fmt.Errorf("owm/node: create key table: %w", err)
	}
	return &KeyDirectory{db: db, cache: make(map[core.KeyID]*core.PublicKey)}, nil
}

// Register admits a public key.
//
// The call is repeatable: if the identifier is already there and points at the
// same bytes, nothing changes. If it points at other bytes, a SHA-256 collision
// would have been found — that is what ErrKeyConflict reports, and then
// something fundamental is wrong.
func (d *KeyDirectory) Register(ctx context.Context, pub *core.PublicKey, label string, parent *core.KeyID) error {
	if pub == nil {
		return fmt.Errorf("%w: key", owmlog.ErrMissingField)
	}
	id := pub.ID()
	var (
		raw      []byte
		disabled sql.NullInt64
	)
	err := d.db.QueryRowContext(ctx,
		`SELECT public, disabled_at FROM node_keys WHERE key_id = ?`, id[:]).Scan(&raw, &disabled)
	switch {
	case err == nil:
		if !bytes.Equal(raw, pub.Bytes()) {
			return fmt.Errorf("%w: %s", ErrKeyConflict, id)
		}
		if disabled.Valid {
			// A disabled key is not quietly armed again on the side. Whoever
			// wants that should do it explicitly.
			return fmt.Errorf("%w: %s", ErrKeyDisabled, id)
		}
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("owm/node: check key: %w", err)
	}

	var parentBlob any
	if parent != nil {
		parentBlob = parent[:]
	}
	if _, err := d.db.ExecContext(ctx,
		`INSERT INTO node_keys (key_id, alg, public, label, added_at, parent)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id[:], int64(pub.Alg()), pub.Bytes(), label, time.Now().UTC().UnixMilli(), parentBlob); err != nil {
		return fmt.Errorf("owm/node: admit key: %w", err)
	}
	d.forget(id)
	return nil
}

// Disable retires a key: no new entries are accepted from it any more.
//
// What it signed earlier stays valid. A log that retroactively invalidates
// statements would be no transparency log — the question "was this signature
// valid at time X?" is answered by the rotation chain, not by striking out an
// entry.
func (d *KeyDirectory) Disable(ctx context.Context, id core.KeyID) error {
	res, err := d.db.ExecContext(ctx,
		`UPDATE node_keys SET disabled_at = ? WHERE key_id = ? AND disabled_at IS NULL`,
		time.Now().UTC().UnixMilli(), id[:])
	if err != nil {
		return fmt.Errorf("owm/node: disable key: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("owm/node: disable key: %w", err)
	}
	d.forget(id)
	if n == 0 {
		// Either unknown or long since disabled. The difference is irrelevant
		// to the caller, the outcome the same.
		if _, err := d.Info(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// PublicKey satisfies log.KeyResolver.
func (d *KeyDirectory) PublicKey(ctx context.Context, id core.KeyID) (*core.PublicKey, error) {
	d.mu.RLock()
	pub, ok := d.cache[id]
	d.mu.RUnlock()
	if ok {
		return pub, nil
	}
	pub, err := d.load(ctx, id)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.cache[id] = pub
	d.mu.Unlock()
	return pub, nil
}

// Lookup returns the public key together with its record — for disabled keys as
// well.
//
// The difference to PublicKey is deliberate and the reason both exist:
// PublicKey answers "may this key submit right now?" and therefore turns a
// disabled one away. Here it is the other question — "what do I check a
// signature with that has long been in the log?". A key disabled today signed
// validly yesterday; were this lookup to conceal it, every older entry would be
// unverifiable.
func (d *KeyDirectory) Lookup(ctx context.Context, id core.KeyID) (*core.PublicKey, KeyInfo, error) {
	var (
		keyID    []byte
		alg      int64
		raw      []byte
		label    string
		added    int64
		disabled sql.NullInt64
		parent   []byte
	)
	err := d.db.QueryRowContext(ctx,
		`SELECT key_id, alg, public, label, added_at, disabled_at, parent
		 FROM node_keys WHERE key_id = ?`, id[:]).
		Scan(&keyID, &alg, &raw, &label, &added, &disabled, &parent)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, KeyInfo{}, fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	if err != nil {
		return nil, KeyInfo{}, fmt.Errorf("owm/node: read key: %w", err)
	}
	pub, err := core.ParsePublicKey(core.SigAlg(alg), raw)
	if err != nil {
		return nil, KeyInfo{}, fmt.Errorf("owm/node: key %s: %w", id, err)
	}
	if pub.ID() != id {
		return nil, KeyInfo{}, fmt.Errorf("%w: %s", ErrKeyConflict, id)
	}
	info := KeyInfo{ID: id, Alg: core.SigAlg(alg), Label: label, AddedAt: added}
	if disabled.Valid {
		v := disabled.Int64
		info.DisabledAt = &v
	}
	if len(parent) > 0 {
		p, err := core.DigestFromBytes(parent)
		if err != nil {
			return nil, KeyInfo{}, fmt.Errorf("owm/node: predecessor key: %w", err)
		}
		k := core.KeyID(p)
		info.Parent = &k
	}
	return pub, info, nil
}

// Info returns the record for an identifier, for disabled keys as well.
func (d *KeyDirectory) Info(ctx context.Context, id core.KeyID) (KeyInfo, error) {
	row := d.db.QueryRowContext(ctx,
		`SELECT key_id, alg, label, added_at, disabled_at, parent FROM node_keys WHERE key_id = ?`, id[:])
	info, err := scanKeyInfo(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyInfo{}, fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	return info, err
}

// List returns every known key, most recently admitted first.
func (d *KeyDirectory) List(ctx context.Context) ([]KeyInfo, error) {
	rows, err := d.db.QueryContext(ctx,
		`SELECT key_id, alg, label, added_at, disabled_at, parent FROM node_keys ORDER BY added_at DESC, key_id`)
	if err != nil {
		return nil, fmt.Errorf("owm/node: list keys: %w", err)
	}
	defer rows.Close()

	var out []KeyInfo
	for rows.Next() {
		info, err := scanKeyInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("owm/node: list keys: %w", err)
	}
	return out, nil
}

// load fetches a key from the database.
func (d *KeyDirectory) load(ctx context.Context, id core.KeyID) (*core.PublicKey, error) {
	var (
		alg      int64
		raw      []byte
		disabled sql.NullInt64
	)
	err := d.db.QueryRowContext(ctx,
		`SELECT alg, public, disabled_at FROM node_keys WHERE key_id = ?`, id[:]).
		Scan(&alg, &raw, &disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	if err != nil {
		return nil, fmt.Errorf("owm/node: read key: %w", err)
	}
	if disabled.Valid {
		return nil, fmt.Errorf("%w: %s", ErrKeyDisabled, id)
	}
	pub, err := core.ParsePublicKey(core.SigAlg(alg), raw)
	if err != nil {
		return nil, fmt.Errorf("owm/node: key %s: %w", id, err)
	}
	if pub.ID() != id {
		// The identifier is the hash of the key. If the two diverge, the
		// database has been tampered with.
		return nil, fmt.Errorf("%w: %s", ErrKeyConflict, id)
	}
	return pub, nil
}

func (d *KeyDirectory) forget(id core.KeyID) {
	d.mu.Lock()
	delete(d.cache, id)
	d.mu.Unlock()
}

// scanner covers both *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

func scanKeyInfo(s scanner) (KeyInfo, error) {
	var (
		id       []byte
		alg      int64
		label    string
		added    int64
		disabled sql.NullInt64
		parent   []byte
	)
	if err := s.Scan(&id, &alg, &label, &added, &disabled, &parent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return KeyInfo{}, err
		}
		return KeyInfo{}, fmt.Errorf("owm/node: read key: %w", err)
	}
	d, err := core.DigestFromBytes(id)
	if err != nil {
		return KeyInfo{}, fmt.Errorf("owm/node: key identifier: %w", err)
	}
	info := KeyInfo{ID: core.KeyID(d), Alg: core.SigAlg(alg), Label: label, AddedAt: added}
	if disabled.Valid {
		v := disabled.Int64
		info.DisabledAt = &v
	}
	if len(parent) > 0 {
		p, err := core.DigestFromBytes(parent)
		if err != nil {
			return KeyInfo{}, fmt.Errorf("owm/node: predecessor key: %w", err)
		}
		k := core.KeyID(p)
		info.Parent = &k
	}
	return info, nil
}
