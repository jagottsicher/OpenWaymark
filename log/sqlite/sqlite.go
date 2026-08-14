// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package sqlite keeps an OpenWaymark log permanently in a SQLite file.
//
// The driver is modernc.org/sqlite, a pure Go translation without cgo. That is
// not a matter of taste: it is the only way to build node binaries for ARM
// without setting up a cross toolchain — and without a node on Raspberry Pi
// class hardware the federated model of OWM-0 §3.1 collapses.
//
// The package is deliberately separate from package log: log is meant to stay
// compilable to WASM (OWM-9 A11), and an embedded SQLite has no business in a
// consumer's browser.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/transparency-dev/merkle/compact"
	_ "modernc.org/sqlite" // driver "sqlite"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// schema is deliberately kept narrow.
//
// Nodes live in a table of their own and are never modified: only what
// completes a full subtree is stored, and that is settled for all time. Exactly
// that is why a single set of nodes suffices for proofs over every past tree
// size — without this property one would need a separate copy per tree size.
const schema = `
CREATE TABLE IF NOT EXISTS leaves (
	seq       INTEGER PRIMARY KEY,
	hash      BLOB    NOT NULL,
	entry_id  BLOB    NOT NULL,
	subject   BLOB    NOT NULL,
	logged_at INTEGER NOT NULL,
	data      BLOB    NOT NULL
);
CREATE INDEX IF NOT EXISTS leaves_by_entry   ON leaves (entry_id, seq);
CREATE INDEX IF NOT EXISTS leaves_by_subject ON leaves (subject, seq);

CREATE TABLE IF NOT EXISTS nodes (
	level INTEGER NOT NULL,
	idx   INTEGER NOT NULL,
	hash  BLOB    NOT NULL,
	PRIMARY KEY (level, idx)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS sths (
	size      INTEGER PRIMARY KEY,
	issued_at INTEGER NOT NULL,
	data      BLOB    NOT NULL
);

CREATE TABLE IF NOT EXISTS blobs (
	entry_id  BLOB PRIMARY KEY,
	salt      BLOB,
	payload   BLOB,
	erased    INTEGER NOT NULL DEFAULT 0,
	erased_at INTEGER
) WITHOUT ROWID;
`

// pragmas are set when connecting.
//
// secure_delete is the most important entry: without it SQLite merely marks
// freed pages as available and leaves the old content sitting in the file. An
// erasure under Art. 17 GDPR would then be none. For the limits that remain,
// see the note on BlobStore.Erase.
var pragmas = []string{
	"journal_mode(WAL)",
	"synchronous(NORMAL)",
	"busy_timeout(5000)",
	"secure_delete(ON)",
	"foreign_keys(ON)",
}

// Store implements log.Storage and log.BlobStore on top of a SQLite file.
type Store struct {
	db *sql.DB
}

var (
	_ owmlog.Storage   = (*Store)(nil)
	_ owmlog.BlobStore = (*Store)(nil)
)

// Open opens or creates the database at path and installs the schema.
//
// For a pure in-memory test database, ":memory:" suffices.
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: open: %w", err)
	}
	// SQLite serialises writes anyway. A single connection saves the waiting
	// on one another and keeps ":memory:" alive for the lifetime of the store
	// — otherwise the database would vanish with the connection.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("owm/log/sqlite: connect: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("owm/log/sqlite: create schema: %w", err)
	}
	return &Store{db: db}, nil
}

// dsn builds the connection string including pragmas.
//
// _txlock=immediate makes every transaction take the write lock straight away.
// Without it Append starts out reading and has to upgrade later — and that is
// precisely where the classic SQLITE_BUSY deadlock between two writers arises.
func dsn(path string) string {
	if path == ":memory:" {
		path = "file::memory:"
	} else if !strings.HasPrefix(path, "file:") {
		path = "file:" + path
	}
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	q.Set("_txlock", "immediate")
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + q.Encode()
}

// DB hands out the underlying connection, for backups for instance.
func (s *Store) DB() *sql.DB { return s.db }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Size returns the number of leaves.
//
// Positions run without gaps from 0, so the largest position plus one is the
// size — and thanks to the primary key index it is available immediately.
func (s *Store) Size(ctx context.Context) (uint64, error) {
	var size int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq) + 1, 0) FROM leaves`).Scan(&size)
	if err != nil {
		return 0, fmt.Errorf("owm/log/sqlite: size: %w", err)
	}
	return uint64(size), nil
}

// Append adds leaf and nodes in one transaction.
func (s *Store) Append(ctx context.Context, oldSize uint64, leaf owmlog.LeafRecord, nodes []owmlog.Node) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var size int64
	if err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq) + 1, 0) FROM leaves`).Scan(&size); err != nil {
		return fmt.Errorf("owm/log/sqlite: size: %w", err)
	}
	if uint64(size) != oldSize {
		err = fmt.Errorf("%w: expected %d, stored %d", owmlog.ErrConflict, oldSize, size)
		return err
	}
	if leaf.Seq != oldSize {
		err = fmt.Errorf("%w: seq=%d, expected %d", owmlog.ErrLeafConflict, leaf.Seq, oldSize)
		return err
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO leaves (seq, hash, entry_id, subject, logged_at, data)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		int64(leaf.Seq), leaf.Hash[:], leaf.EntryID[:], leaf.Subject[:],
		leaf.LoggedAt, leaf.Data); err != nil {
		return fmt.Errorf("owm/log/sqlite: write leaf: %w", err)
	}

	// Nodes are inserted without OR REPLACE. A conflict would mean a complete
	// subtree was computed a second time and came out different — that would
	// not be an edge case but a broken tree.
	for _, n := range nodes {
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO nodes (level, idx, hash) VALUES (?, ?, ?)`,
			int64(n.Level), int64(n.Index), n.Hash[:]); err != nil {
			return fmt.Errorf("owm/log/sqlite: node (%d,%d): %w", n.Level, n.Index, err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("owm/log/sqlite: commit: %w", err)
	}
	return nil
}

const leafColumns = `seq, hash, entry_id, subject, logged_at, data`

func scanLeaf(row interface{ Scan(...any) error }) (*owmlog.LeafRecord, error) {
	var (
		seq                    int64
		hash, entryID, subject []byte
		loggedAt               int64
		data                   []byte
	)
	if err := row.Scan(&seq, &hash, &entryID, &subject, &loggedAt, &data); err != nil {
		return nil, err
	}
	rec := &owmlog.LeafRecord{Seq: uint64(seq), LoggedAt: loggedAt, Data: data}
	var err error
	if rec.Hash, err = core.DigestFromBytes(hash); err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: leaf hash: %w", err)
	}
	if rec.EntryID, err = core.DigestFromBytes(entryID); err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: entry ID: %w", err)
	}
	d, err := core.DigestFromBytes(subject)
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: subject: %w", err)
	}
	rec.Subject = core.SubjectID(d)
	return rec, nil
}

func (s *Store) LeafBySeq(ctx context.Context, seq uint64) (*owmlog.LeafRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+leafColumns+` FROM leaves WHERE seq = ?`, int64(seq))
	rec, err := scanLeaf(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: leaf %d", owmlog.ErrNotFound, seq)
	}
	return rec, err
}

func (s *Store) LeafByEntryID(ctx context.Context, id core.Digest) (*owmlog.LeafRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+leafColumns+` FROM leaves WHERE entry_id = ? ORDER BY seq LIMIT 1`, id[:])
	rec, err := scanLeaf(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: entry %s", owmlog.ErrNotFound, id)
	}
	return rec, err
}

func (s *Store) LeavesBySubject(ctx context.Context, subject core.SubjectID) ([]owmlog.LeafRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+leafColumns+` FROM leaves WHERE subject = ? ORDER BY seq`, subject[:])
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: subject lookup: %w", err)
	}
	defer rows.Close()

	var out []owmlog.LeafRecord
	for rows.Next() {
		rec, err := scanLeaf(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: subject lookup: %w", err)
	}
	return out, nil
}

func (s *Store) Nodes(ctx context.Context, ids []compact.NodeID) ([]core.Digest, error) {
	out := make([]core.Digest, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	stmt, err := s.db.PrepareContext(ctx,
		`SELECT hash FROM nodes WHERE level = ? AND idx = ?`)
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: node query: %w", err)
	}
	defer stmt.Close()

	for i, id := range ids {
		var hash []byte
		err := stmt.QueryRowContext(ctx, int64(id.Level), int64(id.Index)).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: node (%d,%d)", owmlog.ErrNotFound, id.Level, id.Index)
		}
		if err != nil {
			return nil, fmt.Errorf("owm/log/sqlite: node (%d,%d): %w", id.Level, id.Index, err)
		}
		if out[i], err = core.DigestFromBytes(hash); err != nil {
			return nil, fmt.Errorf("owm/log/sqlite: node (%d,%d): %w", id.Level, id.Index, err)
		}
	}
	return out, nil
}

// PutSTH stores an STH.
//
// An STH already present for the same size is NOT overwritten. Two different
// STHs for the same size are the split-view finding par excellence (OWM-2 §9)
// — one's own database is the last place where it should quietly disappear.
func (s *Store) PutSTH(ctx context.Context, size uint64, sth *owmlog.SignedSTH) error {
	blob, err := sth.Encode()
	if err != nil {
		return err
	}
	parsed, err := sth.STH()
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO sths (size, issued_at, data) VALUES (?, ?, ?)
		 ON CONFLICT (size) DO NOTHING`,
		int64(size), parsed.IssuedAt, blob)
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: write STH: %w", err)
	}
	return nil
}

func (s *Store) LatestSTH(ctx context.Context) (*owmlog.SignedSTH, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM sths ORDER BY size DESC, issued_at DESC LIMIT 1`).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: no STH issued yet", owmlog.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: read STH: %w", err)
	}
	return owmlog.ParseSignedSTH(blob)
}

func (s *Store) STHBySize(ctx context.Context, size uint64) (*owmlog.SignedSTH, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM sths WHERE size = ?`, int64(size)).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: STH over %d leaves", owmlog.ErrNotFound, size)
	}
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: read STH: %w", err)
	}
	return owmlog.ParseSignedSTH(blob)
}

// STHSizes returns the sizes of all stored STHs, ascending.
func (s *Store) STHSizes(ctx context.Context) ([]uint64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT size FROM sths ORDER BY size`)
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: STH sizes: %w", err)
	}
	defer rows.Close()
	var out []uint64
	for rows.Next() {
		var size int64
		if err := rows.Scan(&size); err != nil {
			return nil, err
		}
		out = append(out, uint64(size))
	}
	return out, rows.Err()
}

// Put stores payload and salt.
func (s *Store) Put(ctx context.Context, entryID core.Digest, salt core.Salt, payload []byte) error {
	var erased int64
	err := s.db.QueryRowContext(ctx,
		`SELECT erased FROM blobs WHERE entry_id = ?`, entryID[:]).Scan(&erased)
	switch {
	case err == nil && erased != 0:
		// See log.MemBlobStore.Put: accepting an erased payload again would
		// mean taking the erasure back.
		return fmt.Errorf("%w: %s", owmlog.ErrErased, entryID)
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("owm/log/sqlite: check payload: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO blobs (entry_id, salt, payload, erased) VALUES (?, ?, ?, 0)
		 ON CONFLICT (entry_id) DO UPDATE SET salt = excluded.salt, payload = excluded.payload`,
		entryID[:], salt[:], payload)
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: write payload: %w", err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, entryID core.Digest) (core.Salt, []byte, error) {
	var (
		salt, payload []byte
		erased        int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT salt, payload, erased FROM blobs WHERE entry_id = ?`,
		entryID[:]).Scan(&salt, &payload, &erased)
	if errors.Is(err, sql.ErrNoRows) {
		return core.Salt{}, nil, fmt.Errorf("%w: payload for %s", owmlog.ErrNotFound, entryID)
	}
	if err != nil {
		return core.Salt{}, nil, fmt.Errorf("owm/log/sqlite: read payload: %w", err)
	}
	if erased != 0 {
		return core.Salt{}, nil, fmt.Errorf("%w: %s", owmlog.ErrErased, entryID)
	}
	if len(salt) != core.SaltSize {
		return core.Salt{}, nil, fmt.Errorf("owm/log/sqlite: salt has %d bytes, expected %d",
			len(salt), core.SaltSize)
	}
	var out core.Salt
	copy(out[:], salt)
	return out, payload, nil
}

// Erase deletes payload and salt and records the erasure.
//
// Honest about the limits: secure_delete (see pragmas) overwrites the freed
// pages in the database file. What it does NOT reach are copies outside of it:
// WAL files from earlier sessions, file system snapshots, backups, and the
// block remanence of SSDs. A complete erasure additionally requires a retention
// policy for backups — that is an operational question, not a code one, and
// OWM-2 §7.7 therefore says so there as well.
func (s *Store) Erase(ctx context.Context, entryID core.Digest) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE blobs SET salt = NULL, payload = NULL, erased = 1,
		        erased_at = unixepoch('subsec') * 1000
		 WHERE entry_id = ?`, entryID[:])
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: delete: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: delete: %w", err)
	}
	if n > 0 {
		return nil
	}
	// Nothing stored: the tombstone is set all the same, so that nothing can
	// be supplied after the fact.
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO blobs (entry_id, salt, payload, erased, erased_at)
		 VALUES (?, NULL, NULL, 1, unixepoch('subsec') * 1000)
		 ON CONFLICT (entry_id) DO NOTHING`, entryID[:])
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: set tombstone: %w", err)
	}
	return nil
}

func (s *Store) Status(ctx context.Context, entryID core.Digest) (owmlog.BlobStatus, error) {
	var erased int64
	err := s.db.QueryRowContext(ctx,
		`SELECT erased FROM blobs WHERE entry_id = ?`, entryID[:]).Scan(&erased)
	if errors.Is(err, sql.ErrNoRows) {
		return owmlog.BlobAbsent, nil
	}
	if err != nil {
		return owmlog.BlobAbsent, fmt.Errorf("owm/log/sqlite: status: %w", err)
	}
	if erased != 0 {
		return owmlog.BlobErased, nil
	}
	return owmlog.BlobPresent, nil
}
