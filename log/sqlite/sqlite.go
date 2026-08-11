// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package sqlite hält ein OpenWaymark-Log dauerhaft in einer SQLite-Datei.
//
// Der Treiber ist modernc.org/sqlite, eine reine Go-Übersetzung ohne cgo. Das
// ist keine Geschmacksfrage: Nur so lassen sich Node-Binaries für ARM bauen,
// ohne eine Cross-Toolchain aufzusetzen — und ohne Node auf Raspberry-Pi-Klasse
// bricht das föderierte Modell aus OWM-0 §3.1 in sich zusammen.
//
// Das Paket ist bewusst vom Paket log getrennt: log soll auch nach WASM
// übersetzbar bleiben (OWM-9 A10), und ein eingebettetes SQLite hat im Browser
// des Verbrauchers nichts verloren.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/transparency-dev/merkle/compact"
	_ "modernc.org/sqlite" // Treiber "sqlite"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// schema ist bewusst schmal gehalten.
//
// Knoten stehen in einer eigenen Tabelle und werden nie geändert: Gespeichert
// wird nur, was einen vollständigen Teilbaum abschließt, und das steht für alle
// Zeit fest. Genau deshalb genügt ein einziger Knotenbestand für Beweise über
// jede vergangene Baumgröße — ohne diese Eigenschaft bräuchte man pro
// Baumgröße eine eigene Kopie.
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

// pragmas werden beim Verbinden gesetzt.
//
// secure_delete ist der wichtigste Eintrag: Ohne ihn markiert SQLite gelöschte
// Seiten nur als frei und lässt den alten Inhalt in der Datei stehen. Eine
// Löschung nach Art. 17 DSGVO wäre dann keine. Zu den verbleibenden Grenzen
// siehe die Anmerkung bei BlobStore.Erase.
var pragmas = []string{
	"journal_mode(WAL)",
	"synchronous(NORMAL)",
	"busy_timeout(5000)",
	"secure_delete(ON)",
	"foreign_keys(ON)",
}

// Store implementiert log.Storage und log.BlobStore über eine SQLite-Datei.
type Store struct {
	db *sql.DB
}

var (
	_ owmlog.Storage   = (*Store)(nil)
	_ owmlog.BlobStore = (*Store)(nil)
)

// Open öffnet oder erzeugt die Datenbank unter path und legt das Schema an.
//
// Für eine reine Testdatenbank im Arbeitsspeicher genügt ":memory:".
func Open(ctx context.Context, path string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: öffnen: %w", err)
	}
	// SQLite serialisiert Schreibvorgänge ohnehin. Eine einzige Verbindung
	// erspart das Aufeinanderwarten und hält ":memory:" über die Lebensdauer
	// des Stores am Leben — sonst verschwände die Datenbank mit der Verbindung.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("owm/log/sqlite: verbinden: %w", err)
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("owm/log/sqlite: Schema anlegen: %w", err)
	}
	return &Store{db: db}, nil
}

// dsn baut den Verbindungsstring samt Pragmas.
//
// _txlock=immediate lässt jede Transaktion die Schreibsperre sofort nehmen.
// Ohne das beginnt Append lesend und muss später hochstufen — und genau dabei
// entsteht der klassische SQLITE_BUSY-Deadlock zwischen zwei Schreibern.
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

// DB gibt die zugrundeliegende Verbindung heraus, etwa für Sicherungen.
func (s *Store) DB() *sql.DB { return s.db }

// Close schließt die Datenbank.
func (s *Store) Close() error { return s.db.Close() }

// Size liefert die Zahl der Blätter.
//
// Die Positionen sind lückenlos ab 0, deshalb ist die größte Position plus eins
// die Größe — und die steht dank Primärschlüsselindex sofort bereit.
func (s *Store) Size(ctx context.Context) (uint64, error) {
	var size int64
	err := s.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq) + 1, 0) FROM leaves`).Scan(&size)
	if err != nil {
		return 0, fmt.Errorf("owm/log/sqlite: Größe: %w", err)
	}
	return uint64(size), nil
}

// Append fügt Blatt und Knoten in einer Transaktion hinzu.
func (s *Store) Append(ctx context.Context, oldSize uint64, leaf owmlog.LeafRecord, nodes []owmlog.Node) (err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: Transaktion: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var size int64
	if err = tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(seq) + 1, 0) FROM leaves`).Scan(&size); err != nil {
		return fmt.Errorf("owm/log/sqlite: Größe: %w", err)
	}
	if uint64(size) != oldSize {
		err = fmt.Errorf("%w: erwartet %d, gespeichert %d", owmlog.ErrConflict, oldSize, size)
		return err
	}
	if leaf.Seq != oldSize {
		err = fmt.Errorf("%w: seq=%d, erwartet %d", owmlog.ErrLeafConflict, leaf.Seq, oldSize)
		return err
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO leaves (seq, hash, entry_id, subject, logged_at, data)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		int64(leaf.Seq), leaf.Hash[:], leaf.EntryID[:], leaf.Subject[:],
		leaf.LoggedAt, leaf.Data); err != nil {
		return fmt.Errorf("owm/log/sqlite: Blatt schreiben: %w", err)
	}

	// Knoten werden ohne OR REPLACE eingefügt. Ein Konflikt hieße, dass ein
	// vollständiger Teilbaum ein zweites Mal berechnet wurde und dabei anders
	// ausfiel — das wäre kein Randfall, sondern ein defekter Baum.
	for _, n := range nodes {
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO nodes (level, idx, hash) VALUES (?, ?, ?)`,
			int64(n.Level), int64(n.Index), n.Hash[:]); err != nil {
			return fmt.Errorf("owm/log/sqlite: Knoten (%d,%d): %w", n.Level, n.Index, err)
		}
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("owm/log/sqlite: festschreiben: %w", err)
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
		return nil, fmt.Errorf("owm/log/sqlite: Blatthash: %w", err)
	}
	if rec.EntryID, err = core.DigestFromBytes(entryID); err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: Eintragskennung: %w", err)
	}
	d, err := core.DigestFromBytes(subject)
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: Subjekt: %w", err)
	}
	rec.Subject = core.SubjectID(d)
	return rec, nil
}

func (s *Store) LeafBySeq(ctx context.Context, seq uint64) (*owmlog.LeafRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+leafColumns+` FROM leaves WHERE seq = ?`, int64(seq))
	rec, err := scanLeaf(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: Blatt %d", owmlog.ErrNotFound, seq)
	}
	return rec, err
}

func (s *Store) LeafByEntryID(ctx context.Context, id core.Digest) (*owmlog.LeafRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+leafColumns+` FROM leaves WHERE entry_id = ? ORDER BY seq LIMIT 1`, id[:])
	rec, err := scanLeaf(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: Eintrag %s", owmlog.ErrNotFound, id)
	}
	return rec, err
}

func (s *Store) LeavesBySubject(ctx context.Context, subject core.SubjectID) ([]owmlog.LeafRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+leafColumns+` FROM leaves WHERE subject = ? ORDER BY seq`, subject[:])
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: Subjektsuche: %w", err)
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
		return nil, fmt.Errorf("owm/log/sqlite: Subjektsuche: %w", err)
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
		return nil, fmt.Errorf("owm/log/sqlite: Knotenabfrage: %w", err)
	}
	defer stmt.Close()

	for i, id := range ids {
		var hash []byte
		err := stmt.QueryRowContext(ctx, int64(id.Level), int64(id.Index)).Scan(&hash)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: Knoten (%d,%d)", owmlog.ErrNotFound, id.Level, id.Index)
		}
		if err != nil {
			return nil, fmt.Errorf("owm/log/sqlite: Knoten (%d,%d): %w", id.Level, id.Index, err)
		}
		if out[i], err = core.DigestFromBytes(hash); err != nil {
			return nil, fmt.Errorf("owm/log/sqlite: Knoten (%d,%d): %w", id.Level, id.Index, err)
		}
	}
	return out, nil
}

// PutSTH legt einen STH ab.
//
// Ein bereits vorhandener STH derselben Größe wird NICHT überschrieben. Zwei
// verschiedene STHs zur selben Größe sind der Split-View-Befund schlechthin
// (OWM-2 §9) — die eigene Datenbank ist der letzte Ort, an dem er stillschweigend
// verschwinden sollte.
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
		return fmt.Errorf("owm/log/sqlite: STH schreiben: %w", err)
	}
	return nil
}

func (s *Store) LatestSTH(ctx context.Context) (*owmlog.SignedSTH, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM sths ORDER BY size DESC, issued_at DESC LIMIT 1`).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: noch kein STH ausgestellt", owmlog.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: STH lesen: %w", err)
	}
	return owmlog.ParseSignedSTH(blob)
}

func (s *Store) STHBySize(ctx context.Context, size uint64) (*owmlog.SignedSTH, error) {
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM sths WHERE size = ?`, int64(size)).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: STH über %d Blätter", owmlog.ErrNotFound, size)
	}
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: STH lesen: %w", err)
	}
	return owmlog.ParseSignedSTH(blob)
}

// STHSizes liefert die Größen aller abgelegten STHs, aufsteigend.
func (s *Store) STHSizes(ctx context.Context) ([]uint64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT size FROM sths ORDER BY size`)
	if err != nil {
		return nil, fmt.Errorf("owm/log/sqlite: STH-Größen: %w", err)
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

// Put hinterlegt Nutzlast und Salt.
func (s *Store) Put(ctx context.Context, entryID core.Digest, salt core.Salt, payload []byte) error {
	var erased int64
	err := s.db.QueryRowContext(ctx,
		`SELECT erased FROM blobs WHERE entry_id = ?`, entryID[:]).Scan(&erased)
	switch {
	case err == nil && erased != 0:
		// Siehe log.MemBlobStore.Put: Eine gelöschte Nutzlast wieder
		// anzunehmen hieße, die Löschung zurückzunehmen.
		return fmt.Errorf("%w: %s", owmlog.ErrErased, entryID)
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return fmt.Errorf("owm/log/sqlite: Nutzlast prüfen: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO blobs (entry_id, salt, payload, erased) VALUES (?, ?, ?, 0)
		 ON CONFLICT (entry_id) DO UPDATE SET salt = excluded.salt, payload = excluded.payload`,
		entryID[:], salt[:], payload)
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: Nutzlast schreiben: %w", err)
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
		return core.Salt{}, nil, fmt.Errorf("%w: Nutzlast zu %s", owmlog.ErrNotFound, entryID)
	}
	if err != nil {
		return core.Salt{}, nil, fmt.Errorf("owm/log/sqlite: Nutzlast lesen: %w", err)
	}
	if erased != 0 {
		return core.Salt{}, nil, fmt.Errorf("%w: %s", owmlog.ErrErased, entryID)
	}
	if len(salt) != core.SaltSize {
		return core.Salt{}, nil, fmt.Errorf("owm/log/sqlite: Salt hat %d Byte, erwartet %d",
			len(salt), core.SaltSize)
	}
	var out core.Salt
	copy(out[:], salt)
	return out, payload, nil
}

// Erase löscht Nutzlast und Salt und vermerkt die Löschung.
//
// Ehrlich zu den Grenzen: secure_delete (siehe pragmas) überschreibt die
// freigegebenen Seiten in der Datenbankdatei. Was es NICHT erreicht, sind
// Kopien außerhalb: WAL-Dateien früherer Sitzungen, Dateisystem-Snapshots,
// Sicherungen und die Blockremanenz von SSDs. Eine vollständige Löschung
// verlangt zusätzlich eine Aufbewahrungsfrist für Sicherungen — das ist eine
// Betriebs-, keine Codefrage, und OWM-2 §7.7 sagt es deshalb auch dort.
func (s *Store) Erase(ctx context.Context, entryID core.Digest) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE blobs SET salt = NULL, payload = NULL, erased = 1,
		        erased_at = unixepoch('subsec') * 1000
		 WHERE entry_id = ?`, entryID[:])
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: löschen: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: löschen: %w", err)
	}
	if n > 0 {
		return nil
	}
	// Nichts hinterlegt: Der Grabstein wird trotzdem gesetzt, damit später
	// nichts mehr nachgereicht werden kann.
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO blobs (entry_id, salt, payload, erased, erased_at)
		 VALUES (?, NULL, NULL, 1, unixepoch('subsec') * 1000)
		 ON CONFLICT (entry_id) DO NOTHING`, entryID[:])
	if err != nil {
		return fmt.Errorf("owm/log/sqlite: Grabstein setzen: %w", err)
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
		return owmlog.BlobAbsent, fmt.Errorf("owm/log/sqlite: Status: %w", err)
	}
	if erased != 0 {
		return owmlog.BlobErased, nil
	}
	return owmlog.BlobPresent, nil
}
