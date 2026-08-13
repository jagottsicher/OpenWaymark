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

// Fehler des Schlüsselverzeichnisses.
var (
	// ErrUnknownKey meldet einen Aussteller, den diese Node nicht kennt.
	ErrUnknownKey = errors.New("owm/node: unknown key")
	// ErrKeyDisabled meldet einen stillgelegten Schlüssel.
	ErrKeyDisabled = errors.New("owm/node: key is disabled")
	// ErrKeyConflict meldet eine Kennung, die bereits auf andere Bytes zeigt.
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

// KeyInfo beschreibt einen Eintrag des Verzeichnisses.
type KeyInfo struct {
	ID         core.KeyID  `json:"key_id"`
	Alg        core.SigAlg `json:"alg"`
	Label      string      `json:"label,omitempty"`
	AddedAt    int64       `json:"added_at"`
	DisabledAt *int64      `json:"disabled_at,omitempty"`
	Parent     *core.KeyID `json:"parent,omitempty"`
}

// KeyDirectory ist das Schlüsselverzeichnis einer Node.
//
// Es beantwortet genau eine Frage: Wessen Einträge nimmt diese Node an? Damit
// ist es die Einlasskontrolle des Logs — log.Log prüft jede Signatur über
// diesen Auflöser und weist alles ab, was von einem unbekannten Aussteller
// kommt.
//
// Aufnehmen darf nur die Betreiberin, über die Verwaltungsschnittstelle. Das
// ist keine Bequemlichkeitsentscheidung, sondern folgt aus dem föderierten
// Modell: Eine Node ist autoritativ für ihre eigenen Teilnehmer und für sonst
// niemanden. Wer hier nicht steht, hat eine andere Node.
type KeyDirectory struct {
	db *sql.DB

	mu    sync.RWMutex
	cache map[core.KeyID]*core.PublicKey
}

var _ owmlog.KeyResolver = (*KeyDirectory)(nil)

// OpenKeyDirectory legt die Tabelle an, falls sie fehlt.
//
// Das Verzeichnis liegt in derselben Datenbank wie das Log — eine Datei, ein
// Backup, ein Zustand. Die Tabellen des Logs fasst es nicht an.
func OpenKeyDirectory(ctx context.Context, db *sql.DB) (*KeyDirectory, error) {
	if db == nil {
		return nil, errors.New("owm/node: no database")
	}
	if _, err := db.ExecContext(ctx, keyDirSchema); err != nil {
		return nil, fmt.Errorf("owm/node: create key table: %w", err)
	}
	return &KeyDirectory{db: db, cache: make(map[core.KeyID]*core.PublicKey)}, nil
}

// Register nimmt einen öffentlichen Schlüssel auf.
//
// Der Aufruf ist wiederholbar: Ist die Kennung schon da und zeigt auf dieselben
// Bytes, ändert sich nichts. Zeigt sie auf andere Bytes, wäre eine
// SHA-256-Kollision gefunden — das meldet ErrKeyConflict, und dann stimmt etwas
// Grundlegendes nicht.
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
			// Ein stillgelegter Schlüssel wird nicht nebenbei wieder scharf
			// geschaltet. Wer das will, soll es ausdrücklich tun.
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

// Disable legt einen Schlüssel still: Von ihm werden keine neuen Einträge mehr
// angenommen.
//
// Was er früher signiert hat, bleibt gültig. Ein Log, das rückwirkend Aussagen
// entwertet, wäre kein Transparenzlog — die Frage "war diese Signatur zum
// Zeitpunkt X gültig?" beantwortet die Rotationskette, nicht das Streichen
// eines Eintrags.
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
		// Entweder unbekannt oder längst stillgelegt. Der Unterschied ist für
		// den Aufrufer belanglos, das Ergebnis dasselbe.
		if _, err := d.Info(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// PublicKey erfüllt log.KeyResolver.
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

// Lookup liefert den öffentlichen Schlüssel samt Angaben — auch für
// stillgelegte Schlüssel.
//
// Der Unterschied zu PublicKey ist Absicht und der Grund, warum es beide gibt:
// PublicKey beantwortet "darf dieser Schlüssel gerade einreichen?" und lehnt
// einen stillgelegten deshalb ab. Hier geht es um die andere Frage — "womit
// prüfe ich eine Signatur, die längst im Log steht?". Ein Schlüssel, der heute
// stillgelegt ist, hat gestern gültig unterschrieben; würde diese Auskunft ihn
// verschweigen, wäre jeder ältere Eintrag unprüfbar.
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

// Info liefert die Angaben zu einer Kennung, auch für stillgelegte Schlüssel.
func (d *KeyDirectory) Info(ctx context.Context, id core.KeyID) (KeyInfo, error) {
	row := d.db.QueryRowContext(ctx,
		`SELECT key_id, alg, label, added_at, disabled_at, parent FROM node_keys WHERE key_id = ?`, id[:])
	info, err := scanKeyInfo(row)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyInfo{}, fmt.Errorf("%w: %s", ErrUnknownKey, id)
	}
	return info, err
}

// List liefert alle bekannten Schlüssel, zuletzt aufgenommene zuerst.
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

// load holt einen Schlüssel aus der Datenbank.
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
		// Die Kennung ist der Hash des Schlüssels. Weichen sie voneinander ab,
		// wurde die Datenbank angefasst.
		return nil, fmt.Errorf("%w: %s", ErrKeyConflict, id)
	}
	return pub, nil
}

func (d *KeyDirectory) forget(id core.KeyID) {
	d.mu.Lock()
	delete(d.cache, id)
	d.mu.Unlock()
}

// scanner fasst *sql.Row und *sql.Rows zusammen.
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
