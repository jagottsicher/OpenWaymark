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
	ErrNotFound     = errors.New("owm/log: nicht gefunden")
	ErrConflict     = errors.New("owm/log: Baumgröße hat sich zwischenzeitlich geändert")
	ErrErased       = errors.New("owm/log: Nutzlast wurde gelöscht")
	ErrNotErasable  = errors.New("owm/log: dieser Eintragstyp ist nicht löschbar")
	ErrNoBlobStore  = errors.New("owm/log: kein Nutzlastspeicher konfiguriert")
	ErrCommitment   = errors.New("owm/log: Nutzlast passt nicht zum Commitment")
	ErrLeafConflict = errors.New("owm/log: Blatt mit dieser Position existiert bereits")
)

// Node ist ein Knoten des Merkle-Baums.
//
// Level 0 sind die Blätter. Gespeichert werden nur vollständige (perfekte)
// Teilbäume; die unvollständigen Knoten am rechten Rand werden bei Bedarf neu
// gerechnet. Ein einmal vollständiger Knoten ändert sich nie wieder — deshalb
// genügt ein einziger Knotenbestand, um Beweise für jede vergangene Baumgröße
// auszustellen.
type Node struct {
	Level uint
	Index uint64
	Hash  core.Digest
}

// LeafRecord ist ein gespeichertes Blatt samt der Felder, nach denen gesucht
// wird.
//
// EntryID und Subject sind aus Data ableitbar und werden trotzdem mitgeführt:
// Ohne sie müsste für jede Suche jedes Blatt dekodiert werden.
type LeafRecord struct {
	Seq      uint64
	Hash     core.Digest
	EntryID  core.Digest
	Subject  core.SubjectID
	LoggedAt int64
	Data     []byte
}

// Storage hält Blätter, Knoten und STHs.
//
// Die Schnittstelle ist bewusst schmal und kennt keine Transaktionen: Die
// einzige Operation, die atomar sein muss, ist Append, und die trägt ihre
// erwartete Ausgangsgröße selbst mit sich.
type Storage interface {
	// Size liefert die aktuelle Zahl der Blätter.
	Size(ctx context.Context) (uint64, error)

	// Append fügt ein Blatt und die dadurch vervollständigten Knoten atomar
	// hinzu und erhöht die Baumgröße um eins.
	//
	// Weicht die gespeicherte Größe von oldSize ab, MUSS die Implementierung
	// ErrConflict liefern und nichts schreiben. Das ist die einzige
	// Nebenläufigkeitssicherung der Schnittstelle — und sie genügt, weil ein
	// Log nur an einer Stelle wächst.
	Append(ctx context.Context, oldSize uint64, leaf LeafRecord, nodes []Node) error

	// LeafBySeq liefert das Blatt an der angegebenen Position.
	LeafBySeq(ctx context.Context, seq uint64) (*LeafRecord, error)

	// LeafByEntryID liefert das älteste Blatt mit dieser Eintragskennung.
	// Derselbe Eintrag darf mehrfach angehängt worden sein.
	LeafByEntryID(ctx context.Context, id core.Digest) (*LeafRecord, error)

	// LeavesBySubject liefert alle Blätter zu einem Subjekt, nach Position
	// aufsteigend. Das ist die Grundlage der Produkthistorie.
	LeavesBySubject(ctx context.Context, subject core.SubjectID) ([]LeafRecord, error)

	// Nodes liefert die Hashes der angegebenen Knoten in derselben Reihenfolge.
	// Fehlt einer, ist das ErrNotFound.
	Nodes(ctx context.Context, ids []compact.NodeID) ([]core.Digest, error)

	// PutSTH legt einen ausgestellten STH ab.
	//
	// Ein Beobachter braucht alte STHs, um überhaupt vergleichen zu können; ein
	// Log, das nur den jeweils neuesten vorhält, macht sich unüberprüfbar.
	PutSTH(ctx context.Context, size uint64, s *SignedSTH) error

	// LatestSTH liefert den zuletzt ausgestellten STH oder ErrNotFound.
	LatestSTH(ctx context.Context) (*SignedSTH, error)

	// STHBySize liefert einen STH zur angegebenen Baumgröße oder ErrNotFound.
	STHBySize(ctx context.Context, size uint64) (*SignedSTH, error)
}

// BlobStatus beschreibt den Zustand einer Nutzlast.
type BlobStatus int

const (
	// BlobAbsent: zu diesem Eintrag wurde nie eine Nutzlast hinterlegt.
	BlobAbsent BlobStatus = iota
	// BlobPresent: Nutzlast und Salt liegen vor.
	BlobPresent
	// BlobErased: Nutzlast und Salt wurden gelöscht. Der Zustand bleibt
	// dauerhaft nachweisbar — er ist der Unterschied zwischen einer
	// rechtmäßigen Löschung und dem Zurückhalten von Daten (OWM-9 A3).
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

// BlobStore hält die Nutzlasten außerhalb des Logs.
//
// Der Salt liegt beim Blob und wird mit ihm gelöscht. Genau das macht die
// Löschung wirksam: Das Commitment im Log ist HMAC-SHA-256 mit dem Salt als
// Schlüssel — ohne ihn ist der Wert über den Schlüsselraum gleichverteilt und
// selbst ein Wertebereich aus zwei Möglichkeiten nicht mehr aufzulösen.
type BlobStore interface {
	// Put hinterlegt Nutzlast und Salt zu einer Eintragskennung.
	Put(ctx context.Context, entryID core.Digest, salt core.Salt, payload []byte) error

	// Get liefert Nutzlast und Salt, ErrErased nach einer Löschung oder
	// ErrNotFound, wenn nie etwas hinterlegt wurde.
	Get(ctx context.Context, entryID core.Digest) (core.Salt, []byte, error)

	// Erase löscht Nutzlast und Salt unwiederbringlich und vermerkt die
	// Löschung. Ein zweiter Aufruf ist zulässig und ändert nichts.
	Erase(ctx context.Context, entryID core.Digest) error

	// Status meldet den Zustand ohne die Daten zu lesen.
	Status(ctx context.Context, entryID core.Digest) (BlobStatus, error)
}
