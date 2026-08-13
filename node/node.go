// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package node ist die Serversoftware einer OpenWaymark-Node.
//
// Eine Node ist autoritativ für ihre eigenen Daten und für sonst nichts. Sie
// führt ein lokales Merkle-Log (Paket log), hält die Nutzlasten off-chain, kennt
// ihre eigenen Teilnehmer über ein Schlüsselverzeichnis und nimmt nur Einträge
// mit Profilen an, die sie prüfen kann. Es gibt keinen globalen Zustand und
// keinen Konsens — die Manipulationssicherheit entsteht aus signierten
// Baumzuständen und deren Beobachtung von außen.
//
// Aufteilung der Schnittstellen:
//
//   - Die öffentliche API liest und nimmt Einträge entgegen. Sie ist für die
//     Welt gedacht.
//   - Die Verwaltungsschnittstelle löscht Nutzlasten, nimmt Schlüssel auf und
//     stellt STHs aus. Sie kennt keine Authentifizierung und gehört deshalb an
//     eine lokal gebundene Adresse.
//
// Dass die Löschung dort liegt und nicht in der öffentlichen API, ist keine
// Bequemlichkeit: Nach Art. 17 DSGVO richtet sich das Begehren an die
// Verantwortliche, und die entscheidet darüber — nicht ein anonymer Aufruf.
package node

import (
	"context"
	"errors"
	"fmt"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/log/sqlite"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/food"
)

// Fehler, die eine Einreichung ablehnen.
var (
	// ErrPayloadRequired meldet einen Eintrag mit Commitment, aber ohne Nutzlast.
	ErrPayloadRequired = errors.New("owm/node: entry carries a commitment but no payload was supplied")
	// ErrPayloadUnexpected meldet eine Nutzlast ohne zugehöriges Commitment.
	ErrPayloadUnexpected = errors.New("owm/node: payload without a commitment in the entry")
	// ErrPayloadTooLarge meldet eine zu große Nutzlast.
	ErrPayloadTooLarge = errors.New("owm/node: payload too large")
	// ErrNotSubmittable meldet einen Eintragstyp, den nur die Node selbst
	// erzeugen darf.
	ErrNotSubmittable = errors.New("owm/node: this entry type is not accepted")
)

// Node bündelt Log, Schlüsselverzeichnis und Profile.
type Node struct {
	cfg      Config
	identity *Identity
	store    *sqlite.Store
	log      *owmlog.Log
	keys     *KeyDirectory
	profiles *profiles.Registry
	now      func() time.Time
}

// Open öffnet Datenbank und Identität und baut daraus eine betriebsbereite Node.
func Open(ctx context.Context, cfg Config) (*Node, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	identity, err := LoadOrCreateIdentity(cfg.Identity, core.SigAlgMLDSA65)
	if err != nil {
		return nil, err
	}
	reg, err := buildRegistry(cfg.Profiles)
	if err != nil {
		return nil, err
	}
	store, err := sqlite.Open(ctx, cfg.Database)
	if err != nil {
		return nil, err
	}
	keys, err := OpenKeyDirectory(ctx, store.DB())
	if err != nil {
		store.Close()
		return nil, err
	}
	// Die Node muss ihren eigenen Schlüssel kennen. Sie signiert damit die
	// Löschbezeugungen, und die laufen durch dieselbe Einlasskontrolle wie jeder
	// fremde Eintrag — ohne diesen Schritt könnte sie nichts löschen.
	if err := keys.Register(ctx, identity.Key.Public(), "node", nil); err != nil {
		store.Close()
		return nil, err
	}

	l, err := owmlog.New(owmlog.Options{
		Storage: store,
		Signer:  identity.Key,
		Genesis: identity.Genesis,
		Blobs:   store,
		Keys:    keys,
	})
	if err != nil {
		store.Close()
		return nil, err
	}
	return &Node{
		cfg:      cfg,
		identity: identity,
		store:    store,
		log:      l,
		keys:     keys,
		profiles: reg,
		now:      time.Now,
	}, nil
}

// buildRegistry lädt die verlangten Profile.
func buildRegistry(want []string) (*profiles.Registry, error) {
	available := map[string]func() (*profiles.Profile, error){
		food.ID: food.New,
	}
	reg := profiles.NewRegistry()
	if len(want) == 0 {
		for _, load := range available {
			p, err := load()
			if err != nil {
				return nil, err
			}
			if err := reg.Add(p); err != nil {
				return nil, err
			}
		}
		return reg, nil
	}
	for _, id := range want {
		load, ok := available[id]
		if !ok {
			return nil, fmt.Errorf("%w: %s is not compiled in", profiles.ErrUnknown, id)
		}
		p, err := load()
		if err != nil {
			return nil, err
		}
		if err := reg.Add(p); err != nil {
			return nil, err
		}
	}
	return reg, nil
}

// Close schließt die Datenbank.
func (n *Node) Close() error { return n.store.Close() }

// Log liefert das Log der Node.
func (n *Node) Log() *owmlog.Log { return n.log }

// Keys liefert das Schlüsselverzeichnis.
func (n *Node) Keys() *KeyDirectory { return n.keys }

// Profiles liefert die geladenen Profile.
func (n *Node) Profiles() *profiles.Registry { return n.profiles }

// Identity liefert die Identität der Node.
func (n *Node) Identity() *Identity { return n.identity }

// Config liefert die Konfiguration.
func (n *Node) Config() Config { return n.cfg }

// Submit prüft einen eingereichten Eintrag und hängt ihn an.
//
// Reihenfolge der Prüfungen, von billig nach teuer und von struktureller nach
// inhaltlicher Aussage:
//
//  1. Eintragstyp — Löschbezeugungen erzeugt nur die Node selbst.
//  2. Nutzlastgröße.
//  3. Profil und Schema.
//  4. Signatur und Aussteller (im Log, über das Schlüsselverzeichnis).
//  5. Commitment gegen Nutzlast (im Log).
//
// Was hier durchkommt, ist wohlgeformt und zurechenbar. Ob es wahr ist, sagt
// keine dieser Prüfungen — das kann keine Software (OWM-9, Orakelproblem).
func (n *Node) Submit(ctx context.Context, se *core.SignedEntry, salt core.Salt, payload []byte) (*owmlog.Leaf, error) {
	if se == nil {
		return nil, fmt.Errorf("%w: entry", owmlog.ErrMissingField)
	}
	e, err := se.Entry()
	if err != nil {
		return nil, err
	}
	// Eine Löschbezeugung ist eine Tatsache über den Speicher dieser Node. Sie
	// von außen anzunehmen hieße, jemanden behaupten zu lassen, hier sei etwas
	// gelöscht worden.
	if e.Type == core.EntryTypeErasure {
		return nil, fmt.Errorf("%w: %s", ErrNotSubmittable, e.Type)
	}
	if int64(len(payload)) > n.cfg.MaxPayload {
		return nil, fmt.Errorf("%w: %d bytes, allowed %d", ErrPayloadTooLarge, len(payload), n.cfg.MaxPayload)
	}

	hasCommitment := !e.Commitment.IsZero()
	switch {
	case hasCommitment && len(payload) == 0:
		return nil, ErrPayloadRequired
	case !hasCommitment && len(payload) > 0:
		return nil, ErrPayloadUnexpected
	}

	if hasCommitment {
		if err := n.profiles.Check(e, payload); err != nil {
			return nil, err
		}
	} else if e.Profile != "" {
		// Ohne Nutzlast gibt es nichts zu prüfen, das Profil muss aber bekannt
		// sein — sonst nähme die Node einen Eintrag an, dessen Regeln sie nicht
		// kennt.
		if _, ok := n.profiles.Get(e.Profile); !ok {
			return nil, fmt.Errorf("%w: %s", profiles.ErrUnknown, e.Profile)
		}
	}

	if !hasCommitment {
		return n.log.Append(ctx, se)
	}
	leaf, err := n.log.AppendWithPayload(ctx, se, salt, payload)
	if err != nil {
		return nil, err
	}
	// Ein angenommener Rotationseintrag bleibt wirkungslos, solange der
	// Nachfolger nicht im Verzeichnis steht. Erst jetzt, nach dem Anhängen:
	// Nur was im Log steht, ist nachvollziehbar begründet.
	if e.Type == core.EntryTypeKeyRotation {
		if err := n.applyRotation(ctx, e, payload); err != nil {
			return leaf, err
		}
	}
	return leaf, nil
}

// Erase löscht Nutzlast und Salt eines Eintrags und hängt die Löschbezeugung an.
func (n *Node) Erase(ctx context.Context, entryID core.Digest) (*owmlog.Leaf, error) {
	return n.log.Erase(ctx, entryID)
}

// IssueSTH stellt einen Signed Tree Head aus.
func (n *Node) IssueSTH(ctx context.Context) (*owmlog.SignedSTH, error) {
	return n.log.IssueSTH(ctx)
}

// RunSTH stellt in festem Abstand STHs aus, bis der Kontext endet.
//
// Der Abstand ist die Obergrenze dafür, wie lange eine Manipulation unbemerkt
// bleiben kann: Was nicht unterschrieben wurde, kann ein Beobachter nicht
// festnageln. Beim Beenden wird noch einmal ausgestellt, damit der letzte
// Zustand vor dem Herunterfahren bezeugt ist.
func (n *Node) RunSTH(ctx context.Context) error {
	interval := n.cfg.STHInterval.Duration()
	if interval <= 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Eigener Kontext: der übergebene ist an dieser Stelle bereits
			// abgelaufen, und ohne frischen käme der letzte STH nie zustande.
			last, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			_, err := n.log.IssueSTH(last)
			cancel()
			if err != nil {
				return err
			}
			return ctx.Err()
		case <-t.C:
			if _, err := n.log.IssueSTH(ctx); err != nil {
				return err
			}
		}
	}
}
