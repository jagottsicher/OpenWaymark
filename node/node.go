// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package node is the server software of an OpenWaymark node.
//
// A node is authoritative for its own data and for nothing else. It maintains a
// local Merkle log (package log), keeps payloads off-chain, knows its own
// participants through a key directory, and accepts only entries with profiles
// it can check. There is no global state and no consensus — tamper evidence
// arises from signed tree states and their observation from the outside.
//
// How the interfaces are split:
//
//   - The public API reads and accepts entries. It is meant for the world.
//   - The admin interface erases payloads, admits keys and issues STHs. It knows
//     no authentication and therefore belongs on a locally bound address.
//
// That erasure sits there and not in the public API is no convenience: under
// Art. 17 GDPR the request is addressed to the controller, and the controller
// decides on it — not an anonymous call.
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
	"openwaymark.org/owm/profiles/aviation"
	"openwaymark.org/owm/profiles/diamonds"
	"openwaymark.org/owm/profiles/electronics"
	"openwaymark.org/owm/profiles/eu/battery"
	"openwaymark.org/owm/profiles/eudr"
	"openwaymark.org/owm/profiles/food"
	"openwaymark.org/owm/profiles/meddevice"
	"openwaymark.org/owm/profiles/minerals"
	"openwaymark.org/owm/profiles/pharma"
	"openwaymark.org/owm/profiles/seafood"
	"openwaymark.org/owm/profiles/vehicle"
	"openwaymark.org/owm/trust"
)

// Errors that reject a submission.
var (
	// ErrPayloadRequired reports an entry with a commitment but no payload.
	ErrPayloadRequired = errors.New("owm/node: entry carries a commitment but no payload was supplied")
	// ErrPayloadUnexpected reports a payload without a matching commitment.
	ErrPayloadUnexpected = errors.New("owm/node: payload without a commitment in the entry")
	// ErrPayloadTooLarge reports a payload that is too large.
	ErrPayloadTooLarge = errors.New("owm/node: payload too large")
	// ErrNotSubmittable reports an entry type only the node itself may create.
	ErrNotSubmittable = errors.New("owm/node: this entry type is not accepted")
)

// Node ties together log, key directory and profiles.
type Node struct {
	cfg        Config
	identity   *Identity
	store      *sqlite.Store
	log        *owmlog.Log
	keys       *KeyDirectory
	profiles   *profiles.Registry
	trustRoots trust.RootSet
	now        func() time.Time
}

// Open opens database and identity and builds a node ready for operation.
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
	// The node has to know its own key. It signs erasure witnesses with it, and
	// those pass through the same admission control as any foreign entry —
	// without this step it could erase nothing.
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
	roots, err := loadTrustRoots(cfg.TrustRootsFile)
	if err != nil {
		store.Close()
		return nil, err
	}
	return &Node{
		cfg:        cfg,
		identity:   identity,
		store:      store,
		log:        l,
		keys:       keys,
		profiles:   reg,
		trustRoots: roots,
		now:        time.Now,
	}, nil
}

// buildRegistry loads the requested profiles.
func buildRegistry(want []string) (*profiles.Registry, error) {
	available := map[string]func() (*profiles.Profile, error){
		food.ID:        food.New,
		pharma.ID:      pharma.New,
		meddevice.ID:   meddevice.New,
		aviation.ID:    aviation.New,
		vehicle.ID:     vehicle.New,
		electronics.ID: electronics.New,
		minerals.ID:    minerals.New,
		seafood.ID:     seafood.New,
		eudr.ID:        eudr.New,
		diamonds.ID:    diamonds.New,
		battery.ID:     battery.New,
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

// Close closes the database.
func (n *Node) Close() error { return n.store.Close() }

// Log returns the node's log.
func (n *Node) Log() *owmlog.Log { return n.log }

// Keys returns the key directory.
func (n *Node) Keys() *KeyDirectory { return n.keys }

// Profiles returns the loaded profiles.
func (n *Node) Profiles() *profiles.Registry { return n.profiles }

// TrustRoots returns the locally recognised accreditation roots (OWM-6 §8).
func (n *Node) TrustRoots() trust.RootSet { return n.trustRoots }

// TrustSource returns a trust.Source that walks this node's own log —
// what trust.Compute needs to recompute an entity's trust level.
func (n *Node) TrustSource() trust.Source { return &logSource{n: n} }

// Identity returns the node's identity.
func (n *Node) Identity() *Identity { return n.identity }

// Config returns the configuration.
func (n *Node) Config() Config { return n.cfg }

// Submit checks a submitted entry and appends it.
//
// Order of the checks, from cheap to expensive and from structural to
// substantive:
//
//  1. Entry type — erasure witnesses are created by the node itself only.
//  2. Payload size.
//  3. Profile and schema; an attestation payload's shape (OWM-6 §3).
//  4. Signature and issuer (in the log, through the key directory).
//  5. Commitment against payload (in the log).
//
// What gets through here is well formed and attributable. Whether it is true is
// something none of these checks says — no software can (OWM-9, oracle
// problem).
func (n *Node) Submit(ctx context.Context, se *core.SignedEntry, salt core.Salt, payload []byte) (*owmlog.Leaf, error) {
	if se == nil {
		return nil, fmt.Errorf("%w: entry", owmlog.ErrMissingField)
	}
	e, err := se.Entry()
	if err != nil {
		return nil, err
	}
	// An erasure witness is a fact about this node's storage. Accepting one from
	// the outside would mean letting somebody claim that something had been
	// erased here.
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
		if e.Type == core.EntryTypeAttestation {
			if err := checkAttestationPayload(e, payload); err != nil {
				return nil, err
			}
		}
		if err := n.profiles.Check(e, payload); err != nil {
			return nil, err
		}
	} else if e.Profile != "" {
		// Without a payload there is nothing to check, but the profile has to be
		// known — otherwise the node would accept an entry whose rules it does
		// not know.
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
	// An accepted rotation entry stays without effect as long as the successor
	// is not in the directory. Only now, after appending: only what is in the
	// log has a traceable justification.
	if e.Type == core.EntryTypeKeyRotation {
		if err := n.applyRotation(ctx, e, payload); err != nil {
			return leaf, err
		}
	}
	return leaf, nil
}

// Erase deletes payload and salt of an entry and appends the erasure witness.
func (n *Node) Erase(ctx context.Context, entryID core.Digest) (*owmlog.Leaf, error) {
	return n.log.Erase(ctx, entryID)
}

// IssueSTH issues a Signed Tree Head.
func (n *Node) IssueSTH(ctx context.Context) (*owmlog.SignedSTH, error) {
	return n.log.IssueSTH(ctx)
}

// RunSTH issues STHs at a fixed interval until the context ends.
//
// The interval is the upper bound on how long tampering can stay unnoticed:
// what was never signed cannot be pinned down by an observer. On shutdown one
// more is issued so that the last state before going down is witnessed.
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
			// A context of our own: the one passed in has already expired at
			// this point, and without a fresh one the last STH would never
			// come about.
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
