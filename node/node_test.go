// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/profiles"
	"openwaymark.org/owm/profiles/food"
)

// testConfig sets up a node in a throwaway directory.
func testConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.Database = filepath.Join(dir, "owm.sqlite")
	cfg.Identity = filepath.Join(dir, "identity.json")
	cfg.Listen = "127.0.0.1:0"
	cfg.AdminListen = "127.0.0.1:0"
	// No ticker in the test: STHs are issued when the test wants them.
	cfg.STHInterval = 0
	cfg.Operator = Operator{Name: "Test operator", Contact: "mailto:test@example.org"}
	return cfg
}

func newTestNode(t *testing.T) *Node {
	t.Helper()
	n, err := Open(context.Background(), testConfig(t))
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	return n
}

// participant is a participant with a key the node knows.
type participant struct {
	key *core.PrivateKey
}

func newParticipant(t *testing.T, n *Node, alg core.SigAlg, label string) *participant {
	t.Helper()
	k, err := core.GenerateKey(alg)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := n.Keys().Register(context.Background(), k.Public(), label, nil); err != nil {
		t.Fatalf("admit key: %v", err)
	}
	return &participant{key: k}
}

// sign builds a signed entry together with a salt over a payload.
func (p *participant) sign(t *testing.T, typ core.EntryType, subject core.SubjectID, payload string, parents ...core.EntryRef) (*core.SignedEntry, core.Salt, []byte) {
	t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	body := []byte(payload)
	e := &core.Entry{
		Version:    1,
		Type:       typ,
		Profile:    food.ID,
		Subject:    subject,
		Issuer:     p.key.Public().ID(),
		Commitment: core.Commit(salt, body),
		Parents:    parents,
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(p.key, e)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	return se, salt, body
}

func newSubject(t *testing.T) core.SubjectID {
	t.Helper()
	s, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("generate subject: %v", err)
	}
	return s
}

const productionPayload = `{
	"event": "production",
	"time": "2026-08-10T06:30:00+02:00",
	"party": {"name": "Hof Sonnenblick", "gln": "4012345000009"},
	"product": {"gtin": "04012345678901", "name": "Free-range eggs", "lot": "L-2026-0810"},
	"quantity": {"value": 1000, "unit": "H87"}
}`

func TestOpenRegistersOwnKey(t *testing.T) {
	n := newTestNode(t)
	// Without its own key in the directory the node could not append an erasure
	// witness — that one passes through the same admission control.
	info, err := n.Keys().Info(context.Background(), n.Identity().Key.Public().ID())
	if err != nil {
		t.Fatalf("own key missing from the directory: %v", err)
	}
	if info.Label != "node" {
		t.Fatalf("label %q, expected \"node\"", info.Label)
	}
}

func TestSubmitAndErase(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	farm := newParticipant(t, n, core.SigAlgMLDSA65, "farm")
	subject := newSubject(t)

	se, salt, payload := farm.sign(t, core.EntryTypeAssertion, subject, productionPayload)
	leaf, err := n.Submit(ctx, se, salt, payload)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	entryID := leaf.EntryID()

	got, err := n.Log().Payload(ctx, entryID)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatal("payload came back modified")
	}

	// The proof from before the erasure — it has to survive it.
	if _, err := n.IssueSTH(ctx); err != nil {
		t.Fatalf("issue STH: %v", err)
	}
	signed, err := n.Log().LatestSTH(ctx)
	if err != nil {
		t.Fatalf("read STH: %v", err)
	}
	sth, err := signed.STH()
	if err != nil {
		t.Fatalf("unwrap STH: %v", err)
	}
	proof, err := n.Log().InclusionProof(ctx, leaf.Seq, sth.Size)
	if err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}
	leafHash, err := leaf.Hash()
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}

	if _, err := n.Erase(ctx, entryID); err != nil {
		t.Fatalf("erase: %v", err)
	}
	if _, err := n.Log().Payload(ctx, entryID); !errors.Is(err, owmlog.ErrErased) {
		t.Fatalf("after the erasure: %v, expected ErrErased", err)
	}
	if err := proof.Verify(leafHash, sth); err != nil {
		t.Fatalf("the earlier proof no longer holds: %v", err)
	}
}

func TestSubmitRejects(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	farm := newParticipant(t, n, core.SigAlgMLDSA65, "farm")
	subject := newSubject(t)

	t.Run("unknown issuer", func(t *testing.T) {
		stranger := &participant{key: mustKey(t, core.SigAlgMLDSA65)}
		se, salt, payload := stranger.sign(t, core.EntryTypeAssertion, subject, productionPayload)
		_, err := n.Submit(ctx, se, salt, payload)
		if !errors.Is(err, ErrUnknownKey) {
			t.Fatalf("%v, expected ErrUnknownKey", err)
		}
	})

	t.Run("payload does not match the schema", func(t *testing.T) {
		se, salt, payload := farm.sign(t, core.EntryTypeAssertion, subject, `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`)
		_, err := n.Submit(ctx, se, salt, payload)
		if !errors.Is(err, profiles.ErrSchema) {
			t.Fatalf("%v, expected ErrSchema", err)
		}
	})

	t.Run("erasure attestation from outside", func(t *testing.T) {
		// Well formed down to the last field — and still to be turned away: an
		// erasure witness is a statement about this node's storage.
		e := &core.Entry{
			Version: 1,
			Type:    core.EntryTypeErasure,
			Subject: subject,
			Issuer:  farm.key.Public().ID(),
			Target:  &core.EntryRef{Entry: core.Digest{1, 2, 3}},
		}
		e.SetIssuedAt(time.Now())
		se, err := core.SignEntry(farm.key, e)
		if err != nil {
			t.Fatalf("sign entry: %v", err)
		}
		if _, err := n.Submit(ctx, se, core.Salt{}, nil); !errors.Is(err, ErrNotSubmittable) {
			t.Fatalf("%v, expected ErrNotSubmittable", err)
		}
	})

	t.Run("payload too large", func(t *testing.T) {
		n.cfg.MaxPayload = 16
		defer func() { n.cfg.MaxPayload = DefaultMaxPayload }()
		se, salt, payload := farm.sign(t, core.EntryTypeAssertion, subject, productionPayload)
		_, err := n.Submit(ctx, se, salt, payload)
		if !errors.Is(err, ErrPayloadTooLarge) {
			t.Fatalf("%v, expected ErrPayloadTooLarge", err)
		}
	})

	t.Run("commitment without payload", func(t *testing.T) {
		se, _, _ := farm.sign(t, core.EntryTypeAssertion, subject, productionPayload)
		_, err := n.Submit(ctx, se, core.Salt{}, nil)
		if !errors.Is(err, ErrPayloadRequired) {
			t.Fatalf("%v, expected ErrPayloadRequired", err)
		}
	})
}

func mustKey(t *testing.T, alg core.SigAlg) *core.PrivateKey {
	t.Helper()
	k, err := core.GenerateKey(alg)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return k
}

func TestKeyRotation(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	old := newParticipant(t, n, core.SigAlgMLDSA65, "farm")
	next := mustKey(t, core.SigAlgMLDSA65)

	announce := func(subject core.SubjectID, pub *core.PublicKey) error {
		body, err := json.Marshal(RotationPayload{
			Alg:    pub.Alg().String(),
			Public: hex.EncodeToString(pub.Bytes()),
			Label:  "farm (new)",
		})
		if err != nil {
			return err
		}
		salt, err := core.NewSalt()
		if err != nil {
			return err
		}
		e := &core.Entry{
			Version:    1,
			Type:       core.EntryTypeKeyRotation,
			Subject:    subject,
			Issuer:     old.key.Public().ID(),
			Commitment: core.Commit(salt, body),
		}
		e.SetIssuedAt(time.Now())
		se, err := core.SignEntry(old.key, e)
		if err != nil {
			return err
		}
		_, err = n.Submit(ctx, se, salt, body)
		return err
	}

	if err := announce(core.SubjectID(next.Public().ID()), next.Public()); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	info, err := n.Keys().Info(ctx, next.Public().ID())
	if err != nil {
		t.Fatalf("successor missing from the directory: %v", err)
	}
	if info.Parent == nil || *info.Parent != old.key.Public().ID() {
		t.Fatal("the successor does not point at the predecessor")
	}
	// The predecessor stays valid; otherwise every rotation would break operation.
	if _, err := n.Keys().PublicKey(ctx, old.key.Public().ID()); err != nil {
		t.Fatalf("predecessor no longer valid: %v", err)
	}

	t.Run("subject does not match the announced key", func(t *testing.T) {
		other := mustKey(t, core.SigAlgMLDSA44)
		err := announce(newSubject(t), other.Public())
		if !errors.Is(err, ErrRotation) {
			t.Fatalf("%v, expected ErrRotation", err)
		}
	})
}

func TestKeyDirectory(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	k := mustKey(t, core.SigAlgMLDSA44)

	if _, err := n.Keys().PublicKey(ctx, k.Public().ID()); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("%v, expected ErrUnknownKey", err)
	}
	if err := n.Keys().Register(ctx, k.Public(), "sensor", nil); err != nil {
		t.Fatalf("admit: %v", err)
	}
	// Admitting the same bytes again is not an error.
	if err := n.Keys().Register(ctx, k.Public(), "sensor", nil); err != nil {
		t.Fatalf("admit again: %v", err)
	}
	if err := n.Keys().Disable(ctx, k.Public().ID()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := n.Keys().PublicKey(ctx, k.Public().ID()); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("%v, expected ErrKeyDisabled", err)
	}
	// A disabled key is not quietly armed again on the side.
	if err := n.Keys().Register(ctx, k.Public(), "sensor", nil); !errors.Is(err, ErrKeyDisabled) {
		t.Fatalf("%v, expected ErrKeyDisabled", err)
	}
	info, err := n.Keys().Info(ctx, k.Public().ID())
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.DisabledAt == nil {
		t.Fatal("disabled_at missing")
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "identity.json")
	a, err := CreateIdentity(path, core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	b, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if a.Key.Public().ID() != b.Key.Public().ID() {
		t.Fatal("the loaded key is a different one")
	}
	idA, err := a.LogID()
	if err != nil {
		t.Fatalf("LogID: %v", err)
	}
	idB, err := b.LogID()
	if err != nil {
		t.Fatalf("LogID: %v", err)
	}
	if idA != idB {
		t.Fatal("the log ID is not stable")
	}

	if _, err := CreateIdentity(path, core.SigAlgMLDSA65); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("%v, expected ErrIdentityExists - an existing identity must never be overwritten", err)
	}

	// The file contains the seed. World-readable, that would be a silent total loss.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Fatal("a world-readable identity file was accepted")
	}
}

func TestLoadConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"listen":"127.0.0.1:9000","sth_interval":"10s","operator":{"name":"Farm"}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.STHInterval.Duration() != 10*time.Second {
		t.Fatalf("sth_interval = %v", cfg.STHInterval.Duration())
	}
	// Fields that are not named keep the default.
	if cfg.Database != DefaultDatabase {
		t.Fatalf("database = %q", cfg.Database)
	}

	if err := os.WriteFile(path, []byte(`{"listne":"x"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "listne") {
		t.Fatalf("a misspelled field was silently accepted: %v", err)
	}
}

func TestUnknownProfileIsRejected(t *testing.T) {
	cfg := testConfig(t)
	cfg.Profiles = []string{"gems.v1"}
	if _, err := Open(context.Background(), cfg); !errors.Is(err, profiles.ErrUnknown) {
		t.Fatalf("%v, expected ErrUnknown", err)
	}
}
