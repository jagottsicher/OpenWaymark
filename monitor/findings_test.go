// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package monitor

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/gossip"
	owmlog "openwaymark.org/owm/log"
)

func testDigest(t *testing.T, label string) core.Digest {
	t.Helper()
	sum := sha256.Sum256([]byte(label))
	d, err := core.DigestFromBytes(sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func testSignedSTH(t *testing.T, key *core.PrivateKey, logID core.LogID, size uint64, root core.Digest) *owmlog.SignedSTH {
	t.Helper()
	sth := &owmlog.STH{
		Version:  owmlog.FormatVersion,
		Log:      logID,
		Size:     size,
		IssuedAt: time.Now().UnixMilli(),
		Root:     root,
		Key:      key.Public().ID(),
	}
	signed, err := owmlog.SignSTH(key, sth)
	if err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	return signed
}

func TestWriteFinding(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	prev := testSignedSTH(t, key, logID, 5, testDigest(t, "root-a"))
	cur := testSignedSTH(t, key, logID, 5, testDigest(t, "root-b"))

	dir := filepath.Join(t.TempDir(), "findings") // deliberately missing, WriteFinding must create it
	f := gossip.Finding{
		Kind:     gossip.FindingSplitView,
		Log:      logID,
		Previous: prev,
		Current:  cur,
		Err:      owmlog.ErrSplitView,
	}
	path, err := WriteFinding(dir, "some/../weird name", f)
	if err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	if filepath.Dir(path) != dir {
		t.Errorf("finding was not written inside %s: %s", dir, path)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read finding: %v", err)
	}
	var rec findingFile
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decode finding: %v", err)
	}
	if rec.Kind != "split_view" {
		t.Errorf("Kind = %q", rec.Kind)
	}
	if rec.Log != logID.String() {
		t.Errorf("Log = %q", rec.Log)
	}

	// The evidence must be the real, re-verifiable signed STHs — not a
	// summary of them.
	prevBytes, err := base64.StdEncoding.DecodeString(rec.Previous)
	if err != nil {
		t.Fatalf("decode previous: %v", err)
	}
	gotPrev, err := owmlog.ParseSignedSTH(prevBytes)
	if err != nil {
		t.Fatalf("parse previous STH: %v", err)
	}
	if err := gotPrev.Verify(key.Public()); err != nil {
		t.Errorf("the persisted previous STH does not verify: %v", err)
	}
	curBytes, err := base64.StdEncoding.DecodeString(rec.Current)
	if err != nil {
		t.Fatalf("decode current: %v", err)
	}
	gotCur, err := owmlog.ParseSignedSTH(curBytes)
	if err != nil {
		t.Fatalf("parse current STH: %v", err)
	}
	if err := gotCur.Verify(key.Public()); err != nil {
		t.Errorf("the persisted current STH does not verify: %v", err)
	}
	gotPrevSTH, _ := gotPrev.STH()
	gotCurSTH, _ := gotCur.STH()
	if gotPrevSTH.Root == gotCurSTH.Root {
		t.Error("the two persisted STHs have the same root — the whole point was that they differ")
	}
}

// TestFindingsSurviveRestart checks the property the design rests on: once
// written, a finding is never touched again by anything in this package —
// not by WriteFinding writing a second finding, and not by New's directory
// setup on a later run.
func TestFindingsSurviveRestart(t *testing.T) {
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	logID, err := core.DeriveLogID(key.Public())
	if err != nil {
		t.Fatalf("derive log ID: %v", err)
	}
	dir := t.TempDir()
	f := gossip.Finding{
		Kind:     gossip.FindingSplitView,
		Log:      logID,
		Previous: testSignedSTH(t, key, logID, 1, testDigest(t, "a")),
		Current:  testSignedSTH(t, key, logID, 1, testDigest(t, "b")),
		Err:      owmlog.ErrSplitView,
	}
	path, err := WriteFinding(dir, "target", f)
	if err != nil {
		t.Fatalf("WriteFinding: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	// Simulate a restart: a fresh Monitor over the same, now-populated
	// findings directory.
	cfg := DefaultConfig()
	cfg.FindingsDir = dir
	if _, err := New(cfg); err != nil {
		t.Fatalf("New: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("finding did not survive: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the finding's content changed across a restart")
	}
}
