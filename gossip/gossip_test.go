// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package gossip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// testDigest derives a reproducible, distinct digest from a label — a
// stand-in root hash where the tests don't need a real Merkle tree behind it.
func testDigest(label string) core.Digest {
	sum := sha256.Sum256([]byte(label))
	d, err := core.DigestFromBytes(sum[:])
	if err != nil {
		panic(err) // unreachable: sum is always DigestSize bytes
	}
	return d
}

// buildSTH constructs and signs an STH directly, without a real tree — Client
// and Watch only care about the wire contract (OWM-5 §3.4), not how the root
// was produced.
func buildSTH(t *testing.T, key *core.PrivateKey, logID core.LogID, size uint64, root core.Digest, issuedAt time.Time) *owmlog.SignedSTH {
	t.Helper()
	sth := &owmlog.STH{
		Version:  owmlog.FormatVersion,
		Log:      logID,
		Size:     size,
		IssuedAt: issuedAt.UnixMilli(),
		Root:     root,
		Key:      key.Public().ID(),
	}
	signed, err := owmlog.SignSTH(key, sth)
	if err != nil {
		t.Fatalf("SignSTH: %v", err)
	}
	return signed
}

// fakeKeyResponse mirrors node/server.go's publicKeyView closely enough for
// these tests: an explicit hex string for Public, since gossip's own
// keyResponse type only implements UnmarshalJSON, not the reverse.
type fakeKeyResponse struct {
	Alg    string `json:"alg"`
	Public string `json:"public"`
}

// fakeNode serves just enough of a node's public API for gossip tests: STH,
// key lookup and consistency proof. STHs are queued explicitly by the test,
// one per request, so a poll sequence (STH #1, then STH #2, ...) is under
// the test's direct control.
type fakeNode struct {
	srv *httptest.Server

	mu          sync.Mutex
	sths        []sthOutcome
	sthCalls    int
	keys        map[core.KeyID]*core.PublicKey
	keyOverride *core.PublicKey // when set, every key lookup answers with this key regardless of the requested ID
	proof       *owmlog.ConsistencyProof
	proofErr    bool
}

type sthOutcome struct {
	signed *owmlog.SignedSTH
	fail   bool
}

func newFakeNode(t *testing.T) *fakeNode {
	t.Helper()
	n := &fakeNode{keys: make(map[core.KeyID]*core.PublicKey)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /owm/v1/sth", n.handleSTH)
	mux.HandleFunc("GET /owm/v1/keys/{id}", n.handleKey)
	mux.HandleFunc("GET /owm/v1/proof/consistency", n.handleConsistency)
	n.srv = httptest.NewServer(mux)
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNode) client() *Client { return NewClient(n.srv.URL) }

func (n *fakeNode) addKey(pub *core.PublicKey) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.keys[pub.ID()] = pub
}

// forceKeyMismatch makes every key lookup answer with pub's bytes, regardless
// of the identifier requested — simulating a server (buggy or malicious)
// that hands back the wrong key.
func (n *fakeNode) forceKeyMismatch(pub *core.PublicKey) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.keyOverride = pub
}

func (n *fakeNode) queueSTH(signed *owmlog.SignedSTH) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sths = append(n.sths, sthOutcome{signed: signed})
}

func (n *fakeNode) queueSTHFailure() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sths = append(n.sths, sthOutcome{fail: true})
}

func (n *fakeNode) setProof(p *owmlog.ConsistencyProof) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.proof, n.proofErr = p, false
}

func (n *fakeNode) setProofUnavailable() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.proof, n.proofErr = nil, true
}

func (n *fakeNode) handleSTH(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	var out sthOutcome
	switch {
	case n.sthCalls < len(n.sths):
		out = n.sths[n.sthCalls]
	case len(n.sths) > 0:
		out = n.sths[len(n.sths)-1] // the last queued outcome repeats
	}
	n.sthCalls++
	n.mu.Unlock()

	if out.fail || out.signed == nil {
		http.Error(w, `{"error":"sth unavailable"}`, http.StatusInternalServerError)
		return
	}
	writeJSONBody(w, sthResponse{Signed: out.signed})
}

func (n *fakeNode) handleKey(w http.ResponseWriter, r *http.Request) {
	requested := r.PathValue("id")

	n.mu.Lock()
	override := n.keyOverride
	n.mu.Unlock()
	if override != nil {
		writeJSONBody(w, fakeKeyResponse{Alg: override.Alg().String(), Public: hex.EncodeToString(override.Bytes())})
		return
	}

	id, err := core.ParseDigest(requested)
	if err != nil {
		http.Error(w, `{"error":"bad id"}`, http.StatusBadRequest)
		return
	}
	n.mu.Lock()
	pub, ok := n.keys[core.KeyID(id)]
	n.mu.Unlock()
	if !ok {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	writeJSONBody(w, fakeKeyResponse{Alg: pub.Alg().String(), Public: hex.EncodeToString(pub.Bytes())})
}

func (n *fakeNode) handleConsistency(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	proof, unavailable := n.proof, n.proofErr
	n.mu.Unlock()
	if unavailable {
		http.Error(w, `{"error":"not_found"}`, http.StatusNotFound)
		return
	}
	if proof == nil {
		http.Error(w, `{"error":"no proof configured"}`, http.StatusInternalServerError)
		return
	}
	writeJSONBody(w, proof)
}

func writeJSONBody(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(fmt.Sprintf("gossip test fixture: encode response: %v", err))
	}
}

// testLog is a real, small Merkle log (in-memory storage) for the one test
// that needs a genuinely valid consistency proof — every other test hand-
// crafts STHs directly, since Client and Watch don't care how a root was
// produced.
type testLog struct {
	t     *testing.T
	key   *core.PrivateKey
	log   *owmlog.Log
	clock int64
}

func newTestLog(t *testing.T) *testLog {
	t.Helper()
	key, err := core.GenerateKey(core.SigAlgMLDSA65)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	lg, err := owmlog.New(owmlog.Options{
		Storage: owmlog.NewMemStorage(),
		Signer:  key,
		Blobs:   owmlog.NewMemBlobStore(),
	})
	if err != nil {
		t.Fatalf("create log: %v", err)
	}
	return &testLog{t: t, key: key, log: lg, clock: time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC).UnixMilli()}
}

func (l *testLog) now() time.Time {
	l.clock++
	return time.UnixMilli(l.clock).UTC()
}

func (l *testLog) appendOne() {
	l.t.Helper()
	subject, err := core.NewSubjectID()
	if err != nil {
		l.t.Fatalf("subject: %v", err)
	}
	salt, err := core.NewSalt()
	if err != nil {
		l.t.Fatalf("salt: %v", err)
	}
	payload := []byte("payload")
	ent := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "test",
		Subject:    subject,
		IssuedAt:   l.now().UnixMilli(),
		Issuer:     l.key.Public().ID(),
		Commitment: core.Commit(salt, payload),
	}
	se, err := core.SignEntry(l.key, ent)
	if err != nil {
		l.t.Fatalf("sign entry: %v", err)
	}
	if _, err := l.log.AppendWithPayload(context.Background(), se, salt, payload); err != nil {
		l.t.Fatalf("append: %v", err)
	}
}

func (l *testLog) issueSTH() *owmlog.SignedSTH {
	l.t.Helper()
	signed, err := l.log.IssueSTH(context.Background())
	if err != nil {
		l.t.Fatalf("issue STH: %v", err)
	}
	return signed
}
