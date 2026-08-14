// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// maxHistory caps a history response. A subject can carry thousands of
// measurement series; a response delivering all of it at once would be useless
// for a lookup over a phone.
const (
	defaultHistoryLimit = 200
	maxHistoryLimit     = 1000
)

// PublicHandler is the node's public API (OWM-7).
func (n *Node) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openwaymark", n.handleMeta)
	mux.HandleFunc("POST /owm/v1/entries", n.handleSubmit)
	mux.HandleFunc("GET /owm/v1/entries/{id}", n.handleEntry)
	mux.HandleFunc("GET /owm/v1/entries/{id}/payload", n.handlePayload)
	mux.HandleFunc("GET /owm/v1/leaves/{seq}", n.handleLeaf)
	mux.HandleFunc("GET /owm/v1/sth", n.handleSTH)
	mux.HandleFunc("GET /owm/v1/proof/inclusion", n.handleInclusion)
	mux.HandleFunc("GET /owm/v1/proof/consistency", n.handleConsistency)
	mux.HandleFunc("GET /owm/v1/subjects/{id}", n.handleSubject)
	mux.HandleFunc("GET /owm/v1/keys/{id}", n.handlePublicKey)
	mux.HandleFunc("GET /owm/v1/profiles", n.handleProfiles)
	mux.HandleFunc("GET /owm/v1/schema", n.handleSchema)
	return jsonRouterErrors(mux)
}

// submitRequest is the envelope of a submission.
//
// The entry travels as Base64 of the canonical bytes and is passed on by the
// node unchanged. It is not taken in as a JSON object and re-encoded on the
// server: the signature covers exactly these bytes, and every re-encoding would
// be an opportunity to lose it.
type submitRequest struct {
	Entry   []byte   `json:"entry"`
	Salt    hexBytes `json:"salt,omitempty"`
	Payload []byte   `json:"payload,omitempty"`
}

type submitResponse struct {
	Log      core.LogID  `json:"log"`
	EntryID  core.Digest `json:"entry_id"`
	Seq      uint64      `json:"seq"`
	LoggedAt int64       `json:"logged_at"`
	Leaf     []byte      `json:"leaf"`
}

func (n *Node) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Entry) == 0 {
		writeError(w, malformed("entry missing"))
		return
	}
	se, err := core.ParseSignedEntry(req.Entry)
	if err != nil {
		writeError(w, err)
		return
	}
	var salt core.Salt
	if len(req.Payload) > 0 {
		if len(req.Salt) != core.SaltSize {
			writeError(w, malformed("salt: expected %d bytes, got %d", core.SaltSize, len(req.Salt)))
			return
		}
		copy(salt[:], req.Salt)
	}

	leaf, err := n.Submit(r.Context(), se, salt, req.Payload)
	if err != nil {
		writeError(w, err)
		return
	}
	encoded, err := leaf.Encode()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, submitResponse{
		Log:      leaf.Log,
		EntryID:  leaf.EntryID(),
		Seq:      leaf.Seq,
		LoggedAt: leaf.LoggedAt,
		Leaf:     encoded,
	})
}

// leafView is the response to a leaf query.
type leafView struct {
	Log      core.LogID  `json:"log"`
	Seq      uint64      `json:"seq"`
	LoggedAt int64       `json:"logged_at"`
	EntryID  core.Digest `json:"entry_id"`
	Leaf     []byte      `json:"leaf"`
	Entry    []byte      `json:"entry"`
	Payload  string      `json:"payload_status"`
	Decoded  entryView   `json:"decoded"`
}

func (n *Node) viewLeaf(ctx context.Context, leaf *owmlog.Leaf) (leafView, error) {
	encoded, err := leaf.Encode()
	if err != nil {
		return leafView{}, err
	}
	se, err := leaf.SignedEntry()
	if err != nil {
		return leafView{}, err
	}
	e, err := se.Entry()
	if err != nil {
		return leafView{}, err
	}
	entryID := leaf.EntryID()
	status, err := n.log.BlobStatus(ctx, entryID)
	if err != nil {
		return leafView{}, err
	}
	return leafView{
		Log:      leaf.Log,
		Seq:      leaf.Seq,
		LoggedAt: leaf.LoggedAt,
		EntryID:  entryID,
		Leaf:     encoded,
		Entry:    leaf.Entry,
		Payload:  status.String(),
		Decoded:  viewEntry(e),
	}, nil
}

func (n *Node) handleEntry(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	leaf, err := n.log.LeafByEntryID(r.Context(), id)
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := n.viewLeaf(r.Context(), leaf)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (n *Node) handleLeaf(w http.ResponseWriter, r *http.Request) {
	seq, err := parsePathUint(r, "seq")
	if err != nil {
		writeError(w, err)
		return
	}
	leaf, err := n.log.Leaf(r.Context(), seq)
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := n.viewLeaf(r.Context(), leaf)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// payloadResponse delivers payload and salt together.
//
// Without the salt the commitment could not be recomputed, and the payload
// would be no more than what the server currently claims. Whoever has both can
// check — that is the point. After an erasure both are gone and the response is
// 410.
type payloadResponse struct {
	EntryID core.Digest `json:"entry_id"`
	Salt    hexBytes    `json:"salt"`
	Payload []byte      `json:"payload"`
}

func (n *Node) handlePayload(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	// Payload checks the commitment along the way but does not hand out the salt.
	payload, err := n.log.Payload(ctx, id)
	if err != nil {
		writeError(w, err)
		return
	}
	salt, _, err := n.store.Get(ctx, id)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, payloadResponse{EntryID: id, Salt: salt[:], Payload: payload})
}

type sthResponse struct {
	Signed  *owmlog.SignedSTH `json:"signed"`
	Decoded *owmlog.STH       `json:"decoded"`
}

func (n *Node) handleSTH(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	size, err := parseUintQuery(r, "size", 0)
	if err != nil {
		writeError(w, err)
		return
	}
	var signed *owmlog.SignedSTH
	if r.URL.Query().Has("size") {
		signed, err = n.store.STHBySize(ctx, size)
	} else {
		signed, err = n.log.LatestSTH(ctx)
	}
	if err != nil {
		writeError(w, err)
		return
	}
	sth, err := signed.STH()
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sthResponse{Signed: signed, Decoded: sth})
}

// proofSize determines the tree size a proof is issued against.
//
// The default is the size of the most recently issued STH and not the current
// tree size. A proof against a size for which no signature exists cannot be
// checked against anything — the client would have to believe the server, and
// that is precisely what it should not have to do.
func (n *Node) proofSize(ctx context.Context) (uint64, error) {
	signed, err := n.log.LatestSTH(ctx)
	if err == nil {
		sth, err := signed.STH()
		if err == nil {
			return sth.Size, nil
		}
	}
	if err != nil && !errors.Is(err, owmlog.ErrNotFound) {
		return 0, err
	}
	return n.log.Size(ctx)
}

func (n *Node) handleInclusion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	def, err := n.proofSize(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	size, err := parseUintQuery(r, "size", def)
	if err != nil {
		writeError(w, err)
		return
	}

	var seq uint64
	switch {
	case q.Has("entry"):
		id, err := core.ParseDigest(q.Get("entry"))
		if err != nil {
			writeError(w, malformed("entry: %v", err))
			return
		}
		leaf, err := n.log.LeafByEntryID(ctx, id)
		if err != nil {
			writeError(w, err)
			return
		}
		seq = leaf.Seq
	case q.Has("seq"):
		seq, err = parseUintQuery(r, "seq", 0)
		if err != nil {
			writeError(w, err)
			return
		}
	default:
		writeError(w, malformed("entry or seq is required"))
		return
	}

	p, err := n.log.InclusionProof(ctx, seq, size)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (n *Node) handleConsistency(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	oldSize, err := parseUintQuery(r, "old", 0)
	if err != nil {
		writeError(w, err)
		return
	}
	def, err := n.proofSize(ctx)
	if err != nil {
		writeError(w, err)
		return
	}
	newSize, err := parseUintQuery(r, "new", def)
	if err != nil {
		writeError(w, err)
		return
	}
	p, err := n.log.ConsistencyProof(ctx, oldSize, newSize)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

type historyResponse struct {
	Subject core.SubjectID `json:"subject"`
	Log     core.LogID     `json:"log"`
	Total   int            `json:"total"`
	Offset  uint64         `json:"offset"`
	Entries []leafView     `json:"entries"`
}

func (n *Node) handleSubject(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	limit, err := parseUintQuery(r, "limit", defaultHistoryLimit)
	if err != nil {
		writeError(w, err)
		return
	}
	if limit > maxHistoryLimit {
		limit = maxHistoryLimit
	}
	offset, err := parseUintQuery(r, "offset", 0)
	if err != nil {
		writeError(w, err)
		return
	}

	ctx := r.Context()
	leaves, err := n.log.History(ctx, core.SubjectID(id))
	if err != nil {
		writeError(w, err)
		return
	}
	out := historyResponse{
		Subject: core.SubjectID(id),
		Log:     n.log.ID(),
		Total:   len(leaves),
		Offset:  offset,
		Entries: []leafView{},
	}
	for i := offset; i < uint64(len(leaves)) && uint64(len(out.Entries)) < limit; i++ {
		view, err := n.viewLeaf(ctx, leaves[i])
		if err != nil {
			writeError(w, err)
			return
		}
		out.Entries = append(out.Entries, view)
	}
	writeJSON(w, http.StatusOK, out)
}

// publicKeyView is the public information about a key.
//
// Without it a foreign client could not check a single signature: the entry
// names only the issuer's identifier, and that is the hash of the key — the key
// cannot be recovered from it. Whoever receives the key recomputes the
// identifier and does not have to believe the node.
//
// The label from the directory is explicitly not part of it. It is free text
// written by the operator and often carries a name; the public API is no place
// for something like that to show up in passing.
type publicKeyView struct {
	ID         core.KeyID  `json:"key_id"`
	Alg        string      `json:"alg"`
	Public     hexBytes    `json:"public"`
	AddedAt    int64       `json:"added_at"`
	DisabledAt *int64      `json:"disabled_at,omitempty"`
	Parent     *core.KeyID `json:"parent,omitempty"`
}

// handlePublicKey returns a single key, looked up by its identifier.
//
// Singly and by identifier only: a list of all keys would be this node's
// participant directory and thereby the answer to a question nobody asked.
// Whoever looks something up here has the identifier from an entry they already
// have in front of them.
//
// A disabled key is handed out as well, with disabled_at. What it signed
// earlier stays verifiable — otherwise every older entry would be worthless
// after the first key was retired.
func (n *Node) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	pub, info, err := n.keys.Lookup(r.Context(), core.KeyID(id))
	if err != nil {
		if errors.Is(err, ErrUnknownKey) {
			// On a read query an unknown key is not a question of access but
			// simply nothing there.
			writeError(w, fmt.Errorf("%w: key %s", owmlog.ErrNotFound, id))
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, publicKeyView{
		ID:         info.ID,
		Alg:        pub.Alg().String(),
		Public:     pub.Bytes(),
		AddedAt:    info.AddedAt,
		DisabledAt: info.DisabledAt,
		Parent:     info.Parent,
	})
}

type profileView struct {
	ID           string      `json:"id"`
	Title        string      `json:"title,omitempty"`
	SchemaDigest core.Digest `json:"schema_digest"`
	Files        []string    `json:"files"`
}

func (n *Node) profileViews() []profileView {
	all := n.profiles.All()
	out := make([]profileView, 0, len(all))
	for _, p := range all {
		files := p.Files()
		names := make([]string, 0, len(files))
		for _, f := range files {
			names = append(names, f.Name)
		}
		out = append(out, profileView{
			ID:           p.ID(),
			Title:        p.Title(),
			SchemaDigest: p.SchemaDigest(),
			Files:        names,
		})
	}
	return out
}

func (n *Node) handleProfiles(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"profiles": n.profileViews()})
}

// handleSchema returns a single schema file.
//
// Profile and file sit in the query string and not in the path because a
// profile identifier may itself contain slashes ("eu/battery.v1") — in the path
// it would no longer be possible to tell where the identifier ends.
func (n *Node) handleSchema(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p, ok := n.profiles.Get(q.Get("profile"))
	if !ok {
		writeError(w, owmlog.ErrNotFound)
		return
	}
	name := q.Get("file")
	for _, f := range p.Files() {
		if f.Name == name {
			w.Header().Set("Content-Type", "application/schema+json")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Write(f.Data) //nolint:errcheck // see writeJSON
			return
		}
	}
	writeError(w, owmlog.ErrNotFound)
}

type keyView struct {
	Alg    string     `json:"alg"`
	ID     core.KeyID `json:"id"`
	Public hexBytes   `json:"public"`
}

type metaResponse struct {
	Protocol   string        `json:"protocol"`
	Log        core.LogID    `json:"log"`
	BaseURL    string        `json:"base_url,omitempty"`
	Operator   Operator      `json:"operator"`
	Key        keyView       `json:"key"`
	Genesis    keyView       `json:"genesis_key"`
	TreeSize   uint64        `json:"tree_size"`
	Profiles   []profileView `json:"profiles"`
	MaxPayload int64         `json:"max_payload"`
	MaxLeaf    int           `json:"max_leaf"`
	API        string        `json:"api"`
}

// handleMeta describes the node.
//
// This is the federation's entry point: the DNS TXT record points at the node,
// this response says which log it maintains, which key it signs with and who is
// responsible for it.
func (n *Node) handleMeta(w http.ResponseWriter, r *http.Request) {
	size, err := n.log.Size(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	pub := n.identity.Key.Public()
	writeJSON(w, http.StatusOK, metaResponse{
		Protocol:   "OWM/1",
		Log:        n.log.ID(),
		BaseURL:    n.cfg.BaseURL,
		Operator:   n.cfg.Operator,
		Key:        keyView{Alg: pub.Alg().String(), ID: pub.ID(), Public: pub.Bytes()},
		Genesis:    keyView{Alg: n.identity.Genesis.Alg().String(), ID: n.identity.Genesis.ID(), Public: n.identity.Genesis.Bytes()},
		TreeSize:   size,
		Profiles:   n.profileViews(),
		MaxPayload: n.cfg.MaxPayload,
		MaxLeaf:    owmlog.MaxLeafSize,
		API:        "/owm/v1",
	})
}

// Run starts the public API, the admin interface and the automatic STH
// issuance, and runs until ctx ends.
func (n *Node) Run(ctx context.Context) error {
	public := &http.Server{
		Addr:              n.cfg.Listen,
		Handler:           n.PublicHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
	admin := &http.Server{
		Addr:              n.cfg.AdminListen,
		Handler:           n.AdminHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Minute,
		WriteTimeout:      time.Minute,
	}

	errs := make(chan error, 3)
	go func() { errs <- serve(public) }()
	if n.cfg.AdminListen != "" {
		go func() { errs <- serve(admin) }()
	}
	go func() { errs <- n.RunSTH(ctx) }()

	var first error
	select {
	case first = <-errs:
	case <-ctx.Done():
		first = ctx.Err()
	}

	shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	public.Shutdown(shutdown) //nolint:errcheck // We are shutting down anyway.
	admin.Shutdown(shutdown)  //nolint:errcheck
	if errors.Is(first, context.Canceled) {
		return nil
	}
	return first
}

func serve(s *http.Server) error {
	err := s.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
