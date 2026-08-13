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

// maxHistory begrenzt eine Historieantwort. Ein Subjekt kann tausende
// Messreihen tragen; eine Antwort, die alles auf einmal liefert, wäre für den
// Abruf per Telefon unbrauchbar.
const (
	defaultHistoryLimit = 200
	maxHistoryLimit     = 1000
)

// PublicHandler ist die öffentliche API der Node (OWM-7).
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

// submitRequest ist der Umschlag einer Einreichung.
//
// Der Eintrag wird als Base64 der kanonischen Bytes übertragen und von der Node
// unverändert weitergereicht. Er wird nicht als JSON-Objekt entgegengenommen und
// serverseitig neu kodiert: Die Signatur gilt für genau diese Bytes, und jede
// Neukodierung wäre eine Gelegenheit, sie zu verlieren.
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

// leafView ist die Antwort auf eine Blattabfrage.
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

// payloadResponse liefert Nutzlast und Salt zusammen.
//
// Ohne den Salt ließe sich das Commitment nicht nachrechnen, und die Nutzlast
// wäre nur das, was der Server gerade behauptet. Wer beides hat, kann prüfen —
// das ist der Sinn. Nach einer Löschung ist beides fort, und die Antwort ist
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
	// Payload prüft das Commitment mit, liefert aber den Salt nicht heraus.
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

// proofSize bestimmt die Baumgröße, gegen die ein Beweis ausgestellt wird.
//
// Voreinstellung ist die Größe des zuletzt ausgestellten STH und nicht die
// aktuelle Baumgröße. Ein Beweis gegen eine Größe, zu der es keine Unterschrift
// gibt, ist gegen nichts prüfbar — der Client müsste dem Server glauben, und
// genau das soll er nicht müssen.
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

// publicKeyView ist die öffentliche Auskunft über einen Schlüssel.
//
// Ohne sie könnte ein fremder Client keine einzige Signatur prüfen: Der Eintrag
// nennt nur die Kennung des Ausstellers, und die ist der Hash des Schlüssels —
// aus ihr lässt sich der Schlüssel nicht zurückgewinnen. Wer den Schlüssel
// bekommt, prüft die Kennung selbst nach und braucht der Node nicht zu glauben.
//
// Das Etikett aus dem Verzeichnis steht ausdrücklich nicht darin. Es ist
// Freitext der Betreiberin und trägt oft einen Namen; die öffentliche API ist
// kein Ort, an dem so etwas nebenbei erscheint.
type publicKeyView struct {
	ID         core.KeyID  `json:"key_id"`
	Alg        string      `json:"alg"`
	Public     hexBytes    `json:"public"`
	AddedAt    int64       `json:"added_at"`
	DisabledAt *int64      `json:"disabled_at,omitempty"`
	Parent     *core.KeyID `json:"parent,omitempty"`
}

// handlePublicKey liefert einen einzelnen Schlüssel, nachgeschlagen über seine
// Kennung.
//
// Nur einzeln und nur über die Kennung: Eine Liste aller Schlüssel wäre das
// Teilnehmerverzeichnis dieser Node und damit die Antwort auf eine Frage, die
// niemand gestellt hat. Wer hier nachschlägt, hat die Kennung aus einem
// Eintrag, den er ohnehin schon vor sich hat.
//
// Auch ein stillgelegter Schlüssel wird herausgegeben, mit disabled_at. Was er
// früher unterschrieben hat, bleibt prüfbar — sonst wäre jeder ältere Eintrag
// nach der ersten Stilllegung wertlos.
func (n *Node) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	pub, info, err := n.keys.Lookup(r.Context(), core.KeyID(id))
	if err != nil {
		if errors.Is(err, ErrUnknownKey) {
			// Auf einer Leseabfrage ist ein unbekannter Schlüssel keine
			// Zugangsfrage, sondern schlicht nichts da.
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

// handleSchema liefert eine einzelne Schemadatei.
//
// Profil und Datei stehen in der Abfrage und nicht im Pfad, weil eine
// Profilkennung selbst Schrägstriche enthalten darf ("eu/battery.v1") — im Pfad
// wäre nicht mehr zu erkennen, wo die Kennung endet.
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
			w.Write(f.Data) //nolint:errcheck // siehe writeJSON
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

// handleMeta beschreibt die Node.
//
// Das ist der Einstiegspunkt der Föderation: Der DNS-TXT-Eintrag verweist auf
// die Node, diese Antwort sagt, welches Log sie führt, mit welchem Schlüssel sie
// unterschreibt und wer für sie verantwortlich ist.
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

// Run startet die öffentliche API, die Verwaltungsschnittstelle und die
// selbsttätige STH-Ausgabe und läuft, bis ctx endet.
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
	public.Shutdown(shutdown) //nolint:errcheck // Wir beenden ohnehin.
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
