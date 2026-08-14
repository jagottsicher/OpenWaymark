// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"net/http"

	"openwaymark.org/owm/core"
)

// AdminHandler is the node's admin interface.
//
// It knows no authentication. That is deliberate and not an omission: access
// control belongs to the environment here — a locally bound address, a Unix
// socket behind a reverse proxy, a VPN. A home-grown token scheme in application
// code would be weaker than what the operating system and a grown-up proxy can
// do anyway, and it would pretend the question had been settled.
//
// Whoever reaches this interface can add keys and erase payloads. It does not
// belong on the open network.
func (n *Node) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /admin/v1/keys", n.handleListKeys)
	mux.HandleFunc("POST /admin/v1/keys", n.handleAddKey)
	mux.HandleFunc("GET /admin/v1/keys/{id}", n.handleKey)
	mux.HandleFunc("POST /admin/v1/keys/{id}/disable", n.handleDisableKey)
	mux.HandleFunc("POST /admin/v1/erasures", n.handleErase)
	mux.HandleFunc("POST /admin/v1/sth", n.handleIssueSTH)
	return jsonRouterErrors(mux)
}

// keyInfoView is KeyInfo with the algorithm name spelled out.
type keyInfoView struct {
	ID         core.KeyID  `json:"key_id"`
	Alg        string      `json:"alg"`
	Label      string      `json:"label,omitempty"`
	AddedAt    int64       `json:"added_at"`
	DisabledAt *int64      `json:"disabled_at,omitempty"`
	Parent     *core.KeyID `json:"parent,omitempty"`
}

func viewKey(i KeyInfo) keyInfoView {
	return keyInfoView{
		ID:         i.ID,
		Alg:        i.Alg.String(),
		Label:      i.Label,
		AddedAt:    i.AddedAt,
		DisabledAt: i.DisabledAt,
		Parent:     i.Parent,
	}
}

func (n *Node) handleListKeys(w http.ResponseWriter, r *http.Request) {
	infos, err := n.keys.List(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]keyInfoView, 0, len(infos))
	for _, i := range infos {
		out = append(out, viewKey(i))
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": out})
}

func (n *Node) handleKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	info, err := n.keys.Info(r.Context(), core.KeyID(id))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewKey(info))
}

// addKeyRequest takes in a public key.
//
// The key sits hex-encoded in the public field, the algorithm spelled out next
// to it. The two are checked against each other: a length that does not match
// the named algorithm is rejected rather than guessed at.
type addKeyRequest struct {
	Alg    string      `json:"alg"`
	Public hexBytes    `json:"public"`
	Label  string      `json:"label,omitempty"`
	Parent *core.KeyID `json:"parent,omitempty"`
}

func (n *Node) handleAddKey(w http.ResponseWriter, r *http.Request) {
	var req addKeyRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	alg, err := ParseSigAlg(req.Alg)
	if err != nil {
		writeError(w, malformed("alg: %v", err))
		return
	}
	pub, err := core.ParsePublicKey(alg, req.Public)
	if err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	if err := n.keys.Register(ctx, pub, req.Label, req.Parent); err != nil {
		writeError(w, err)
		return
	}
	info, err := n.keys.Info(ctx, pub.ID())
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, viewKey(info))
}

func (n *Node) handleDisableKey(w http.ResponseWriter, r *http.Request) {
	id, err := parseDigestParam(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	ctx := r.Context()
	if err := n.keys.Disable(ctx, core.KeyID(id)); err != nil {
		writeError(w, err)
		return
	}
	info, err := n.keys.Info(ctx, core.KeyID(id))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, viewKey(info))
}

// eraseRequest names the entry whose payload is to disappear.
type eraseRequest struct {
	EntryID core.Digest `json:"entry_id"`
}

// handleErase deletes payload and salt and appends the erasure witness.
//
// What disappears is the plaintext together with the salt. What remains is the
// leaf in the tree — and with it every STH and inclusion proof ever issued stays
// valid. That is precisely what makes Art. 17 GDPR and tamper evidence
// compatible with each other (OWM-2 §7).
//
// The operation is final. Without the salt the payload cannot be recovered from
// the commitment even for a tiny range of possible values.
func (n *Node) handleErase(w http.ResponseWriter, r *http.Request) {
	var req eraseRequest
	if err := decodeBody(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.EntryID.IsZero() {
		writeError(w, malformed("entry_id missing"))
		return
	}
	ctx := r.Context()
	leaf, err := n.Erase(ctx, req.EntryID)
	if err != nil {
		writeError(w, err)
		return
	}
	view, err := n.viewLeaf(ctx, leaf)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"erased":    req.EntryID,
		"tombstone": view,
	})
}

func (n *Node) handleIssueSTH(w http.ResponseWriter, r *http.Request) {
	signed, err := n.IssueSTH(r.Context())
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
