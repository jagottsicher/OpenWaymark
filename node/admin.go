// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"net/http"

	"openwaymark.org/owm/core"
)

// AdminHandler ist die Verwaltungsschnittstelle der Node.
//
// Sie kennt keine Authentifizierung. Das ist Absicht und keine Auslassung:
// Zugangsschutz gehört an dieser Stelle in die Umgebung — eine lokal gebundene
// Adresse, ein Unix-Socket hinter einem Reverse-Proxy, ein VPN. Ein selbst
// gestricktes Token-Verfahren im Anwendungscode wäre schwächer als das, was das
// Betriebssystem und ein ausgewachsener Proxy ohnehin können, und würde
// vortäuschen, die Frage sei geklärt.
//
// Wer diese Schnittstelle erreicht, kann Schlüssel aufnehmen und Nutzlasten
// löschen. Sie gehört nicht ins offene Netz.
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

// keyInfoView ist KeyInfo mit ausgeschriebenem Algorithmusnamen.
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

// addKeyRequest nimmt einen öffentlichen Schlüssel auf.
//
// Der Schlüssel steht hexkodiert im Feld public, der Algorithmus ausgeschrieben
// daneben. Beides wird gegeneinander geprüft: Eine Länge, die nicht zum
// genannten Verfahren passt, wird abgelehnt, statt sie zu erraten.
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

// eraseRequest benennt den Eintrag, dessen Nutzlast verschwinden soll.
type eraseRequest struct {
	EntryID core.Digest `json:"entry_id"`
}

// handleErase löscht Nutzlast und Salt und hängt die Löschbezeugung an.
//
// Was verschwindet, ist der Klartext samt Salt. Was bleibt, ist das Blatt im
// Baum — und damit gelten alle je ausgestellten STHs und Inklusionsbeweise
// weiter. Genau das macht Art. 17 DSGVO und Manipulationssicherheit
// miteinander vereinbar (OWM-2 §7).
//
// Der Vorgang ist endgültig. Ohne Salt ist die Nutzlast auch bei winzigem
// Wertebereich nicht mehr aus dem Commitment zurückzurechnen.
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
