// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/profiles/food"
)

// api ist ein knapper Testclient für die HTTP-Schnittstellen.
type api struct {
	t      *testing.T
	public string
	admin  string
}

func newAPI(t *testing.T, n *Node) *api {
	t.Helper()
	pub := httptest.NewServer(n.PublicHandler())
	adm := httptest.NewServer(n.AdminHandler())
	t.Cleanup(pub.Close)
	t.Cleanup(adm.Close)
	return &api{t: t, public: pub.URL, admin: adm.URL}
}

// call schickt eine Anfrage und dekodiert die Antwort, falls out gesetzt ist.
func (a *api) call(method, url string, body, out any) int {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			a.t.Fatalf("encode request: %v", err)
		}
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		a.t.Fatalf("build request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", method, url, err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		a.t.Fatalf("read response: %v", err)
	}
	// Jede Antwort dieser API ist JSON — auch die des Routers.
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") &&
		!strings.HasPrefix(ct, "application/schema+json") {
		a.t.Fatalf("%s %s: Content-Type %q", method, url, ct)
	}
	if out != nil && res.StatusCode < 400 {
		if err := json.Unmarshal(raw, out); err != nil {
			a.t.Fatalf("%s %s: decode response: %v\n%s", method, url, err, raw)
		}
	}
	return res.StatusCode
}

func (a *api) get(path string, out any) int { return a.call(http.MethodGet, a.public+path, nil, out) }
func (a *api) post(path string, body, out any) int {
	return a.call(http.MethodPost, a.public+path, body, out)
}
func (a *api) adminPost(path string, body, out any) int {
	return a.call(http.MethodPost, a.admin+path, body, out)
}
func (a *api) adminGet(path string, out any) int {
	return a.call(http.MethodGet, a.admin+path, nil, out)
}

func (a *api) mustGet(path string, out any) {
	a.t.Helper()
	if code := a.get(path, out); code != http.StatusOK {
		a.t.Fatalf("GET %s: %d", path, code)
	}
}

// submit reicht einen signierten Eintrag über die öffentliche API ein.
func (a *api) submit(se *core.SignedEntry, salt core.Salt, payload []byte) submitResponse {
	a.t.Helper()
	encoded, err := se.Encode()
	if err != nil {
		a.t.Fatalf("encode entry: %v", err)
	}
	req := submitRequest{Entry: encoded}
	if len(payload) > 0 {
		req.Salt = salt[:]
		req.Payload = payload
	}
	var out submitResponse
	if code := a.post("/owm/v1/entries", req, &out); code != http.StatusCreated {
		a.t.Fatalf("submit: %d", code)
	}
	return out
}

// Die Ereignisse einer durchgehenden Lebensmittelkette, in der Reihenfolge, in
// der sie anfallen. Zusammen sind sie der Beleg, dass sich eine reale Kette mit
// dem Profil food.v1 abbilden lässt — Erzeugung, Zusammenfassung, Transport mit
// Kühlkettenmessung, Verarbeitung, Übergabe.
const (
	evProduction = `{
		"event": "production",
		"time": "2026-08-10T06:30:00+02:00",
		"party": {"name": "Hof Sonnenblick", "gln": "4012345000009"},
		"location": {"country": "DE", "geo": {"lat": 52.5, "lon": 13.4}},
		"product": {"name": "Raw milk", "lot": "RM-2026-0810"},
		"quantity": {"value": 1000, "unit": "LTR"},
		"certifications": [{"scheme": "EU-Bio", "id": "DE-ÖKO-006", "valid_until": "2027-03-31"}]
	}`
	evTransport = `{
		"event": "transport",
		"time": "2026-08-10T11:15:00+02:00",
		"step": "departure",
		"carrier": {"name": "Kühlspedition Nord"},
		"from": {"gln": "4012345000009"},
		"to": {"gln": "4012345000016"},
		"consignment": "CNSG-77123",
		"conditions": {"temperature_c": {"min": 2, "max": 8}}
	}`
	evMeasurement = `{
		"event": "measurement",
		"time": "2026-08-10T11:15:00+02:00",
		"sensor": {"id": "kuehl-77", "model": "TempLog 3"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [
			{"t": "2026-08-10T11:15:00+02:00", "v": 4.2},
			{"t": "2026-08-10T12:15:00+02:00", "v": 4.6},
			{"t": "2026-08-10T13:15:00+02:00", "v": 5.1}
		]
	}`
	evHandover = `{
		"event": "handover",
		"time": "2026-08-11T14:00:00+02:00",
		"from": {"name": "Molkerei Tal"},
		"to": {"name": "Großhandel Mitte", "gln": "4012345000023"},
		"transaction": {"type": "desadv", "id": "DE-2026-99812"}
	}`
)

// TestSupplyChainEndToEnd führt eine vollständige Kette über die HTTP-API und
// prüft am Ende, was das Protokoll verspricht: Die Historie ist abrufbar, jeder
// Eintrag ist gegen einen unterschriebenen Baumzustand beweisbar, und eine
// Löschung nimmt die Nutzlast, ohne einen einzigen Beweis zu entwerten.
func TestSupplyChainEndToEnd(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)

	farm := newParticipant(t, n, core.SigAlgMLDSA65, "Hof Sonnenblick")
	dairy := newParticipant(t, n, core.SigAlgMLDSA65, "Molkerei Tal")
	sensor := newParticipant(t, n, core.SigAlgMLDSA44, "kuehl-77")

	milk := newSubject(t)
	tank := newSubject(t)
	cheese := newSubject(t)

	ref := func(r submitResponse) core.EntryRef {
		return core.EntryRef{Entry: r.EntryID, Log: r.Log}
	}

	// 1. Erzeugung.
	se, salt, payload := farm.sign(t, core.EntryTypeAssertion, milk, evProduction)
	production := a.submit(se, salt, payload)
	if production.Seq != 0 {
		t.Fatalf("first entry has seq %d", production.Seq)
	}

	// Ein STH von früh in der Kette — gegen ihn wird später die Konsistenz
	// geprüft.
	var early sthResponse
	if code := a.adminPost("/admin/v1/sth", nil, &early); code != http.StatusOK {
		t.Fatalf("issue STH: %d", code)
	}

	// 2. Zusammenfassung im Tank.
	evAggregation := `{
		"event": "aggregation",
		"time": "2026-08-10T09:00:00+02:00",
		"action": "add",
		"container": {"name": "Sammeltank T-3"},
		"children": [{"subject": "` + hex.EncodeToString(milk[:]) + `", "quantity": {"value": 1000, "unit": "LTR"}}]
	}`
	se, salt, payload = farm.sign(t, core.EntryTypeAssertion, tank, evAggregation, ref(production))
	aggregation := a.submit(se, salt, payload)

	// 3. Transport und die Messung der Kühlkette dazu.
	se, salt, payload = farm.sign(t, core.EntryTypeAssertion, tank, evTransport, ref(aggregation))
	transport := a.submit(se, salt, payload)

	se, salt, payload = sensor.sign(t, core.EntryTypeSensorReading, tank, evMeasurement, ref(transport))
	measurement := a.submit(se, salt, payload)

	// 4. Verarbeitung zu Käse.
	evProcessing := `{
		"event": "processing",
		"time": "2026-08-11T08:00:00+02:00",
		"process": "pasteurise and make cheese",
		"inputs": [{"subject": "` + hex.EncodeToString(tank[:]) + `", "quantity": {"value": 1000, "unit": "LTR"}}],
		"outputs": [{"subject": "` + hex.EncodeToString(cheese[:]) + `", "product": {"name": "Bergkäse"}, "quantity": {"value": 100, "unit": "KGM"}}]
	}`
	se, salt, payload = dairy.sign(t, core.EntryTypeAssertion, cheese, evProcessing, ref(measurement))
	processing := a.submit(se, salt, payload)

	// 5. Übergabe an den Großhandel.
	se, salt, payload = dairy.sign(t, core.EntryTypeAssertion, cheese, evHandover, ref(processing))
	handover := a.submit(se, salt, payload)

	if handover.Seq != 5 {
		t.Fatalf("after six entries the handover sits at seq %d", handover.Seq)
	}

	// Historie: Der Tank trägt Zusammenfassung, Transport und Messung.
	var history historyResponse
	a.mustGet("/owm/v1/subjects/"+tank.String(), &history)
	if history.Total != 3 {
		t.Fatalf("history of the tank has %d entries, expected 3", history.Total)
	}
	if len(history.Entries) != 3 {
		t.Fatalf("%d entries returned", len(history.Entries))
	}
	for i, want := range []string{"aggregation", "transport", "measurement"} {
		var got struct {
			Event string `json:"event"`
		}
		var pr payloadResponse
		a.mustGet("/owm/v1/entries/"+history.Entries[i].EntryID.String()+"/payload", &pr)
		if err := json.Unmarshal(pr.Payload, &got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if got.Event != want {
			t.Fatalf("history[%d] is %q, expected %q", i, got.Event, want)
		}
		// Der Salt kommt mit, sonst wäre das Commitment nicht nachzurechnen —
		// und die Nutzlast wäre nur das, was der Server gerade behauptet.
		var s core.Salt
		copy(s[:], pr.Salt)
		want := history.Entries[i].Decoded.Commitment
		if want == nil || core.Commit(s, pr.Payload) != *want {
			t.Fatalf("history[%d]: the commitment does not match salt and payload", i)
		}
	}

	// Ein Eintrag mit Nutzlast, decodierter Sicht und Zustand.
	var view leafView
	a.mustGet("/owm/v1/entries/"+production.EntryID.String(), &view)
	if view.Payload != "present" {
		t.Fatalf("payload_status = %q", view.Payload)
	}
	if view.Decoded.Profile != food.ID {
		t.Fatalf("profile = %q", view.Decoded.Profile)
	}
	if view.Decoded.Issuer != farm.key.Public().ID() {
		t.Fatal("the issuer in the decoded view does not match")
	}

	// Beweiskette: STH holen, Inklusionsbeweis prüfen — mit dem Blatt aus der
	// Antwort, nicht mit dem, was der Server behauptet.
	var latest sthResponse
	if code := a.adminPost("/admin/v1/sth", nil, &latest); code != http.StatusOK {
		t.Fatalf("issue STH: %d", code)
	}
	if err := latest.Signed.Verify(n.Identity().Key.Public()); err != nil {
		t.Fatalf("STH signature: %v", err)
	}
	sth, err := latest.Signed.STH()
	if err != nil {
		t.Fatalf("unwrap STH: %v", err)
	}
	if sth.Size != 6 {
		t.Fatalf("tree size %d, expected 6", sth.Size)
	}

	var proof owmlog.InclusionProof
	a.mustGet("/owm/v1/proof/inclusion?entry="+production.EntryID.String(), &proof)
	leaf, err := owmlog.ParseLeaf(view.Leaf)
	if err != nil {
		t.Fatalf("read leaf: %v", err)
	}
	leafHash, err := leaf.Hash()
	if err != nil {
		t.Fatalf("leaf hash: %v", err)
	}
	if err := proof.Verify(leafHash, sth); err != nil {
		t.Fatalf("inclusion proof: %v", err)
	}

	// Konsistenz zwischen frühem und aktuellem Baumzustand.
	earlySTH, err := early.Signed.STH()
	if err != nil {
		t.Fatalf("early STH: %v", err)
	}
	var cons owmlog.ConsistencyProof
	a.mustGet("/owm/v1/proof/consistency?old=1&new=6", &cons)
	if err := cons.Verify(earlySTH, sth); err != nil {
		t.Fatalf("consistency proof: %v", err)
	}

	// Löschung: Die Nutzlast der Erzeugung verschwindet, der Baum bleibt.
	var erased struct {
		Erased    core.Digest `json:"erased"`
		Tombstone leafView    `json:"tombstone"`
	}
	if code := a.adminPost("/admin/v1/erasures", eraseRequest{EntryID: production.EntryID}, &erased); code != http.StatusOK {
		t.Fatalf("erase: %d", code)
	}
	if erased.Tombstone.Decoded.Type != core.EntryTypeErasure.String() {
		t.Fatalf("erasure attestation has type %q", erased.Tombstone.Decoded.Type)
	}

	if code := a.get("/owm/v1/entries/"+production.EntryID.String()+"/payload", nil); code != http.StatusGone {
		t.Fatalf("payload after the erasure: %d, expected 410", code)
	}
	var after leafView
	a.mustGet("/owm/v1/entries/"+production.EntryID.String(), &after)
	if after.Payload != "erased" {
		t.Fatalf("payload_status = %q, expected erased", after.Payload)
	}
	// Der Kniff des ganzen Entwurfs: derselbe Beweis, derselbe STH, weiterhin
	// gültig. Gelöscht wurde außerhalb des Baums.
	if err := proof.Verify(leafHash, sth); err != nil {
		t.Fatalf("the proof from before the erasure no longer holds: %v", err)
	}

	// Und die Nutzlast ist auch nicht mehr zu erraten: Ohne Salt trifft kein
	// Kandidat aus dem Wertebereich das Commitment.
	entry, err := after.decodedEntry()
	if err != nil {
		t.Fatalf("read entry: %v", err)
	}
	for _, cand := range []string{evProduction, evTransport, evHandover} {
		if core.VerifyCommitment(entry.Commitment, core.Salt{}, []byte(cand)) {
			t.Fatal("the commitment can be resolved without the salt")
		}
	}
}

// decodedEntry liest den Eintrag aus der Blattsicht.
func (v leafView) decodedEntry() (*core.Entry, error) {
	se, err := core.ParseSignedEntry(v.Entry)
	if err != nil {
		return nil, err
	}
	return se.Entry()
}

func TestPublicMetadata(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)

	var meta metaResponse
	a.mustGet("/.well-known/openwaymark", &meta)
	if meta.Protocol != "OWM/1" {
		t.Fatalf("protocol = %q", meta.Protocol)
	}
	if meta.Log != n.Log().ID() {
		t.Fatal("the log ID does not match")
	}
	if meta.Key.ID != n.Identity().Key.Public().ID() {
		t.Fatal("the named key is not the node's key")
	}
	// Wer ein Löschbegehren stellen will, muss erfahren, an wen.
	if meta.Operator.Name == "" || meta.Operator.Contact == "" {
		t.Fatal("the operator is missing from the metadata")
	}
	if len(meta.Profiles) != 1 || meta.Profiles[0].ID != food.ID {
		t.Fatalf("profiles = %+v", meta.Profiles)
	}
	if meta.Profiles[0].SchemaDigest.IsZero() {
		t.Fatal("the schema hash is missing")
	}

	// Die Schemadateien sind abrufbar — sonst könnte ein Client nicht prüfen,
	// wogegen die Node validiert.
	code := a.call(http.MethodGet, a.public+"/owm/v1/schema?profile="+food.ID+"&file="+meta.Profiles[0].Files[0], nil, nil)
	if code != http.StatusOK {
		t.Fatalf("schema file: %d", code)
	}
}

// TestPublicKeyLookup prüft, was ein fremder Client braucht, um überhaupt
// prüfen zu können: den öffentlichen Schlüssel zu einer Ausstellerkennung.
func TestPublicKeyLookup(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)
	farm := newParticipant(t, n, core.SigAlgMLDSA65, "Hof Sonnenblick")
	id := farm.key.Public().ID()

	var view publicKeyView
	a.mustGet("/owm/v1/keys/"+id.String(), &view)
	if view.ID != id {
		t.Fatalf("key_id = %s, expected %s", view.ID, id)
	}
	if view.Alg != core.SigAlgMLDSA65.String() {
		t.Fatalf("alg = %q", view.Alg)
	}

	// Der Client rechnet die Kennung selbst nach. Genau das macht die Auskunft
	// unabhängig davon, ob die Node die Wahrheit sagt.
	pub, err := core.ParsePublicKey(core.SigAlgMLDSA65, view.Public)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if pub.ID() != id {
		t.Fatal("the delivered bytes yield a different identifier")
	}

	// Und er kann damit eine Signatur aus dem Log prüfen.
	se, salt, payload := farm.sign(t, core.EntryTypeAssertion, newSubject(t), evProduction)
	a.submit(se, salt, payload)
	if err := se.Verify(pub); err != nil {
		t.Fatalf("signature with the fetched key: %v", err)
	}

	// Das Etikett der Betreiberin bleibt drinnen: Es ist Freitext und trägt
	// oft einen Namen.
	var raw map[string]any
	a.mustGet("/owm/v1/keys/"+id.String(), &raw)
	if _, ok := raw["label"]; ok {
		t.Fatal("the label appears in the public response")
	}

	// Ein stillgelegter Schlüssel bleibt abrufbar — sonst wäre alles, was er
	// je unterschrieben hat, nicht mehr prüfbar.
	if code := a.adminPost("/admin/v1/keys/"+id.String()+"/disable", nil, nil); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	view = publicKeyView{}
	a.mustGet("/owm/v1/keys/"+id.String(), &view)
	if view.DisabledAt == nil {
		t.Fatal("the disabling is not reported")
	}
	if !bytes.Equal(view.Public, farm.key.Public().Bytes()) {
		t.Fatal("a disabled key returns different bytes")
	}

	// Eine Liste aller Teilnehmer gibt es öffentlich nicht.
	if code := a.call(http.MethodGet, a.public+"/owm/v1/keys", nil, nil); code != http.StatusNotFound {
		t.Fatalf("GET /owm/v1/keys: %d, expected 404", code)
	}
}

func TestHTTPErrors(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)
	farm := newParticipant(t, n, core.SigAlgMLDSA65, "hof")

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"unknown path", http.MethodGet, "/owm/v1/nichts", nil, http.StatusNotFound},
		{"wrong method", http.MethodPost, "/owm/v1/sth", struct{}{}, http.StatusMethodNotAllowed},
		{"broken identifier", http.MethodGet, "/owm/v1/entries/nichthex", nil, http.StatusBadRequest},
		{"unknown entry", http.MethodGet, "/owm/v1/entries/" + strings.Repeat("ab", 32), nil, http.StatusNotFound},
		{"broken sequence number", http.MethodGet, "/owm/v1/leaves/x", nil, http.StatusBadRequest},
		{"proof without a reference", http.MethodGet, "/owm/v1/proof/inclusion", nil, http.StatusBadRequest},
		{"unknown profile", http.MethodGet, "/owm/v1/schema?profile=gems.v1&file=x.json", nil, http.StatusNotFound},
		{"broken key identifier", http.MethodGet, "/owm/v1/keys/nichthex", nil, http.StatusBadRequest},
		{"unknown key", http.MethodGet, "/owm/v1/keys/" + strings.Repeat("cd", 32), nil, http.StatusNotFound},
		{"envelope without an entry", http.MethodPost, "/owm/v1/entries", submitRequest{}, http.StatusBadRequest},
		{"unknown field in the envelope", http.MethodPost, "/owm/v1/entries", map[string]string{"eintrag": "x"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code := a.call(c.method, a.public+c.path, c.body, nil); code != c.want {
				t.Fatalf("%s %s: %d, expected %d", c.method, c.path, code, c.want)
			}
		})
	}

	t.Run("unknown issuer", func(t *testing.T) {
		stranger := &participant{key: mustKey(t, core.SigAlgMLDSA65)}
		se, salt, payload := stranger.sign(t, core.EntryTypeAssertion, newSubject(t), evProduction)
		encoded, err := se.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		req := submitRequest{Entry: encoded, Salt: salt[:], Payload: payload}
		if code := a.post("/owm/v1/entries", req, nil); code != http.StatusForbidden {
			t.Fatalf("%d, expected 403", code)
		}
	})

	t.Run("payload does not match the schema", func(t *testing.T) {
		se, salt, payload := farm.sign(t, core.EntryTypeAssertion, newSubject(t), `{"event":"teleportation","time":"2026-08-10T06:30:00Z"}`)
		encoded, err := se.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		req := submitRequest{Entry: encoded, Salt: salt[:], Payload: payload}
		if code := a.post("/owm/v1/entries", req, nil); code != http.StatusUnprocessableEntity {
			t.Fatalf("%d, expected 422", code)
		}
	})

	t.Run("salt with the wrong length", func(t *testing.T) {
		se, _, payload := farm.sign(t, core.EntryTypeAssertion, newSubject(t), evProduction)
		encoded, err := se.Encode()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		req := submitRequest{Entry: encoded, Salt: []byte{1, 2, 3}, Payload: payload}
		if code := a.post("/owm/v1/entries", req, nil); code != http.StatusBadRequest {
			t.Fatalf("%d, expected 400", code)
		}
	})
}

func TestAdminKeys(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)
	k := mustKey(t, core.SigAlgMLDSA44)

	var added keyInfoView
	req := addKeyRequest{Alg: "ML-DSA-44", Public: k.Public().Bytes(), Label: "sensor-1"}
	if code := a.adminPost("/admin/v1/keys", req, &added); code != http.StatusCreated {
		t.Fatalf("admit: %d", code)
	}
	if added.ID != k.Public().ID() || added.Alg != "ML-DSA-44" {
		t.Fatalf("admitted: %+v", added)
	}

	var list struct {
		Keys []keyInfoView `json:"keys"`
	}
	if code := a.adminGet("/admin/v1/keys", &list); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	// Der eigene Schlüssel der Node und der eben aufgenommene.
	if len(list.Keys) != 2 {
		t.Fatalf("%d keys, expected 2", len(list.Keys))
	}

	var disabled keyInfoView
	if code := a.adminPost("/admin/v1/keys/"+k.Public().ID().String()+"/disable", nil, &disabled); code != http.StatusOK {
		t.Fatalf("disable: %d", code)
	}
	if disabled.DisabledAt == nil {
		t.Fatal("disabled_at missing")
	}

	// Ein Eintrag von einem stillgelegten Schlüssel wird nicht mehr angenommen.
	p := &participant{key: k}
	se, salt, payload := p.sign(t, core.EntryTypeSensorReading, newSubject(t), evMeasurement)
	encoded, err := se.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if code := a.post("/owm/v1/entries", submitRequest{Entry: encoded, Salt: salt[:], Payload: payload}, nil); code != http.StatusForbidden {
		t.Fatalf("%d, expected 403", code)
	}

	t.Run("length does not match the algorithm", func(t *testing.T) {
		bad := addKeyRequest{Alg: "ML-DSA-65", Public: k.Public().Bytes()}
		if code := a.adminPost("/admin/v1/keys", bad, nil); code != http.StatusUnprocessableEntity {
			t.Fatalf("%d, expected 422", code)
		}
	})
	t.Run("unknown algorithm", func(t *testing.T) {
		bad := addKeyRequest{Alg: "Ed25519", Public: k.Public().Bytes()}
		if code := a.adminPost("/admin/v1/keys", bad, nil); code != http.StatusBadRequest {
			t.Fatalf("%d, expected 400 - classical algorithms do not exist here", code)
		}
	})
}

func TestAdminEraseUnknownEntry(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)
	req := eraseRequest{EntryID: core.Digest{1, 2, 3}}
	if code := a.adminPost("/admin/v1/erasures", req, nil); code != http.StatusNotFound {
		t.Fatalf("%d, expected 404", code)
	}
}

func TestRunStopsWithContext(t *testing.T) {
	n := newTestNode(t)
	// Freie Ports, damit der Test keine belegte Adresse trifft.
	n.cfg.Listen = "127.0.0.1:0"
	n.cfg.AdminListen = "127.0.0.1:0"
	n.cfg.STHInterval = Duration(20 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run does not terminate")
	}
}
