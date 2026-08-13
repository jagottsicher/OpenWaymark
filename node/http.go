// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/profiles"
)

// maxRequestBody begrenzt eine Anfrage. Ein Blatt darf MaxLeafSize groß werden,
// dazu kommt die Nutzlast und der Base64-Aufschlag von einem Drittel.
const maxRequestBody = 2 * (owmlog.MaxLeafSize + DefaultMaxPayload)

// errorBody ist die Fehlerantwort der API.
//
// Ein Feld für die Maschine, eines für den Menschen. Die Fehlertexte nennen
// beim Namen, was schiefging: Wer einen Eintrag einreicht und ihn abgelehnt
// bekommt, muss erfahren, warum — sonst rät er.
type errorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	buf, err := json.Marshal(v)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	w.Write(buf) //nolint:errcheck // Der Client ist weg; melden ließe sich das niemandem.
}

func writeError(w http.ResponseWriter, err error) {
	status := statusFor(err)
	code := "error"
	switch status {
	case http.StatusNotFound:
		code = "not_found"
	case http.StatusGone:
		code = "erased"
	case http.StatusForbidden:
		code = "not_admitted"
	case http.StatusConflict:
		code = "conflict"
	case http.StatusRequestEntityTooLarge:
		code = "too_large"
	case http.StatusUnprocessableEntity:
		code = "rejected"
	case http.StatusBadRequest:
		code = "malformed"
	case http.StatusInternalServerError:
		code = "internal"
	}
	detail := err.Error()
	if status == http.StatusInternalServerError {
		// Interne Fehler können Pfade und SQL enthalten. Nach außen genügt,
		// dass etwas schiefging.
		detail = ""
	}
	writeJSON(w, status, errorBody{Error: code, Detail: detail})
}

// statusFor übersetzt die Fehler der unteren Schichten in HTTP-Codes.
//
// Die Unterscheidung, auf die es ankommt: 400 heißt "die Anfrage war schon
// formal kaputt", 422 heißt "die Anfrage war lesbar, der Eintrag wurde
// geprüft und abgelehnt", 403 heißt "der Aussteller gehört nicht zu dieser
// Node". Nur der mittlere Fall besagt etwas über den Inhalt.
func statusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK

	case errors.Is(err, owmlog.ErrErased):
		return http.StatusGone
	case errors.Is(err, owmlog.ErrNotFound):
		return http.StatusNotFound

	case errors.Is(err, ErrUnknownKey),
		errors.Is(err, ErrKeyDisabled),
		errors.Is(err, ErrNotSubmittable):
		return http.StatusForbidden

	case errors.Is(err, owmlog.ErrConflict),
		errors.Is(err, owmlog.ErrLeafConflict),
		errors.Is(err, ErrKeyConflict),
		errors.Is(err, ErrIdentityExists):
		return http.StatusConflict

	case errors.Is(err, ErrPayloadTooLarge),
		errors.Is(err, owmlog.ErrLeafSize):
		return http.StatusRequestEntityTooLarge

	case errors.Is(err, errMalformed),
		errors.Is(err, owmlog.ErrProofSize):
		return http.StatusBadRequest

	case errors.Is(err, profiles.ErrUnknown),
		errors.Is(err, profiles.ErrSchema),
		errors.Is(err, profiles.ErrPayload),
		errors.Is(err, profiles.ErrEntry),
		errors.Is(err, ErrRotation),
		errors.Is(err, ErrPayloadRequired),
		errors.Is(err, ErrPayloadUnexpected),
		errors.Is(err, owmlog.ErrCommitment),
		errors.Is(err, owmlog.ErrNotErasable),
		errors.Is(err, core.ErrBadSignature),
		errors.Is(err, core.ErrIssuerMismatch),
		errors.Is(err, core.ErrAlgMismatch),
		errors.Is(err, core.ErrVersion),
		errors.Is(err, core.ErrEntryType),
		errors.Is(err, core.ErrProfile),
		errors.Is(err, core.ErrMissingField),
		errors.Is(err, core.ErrUnexpectedTgt),
		errors.Is(err, core.ErrTooManyParents),
		errors.Is(err, core.ErrKeySize),
		errors.Is(err, core.ErrSigSize),
		errors.Is(err, core.ErrUnknownAlg),
		errors.Is(err, owmlog.ErrMissingField),
		errors.Is(err, owmlog.ErrLeafVersion),
		errors.Is(err, owmlog.ErrLogMismatch):
		return http.StatusUnprocessableEntity
	}
	return http.StatusInternalServerError
}

// errMalformed steht für alles, was schon am Umschlag scheitert.
var errMalformed = errors.New("owm/node: request is unreadable")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errMalformed, fmt.Sprintf(format, args...))
}

// decodeBody liest den JSON-Umschlag einer Anfrage.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return fmt.Errorf("%w: more than %d bytes", ErrPayloadTooLarge, tooLarge.Limit)
		}
		return malformed("%v", err)
	}
	return nil
}

// parseDigestParam liest einen hexkodierten Hashwert aus dem Pfad.
func parseDigestParam(r *http.Request, name string) (core.Digest, error) {
	s := r.PathValue(name)
	d, err := core.ParseDigest(s)
	if err != nil {
		return core.Digest{}, malformed("%s: %v", name, err)
	}
	return d, nil
}

// parsePathUint liest eine vorzeichenlose Zahl aus dem Pfad.
func parsePathUint(r *http.Request, name string) (uint64, error) {
	v, err := strconv.ParseUint(r.PathValue(name), 10, 64)
	if err != nil {
		return 0, malformed("%s: %v", name, err)
	}
	return v, nil
}

// parseUintQuery liest eine vorzeichenlose Zahl aus der Abfrage.
// Fehlt der Parameter, gilt def.
func parseUintQuery(r *http.Request, name string, def uint64) (uint64, error) {
	s := r.URL.Query().Get(name)
	if s == "" {
		return def, nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, malformed("%s: %v", name, err)
	}
	return v, nil
}

// jsonRouterErrors sorgt dafür, dass auch die Antworten des Routers JSON sind.
//
// http.ServeMux beantwortet einen unbekannten Pfad mit 404 und eine falsche
// Methode auf einem bekannten Pfad mit 405 — beides in text/plain. Ein Client,
// der Fehler in einer Form erwartet, bekäme ausgerechnet in diesen beiden
// Fällen eine andere. Die Unterscheidung 404/405 stammt weiterhin vom Router,
// sie ist nur ohne eigene Routentabelle nicht nachzubauen.
func jsonRouterErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&routerErrorWriter{ResponseWriter: w}, r)
	})
}

type routerErrorWriter struct {
	http.ResponseWriter
	replaced bool
}

func (w *routerErrorWriter) WriteHeader(status int) {
	if w.replaced {
		return
	}
	// Ein Handler, der selbst geantwortet hat, hat den JSON-Typ bereits
	// gesetzt. Nur die Standardantworten des Routers werden ersetzt.
	replaceable := status == http.StatusNotFound || status == http.StatusMethodNotAllowed
	if !replaceable || strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	body := errorBody{Error: "not_found", Detail: "no such endpoint"}
	if status == http.StatusMethodNotAllowed {
		body = errorBody{Error: "method_not_allowed", Detail: "allowed: " + w.Header().Get("Allow")}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.replaced = true
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(buf)))
	w.ResponseWriter.WriteHeader(status)
	w.ResponseWriter.Write(buf) //nolint:errcheck // siehe writeJSON
}

func (w *routerErrorWriter) Write(b []byte) (int, error) {
	if w.replaced {
		// Der Standardtext des Routers wird verworfen, nicht angehängt.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// hexBytes ist ein Bytefeld, das in JSON hexadezimal steht.
//
// Hex und nicht Base64 überall dort, wo ein Mensch den Wert vergleichen können
// muss: Schlüssel, Kennungen, Salt. Für die großen, opaken Bytefolgen — Eintrag,
// Blatt, Signatur — bleibt es bei Base64, weil sie niemand von Hand vergleicht.
type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = raw
	return nil
}

// entryView ist die dekodierte Sicht auf einen Eintrag.
//
// Ausdrücklich kein Beweis, sondern Bequemlichkeit: Verbindlich sind allein die
// kanonischen Bytes im Feld entry, gegen die die Signatur geprüft wird. Wer
// dieser Sicht glaubt statt den Bytes, glaubt dem Server.
type entryView struct {
	Version    uint16           `json:"v"`
	Type       string           `json:"typ"`
	Profile    string           `json:"prof,omitempty"`
	Subject    core.SubjectID   `json:"subj"`
	IssuedAt   int64            `json:"iat"`
	Issuer     core.KeyID       `json:"iss"`
	Commitment *core.Commitment `json:"cmt,omitempty"`
	Parents    []core.EntryRef  `json:"par,omitempty"`
	Target     *core.EntryRef   `json:"tgt,omitempty"`
}

func viewEntry(e *core.Entry) entryView {
	v := entryView{
		Version:  e.Version,
		Type:     e.Type.String(),
		Profile:  e.Profile,
		Subject:  e.Subject,
		IssuedAt: e.IssuedAt,
		Issuer:   e.Issuer,
		Parents:  e.Parents,
		Target:   e.Target,
	}
	if !e.Commitment.IsZero() {
		c := e.Commitment
		v.Commitment = &c
	}
	return v
}
