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

// maxRequestBody caps a request. A leaf may grow to MaxLeafSize, plus the
// payload and the one-third overhead of Base64.
const maxRequestBody = 2 * (owmlog.MaxLeafSize + DefaultMaxPayload)

// errorBody is the API's error response.
//
// One field for the machine, one for the human. The error texts name what went
// wrong: whoever submits an entry and has it rejected has to learn why —
// otherwise they are guessing.
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
	w.Write(buf) //nolint:errcheck // The client is gone; there is nobody left to report it to.
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
	case http.StatusTooManyRequests:
		code = "rate_limited"
	case http.StatusInternalServerError:
		code = "internal"
	}
	detail := err.Error()
	if status == http.StatusInternalServerError {
		// Internal errors can contain paths and SQL. To the outside it is enough
		// that something went wrong.
		detail = ""
	}
	writeJSON(w, status, errorBody{Error: code, Detail: detail})
}

// statusFor translates the errors of the lower layers into HTTP codes.
//
// The distinction that matters: 400 means "the request was already broken
// formally", 422 means "the request was readable, the entry was checked and
// rejected", 403 means "the issuer does not belong to this node". Only the
// middle case says anything about the content.
func statusFor(err error) int {
	switch {
	case err == nil:
		return http.StatusOK

	case errors.Is(err, owmlog.ErrErased):
		return http.StatusGone
	case errors.Is(err, owmlog.ErrNotFound):
		return http.StatusNotFound

	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests

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

// errMalformed stands for everything that already fails at the envelope.
var errMalformed = errors.New("owm/node: request is unreadable")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errMalformed, fmt.Sprintf(format, args...))
}

// decodeBody reads the JSON envelope of a request.
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

// parseDigestParam reads a hex-encoded hash value from the path.
func parseDigestParam(r *http.Request, name string) (core.Digest, error) {
	s := r.PathValue(name)
	d, err := core.ParseDigest(s)
	if err != nil {
		return core.Digest{}, malformed("%s: %v", name, err)
	}
	return d, nil
}

// parsePathUint reads an unsigned number from the path.
func parsePathUint(r *http.Request, name string) (uint64, error) {
	v, err := strconv.ParseUint(r.PathValue(name), 10, 64)
	if err != nil {
		return 0, malformed("%s: %v", name, err)
	}
	return v, nil
}

// parseUintQuery reads an unsigned number from the query string.
// If the parameter is absent, def applies.
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

// withCORS allows any origin to read the public API from a browser.
//
// Every route here is already documented as unauthenticated and meant "for
// the world" (OWM-7) — this changes who may read a response inside a
// browser, nothing about what the API accepts. Submitting an entry is still
// gated by key admission (node.Submit), never by origin, so the one write
// route gains no new capability either — only the ability for a page on a
// different origin, such as a shared web verifier, to read the response.
//
// Only ever composed into PublicHandler. node/admin.go builds its own
// handler and never passes through this wrapper — the admin interface stays
// exactly as unreachable from a browser on another origin as it always was.
func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if r.Method == http.MethodOptions {
			// A cross-origin POST /owm/v1/entries with a JSON body is not a
			// CORS "simple request" and triggers a preflight first — answer
			// it here rather than leaving submission half-reachable.
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// jsonRouterErrors makes sure the router's own responses are JSON as well.
//
// http.ServeMux answers an unknown path with 404 and a wrong method on a known
// path with 405 — both in text/plain. A client that expects errors in one shape
// would get another one in exactly those two cases. The 404/405 distinction
// still comes from the router; it just cannot be rebuilt without a routing
// table of one's own.
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
	// A handler that answered on its own has already set the JSON type. Only
	// the router's default responses get replaced.
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
	w.ResponseWriter.Write(buf) //nolint:errcheck // see writeJSON
}

func (w *routerErrorWriter) Write(b []byte) (int, error) {
	if w.replaced {
		// The router's default text is discarded, not appended.
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// hexBytes is a byte slice that appears in JSON as hexadecimal.
//
// Hex and not Base64 wherever a human needs to be able to compare the value:
// keys, identifiers, salt. For the large opaque byte strings — entry, leaf,
// signature — Base64 stays, because nobody compares those by hand.
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

// entryView is the decoded view of an entry.
//
// Explicitly not proof but convenience: what counts are the canonical bytes in
// the entry field alone, against which the signature is checked. Whoever
// believes this view instead of the bytes is believing the server.
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
