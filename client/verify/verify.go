// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package verify fetches an entry chain from a node's public API and checks
// it — signature, commitment, inclusion proof, entity trust level — the same
// way the node itself would, using the exact core, log and trust code the
// node is built on.
//
// This package does not implement any cryptography of its own. It
// orchestrates core.SignedEntry.Verify, core.VerifyCommitment,
// log.Leaf.Verify, log.InclusionProof.Verify, log.ConsistencyProof.Verify and
// trust.Compute against data fetched through the small Fetcher interface —
// so a client that believed the server without calling this package would
// make OWM-9 A1 through A3 moot (A11: "a client that trusts an answer
// without computing for itself has given away the entire point").
//
// Deliberately read-only. Submitting entries is a business/ERP-integration
// concern (POST /owm/v1/entries), not something this package touches.
package verify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
	"openwaymark.org/owm/trust"
)

// Status is the outcome of checking one entry in a subject's history.
type Status string

const (
	// StatusOK reports that signature, structure and inclusion proof all
	// checked out, and the commitment matched the payload where a payload
	// exists.
	StatusOK Status = "ok"
	// StatusErased reports that the entry's evidence was lawfully removed
	// under Art. 17 GDPR — the statement stands, its evidence does not
	// (core.Entry's own erasure/revocation split). Not a failure.
	StatusErased Status = "erased"
	// StatusFailed reports that a check that should have passed did not.
	// Reason names exactly which one.
	StatusFailed Status = "failed"
)

// EntryResult is what checking one entry found.
type EntryResult struct {
	EntryID  core.Digest    `json:"entry_id"`
	Seq      uint64         `json:"seq"`
	Type     core.EntryType `json:"type"`
	Profile  string         `json:"profile,omitempty"`
	Issuer   core.KeyID     `json:"issuer"`
	IssuedAt int64          `json:"issued_at"`
	Status   Status         `json:"status"`
	// Reason is set only for StatusFailed, and names exactly which check
	// failed — never a bare pass/fail, per this package's own reason for
	// existing.
	Reason string `json:"reason,omitempty"`
	// Payload is the checked payload, present only for StatusOK entries
	// that carry one.
	Payload []byte `json:"payload,omitempty"`
}

// Result is the outcome of verifying one subject's full history against one
// node.
type Result struct {
	Subject core.SubjectID `json:"subject"`
	Log     core.LogID     `json:"log"`
	STH     *owmlog.STH    `json:"sth"`
	Entries []EntryResult  `json:"entries"`

	// TrustLevel is the entity trust level this call recomputed itself for
	// every issuer it encountered, keyed by KeyID — never taken from the
	// server. Absent entries mean LevelNone was computed for that issuer,
	// which trust.Compute treats as an ordinary result, not an error.
	TrustLevel map[core.KeyID]trust.Level `json:"trust_level,omitempty"`

	// ServerTrustLevel is the node's own opinion (GET /keys/{id}/trust),
	// fetched only for comparison against TrustLevel — a claim to check,
	// never an answer to accept (OWM-9 A11).
	ServerTrustLevel map[core.KeyID]trust.Level `json:"server_trust_level,omitempty"`

	// Findings are things worth surfacing regardless of any single entry's
	// status: a TrustLevel/ServerTrustLevel mismatch, an unresolved
	// cross-log reference, a failed consistency check against a
	// caller-supplied previous STH.
	Findings []string `json:"findings,omitempty"`

	// Bindings holds every kind:"binding" attestation found for subject
	// (OWM-9 A8) — how forgery-resistant the physical-digital binding is
	// claimed to be, printed QR code through PUF-backed chip. Always
	// computed, never opt-in: OWM-9 A8 requires a client to display this
	// when present. More than one entry means more than one claim was made;
	// this package reports all of them rather than silently picking one —
	// the same "surface everything, let the caller judge" choice already
	// made for TrustLevel/ServerTrustLevel mismatches.
	Bindings []BindingClaim `json:"bindings,omitempty"`
}

// BindingClaim is one kind:"binding" attestation found in a subject's
// history, together with the issuer's own entity trust level — the claim's
// only source of credibility, since a binding attestation is never walked
// to a root the way an entity attestation is (trust/payload.go's own doc
// comment on KindBinding).
type BindingClaim struct {
	Level       trust.BindingLevel `json:"level"`
	Issuer      core.KeyID         `json:"issuer"`
	IssuerLevel trust.Level        `json:"issuer_level"`
	EvidenceURL string             `json:"evidence_url,omitempty"`
}

// OK reports whether every entry checked out and nothing was flagged as a
// Finding. It does not distinguish StatusErased from StatusOK — an erased
// entry is not a failure.
func (r *Result) OK() bool {
	for _, e := range r.Entries {
		if e.Status == StatusFailed {
			return false
		}
	}
	return len(r.Findings) == 0
}

// Options configures a VerifySubject call. The zero value is safe and
// produces a strictly weaker but still honest result: no trust computation
// (everything computes to LevelNone), no consistency check, no cross-log
// following.
type Options struct {
	// Roots is the caller's own accreditation root set for recomputing
	// entity trust levels (OWM-6 §6) — the same "operator-supplied, never
	// gossiped, analogous to a browser's root-CA store" object a node
	// itself is configured with. Never baked into this package: which
	// bodies to recognise is real-world governance (CLAUDE.md §4.1), not
	// something a library gets to decide for its caller.
	Roots trust.RootSet
	// PreviousSTH, given by a caller that kept state across visits (the web
	// app, via localStorage), unlocks a consistency-proof check against the
	// STH this call fetches — the only way a single, stateless call could
	// ever detect a shrunk or rewritten tree on its own.
	PreviousSTH *owmlog.STH
	// LogURLs resolves a foreign log referenced by a parent EntryRef to a
	// node base URL. A referenced log with no entry here is reported as an
	// unresolved cross-log reference, not silently dropped or guessed at —
	// there is no protocol-level way to resolve a bare LogID to a URL
	// (gossip.Client needs a configured partner URL for the same reason).
	LogURLs map[core.LogID]string
	// Profiles enables client-side cross-checking (OWM-9 A4): for every
	// checked sensor_reading entry, its parent entries within this same
	// history are looked up, and — when both share a profile — its
	// CrossCheck runs against the pair. nil disables cross-checking
	// entirely, the same "caller decides" convention Roots already follows
	// for accreditation roots.
	//
	// Typed as an interface, not *profiles.Registry, deliberately: this
	// package does not otherwise depend on profiles/ and, transitively, its
	// JSON Schema library — a real cost for every caller that never sets
	// this field at all, size-sensitive callers like client/wasm above all.
	// *profiles.Registry satisfies ProfileLookup on its own (its CrossCheck
	// method); a caller that already imports profiles/ passes one directly.
	Profiles ProfileLookup
}

// ProfileLookup is the minimum this package needs from a profile registry to
// run cross-checks. *profiles.Registry implements it without either package
// needing to know about the other.
type ProfileLookup interface {
	// CrossCheck looks up profileID and, if found and it defines a
	// cross-check, runs it against claim and msmt. ok is false when the
	// profile is unknown, defines none, or the cross-check found nothing to
	// report.
	CrossCheck(profileID string, claim, msmt []byte) (finding string, ok bool)
}

// VerifySubject fetches nodeBaseURL's current STH, the full history of
// subject, and checks every entry in it: signature, structure, inclusion
// against the fetched STH, commitment against payload where one exists.
//
// A fetch failure aborts the call — there is nothing to report without data.
// A verification failure does not: it is recorded on the specific
// EntryResult and the call continues, because the value of this package is
// exactly in surfacing everything wrong, not stopping at the first one.
func VerifySubject(ctx context.Context, f Fetcher, nodeBaseURL string, subject core.SubjectID, opts Options) (*Result, error) {
	c := &client{f: f, base: nodeBaseURL, keys: map[core.KeyID]*core.PublicKey{}}

	signedSTH, err := c.fetchSTH(ctx)
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: fetch STH: %w", err)
	}
	sth, err := signedSTH.STH()
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: decode STH: %w", err)
	}
	sthKey, err := c.key(ctx, sth.Key)
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: fetch STH signer %s: %w", sth.Key, err)
	}

	// Entries starts as an empty slice, not nil: a subject with no history is
	// an ordinary, common result (a fresh QR code, an unrelated random
	// subject) and JSON's "[]" says exactly that — "null" would make a
	// caller's own len(res.entries) check a footgun for no reason.
	res := &Result{Subject: subject, Log: sth.Log, Entries: []EntryResult{}}
	if err := signedSTH.Verify(sthKey); err != nil {
		res.Findings = append(res.Findings, fmt.Sprintf("STH signature does not verify: %v", err))
	} else {
		res.STH = sth
	}

	if opts.PreviousSTH != nil && res.STH != nil {
		if opts.PreviousSTH.Size == res.STH.Size {
			if opts.PreviousSTH.Root != res.STH.Root {
				res.Findings = append(res.Findings, fmt.Sprintf(
					"split view: two STHs for tree size %d with different roots — %s",
					res.STH.Size, owmlog.ErrSplitView))
			}
		} else if opts.PreviousSTH.Size < res.STH.Size {
			cp, err := c.fetchConsistency(ctx, opts.PreviousSTH.Size, res.STH.Size)
			if err != nil {
				res.Findings = append(res.Findings, fmt.Sprintf("fetch consistency proof: %v", err))
			} else if err := cp.Verify(opts.PreviousSTH, res.STH); err != nil {
				res.Findings = append(res.Findings, fmt.Sprintf("consistency proof failed: %v", err))
			}
		} else {
			res.Findings = append(res.Findings, fmt.Sprintf(
				"tree shrank: previously seen size %d, node now reports %d",
				opts.PreviousSTH.Size, res.STH.Size))
		}
	}

	hist, err := c.fetchHistory(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("owm/client/verify: fetch history: %w", err)
	}

	issuers := map[core.KeyID]bool{}
	checked := make(map[core.Digest]checkedEntry, len(hist.Entries))
	for _, lv := range hist.Entries {
		er, e, issuer, ok := c.checkEntry(ctx, lv, sth.Log, res.STH)
		res.Entries = append(res.Entries, er)
		if e != nil {
			checked[er.EntryID] = checkedEntry{entry: e, result: er}
		}
		if ok {
			issuers[issuer] = true
		}
	}
	res.Findings = append(res.Findings, crossCheckFindings(opts.Profiles, sth.Log, checked)...)

	// trust.Compute is well-defined (LevelNone, nil error) even over an
	// empty root set — "no evidence" is an ordinary result, not something
	// to special-case around here.
	src := &httpTrustSource{c: c}
	res.TrustLevel = map[core.KeyID]trust.Level{}
	res.ServerTrustLevel = map[core.KeyID]trust.Level{}
	for issuer := range issuers {
		lvl, _, err := trust.Compute(ctx, src, opts.Roots, issuer)
		if err != nil {
			res.Findings = append(res.Findings, fmt.Sprintf("trust level of %s: %v", issuer, err))
			continue
		}
		res.TrustLevel[issuer] = lvl

		serverLvl, err := c.fetchTrust(ctx, issuer)
		if err != nil {
			continue // the convenience endpoint is optional; its absence is not a finding
		}
		res.ServerTrustLevel[issuer] = serverLvl
		if serverLvl != lvl {
			res.Findings = append(res.Findings, fmt.Sprintf(
				"trust level mismatch for %s: recomputed %s, node claims %s",
				issuer, lvl, serverLvl))
		}
	}

	// Binding claims (OWM-9 A8): a kind:"binding" attestation is an
	// ordinary attestation entry, already checked like any other above —
	// this only picks the ones with that shape out of what was already
	// verified. res.TrustLevel[issuer] degrades to LevelNone when absent,
	// the same convention its own doc comment already establishes.
	for _, ce := range checked {
		if ce.result.Status != StatusOK || ce.result.Type != core.EntryTypeAttestation {
			continue
		}
		p, err := trust.ParsePayload(ce.result.Payload)
		if err != nil || p.Kind != trust.KindBinding {
			continue
		}
		res.Bindings = append(res.Bindings, BindingClaim{
			Level:       p.BindingLevel,
			Issuer:      ce.result.Issuer,
			IssuerLevel: res.TrustLevel[ce.result.Issuer],
			EvidenceURL: p.EvidenceURL,
		})
	}

	return res, nil
}

// checkEntry verifies one entry from a subject's history: leaf signature and
// structure, inclusion against sth (if the STH itself verified), and
// commitment against payload unless the entry was erased or carries none.
//
// The second return value is the parsed entry, non-nil whenever the leaf and
// signed entry themselves could be decoded — used by the cross-check pass to
// walk Parents, and returned regardless of ok so a later, unrelated failure
// (a bad inclusion proof, a payload that does not match) does not also hide
// an otherwise-readable Parents list. The third return value is the issuer,
// useful to the caller only when ok is true — an entry that failed to parse
// at all names no issuer worth trusting.
func (c *client) checkEntry(ctx context.Context, lv leafView, logID core.LogID, sth *owmlog.STH) (EntryResult, *core.Entry, core.KeyID, bool) {
	leaf, err := owmlog.ParseLeaf(lv.Leaf)
	if err != nil {
		return EntryResult{Seq: lv.Seq, Status: StatusFailed, Reason: fmt.Sprintf("parse leaf: %v", err)}, nil, core.KeyID{}, false
	}
	se, err := leaf.SignedEntry()
	if err != nil {
		return EntryResult{Seq: lv.Seq, Status: StatusFailed, Reason: fmt.Sprintf("parse entry: %v", err)}, nil, core.KeyID{}, false
	}
	e, err := se.Entry()
	if err != nil {
		return EntryResult{Seq: lv.Seq, Status: StatusFailed, Reason: fmt.Sprintf("decode entry: %v", err)}, nil, core.KeyID{}, false
	}
	entryID := leaf.EntryID()
	er := EntryResult{
		EntryID:  entryID,
		Seq:      leaf.Seq,
		Type:     e.Type,
		Profile:  e.Profile,
		Issuer:   e.Issuer,
		IssuedAt: e.IssuedAt,
	}

	pub, err := c.key(ctx, e.Issuer)
	if err != nil {
		er.Status, er.Reason = StatusFailed, fmt.Sprintf("fetch issuer key: %v", err)
		return er, e, e.Issuer, false
	}
	if err := leaf.Verify(logID, pub); err != nil {
		er.Status, er.Reason = StatusFailed, fmt.Sprintf("signature/structure: %v", err)
		return er, e, e.Issuer, false
	}

	if sth != nil {
		leafHash, err := leaf.Hash()
		if err != nil {
			er.Status, er.Reason = StatusFailed, fmt.Sprintf("leaf hash: %v", err)
			return er, e, e.Issuer, false
		}
		ip, err := c.fetchInclusion(ctx, entryID, sth.Size)
		if err != nil {
			er.Status, er.Reason = StatusFailed, fmt.Sprintf("fetch inclusion proof: %v", err)
			return er, e, e.Issuer, false
		}
		if err := ip.Verify(leafHash, sth); err != nil {
			er.Status, er.Reason = StatusFailed, fmt.Sprintf("inclusion proof: %v", err)
			return er, e, e.Issuer, false
		}
	}

	if e.Commitment.IsZero() {
		// Revocation and erasure entries carry no commitment (core.Entry's
		// own rule) — nothing further to check.
		er.Status = StatusOK
		return er, e, e.Issuer, true
	}

	salt, payload, err := c.fetchPayload(ctx, entryID)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Erased() {
			er.Status = StatusErased
			return er, e, e.Issuer, true
		}
		er.Status, er.Reason = StatusFailed, fmt.Sprintf("fetch payload: %v", err)
		return er, e, e.Issuer, false
	}
	if !core.VerifyCommitment(e.Commitment, salt, payload) {
		er.Status, er.Reason = StatusFailed, "payload does not match the entry's commitment"
		return er, e, e.Issuer, false
	}
	er.Status = StatusOK
	er.Payload = payload
	return er, e, e.Issuer, true
}

// checkedEntry pairs a checked EntryResult with the parsed core.Entry it
// came from, keyed by entry ID — what the cross-check pass needs to walk
// Parents and look up whether they, too, checked out.
type checkedEntry struct {
	entry  *core.Entry
	result EntryResult
}

// crossCheckFindings runs every checked sensor_reading entry's profile
// cross-check (OWM-9 A4) against its own parents within this same history.
// lookup == nil disables the whole pass — the caller's explicit choice not
// to cross-check, the same as an empty Options.Roots disables trust
// computation.
func crossCheckFindings(lookup ProfileLookup, logID core.LogID, checked map[core.Digest]checkedEntry) []string {
	if lookup == nil {
		return nil
	}
	var findings []string
	for _, ce := range checked {
		if ce.result.Status != StatusOK || ce.result.Type != core.EntryTypeSensorReading {
			continue
		}
		for _, ref := range ce.entry.Parents {
			if !ref.Log.IsZero() && ref.Log != logID {
				continue // a foreign-log parent is out of scope for this pass
			}
			parent, ok := checked[ref.Entry]
			if !ok || parent.result.Status != StatusOK || parent.result.Profile != ce.result.Profile {
				continue
			}
			if finding, ok := lookup.CrossCheck(ce.result.Profile, parent.result.Payload, ce.result.Payload); ok {
				findings = append(findings, fmt.Sprintf("entry %s: %s", ce.result.EntryID, finding))
			}
		}
	}
	return findings
}

// client bundles a Fetcher with a node base URL and a per-call public-key
// cache, so that an issuer appearing in several entries is fetched once.
type client struct {
	f    Fetcher
	base string
	keys map[core.KeyID]*core.PublicKey
}

func (c *client) key(ctx context.Context, id core.KeyID) (*core.PublicKey, error) {
	if pub, ok := c.keys[id]; ok {
		return pub, nil
	}
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/keys/"+id.String())
	if err != nil {
		return nil, err
	}
	var v publicKeyView
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode key: %w", err)
	}
	alg, err := core.ParseSigAlg(v.Alg)
	if err != nil {
		return nil, err
	}
	pub, err := core.ParsePublicKey(alg, v.Public)
	if err != nil {
		return nil, err
	}
	if pub.ID() != id {
		// The node computed a different identifier for the bytes it just
		// handed back than the one asked for — never trust this key.
		return nil, fmt.Errorf("key %s: node returned a key identifying as %s", id, pub.ID())
	}
	c.keys[id] = pub
	return pub, nil
}

func (c *client) fetchSTH(ctx context.Context) (*owmlog.SignedSTH, error) {
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/sth")
	if err != nil {
		return nil, err
	}
	var v sthResponse
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode STH: %w", err)
	}
	if v.Signed == nil {
		return nil, errors.New("no signed STH in response")
	}
	return v.Signed, nil
}

func (c *client) fetchHistory(ctx context.Context, subject core.SubjectID) (*historyResponse, error) {
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/subjects/"+subject.String())
	if err != nil {
		return nil, err
	}
	var v historyResponse
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("decode history: %w", err)
	}
	return &v, nil
}

func (c *client) fetchPayload(ctx context.Context, entryID core.Digest) (core.Salt, []byte, error) {
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/entries/"+entryID.String()+"/payload")
	if err != nil {
		return core.Salt{}, nil, err
	}
	var v payloadResponse
	if err := json.Unmarshal(b, &v); err != nil {
		return core.Salt{}, nil, fmt.Errorf("decode payload: %w", err)
	}
	if len(v.Salt) != core.SaltSize {
		return core.Salt{}, nil, fmt.Errorf("salt: expected %d bytes, got %d", core.SaltSize, len(v.Salt))
	}
	var salt core.Salt
	copy(salt[:], v.Salt)
	return salt, v.Payload, nil
}

func (c *client) fetchInclusion(ctx context.Context, entryID core.Digest, size uint64) (*owmlog.InclusionProof, error) {
	q := url.Values{"entry": {entryID.String()}, "size": {strconv.FormatUint(size, 10)}}
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/proof/inclusion?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var p owmlog.InclusionProof
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode inclusion proof: %w", err)
	}
	return &p, nil
}

func (c *client) fetchConsistency(ctx context.Context, oldSize, newSize uint64) (*owmlog.ConsistencyProof, error) {
	q := url.Values{"old": {strconv.FormatUint(oldSize, 10)}, "new": {strconv.FormatUint(newSize, 10)}}
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/proof/consistency?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var p owmlog.ConsistencyProof
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("decode consistency proof: %w", err)
	}
	return &p, nil
}

func (c *client) fetchTrust(ctx context.Context, id core.KeyID) (trust.Level, error) {
	b, err := c.f.Fetch(ctx, c.base+"/owm/v1/keys/"+id.String()+"/trust")
	if err != nil {
		return 0, err
	}
	var v trustResponse
	if err := json.Unmarshal(b, &v); err != nil {
		return 0, fmt.Errorf("decode trust: %w", err)
	}
	return trust.Level(v.Level), nil
}

// hexBytes decodes a JSON string of hex digits into raw bytes — the same
// wire convention node.hexBytes uses for Salt and Public in its own
// responses. Only decoding is needed; this package never encodes a request
// body.
type hexBytes []byte

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

// The response shapes below mirror node/server.go's own (unexported)
// response types field for field. There is no shared Go type across the
// module boundary by design — this package only ever knows the wire shape,
// the same as any other client of the public API.

type historyResponse struct {
	Subject core.SubjectID `json:"subject"`
	Log     core.LogID     `json:"log"`
	Total   int            `json:"total"`
	Offset  uint64         `json:"offset"`
	Entries []leafView     `json:"entries"`
}

type leafView struct {
	Seq  uint64 `json:"seq"`
	Leaf []byte `json:"leaf"`
}

type payloadResponse struct {
	Salt    hexBytes `json:"salt"`
	Payload []byte   `json:"payload"`
}

type publicKeyView struct {
	Alg    string   `json:"alg"`
	Public hexBytes `json:"public"`
}

type sthResponse struct {
	Signed *owmlog.SignedSTH `json:"signed"`
}

type trustResponse struct {
	Level int `json:"level"`
}
