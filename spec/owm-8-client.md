<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-8 — Client and verifier

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md), [OWM-2](owm-2-log.md),
[OWM-6](owm-6-trust.md), [OWM-7](owm-7-node-api.md) · **Threat model:** [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Describes `client/`: how a chain fetched from a node's public API (OWM-7) is checked rather than
believed, and how that check is exposed to a browser. The governing sentence is already written, in
[OWM-9 A11](owm-9-threat-model.md#a11--server-lying-to-the-client): *"a client that trusts an
answer without computing for itself has given away the entire point."* This document is not a UI
specification with a verification feature attached to it — it is the verification contract, with a
UI as one possible caller.

**Read and verify only.** Submitting entries (`POST /owm/v1/entries`, OWM-7) is out of scope —
that stays business/ERP/scanner-integration territory, unaffected by anything here.

## 2. Two layers

| Layer | What it is | License |
|---|---|---|
| `client/verify` | A pure Go library: fetch a subject's history and an STH, check signature, structure, inclusion proof and commitment, recompute entity trust level. No cryptography of its own — it orchestrates `core`, `log` and `trust`'s existing `Verify` methods and `Compute` function. | Apache-2.0 |
| `client/wasm` + `client/web` | `client/verify` compiled to WebAssembly and exposed to JavaScript as one function; a static page (plain HTML/CSS/JS, no build step) that calls it and renders the result. | Apache-2.0 |

Any caller of `client/verify` — the WASM build, a future CLI verifier, a test — supplies its own
`Fetcher` (`Fetch(ctx, url) ([]byte, error)`): the same trusted-local-data/remote-claim split
`gossip.Client` already draws elsewhere in this project ([OWM-9 A11](owm-9-threat-model.md#a11--server-lying-to-the-client)).
What a caller ends up trusting is exactly, and only, what its own `Fetcher` returns.

## 3. The fetch-then-verify contract

For a subject's full history against a node's current state, in this order:

1. `GET /owm/v1/sth` → verify the signature against the signer's own key
   (`GET /owm/v1/keys/{id}`).
2. `GET /owm/v1/subjects/{id}` → the leaves naming that subject.
3. For each leaf: decode it, verify its embedded entry's signature and structure
   (`log.Leaf.Verify`), fetch an inclusion proof against the STH from step 1
   (`GET /owm/v1/proof/inclusion?entry=...&size=...`) and verify it.
4. Where the entry carries a commitment: fetch payload and salt
   (`GET /owm/v1/entries/{id}/payload`) and verify the commitment
   (`core.VerifyCommitment`). A 410 response (`"error":"erased"`) is reported as erased, not as a
   failure — the statement stands, only its evidence is gone (OWM-2 §7).
5. For every issuer encountered: recompute its entity trust level (OWM-6 §6) via `trust.Compute`,
   fed by attestations fetched the same way (`GET /owm/v1/subjects/{issuerKeyID}`) — never taken
   from `GET /owm/v1/keys/{id}/trust`, which is fetched only for comparison. A mismatch between the
   two MUST be surfaced, not silently resolved in the node's favour.

A caller that already holds an STH from an earlier visit MAY supply it to unlock a consistency-proof
check (`GET /owm/v1/proof/consistency`) against the freshly fetched one — the only way a single,
otherwise stateless run can ever detect a shrunk or rewritten tree on its own. Two STHs of the same
size with different roots is a split view (OWM-9 A1) and MUST be reported as a finding regardless of
whether a consistency proof was even attempted.

## 4. Trust-chain scope

`client/verify`'s HTTP-backed `trust.Source` follows attestation chains against the **same base
URL** the top-level call was given. An attestation chain crossing node boundaries — an
accreditation body attesting an entity whose own log lives elsewhere — is not followed; the walk
simply stops there, which `trust.Compute` already treats as "no further contribution," the same as
a chain with no attestation at all. This is not an oversight quietly assumed away: there is no
protocol-level way to resolve a bare `LogID` to a URL (§6 covers the same limit for `EntryRef.Log`),
and extending cross-node trust-chain resolution is future work.

## 5. Cross-log parent references

`core.EntryRef.Log` is a non-empty hint whenever a parent entry lives in a different log ("the same
entry can live in several logs," per its own doc comment). A caller MAY resolve it — through
`discovery/` from a known domain, or through an explicit map of `LogID` to base URL it already
holds — and continue verification against the foreign log. A caller that cannot resolve it MUST
report the reference as unresolved rather than silently dropping it or guessing at a URL: **there is
no protocol-level mechanism to resolve a bare `LogID` to a node's base URL at all.**
`gossip.Client` needs a configured partner URL for the identical reason — this is not a gap specific
to the client, it is a property of the federation model itself (no global index, OWM-0 §2).

## 6. CORS

A verifier not literally served by the node it queries needs to read that node's public API from a
different origin. Every route under a node's public handler is already documented as
unauthenticated and meant "for the world" (OWM-7 §2) — a node operator who wants to be checkable by
a shared or third-party verifier MUST serve `Access-Control-Allow-Origin` permissively on the public
API. This changes who may *read* a response in a browser, nothing about what the API accepts:
submission stays gated by key admission (`node.Submit`), never by origin. The admin interface MUST
NOT carry this header — it is not part of the public API and stays exactly as unreachable from a
browser on another origin as it always was.

## 7. Addressing and privacy

A caller needs a node base URL and a subject ID to check anything. `client/web` reads both from the
URL **fragment** (`#node=...&subject=...`), not the query string or the path. The fragment is never
sent to the server hosting the page itself — a centrally hosted copy of this static page therefore
never learns, from its own access logs, which node or which subject a visitor looked up. The same
privacy posture the rest of this project holds itself to (OWM-9 §6.1's own STH-reporting trade)
applies here at the level of the page's own hosting, not only the protocol.

## 8. Rendering — convenience, not a trust boundary

`GET /owm/v1/schema?profile=X` serves a profile's actual JSON Schema files, whose `description`
fields are written in plain language throughout this project's profiles specifically so a generic,
schema-driven renderer can use them without profile-specific code. **Stated plainly, not glossed
over: trusting a fetched schema for rendering is strictly weaker than the checks in §3.** A
dishonest node could serve a different schema to change how an entry *displays*, without touching
signature, commitment or inclusion-proof validity at all — those remain independently checked
regardless of which schema was used to label the fields. A caller with a stronger requirement here
MAY pin known profile schemas by digest (`SchemaDigest`, OWM-4 §3) rather than trusting whatever a
node happens to serve.

## 9. Open points

- Supplying a caller's own accreditation root set (`trust.RootSet`) from within `client/web` itself
  — the current build calls `client/verify` with an empty set, so every entity trust level
  recomputes to `LevelNone`, an honest result, not a wrong one, but a real limitation on what the
  page can show today.
- Cross-node trust-chain resolution (§4) and a general `LogID`-to-URL resolution mechanism (§5) —
  both named as gaps here, neither solved here.
- Where a canonical, community-run copy of `client/web` is hosted, if one is — a deployment
  decision, not a protocol question, and explicitly not decided by this document.
- A CLI verifier reusing `client/verify` with a real `net/http`-backed `Fetcher` — the package is
  already shaped for this; none has been built yet.
- In-page QR scanning (`BarcodeDetector`, with a JS fallback) was the original ambition for this
  stage; §7's URL-fragment addressing turned out to make it unnecessary for the common case — a QR
  code can simply encode the full page URL with its fragment, scanned by the phone's own camera
  app, no in-page camera access needed. Left here as a possible future convenience, not a gap in
  what the page can already do.
