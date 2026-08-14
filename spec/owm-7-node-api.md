<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-7 — Node API

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md), [OWM-2](owm-2-log.md),
[OWM-3](owm-3-keys.md) · **Threat model:** [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose

How a node is addressed over HTTP: submitting entries, reading entries and payloads, fetching STHs
and proofs, retrieving the history of a subject, obtaining profiles and their schemas.

The API transports what OWM-0 and OWM-2 define; it defines nothing security-relevant of its own.
**Everything that matters is already signed before it reaches this interface.** A client that checks
the signatures itself has to believe the node nothing — and the shape of the responses is cut for
exactly that.

**What this document does not govern:** how nodes find one another and exchange STHs (OWM-5), how
trust levels come about (OWM-6).

## 2. Two interfaces

| | Prefix | Who | Binding |
|---|---|---|---|
| Public API | `/owm/v1`, `/.well-known/openwaymark` | the world | public, behind a TLS proxy |
| Administration | `/admin/v1` | the operator | local, see §8 |

The separation is not merely organisational. An erasure under Article 17 GDPR is addressed to the
controller, and the controller decides on it — not an anonymous call from outside. Likewise, nobody
from outside admits keys to the directory (OWM-3 §5.1). Both operations therefore sit behind
`/admin/v1` and not behind a permission check in the public API.

A node MUST be able to bind the two interfaces to separate addresses. It SHOULD run the public API
behind a TLS-terminating reverse proxy; terminating TLS itself is not among the tasks of log
software.

## 3. Conventions

**Encoding.** All responses are `application/json; charset=utf-8`, except schema files
(`application/schema+json`). Byte fields are given

- **in hexadecimal** wherever a human has to be able to compare them: keys, identifiers, salt, root
  hashes;
- **in Base64** (standard alphabet, with padding) wherever they are opaque and large: entry, leaf,
  signature, payload.

Times are milliseconds since the Unix epoch, UTC — the same format as in entry and leaf.

**Unknown fields.** A request body with an unknown field MUST be rejected. A mistyped field would
otherwise be a setting that has no effect while the submitter believes they have made it.

**Errors.** Every error response, including the router's, is JSON:

```json
{ "error": "rejected", "detail": "owm/profiles: payload does not match the schema: ..." }
```

| Status | `error` | Meaning |
|---|---|---|
| 400 | `malformed` | The request was already broken in form. |
| 403 | `not_admitted` | The issuer does not belong to this node, or their key is disabled. |
| 404 | `not_found` | No such entry, endpoint, key or STH. |
| 405 | `method_not_allowed` | The path exists, the method does not. `Allow` names the permitted ones. |
| 409 | `conflict` | Contradiction with the existing state (e.g. key identifier with different bytes). |
| 410 | `erased` | The payload has been erased. The entry still stands in the log. |
| 413 | `too_large` | Payload or leaf exceed the limit. |
| 422 | `rejected` | The request was readable, the entry was checked and rejected. |
| 500 | `internal` | Error of the node. `detail` stays empty. |

The distinction that matters: **400 means "unreadable", 422 means "checked and rejected", 403 means
"not responsible".** Only the middle case says anything about the content. `detail` MUST stay empty
on 500 — internal messages carry paths and queries.

**410 instead of 404 after an erasure.** An erased payload is not the same thing as one that never
existed. 410 says: the entry is in the tree, its evidence is gone. That distinction is the
precondition for an observer being able to tell erasure and withholding apart (OWM-9 A3).

**Pruned is not an error.** After the pruning period a node MAY discard the signed entry and keep
only the leaf hash ([OWM-2 §10](owm-2-log.md#10-retention-and-pruning), §10.2). Such an entry is
neither unknown nor erased: the leaf still stands in the tree, and every proof over it still
computes. A node MUST therefore answer with `200` and `entry_status: "pruned"` (§4.4), and MUST NOT
answer 404 or 410 — an error status would say the request could not be answered, when in truth it
was answered with everything that is left of the entry.

## 4. Endpoints of the public API

| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/openwaymark` | description of the node |
| POST | `/owm/v1/entries` | submit an entry |
| GET | `/owm/v1/entries/{entry_id}` | leaf for an entry identifier |
| GET | `/owm/v1/entries/{entry_id}/payload` | payload **and salt** |
| GET | `/owm/v1/leaves/{seq}` | leaf for a sequence number |
| GET | `/owm/v1/sth[?size=n]` | latest or a particular STH |
| GET | `/owm/v1/proof/inclusion?…` | inclusion proof |
| GET | `/owm/v1/proof/consistency?old=…&new=…` | consistency proof |
| GET | `/owm/v1/subjects/{subject_id}` | history of a subject |
| GET | `/owm/v1/keys/{key_id}` | public key of an issuer |
| GET | `/owm/v1/profiles` | loaded profiles |
| GET | `/owm/v1/schema?profile=…&file=…` | a single schema file |

### 4.1 Description of the node

`GET /.well-known/openwaymark` is the entry point of the federation: the DNS TXT record (OWM-0 §7)
points at the node, and this response says which log it keeps, what it signs with, who is
responsible for it, and how long it keeps what.

```json
{
  "protocol": "OWM/1",
  "log": "…64 hex characters…",
  "base_url": "https://provenance.example.com",
  "operator": { "name": "…", "contact": "…", "privacy": "…" },
  "key":         { "alg": "ML-DSA-65", "id": "…", "public": "…" },
  "genesis_key": { "alg": "ML-DSA-65", "id": "…", "public": "…" },
  "tree_size": 42,
  "profiles": [ … ],
  "max_payload": 262144,
  "max_leaf": 131072,
  "retention": { "food.v1": 63072000000 },
  "pruning_period": 94608000000,
  "api": "/owm/v1"
}
```

`genesis_key` stands next to `key` because only it makes the log identifier recomputable (OWM-2 §2,
OWM-3 §4). After a rotation the two differ, and a client given only `key` could no longer check
`log`.

`operator` is not decoration: whoever wants to lodge a request for access or erasure has to be able
to find out with whom. A node SHOULD set `contact`.

`retention` names, per profile, the period after which the node erases payload and salt of its own
accord ([OWM-2 §10](owm-2-log.md#10-retention-and-pruning), §10.1); `pruning_period` names the
period after which it discards the signed entry as well and keeps only the leaf hash (§10.2). Both
are durations in milliseconds, both count from `logged_at`, and `pruning_period` MUST NOT be shorter
than the longest published retention period — a node may not throw away the entry before the payload
was due to go. `null` means that no period has been laid down; it does not mean "kept for ever".

Publishing the two periods is what allows a client to tell a payload that has legitimately aged out
from one being withheld. A node that publishes neither leaves every gap looking the same, and that
is precisely the confusion OWM-9 A3 lives on.

The path follows RFC 8615. The response is unauthenticated — it describes the node, it proves
nothing. What it says about the key is checked by a client verifying an STH with it.

### 4.2 Submitting an entry

```
POST /owm/v1/entries
{
  "entry":   "…Base64 of the canonical bytes of the signed entry…",
  "salt":    "…64 hex characters…",
  "payload": "…Base64…"
}
```

The signed entry is transmitted as **bytes** and passed on unchanged by the node. It MUST NOT be
taken in as a JSON object and re-encoded server-side: the signature holds for exactly these bytes,
and every re-encoding would be an opportunity to lose it (OWM-0 §6.3).

`salt` and `payload` are omitted for an entry without `cmt`. Otherwise:

- entry with `cmt` but without `payload` → 422. The node could not check the commitment and would
  hold nothing for it to refer to.
- `payload` without `cmt` in the entry → 422. The payload would be bound to nothing.
- `salt` ≠ 32 bytes with a `payload` present → 400.

**Order of checks** — from cheap to expensive, from structural to substantive:

1. Entry type: `erasure` is not accepted from outside (§4.3).
2. Payload size against `max_payload`.
3. Profile and schema (OWM-4).
4. Signature and issuer against the key directory (OWM-3 §5).
5. Commitment against payload.

What gets through here is well-formed and attributable. **Whether it is true is what none of these
checks says** — no software can (OWM-9, the oracle problem).

Response `201 Created`:

```json
{
  "log": "…", "entry_id": "…", "seq": 5,
  "logged_at": 1786000000000,
  "leaf": "…Base64 of the leaf…"
}
```

The complete leaf comes back, not merely its sequence number: from it the submitter can compute the
leaf hash themselves and request the inclusion proof as soon as the next STH stands.

### 4.3 What the public API does not accept

A node MUST reject `erasure` entries from outside (403). An erasure witness is a fact about the
storage of **this** node (OWM-0 §6.1); accepting it from outside would mean letting somebody else
claim that something had been erased here. It is produced solely through §8.3.

A `key_rotation` entry, by contrast, is accepted — admission of the successor then happens through
the node itself, by the rules of OWM-3 §6, and only **after** appending: only what stands in the log
is traceably justified.

### 4.4 Reading a leaf

`GET /owm/v1/entries/{entry_id}` and `GET /owm/v1/leaves/{seq}` deliver the same structure:

```json
{
  "log": "…", "seq": 5, "logged_at": 1786000000000, "entry_id": "…",
  "leaf":  "…Base64…",
  "entry": "…Base64…",
  "leaf_hash": "…64 hex characters…",
  "entry_status": "present",
  "payload_status": "present",
  "decoded": { "v": 1, "typ": "assertion", "prof": "food.v1", "subj": "…", … }
}
```

`decoded` is **expressly not proof** but convenience. Binding are the bytes in `entry` alone,
against which the signature is checked. Whoever believes `decoded` instead of the bytes believes the
server — and has thereby taken away from themselves exactly the property the log exists for. An
implementation that makes `decoded` the basis of a check is not conformant.

`payload_status` is `present`, `erased` or `absent`. `entry_status` is `present` or `pruned`.

After the pruning period the node no longer holds the signed entry (OWM-2 §10.2). The answer then
carries `entry_status: "pruned"`; `entry`, `leaf` and `decoded` are absent, and what remains is the
position in the tree:

```json
{
  "log": "…", "seq": 5, "logged_at": 1786000000000, "entry_id": "…",
  "leaf_hash": "…64 hex characters…",
  "entry_status": "pruned",
  "payload_status": "erased"
}
```

This is a `200` and not an error, for the reason given in §3: the node answers the question the
endpoint exists for, it merely has little left to answer it with. A client that reads only the HTTP
status and not `entry_status` will find `entry` missing and MUST treat that as an error rather than
as an entry that happens to have no signature.

`leaf_hash` is convenience as long as the leaf is present — it follows from `leaf` (OWM-2 §3.2), and
a client SHOULD compute it itself. For a pruned entry it is the whole of the answer, and there it is
a **claim of the node** and nothing more: that a leaf with this hash sits at this position is
provable (§4.7), but that this leaf is the one belonging to `entry_id` can no longer be checked by
anybody who did not archive the entry themselves. Pruning is cheap for the node and expensive for
whoever kept nothing.

Being able to distinguish `pruned` from `not_found` at all costs a little more than the 32 bytes of
the cold tier in OWM-2 §10: the node has to keep the entry identifier and the sequence number next
to the leaf hash, some 72 bytes per entry instead of 32. That is the price of the difference between
"we no longer have it" and "we never had it" — and it is a difference an observer needs (OWM-9 A3).

`key_rotation` entries are never pruned (OWM-2 §10.3); their `entry_status` is always `present`.
Were they pruned, the rotation chain would break and every later signature would become
unattributable.

### 4.5 Reading the payload

```
GET /owm/v1/entries/{entry_id}/payload
→ { "entry_id": "…", "salt": "…hex…", "payload": "…Base64…" }
```

The response MUST deliver **salt and payload together**. Without the salt the commitment could not
be recomputed, and the payload would be no more than what the server currently claims. Whoever has
both checks `commitment == HMAC-SHA-256(salt, label ‖ payload)` against the `cmt` in the signed
entry — that is the entire purpose of the endpoint.

After an erasure: `410 erased`. Salt and payload are gone, and both of them (OWM-2 §7.1).

For a pruned entry this endpoint likewise answers `410 erased`. Pruning never comes before the
payload has gone (OWM-2 §10.2), so there is nothing here a `pruned` answer could be about: the
payload was already gone before the entry was.

### 4.6 STH

`GET /owm/v1/sth` delivers the latest, `?size=n` the one for a particular tree size.

```json
{ "signed": { … CBOR envelope, Base64 … }, "decoded": { "v":1, "log":"…", "size":6, "ts":…, "root":"…", "key":"…" } }
```

Here too `decoded` is only a reading aid; checking happens over `signed`. A client MUST check the
signature against a key it knows independently or has traced back through the rotation chain to the
genesis key.

A node MUST keep old STHs retrievable for as long as it holds them. An observer needs them in order
to be able to compare at all; without access to earlier signatures, split-view detection is
pointless (OWM-2 §9, §10).

### 4.7 Proofs

```
GET /owm/v1/proof/inclusion?entry=<entry_id>[&size=n]
GET /owm/v1/proof/inclusion?seq=<i>[&size=n]
GET /owm/v1/proof/consistency?old=<n₁>[&new=<n₂>]
```

**If `size` or `new` is missing, the size of the most recently issued STH applies — not the current
tree size.** That is the most important stipulation of this section: a proof against a size for
which no signature exists is checkable against nothing. The client would have to believe the server,
and that is precisely what it must not have to do. Only where the log has not yet issued any STH
does the default fall back on the current tree size.

Proofs are **not signed** and therefore need no canonical format (OWM-2 §5.3). Their integrity
follows entirely from whether they come out at a signed root hash or do not. A verifier MUST compute
every inclusion proof against the root hash of a concrete STH, and in doing so check that `size` is
the tree size of that STH.

An inclusion proof stays valid after the payload has been erased, and equally after the signed entry
has been pruned — the tree was not touched in either case. That property is checkable and SHOULD be
checked.

A node MUST therefore serve inclusion and consistency proofs for pruned leaves exactly as for any
others. A proof request MUST NOT fail because the entry itself is gone: the tree is made of leaf
hashes, and those are what a node keeps (OWM-2 §10.2). Whoever archived the entry earlier can still
check it in full; whoever did not can at least establish that a leaf with this hash stands in the
tree.

### 4.8 History of a subject

`GET /owm/v1/subjects/{subject_id}?limit=&offset=` delivers all leaves of this node for a subject,
ascending by sequence number.

```json
{ "subject": "…", "log": "…", "total": 3, "offset": 0,
  "entries":  [ … leaves as in §4.4 … ],
  "mirrored": [ … mirrored leaves as in §5.3 … ] }
```

`limit` is 200 by default and 1000 at most. A subject can carry thousands of measurement series; an
answer delivering everything at once would be useless for retrieval over a telephone.

**The answer is the view of *one* node, not the supply chain.** Predecessor entries in `par` may lie
in foreign logs; the reference then names a different `log_id` (OWM-0 §6.2), and the client follows
it itself. A node that presented foreign chains as its own would be vouching for statements that are
not its own — which is why mirrored ancestors, where a node serves them at all, stand in their own
field and carry their origin with them (§5).

### 4.9 An issuer's key

`GET /owm/v1/keys/{key_id}` delivers the public key for an issuer identifier.

```json
{ "key_id": "…", "alg": "ML-DSA-65", "public": "…hex…", "added_at": 1786000000000,
  "disabled_at": null, "parent": null }
```

Without this endpoint, step 2 of the minimum check (§6) would be impracticable for a foreign client:
an entry names only the identifier in `iss`, and that identifier is the hash of the key — the key
cannot be recovered from it.

A client MUST recompute the identifier from the delivered bytes itself (OWM-3 §3). Only that makes
the answer independent of whether the node tells the truth: a node that delivers different bytes for
an identifier is thereby convicted and not merely suspect.

A **disabled** key is still handed out, with `disabled_at` set. What it signed earlier stays
checkable; were the answer to conceal it, every older entry of that issuer would become uncheckable
from the first disabling onwards. Whether a key may still submit *today* is a different question,
and it is answered on submission (§4.2).

Lookups happen **one at a time and only by identifier**. There is no public listing of all keys: it
would be the node's participant register and thus the answer to a question nobody asked. Whoever
looks something up here has the identifier from an entry they already have in front of them.

The label from the directory (OWM-3 §5) is **not** delivered. It is the operator's free text and in
practice often carries a person's name; the public API is no place for such a thing to turn up in
passing.

### 4.10 Profiles and schemas

`GET /owm/v1/profiles` names every loaded profile with `id`, `title`, `schema_digest` and the list
of its files. `GET /owm/v1/schema?profile=…&file=…` delivers one of them.

Profile and file stand in the **query** and not in the path, because a profile identifier may itself
contain slashes (`eu/battery.v1`) — in the path it would no longer be recognisable where the
identifier ends.

The `schema_digest` makes it verifiable which rules the node checks against (OWM-4 §3). Two nodes
that name the same profile but report different digests check differently — and that belongs in
plain sight.

## 5. Ancestor mirroring

The predecessor of an entry may lie in a foreign log: the reference in `par` then names a different
`log_id` (OWM-0 §6.2). Reading a complete chain therefore means reaching that other node — and this
is where the federated model has its weakest hour.

Small producers often have no node of their own, and a node that is switched off makes its segment
of the chain unreachable. A consumer scanning a QR code in a shop must not depend on a Raspberry Pi
in a barn being powered on at that moment. The chain is then not wrong, merely unreadable, and for
the person standing in front of the shelf that comes to the same thing.

### 5.1 Why a copy is as good as the original

Entries are **self-authenticating**. The signature is checked against the issuer's key, the
inclusion proof against a signed root hash, the STH against the log's key — none of these three
steps asks who handed over the bytes. A copy held by a supply chain partner is therefore exactly as
trustworthy as the original: the evidence travels with the data.

Only two questions genuinely need the authoritative node: whether the payload is still there or has
been erased, and whether anything newer has since been said about the entry. Those are questions of
**freshness**, and freshness is the one property a copy cannot carry.

### 5.2 What a node mirrors

A node that serves a consumer-facing subject SHOULD mirror the ancestor entries its own entries
depend on: the signed entry, the inclusion proof as it was issued at the time, and the STH that
proof was checked against. It SHOULD serve them alongside its own chain (§4.8).

Mirroring is a matter of storage and nothing more. The mirrored material is not the node's
statement, it adds no claim of the node's own, and it MUST NOT be appended to the mirroring node's
log — an entry belongs to exactly one tree, and copying it into a second one would have two logs
claiming the same leaf.

How far up the chain a node mirrors is its own decision. The sensible bound is the part of the chain
a consumer is actually shown; mirroring the whole of the upstream ends with every node holding every
other node's log, which is the design this protocol declined at the outset (OWM-2 §1).

### 5.3 How a mirrored entry is marked

A mirrored entry MUST be marked as mirrored. `log` names the **foreign** log the leaf belongs to,
and a `mirrored` object names what the copy was verified against:

```json
{
  "log": "…64 hex characters, the foreign log…",
  "seq": 12, "logged_at": 1785900000000, "entry_id": "…",
  "leaf":  "…Base64…",
  "entry": "…Base64…",
  "leaf_hash": "…64 hex characters…",
  "entry_status": "present",
  "payload_status": "absent",
  "mirrored": {
    "log": "…64 hex characters…",
    "base_url": "https://provenance.example.com",
    "sth": { "signed": "…Base64…", "decoded": { "size": 512, "ts": 1785903600000, … } },
    "inclusion": { "size": 512, "path": [ "…hex…", … ] },
    "sth_age": 5400000
  }
}
```

Without the marking a client could not tell a first-hand statement from a mirrored one — and the
difference matters, because the two are answered by different parties and go stale in different
ways. `base_url` is part of the marking and not decoration: it is the address at which a client
settles the freshness question for itself (§5.4).

A client MUST verify a mirrored entry against the foreign log's STH exactly as it would against the
origin — the full check of §6, with the foreign log's key and the foreign log's root hash.
**Mirroring grants no trust; it saves a round trip.** A node serving a mirrored entry whose proof
does not come out is caught by the very check it might have hoped would be skipped.

A node MAY also answer `GET /owm/v1/entries/{entry_id}` for a mirrored entry; if it does, the
response MUST carry the `mirrored` object. A mirrored entry MUST NOT be served through
`/owm/v1/leaves/{seq}`: sequence numbers are positions in *this* node's tree, and a foreign leaf has
none here.

### 5.4 What mirroring does not provide

A mirror cannot say whether the origin has since erased the payload or revoked the entry. It holds
what was true at the time of copying and nothing about the state now. A mirroring node therefore
MUST NOT assert that a mirrored entry is still unerased at the origin: nobody has signed such an
assertion, and it could not be checked.

A node SHOULD state the age of the mirrored STH — `sth_age` in §5.3, milliseconds since that STH was
issued. An entry proven against an STH from an hour ago says something different from the same entry
proven against one from last year, and a client that is shown the number can decide for itself
whether to go to `base_url` and ask.

The honest summary: mirroring makes a chain **readable** when its origin is unreachable. It does not
make it **current**. For provenance — statements about what happened in the past — readability is
usually what is wanted; for the question whether a certificate still holds today it is not enough,
and there is no way round the origin.

## 6. What a client must check

A client that trusts an answer of this API without computing for itself has given away the entire
evidential value of the system. The minimum check:

1. Re-encode `entry` and compare with the received bytes (canonicality, OWM-0 §6.4).
2. Check the signature of the entry against the issuer's public key (§4.9) and recompute that
   issuer's identifier from the key bytes.
3. Recompute `cmt` against `salt ‖ payload`.
4. Form the leaf hash from `leaf`, compute the inclusion proof against the root hash **of an STH**.
5. Check the STH signature against a key that hangs on the genesis key through the rotation chain,
   and `log` against the expected log identifier.
6. On repeated retrieval: consistency proof between the STH seen earlier and the present one.

Step 6 is the one most readily left out and the one least deserving to be. Without it a client does
not notice that the node has rewritten its history; with it, it notices on the next retrieval. And
even then: **a single observer cannot detect a split view in principle** (OWM-2 §9). That takes
OWM-5.

A mirrored entry (§5) goes through the same six steps, only against the foreign log's key and STH.
That it arrived by way of a third party changes nothing about the check — and if it changed
anything, mirroring would be a hole rather than a convenience.

## 7. Limits and abuse

| Limit | Value | Effect on exceeding |
|---|---|---|
| Leaf | 128 KiB | 413 |
| Payload | configurable, 256 KiB by default | 413 |
| Request body | 2 × (leaf + payload) | 413 |
| History per answer | 1000 entries | silently truncated |

A payload is a data record, not a file attachment: photographs, laboratory reports and certificates
belong behind a URL whose hash stands in the payload.

The cap on history per answer counts mirrored ancestors (§5) as well — an answer is bounded by what
it contains, not by whose log it came from.

Appending costs a signature check and a write; issuing an STH costs an ML-DSA signature. A publicly
reachable node SHOULD limit submission by volume. The protocol deliberately provides no mechanism
for it — rate limiting belongs in the reverse proxy, where it belongs, and a home-made substitute in
application code would be weaker.

Reading endpoints are unprotected and are meant to be. What they deliver is the purpose of the log.

## 8. Administration interface

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/v1/keys` | list the directory |
| POST | `/admin/v1/keys` | admit a key |
| GET | `/admin/v1/keys/{key_id}` | read a single record |
| POST | `/admin/v1/keys/{key_id}/disable` | disable a key |
| POST | `/admin/v1/erasures` | erase a payload |
| POST | `/admin/v1/sth` | issue an STH immediately |

### 8.1 No authentication — on purpose

The administration interface knows no login procedure. That is a decision, not an omission: access
protection belongs to the environment here — a locally bound address, a Unix socket behind a reverse
proxy, a VPN. A hand-knitted token scheme in application code would be weaker than what the
operating system and a fully grown proxy can do anyway, and it would pretend the question had been
settled.

From this follows a hard requirement: **a node MUST bind the administration interface to a local
address by default and MUST NOT put it unprotected on the open network.** Whoever reaches it can
admit keys and erase payloads.

### 8.2 Keys

`POST /admin/v1/keys` takes `{ "alg": "ML-DSA-65", "public": "…hex…", "label": "…", "parent": "…"
}`. Algorithm and key length are checked against each other: a length that does not fit the named
scheme is rejected rather than guessed at. Re-admitting the same key is not an error; the same
identifier with different bytes is one (409). The rules are in OWM-3 §5.

Disabling works forwards only. Old signatures stay valid — the reasoning is in OWM-3 §5.2.

### 8.3 Erasing

`POST /admin/v1/erasures` with `{ "entry_id": "…" }` erases payload and salt irretrievably and
appends the erasure witness. The response contains the tombstone as a leaf, so that the operator can
demonstrate that and when erasure took place.

The operation is final and **successful precisely because it cannot be undone** — that is its
purpose. What remains is the leaf in the tree; all STHs and inclusion proofs ever issued continue to
hold (OWM-2 §7).

The erasure of a `key_rotation` entry MUST be refused (OWM-2 §7.6).

### 8.4 Issuing an STH

`POST /admin/v1/sth` issues one immediately, independently of the configured interval. Useful for
tests and for witnessing the state before maintenance.

A node SHOULD issue STHs at a fixed interval even when nothing has been appended. The interval is
the upper bound on how long a manipulation can stay unnoticed — what was not signed cannot be pinned
down by an observer. Otherwise a silent log cannot be told apart from a halted one (OWM-9 A3).

## 9. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Node delivers a false `decoded` view | Client sees something other than what was signed | only the bytes are binding (§4.4, §6) |
| Node delivers a proof against an unsigned size | Proof against nothing | the default is the STH size (§4.7) |
| Node delivers the payload without the salt | Commitment not recomputable | the salt belongs in the same answer (§4.5) |
| Node withholds an entry | Submission disappears | at present only noticeable, not provable (§10) |
| Node shows two histories | Split view | not solvable client-side, see OWM-5 |
| Node calls an entry `pruned` in order to withhold it | Withholding looks like routine housekeeping | leaf hash and proofs stay available (§4.4, §4.7); whoever archived the entry proves its inclusion |
| Mirror passes a foreign entry off as first-hand | Copy taken for a statement of this node | mirrored entries are marked, with foreign `log_id` and STH (§5.3) |
| Mirror serves an entry the origin has since erased | Client sees evidence that no longer exists there | a mirror asserts nothing about the present; STH age, then ask the origin (§5.4) |
| Administration reachable from the network | Foreign keys, foreign erasures | local binding (§8.1) |
| Mass submission | Log fills up, signing load | limits §7, rate limiting in the proxy |

## 10. Open points

- **Receipts on appending**, analogous to the SCT in Certificate Transparency. Today the node
  acknowledges with the finished leaf, but without a signature of its own on the undertaking to
  include it. A submitter can therefore *notice* that their entry is missing, but not *prove* that
  the node had accepted it. Only a signed receipt with a committed deadline makes withholding
  provable (OWM-2 §9, last line).
- How far back a node's STHs reach is now bounded from below:
  [OWM-2 §10](owm-2-log.md#10-retention-and-pruning) requires every STH to be kept for at least the
  pruning period (§10.4). What stays open on the API side is whether the node description SHOULD
  name the oldest STH still retrievable, so that a monitor learns the span it can compare over
  without probing for it.
- How stale a mirrored STH may be before a node has to refresh it at the origin. §5.4 requires only
  that the age be stated, not that it be bounded — and a bound would have to come from the profile,
  because a cold chain and a certificate age at different speeds.
- Whether an erasure or a revocation at the origin should be pushed to known mirrors. A mirror holds
  no payload, but it does hold the signed entry, and OWM-2 §7.5 already records that an erasure does
  not reach foreign copies.
- Whether a third party who archived an entry may hand it back after pruning ("resurrection", OWM-2
  §11) — the leaf hash decides whether the copy is genuine, but this document specifies no endpoint
  through which it would arrive.
- Batch retrieval of several leaves in one answer, for monitors going through a whole log.
- Conditional retrieval (`ETag`, `If-None-Match`) for STHs, so that frequent polling becomes cheap.
