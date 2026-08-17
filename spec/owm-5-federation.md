<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-5 — Federation: discovery and gossip

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md), [OWM-2](owm-2-log.md),
[OWM-3](owm-3-keys.md), [OWM-7](owm-7-node-api.md) · **Threat model:** [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

This document answers three questions:

1. How is a node found from a domain name (discovery)?
2. How do nodes exchange Signed Tree Heads with each other, and with independent observers
   (gossip)?
3. What must an independent monitor do to be worth relying on (the monitor contract)?

**What this document does not govern:** whether or how a monitor gets paid for what it finds — that
is deliberately deferred to the deposit system (OWM-9 §6.2, E7/E8; there is no code for it yet, and
this document assumes there may never be, since watching can be made attractive but not compelled).
Nor does it introduce any replication of data between nodes: a node stays authoritative for its own
log and its own participants (OWM-0 §2); what crosses between nodes here is Signed Tree Heads and
proofs about them, never entries or payloads.

## 2. DNS discovery

### 2.1 The `_openwaymark` TXT record

A node announces itself under its operator's domain:

```
_openwaymark.example.com.  IN TXT  "v=owm1; node=https://provenance.example.com"
```

- The label MUST be `_openwaymark`, not a generic term such as `_provenance` — a generic label
  invites collision with an unrelated project's use of the same name (OWM-0 §7). It is intended for
  registration with IANA under RFC 8552; until then it is used as a de-facto convention.
- The record MUST begin with the tag `v=owm1;`. The tag is what makes the record
  **self-identifying**: a resolver can tell an OpenWaymark record apart from an unrelated TXT record
  that some other application also happens to publish at the same name. A record without this tag,
  or with a different version tag, MUST be ignored, not guessed at.
- `node=` MUST be an absolute `https://` URL — the node's base URL, the same value it reports as
  `base_url` in its own metadata (§2.2).
- Further `key=value` pairs after `node=` MAY appear and MUST be ignored by a resolver that does not
  recognise them — the same forward-compatibility rule as the entry format's unknown-field handling.
- **Zero matching records** at the name means the domain runs no OpenWaymark node (or the record is
  missing/misconfigured) — not an error condition to retry indefinitely, just "not found."
- **More than one** record starting with `v=owm1;` at the same name is a misconfiguration and MUST
  be treated as an error, not resolved by picking one. Silently accepting the first one found would
  let whoever can add a second TXT record at that name redirect discovery without the legitimate
  operator noticing.
- DNSSEC is not required and not assumed. Discovery's role is only to locate a base URL; nothing
  about the record itself is trusted cryptographically — the node's actual signing key is obtained
  and trusted per §2.2, not from the DNS response. An attacker who can spoof DNS without DNSSEC can
  at most point discovery at the wrong `https://` URL, which then fails to present a log whose
  `.well-known` matches what the caller already expected (log ID, if pinned) or is caught by TLS
  certificate validation for a URL the attacker does not control.

### 2.2 Node description

The second half of discovery is `GET /.well-known/openwaymark`, fully specified in
[OWM-7 §4.1](owm-7-node-api.md#41-description-of-the-node). Restated here only for how it composes
with §2.1: the TXT record gives a base URL, `.well-known` at that URL gives the node's current log
ID, signing key and genesis key.

This response is **unauthenticated by design** — it carries no signature of its own. Trust in it
rides entirely on having reached `base_url` over TLS, exactly the same trust boundary as a
certificate transparency log's own HTTPS endpoint. There is no additional PKI layer for node
identity: whoever controls the domain and its TLS certificate controls what `.well-known` says.
Everything downstream of it (STHs, proofs, entries) is then held to a much higher standard —
individually signed and independently checkable — which is precisely why this one step is allowed
to be the comparatively weak link: it only ever hands out a *starting point* to verify from, never a
statement that has to be trusted on its own.

### 2.3 Fallback registry

Participants without a domain of their own are meant to be referred to a community node through a
lightweight fallback registry (OWM-0 §3.1) that itself holds no product data — comparable to a DNS
root server's role. **Not specified here and not implemented.** Who operates it in the long run and
how it is funded is an open point (CLAUDE.md §9); this document reserves the name and the role but
does not fix a protocol for it yet.

## 3. Gossip

### 3.1 What gossip is and is not

Gossip in OpenWaymark exists for exactly one purpose: making a node's **self-contradiction**
detectable. It is not a synchronisation mechanism, not a way to replicate entries between nodes, and
not a way for one node to verify another's claims about physical reality — no exchange protocol
closes the oracle problem (OWM-9 A4). What it closes is narrower and mechanical: a node that signs
two different tree states for the same size has produced non-repudiable proof of misbehaviour
against itself, but **only if some second observer has a copy of the first statement to compare
against.** Full reasoning: [OWM-9 A1](owm-9-threat-model.md#a1--split-view--the-central-attack).

### 3.2 Targeted partner gossip

Nodes SHOULD poll the latest STH of their actual supply chain partners — the nodes they exchange
entries with — at a regular interval. This is where the interest and the context already sit: a
buyer has direct reason to notice if a supplier's log becomes internally inconsistent, and the
polling effort stays proportional to a real business relationship instead of scaling with the size
of the whole network.

### 3.3 STH gossip to independent monitors

Targeted partner gossip alone leaves a gap: it cannot catch a split view aimed at an **outsider**,
because the partners, by construction, both see the same view a dishonest node chooses to show them.
Closing that gap needs an observer the node cannot single out — an **independent monitor**
(`monitor/`) with no business relationship to the observed node, polling the same endpoint from
outside. Both mechanisms are needed; neither substitutes for the other.

An operational consequence follows directly: a monitor that is recognisable as one (a dedicated IP
range, a predictable request pattern, an operator's own advance notice) lets a dishonest node simply
maintain a third, separate, permanently-consistent view reserved just for it — defeating the whole
point. Nothing in this protocol enforces indistinguishability; it is a property of how a monitor is
run, not of the wire format.

### 3.4 Polling behaviour

A gossip participant (a partner node or a monitor) watching a target log:

1. Fetches the target's latest STH: `GET /owm/v1/sth` (unversioned — always the newest, never a
   specific historical size).
2. Resolves the STH's signing key **fresh, on every poll**, via `GET /owm/v1/keys/{id}` rather than
   caching the key obtained from `.well-known` (§2.2) at first discovery. This is deliberate: a key
   rotation ([OWM-3 §6](owm-3-keys.md)) then requires no coordination with gossip participants at
   all — the next poll simply resolves the new key through the same directory lookup that already
   has to happen. `GET /owm/v1/keys/{id}` recomputes the key's identifier from the returned bytes
   rather than trusting a claimed identifier in the response, so a mismatched key cannot be smuggled
   through this step.
3. Verifies the STH's signature against that key. An STH that does not verify is discarded, not
   compared — it is not evidence of anything, only of a malformed or unreachable response.
4. Compares the newly fetched, verified STH against the last one this participant verified for the
   same log (OWM-2 §9's table, restated by reference, not duplicated here):
   - same `size`, different `root` → split view.
   - later `size` smaller than an earlier one → the tree shrank.
   - `size` grew: additionally fetches `GET /owm/v1/proof/consistency?old=…&new=…` and verifies it
     against both STHs' roots. A proof that does not verify is exactly as serious a finding as a
     split view — the tree changed in a way that is not a pure append.
5. A finding from step 4 MUST be treated as non-repudiable evidence — the node signed both
   statements itself — and MUST NOT be silently discarded (§4).

**What does not count as a finding**: a failed fetch (network error, non-2xx response, malformed
body), or a consistency proof request that fails because the requested old size has since been
pruned past a node's retention window ([OWM-2 §10](owm-2-log.md#10-retention-and-pruning)). Both are
a reduction in coverage for that cycle, not evidence of misbehaviour, and MUST be retried on the next
poll without discarding the last-known-good state.

This is a **pull-only** design. No push or webhook mechanism is specified; a target being polled has
no way to know which of its observers, if any, are watching at a given moment, and that is
intentional (§3.3).

### 3.5 Limits

Detection is not prevention. A split view is uncovered only after the fact, and only within the
window between when it happened and the next successful poll of an observer who happened to be
watching. Whoever needs a shorter window has exactly one lever: poll more often. There is no way
around this that does not reintroduce a form of global consensus (OWM-0 §2's reasoning for rejecting
one applies here too).

## 4. The independent monitor's contract

A conformant monitor:

- Polls every configured target per §3.4, on a regular interval, without gaps it can avoid.
- Verifies signatures and proofs itself — it MUST NOT trust a target's own claim that something
  checks out.
- On a finding, MUST retain the raw evidence: the two conflicting `SignedSTH` (or the STH pair and
  the failing consistency proof) that together constitute the non-repudiable proof. Losing this on
  a restart or discarding it after only logging a message defeats the purpose — the finding is only
  as good as the bytes that back it up.
- MUST surface a finding to its operator. How (a log line, a file, an external alert) is an
  operational choice, not a protocol requirement.

Explicitly out of scope for a monitor under this document: arbitrating disputes, reporting to a
third party, and any notion of being paid for what it finds (§1).

## 5. Interop notes for third-party implementations

The entire interop surface for federation is: the `_openwaymark` TXT record (§2.1), the
`.well-known/openwaymark` response shape (OWM-7 §4.1), and the three HTTP endpoints `GET
/owm/v1/sth`, `GET /owm/v1/keys/{id}`, `GET /owm/v1/proof/consistency` (OWM-7 §3) — all already
required for a conformant node regardless of E4. Poll interval, how findings are stored, and how
they are surfaced are deliberately left as operational choices, not normative requirements: nothing
about interop between two independent implementations depends on them matching.
