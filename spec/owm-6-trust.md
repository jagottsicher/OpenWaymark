<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-6 — Trust levels and attestation

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md), [OWM-3](owm-3-keys.md) ·
**Threat model:** [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

This document answers three questions:

1. How verified is the entity behind a key — the **entity trust level**?
2. How forgery-resistant is a product's physical-digital binding — the **binding trust level**?
3. How do the two combine into the trust level of an entire supply chain?

**What this document does not govern:** whether verification pays off economically. A closed,
non-tradable deposit system that ties initial balance and a Sybil-resistant bonus cap to the
entity trust level is design intent for stages E7/E8 — deliberately deferred, no code, start
condition explicitly at least two independently operated nodes carrying real data. This document
makes the trust level *computable*; what, if anything, is paid for reaching one is a separate,
later question. See [OWM-9 A7](owm-9-threat-model.md#a7--sybil-attack) for why the bonus formula
itself is not, and never can be, the actual Sybil defence — that defence is the cost of the
verification this document describes.

Also out of scope: automating the recognition of accreditation bodies (§8 names this explicitly as
a real-world governance question, not a protocol mechanism this document can settle in code).

## 2. Entity trust level

Seven levels, 0 through 6, each strictly requiring the evidence class of the level below:

| Level | Evidence |
|---|---|
| 0 | No verification |
| 1 | Email confirmed |
| 2 | Domain control (DNS TXT record) |
| 3 | Trade/company register record (e.g. Gewerbeanmeldung, Handelsregisterauszug) |
| 4 | Industry certification by an independent third party (organic seal, ISO, etc.) |
| 5 | State or official accreditation with regular inspection |
| 6 | A state body itself |

A level is never self-declared. It is **computed** by a verifier — a node's own optional
convenience lookup (§6), or a future client — by walking a chain of `attestation` entries
(OWM-0 §6.1) back to a locally recognised accreditation root (§8). Nothing in the protocol
prevents an entity from *claiming* any level in an ordinary `assertion`; such a claim is exactly
as trustworthy as any other unattested self-declaration (OWM-9 A4) — worth nothing until an
independent attestation chain backs it.

[OWM-9 §3](owm-9-threat-model.md#3-explicit-non-goals) states the reason this system rests on
identifiability rather than anonymity: "Only level 0 is anonymous, and by definition it is worth
nothing."

## 3. Attestation entries

An `attestation` entry (`typ = attestation`, OWM-0 §6.1) is the sole mechanism by which a trust
level or a sensor's operator binding becomes part of the log:

```
typ  = attestation
subj = KeyID of the party being attested
iss  = KeyID of the attesting party
cmt  = commitment over the payload
```

The payload has three shapes, distinguished by `kind`:

**`kind: "entity"`** — an entity trust-level claim:

```json
{
  "kind": "entity",
  "level": 4,
  "scheme": "iso17065",
  "evidence_url": "https://example-cert-body.org/cert/12345"
}
```

- `level` MUST be an integer 0–6 (§2). A verifier MUST reject any other value.
- `scheme` SHOULD name the evidence class as concretely as practical (`"iso17065"`,
  `"handelsregister"`, `"dns-txt"`, `"email"`, …) — free text, not a closed enumeration, since new
  accreditation schemes will appear without a protocol version bump.
- `evidence_url` MAY point at supporting material off-chain. It is informational only; a verifier
  MUST NOT treat its mere presence as evidence — only the issuer's own computed trust level
  backs the claim (§7).

**`kind: "sensor"`** — a sensor certificate (§4):

```json
{
  "kind": "sensor",
  "label": "Cold-chain logger, unit TW-7"
}
```

- `label` is purely descriptive, the same free-text convention as a key directory label
  (OWM-3 §5), and carries no protocol meaning.
- `level` MUST be absent — a sensor's level is never claimed, only inherited (§4).

**`kind: "concluded"`** — the issuer's own participation under this key has ended (OWM-9 A15):

```json
{
  "kind": "concluded",
  "reason": "succeeded",
  "successor": "5c8f4a3b2e1d0c9b8a7f6e5d4c3b2a190807060504030201f0e1d2c3b4a59687",
  "evidence_url": "https://example.org/merger-notice"
}
```

- `reason` MUST be `"succeeded"` (a different, already independently operating key continues the
  business) or `"discontinued"` (participation simply ended, no successor). A verifier MUST reject
  any other value.
- `successor` (a `KeyID`) MUST be present when `reason` is `"succeeded"` and MUST be absent when
  `reason` is `"discontinued"`.
- `evidence_url` MAY point at supporting material off-chain, the same informational-only convention
  as `kind: "entity"`'s own field — nothing here is verified by the protocol, only made
  attributable and attackable-by-critique.
- `subj` MUST equal `iss` — a `kind: "concluded"` attestation MUST be self-issued. Only the
  keyholder can attributably say their own participation has ended; anyone else's say-so is a
  rumour, not evidence. A verifier MUST reject one where they differ.

This is deliberately not a claim §6's computation has to interpret: `successor` is a pointer for a
*reader* to follow, not an input to anyone's trust level. §6's algorithm gives `kind: "concluded"`
no case of its own for exactly this reason — a self-issued attestation is
already inert to it (self-referential attestations resolve through the same cycle handling that
makes any self-attestation contribute nothing), so treating it like an unfamiliar `kind: "entity"`
claim without a `level` already yields the one correct answer: no contribution, by construction,
not by a special rule that has to be kept in sync with this one.

A verifier MUST reject an attestation payload naming any `kind` other than `entity`, `sensor` or
`concluded`, and MUST reject `kind: "entity"` without a valid `level`, `kind: "sensor"` carrying
one, or `kind: "concluded"` with an invalid `reason` or a `successor` that does not match it.

**Why not a schema profile.** Attestation entries carry `Profile == ""` (the empty string) and
their payload is validated against the fixed shape above directly, not through the profile
mechanism (OWM-4). Trust levels are cross-industry protocol infrastructure, the same category as
`key_rotation` — not an opt-in industry vertical like `food.v1`. Gating them behind a profile
identifier would mean a node has to explicitly load a "trust" profile before attestations work at
all, which is wrong for something every node needs regardless of which industries it serves.

## 4. Sensor certificates

Restating and finalising [OWM-3 §7](owm-3-keys.md#7-sensor-keys) normatively:

A sensor receives its own key pair when put into service and is admitted to the node's key
directory like any other key (OWM-3 §5) — nothing about *registering* a sensor key differs from
registering any other. What is new here is the **public, in-log, attributable statement** binding
that key to its operator, which the directory admission alone does not provide (the directory is
local to one node and, per OWM-3 §5.3, deliberately not listed publicly).

That binding is a `kind: "sensor"` attestation: `iss` = a key the operator controls, `subj` = the
sensor's KeyID. The issuer key is **not** required to be the node's own log-signing key
specifically — an operator MAY use a separate key for issuing attestations, the same way a node's
signing key and genesis key are already kept apart (OWM-3 §4) for unrelated reasons. What matters
is that the issuer is verifiably the same operator elsewhere trusted, not which of the operator's
keys happened to sign.

A sensor's entity trust level is not claimed and has no `level` field of its own — it is **capped
by its operator's own computed level** (§7): an operator verified only to level 2 cannot mint a
level-6 sensor by attesting one.

## 5. Physical-digital binding trust level

Four levels, increasing forgery resistance:

| Level | Method | Forgery resistance |
|---|---|---|
| Low | Printed static QR code | Easily copied |
| Medium | Single-use serial code, scan-locked after first redemption | Race-condition-prone |
| High | NFC/RFID chip with challenge-response signature | Practically unclonable |
| Very high | Physical Unclonable Function (PUF) + chip signature | Physically unclonable |

Unlike the entity trust level, this document does not define a wire mechanism for asserting a
binding level — it fixes the vocabulary (this table) and leaves attaching it to a physical item to
whichever schema profile declares it. No profile does yet: `food.v1` is immutable once shipped
(OWM-4 §3), so wiring this in is `food.v2` or later, out of scope here. A client MUST display
whichever binding level a profile does supply rather than defaulting silently to a stronger one
than what was actually used ([OWM-9 A8](owm-9-threat-model.md#a8--physical-substitution-or-cloning)).

## 6. Computing a level

A verifier computing the entity trust level of a `KeyID`:

1. If the key is itself a recognised accreditation root (§8), its level is that root's own
   `MaxLevel` — computation stops here.
2. Otherwise, collect every unrevoked `kind: "entity"` attestation naming this key as `subj`.
3. For each, recursively compute the issuer's own level, then take `min(claimed level, issuer's
   computed level)` — an issuer verified only to level 3 cannot vouch a subject past level 3,
   regardless of what the attestation claims.
4. The key's level is the **maximum** across all such attestations — several independent
   attestations only ever help, never hurt (this is why a self-attestation, `iss == subj`, is
   harmless rather than requiring a special rejection: it can only ever produce `min(claimed,
   0) == 0` for a key with no other backing, or add nothing to a key that already has a stronger
   path).
5. Absent any attestation at all, or any of the above never reaching a root, the level is 0.

**Revocation.** A `revocation` entry (OWM-0 §6.1) defeats an attestation for the purpose of this
computation only when it names the same `subj` and comes from the **same** `iss` as the
attestation it revokes — a revocation from a different issuer is a separate, unrelated claim about
the same subject, not a defeat of someone else's attestation. This is an interpretive convention a
verifier applies when walking the log; it is not enforced as a submission-time rule, the same way
the log records claims generally without judging their content (OWM-9 A4).

**Cycles and depth.** An attestation graph among colluding keys can contain a cycle; a verifier
MUST detect this (e.g. by tracking keys currently being resolved) and MUST treat a cycle as
contributing nothing, not as an error that aborts the whole computation. A verifier MUST also
bound the chain depth it is willing to walk (a depth of at least 16 SHOULD be supported) and MUST
treat truncation past that bound as "no further contribution", not as a fatal error — an
adversarial chain being long is not a reason to let it deny service to a verifier resolving an
unrelated key.

**Kind `sensor`.** A `kind: "sensor"` attestation's subject inherits the issuer's computed level
directly (§4) — it does not go through the `min(claimed, issuer)` step above, since it makes no
level claim of its own to cap.

**Kind `concluded`.** Never contributes to a level (§3) — a self-issued statement about the
issuer's own participation ending is not a trust claim of any kind to begin with, and requires no
dedicated step in this algorithm to exclude: being self-issued (`subj == iss`, enforced at
submission), its own recursive lookup in step 3 immediately hits the same-key-already-being-resolved
case in the cycles rule above, which already yields "no contribution."

**Implementation.** Package `trust` (Apache-2.0) implements this algorithm as a pure function over
caller-supplied data — no I/O, no state of its own (OWM-9 A11's trusted-local-data split). A node
optionally exposes it as a convenience over its own log at
[`GET /owm/v1/keys/{id}/trust`](owm-7-node-api.md#411-trust-level-of-a-key), with the same
unauthenticated, non-evidentiary status as every other node-computed answer.

## 7. Minimum principle

The overall trust level of a supply chain is the **lowest** level among every participating
entity and every physical-digital binding involved — reported as the pair `(entity, binding)`,
not collapsed into one scalar, since the two dimensions are not on a shared scale.

One weakly verified participant or one low-grade binding drags the whole chain's reported level
down to its own, even if every other participant and binding involved is highly verified. A sensor
registered only through a website check pulls the entire chain's entity dimension down to that
sensor's own (capped, per §4) level.

## 8. Accreditation-root recognition

CLAUDE.md's governance intent — "an open, documented accreditation procedure modelled on the
CA/Browser Forum; any body that demonstrably meets fixed, publicly inspectable criteria is
recognised automatically" — is a real-world governance process, not something this document
specifies as a protocol mechanism. Automating "any ISO 17065-accredited body is recognised" in
code would misrepresent what the software actually verifies: a real accreditation-body audit,
which no amount of Go code performs.

What this document specifies instead, deliberately minimal: a verifier consults a **local,
operator- (or client-user-) supplied list** of recognised roots — the same shape as a browser's
root certificate store — each entry naming a `KeyID`, a display name, and a `MaxLevel` ceiling
(a root recognised only up to level 4 cannot back a level-6 claim just because it appears in the
list). Populating, reviewing and propagating that list is left as an operational and, eventually,
governance question — explicitly not solved here. A verifier with an empty root list computes
level 0 for everyone, which is the correct, safe default: "worth nothing" (§2) until an operator
actively decides otherwise.

## 9. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Self-attestation | none | contributes at most `min(claimed, 0) = 0` unless independently backed (§6) |
| Attestation cycle among colluding keys | denial of service if unhandled | cycle detection, treated as no contribution, not an error (§6) |
| Deep adversarial attestation chain | denial of service if unhandled | bounded chain depth, truncation is not fatal (§6) |
| Forged root in a verifier's local list | arbitrary trust level, entirely local to that verifier | root list is operator/user-controlled, not protocol-distributed; compromise is a local configuration failure, not a protocol one |
| Revocation from an unrelated issuer misread as defeating an attestation | trust level wrongly lowered or unaffected | revocation only defeats an attestation from the *same* issuer (§6) |
| Sensor attested past its operator's own level | inflated sensor trust | sensor level is capped by, never exceeds, the issuer's own computed level (§4, §6) |
