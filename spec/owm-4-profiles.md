<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 — Profile mechanism and the food profile `food.v1`

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md) · **Threat model:**
[OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose

**The core knows no industry semantics.** An entry carries a profile identifier such as `food.v1`;
what a `processing` event means and which fields it needs is laid down by the profile alone. New
industries arrive as a new profile, without anything in the data model changing.

Part A of this document describes the mechanism, part B the first profile.

---

# Part A — The mechanism

## 2. Profile identifier

The identifier sits in the field `prof` of the entry (OWM-0 §6) and is optional: an entry without
a profile is admissible and is not checked, because there is nothing to check.

Admissible are at most 64 characters from `a–z`, `0–9`, `.`, `/`, `-`, `_`. No capital letter, no
space, no free text — otherwise control characters or path components end up there sooner or
later. The slash allows namespaces (`eu/battery.v1`).

**The version belongs in the identifier.** Changes appear as `food.v2`, not as a modified
`food.v1`.

## 3. Immutability and schema digest

> A profile version is immutable. Once `food.v1` is published, its schema never changes again.

The reason is not tidiness. Were the schema to change, an entry from yesterday would be invalid
today although nobody touched it — and a monitor could no longer reconstruct what the node checked
against at the time. A log whose checking rules wander retroactively no longer witnesses anything
determinate.

This becomes checkable through the schema digest:

```
SchemaDigest = H("OWM/1 profile-schema", id, name₁, data₁, name₂, data₂, …)
```

`H` is the length-prefixed hash function from OWM-0 §3.3; the files go in **sorted by name**, each
with name and content, so that names and contents cannot be shifted into one another.

A node MUST publish the digest of the profiles it has loaded (OWM-7 §4.9). Two nodes that name the
same profile but report different digests check differently — and that belongs out in the open,
not hidden. The digest is the only way to establish it from outside.

## 4. Checking

A profile consists of a set of JSON Schema files (draft 2020-12) with one root schema, usually
`event.json`.

### 4.1 The payload is read strictly

The bytes of the payload are pinned down by the commitment. So every implementation MUST read them
the same way — otherwise two nodes check the same payload against different values. Beyond JSON,
therefore:

- **Duplicate object keys are an error.** One language takes the last value, another the first; the
  same bytes would then mean different things.
- **Text after the top-level value is an error.**
- **Nesting is limited to 32 levels.** The decoder runs recursively and the payload comes from
  outside; without a limit a chain of brackets suffices to kill the process. There is no supply
  chain event with thirty levels.
- **The top-level value MUST be an object.**

### 4.2 `format` is a check, not an annotation

In the JSON Schema standard `format` is without consequence by default. For a profile it is
exactly the check that counts: a timestamp that is not one belongs not in the log but in the error
message to the submitter. An implementation MUST enforce `format`.

### 4.3 No foreign schema sources

A `$ref` to a foreign URL would reach out to the network during compilation. An implementation
MUST reject that. A profile whose rules depend on a foreign server is no longer a pinned-down
profile — the digest from §3 would be worthless, because the rules actually applied could change
at any time without any file changing.

All `$ref` are relative and are resolved within the profile.

### 4.4 Rules over the entry

Some things cannot be expressed in the JSON schema, because the schema sees only the payload and
not the entry. A profile MAY therefore lay down additional rules that check both together. They
run only once the payload conforms to the schema.

The food profile uses exactly one such rule (§8).

## 5. What the check achieves — and what it does not

It is an **intake filter, not a statement about truth**. A schema-conformant entry can be a
complete lie: the schema checks form, not reality. It keeps typos, missing mandatory fields and
format mix-ups out of the log, so that the chain can be evaluated by machine later at all.

The division of labour, which must not be confused:

| Question | Answered by |
|---|---|
| Does the payload have the right form? | profile schema |
| Does the payload belong to exactly this entry? | commitment (OWM-0 §5) |
| Who stands behind it? | signature |
| Is it true? | nobody — see OWM-9, oracle problem |

## 6. Unknown profiles

A node MUST reject entries with a profile identifier it has not loaded — even when no commitment
is present and there would be nothing to check.

Rejecting a profile one cannot check is more honest than accepting it unchecked: the node then
claims nothing it cannot stand behind. In the federated model other nodes hold other profiles;
whoever wants to submit `eu/battery.v1` looks for a node that knows it. The node metadata
(OWM-7 §4.1) says in advance which those are.

---

# Part B — The food profile `food.v1`

## 7. Alignment with EPCIS 2.0

The events are modelled on GS1 EPCIS 2.0 rather than invented afresh. EPCIS is the language in
which trade and logistics already describe supply chain events. Whoever builds on it needs no
translation layer; whoever thinks up their own semantics has them for ever.

| `event` | EPCIS 2.0 | Meaning |
|---|---|---|
| `production` | ObjectEvent, action ADD, bizStep commissioning | a good comes into being: harvest, slaughter, catch, filling |
| `aggregation` | AggregationEvent, action ADD/DELETE | eggs into ten-packs, cartons onto a pallet |
| `transport` | ObjectEvent, action OBSERVE, bizStep shipping/receiving | departure or arrival |
| `processing` | TransformationEvent | milk from three farms becomes a wheel of cheese |
| `handover` | TransactionEvent | change of responsibility or ownership |
| `measurement` | sensorElementList | automatically recorded series of readings |

## 8. Event type and entry type

All six events share **one** profile identifier, and the event type sits in the payload, not in the
field `prof`.

That is deliberate. Were the event type in `prof`, it would still be visible after an erasure what
kind of event it had been — and from `handover` alone a good deal can be inferred. This way what
remains is that at some point there was a food event concerning a subject, and no more.

The one rule over the entry (§4.4) binds the event type to the entry type:

| `event` | required `typ` |
|---|---|
| `measurement` | `sensor_reading` (5) |
| all others | `assertion` (1) |

**A measurement is not a self-declaration.** It comes from a device and is signed by a device key.
Without this binding, a hand-written cold chain could later be passed off as sensor evidence — and
the whole value of a series of readings lies in its being able to **contradict** a human
self-declaration (OWM-9, oracle problem).

## 9. Structure of the schemas

`event.json` is the root schema. It requires `event` and `time`, allows `party`, `location` and
`note`, and switches in the subschema of the respective event through `if/then`.
`unevaluatedProperties: false` forbids everything that is provided for neither here nor there —
`additionalProperties` would be wrong at this point, because it would not see the fields of the
subschemas.

`defs.json` holds the shared building blocks: `subject`, `keyid`, `timestamp`, `date`, `text`,
`party`, `location`, `quantity`, `product`, `certification`, `item`.

### 9.1 Three times that must not be confused

| Field | Where | Meaning |
|---|---|---|
| `time` | payload | point in time of the event **in reality** |
| `iat` | entry | when the issuer made the statement |
| `ts` | leaf | when the node took it in |

That they may diverge is the point: a backdated event can be recognised by its time of intake
(OWM-2 §3.1).

### 9.2 Connection to existing identification systems

The profile uses GS1 identifiers where they exist — `gtin` for the goods, `gln` for business and
place — and UN/CEFACT Recommendation 20 for units (`KGM`, `LTR`, `CEL`, `H87`). Country codes per
ISO 3166-1 alpha-2.

That is the same consideration as with EPCIS: a business that keeps GTINs anyway should not have
to translate them into a second system.

## 10. How the chain arises

The chaining is achieved **not** by the profile but by the field `par` of the entry (OWM-0 §6.2).
The profile only describes what happened at a step.

- **Aggregation** groups together and can be undone again (`action: add` / `delete`). The subject
  of the entry is the superordinate unit, the constituents are listed in `children`.
- **Processing** goes further: the inputs perish, they cannot be taken apart again. The origin
  nevertheless stays traceable, because the inputs are listed in `par`.

A reference in `par` may point into a **foreign** log; `log_id` then names it. That is how a chain
runs across company boundaries without one node having to hold another's data.

**Transport is in two parts.** Departure and arrival are two entries, usually issued by two
different parties. The agreement between the two statements is part of the evidence — which is why
the arrival is not a field in the departure event.

**Handover is an event of its own**, not a side field of transport. It is the place where a chain
usually breaks.

### 10.1 Subject granularity

A profile MUST lay down at which level the subject of an entry sits, and there are two:

| Level | Subject | EPCIS |
|---|---|---|
| class level | a lot | LGTIN |
| instance level | an individual item | SGTIN |

The decision governs the size of the log more strongly than any crypto parameter. A laying farm
with 10 000 hens produces about 300 000 ten-packs a year; at five events per pack that is 1.5
million entries, at lot level about 5000. Factor 300, from one decision.

The rule: **instance level only where item identity carries real value.** That value is
anti-counterfeiting — the ability to tell two physically identical items apart and to notice that
one identifier appears twice. For a diamond, a pharmaceutical or a spare part with a safety
function that is worth the cost; for an egg it is not, because the consumer's question ("which
farm, organic, cold chain kept?") is answered in full by the lot.

For `food.v1` the subject is therefore the **lot** by default. An implementation MAY serialise
individual items; it SHOULD NOT do so without a reason it can name.

The consequences for the log's storage requirement, and what a node does with old entries, are in
[OWM-2 §10](owm-2-log.md#10-retention-and-pruning).

## 11. Claim and confirmation

`production.certifications` is expressly **what the producer claims**. A claim, not a check.

It is confirmed only by an `attestation` entry of the certification body over the producer's key
(OWM-0 §6.1). A client that displays an organic seal MUST keep the two apart and SHOULD mark
unconfirmed self-declarations as such. How a trust level arises from attestations is in OWM-6.

The same holds for `transport.conditions`: those are **promised** carriage conditions. Whether
they were kept is what the `measurement` entries say — not this field.

## 12. Series of readings

`measurement` requires `sensor`, `quantity_kind`, `unit` and `readings` (up to 4096 value pairs of
point in time and number). `sensor.key` names the key identifier of the device; its trust level is
capped by that of its operator (OWM-3 §7, OWM-6).

At fine resolution the number of entries becomes a storage problem. The lever against it sits with
the issuer and is described in OWM-2 §8: whoever produces many readings of the same kind builds a
Merkle tree from them themselves, puts its root into **one** payload and writes **one** entry with
**one** signature. The individual value is shown through an inclusion proof in that subtree, which
lies off-chain next to the payload. 8640 readings of a day thus become one entry instead of 8640.

For `food.v1`: the bundling is **not** part of the schema. A bundled set of readings is transmitted
as a payload form of its own, whose definition is open (§14). Until then `readings` carries the
values directly, and the limit of 4096 is the practical upper bound of an entry.

## 13. Data protection in the profile

The hard rule from OWM-0 §2 applies here too, and the profile is cut to fit it:

- **`party` knows only businesses.** Names of natural persons do not belong in it. There is no
  field for a contact person, and that is not an oversight.
- **All fields of the payload are erasable**, because they lie behind the commitment. What remains
  is subject ID, issuer, times, profile identifier, entry type and predecessors (OWM-2 §7.4).
- **`location.geo` is a borderline case.** A coordinate to three decimal places can be relatable to
  a person in the case of a single business. It lies in the payload and is therefore erasable;
  whoever does not collect it in the first place is better off. Data minimisation is the actual
  measure, not erasure afterwards.
- Where linkability through the subject ID does harm, it MUST be chosen at random and MUST NOT be
  derived from the GTIN (OWM-0 §4.2). See OWM-9 A10 for what a derived identifier discloses.

## 14. Open points

- **Payload form for bundled series of readings** (§12): root hash, tree construction and the form
  of the off-chain proof are not laid down yet. Until then `readings` stands.
- **No revocation event in the profile.** A wrong event is withdrawn through a `revocation` entry
  of the core, not through a profile field. Whether that suffices in practice remains to be seen.
- Mapping to existing code lists for `process` in `processing` — currently free text.
- `eu/battery.v1` as the second profile (EU battery passport, mandatory from February 2027). It is
  the real test of whether the mechanism is industry-agnostic: if the core has to be touched for
  it, part A has failed.
- [`pharma.v1`](owm-4-pharma.md) — spec drafted, not implemented. A second, independent data point
  for the same test: six of its eight events are `food.v1`'s, unchanged, and the two genuinely new
  ones (a batch-release certification, a unit decommissioning) needed nothing from the core either
  — only new profile-level payload shape. No core change either time is starting to look less like
  luck and more like the mechanism actually working as designed.

## 15. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Node silently changes its schema | checks differently from what it claims | schema digest (§3) |
| `$ref` to a foreign server | rules changeable from outside | no foreign sources (§4.3) |
| Duplicate keys in the payload | two readings of the same bytes | strict reading (§4.1) |
| Deeply nested payload | node dies on the stack | depth limit 32 (§4.1) |
| Hand-written cold chain as sensor evidence | false evidentiary weight | binding to `sensor_reading` (§8) |
| Event type in the field `prof` | reveals after erasure what happened | one identifier for all events (§8) |
| Self-declaration looks like a certificate | pretence of checked provenance | separation of claim and attestation (§11) |
| Subject ID derived from the GTIN | lot structure and volumes enumerable | random subject ID where it does harm (§13, OWM-9 A10) |
