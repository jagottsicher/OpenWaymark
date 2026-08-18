<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Pharmaceutical supply chain `pharma.v1`

**Status:** draft, not yet implemented · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) (the mechanism this profile is built on) ·
**See also:** [OWM-6](owm-6-trust.md) (claim vs. confirmation), [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

This document is a profile specification in the sense OWM-4 Part A defines, structured in parallel
to OWM-4 Part B (`food.v1`) — same mechanism, same six events wherever the underlying shape
matches, extended only where the pharmaceutical domain genuinely needs something food does not.
That the extension turns out small is itself a finding: it is further evidence, alongside
`food.v1`, that Part A's promise — "new industries arrive as a new profile, without anything in the
data model changing" — holds.

**Implementation status: none.** No `profiles/pharma/` package, no JSON Schema, no code. This
document fixes the event taxonomy and field-level design so that implementation, when it happens,
does not have to re-derive it.

## 1. Purpose and scope

Covers the pharmaceutical supply chain from the **API starting material** (ICH Q7) through
**intermediates**, the **active pharmaceutical ingredient (API)**, the **finished dosage form**
(tablet, capsule, vial, …), and its distribution to the point of dispensing — manufacturer,
wholesaler, distributor, pharmacy or hospital.

**Explicitly out of scope, and this is a hard boundary, not an oversight:**

- **Dispensing to an individual patient, and anything about a named patient.** This profile stops
  at the pharmacy or hospital as an *entity*. What happens to a specific pack once it is handed to
  a specific patient is medical data, not supply chain data, and does not belong in an
  append-only log under any circumstance (§11).
- **Clinical trials and pharmacovigilance (adverse-event reporting).** Different regulatory regime
  entirely (in the EU: Regulation (EU) No 536/2014 and the pharmacovigilance provisions of
  Directive 2001/83/EC), different data subjects, different retention rules. A future profile's
  problem, not this one's.
- **Prescribing.** A clinical decision, not a supply chain event.

## 2. Regulatory grounding

Unlike `food.v1`, which aligns with one voluntary industry standard (GS1 EPCIS 2.0), this profile
sits on top of several **legally binding** regimes that already mandate large parts of the shape
described here. That changes the argument for building it: this is not "a plausible future
standard," it is "digitizing paper trails multiple jurisdictions already require by law."

| Regime | Jurisdiction | Covers | Status |
|---|---|---|---|
| DSCSA (Drug Supply Chain Security Act) | US | Unit-level serialization (GTIN + serial + lot + expiry), transaction data (T3: history/information/statement) at each change of ownership | In force; manufacturer/wholesaler/large-dispenser exemptions expired 2025, small dispensers exempt until Nov. 2026 |
| FMD (Falsified Medicines Directive, 2011/62/EU) + EMVS | EU | 2D data-matrix per pack (GTIN, serial, batch, expiry) plus an anti-tampering device, verified against a central repository at dispensing | In force since 2019 |
| EU GDP Guidelines (2013/C 343/01) | EU | Good Distribution Practice: temperature-controlled transport, validated equipment, deviation/CAPA handling | In force |
| ICH Q7 | Global (adopted by FDA, EMA, and others) | GMP for APIs: starting material → intermediate → API, batch documentation, traceability | In force |
| WHO TRS 961, Annex 9, Supplement 8 | Global (WHO GDP guidance) | Temperature mapping of storage areas, methodologically distinct from transport mapping | In force, widely adopted as reference practice |
| GS1 "Applying GS1 System of Standards for DSCSA and Traceability" | US (GS1 US implementation guideline) | The actual, already-published bridge between DSCSA's legal text and EPCIS/CBV events — lot-level and serialized-item event specifications both covered | Current release in active use |
| EU Pharmaceutical Package (recast of Directive 2001/83/EC and Regulation (EC) No 726/2004) | EU | Comprehensive reform of EU pharma law | Political agreement Dec. 2025, texts confirmed by COREPER I March 2026. **Not analyzed here** — nothing found in this research pass details its traceability/serialization provisions specifically. Tracked as an open point (§12), not a design input yet. |

**None of these regimes is reproduced normatively here.** This profile's schema is checked, per
OWM-4 §5, against *form*, not against legal compliance — a schema-conformant entry can still be a
regulatory violation the schema cannot see. What this profile aims for is a shape into which the
data these regimes already require can be put, verifiably and tamper-evidently, not a compliance
engine for any one of them.

**The GS1 guideline is worth dwelling on, because it changes the nature of the claim `food.v1`
already made for EPCIS alignment.** `food.v1` argued that building on EPCIS avoids inventing a
translation layer for an industry that already speaks it. For pharma, that argument is no longer
just plausible — GS1 US has already published the concrete cross-walk from DSCSA's legal
requirements to EPCIS/CBV events, covering both lot-level and fully serialized item-level cases.
`pharma.v1`'s event set is deliberately shaped to be expressible against that same cross-walk, not
against a from-scratch reading of the statute. That this is also where the commercial market
already lives reinforces the point rather than being a separate one: TraceLink alone reports
processing billions of DSCSA transactions for the large majority of top global pharma
manufacturers, alongside SAP ATTP, rfxcel/Antares Vision, Systech and others — all exchanging
EPCIS-shaped data today. `pharma.v1` is not proposing a data model the industry would have to
learn; it is proposing a tamper-evident log for the shape of data it already produces.

**Vaccines are a flagship case within this profile, not a separate one.** They fit as ordinary
`finished_product`-stage doses — nothing about the model changes for them — but the fraud patterns
motivating this profile at all show up here in a particularly sharp, current form. WHO has publicly
warned of counterfeit COVID-19 vaccines sold on the dark web, and — the pattern this profile's
design speaks to most directly — of vaccines "being diverted and reintroduced into the supply
chain, with no guarantee that [the] cold chain has been maintained," alongside reports of criminal
groups **reusing emptied vaccine vials**
([Healthcare IT News, citing WHO](https://www.healthcareitnews.com/news/who-warns-about-fake-covid-19-vaccines-dark-web)).
Pfizer separately identified counterfeit COVID-19 vaccine in Mexico and Poland
([CBS News](https://www.cbsnews.com/amp/news/pfizer-vaccine-fake-covid-19-vaccine-counterfeit-mexico-poland/)),
and country-level alerts continue: Zimbabwe's medicines regulator warned of a falsified rabies
vaccine distributed through unauthorized channels in January 2025
([allAfrica](https://allafrica.com/stories/202501230026.html)). Two of these patterns map onto
specific parts of this design, not onto a vaccine-specific mechanism: **diversion with a broken
cold chain** is exactly the promise/observation mismatch §7 already detects, and **reused emptied
vials** is what `decommission` (§3, §9) exists to make detectable.

## 3. Events

Nine events, sharing one profile identifier (`pharma.v1`) in the payload's `event` field — the
same reasoning as `food.v1` §8: keeping the event type out of `prof` means an erasure still leaves
only "at some point there was a pharma event concerning a subject," nothing more specific.

| `event` | Meaning | Regulatory anchor |
|---|---|---|
| `production` | A starting material batch, an intermediate, an API batch, or a finished dosage-form batch comes into being | ICH Q7 (batch genesis) |
| `aggregation` | Units packed into cases, cases onto pallets — and the reverse | GS1 pharma packaging hierarchy; DSCSA aggregation |
| `transport` | Departure or arrival of a shipment | EU GDP |
| `storage` | **New.** A batch or unit enters or leaves a temperature-mapped, qualified storage facility | EU GDP; WHO TRS 961 Annex 9 Supplement 8 |
| `processing` | Starting material → intermediate → API → finished dosage form | ICH Q7 |
| `handover` | Change of ownership or responsibility | DSCSA T3 trigger; FMD chain of custody; DSCSA Authorized Trading Partner |
| `measurement` | A series of readings from a device — the cold chain, above all | EU GDP temperature monitoring |
| `release` | **New.** A Qualified Person certifies a batch fit for release | ICH Q7 / EU GMP Annex 16 (qualified person certification) |
| `decommission` | **New.** A specific serialized unit's physical life ends — administered, destroyed, withdrawn | GS1 EPCIS 2.0's own `decommissioning` bizStep; DSCSA/FMD unit lifecycle |

Six of the nine are `food.v1`'s events, unchanged in shape. `storage`, `release` and `decommission`
are new, each for a specific, arguable reason (§7, §8, §9) — not because the other six were found
wanting.

## 4. Event type and entry type

The same binding rule as `food.v1` §8, extended by one row:

| `event` | required `typ` |
|---|---|
| `measurement` | `sensor_reading` (5) |
| all others, including `storage`, `release` and `decommission` | `assertion` (1) |

`release` is `assertion`, not `attestation` (core type 2). This is worth being precise about,
because the two are easy to conflate here: `attestation`'s `subj` is a **KeyID**, the identifier of
a party being vouched for (OWM-6 §3) — but a batch release is a statement about a **product batch**,
not about anyone's identity. `release`'s `subj` is the batch's ordinary subject ID, exactly like
every other pharma event. What *is* an OWM-6 question is a separate one: how trustworthy is the
Qualified Person who signed the release? That is answered by the entity trust level of the QP's own
key (§8), not by the release entry's type.

## 5. Structure of the schemas

Not implemented (see the implementation-status note above), but the shape to build: a root
`event.json` switching on `event` exactly as
`food.v1`'s does, `unevaluatedProperties: false`, and its own `defs.json` — **not** shared with
`food.v1`'s. OWM-4 §4.3 forbids a `$ref` to a foreign source, and a profile's schema files are
pinned by the schema digest as a set (OWM-4 §3); reaching into a different profile's files would
make that profile's own immutability someone else's problem. `pharma.v1` needs its own `subject`,
`keyid`, `timestamp`, `party`, `location`, `quantity` and `product` definitions, parallel to
`food.v1`'s but independently versioned.

New building blocks `food.v1` has no equivalent of:

- `lot` — a batch/lot identifier, free text bounded in length (GS1 doesn't standardize a format;
  manufacturers assign their own).
- `expiry` — a date, format-checked (OWM-4 §4.2 makes `format` a real check, not an annotation).
  Required on every `product` from the point a finished dosage form exists; meaningless earlier in
  the chain (a starting-material batch has a retest date, not necessarily an "expiry" in the
  regulatory sense — modeled as the same field, since both answer "how long is this batch usable",
  and forcing a semantic split here would buy nothing).
- `stage` — an enum on `product`: `starting_material` \| `intermediate` \| `api` \|
  `finished_product`. Makes explicit which regulatory regime governs this specific entry (ICH Q7
  for the first three, DSCSA/FMD once `finished_product` is reached) without the schema having to
  encode that regime split itself.

## 6. Subject granularity — two tiers, not one

OWM-4 §10.1 already names the reason a pharmaceutical is the textbook case for instance-level
subject IDs (SGTIN-equivalent, one subject per individually serialized saleable unit) instead of
`food.v1`'s lot-level default: "That value is anti-counterfeiting... for a diamond, a pharmaceutical
or a spare part with a safety function that is worth the cost." DSCSA and FMD both mandate exactly
this at the saleable-unit level.

But that is only true **downstream of packaging**. A synthesis batch of API does not have
"500,000 individually serialized units" — it has one lot, tested against one Certificate of
Analysis, until it is formulated and packaged into individually serialized saleable units. Forcing
instance-level granularity onto the API/intermediate side would multiply entries for no reason
DSCSA or FMD ask for; forcing lot-level granularity onto the finished-product side would fail the
one regulatory requirement that specifically wants unit-level serialization.

**The rule:** `stage: starting_material | intermediate | api` uses **lot-level** subject IDs, the
same default `food.v1` uses. `stage: finished_product`, from the point of packaging into an
individually serialized saleable unit onward, uses **instance-level** subject IDs. The `processing`
entry that turns a lot of API into a lot of finished-dosage-form batches is itself still lot-level
(a `production`-into-batch step); it is the **first `aggregation` that assigns individual serials**
where the tier changes, `par` pointing back at the lot-level `production`/`processing` entry that
produced it — the same mechanism `food.v1` already uses to bridge levels of a hierarchy, applied at
the one point pharma actually needs a second tier.

**Why this does not explode the log.** DSCSA does not require a fresh log entry per individual pack
at every hand-off — it explicitly allows **aggregation**: cases and pallets carry their own
identifier associated with the serials packed into them, and downstream partners verify by drilling
into that association only when needed, not by re-stating every serial at every step. That is
`food.v1`'s `aggregation` event exactly (§10 of OWM-4, "eggs into ten-packs, cartons onto a pallet"),
so a `handover` of a pallet of 5,000 individually serialized packs is **one** `handover` entry
naming the pallet's aggregate subject, not 5,000 — the same "factor 300" argument OWM-4 §10.1 makes
for `food.v1`'s own granularity choice, resolved here by aggregation rather than by choosing
coarser identifiers, because DSCSA specifically forecloses the coarser option for the finished
product.

## 7. Cold chain, storage and transport requirements

GDP treats storage and transport as two related but administratively distinct qualification
exercises — "warehouse and transport temperature mapping methodologies should be consistent," in
current GDP guidance, precisely because they are not the same exercise. This profile follows that
split: `transport` for movement between two places, `storage` for a stay at one, both built on the
same promise/observation pair `food.v1`'s `transport.conditions` \/ `measurement` already
establishes (OWM-4 §11: conditions are **promised**, a `measurement` entry is what actually
happened, and only the two together, compared, say whether the promise was kept).

### 7.1 Transport

`transport.conditions`, extended by one field beyond `food.v1`'s:

- `conditions.temperature_c: {min, max}` — unchanged from `food.v1`. EU GDP's own reference ranges
  are commonly 2–8 °C (refrigerated) or 15–25 °C (controlled room temperature); this profile does
  not hardcode either — the range is asserted per shipment, the way `food.v1` already does it. Not
  hardcoding it is not a theoretical caution: mRNA vaccines widely deployed since 2021 require
  ultra-cold storage as low as −70 °C, an order of magnitude outside ordinary GDP ranges, and a
  fixed-range field would have had to be redesigned for exactly this case.
- `conditions.max_transit_hours` — **new**. GDP's excursion concept is not purely about
  temperature: "three hours at 15 °C on a 2–8 °C lane" (a real example from current GDP guidance) is
  an excursion regardless of whether the temperature limit itself was breached, because validated
  shipping lanes are qualified for a temperature range **for a bounded duration**. Actual transit
  time is derivable by comparing the `time` fields of the two `transport` entries (departure,
  arrival) without a separate field; `max_transit_hours` is the **promise** against which that
  derived actual is checked, the same asymmetry `temperature_c` already has between promise and
  observation.

### 7.2 Storage

A batch or unit does not stop existing between two `transport` legs — it typically sits in a
distribution center for days to weeks, and GDP requires that stay to be just as accounted for as
the trip either side of it. `storage` is the entry that says so:

```json
{ "event": "storage", "action": "enter", "time": "…",
  "location": { "gln": "…" }, "conditions": { "temperature_c": { "min": 2, "max": 8 } } }
```

`action` is `enter` or `leave`, the same shape `aggregation`'s add/delete pair already uses (OWM-4
§10). Unlike `transport`, `location` is a single place, not an origin and a destination —
`conditions` is asserted **by the facility operator**, once per stay, not derived from a lane
qualification. What backs that promise is a distinct exercise: WHO's own guidance recommends
**temperature mapping a storage area for at least 7 to 10 consecutive days** before it is qualified
for use, a duration mapping exercise this log does not itself record (it is a one-time
qualification of the *facility*, not a per-batch event) — but the `measurement` entries taken
during an actual stay, subject to the same `storage.conditions` promise, are exactly what OWM-4
§11's claim/confirmation split already handles: the facility's qualification is the operator's
claim, an ongoing `measurement` series is the evidence.

### 7.3 Excursion handling

**Deliberately not a new mechanism, for either.** An excursion is discovered exactly the way a
broken cold chain already is in `food.v1`: a `measurement` entry (or a derived transit/dwell time)
that contradicts a `transport.conditions` or `storage.conditions` promise. What GDP requires next —
quarantine, investigation, a CAPA record — is an operational process outside this log's concern; if
that investigation concludes the batch may not be released, that is expressed the same way any
other withdrawn statement is (§9), not through a bespoke "excursion" entry.

## 8. Batch release, trading partners and the claim/confirmation boundary

### 8.1 Batch release

`release` is its own event, not a field on `production`, for the same reason `food.v1` §10 gives
for why `handover` is its own event and not a side field of `transport`: it is typically issued by
a **different party** (the Qualified Person, who under EU GMP carries personal regulatory
liability distinct from the manufacturing site) at a **later time** (after QC testing completes,
which can take days to weeks) — not the same statement, extended, but a genuinely separate one.

```json
{ "event": "release", "time": "…", "lot": "…", "certified": true,
  "standard": "eu-gmp-annex16", "reference": "…" }
```

`release.certified: false` is representable and meaningful — a QP declining to certify a batch is
itself a statement worth logging, not merely the absence of one. `subj` names the batch (the same
subject as the `production`/`processing` entry it concerns, referenced through `par` — the same
same-subject convention OWM-6 §6 already establishes for a revocation that is meant to be found
together with what it concerns).

**This is a claim, not a confirmation** — precisely the distinction OWM-4 §11 draws for
`food.v1`'s `production.certifications`. `release.certified: true` is what the QP says. Whether the
QP is who they claim to be, and how far their own accreditation reaches, is answered by their
entity trust level (OWM-6), computed from `attestation` entries over the QP's own key — typically
anchored at level 5 ("state/official accreditation with regular inspection," CLAUDE.md §4.1's own
example row), since QPs are themselves subject to regulatory licensing in most jurisdictions. A
`release` entry from an unaccredited key is exactly as informative as an unconfirmed organic seal in
`food.v1` — worth exactly nothing until backed.

### 8.2 Trading partners — wholesalers and intermediaries

`handover` (§3) is reused unchanged from `food.v1`, but who may legitimately appear on either side
of one is a materially higher-stakes question here than in food: DSCSA requires every wholesale
distributor and third-party logistics provider to be an **Authorized Trading Partner (ATP)** —
licensed under state law or federal registration, *verified before the first transaction*, with
verification records kept a minimum of six years, and annual licensure reporting to the FDA every
January–March. A wholesaler who is not an ATP may not legally receive or pass on a covered drug at
all.

This profile does not, and structurally cannot, enforce that a `handover` counterparty is
licensed — a node accepts a well-formed entry from a known key, not a judgment about that key's
regulatory standing (OWM-4 §5's own division of labour: the schema checks form, not truth). What it
*can* do is make the standing checkable the same way batch release already is (§8.1): a
wholesaler's key carries an entity trust level (OWM-6), backed by `attestation` entries from
whichever accreditation root the verifier recognises — a state pharmacy board, for instance, at
level 5 or 6 depending on jurisdiction. A `handover` naming an unaccredited key is not rejected by
the node, but it is visibly, checkably unaccredited to anyone who looks — exactly the claim/
confirmation split this profile already applies to release and to `food.v1`'s own certifications,
extended to the parties in the chain rather than only to the goods.

## 9. Decommissioning, recall and quarantine

**Decommissioning closes the loop on a specific unit's identity.** At `stage: finished_product`
instance level (§6), a subject ID names one physical, individually serialized pack — and once that
pack is administered, destroyed, or otherwise permanently withdrawn from circulation, its identity
should never legitimately appear again. `decommission` is the entry that says so: issued by the
administering or destroying entity (a clinic, a hospital, a pharmacy — as a business, per §11, never
as or naming a patient), `subj` the same instance-level subject as everything else concerning that
unit.

```json
{ "event": "decommission", "time": "…", "reason": "administered" }
```

`reason` is a small closed vocabulary (`administered`, `destroyed`, `expired`, `withdrawn`) —
deliberately not open text, because what matters for detection is only that a terminal event
happened, not the operational detail of which. This is the direct answer to the fraud pattern named
in §2: WHO reports criminal groups **reusing emptied vaccine vials** — refilling a genuine, already
administered vial with a falsified substitute and reintroducing it under its own, now-reused,
identity. A `decommission` entry makes that reuse **structurally detectable**, the same
self-contradiction-detection move the log already makes for split views
([OWM-9 A1](owm-9-threat-model.md#a1--split-view--the-central-attack)): a
`production`, `aggregation`, `handover` or further `decommission` entry naming a subject ID that
already carries a `decommission` is not proof of fraud by itself — nobody outside the log can
confirm what physically happened to a specific vial — but it is exactly the kind of contradiction a
client or monitor can flag mechanically, the same limited, honest claim OWM-9 makes for every other
use of this pattern in this project.

**Recall and quarantine reuse the core, no new profile mechanism** — mirroring `food.v1` §14's own
resolution of the identical question: a batch found unfit after release is not withdrawn through a
profile field but through a **`revocation`** entry of the core (OWM-0 §6.1), targeting the
`release` entry that certified it. The statement "this batch was released" stays visible — a
revocation does not erase it, only withdraws it (that distinction is the entire reason revocation
and erasure are two different mechanisms, OWM-0 §6.1) — while a client reading the chain sees
plainly that the certification no longer stands.

## 10. Identifiers

| Kind | Standard | Note |
|---|---|---|
| Trade item | GTIN, 8–14 digits | Primary, as in `food.v1` |
| US product code | NDC (National Drug Code) | Optional, alongside `gtin` — DSCSA's own barcode encodes a GTIN *derived from* the NDC, so this profile carries both rather than forcing a US-only identifier into the primary field |
| Business, location | GLN, 13 digits | As in `food.v1` |
| Batch/lot | `lot`, free text | No standardized format; manufacturer-assigned |
| Individual unit | serial number, free text, only at `stage: finished_product` instance level | §6 |
| Country | ISO 3166-1 alpha-2 | As in `food.v1` |
| Timestamps | RFC 3339 with time zone | As in `food.v1` |

## 11. Data protection

The `food.v1` rule (OWM-4 §13) applies without softening, and pharma is where getting it wrong
would hurt the most: **`party` knows only businesses — manufacturer, wholesaler, pharmacy as an
entity.** No field for a patient, a prescriber, or a pharmacist's name exists anywhere in this
profile, and none MUST be added by an implementation. §1 already excludes dispensing-to-a-patient
from scope entirely; this section is the same boundary restated at the field level, because a
"just one more field for the pharmacy to note who picked it up" request is exactly how a supply
chain log turns into a health record by accretion.

All payload fields remain erasable per the core mechanism (OWM-2 §7); what survives an erasure is
subject ID, issuer, times, profile identifier, entry type and predecessors — same as `food.v1`.
Subject IDs at the finished-product instance level MUST be random, not derived from the serial
number printed on the pack (OWM-0 §4.2, OWM-9 A10): a derived ID would let anyone who reads a
package's own serial off the box compute its subject ID and pull its full history, including which
pharmacy it was shipped to — a capability with no legitimate use outside verification at the point
of dispensing, where the serial is available anyway.

## 12. Open points

- **The EU Pharmaceutical Package (recast Directive 2001/83/EC, Regulation 726/2004).** Political
  agreement stands (Dec. 2025), texts confirmed by COREPER I (March 2026), but this research pass
  found no detail on what it changes for traceability or serialization specifically. Nothing in
  this document is built against it; revisit once the confirmed text is actually analyzed.
- **Whether `release` should be its own core entry type** rather than a profile-level `assertion`
  — raised and set aside in §4. The case for leaving it as `assertion` is that nothing about batch
  release differs structurally from any other party's self-declaration; the case against is that
  "who may issue a `release`" is a materially higher-stakes question than any other pharma event.
  Left as `assertion` for this draft; worth re-examining once real operator experience exists,
  same caution OWM-4 §14 already applies to `food.v1`'s own open points.
- **Mapping `stage` and processing-step vocabulary to an external code list** — currently a closed
  four-value enum for `stage`, free text for the processing step itself. Same open point `food.v1`
  §14 carries for `process`.
- **Payload form for bundled series of readings** (temperature logs at fine resolution) — not
  laid down, same open point as `food.v1` §14; a cold-chain logger on a multi-day transatlantic
  shipment is exactly the case OWM-2 §8's batch-signing mechanism exists for.
- **Facility-level temperature-mapping evidence is out of scope.** `storage.conditions` is the
  operator's promise for a given stay; the underlying WHO-recommended 7–10-day mapping exercise
  that qualifies the facility in the first place is a one-time, operational qualification this
  profile does not model as its own event — an operator MAY back it with an `attestation` if a
  recognised inspection body issues one, but nothing requires it yet.
- **No API/finished-product split into two profiles was chosen**, deliberately: one `pharma.v1`
  spanning ICH Q7's manufacturing side and DSCSA/FMD's distribution side, linked by the same
  `processing` chain. Revisit if the two sides turn out to need incompatible schema evolution
  cadences — `food.v1`'s immutability rule (OWM-4 §3) means a split later is a new profile, not a
  patch.

## 13. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Instance-level subject ID derived from the printed serial | full shipment history readable from the box alone | random subject ID at instance level, mandatory (§11) |
| Fabricated `release` from an unaccredited key | forged batch certification looks identical to a real one | entity trust level of the QP's key, computed via OWM-6, not the entry's mere presence |
| Temperature excursion undetected because duration was never promised | a lane breaching its qualified transit time is invisible even with `temperature_c` intact | `max_transit_hours` as a separate promised bound (§7) |
| Per-unit logging at every hand-off | log size grows with saleable-unit count at every step, not just at packaging | mandatory aggregation for multi-unit hand-offs (§6) |
| Patient identity added to `party` "for convenience" | supply chain log becomes a health record | no patient field exists in the schema; out of scope at the profile boundary, not just discouraged (§1, §11) |
| Release claim mistaken for confirmed compliance | false sense of regulatory assurance | claim/confirmation split enforced the same way as `food.v1` certifications (§8, OWM-4 §11) |
| Emptied unit refilled and reintroduced under its own identity | a real, reported vaccine-fraud pattern (§2) goes undetected | `decommission` makes the same subject ID reappearing afterward a structural contradiction (§9) |
| Storage facility never actually temperature-mapped, `storage.conditions` asserted anyway | an unqualified facility looks identical to a qualified one from the log alone | the promise is checkable against `measurement` evidence during the stay, same as transport (§7.2) |
| `handover` accepted from an unlicensed wholesaler | a covered drug moves through a party DSCSA prohibits from handling it | entity trust level of the counterparty's key, computed via OWM-6, not the entry's mere presence (§8.2) |
