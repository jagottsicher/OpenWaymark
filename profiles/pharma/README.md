<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/pharma/` — Pharmaceutical profile `pharma.v1` · Apache-2.0

OpenWaymark's second schema profile. Full normative specification, with the regulatory citations
this README only summarises: [`spec/owm-4-pharma.md`](../../spec/owm-4-pharma.md).

| Event (`event`) | Meaning | Regulatory anchor |
|---|---|---|
| `production` | A starting material batch, an intermediate, an API batch, or a finished dosage-form batch comes into being | ICH Q7 |
| `aggregation` | Cases onto pallets, or the first packaging step that assigns individual serials | GS1 pharma packaging hierarchy; DSCSA |
| `transport` | Departure or arrival of a shipment | EU GDP |
| `storage` | A batch or unit enters or leaves a qualified storage facility | EU GDP; WHO TRS 961 Annex 9 Suppl. 8 |
| `processing` | Starting material → intermediate → API → finished dosage form | ICH Q7 |
| `handover` | Change of ownership or responsibility | DSCSA T3 trigger; FMD chain of custody |
| `measurement` | A series of readings from a device — the cold chain, above all | EU GDP temperature monitoring |
| `release` | A Qualified Person certifies a batch fit for release | ICH Q7 / EU GMP Annex 16 |
| `decommission` | A specific serialized unit's physical life ends | GS1 EPCIS 2.0's `decommissioning` bizStep |

## Six of nine, unchanged

Six events are `food.v1`'s events, unchanged in shape — `production`, `aggregation`, `transport`,
`processing`, `handover`, `measurement`. `storage`, `release` and `decommission` are new, each for
a specific, arguable reason spelled out in the spec, not because the other six were found wanting.
That the extension is this small is itself evidence for OWM-4 Part A's claim that new industries
arrive as a new profile, without the data model changing.

## Two tiers of subject granularity

API and intermediate batches use lot-level subject IDs, the same default `food.v1` uses. From the
point an individual saleable unit is serialized — `product.stage: "finished_product"` — subject IDs
move to instance level, one per physical pack, because DSCSA and the EU's FMD both mandate
unit-level serialization there specifically. The tier change happens at exactly one point: the
first `aggregation` that assigns individual serials, `par` pointing back at the lot-level entry that
produced it. Spec §6 has the full reasoning, including why this does not explode the log
(aggregation, not per-unit hand-off logging).

## Storage is not transport

GDP treats warehouse and transport temperature mapping as related but administratively distinct
qualification exercises. `storage` — enter/leave a facility, a promised `conditions.temperature_c`
— is `transport`'s sibling, not a special case of it: `location` is one place, not an origin and a
destination, and the promise is the facility operator's, not a shipping lane's. Both share the same
promise-vs-`measurement` mechanism food.v1 already established.

## Claim, not confirmation — twice over

`release.certified: true` is what a Qualified Person says, not proof. Whether the QP's own
accreditation backs that claim is a separate, computed question — their entity trust level (OWM-6),
walked from `attestation` entries back to a recognised root. The same split applies to `handover`
counterparties: DSCSA requires wholesalers to be licensed Authorized Trading Partners, verified
before the first transaction. This profile cannot enforce that a `handover` counterparty is
licensed — a node checks form, not regulatory standing — but it makes the standing checkable the
same way: an unaccredited key is visible as such to anyone who looks.

## Never patient-linked

`party` knows only businesses — manufacturer, wholesaler, pharmacy, hospital as an entity. No field
for a patient, a prescriber or a pharmacist's name exists anywhere in this profile, and dispensing
to a named patient is out of scope entirely, not merely discouraged. `decommission` — the event that
closes a specific unit's identity, administered/destroyed/expired/withdrawn — names no patient
either: it exists to make a reused, emptied unit's identity reappearing later a structural
contradiction (a real, WHO-documented vaccine-fraud pattern), not to record who received a dose.

## Units and identifiers

- Trade items: GTIN, 8–14 digits, primary — optionally alongside an NDC for the US market
- Batch/lot: `lot`, free text, manufacturer-assigned
- Individual unit: `serial`, free text, only at `stage: finished_product` instance level
- Controlled substances: `controlled_substance_schedule` (DEA Schedule I–V), flags the additional
  ARCOS/Form 222 regime without a separate event
- Quantities: UN/CEFACT Recommendation 20 (`KGM`, `LTR`, `H87` for pieces, `CEL` for °C)
- Locations and businesses: GLN, 13 digits
- Countries: ISO 3166-1 alpha-2, uppercase
- Timestamps: RFC 3339 **with time zone**

Example payloads for every event are in [`pharma_test.go`](pharma_test.go).
