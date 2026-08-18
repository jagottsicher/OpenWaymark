<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Deforestation-free commodities `eudr.v1`

**Status:** implemented (`profiles/eudr/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers timber, cocoa, coffee, palm oil, soy, rubber and cattle from the production plot through
processing to a manufacturer or importer — the commodities the EU Deforestation Regulation names.
Named after the regulation, not a single commodity, because what unifies these otherwise unrelated
supply chains is exactly one shared requirement: plot-level geolocation proof that production did
not cause deforestation after a fixed date. That requirement, not any one commodity's own
processing steps, is this profile's center of gravity.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| EU Deforestation Regulation ((EU) 2023/1115) | Geolocation-based due diligence proving a commodity was not produced on land deforested after 31 Dec. 2020. In force from 30 Dec. 2026 (large/medium operators), 30 June 2027 (small/micro). Fines up to 4% of EU-wide annual turnover |

The regulation's own Due Diligence Statement (DDS), filed through the EU's TRACES NT system,
requires: plot-level geolocation (a point for plots ≤4 ha and for cattle establishments, a polygon
above that, coordinates to at least six decimal degrees, checked against the JRC 2020 forest-cover
baseline), proof of the cutoff date, supplier and HS code details, and a risk assessment. None of
this regime is reproduced normatively here (OWM-4 §5): this profile's schema checks form, not
compliance — it does not itself validate a polygon against JRC imagery.

## 3. Events

| `event` | Meaning |
|---|---|
| `production` | Harvest at the plot — carries the geolocation and the deforestation-free claim (§4) |
| `aggregation` | Plot-level harvests pooled into a batch — EUDR explicitly anticipates smallholder aggregation models |
| `transport` | Departure or arrival of a shipment |
| `processing` | Cocoa beans into chocolate, raw rubber into processed rubber, and so on |
| `handover` | Change of ownership |
| `measurement` | Moisture/quality sensor data, or geo-tracked shipment monitoring, where fitted |
| `release` | The Due Diligence Statement itself — filed, and rated for risk (§5) |

No `decommission`: the same reasoning `minerals.v1` and `seafood.v1` already give — a raw commodity
batch has no life that ends independently of being processed or sold.

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release`, is an ordinary self-declaration (`assertion`).

## 4. Geolocation is the center of gravity

`product.geolocation` carries either `point` (a single lat/lon, for plots ≤4 ha and cattle
establishments) or `polygon` (an array of lat/lon vertices, for larger plots) — the same point/
polygon split the regulation itself draws. `product.deforestation_free` is the producer's own claim
at the point of harvest, the same "what the producer asserts, not what is confirmed" pattern
`food.v1` §11 already establishes for `production.certifications`.

## 5. The Due Diligence Statement as a claim

`release` models the DDS itself: `certified` (was one filed and accepted), `risk_rating`
(`negligible` \| `standard` \| `high`, the regulation's own three-way classification). Whether the
operator filing it is who they claim to be — and whether their risk assessments have historically
held up — is answered by their entity trust level (OWM-6), the same claim/confirmation split every
prior profile's release-shaped event already establishes.

## 6. Identifiers

| Kind | Note |
|---|---|
| Commodity | `commodity`, free text (e.g. `"cocoa"`, `"palm_oil"`, `"cattle"`) — not a closed enum |
| Lot | `lot`, free text |
| Geolocation | `point` (lat/lon) or `polygon` (lat/lon vertices) — §4 |

## 7. Data protection

`geolocation` is the one field in this project's entire profile set that is, by design, closer to
personal data than any other: a precise plot coordinate can identify a single smallholder family's
land. It lies in the payload and is therefore erasable under the core mechanism (OWM-2 §7), the same
protection `food.v1` §13 already flags for its own, less precise `location.geo` field — but data
minimisation, not erasure after the fact, is the actual measure operators should rely on.
`party` otherwise knows only businesses, the rule every prior profile applies.

## 8. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Fabricated or shifted geolocation coordinates | deforested land laundered as compliant | this profile records the claim, it cannot itself verify a polygon against satellite imagery — recomputing that check is left to whoever the regulation actually holds responsible for it (the oracle problem, OWM-9) |
| DDS accepted from an unaccredited or fabricated filer | non-compliant goods enter the EU market as cleared | entity trust level of the filing operator's key, computed via OWM-6, not the entry's mere presence (§5) |
| Precise plot coordinates exposed unnecessarily | identifies a specific smallholder's land | data minimisation at collection, erasure available after the fact (§7) |
