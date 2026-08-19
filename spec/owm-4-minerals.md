<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Raw materials `minerals.v1`

**Status:** implemented (`profiles/minerals/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers critical raw materials and 3TG minerals (tin, tantalum, tungsten, gold — the traditional
conflict-minerals set — plus lithium, cobalt, nickel, rare earths and copper under the EU's broader
critical-raw-materials framework) from extraction through smelting/refining to a manufacturer.
CLAUDE.md's own vision section already names "conflict-free" as a founding example of what this
project should demonstrate; this profile is that example, concretely.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| EU Conflict Minerals Regulation ((EU) 2017/821) | In force since 1 Jan. 2021. Mandatory due diligence for EU importers of tin, tantalum, tungsten and gold above an import-volume threshold, aligned with the OECD's own guidance |
| OECD Due Diligence Guidance for Responsible Mineral Supply Chains | The five-step framework this regulation, and this profile, are built against: (1) adopt a policy, (2) identify and assess supply-chain risk — including identifying smelters/refiners and the chain of custody, (3) map factual circumstances, (4) independent third-party audits at **control points** (smelters/refiners), (5) public reporting |
| EU Critical Raw Materials Act ((EU) 2024/1252) | In force since 23 May 2024. 34 critical and 17 strategic raw materials (incl. lithium, cobalt, nickel, rare earths); 2030 benchmarks (10% domestic extraction, 40% domestic processing, 25% recycling); a March 2026 Council position explicitly allows product passports to satisfy its information obligations for permanent magnets specifically |

None of these regimes is reproduced normatively here (OWM-4 §5): this profile's schema checks
form, not compliance.

## 3. The smelter/refiner is the control point

OECD guidance concentrates due diligence at smelters and refiners specifically, because that is
where materials from many, often untraceable, upstream sources converge into a fungible output —
verifying every artisanal mine directly is not realistic, verifying the control point everything
passes through is. This profile does not invent a mechanism for that: a smelter/refiner's
conformance to a recognised audit scheme (the real-world analogue being the Responsible Minerals
Initiative's RMAP "Conformant" designation) is a `release` entry, the same claim/confirmation
pattern every prior profile's release-shaped event already establishes (§5).

## 4. Events

| `event` | Meaning |
|---|---|
| `production` | Ore or concentrate is extracted at a mine |
| `aggregation` | Batches from several sources combined before smelting, or split |
| `transport` | Departure or arrival of a shipment |
| `processing` | Smelting/refining — raw material in, refined metal out — the control point (§3) |
| `handover` | Change of ownership |
| `measurement` | Assay/purity lab results |
| `release` | A smelter or refiner certifies conformance to a due-diligence audit scheme |

No `decommission`: a mineral batch does not have a life that ends the way a device or vehicle
does — `processing` already retires an input subject into its output the moment it is smelted,
the same mechanism `food.v1` uses for milk becoming cheese.

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release`, is an ordinary self-declaration (`assertion`).

## 5. Claim, not confirmation

`release.certified` is what the smelter or refiner says about its own conformance — a facility-level
claim, unlike a per-batch release elsewhere, but the same mechanism: the smelter's own key
self-declares it. Whether that claim is worth anything is answered by the smelter's own entity
trust level (OWM-6), computed from `attestation` entries back to a recognised accreditation root —
in practice, whichever body actually performs the OECD step-4 independent audit (the real-world
analogue being the RMI). A `release` from a key with no such backing is exactly as informative as
an unconfirmed organic seal in `food.v1`: nothing.

## 6. Subject granularity: lot upstream, sometimes instance downstream

Ore and concentrate are lot-level throughout, the same default `food.v1` uses — there is no
individual-unit concept for a shipment of ore. Refined output can be different: LBMA "Good
Delivery" gold and silver bars carry their own stamped serial number, weight and purity from an
accredited refiner. The same convention `pharma.v1`, `vehicle.v1` and `electronics.v1` all already
use applies without a dedicated field: a `product` carrying `serial` is one specific bar; one
carrying only `lot` is a batch.

## 7. Identifiers

| Kind | Note |
|---|---|
| Mineral | `mineral`, free text (e.g. `"tin"`, `"cobalt"`, `"rare_earth"`) — not a closed enum; new critical materials are designated over time |
| Lot | `lot`, free text |
| Serial | `serial`, free text — refined bars/ingots only (§6) |

## 8. Data protection

`party` knows only businesses — mine operator, smelter, refiner, manufacturer. No field for a named
individual exists anywhere in this profile.

## 9. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Self-assessed "conformant" claim with no real audit behind it | false due-diligence assurance | entity trust level of the smelter's own key, computed via OWM-6 back to a recognised accreditation root, not the entry's mere presence (§5) |
| Material laundered through an unaudited intermediary before reaching a control point | origin obscured before the point where verification concentrates | the chain (`par`, `handover`) stays visible end to end regardless of where the audit sits |
| Conflict-sourced material declared as a different, unaffected origin | a bare geographic claim looks the same as a verified one | claim/confirmation split (§5) — an unbacked origin claim is worth exactly what an unconfirmed organic seal is in `food.v1`: nothing |
