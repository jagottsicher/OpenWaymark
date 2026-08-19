<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Batteries `eu/battery.v1`

**Status:** implemented (`profiles/eu/battery/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers batteries — portable, LMT (light means of transport, e.g. e-bikes), EV, industrial and SLI
(starter/lighting/ignition) — from manufacture through use, second life and end-of-life recycling.
Named `eu/battery.v1`, the exact identifier CLAUDE.md, README and OWM-4 §2/§14 have already used as
the namespace-slash example since this project's earliest specs — the second profile earmarked from
the start, now the tenth actually built.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| EU Battery Regulation ((EU) 2023/1542) | Mandatory Digital Battery Passport — a QR-linked, machine-readable record — from 18 Feb. 2027 for LMT, industrial (>2 kWh) and EV batteries. Carries carbon footprint, recycled content, chemistry, state of health, due-diligence declarations, end-of-life instructions |

The regulation's own numbers, for grounding rather than enforcement — this profile's schema checks
form, not compliance (OWM-4 §5): carbon footprint performance classes apply to EV batteries from
Aug. 2026; recycled-content-share documentation (cobalt, lithium, nickel) for industrial/EV/SLI
batteries from Aug. 2028; minimum recycled-content levels (16% cobalt, 6% lithium, 6% nickel, 85%
lead) from Aug. 2031; end-of-life material recovery targets of 90% (cobalt/copper/lead/nickel) and
50% (lithium) by end of 2027, rising further by 2031.

## 3. Events

| `event` | Meaning |
|---|---|
| `production` | A cell or pack is manufactured — carries the passport's core claims (§4) |
| `aggregation` | Cells assembled into a module or pack |
| `transport` | Departure or arrival of a shipment |
| `processing` | End-of-life material recovery: the battery in, recovered materials out |
| `handover` | Change of ownership |
| `measurement` | State of health, cycle count, capacity — the passport's ongoing data, not only its birth certificate |
| `release` | Third-party verification of a carbon footprint or due-diligence declaration (§4) |
| `decommission` | First life ends — into a second life, recycling, destruction, or disposal (§5) |

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release` and `decommission`, is an ordinary self-declaration (`assertion`).

## 4. Claim, not confirmation — twice, for two different declarations

`product.carbon_footprint_kg_co2e_per_kwh` is the manufacturer's own declared figure, calculated
per model and plant, exactly the metric the regulation defines: kg CO₂-equivalent per kWh of
energy the battery is expected to provide over its service life. That figure MUST be third-party
verified before it is publicly meaningful — `release` with `standard: "carbon-footprint-
verification"` is that verification, the same claim/confirmation split every prior profile's
release-shaped event already establishes. A second, independent use of `release`
(`standard: "due-diligence"`) covers supply-chain due diligence for the battery's own active
materials (cobalt, lithium, nickel) — the same cobalt, lithium and nickel `minerals.v1` already
tracks upstream through smelting; a battery manufacturer's due-diligence declaration is naturally
the point where that chain and this one meet.

## 5. Second life is not an ending

Unlike every profile since `pharma.v1` that dropped `decommission` because nothing in scope has a
life that "ends" in a way worth naming, batteries genuinely do end their *first* life in more than
one way, and the regulation cares which: `decommission.reason` distinguishes `second_life` (an EV
battery retired to stationary storage) from `recycled`, `destroyed` and `disposed`. A battery
entering second life does not get a fresh `production` entry — the same physical identity
continues, `handover` and `measurement` carry on exactly as before, only the eventual final
`decommission` differs in what led to it.

## 6. Identifiers

| Kind | Note |
|---|---|
| Category | `category`: `portable` \| `lmt` \| `ev` \| `industrial` \| `sli` — the regulation's own battery categories |
| Unique identifier | `unique_identifier`, free text — the QR-linked passport identifier the regulation itself specifies |
| Chemistry | `chemistry`, free text (e.g. `"li-ion"`, `"lfp"`, `"nimh"`) |

## 7. Data protection

`party` knows only businesses. No field for an individual owner or user exists anywhere in this
profile, the rule every prior profile applies (OWM-4 §13).

## 8. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Unverified carbon footprint figure presented as compliant | false environmental claim reaches the passport | claim/confirmation split — `release` verification, not the bare `product` figure, is what a verifier should rely on (§4) |
| A recycled battery's identity reused for a new one | a disposed-of unit re-enters circulation under its old identity | the same subject-reappearing-after-`decommission` contradiction every prior profile already makes structurally detectable |
| Second-life reclassification used to quietly skip due-diligence renewal | a battery escapes the scrutiny its continued circulation should carry | second life is not a fresh `production` (§5) — the original identity, and its full history, stays attached |
