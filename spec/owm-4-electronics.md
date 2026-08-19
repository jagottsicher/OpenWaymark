<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Electronics `electronics.v1`

**Status:** implemented (`profiles/electronics/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers electronic components and finished devices (RAM, SSDs, boards, consumer electronics) from
manufacture through assembly, distribution, and end-of-life recycling. Out of scope: anything about
an individual consumer who owns or uses a device — this profile stops at retail as an entity, the
same boundary every prior profile draws.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| IPC-1782 | "Standard for Manufacturing and Supply Chain Traceability of Electronic Products" — four levels each of material (M1–M4) and process (P1–P4) traceability, tied to IPC Product Classification (Class 1/2/3, Space/Defense/Medical). The electronics industry's own EPCIS-equivalent; this profile's events are shaped to be expressible against it, the same relationship `food.v1` has to EPCIS. |
| EU ESPR / Digital Product Passport | Delegated acts finalised 2024–2025, enforcement from 2026 onward across priority sectors incl. electronics. For electronics specifically: repairability index and spare-parts data (targeted 2027), recycled-content and recyclability requirements (targeted 2029), substances-of-concern declarations throughout. |
| WEEE Directive (2012/19/EU) | End-of-life collection and recycling obligations for electrical and electronic equipment |

None of these regimes is reproduced normatively here (OWM-4 §5): this profile's schema checks
form, not compliance.

## 3. Subject granularity: two tiers, the same shape `pharma.v1` already uses

Small components (resistors, individual chips) are tracked by lot/date-code, the same default
`food.v1` uses — IPC-1782's own M-level traceability is lot-based at this scale. Finished,
individually serialized devices (a laptop, an SSD with its own serial number) move to
instance-level. No new mechanism: a `product` carrying `serial` is one specific unit; one carrying
only `lot` is a batch — the same convention `pharma.v1` §6 and `vehicle.v1` already establish, not
a dedicated granularity field.

## 4. Events

| `event` | Meaning |
|---|---|
| `production` | A component lot or a finished device comes into being |
| `aggregation` | Components assembled into a board or device — a bill of materials |
| `transport` | Departure or arrival of a shipment |
| `handover` | Change of ownership — manufacturer to distributor to OEM to retailer |
| `measurement` | Reliability/burn-in test data, or environmental sensor data where fitted |
| `release` | Compliance certification — CE marking, RoHS, REACH substances-of-concern declaration |
| `processing` | End-of-life recycling: the device as input, recovered materials as outputs (WEEE) |
| `decommission` | The unit's life ends — recycled, destroyed, lost, disposed |

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release` and `decommission`, is an ordinary self-declaration (`assertion`).

## 5. Digital Product Passport fields

`product` carries three fields aimed directly at what the DPP's own key data points are reported to
require: `recycled_content_pct` (0–100), `repairability_index`, `warranty_months`. This profile does
not compute or certify any of them — they are asserted the same way every other claim in this
project is, checked against form only (OWM-4 §5), confirmed (if at all) by whoever the asserting
party's entity trust level backs.

## 6. Claim, not confirmation

`release.certified` is what the certifying party says about CE/RoHS/REACH compliance. Whether that
party is accredited to make the claim is answered by its entity trust level (OWM-6), the same
pattern every prior profile's release-shaped event establishes — directly relevant here given the
electronics industry's own well-documented counterfeit-component problem (recycled or relabeled
parts resold as new), the same shape `aviation.v1`'s AS6081 concern addresses for aircraft parts.

## 7. Identifiers

| Kind | Note |
|---|---|
| Trade item | `gtin`, 8–14 digits — for a retail-packaged product |
| Manufacturer part number | `part_number`, free text (MPN) |
| Lot/date code | `lot`, free text — component-level, IPC-1782 M-level |
| Serial number | `serial`, free text — instance-level, a specific finished device |

## 8. Data protection

`party` knows only businesses. No field anywhere in this profile names an individual consumer or
owner — end-user ownership and use are out of scope entirely (§1), not merely discouraged.

## 9. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Counterfeit or recycled component sold as new | reliability and safety risk downstream | entity trust level of the certifying party's key, computed via OWM-6, not the entry's mere presence (§6) |
| Recycled-content or repairability claim asserted without basis | false DPP compliance signal | claim/confirmation split (§5, §6) — a bare assertion is worth nothing until backed |
| Decommissioned unit's serial reused | a disposed-of device re-enters circulation under its old identity | the same subject-reappearing-after-`decommission` contradiction every prior profile already makes structurally detectable |
