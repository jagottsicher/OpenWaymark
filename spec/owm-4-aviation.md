<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Aircraft parts `aviation.v1`

**Status:** implemented (`profiles/aviation/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers used/serviceable aircraft parts from manufacture through installation, removal, repair,
overhaul and eventual retirement — the industry's own "back-to-birth traceability." Out of scope:
flight operations, crew records, passenger data (none of which this profile has any field for).

**Why this, and why now.** The industry already runs on exactly this shape by hand: a signed
document chain from manufacture through every installation/removal/repair to retirement, built on
FAA Form 8130-3 / EASA Form 1 airworthiness tags and ATA Spec 2000 ch. 15/16. The AOG Technics
scandal (2023–2025: 100+ aircraft grounded across American, Delta, Southwest, Ryanair, TAP, from
counterfeit CFM engine bushings with forged 8130-3/Form 1 paperwork sold by an unauthorised
distributor) is a concrete, recent failure of the *paper* version of the system this profile builds
digitally — precisely the gap AS6081 (counterfeit-parts prevention for independent distributors)
already exists to close by other means.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| FAA Form 8130-3 / EASA Form 1 | Authorized Release Certificate — issued by a Production Organization Approval (POA) holder at manufacture ("Certificate of Conformity"), and again by a Part-145 Maintenance Organization Approval holder after repair/overhaul ("returned to serviceability") |
| ATA Spec 2000 ch. 15 | Aircraft Transfer Parts List — the transfer of parts between operators |
| ATA Spec 2000 ch. 16 | XML electronic format for 8130-3/Form 1, approved by FAA, EASA, Transport Canada |
| IATA "Guidance Material and Best Practices for LLP Traceability" | Back-to-birth traceability specifically for life-limited parts |
| AS9100 | Aerospace quality management system certification |
| AS6081 | Counterfeit-parts prevention for independent distributors sourcing/supplying in the open market — the AS9100/AS9110/AS9120 add-on directly responsive to cases like AOG Technics |

None of these regimes is reproduced normatively here (OWM-4 §5): this profile's schema checks form,
not compliance.

## 3. Subject granularity: always instance-level

Unlike `food.v1` (lot-level default) or `pharma.v1` (two-tier, lot until packaging), every aircraft
part of any consequence already carries its own serial number from the moment it is manufactured —
there is no bulk-lot stage to model. Every subject in this profile is one physical part, one serial
number, from `production` onward. A third, simpler data point for OWM-4 §10.1's own claim that
subject granularity is a per-industry decision, not a protocol default.

## 4. Events

| `event` | Meaning |
|---|---|
| `production` | The part is manufactured and receives its first Authorized Release Certificate (POA) |
| `aggregation` | Installed into, or removed from, a higher assembly — `action: install \| remove` |
| `transport` | Departure or arrival of a shipment between operators or repair stations |
| `handover` | Change of ownership or operator (ATA Spec 2000 ch. 15) |
| `measurement` | Condition-monitoring sensor data (e.g. engine vibration), where fitted |
| `release` | A Part-145 organization re-certifies the part fit for service after repair/overhaul |
| `decommission` | The part's life ends — life-limit reached, scrapped, lost, destroyed |

No `processing`, no `storage`: nothing in this profile's scope transforms one part into a
structurally different one (that happens further upstream, outside a part's own back-to-birth
record), and shelf-life storage conditions are a secondary concern here, not the center of gravity
GDP makes it for pharma. `aggregation` uses `install`/`remove` rather than `food.v1`'s `add`/`delete`
— the industry's own vocabulary, since installation into an assembly is exactly what this event
records.

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release` and `decommission`, is an ordinary self-declaration (`assertion`) — the same binding rule
`food.v1` and `pharma.v1` both use, for the same reason: a hand-written condition report must not be
passable off as sensor evidence.

## 5. Life-limited parts and cycle tracking

A life-limited part (LLP — typically turbine discs, blades, landing gear, APU components) carries a
hard limit in flight cycles, not calendar time. `product.life_limited: true` plus
`product.cycle_limit` mark it; `product.cycles_used`, asserted at each `production` or `release`
entry, carries the cumulative count as of that point — the same shape the industry's own paper LLP
tracking sheets already use, digitised. This profile does not compute remaining life or enforce the
limit; a client reads the latest `cycles_used` against `cycle_limit` itself, the same
"claim, not confirmation" posture OWM-4 §11 already establishes elsewhere.

## 6. Claim, not confirmation

`release.certificate_ref` is what the releasing organization says. Whether that organization is who
it claims — an AS9100-certified, appropriately approved Part-145 holder, not an AS6081 case waiting
to happen — is answered by its entity trust level (OWM-6), computed from `attestation` entries back
to a recognised accreditation root, not by the presence of a `release` entry itself. An unaccredited
key issuing `release` entries is exactly as informative as an unconfirmed certificate in the paper
world used to be before anyone checked it against the issuing organization's own approval.

## 7. Identifiers

| Kind | Note |
|---|---|
| Part number | `part_number`, free text — no single global registry, manufacturer-assigned |
| Serial number | `serial_number`, free text — mandatory; this is the subject's real-world identity |
| Certificate reference | `certificate_ref` — the 8130-3/Form 1 tracking number |
| Approval type | `approval_type`: `poa` \| `part145` — which kind of organization issued the certificate this entry concerns |

## 8. Data protection

`party` knows only businesses — manufacturer, operator, MRO shop, lessor — the same rule `food.v1`
and `pharma.v1` both apply (OWM-4 §13). Nothing about a part's history requires naming a natural
person, and no field for one exists.

## 9. Open points

- Component-level linkage (which specific bushing sits in which specific engine, at what
  granularity) is expressed through `aggregation`'s `children`, the same mechanism `food.v1` and
  `pharma.v1` use — not yet exercised against a real multi-thousand-component assembly; revisit if
  that scale surfaces schema-size problems `food.v1`'s own MaxParents bound does not already cover.
- No modeling of AS6081's own distributor-vetting process beyond entity trust levels — deliberately;
  see §6.

## 10. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Forged 8130-3/Form 1 from an unauthorised distributor (the AOG Technics pattern) | counterfeit part looks certified | entity trust level of the releasing organization's key, computed via OWM-6, not the entry's mere presence (§6) |
| LLP flown past its cycle limit, cycle count never corrected | catastrophic in-service failure risk | `cycles_used` asserted at every release; a client compares it against `cycle_limit` itself — this profile does not silently trust a stale count |
| Part decommissioned, then reappears in a later `production`/`aggregation`/`handover` | a scrapped part re-enters service under its old identity | the same subject-reappearing-after-`decommission` contradiction `pharma.v1` §9 already makes structurally detectable |
