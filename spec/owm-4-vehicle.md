<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Vehicles `vehicle.v1`

**Status:** implemented (`profiles/vehicle/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers used cars and motorcycles from manufacture through import/export, ownership transfers,
inspections, and eventual end-of-life dismantling — including, as one use of the same mechanism,
collector-market "matching numbers" provenance for classic vehicles. Out of scope: driver records,
insurance claims involving a named person, anything about who was driving.

**Why this fits especially well.** A VIN is already a clean, globally unique, mandatory identifier
(ISO 3779) — the subject-granularity question `food.v1` and `pharma.v1` both had to answer
non-trivially has a fixed answer here (§3). Two large, quantified fraud patterns map directly onto
what a tamper-evident append-only log defeats structurally: **odometer rollback** (a 2024 CARFAX
study found ~2.1 million US vehicles on the road with rolled-back odometers, up 14% since 2021,
roughly $4,000 average loss per buyer) and **title washing** (a salvage or flood brand erased by
re-registering in a jurisdiction with weaker enforcement).

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| US Truth in Mileage Act (49 U.S.C. § 32705) | Odometer disclosure at every ownership transfer, currently the first 20 years from Model Year 2011 |
| NMVTIS (28 CFR Part 25 Subpart B) | Federal US title-brand and odometer database; states must report title data within 24 hours — built specifically to defeat title washing and stolen-vehicle reintroduction |
| EU End-of-Life Vehicles Regulation ((EU) 2026/1738) | In force 13 Aug. 2026, applies generally from 1 Sept. 2028; mandates a **Digital Circularity Vehicle Passport** (composition, critical-raw-material content, traceability) for new vehicle types from 1 Sept. 2032, plus an EU-wide Extended Producer Responsibility system from 2029 and minimum recycled-content rules |

NMVTIS and TIMA are the closest existing precedent for what this profile aims at: a title/mileage
history that survives an attempted re-registration elsewhere, the same "the honest trail is
checkable and an absent one is itself the finding" posture this project already applies elsewhere
(CLAUDE.md's own research notes on burden-shifting). This profile does not replace either — it is a
shape the data they already require can be put into, verifiably (OWM-4 §5).

## 3. Subject granularity: always instance-level

A VIN is issued once, is globally unique, and never changes for the life of the vehicle — there is
no lot stage, the same fixed answer `aviation.v1` gives for aircraft parts (OWM-4 §10.1). Individual
major components (engine, transmission) that carry their own serial numbers are tracked the same
way, as their own instance-level subjects, linked to the vehicle via `aggregation` (§5) — which is
also how this profile answers "matching numbers" without a dedicated mechanism: compare the engine
subject in the vehicle's *original* production-time `aggregation` against whatever is aggregated
now (§6).

## 4. Events

| `event` | Meaning |
|---|---|
| `production` | The vehicle (or a major component) is manufactured and receives its VIN or serial |
| `aggregation` | A component installed into, or removed from, the vehicle — `action: install \| remove` |
| `transport` | Import/export shipment, departure or arrival |
| `handover` | Change of ownership |
| `measurement` | Automated telematics/odometer data, device-sourced |
| `inspection` | A body certifies roadworthiness, or declares salvage/total-loss |
| `processing` | End-of-life dismantling: the vehicle as input, recovered parts/materials as outputs |
| `decommission` | The vehicle's life ends — scrapped, destroyed, exported permanently |

`measurement` is the one event requiring entry type `sensor_reading`; every other event is an
ordinary self-declaration (`assertion`), the same binding rule every prior profile uses.

## 5. Two paths to an odometer reading — device evidence and human claim

Not every odometer reading comes from a connected car. `measurement` (`quantity_kind: "odometer"`)
carries genuine device-sourced telematics data, signed by a device key — the strong evidence path.
`inspection.odometer` and `handover.odometer` carry a **human-witnessed reading**, an ordinary claim
by whoever inspected or transacted the vehicle, the same claim/confirmation split OWM-4 §11
establishes generically. Rollback is detectable either way: a later reading — device-sourced or
claimed — **lower** than an earlier one in the same vehicle's history is a direct contradiction, no
different in kind from the split-view detection this project's log already exists for elsewhere.

## 6. Matching numbers, without a dedicated mechanism

The one clear case found in this project's research passes of organic market demand for exactly
this kind of provenance, with no regulatory mandate behind it: collector-market "numbers-matching"
verification, cross-checking chassis, engine and transmission identity against factory records.
This profile adds nothing new for it — the `production`-time `aggregation` already names the
original engine and transmission subjects; a later `aggregation` naming different subjects for the
same vehicle *is* the record of a component swap. A client answers "does this car still have its
original engine" by comparing two entries it already has, not by trusting a summary field.

## 7. End-of-life circularity

`processing` models exactly what the EU's ELV Regulation is built around: a decommissioned vehicle
dismantled into recovered parts and materials, inputs and outputs linked through `par` the same way
`food.v1`'s processing chain already works. This profile does not compute recycled-content
percentages or Extended Producer Responsibility figures — that is downstream analysis on top of
what the chain already records, not something the log itself needs to know.

## 8. Claim, not confirmation

`inspection.result` is what the inspecting body says. Whether that body is a legitimate,
accredited inspection authority — not a rubber stamp — is answered by its entity trust level
(OWM-6), the same pattern `pharma.v1`'s QP release and `aviation.v1`'s Part-145 release both
already establish.

## 9. Identifiers

| Kind | Note |
|---|---|
| VIN | `vin`, 17 characters, ISO 3779 — the vehicle's own subject |
| Component serial | `serial`, free text — engine, transmission, tracked the same way |
| Component type | `component_type`: `vehicle` \| `engine` \| `transmission` \| `other` |

## 10. Data protection

`party` knows only businesses — manufacturer, dealer, workshop, inspection body — the same rule
every prior profile applies (OWM-4 §13). Driver identity, insurance claims naming a person, and
anything else about who was behind the wheel have no field anywhere in this profile.

## 11. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Odometer rollback | buyer pays for mileage that was never driven | a later reading lower than an earlier one, device- or human-sourced, is a direct contradiction (§5) |
| Title washing via re-registration elsewhere | a salvage/flood-branded vehicle re-enters the market as clean | the chain's own history stays intact regardless of what a new jurisdiction's registry separately says |
| Forged inspection/roadworthiness certificate | an unsafe vehicle looks certified | entity trust level of the inspecting body's key, computed via OWM-6, not the entry's mere presence (§8) |
| Scrapped vehicle's VIN reused | a decommissioned identity re-enters circulation | the same subject-reappearing-after-`decommission` contradiction `pharma.v1` §9 already makes structurally detectable |
