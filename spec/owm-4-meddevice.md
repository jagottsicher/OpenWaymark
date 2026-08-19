<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Medical devices `meddevice.v1`

**Status:** implemented (`profiles/meddevice/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) (the mechanism this profile is built on) ·
**See also:** [OWM-6](owm-6-trust.md) (claim vs. confirmation), [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

This document is a profile specification in the sense OWM-4 Part A defines, structured in parallel
to OWM-4 Part B (`food.v1`) and to `pharma.v1` and `aviation.v1`, its two closest relatives.

## 1. Purpose and scope

Covers devices with an individually meaningful life-cycle: **implantable devices** (pacemakers,
joint replacements, stents, heart valves) and **capital or reusable equipment** (imaging systems —
CT, MRI, X-ray — surgical equipment, patient monitors). Deliberately excludes disposable, low-risk
items (bandages, tongue depressors, single-use Class I goods): those have no per-unit story worth a
dedicated event chain, the same reasoning `food.v1` uses for a lot rather than an instance as its
default subject.

Both halves of that scope sit under the same regulatory backbone and share the same shape, which is
why they are one profile rather than two: neither has a lot stage, both need a service/calibration
history, and both end with a specific, nameable event (explant, or retirement).

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| EU MDR ((EU) 2017/745) | UDI system (UDI-DI, UDI-PI), EUDAMED registration, Article 18 Implant Card |
| EUDAMED Actor module | Economic operators (manufacturer, authorised representative, importer) register for a Single Registration Number before market placement — mandatory across all four EUDAMED modules from 28 May 2026 |
| FDA UDI system (21 CFR Part 801, Part 830) | US counterpart to MDR's UDI system; device identifier catalogued in GUDID |
| IMDRF | International Medical Device Regulators Forum — harmonises UDI approaches across the EU, US, and others (Brazil, China, Australia, Saudi Arabia, South Korea) |
| ISO 13485 | Quality management system certification for medical device manufacturers — the entity-trust-level anchor this profile leans on, the same way `aviation.v1` leans on AS9100 |

None of these regimes is reproduced normatively here (OWM-4 §5): this profile's schema checks form,
not compliance.

## 3. Subject granularity: always instance-level

Like `aviation.v1` and `vehicle.v1`, and unlike `food.v1` or `pharma.v1`'s two-tier model, every
subject in this profile is one physical unit from `production` onward. There is no bulk-lot stage
to model: a hip stem, a pacemaker and an MRI scanner are each already a single instance the moment
they exist. This is itself consistent with the regulation: UDI's own **UDI-PI** field can encode
either a lot number or a serial number depending on device type, but for the two categories this
profile actually covers — implants and complex active equipment — it is a serial number in
practice, because unit-level traceability is exactly what an Implant Card or a post-market
surveillance recall needs.

## 4. Events

| `event` | Meaning |
|---|---|
| `production` | The device or a component comes into being, carrying its UDI-DI and UDI-PI |
| `aggregation` | Components combined into a kit or system — a hip stem, head and cup; sub-assemblies into a finished scanner |
| `transport` | Departure or arrival of a shipment |
| `installation` | The device begins active service — implanted, or commissioned at a facility |
| `maintenance` | Service performed on a device already in use — preventive, corrective, calibration, a software update |
| `measurement` | Sensor or telemetry readings — implant remote monitoring, imaging QA phantom scans |
| `release` | Conformity assessment or certification — CE marking under MDR, FDA clearance, ISO 13485 |
| `decommission` | The device's active life ends — explanted, recalled, destroyed, disposed, retired |

No `processing`, no `storage`: nothing in this profile's scope is transformed into a structurally
different item the way pharma's API becomes a tablet, and most items here have no cold-chain-style
storage stay distinct from ordinary inventory — where one genuinely exists (a biologic-coated
implant, say), `transport.conditions` already covers it, the same reasoning `aviation.v1` gives for
the same omission.

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release`, `maintenance` and `decommission`, is an ordinary self-declaration (`assertion`) — the
same binding rule every prior profile uses, for the same reason: a hand-written service log must
not be passable off as sensor evidence.

## 5. `installation` — one event, two meanings, on purpose

MDR treats an implant beginning service inside a patient and a capital device beginning service at
a facility as structurally the same moment: Article 18's Implant Card records a UDI-DI/UDI-PI pair
at implantation, and capital equipment undergoes an equivalent installation qualification (IQ/OQ/PQ
— Installation, Operational, Performance Qualification) before first use. `installation.context`
(`implant` or `commission`) is the only field distinguishing them; everything else about the event
— that a specific serialized device began active service on a given date — is identical. No field
for a patient identifier exists anywhere in this schema, or anywhere else in this profile: see §9.

## 6. `maintenance` — service history as a first-class event

Every prior profile that tracks a device's life folds servicing into `release` (a Part-145
re-certification after repair, in `aviation.v1`) or leaves it out entirely. This profile makes it
its own event, because a capital device's safety case rests on cumulative service history as much
as on any single measurement: a CT scanner overdue on dose calibration, or a pacemaker due for a
battery-status check that was never logged, is a risk visible only across a maintenance history, not
in one reading. `maintenance.action` distinguishes preventive, corrective, calibration and
software-update service; `parts_replaced` gives a component-level trail for exactly the kind of
gray-market or counterfeit-part substitution `aviation.v1`'s AS6081 grounding already names as a
live problem in adjacent industries.

## 7. Claim, not confirmation

`release.certified: true` is what a manufacturer, a notified body or a quality system says, not
proof. Whether that claim is worth anything is a separate, computed question — the issuer's entity
trust level (OWM-6), walked from `attestation` entries back to a recognised root, with ISO 13485
certification and EUDAMED's Single Registration Number both plausible evidence a real accreditation
body could attest to. The same split applies to `maintenance`: that a service was performed and
passed is the servicer's claim, not confirmation that the servicer was authorised to perform it —
answered the same way, by the servicer's own entity trust level, not by this schema.

## 8. Identifiers

- Device: `udi_di` (UDI Device Identifier, model-level) and `udi_pi` (UDI Production Identifier,
  this specific unit — a serial number throughout this profile's scope, §3)
- Device class: `class` — MDR risk class, `I`/`IIa`/`IIb`/`III`
- Free-text device type: `device_type`, e.g. `"MRI scanner"`, `"hip stem implant"`
- Expiry, where applicable: `expiry`, for sterile devices with a shelf life
- Timestamps: RFC 3339 with time zone

## 9. Data protection — never patient-linked, structurally

This is the sharpest version of a constraint every profile in this project already follows: no field
for a patient's name, medical record number, date of birth or any other patient-identifying detail
exists anywhere in this schema, in `defs.json`'s shared `party` definition, or anywhere else in this
profile — not merely discouraged, structurally absent. `installation` records that a device began
service, never in whom; `decommission.reason: "explanted"` records that a specific serialized device
came out of service, never who it came out of, in exact parallel with how `pharma.v1`'s
`decommission` never names who received a dose. This matters more here than anywhere else in the
project: patient health data is a special category under GDPR Art. 9, not merely personal data, and
a field that could carry it even occasionally would be a design defect, not an oversight to catch
later.

## 10. Open points

- Whether `release` should distinguish a notified body's MDR conformity assessment from a
  self-declaration (permitted for some Class I/IIa devices under MDR) as separate `standard` values
  or leave that to free text, as it does today.
- EUDAMED's Single Registration Number is named here as a plausible OWM-6 attestation anchor but is
  not wired to any concrete accreditation-root mechanism — the same gap `minerals.v1` and
  `diamonds.v1` leave open for their own accreditation bodies.
- In vitro diagnostics (IVDR, (EU) 2017/746) are a related but distinct EU regulation, deliberately
  out of scope here — a test kit's traceability story is closer to `pharma.v1`'s than to an
  implant's or a scanner's, and would be its own profile if pursued.

## 11. Security considerations

| Risk | Mitigation |
|---|---|
| A previously decommissioned device reappearing (gray-market reuse of an explanted or recalled unit) | Structural contradiction: a subject that already carries a `decommission` entry reappearing under `installation` or `handover` is detectable by any client or monitor, the same pattern every prior profile with a `decommission` event relies on |
| Counterfeit or gray-market replacement parts entering a capital device's maintenance history | `maintenance.parts_replaced` gives a component-level trail; whether the servicer was authorised is answered by their entity trust level (§7), not by this schema |
| A patient identifier entering the log, deliberately or by mistake | Structurally impossible within this schema (§9) — `unevaluatedProperties: false` at the root rejects any field this profile does not define |
| An unlicensed or unaccredited party issuing a `release` certification | Not preventable by schema; made checkable — an unaccredited key's claim is visible as such to anyone who computes its entity trust level (§7) |
