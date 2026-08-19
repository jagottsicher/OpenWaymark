<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/meddevice/` — Medical device profile `meddevice.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-meddevice.md`](../../spec/owm-4-meddevice.md).

| Event (`event`) | Meaning |
|---|---|
| `production` | The device or a component comes into being, carrying its UDI-DI and UDI-PI |
| `aggregation` | Components combined into a kit or system |
| `transport` | Departure or arrival of a shipment |
| `installation` | The device begins active service — implanted, or commissioned at a facility |
| `maintenance` | Service performed on a device already in use |
| `measurement` | Sensor or telemetry readings — implant monitoring, imaging QA |
| `release` | Conformity assessment or certification |
| `decommission` | The device's active life ends — explanted, recalled, destroyed, disposed, retired |

## Two halves of scope, one profile

Implantable devices (pacemakers, joint replacements, stents) and capital/reusable equipment
(CT, MRI, X-ray, surgical equipment) share the same regulatory backbone — EU MDR's UDI/EUDAMED
system, FDA's UDI system/GUDID, harmonised through IMDRF — and the same shape: always
instance-level (§3 of the spec), no lot stage for either a hip stem or an MRI scanner. Disposable
Class I items (bandages) stay out of scope — no per-unit story worth a dedicated event chain.

## `installation`: one event, two meanings

MDR's own Article 18 Implant Card and a capital device's installation qualification (IQ/OQ/PQ)
record the same underlying moment — a specific serialized device begins active service.
`installation.context` (`implant` or `commission`) is the only field distinguishing them. No field
for a patient exists anywhere in this schema — see the data-protection section below.

## `maintenance`: service history as a first-class event

Every prior profile that tracks a device's life folds servicing into `release` (`aviation.v1`'s
Part-145 re-certification) or leaves it out. This profile makes it its own event, because a capital
device's safety case rests on cumulative history as much as on any single reading — a scanner
overdue on calibration is a risk visible only across a maintenance history. `parts_replaced` gives a
component-level trail against gray-market or counterfeit substitution.

## Never patient-linked, structurally

No field for a patient's name, medical record number or any other patient-identifying detail exists
anywhere in this schema, in `defs.json`'s shared `party` definition, or anywhere else in this
profile — not merely discouraged, structurally absent (`unevaluatedProperties: false` at the root
rejects any field the profile does not define). `installation` and `decommission` both record that
something happened to a device, never to whom.

Example payloads for every event are in [`meddevice_test.go`](meddevice_test.go).
