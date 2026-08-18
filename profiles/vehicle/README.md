<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/vehicle/` — Vehicle profile `vehicle.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-vehicle.md`](../../spec/owm-4-vehicle.md).

| Event (`event`) | Meaning |
|---|---|
| `production` | The vehicle or a major component is manufactured, receives its VIN or serial |
| `aggregation` | A component installed into, or removed from, the vehicle |
| `transport` | Import/export shipment |
| `handover` | Change of ownership |
| `measurement` | Automated telematics/odometer data, device-sourced |
| `inspection` | Roadworthiness certification, or a salvage/total-loss declaration |
| `processing` | End-of-life dismantling: the vehicle in, recovered parts/materials out |
| `decommission` | The vehicle's life ends — scrapped, destroyed, exported permanently |

## Always instance-level

A VIN is issued once, globally unique, for the vehicle's whole life — no lot stage exists to model,
the same fixed answer `aviation.v1` gives for aircraft parts.

## Two paths to an odometer reading

`measurement` (`quantity_kind: "odometer"`) is genuine device-sourced telematics data, signed by a
device key. `inspection.odometer` and `handover.odometer` carry a human-witnessed reading instead —
an ordinary claim. Either way, a later reading lower than an earlier one in the same vehicle's
history is a direct, structural contradiction — the mechanism this profile exists to make odometer
rollback detectable.

## Matching numbers without a dedicated mechanism

Comparing the engine/transmission subject named in a vehicle's original production-time
`aggregation` against whatever is aggregated now answers "does this car still have its original
engine" — the collector market's own question — without any field or event built specifically for
it.

## Never driver-linked

`party` knows only businesses. Nothing about who was driving, or any insurance claim naming a
person, has a field anywhere in this profile.

Example payloads for every event are in [`vehicle_test.go`](vehicle_test.go).
