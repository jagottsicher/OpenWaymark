<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/aviation/` — Aircraft parts profile `aviation.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-aviation.md`](../../spec/owm-4-aviation.md).

| Event (`event`) | Meaning |
|---|---|
| `production` | The part is manufactured, first Authorized Release Certificate (POA) |
| `aggregation` | Installed into, or removed from, a higher assembly |
| `transport` | Departure or arrival of a shipment |
| `handover` | Change of ownership or operator (ATA Spec 2000 ch. 15) |
| `measurement` | Condition-monitoring sensor data |
| `release` | A Part-145 organization re-certifies the part after repair/overhaul |
| `decommission` | The part's life ends — life-limit reached, scrapped, lost, destroyed |

## Always instance-level

Unlike `food.v1` (lot-level default) or `pharma.v1` (two-tier), every aircraft part already carries
its own serial number from manufacture — no bulk-lot stage exists to model. Every subject in this
profile is one physical part, from `production` onward.

## Life-limited parts

`product.life_limited` and `product.cycle_limit` mark a part with a hard flight-cycle limit;
`product.cycles_used`, asserted at `production` and at every `release`, carries the cumulative
count — the same shape the industry's own paper LLP tracking sheets already use. This profile does
not enforce the limit; a client compares the latest `cycles_used` against `cycle_limit` itself.

## Claim, not confirmation

A `release` entry's `certified: true` is what the releasing organization says. Whether that
organization's own approval backs it — AS9100-certified, not an AS6081 case waiting to happen — is
a separate, computed question: its entity trust level (OWM-6).

## Never patient- or crew-linked

`party` knows only businesses. Flight operations, crew records and passenger data have no field
anywhere in this profile.

Example payloads for every event are in [`aviation_test.go`](aviation_test.go).
