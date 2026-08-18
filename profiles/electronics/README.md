<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/electronics/` — Electronics profile `electronics.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-electronics.md`](../../spec/owm-4-electronics.md).

| Event (`event`) | Meaning |
|---|---|
| `production` | A component lot or a finished device comes into being |
| `aggregation` | Components assembled into a board or device — a bill of materials |
| `transport` | Departure or arrival of a shipment |
| `handover` | Change of ownership |
| `measurement` | Reliability/burn-in test data, or environmental sensor data |
| `release` | Compliance certification — CE, RoHS, REACH |
| `processing` | End-of-life recycling: the device in, recovered materials out |
| `decommission` | The unit's life ends — recycled, destroyed, lost, disposed |

## IPC-1782, not EPCIS

The electronics industry's own manufacturing/supply-chain traceability standard — four levels each
of material and process traceability. This profile's events are shaped to be expressible against
it, the same relationship `food.v1` has to GS1 EPCIS 2.0.

## Two tiers, the pharma.v1 shape

Small components use lot-level subjects (IPC-1782's M-level); finished, individually serialized
devices move to instance-level. No dedicated field — a `product` carrying `serial` is one specific
unit, one carrying only `lot` is a batch, the same convention `pharma.v1` and `vehicle.v1` already
use.

## Digital Product Passport fields

`recycled_content_pct`, `repairability_index`, `warranty_months` on `product` — aimed directly at
the EU DPP's own reported key data fields for electronics. Asserted, not certified: checked against
form only, the same claim/confirmation split as everything else in this profile.

## Never consumer-linked

`party` knows only businesses. End-user ownership is out of scope entirely, not merely discouraged.

Example payloads for every event are in [`electronics_test.go`](electronics_test.go).
