<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/eu/battery/` — Battery profile `eu/battery.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-battery.md`](../../../spec/owm-4-battery.md).

The exact identifier CLAUDE.md, README and OWM-4 §2/§14 have already used as the namespace-slash
example since this project's earliest specs — the second profile earmarked from the start, now
built.

| Event (`event`) | Meaning |
|---|---|
| `production` | A cell or pack is manufactured — carries the passport's core claims |
| `aggregation` | Cells assembled into a module or pack |
| `transport` | Departure or arrival of a shipment |
| `processing` | End-of-life material recovery: the battery in, recovered materials out |
| `handover` | Change of ownership |
| `measurement` | State of health, cycle count, capacity — ongoing, not only at birth |
| `release` | Third-party verification of a carbon footprint or due-diligence declaration |
| `decommission` | First life ends — second life, recycling, destruction, or disposal |

## Two verifications, one event

`product.carbon_footprint_kg_co2e_per_kwh` is the manufacturer's own declared figure. `release`
(`standard: "carbon-footprint-verification"`) is its third-party verification; a second,
independent use (`standard: "due-diligence"`) covers the battery's own active-material supply
chain — the same cobalt, lithium and nickel `minerals.v1` already tracks upstream through smelting.

## Second life is not an ending

Unlike every profile since `pharma.v1` that dropped `decommission`, batteries genuinely end their
first life in more than one way, and the regulation cares which. `decommission.reason` distinguishes
`second_life` from `recycled`, `destroyed` and `disposed` — a battery entering second life keeps its
same identity, no fresh `production` entry.

Example payloads for every event are in [`battery_test.go`](battery_test.go).
