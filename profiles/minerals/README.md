<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/minerals/` — Raw materials profile `minerals.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-minerals.md`](../../spec/owm-4-minerals.md).

| Event (`event`) | Meaning |
|---|---|
| `production` | Ore or concentrate is extracted at a mine |
| `aggregation` | Batches from several sources combined before smelting, or split |
| `transport` | Departure or arrival of a shipment |
| `processing` | Smelting/refining — raw material in, refined metal out — the control point |
| `handover` | Change of ownership |
| `measurement` | Assay/purity lab results |
| `release` | A smelter or refiner certifies conformance to a due-diligence audit scheme |

## The smelter/refiner is the control point

OECD Due Diligence Guidance concentrates verification here specifically, because this is where
materials from many, often untraceable, upstream sources converge into a fungible output. This
profile follows that: `release` is where a conformance claim lives, not a mechanism spread across
every upstream mine.

## No decommission

A mineral batch does not have a life that ends — `processing` already retires an input subject into
its output the moment it is smelted, the same mechanism `food.v1` uses for milk becoming cheese.

## Lot upstream, sometimes serialized downstream

Ore is always lot-level. Refined output can carry its own serial — LBMA "Good Delivery" gold and
silver bars do — the same `lot`/`serial` convention `pharma.v1`, `vehicle.v1` and `electronics.v1`
already use.

Example payloads for every event are in [`minerals_test.go`](minerals_test.go).
