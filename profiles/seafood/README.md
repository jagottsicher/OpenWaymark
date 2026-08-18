<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/seafood/` — Seafood profile `seafood.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-seafood.md`](../../spec/owm-4-seafood.md).

| Event (`event`) | Meaning |
|---|---|
| `production` | The catch — same name and meaning as one of `food.v1`'s own named examples |
| `aggregation` | Catches from several trips or vessels combined into a lot |
| `transport` | Departure or arrival of a shipment |
| `processing` | Filleting, freezing, canning |
| `handover` | Change of ownership — vessel to processor to distributor to retailer |
| `measurement` | Cold-chain temperature |
| `release` | A validating authority certifies the catch certificate |

## A close sibling of food.v1

`food.v1`'s own `production` event already names "catch" as an example use. This profile's own
`production` carries the same name and meaning rather than inventing a separate concept — each
profile still pins its own schema independently (OWM-4 §3, §4.3) — vessel-to-plate is the same
shape as farm-to-consumer.

## The catch certificate as a claim

Vessel, flag, catch zone, species, gear, weight — what the exporter declares. Its **validation** by
a flag or port state authority (EU CATCH's own "Validating Authority" field) is `release`, the same
claim/confirmation split every prior profile's release-shaped event already establishes.

## Vessel identity

`party.imo` and `party.flag` extend the shared party object — a vessel is tracked the same way any
other party is, with two extra fields matching EU CATCH's own data model directly.

Example payloads for every event are in [`seafood_test.go`](seafood_test.go).
