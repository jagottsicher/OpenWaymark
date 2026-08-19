<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/eudr/` — Deforestation-free commodities profile `eudr.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-eudr.md`](../../spec/owm-4-eudr.md).

Timber, cocoa, coffee, palm oil, soy, rubber, cattle — named after the regulation, not a single
commodity, because what unifies these otherwise unrelated supply chains is exactly one shared
requirement, not any one commodity's own processing steps.

| Event (`event`) | Meaning |
|---|---|
| `production` | Harvest at the plot — carries the geolocation and the deforestation-free claim |
| `aggregation` | Plot-level harvests pooled into a batch |
| `transport` | Departure or arrival of a shipment |
| `processing` | Cocoa beans into chocolate, raw rubber into processed rubber, and so on |
| `handover` | Change of ownership |
| `measurement` | Moisture/quality sensor data, or geo-tracked shipment monitoring |
| `release` | The Due Diligence Statement itself — filed, and rated for risk |

## Geolocation is the center of gravity

`product.geolocation` carries either `point` (a single lat/lon, for plots ≤4 ha and cattle
establishments) or `polygon` (an array of lat/lon vertices, for larger plots) — the EU
Deforestation Regulation's own point/polygon split, coordinates to at least six decimal degrees.
`product.deforestation_free` is the producer's own claim at harvest, not a confirmation.

## The DDS as a claim

`release` models the Due Diligence Statement itself, including the regulation's own three-way risk
rating (`negligible` \| `standard` \| `high`). Whether the filing operator is trustworthy is a
separate, computed question — their entity trust level (OWM-6).

## The one field closer to personal data than any other in this project

A precise plot coordinate can identify a single smallholder family's land. It is erasable under the
core mechanism like any payload field, but data minimisation at collection is the actual measure to
rely on.

Example payloads for every event are in [`eudr_test.go`](eudr_test.go).
