<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/diamonds/` — Diamonds profile `diamonds.v1` · Apache-2.0

Full normative specification: [`spec/owm-4-diamonds.md`](../../spec/owm-4-diamonds.md).

CLAUDE.md's own vision section names "diamonds" as a founding example of what this project should
demonstrate, alongside food and batteries.

| Event (`event`) | Meaning |
|---|---|
| `production` | A rough diamond or parcel is extracted at a mine |
| `aggregation` | Rough parcels combined or split |
| `transport` | A KP-certified cross-border shipment |
| `processing` | Cutting and polishing — rough diamond in, cut stone out |
| `handover` | Change of ownership |
| `measurement` | Automated gemological testing (e.g. photoluminescence spectroscopy) |
| `release` | A KP certificate is validated, or a grading report is issued |

## Two certifications, one event

A diamond passes through two distinct third-party certifications — the Kimberley Process
certificate (rough-shipment conflict-free origin) and a laboratory's grading report (issued after
cutting, also where natural-vs-lab-grown is determined). Both are `release`, distinguished by
`standard`, not two separate mechanisms.

## A genuinely new fraud pattern

A real, documented case: a lab-grown stone fraudulently inscribed with a genuine GIA report number
belonging to a *different*, natural diamond. Two subjects each carrying a `release` naming the
identical `reference` is the structural contradiction that makes this detectable — a new pattern
compared to every prior profile's decommission-based one, since it's a different subject, not the
same one, that gives the fraud away.

## Mandatory disclosure

`product.natural` is the FTC-mandated natural-vs-lab-grown disclosure — present as a required
field, not an afterthought.

Example payloads for every event are in [`diamonds_test.go`](diamonds_test.go).
