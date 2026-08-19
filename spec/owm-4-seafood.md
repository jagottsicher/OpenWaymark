<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Seafood `seafood.v1`

**Status:** implemented (`profiles/seafood/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers seafood from catch through processing, distribution, to retail — vessel-to-plate. A close
sibling of `food.v1`, not a from-scratch design: `food.v1`'s own `production` event already names
"catch" as an example use, and this profile's own `production` event carries the same name and
meaning rather than inventing a separate concept — each profile still pins its own, independently
versioned schema (OWM-4 §3, §4.3), so the reuse is of concept and vocabulary, not shared bytes.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| EU CATCH (via TRACES NT) | Mandatory digital catch certificates for all fishery imports since 10 Jan. 2026, replacing paper. Fields include vessel name, flag, IMO or national registration number, FAO species code (ASFIS), FAO catch zone, fishing gear, weight, HS code, and a validating authority |
| US Seafood Import Monitoring Program (SIMP) | Chain-of-custody reporting from point of harvest to US market entry, for 13 species groups particularly vulnerable to IUU fishing and fraud (incl. tuna, red snapper, shrimp, shark, Atlantic cod) |

Both systems target illegal, unreported and unregulated (IUU) fishing. None of these regimes is
reproduced normatively here (OWM-4 §5): this profile's schema checks form, not compliance.

## 3. Events

| `event` | Meaning |
|---|---|
| `production` | The catch — the same name and meaning `food.v1` already names "catch" as an example of (§1) |
| `aggregation` | Catches from several trips or vessels combined into a lot |
| `transport` | Departure or arrival of a shipment |
| `processing` | Filleting, freezing, canning — raw catch in, processed product out |
| `handover` | Change of ownership — vessel to processor to distributor to retailer |
| `measurement` | Cold-chain temperature, the same mechanism `food.v1` already establishes |
| `release` | A validating authority certifies the catch certificate |

No `decommission`: like `minerals.v1`, a catch does not have a life that ends independently of
being processed or sold — `processing` and `handover` already carry the chain forward.

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release`, is an ordinary self-declaration (`assertion`).

## 4. The catch certificate as a claim

A catch certificate's data — vessel, flag, catch zone, species, gear, weight — is what the exporter
or vessel operator declares (carried on `production`'s `product` and `party` fields, §5). Its
**validation** by the flag or port state's own authority is the separate, third-party act EU CATCH's
own "Validating Authority" field records — modeled here as `release`, the same claim/confirmation
split every prior profile's release-shaped event already establishes. A validating authority is
typically a state body — CLAUDE.md §4.1's own level-6 example — and its entity trust level (OWM-6)
is what tells a verifier whether a `release` claim is worth anything.

## 5. Vessel and species identifiers

| Kind | Note |
|---|---|
| Vessel | `party.imo` (IMO number, or a national registration if none exists) and `party.flag` (ISO 3166-1 alpha-2), extending the shared `party` object |
| Species | `product.species`, free text — the FAO 3-alpha ASFIS code by convention, not a closed enum (the ASFIS list holds over 13,000 entries and is maintained outside this project) |
| Catch zone | `product.catch_zone`, free text — an FAO fishing area code by convention |
| Gear | `product.gear`, free text |

## 6. Data protection

`party` knows only businesses and vessels — no field for an individual crew member or buyer exists
anywhere in this profile, the same rule every prior profile applies (OWM-4 §13).

## 7. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Catch certificate validated by an unaccredited or fabricated authority | IUU catch enters the market as legitimate | entity trust level of the validating authority's key, computed via OWM-6, not the entry's mere presence (§4) |
| Species or catch-zone misdeclaration | overfished or restricted-zone catch passed off as compliant | the declaration is a checkable claim (§4) - the same claim/confirmation posture, not something this profile can verify against reality itself (the oracle problem, OWM-9) |
| Transshipment at sea obscuring true origin | catch laundered through an intermediate vessel | the `handover`/`transport` chain stays visible end to end regardless of how many intermediate steps occur |
