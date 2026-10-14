<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/food/` — Food profile `food.v1` · Apache-2.0

OpenWaymark's first schema profile. The events follow **GS1 EPCIS 2.0** rather than being invented
anew: EPCIS is the language in which trade and logistics describe supply chain events anyway.

| Event (`event`) | EPCIS 2.0 | Meaning |
|---|---|---|
| `production` | ObjectEvent, ADD, `commissioning` | An item comes into being and receives its ID |
| `aggregation` | AggregationEvent, ADD/DELETE | Packing and unpacking — eggs into cartons of ten |
| `transport` | ObjectEvent, OBSERVE, `shipping`/`receiving` | Departure and arrival, two separate entries |
| `processing` | TransformationEvent | Inputs become other goods — milk becomes cheese |
| `handover` | TransactionEvent | A change of responsibility or ownership |
| `measurement` | `sensorElementList` | A series of readings from a device, the cold chain for instance |

## One ID, six events

The event type sits **in the payload**, not in the profile ID. If it sat in the entry's `prof`
field, it would stay visible after an erasure what kind of event it had been. As it is, all that
remains is: at some point there was a food event concerning a subject.

## Aggregation and processing

The difference is at the heart of every real food chain:

- **Aggregation** is reversible. The components stay what they are; the subject of the entry is
  the enclosing unit, and the components are listed in `children`.
- **Processing** is not reversible. The inputs cease to be. Provenance stays traceable all the
  same, because the input entries are named in the entry's `par` field — there, and only there,
  is where the provenance graph comes from.

## Measurements

`measurement` must be submitted with entry type `sensor_reading`, everything else with
`assertion`. That is not checked by the JSON schema but by a profile rule — the schema does not
see the entry. Without that binding, a hand-written cold chain could later be passed off as a
device record.

The value of automatically captured readings lies precisely in their being able to **contradict**
a human self-declaration — and this profile does exactly that, not just in principle: its
cross-check (`profiles.Options.CrossCheck`) compares a `transport` event's promised
`conditions.temperature_c` range against a linked `measurement` event's `readings`, client-side,
once a caller opts in (`client/verify.Options.Profiles`). See
[OWM-4 §4.5](../../spec/owm-4-profiles.md#45-client-side-cross-checking-against-sensor-readings)
and [OWM-9 A4](../../spec/owm-9-threat-model.md#a4--lying-at-first-capture--the-oracle-problem).

## Personal data

The profile knows businesses, not natural persons: `party` has fields for a company's name, GLN
and key ID. Whoever enters a person's name there creates a right to erasure where none was
needed. The subject ID must not be derived from personal data either — it is a lookup key and
deliberately guessable.

## Units and identifiers

- Quantities: UN/CEFACT Recommendation 20 (`KGM`, `GRM`, `LTR`, `H87` for pieces, `CEL` for °C)
- Trade items: GTIN, 8 to 14 digits
- Locations and businesses: GLN, 13 digits
- Countries: ISO 3166-1 alpha-2, uppercase
- Timestamps: RFC 3339 **with time zone**

Example payloads for every event are in [`food_test.go`](food_test.go).
