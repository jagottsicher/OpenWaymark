<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 Profile — Diamonds `diamonds.v1`

**Status:** implemented (`profiles/diamonds/`) · **Prerequisite:** [OWM-0](owm-0-overview.md),
[OWM-4 Part A](owm-4-profiles.md#part-a--the-mechanism) · **See also:** [OWM-6](owm-6-trust.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Covers diamonds from mine through cutting/polishing to a retailer — CLAUDE.md's own vision
section names "diamonds" as a founding example of what this project should demonstrate, alongside
food and batteries, and this profile is that example, concretely.

## 2. Regulatory grounding

| Regime | Covers |
|---|---|
| Kimberley Process Certification Scheme (KPCS) | Every cross-border shipment of rough diamonds requires a government-validated certificate in a tamper-resistant container: country of origin, issuing authority, a unique serial number, total carat weight and value. A central KP data system tracks volumes and values by participating country |
| US FTC Jewelry Guides (updated 2018) | Requires a clear "lab-grown"/"synthetic" qualifier whenever a seller markets a non-natural stone using the word "diamond" |

Neither regime is reproduced normatively here (OWM-4 §5): this profile's schema checks form, not
compliance.

## 3. Events

| `event` | Meaning |
|---|---|
| `production` | A rough diamond or parcel is extracted at a mine |
| `aggregation` | Rough parcels combined or split |
| `transport` | A KP-certified cross-border shipment, departure or arrival |
| `processing` | Cutting and polishing — rough diamond in, cut stone out |
| `handover` | Change of ownership |
| `measurement` | Automated gemological testing (e.g. photoluminescence spectroscopy) |
| `release` | A KP certificate is validated, or a grading report is issued (§4) |

No `decommission`: unlike a device or a vehicle, a polished diamond does not have a life that ends —
it stays itself indefinitely.

`measurement` is the one event requiring entry type `sensor_reading`; every other event, including
`release`, is an ordinary self-declaration (`assertion`).

## 4. Two certifications, one event

A diamond passes through two distinct third-party certifications, and this profile does not invent
a separate mechanism for each: both are `release`, distinguished by `standard`. `standard:
"kimberley-process"` is the KP certificate validating a rough shipment's conflict-free origin;
`standard` naming a grading laboratory (e.g. `"gia-grading"`, `"igi-grading"`) is the 4Cs report
issued after cutting, which is also where natural-vs-lab-grown determination happens. Whether the
certifying party is who it claims is answered by its entity trust level (OWM-6), the same claim/
confirmation split every prior profile's release-shaped event already establishes.

## 5. A genuinely new fraud pattern: reference reuse across subjects

Every prior profile's decommission-based fraud detection catches the *same* subject reappearing
after its life should have ended. Diamonds surface a different, real pattern instead: a laboratory
in Tel Aviv recently detected a lab-grown 6-carat stone fraudulently inscribed with a genuine GIA
report number belonging to a *different*, natural diamond of the same specifications — the
certificate's identity stolen for a different physical stone, not reused for the same one.
`release.reference` makes this structurally detectable the same way every other contradiction in
this project is: two different subjects, each carrying a `release` naming the identical
`reference`, is not proof of fraud by itself (nobody outside the log can confirm which stone the
number legitimately belongs to) — but it is exactly the kind of contradiction a client or monitor
can flag mechanically, the same limited, honest claim OWM-9 makes for every other use of this
pattern.

## 6. Identifiers

| Kind | Note |
|---|---|
| Carat weight | `carat`, a positive number |
| Origin country | `origin_country`, ISO 3166-1 alpha-2 — the KP-relevant mining country, which may differ from an event's own `location` |
| Natural vs. lab-grown | `natural`, boolean — the FTC-mandated disclosure |
| Lot | `lot`, free text — for a rough parcel before individual stones are separated |

## 7. Data protection

`party` knows only businesses — mine operator, cutter, grading laboratory, retailer. No field for a
named individual owner exists anywhere in this profile.

## 8. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Grading report reference stolen for a different physical stone | a lab-grown stone passes as the natural diamond the reference actually belongs to | the same reference claimed by two different subjects is a structural contradiction, detectable the same way a split view is (§5) |
| Undisclosed lab-grown stone sold as natural | consumer fraud, FTC violation | `natural: false` is a required disclosure field, not an afterthought — omitting it is itself a gap a client can flag |
| KP certificate validated by an unaccredited or fabricated authority | conflict diamond enters the market as clean | entity trust level of the validating authority's key, computed via OWM-6, not the entry's mere presence (§4) |
