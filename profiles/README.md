<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/` — Schema profiles · Apache-2.0

The core knows no industry schema. What may appear in a payload is laid down by a profile, which
is referenced through the profile ID in the entry (`prof`).

| Profile | ID | Status |
|---|---|---|
| [Food](food/) | `food.v1` | available |
| EU battery passport | still open | profile no. 2, mandatory from February 2027 |

Full description: [OWM-4](../spec/owm-4-profiles.md).

## What schema validation achieves

It is an **input filter, not a statement of truth**. A schema-conformant entry can be a complete
lie — the schema checks the form, not reality. It keeps typos, missing required fields and
confused formats out of the log so that a chain can be evaluated by machine at all later on.
Binding to the entry is the commitment's job, attributability the signature's.

## Immutability

A profile version never changes. If `food.v1` were different today from yesterday, an entry from
yesterday would be invalid today without anyone having touched it — and a monitor could no longer
reconstruct what a node validated against at the time. Changes appear as `food.v2`.
`Profile.SchemaDigest()` binds the ID to exactly the set of schema files that was shipped;
two nodes with the same profile name but different digests validate differently.

## Your own profile

```go
//go:embed schema/*.json
var schemaFS embed.FS

sub, _ := fs.Sub(schemaFS, "schema")
p, err := profiles.Load(profiles.Options{
    ID:    "eu/battery.v1",   // character set as in the prof field: a–z 0–9 . / - _
    Title: "EU battery passport",
    FS:    sub,
    Root:  "event.json",
    Rule:  bindEntryType,     // optional: checks that concern the entry
})
```

Schemas are compiled according to JSON Schema 2020-12, and `format` is validated. The compiler
rejects references to foreign URLs: a profile whose rules depend on somebody else's server is not
a fixed profile.

## Strictness when reading the payload

`Validate` reads more strictly than `encoding/json`, and for exactly one reason — the bytes of the
payload are pinned by the commitment, so every implementation has to read them the same way:

- **duplicate object keys** are an error (Go takes the last value, other languages the first —
  the same bytes would then mean different things),
- text after the top-level value is an error,
- nesting is capped at 32 levels.
