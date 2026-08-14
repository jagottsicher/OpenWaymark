<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# Test vectors

These files are **part of the specification**, not mere test trimmings. A third-party
implementation counts as conformant with [OWM-0](../../spec/owm-0-overview.md) if it reproduces
them byte for byte. All byte strings are hex-encoded.

Regenerate — and that means changing the protocol, not just a test:

```sh
go test ./core/ -update
```

## `core-v1.json`

| Section | Checks |
|---|---|
| `hash_labels` | The domain-separated hash from OWM-0 §3.3. The two cases `["ab","c"]` and `["a","bc"]` must yield **different** results — an implementation without length prefixes produces the same value twice here and is open to attack. |
| `subject_ids` | The derivation `SubjectID = H("OWM/1 subject-id", namespace, value)`. |
| `keys` | Key derivation from the seed per FIPS 204 and the key ID `H("OWM/1 key-id", u16be(alg), pubkey)`. |
| `commitments` | The salted payload commitment. The salt is fixed here so that the vectors are reproducible; in production **every** payload gets a freshly drawn one. |
| `entries` | The canonical CBOR encoding, the content address and the signed envelope — once each for every entry type and for both signature levels. |

### On the signatures

`signature_deterministic` is produced with the deterministic branch of FIPS 204 and is therefore
reproducible. In production, signing is randomized ("hedged"); there every signature differs and
is valid nonetheless. An implementation that can only sign randomized therefore checks these
vectors by **verification**, not by regeneration.

### Order of checking

Anyone pitting their own implementation against this file is well advised to work from the bottom
up: `hash_labels` first, then `keys`, then `commitments`, and `entries` last. Otherwise an error
in the hash comes through as an apparent signature failure and costs time for nothing.
