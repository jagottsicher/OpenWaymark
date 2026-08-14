<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-0 — Protocol overview

**Status:** draft · **Format version:** 1 · **Date:** 2026-08-10

This document describes the basic terms, the crypto parameters and the wire format of entries. It
is the normative reference for `core/`. The test vectors under
[`testdata/vectors/`](../testdata/vectors/) are part of this specification: a third-party
implementation counts as conformant when it reproduces the vectors there byte for byte.

The key words MUST, MUST NOT, SHOULD and MAY are to be read in the sense of RFC 2119.

## 1. Terms

| Term | Meaning |
|---|---|
| **Node** | Server that keeps a log and is authoritative for its own data. |
| **Entity** | Participant with a key pair — business, authority, certifier, person. |
| **Subject** | The thing being talked about: lot, individual item, container, device. |
| **Entry** | A signed statement by an entity about a subject. |
| **Payload** | The actual data belonging to the entry. Lives **off-chain**, not in the log. |
| **Commitment** | Salted hash of the payload. Only it goes into the log. |
| **Log** | Append-only Merkle tree of a node over its entries. |
| **STH** | Signed Tree Head — signed snapshot of the log state. |
| **Monitor** | Independent software that collects STHs and checks them for contradictions. |
| **Profile** | Industry schema that lays down the structure and mandatory fields of the payload. |

At its core an entry says: *this entity claims something at this point in time about this subject,
and what is claimed is exactly the payload with this commitment.*

## 2. Why the payload does not belong in the log

The log is append-only and is witnessed to the outside through STHs. What is once in it cannot be
removed again without breaking every STH ever issued. Personal data must therefore never sit in
the log — otherwise erasure under the GDPR is technically impossible.

The log accordingly contains the commitment and nothing else. The payload and the salt belonging
to it live in a separate blob store of the same node. An erasure removes blob and salt; the tree
stays unchanged, all proofs stay valid, and without the salt the commitment is no longer a way
back to the payload.

> **Hard rule.** An entry MUST NOT contain personal data in the clear. This holds for every field,
> and in particular for the subject ID: it is an opaque identifier, not a name, not an address,
> not a coordinate.

A bare hash of the payload would not be enough for that. With a small value range — a postcode, a
GPS coordinate to three decimal places, a name from a known list — the plaintext can be recovered
by trying everything. The salt makes that attack impossible, and because it is erased along with
the payload, the erasure is final.

## 3. Crypto parameters

Post-quantum schemes exclusively. No RSA, no ECC, no hybrid model.

| Purpose | Scheme | Parameters |
|---|---|---|
| Signatures, node and entity keys | ML-DSA-65 (FIPS 204) | public key 1952 B, signature 3309 B |
| Signatures, sensors and bulk entries | ML-DSA-44 (FIPS 204) | public key 1312 B, signature 2420 B |
| Key encapsulation (from stage E5) | ML-KEM-768 (FIPS 203) | — |
| Hash, commitment, Merkle tree | SHA-256 | 32 B |
| Serialisation | CBOR, Core Deterministic (RFC 8949 §4.2.1) | — |

### 3.1 Why SHA-256 despite the post-quantum claim

SHA-256 offers 128 bits of collision resistance. The best known quantum attack on collision
resistance (Brassard–Høyer–Tapp) needs quantum memory on a scale that does not make the attack
practically superior to classical methods; Grover halves preimage security to a still sufficient
128 bits. SHA-256 is therefore post-quantum-appropriate — and at the same time keeps compatibility
with RFC 6962, whose tree construction and reference implementation OpenWaymark adopts.

### 3.2 Why two signature strengths

ML-DSA-65 costs 3309 bytes per signature. A million entries are roughly 3.3 GB in signatures
alone — on Raspberry-Pi-class hardware, which the concept expressly wants to support, that is not
a detail. ML-DSA-44 (2420 B) is intended for sensor readings and bulk entries, whose individual
value is small and whose number is large. The second countermeasure, batching over an intermediate
Merkle tree at the issuer, is dealt with in [OWM-2 §8](owm-2-log.md#8-batch-signing).

### 3.3 Domain separation

Every hash computation and every signature is bound against a label, so that a value from one
context is never valid in another.

For hashes:

```
H(label, p₁ … pₙ) = SHA-256( u8(len(label)) ‖ label ‖ u64be(len(p₁)) ‖ p₁ ‖ … ‖ u64be(len(pₙ)) ‖ pₙ )
```

`u8` is one byte, `u64be` a 64-bit integer in big-endian order. The length prefixes make the input
prefix-free: no two different argument lists produce the same hash input.

| Label | Use |
|---|---|
| `OWM/1 key-id` | key identifier from algorithm and public key |
| `OWM/1 entry-id` | content address of an entry |
| `OWM/1 subject-id` | derivation of a subject ID from namespace and value |
| `OWM/1 commit` | payload commitment |

Signatures use the context string from FIPS 204 (`ctx`) rather than a prefix in the message text:

| Context | Use |
|---|---|
| `OWM/1 entry` | signature over an entry |
| `OWM/1 sth` | signature over a signed tree head (OWM-2) |

## 4. Identifiers

### 4.1 Key identifier

```
KeyID = H("OWM/1 key-id", u16be(alg), pubkey)
```

32 bytes. The algorithm goes into it so that the same byte string does not yield the same
identifier under two different schemes.

### 4.2 Subject ID

32 bytes, opaque. It MAY be chosen freely (at random) or derived:

```
SubjectID = H("OWM/1 subject-id", namespace, value)
```

`namespace` names the identification system, for instance `gs1:sgtin` or `owm:batch`; `value` is
the identifier within it. Derivation is convenient but **not a confidentiality measure**: whoever
knows the namespace and a small value range can try the ID out. Where that would create
linkability, a random subject ID is to be chosen.

### 4.3 Entry identifier

```
EntryID = H("OWM/1 entry-id", canonical_cbor(Entry))
```

The identifier covers the entry, **not** the signature. That keeps it stable when the same entry
is signed again or by several parties — ML-DSA signs randomised by default, and a
signature-dependent identifier would not be reproducible. That a leaf in the log cannot be
separated from its signature is ensured by the leaf computation in OWM-2, which goes over the
complete signed entry.

## 5. Payload commitment

```
Salt        = 32 random bytes from a cryptographic random number generator
Commitment  = HMAC-SHA-256( key = Salt, msg = u8(len("OWM/1 commit")) ‖ "OWM/1 commit" ‖ payload )
```

Every payload MUST get its own, freshly drawn salt. A reused salt allows equal payloads to be
recognised across entries, and it survives the erasure of the one entry in the other.

Properties: **binding**, because a second payload with the same commitment requires a SHA-256
collision. **Hiding**, because without the salt every payload is equally plausible — even with a
value range of a few possibilities.

## 6. Entry format

An entry is a CBOR map with integer keys, encoded per RFC 8949 §4.2.1 (Core Deterministic
Encoding).

| Key | Name | Type | Mandatory | Meaning |
|---|---|---|---|---|
| 1 | `v` | uint | yes | format version, currently `1` |
| 2 | `typ` | uint | yes | entry type, see 6.1 |
| 3 | `prof` | tstr | no | profile identifier, e.g. `food.v1` (OWM-4 §2) |
| 4 | `subj` | bstr(32) | yes | subject ID |
| 5 | `iat` | int | yes | issuing time, milliseconds since the Unix epoch, UTC |
| 6 | `iss` | bstr(32) | yes | key identifier of the issuer |
| 7 | `cmt` | bstr(32) | no | payload commitment |
| 8 | `par` | array | no | predecessor entries, see 6.2 |
| 9 | `tgt` | array | no | target entry, only for `revocation` and `erasure` |

Optional fields are **left out** when absent. They MUST NOT be encoded as `null` or as an empty
value — otherwise there would be two encodings of the same entry and therefore two content
addresses.

### 6.1 Entry types

| Value | Type | Meaning |
|---|---|---|
| 1 | `assertion` | Self-declaration about a subject: production, transport, processing, handover. |
| 2 | `attestation` | Statement about another entity or a key, for instance a certification. The subject here is the key identifier of the party confirmed. |
| 3 | `revocation` | Revocation of an earlier entry. `tgt` names it. |
| 4 | `key_rotation` | Announcement of a successor key, see OWM-3. The payload contains the new public key and is not erasable. |
| 5 | `sensor_reading` | Automatically captured measurement, issued by a device key. |
| 6 | `erasure` | Witness that payload and salt of an earlier entry were erased. `tgt` names it. See OWM-2 §7. |

`revocation` and `erasure` are expressly different things and MUST NOT be conflated. A revocation
is a **claim about the world** — the statement was false or no longer holds. An erasure witness is
a **fact about storage** — the statement still stands, but its evidence is gone and can no longer
be checked.

The separation is not cosmetic. Were the two to coincide, every erasure under Article 17 GDPR
would look like an admission that the statement had been false — a data subject exercising their
right would thereby damage the reputation of their supply chain partner against their will.
Conversely, a node could withhold evidence and pass that off as an erasure. An observer has to be
able to tell the two apart (OWM-9 A3).

Neither type carries a `cmt`: they have no payload of their own. Whoever wants to state a reason
points through `par` to an `assertion` entry that carries it — reasons for erasure are themselves
often personal and therefore do not belong in the log but behind a commitment.

### 6.2 Entry reference

A reference is a CBOR array of fixed length 2:

```
[ entry_id : bstr(32), log_id : bstr(0) | bstr(32) ]
```

`log_id` names the log in which the entry is to be found and is a hint for retrieval — not part of
the identity. If it is unknown, an empty byte string stands there. The fixed array length avoids
two admissible encodings of the same reference.

`par` maps the supply chain as a directed acyclic graph. Several predecessors mean merging — three
farms deliver milk for one wheel of cheese. Several entries with the same predecessor mean
splitting — a lot is broken up into packs. The event semantics on top of that are laid down by the
respective profile (OWM-4, modelled on GS1 EPCIS 2.0).

### 6.3 Signed entry

```
{ 1: e   : bstr,   ; canonical CBOR encoding of the entry, embedded as a byte string
  2: alg : uint,   ; signature algorithm
  3: sig : bstr }  ; signature over e with context "OWM/1 entry"
```

The entry is embedded as an **opaque byte string**, not as a nested map. That way every side signs
and checks exactly the same bytes; a re-encoding that might differ never takes place. The lesson
comes from JWS and COSE, where precisely this ambiguity has led to vulnerabilities.

| `alg` | Scheme |
|---|---|
| 1 | ML-DSA-44 |
| 2 | ML-DSA-65 |

The signature goes over the content of `e`, with the FIPS 204 context string `OWM/1 entry`.

### 6.4 Canonicality when decoding

A receiver MUST reject an encoding that is not canonical. The check is mechanical: decode,
re-encode, compare bytes. Without it there would be several valid byte sequences for one entry and
therefore several content addresses — and an attacker could attach a valid signature to a
differently encoded entry.

Also to be rejected: duplicate map keys, indefinite-length encodings and unknown map keys within
the entry.

## 7. Federation, in one paragraph

Nodes are found over DNS:

```
_openwaymark.example.com.  IN TXT  "v=owm1; node=https://provenance.example.com"
```

The label is `_openwaymark`, not the generic `_provenance`, and is to be registered with IANA
later per RFC 8552. Participants without a domain of their own are referred to a community node
through a lightweight fallback registry; the registry itself holds no product data.

Nodes exchange STHs in a targeted way with their actual supply chain partners and additionally
with independent monitors. Why both are necessary and what it wards off is in the
[threat model](owm-9-threat-model.md). The details follow in OWM-2 and OWM-5.

## 8. Versioning

The field `v` names the format version of the entry. New mandatory fields or changed meanings
raise it. As long as version 1 counts as a draft, the format can change without a migration path.

## 9. Further documents

| Document | Content | Status |
|---|---|---|
| OWM-0 | this overview | draft |
| OWM-1 | core data model in detail | contained in OWM-0 |
| OWM-2 | [log, Merkle tree, STH, proofs, erasure path](owm-2-log.md) | draft |
| OWM-3 | [keys, node identity, directory and rotation](owm-3-keys.md) | draft |
| OWM-4 | [profile mechanism and food profile](owm-4-profiles.md) | draft |
| OWM-5 | federation, discovery, gossip | planned |
| OWM-6 | trust levels and attestation | planned |
| OWM-7 | [node API](owm-7-node-api.md) | draft |
| OWM-9 | [threat model](owm-9-threat-model.md) | draft |
