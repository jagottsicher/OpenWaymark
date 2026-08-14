<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-3 — Keys, node identity, directory and rotation

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md), [OWM-2](owm-2-log.md) ·
**Threat model:** [OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

This document answers four questions:

1. Which keys exist and how are they identified?
2. What does a node's identity consist of and how does it sit on disk?
3. Whose entries does a node accept — and who decides that?
4. How does a key change without devaluing the statements made so far?

**What this document does not govern:** how an entity attains a trust level (OWM-6), how keys
become known between nodes (OWM-5), how the directory is served over HTTP (OWM-7).

## 2. Schemes

Post-quantum signatures per FIPS 204 (ML-DSA) exclusively. No RSA, no ECC, no hybrid model — the
reasoning is in OWM-0 §5.

| Scheme | `alg` | Public key | Signature | Intended for |
|---|---|---|---|---|
| ML-DSA-44 | 1 | 1312 B | 2420 B | sensors, bulk entries |
| ML-DSA-65 | 2 | 1952 B | 3309 B | node and entity keys |

The choice is not a security grading but a size trade-off: 889 bytes of difference per entry
decide, over years, the storage requirement of a node that takes in hourly series of readings. A
node MUST be able to verify both schemes. A node SHOULD keep its own key as ML-DSA-65.

Signatures are randomised (`Sign`, not `SignDeterministic`) — except for the test vectors, which
are generated deterministically so that they are comparable at all.

## 3. Key identifier

```
KeyID = H("OWM/1 key-id", u16be(alg), pubkey)
```

32 bytes. `H` is the length-prefixed hash function from OWM-0 §4.1; the scheme goes into it so
that the same byte string would not receive the same identifier under two different schemes.

The identifier is **self-certifying**: whoever has the public key recomputes it without consulting
a directory. A directory that hands out a key with different bytes for an identifier is thereby
not merely unreliable but provably wrong — a node MUST treat this case as an error and MUST NOT
use the key.

## 4. Node identity

A node keeps **two** key roles, and telling them apart is the heart of this section:

| Role | Changes | What for |
|---|---|---|
| Genesis key | never | derivation of the LogID (OWM-2 §2) |
| Signing key | may and should | STHs, erasure witnesses |

With a new node the two are the same. After the first rotation they are not, and the LogID stays
what it was regardless. Were the LogID bound to whichever key is current, every rotation would
devalue all references to this log ever issued — QR codes on packaging included, which nobody can
collect back in.

### 4.1 Identity file

The identity exists as a JSON file:

```json
{
  "alg": "ML-DSA-65",
  "seed": "…64 hex characters…",
  "genesis_public": "…3904 hex characters…",
  "created": "2026-08-11T06:12:00Z",
  "_note": "This file IS the node's private key. …"
}
```

What is stored is the **seed**, not the expanded key pair: FIPS 204 derives the pair from it
deterministically, and 32 bytes of hex can be written down, secured on paper and checked by hand
in case of trouble. An expanded ML-DSA-65 private key is 4032 bytes and none of those things.

Requirements:

- The file MUST be created with permissions `0600`, the directory with `0700`.
- An implementation MUST refuse to load if group or others have rights on the file. A
  world-readable identity file is a silent total loss: the node keeps signing, but so does
  everybody else.
- An existing identity file MUST NOT be overwritten. The write MUST use `O_EXCL`.
- `genesis_public` is redundant as long as no rotation has happened, and becomes the only source
  of the LogID after the first rotation. If the public key derived from the seed differs from
  `genesis_public`, loading MUST fail.

### 4.2 Loss and compromise

| Case | Consequence |
|---|---|
| Signing key lost, genesis key present | rotation, the log carries on |
| Genesis key lost, log present | LogID no longer recomputable; the log stays readable and checkable because the rotation chain is in it |
| Identity file compromised | the attacker can issue STHs for **arbitrary** roots. No internal mechanism helps. |

The last case is A3 from the threat model. The only effective answer is a monitor seeing two
contradictory STHs of the same size (OWM-2 §6.3) — the node cannot withdraw its own signature.
Hence: the file does not belong in a repository, not in an unprotected backup and, where
available, into a hardware security element rather than on disk.

## 5. Key directory

A node's directory answers exactly one question: **whose entries does this node accept?**

It is thereby the log's admission control. Before appending, a node MUST look up the issuer's
public key in its own directory and reject the entry if it is missing or disabled. A log without
this check would accept anything from anyone and would be worthless as provenance evidence.

Every directory record holds:

| Field | Meaning |
|---|---|
| `key_id` | identifier per §3, primary key |
| `alg`, `public` | scheme and public key |
| `label` | free text of the operator, not part of the protocol |
| `added_at` | time of admission |
| `disabled_at` | time of disabling, if disabled |
| `parent` | predecessor key, if admitted through a rotation (§6) |

### 5.1 Admission

Only the operator may admit, through the administration interface (OWM-7 §8) — or the protocol
itself through a rotation (§6). That follows from the federated model: a node is authoritative for
its own participants and for nobody else. Whoever is not listed here has a different node.

Admission is **repeatable**: admitting the same identifier with the same bytes again is not an
error. The same identifier with **different** bytes is one, and a fundamental one at that — it
would be a SHA-256 collision. An implementation MUST report that and MUST NOT replace the existing
key.

A disabled key is **not** re-armed by being admitted again. Putting it back into service is a
separate, explicit step.

### 5.2 Disabling

Disabling means: **no new** entries from this key. What it signed earlier stays valid.

That is not negligence but the condition for the log being a transparency log. A log that
retroactively devalues statements because a key was disabled later would no longer answer the
question "was this signature valid at time X?" — and precisely that question is the only reason to
keep a log. Whoever wants to withdraw a statement **in substance** revokes it with a `revocation`
entry (OWM-0 §3); whoever has to get rid of a payload erases it (OWM-2 §7). Both are entries in
the log, not holes in it.

The node MUST carry its **own** key in the directory. It signs erasure witnesses with it, and
those go through the same admission control as any foreign entry.

### 5.3 Disclosure to the outside

A node MUST hand out the public key belonging to an identifier (OWM-7 §4.9). Without this
disclosure a foreign client could not check a single signature: the entry names only the
identifier in `iss`, and the key cannot be recovered from it.

What is handed out is `alg`, `public`, `added_at`, `disabled_at` and `parent` — **not** the
`label`. The label is the operator's free text and in practice often carries a person's name; it
has no business in a public disclosure.

The disclosure also applies to **disabled** keys, with `disabled_at` set. Otherwise everything a
key signed before it was disabled would no longer be checkable — and §5.2 would be void.

Lookups happen one at a time by identifier. A node need not list its directory publicly and SHOULD
not: the list would be its participant register, and whoever wants to check a signature has the
identifier from the entry in front of them anyway.

## 6. Rotation

A key change is an entry in the log, not a procedure beside it.

```
typ  = key_rotation
subj = KeyID of the successor
iss  = KeyID of the predecessor
cmt  = commitment over the payload
```

Payload:

```json
{
  "alg": "ML-DSA-65",
  "public": "…hex of the successor public key…",
  "label": "Hof Sonnenblick (2027)"
}
```

Rules:

- The entry MUST be signed by the **predecessor**. That makes the rotation what it is meant to be:
  a statement by the previous holder, recorded in the log. A key that announces itself is not a
  rotation but a new registration — and that goes through §5.1.
- `subj` MUST be the identifier of the announced successor. Without this binding the log would
  carry a rotation to key A while the payload names key B — and **after an erasure of the
  payload** it would no longer be determinable which one was meant. The binding is mandatory for
  exactly that reason: it is the part of the statement that survives the erasure.
- Issuer and subject MUST be different.
- A node MUST check the announced length against the scheme named rather than guessing it.
- The node admits the successor to the directory with `parent = iss`.

### 6.1 Overlapping validity

The predecessor is **not** disabled by the rotation.

Both keys are valid alongside each other for a while. Otherwise every rotation would break
day-to-day operation: a sensor in a refrigerated lorry that has not yet seen the announcement goes
on signing with the old key, and its series of readings would drop out of the cold chain — because
of an administrative act that has nothing to do with the goods. Disabling the predecessor is a
separate, later step by the operator (§5.2).

How long the overlap SHOULD be depends on how long a device can be offline in the field. For
sensors in transport chains, weeks are realistic, not hours.

### 6.2 What rotation does not achieve

Rotation is **not** revocation. If a key was compromised, all entries signed with it remain validly
signed — including those the attacker produced. What helps:

1. Disable the predecessor (§5.2), so that no new ones are added.
2. Revoke the affected statements individually (`revocation`, OWM-0 §3).
3. Name the period from which the key counts as compromised.

Point 3 is the hard one: the log witnesses **when** a node took an entry in (OWM-2 §3.1), not when
a key went missing. Whoever claims the moment later than it was spares their own entries; whoever
claims it earlier devalues other people's. The protocol cannot resolve that — it is the same
borderline case as the oracle problem (OWM-9), only at the key level.

## 7. Sensor keys

A sensor receives its own key pair when put into service, where available in a hardware security
element. The **node operator** admits it to the directory and thereby binds it to their own
identity; there is no central body that certifies sensors.

A sensor's trust level is capped by that of its operator. The details — computation, inheritance,
minimum principle across the chain — are in OWM-6.

A sensor key SHOULD be ML-DSA-44 (§2) and SHOULD sign `sensor_reading` entries exclusively. A node
MAY enforce that; the profile can require it (OWM-4 §5).

## 8. Security considerations

| Attack | Effect | Countermeasure |
|---|---|---|
| Foreign key submits entries | none | directory rejects (§5) |
| Identifier points to different bytes | key confusion | self-certifying identifier (§3) |
| Rotation by the successor itself | takeover of an identity | only the predecessor may announce (§6) |
| Rotation without subject binding | target indeterminable after erasure | `subj` = KeyID of the successor (§6) |
| Identity file stolen | arbitrary STHs, split view | file permissions, HSM; detection only externally (OWM-9 A3) |
| Disabling abused as backdating | old statements devalued | disabling only takes effect forwards (§5.2) |
