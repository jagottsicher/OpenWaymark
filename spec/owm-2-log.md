<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-2 — Log, Merkle tree, signed tree heads, proofs, erasure path

**Status:** draft · **Prerequisite:** [OWM-0](owm-0-overview.md) · **Threat model:**
[OWM-9](owm-9-threat-model.md)

The key words MUST, MUST NOT, SHOULD and MAY are to be understood as in RFC 2119.

## 1. Purpose and scope

Every node keeps exactly one append-only log of its entries. The log is **local**: there is no
global state all nodes would have to agree on, and no consensus mechanism. Tamper evidence does
not arise from many parties holding the same data, but from a node being unable to rewrite its own
history unnoticed once it has witnessed that history to more than one observer.

The tree construction is the one from **RFC 6962** (Certificate Transparency), adopted unchanged.
Deviations would only be available at the price of giving up the reference implementation and two
decades of analysis; OpenWaymark therefore deviates only where there is a reason — and the one
reason is erasability (§7), which CT does not know because CT never erases.

**What this document does not govern:** how proofs are transported over HTTP (OWM-7), how
successor keys are authorised (OWM-3), how STHs are exchanged between nodes (OWM-5). This document
defines the data structures and the rules by which they are checked.

## 2. Log identity

```
LogID = H("OWM/1 log-id", u16be(alg), genesis_pubkey)
```

32 bytes, derived from the **genesis key** of the log, not from whichever key is current. An
identifier that changed along would devalue every reference to this log ever issued at each key
rotation. The genesis key never changes.

The derivation makes the identifier self-certifying: whoever has the genesis key recomputes it
without consulting a directory. Which **successor** keys may sign for this log is answered by the
rotation chain in the log itself ([OWM-3](owm-3-keys.md)) — not by the identifier.

## 3. Leaf

A leaf is a CBOR map with integer keys, encoded per RFC 8949 §4.2.1 (Core Deterministic), as in
OWM-0 §6.

| Key | Name | Type | Mandatory | Meaning |
|---|---|---|---|---|
| 1 | `v` | uint | yes | format version, currently `1` |
| 2 | `log` | bstr(32) | yes | LogID, see §2 |
| 3 | `seq` | uint | yes | leaf index, starting at 0 |
| 4 | `ts` | int | yes | time of intake, milliseconds since the Unix epoch, UTC |
| 5 | `ent` | bstr | yes | canonical encoding of the signed entry (OWM-0 §6.3) |

A leaf MUST be ≤ 128 KiB. The signed entry sits in it as an **opaque byte string** and is not
re-encoded when the leaf is formed — the same rule and the same reason as in OWM-0 §6.3.

### 3.1 Why the leaf contains more than the entry

**`ent` and not just the entry identifier.** The entry identifier does not cover the signature
(OWM-0 §4.3, so that it stays stable under randomised ML-DSA). Were only the identifier in the
leaf, the signature would not be part of the tree: a node could later substitute a different valid
signature by the same issuer, or lose the signature entirely, without any inclusion proof noticing.
The tree MUST bind the entry **together with its signature**.

**`seq` and `ts`.** The point in time in `ent` is the issuer's claim about when they made the
statement. `ts` is the node's witness of when it took the statement in. The two are allowed to
diverge, and that they are allowed to is the point: a backdated entry can be recognised by its
intake time. Together with `seq` and `log`, a leaf is a non-repudiable statement by the node about
itself — *this is entry number N in log L, taken in at time T*.

**`log`.** Without the log identifier a leaf would be movable between logs. The identifier costs
32 bytes and makes every leaf attributable on its own, even without the accompanying STH.

The price of these decisions: two identical entries yield two different leaves, and the leaf can
only be formed once the sequence number has been assigned. Both are intended.

### 3.2 Leaf hash

```
LeafHash = SHA-256( 0x00 ‖ leaf_bytes )
MTH(l,r) = SHA-256( 0x01 ‖ l ‖ r )
```

RFC 6962 §2.1 unchanged. The prefixes `0x00` and `0x01` separate leaves from interior nodes and
thereby prevent the security-critical confusion of the two; that is a **different** domain
separation from the one in OWM-0 §3.3 and deliberately replaces it here, because compatibility
with the CT tree construction weighs more. Confusion with CT leaves is ruled out because
`leaf_bytes` in OpenWaymark is always a CBOR map with the fields from §3.

The hash of the empty tree is `SHA-256("")`, likewise per RFC 6962.

## 4. Signed tree head

| Key | Name | Type | Mandatory | Meaning |
|---|---|---|---|---|
| 1 | `v` | uint | yes | format version, currently `1` |
| 2 | `log` | bstr(32) | yes | LogID |
| 3 | `size` | uint | yes | tree size, number of leaves |
| 4 | `ts` | int | yes | time of issue, milliseconds since the Unix epoch, UTC |
| 5 | `root` | bstr(32) | yes | root hash over `size` leaves |
| 6 | `key` | bstr(32) | yes | key identifier of the signer |

Signing uses the context `OWM/1 sth` (OWM-0 §3.3). The envelope has the same shape as the signed
entry:

```
SignedSTH = { 1: sth : bstr, 2: alg : uint, 3: sig : bstr }
```

`key` sits **inside** the signed structure and not in the envelope. Otherwise the statement of
which key signed could be swapped unnoticed — which during a key rotation in particular would make
the question unanswerable whether the signer was authorised.

An STH over the empty tree (`size = 0`) is valid and serves as a founding witness.

A node SHOULD issue STHs at fixed intervals, even when nothing has been appended. A silent log is
otherwise indistinguishable from a halted one (OWM-9 A3).

## 5. Proofs

### 5.1 Inclusion proof

Shows that a particular leaf is contained at position `i` in a tree of size `n`. Components: `i`,
`n`, the leaf hash and a path of ⌈log₂(n)⌉ node hashes. For a million leaves that is 20 nodes,
i.e. 640 bytes — negligible next to the 3309 bytes of the ML-DSA-65 signature in the leaf itself.

A verifier MUST compute it against the root hash of **a concrete STH** and check that `n` is the
tree size of that STH. An inclusion proof on its own says nothing — it merely computes a root, and
the attacker could have supplied it.

### 5.2 Consistency proof

Shows that a tree of size `n₁` is a prefix of a tree of size `n₂ ≥ n₁`: that between the two only
appending took place and nothing was changed or removed. That is the actual promise of the log.

### 5.3 Proofs are not signed

And therefore need **no canonical format**. Their integrity follows entirely from whether they
come out against a signed root hash or not. A tampered proof fails; a proof in a deviating
encoding that comes out is a valid proof. Transport is governed by [OWM-7](owm-7-node-api.md).

## 6. Appending

1. The node checks the signed entry: canonicality, signature, issuer, structure (OWM-0 §6.4).
2. It assigns `seq = current tree size` and sets `ts` to the current time.
3. It forms the leaf, computes its hash and appends the hash to the tree.
4. With the next STH the entry is covered.

An entry MAY be appended several times and then yields several leaves with the same entry
identifier. The log MAY reject duplicates but need not — the entry identifier remains decisive for
attribution.

## 7. Erasure path

The part Certificate Transparency does not have and does not need.

### 7.1 What is erased

**Payload and salt.** Both live off-chain at the node that holds them, never in the log.

**Not erased** are leaf, entry, signature and tree. The log stays byte for byte as it was.

### 7.2 Procedure

1. Payload and salt are erased irrecoverably.
2. The node appends an `erasure` entry (OWM-0 §6.1), signed with its own key, whose `tgt` names
   the entry affected.
3. The next STH covers it.

### 7.3 Why this holds

The tree stays unchanged. From that it follows immediately:

- **Every STH ever issued stays valid.** No observer has to re-evaluate anything.
- **Every inclusion proof stays valid**, including that of the erased entry.
- **Every consistency proof stays valid.** From outside, an erasure is an ordinary append.

And the payload is gone all the same. The commitment is `HMAC-SHA-256(salt, label ‖ payload)` with
a 256-bit salt (OWM-0 §5). Without the salt the value is uniformly distributed over the key space:
even if the entire value range consists of two possibilities — "organic" or "not organic" — it
cannot be said which one it was. An unsalted hash would break here immediately; that is why
OpenWaymark salts and CT does not.

### 7.4 What remains, and what that means

After the erasure the following stay in the log permanently: subject ID, key identifier of the
issuer, time of issue and time of intake, profile identifier, entry type and the predecessor
references. That is traffic data and cannot be removed without breaking the tree.

From this follows the hard rule from OWM-0 §6, repeated here because this is where it has its
consequence:

> No field of an entry MUST contain personal data in the clear. The subject ID included — it is an
> opaque identifier and not a name, not an address, not a coordinate.

Whoever uses derived subject IDs (OWM-0 §4.2) makes them enumerable. Where linkability does harm,
the subject ID MUST be random. Linking through traffic data remains possible and is carried in
OWM-9 A9 as an accepted residual risk.

### 7.5 Limit in a federated network

An erasure takes effect where the data lies. If the payload was passed on to partners in the course
of the supply chain, the erasure does **not** reach their copies. For them the `erasure` entry is a
signal, not enforcement; whether they follow is a legal and not a technical question.

That is not a peculiarity of OpenWaymark but the situation in every distributed system, and it is
recorded here expressly rather than passed over. The technical countermeasure is data minimisation
before passing data on, not erasure afterwards.

### 7.6 What is not erasable

`key_rotation` entries. Their payload is the successor key; without it the rotation chain is
broken and all later signatures can no longer be attributed. A public key is moreover not personal
data in the sense that it could be replaced by something else. A node MUST refuse the erasure of a
`key_rotation` entry.

### 7.7 Limit in storage

The protocol can guarantee that the tree survives an erasure. Whether the bytes actually disappear
from the storage medium is decided by the operator, not by the protocol.

A node MUST operate its payload store such that erased data is overwritten and not merely marked
free — with SQLite that means `PRAGMA secure_delete=ON`, with a file store overwriting before
removing the directory entry. What remains out of reach: backups, file system snapshots,
journal/WAL files of earlier sessions and the block remanence of SSDs.

For those copies there is no technical solution in the log, only a retention period: a node SHOULD
keep backups for a period short enough that an erasure catches up with them within the period
promised, and SHOULD publish that period. Whoever keeps 90 days of backups erases, in effect, with
90 days of delay; that is defensible, but it is a promise a node has to make, and not one the
protocol can make on its behalf.

## 8. Batch signing

The plan carries the size of PQ signatures as an open point: a million entries are roughly 3.3 GB
in ML-DSA-65 signatures alone. Here is the resolution.

**For the log's own signature, batch signing is already the design principle.** The node signs
STHs, not individual leaves. One STH covers arbitrarily many entries; the individual entry is
captured through its inclusion proof. With hourly STHs, a year of log operation costs about 29 MB
in node signatures, independently of the number of entries. Nothing needs to be added here.

**The 3.3 GB are issuer signatures, and those cannot be batched away.** Every entry has to be
attributable to its issuer individually, and the issuers are different parties who cannot sign a
common batch. Two levers remain:

1. **ML-DSA-44 for sensors and bulk entries** (OWM-0 §3.2): 2420 instead of 3309 bytes, about 27 %
   less. Planned and implemented.
2. **Bundling at the issuer.** Whoever produces many readings of the same kind builds a Merkle tree
   from them themselves, puts its root into **one** payload and writes **one** entry with **one**
   signature. The individual reading is shown through an inclusion proof in that subtree, which
   lies off-chain next to the payload. 8640 readings of a daily interval thus become one entry
   instead of 8640.

The second lever is the effective one, and it belongs **not in the log** but at the profile level:
whether and how bundling happens depends on what is measured and how finely it has to be
individually provable. In both cases the log sees only one entry. This is worked out in the food
profile ([OWM-4 §12](owm-4-profiles.md#12-series-of-readings)).

## 9. Detection of misbehaviour

The log cannot monitor itself. What it supplies are the primitives with which an independent
observer (OWM-5, `monitor/`) can **prove** misbehaviour.

| Observation | Meaning |
|---|---|
| Two STHs, same log, same `size`, different `root` | split view. Proof. |
| Two STHs, `size₁ < size₂`, consistency proof does not come out | history changed. Proof. |
| STH with `size₂ < size₁` at a later `ts` | tree shrank. Proof. |
| Entry is not in the tree although receipted | withholding. Provable only with a receipt. |

The first three are **non-repudiable**: the node signed both statements itself. No majority, no
vote and no trusted third party is needed to judge them — only two observers who compare their
views.

And that is exactly the condition: **a single observer cannot detect a split view in principle.**
Both histories are internally consistent and correctly signed. Without exchange between observers
the attack is open, and with it the retroactive alteration of the log. Detection is moreover after
the fact: it does not prevent the attack, it makes it provable and thereby expensive. See OWM-9 A1
and A2.

## 10. Retention and pruning

Erasure under Article 17 (§7) is the case driven by a data subject. Independently of it, a node
needs a rule for what it keeps **by default** and for how long — otherwise the log grows without
bound, and a community node with many small participants pays for all of them.

Three storage tiers per entry:

| Tier | What is held | Size per entry |
|---|---|---|
| hot | signed entry + payload + salt | ~3900 B |
| warm | signed entry, payload and salt gone | ~3400 B |
| cold | **leaf hash only** | **32 B** |

### 10.1 Payload retention

A node SHOULD lay down a retention period per profile after which payload and salt are erased even
without a request, and SHOULD publish it in its metadata (OWM-7). The period follows from the
purpose, not from the protocol: for food it is oriented on shelf life plus the statutory
traceability period, for a certification on its period of validity.

The mechanism is exactly the one from §7 — erase payload and salt, append an `erasure` entry. A
retention erasure is indistinguishable from an erasure on request, and that is intended: otherwise
the type of an erasure would say something about the data subject.

### 10.2 Signature pruning

The tree needs **leaf hashes and nothing else**. Inclusion and consistency proofs are computed
entirely from them; the signed entry itself is never needed for that.

A node MAY therefore, after a pruning period, discard the signed entry as well and keep only the
leaf hash. Consequences:

- **Every STH ever issued stays valid**, the root hash does not change.
- **Every inclusion and consistency proof stays computable**, for every leaf, indefinitely.
- **Lost** is the ability to hand out the entry itself and to check its signature. Whoever archived
  the entry earlier — the supply chain partner, the certifier, a monitor — can still prove its
  inclusion against every STH.

This makes the log's storage requirement **independent of the signature size**: a million pruned
entries are 32 MB instead of 3.3 GB. That is the structural answer to §8, which can only dampen
the per-entry cost.

A node MUST NOT prune before the retention period of the profile has expired, MUST publish the
pruning period, and MUST answer a request for a pruned entry with a distinguishable status
(OWM-7) — "pruned" is not "unknown" and not "erased".

### 10.3 What must not be pruned

`key_rotation` entries, for the reason from §7.6: without them the rotation chain breaks. A node
MUST keep them in full permanently.

### 10.4 STH retention

An observer needs old STHs in order to be able to compare at all. A node MUST keep every STH it
has issued for at least the pruning period and SHOULD keep all of them permanently — an STH is
about 3400 bytes, hourly issue costs 29 MB per year, and it is the only structure through which
past misbehaviour can still be proven.

## 11. Optional payload confidentiality

The public API is unauthenticated for the world by design ([OWM-7](owm-7-node-api.md) §2), and for
an organisation that is the reasoned trade this project makes ([OWM-9](owm-9-threat-model.md) §3:
"anonymity of participants" is an explicit non-goal). It stops being a reasoned trade the moment the
participant is a sole proprietor whose business *is* the person — [OWM-9 A14](owm-9-threat-model.md#a14--full-payload-disclosure-and-business-collapsing-into-person)
is the case this section closes the mechanism gap for.

**A payload MAY be encrypted before it is ever submitted.** Nothing about that changes anything
above this section: the commitment ([OWM-0 §5](owm-0-overview.md#5-payload-commitment)) is
computed over whatever bytes are given, encrypted or not; inclusion, consistency and erasure all
operate on opaque bytes exactly as they always have.
An encrypted entry is an ordinary entry that happens to carry `prof = ""` — the same no-op path
`attestation` entries already use ([OWM-6](owm-6-trust.md) §3), because a node that cannot decrypt
a payload also cannot validate it against a profile schema, and `prof = ""` is the accurate
statement of that, not a workaround.

The envelope format and the hybrid ML-KEM/AES-256-GCM construction that produces it are specified
by the `seal` package (Apache-2.0) — self-contained, no dependency on `core`, `log` or `node`, and
therefore nothing this document needs to normatively pin down beyond the one property that matters
here: whatever `seal.Seal` produces is, to every mechanism in this document, indistinguishable from
any other payload.

**What this does not do**, stated plainly rather than left to be discovered later: it says nothing
about *who submitted*, *when*, or *roughly how much* — the traffic-pattern exposure
[OWM-9 A9](owm-9-threat-model.md#a9--linking-through-metadata) already names as an accepted
residual risk stays exactly as it was. And it is opt-in: a participant who does not encrypt is
exactly as exposed as before this section existed. This closes the *mechanism gap* — that there was
no way to do this at all — not the whole problem A14 describes.

## 12. Open points

- Receipts on appending (analogous to the SCT in CT), so that withholding an entry becomes
  provable and not merely assertable. Belongs to the node API,
  [OWM-7 §10](owm-7-node-api.md#10-open-points).
- Behaviour on reaching the leaf limit of 128 KiB through very wide aggregations (`par` up to
  MaxParents = 1024).
- Whether a pruned entry SHOULD be re-supplied by a third party who archived it (a "resurrection"
  path), and how such a copy is authenticated — the leaf hash decides it, but the transport for it
  is not specified.
- Discovery of a recipient's ML-KEM encapsulation key. §11 leaves this out of band deliberately —
  the same staging discipline [OWM-8](owm-8-client.md) already used for cross-node trust-chain
  resolution — but a real mechanism (key-directory integration, an attestation-like publication
  convention, or something else) is unbuilt.
