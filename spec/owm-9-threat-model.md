<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-9 — Threat model

**Status:** draft · **Date:** 2026-08-10

This document names what OpenWaymark protects against, what it expressly does not protect against,
and which residual risks are deliberately carried. It is the reference for security decisions in
the code: every countermeasure named here should have a test that makes its failure visible.

One sentence up front, because it puts everything else in order: **OpenWaymark does not prove that
a statement is true. It proves who made it and when, and that it has not been altered since.**
Anyone who confuses the two overestimates the system.

## 1. Assets

| Asset | Why it is worth protecting |
|---|---|
| Integrity of the log | A history that can be altered after the fact is worthless. |
| Attributability of statements | Without attributability there is no responsibility and no sanction. |
| Non-equivocation | All observers must see the same history, otherwise every proof holds only locally. |
| Erasability of personal data | A legal duty, and the condition for being allowed to run the system at all. |
| Availability of the evidence | Evidence that cannot be retrieved is no help in a dispute. |
| Confidentiality of the payload | Trade secrets and personal data must not become public along with the log. |

## 2. Security goals

1. **Append integrity.** An entry in the log cannot be altered or removed unnoticed.
2. **Non-equivocation.** A node cannot show two different histories for long without it being
   noticed.
3. **Attributability.** Every entry carries a checkable signature of a named entity.
4. **Erasure without loss of evidence.** Payloads can be erased without a single issued proof
   becoming invalid.
5. **Independent verifiability.** A client must be able to check signatures and inclusion proofs
   itself, and must not have to take the server's word for anything.
6. **Post-quantum durability.** Recorded data stays attributable even if a cryptographically
   relevant quantum computer comes to exist later.

## 3. Explicit non-goals

- **Truth of the first capture.** See A4.
- **Global consistency.** There is no global register of all goods. Anyone looking for global
  consensus is looking at the wrong system.
- **Censorship resistance against one's own node operator.** Whoever runs the node can refuse
  entries. See A3.
- **Protection against physical substitution.** See A8.
- **Anonymity of participants.** The trust level system rests precisely on identifiability. Only
  level 0 is anonymous, and by definition it is worth nothing.

## 4. Attacker types

| Type | Capabilities |
|---|---|
| **N — network attacker** | Reads, delays, drops and forges messages between participants. |
| **B — malicious node operator** | Full control over a node, its keys and its database. |
| **T — malicious participant** | Holds a valid identity, wants to introduce false statements. |
| **A — outsider** | No access, tries to reconstruct data or to link participants. |
| **Q — quantum attacker** | Records today, breaks classical crypto later. |

## 5. Attacks and countermeasures

| # | Attack | Type | Covered |
|---|---|---|---|
| A1 | Split view | B | yes, through gossip and monitors |
| A2 | Retroactive alteration of the log | B | yes, cryptographically |
| A3 | Withholding entries | B | partly |
| A4 | Lying at first capture | T | no, only mitigated |
| A5 | Reconstruction of erased payload | A | yes, through the salt |
| A6 | Key compromise | N, B, T | yes, through rotation |
| A7 | Sybil attack | T | yes, through the cost of verification |
| A8 | Physical substitution or cloning | T | no, only mitigated |
| A9 | Linking through metadata | A | partly |
| A10 | Enumeration of subject identifiers | A | partly |
| A11 | Server lying to the client | B | yes, through client-side checking |
| A12 | Failure of a node | N, B | partly |
| A13 | Record today, decrypt later | Q | yes, through PQ schemes |
| A14 | Full payload disclosure, business collapsing into person | A | no |
| A15 | Entity succession has no durable, attributable statement | A, B | partly, only the compromise case |

### A1 — Split view · **the central attack**

A malicious node shows two observers two different trees, each of them internally consistent. The
supplier gets one history, the auditor another. Both histories are correctly signed, both
inclusion proofs come out. Locally the attack is **not** detectable — and in principle not, not
merely for want of effort.

That is why gossip in OpenWaymark is **not a synchronisation mechanism but a security measure**.
In the concept document it sat under "synchronisation"; it belongs here.

Countermeasures, both of them needed:

- **Targeted partner gossip.** Nodes exchange STHs with their actual supply chain partners and
  check them for consistency. That is where the interest and the context are, and the effort stays
  proportional to the real business relationship.
- **STH gossip to independent monitors.** Partner gossip alone detects no split view *towards
  outsiders* — the partners do, after all, both see the same view. Only a monitor that the node
  cannot recognise as one closes that gap.

What an uncovered split view means: two STHs of the same node for the same tree size with
different root hashes are a signed, non-repudiable proof of misbehaviour. The node signed it
itself.

**A limit that belongs stated plainly:** detection is not prevention. A split view is uncovered
after the fact, it is not prevented. Between the attack and its discovery lies the gossip period.
Whoever needs shorter windows must gossip more often — there is no free way around that.

**Test:** a deliberately manipulated node that shows two observers different trees must be
detected by the monitor. That is the most important test in the project.

### A2 — Retroactive alteration of the log

The operator alters an old entry or strikes it out.

Covered by the Merkle structure: every change changes the root hash. An STH already issued is a
signature of the operator over the old state; consistency proofs between two STHs uncover any
deviation. The security rests on old STHs existing outside the node — which in turn presupposes
A1. **A1 and A2 belong together: without gossip, A2 is not covered either**, because a node that
keeps its own history alone can rewrite it together with all its STHs.

### A3 — Withholding entries

A node does not accept an inconvenient entry in the first place, or does not serve it.

Only partly covered, and that is a deliberate consequence of federation. Mitigations:

- Whoever submits can demand a receipt that obliges the node to include the entry within a
  deadline — the CT pattern of the Signed Certificate Timestamp. A receipt that is not honoured is
  a signed proof of breach.
- A counterparty can submit the same entry to its own node. A delivery relationship has two sides,
  and both are entitled to document it.
- Gaps in the chain are visible to the final verifier: a predecessor reference that points nowhere
  is a signal.

**Not covered:** whoever never submits, and has no partner who does, leaves no trace.

### A4 — Lying at first capture · **the oracle problem**

Somebody scans conventional eggs and enters "organic". Everything downstream is cryptographically
impeccable — and factually false.

**Not covered, and not coverable by any protocol design.** The gap sits between physical reality
and its digital capture, not in the software.

What lowers the residual risk without removing it:

- **Attributability.** The lie is signed and dated. That is the difference between a slip of paper
  and a basis for evidence.
- **Economic stake.** Loss of deposit on confirmed fraud (E7).
- **Sensors as a cross-check.** A GPS tracker contradicts a false location automatically.
  Contradictions between human self-declaration and device data can be found by machine — which is
  exactly what the entry type `sensor_reading` aims at.
- **Sampled physical audits by third parties.** This part remains irreplaceable by software,
  whatever the protocol design.

This limit belongs in every outward communication of the project. A system that promises more than
it can keep loses trust at exactly the moment when it matters.

### A5 — Reconstruction of erased payload

After an erasure, somebody tries to compute the payload back out of the remaining commitment.

Covered: the commitment is `HMAC-SHA-256(Salt, …)` with a 32-byte random salt. Without the salt
every payload is equally plausible — even if only ten values come into question. The salt lies
with the blob and is erased along with it.

An unsalted hash would be insufficient here, and this is the point at which OpenWaymark has to
depart from Certificate Transparency: CT needs no salts because CT never erases.

**Preconditions that lie outside the crypto:** the salt must really disappear — from backups,
replicas and filesystem snapshots as well. And copies of the payload that partners have lawfully
received cannot be caught up with by an erasure at the originating node. Both are operational and
contractual questions, not protocol questions; the specification must name them, it cannot solve
them.

**Test:** after the erasure the payload is not reconstructable even with a value range of a few
thousand possibilities, and the inclusion proof of the leaf still holds.

### A6 — Key compromise

A private key is stolen. What holds for the signatures made before that?

Covered by key rotation as an entry type of its own:

- A `key_rotation` entry announces the successor, signed with the old key.
- Validity windows overlap so that nothing tears during the changeover.
- On compromise, a `revocation` entry revokes the key **with a point in time**. Signatures before
  it stay valid, later ones do not — the point in time is provable from the log, because the
  position in the tree fixes an order that the node cannot change retroactively.
- On loss without provision, all that remains is re-verification through the node to which the
  entity originally proved its trust level.

**Not covered:** the period between the theft and noticing it. Entries from it are formally valid.
That matches every PKI, and it is the reason a revocation carries a timestamp rather than merely a
flag.

### A7 — Sybil attack

A participant creates many identities in order to skim incentives or to tip a dispute resolution.

The defence is **not** the bonus formula — that cannot prevent splitting in principle, whatever
its construction, because `log(a)+log(b) > log(a+b)`. The defence is the cost of identity
verification: the bonus cap is coupled to the trust level. At levels 1–2 a further identity is
cheap, but the cap is low; at levels 5–6 the cap would be high, but a further identity requires a
genuine official check.

The same principle holds for dispute resolution: drawing lots only among highly verified
participants who risk a stake of their own.

### A8 — Physical substitution or cloning

The code is peeled off genuine goods and stuck onto counterfeit ones, or a QR code is simply
copied.

**Not covered** — the binding between the bit and the thing is physical, not cryptographic. The
trust level of the physical-digital binding at least makes this weakness visible instead of hiding
it: printed QR code = easily copied; one-time serial number = vulnerable to a race; NFC with
challenge-response = practically unclonable; PUF = physically unclonable.

The client MUST display the binding level. A printed QR code on an otherwise unbroken chain must
not look like a proof.

### A9 — Linking through metadata

An outsider analyses publicly retrievable log data: who submits how much, and when? From that,
delivery volumes, customer relationships and plant utilisation can be estimated — without seeing a
single payload.

Only partly covered. The payload is protected, the **communication pattern** is not: timestamps,
frequency, reference structure and issuer IDs stand in the log. Mitigations: random rather than
derived subject IDs, batch submission to blur the time structure
([OWM-2 §8](owm-2-log.md#8-batch-signing)), selective encryption of the payload by ML-KEM for
chosen partners (a later, not yet numbered stage).

Residual risk carried: a log that is meant to be checkable must be observable. Complete
unobservability and public verifiability exclude one another.

### A10 — Enumeration of subject identifiers

A subject ID MAY be derived ([OWM-0 §4.2](owm-0-overview.md#42-subject-id)):

```
SubjectID = H("OWM/1 subject-id", namespace, value)
```

For GS1 identifiers the input to that derivation is structured and carries little entropy: a GTIN
plus a lot code that follows an obvious scheme. Whoever knows the GTIN and the naming convention
for lots can compute the identifiers and walk the entire log of that producer — without possessing
a single physical item, and without scanning anything.

Only partly covered. What leaks is not the payload, which lies behind the commitment, but the
traffic data that survives even an erasure
([OWM-2 §7.4](owm-2-log.md#74-what-remains-and-what-that-means)): production volume, delivery
frequency, the number of lots, the timing of the events, and — through `handover` entries — the
structure of the customer relationships.

The other half of the picture belongs here too: derivation is a deliberate design decision, not an
oversight. It is what makes lookup by GTIN and lot possible, and therefore what makes a printed
code resolvable at all. This is a trade, not a bug.

Mitigations:

- **Random subject IDs wherever linkability does harm.** The cost is lookup by GTIN and lot: the
  identifier then has to be printed on the item itself.
- **Coarser subject granularity**
  ([OWM-4 §10.1](owm-4-profiles.md#101-subject-granularity)). Lot level instead of item level
  reduces the resolution of what can be inferred from a sweep.
- **Rate limiting on the read API.**

Residual risk carried: with derived identifiers the enumeration cannot be prevented, only rate
limited. Rate limiting raises the cost and the duration of a sweep; it does not make the sweep
impossible, and anyone patient enough will finish it.

### A11 — Server lying to the client

The server serves the web app an invented chain, complete with a pretty presentation.

Covered, but only if the client really does check for itself. That is why the WASM verifier is not
a convenience feature but the condition for the whole chain of evidence being worth anything: the
client checks signatures and inclusion proofs against an STH it can obtain independently. A client
that believes the server makes A1 to A3 moot — and in that case the log could have been spared.

**Test:** a deliberately manipulated server must be rejected by the client.

### A12 — Failure of a node

Power gone, internet gone, operator gives up.

Partly covered. Entries and STHs already passed on to partners stay retrievable there. New entries
are not possible during the outage — that is the price of federation, and the same price as a mail
server that is down.

For the incentive system it holds asymmetrically: an outage **never** costs holdings, at most new
supply. A system that punishes small operators for a power cut creates exactly the centralisation
it set out to avoid.

### A13 — Record today, break later

An attacker stores everything today and waits for a quantum computer.

Covered, because there is no classical crypto in the protocol: ML-DSA-65 and ML-DSA-44 for
signatures, ML-KEM-768 for encryption, SHA-256 for hashes (reasoning in
[OWM-0 §3.1](owm-0-overview.md#31-why-sha-256-despite-the-post-quantum-claim)). No hybrid model
that would have to be shed later.

For signatures, "record today, break later" is in any case less pressing than for encryption — a
signature forged later helps little if its position in the tree is already attested by old STHs.
For payloads that must stay confidential the urgency is real, and that is precisely why PQ applies
from day one rather than as a migration project.

### A14 — Full payload disclosure, and business collapsing into person

`GET /owm/v1/entries/{id}/payload` serves the complete payload to anyone who has the entry ID —
no authentication, no field-level filtering, no access tier between "public metadata" and
"public everything" ([confirmed against `node/server.go`'s `handlePayload`: it forwards the
stored payload whole, or 410 if erased — nothing in between]). That is a deliberate, reasoned
trade for the corporate case: §3 names "anonymity of participants" as an explicit non-goal,
because the trust level system rests on identifiability. Every profile's `party` definition
follows from that reasoning — it forbids naming a natural person while permitting a named
business, on the assumption that the two are separable.

That assumption does not hold for an independent smallholder — precisely the participant
`community/default nodes` exist for. For a sole proprietor, the business *is* the person; there
is no second identity to fall back on. Combined with a profile like `eudr.v1`, whose geolocation
field is point-level for plots ≤4ha specifically (the regulation's own threshold, not this
project's choice), an unauthenticated reader gets a named individual at a specific coordinate,
no login required, no different from reading a public company's registered address.

Erasure does not retroactively fix this: erasure is a deletion the data holder chooses to make
later, at their own discretion. It does not change that the payload was fully public, to anyone
who asked, from the moment it was submitted until that choice was made — and nothing obliges the
choice to be made at all.

**Not covered today.** Possible mitigations, none built: field-level access tiers on the payload
endpoint (in tension with the "unauthenticated, for the world" design of the public API
elsewhere); coarser aggregation for small holdings at the profile level (a cooperative-level
identifier instead of a per-farmer one — a profile choice, not a protocol one); selective
payload encryption via ML-KEM, the same later, not-yet-numbered stage already named under A9.

### A15 — Entity succession has no durable, attributable statement

A legal-form conversion (GmbH → AG), an IPO, or an acquisition where the surviving entity keeps
its own key all fall out of the existing mechanism cleanly: the accreditation body that attested
the old status issues a `revocation` for the stale attestation and a fresh one for the new — the
ordinary claim/confirmation split (OWM-6) doing exactly what it is for. **Not a gap.** Trust
levels are never inherited automatically either way, which is the correct default, not a missing
feature: a buyer does not acquire a seller's accreditation by acquiring the seller.

The gap sits one case over: an entity is absorbed into an *already independently operating*
different entity, and its own key's participation ends for good. `key_rotation` (A6) does not fit
this shape — it is a statement by an identity about its own successor key, for continuity of the
*same* identity, not a statement that a *different*, pre-existing identity now continues the
business. Nothing in the protocol has that second vocabulary. What remains is silence: whoever
operates the node stops accepting entries under that key, a decision `node/rotation.go` itself
notes is "a separate step taken by the operator" — locally, not as a signed, logged, public
statement.

That silence is exactly what A3 (withholding) and A12 (node failure) already discuss, from a
different angle each. Neither distinguishes a legitimate, voluntary wind-down from those two. An
outside reader sees the same thing in all three cases — a key that stopped signing — and has no
way to tell "the business was sold, ask the successor" from "the operator is hiding something"
from "the lights went out." A `decommission` event exists per profile, for a *product's* ending;
there is nothing equivalent at the *entity* level in `core` or `trust/`.

**Partly covered:** only the involuntary case (A6, key compromise, with a timestamped revocation)
is. The voluntary, ordinary case — a business concluding on its own terms — has no channel to say
so on the record.

## 6. Who watches — observer incentives

The entire tamper-evidence argument rests on somebody actually comparing STHs. A single observer
cannot detect a split view in principle
([OWM-2 §9](owm-2-log.md#9-detection-of-misbehaviour)): both histories are internally consistent
and correctly signed. Detection is therefore not a property of the log. It is a property of the
observer population.

Which makes the honest question not "is the log verifiable?" but "who runs a monitor, and why
would they still be running it next year?" Monitoring costs bandwidth, storage and attention, and
pays nothing back directly. It is the classic free-rider problem: everybody benefits from
detection, nobody in particular is paid for it.

Who has a self-interested reason to watch — as the realistic answer, not as a wish:

- **Supply chain partners downstream of a node.** Their own evidence becomes worthless if the
  upstream log is dishonest. This is the strongest and the most durable incentive in the system,
  and it is why partner gossip (A1) is the load-bearing part rather than the polite one.
- **Certification bodies whose seal is being displayed.** Their reputation is attached directly to
  the entries; a forged organic attestation damages them, not only the producer.
- **Competitors.** They have a motive to catch a rival cheating, and they are cheap to enlist
  because they are watching anyway. An adversarial motive is still a motive.
- **Consumer protection organisations and researchers.** Their incentive is real but episodic — a
  campaign, a paper, a scandal. Valuable, but continuous coverage cannot be built on it.

### 6.1 The client is also an auditor

Every client that checks an inclusion proof against an STH holds, at that moment, one observation
of the tree. It has already done the expensive part. If clients report the STHs they have seen —
even a small, sampled fraction of them — then the observer population becomes the user population,
and that is the only group that grows with the system.

What this costs must be said in the same breath: it is a privacy trade. Reporting an STH discloses
that this client looked at this log at this time. Reporting MUST therefore be sampled, batched or
aggregated, and it MUST be optional. A verifier that reported silently would buy detection with
exactly the observability that participants were promised protection from.

### 6.2 Limits

None of this is enforced by the protocol. The protocol supplies the primitives
([OWM-2 §9](owm-2-log.md#9-detection-of-misbehaviour)) and nothing beyond them: an operator cannot
be compelled to be watched, and nobody can be compelled to watch. Coverage is therefore uneven by
construction. A log with commercially significant partners will be watched; a small log with no
downstream partner may be watched by nobody at all. For the second kind the tamper-evidence claim
is weaker than the design suggests — not wrong, but resting on an observer who may not exist.

Whether observers can be paid rather than merely hoped for belongs to the deferred deposit and
incentive system (E7/E8). It is deliberately not solved here: a mechanism that pays for monitoring
must first know what a monitor's report is worth, and that cannot be calibrated before at least
two independently operated nodes carry real data.

## 7. Deliberately accepted residual risks

| Residual risk | Why it is carried |
|---|---|
| A split view is detected, not prevented | Prevention would require global consensus — and thereby exactly the system that was rejected for good reasons. |
| Lying at first capture | Physical, not technically solvable. Mitigation instead of solution. |
| Metadata can be analysed | Verifiability presupposes observability. |
| Derived subject IDs are enumerable | The price of a printed GTIN being resolvable at all. Rate limiting slows a sweep down, it does not stop it. |
| Monitoring coverage is uneven | Watching cannot be compelled, only made attractive. A log without downstream partners may go unwatched. |
| A node operator can refuse entries | A consequence of the autonomy that makes up the federation. |
| Erasure does not reach lawfully distributed copies | An operational and contractual question, not a protocol question. |
| The operator sees the payloads of its participants | Community nodes require trust in the operator. Whoever does not want that runs a node of their own — that is what federation is for. |
| Full payload disclosure to any reader (A14) | The public-API-for-the-world non-goal (§3) was reasoned through for organisations, not sole proprietors; narrowing it needs profile-level field discipline or the encryption stage under A9, neither built yet. |
| Entity succession leaves no public trace (A15) | Key retirement is a local operator decision, not a logged statement; readers cannot distinguish a legitimate wind-down from A3's withholding or A12's failure. |

## 8. What follows from this for the implementation

1. Gossip is a security function. It must not be built as an optional convenience.
2. The monitor belongs to the core of the project, not to the accessories. Without it, A1 is open.
3. The client checks for itself. A server endpoint that says "trust me, it is valid" must not
   exist.
4. The salt is treated as a secret, with the same seriousness as a private key.
5. Every countermeasure in section 5 comes with a test that makes its failure visible.
