<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OpenWaymark

**An open, federated protocol for cryptographically verifiable provenance and supply chain
evidence.**

Website: <https://openwaymark.org/> · License: Apache-2.0 (libraries) and AGPL-3.0-only (servers)
· Status: early development, the format is not yet stable

For any good — an egg, a diamond, a battery cell — OpenWaymark answers four questions in a way
that can be checked rather than believed:

- Where does it come from?
- Which stations has it passed through?
- Who claimed that, and how well verified is that person or body?
- Was the cold chain kept, is it certified organic, is it conflict-free?

The answer consists of signed entries in append-only logs, of proofs a client recomputes for
itself, and of the ability to contradict a node that lies.

## Contents

- [What OpenWaymark is — and what it is not](#what-openwaymark-is--and-what-it-is-not)
- [Try it in five minutes](#try-it-in-five-minutes)
- [How it works](#how-it-works)
- [Running your own node](#running-your-own-node)
- [Repository layout](#repository-layout)
- [Status and roadmap](#status-and-roadmap)
- [Documentation](#documentation)
- [Security](#security)
- [Contributing](#contributing)
- [Releases and versioning](#releases-and-versioning)
- [License](#license)

## What OpenWaymark is — and what it is not

|  |  |
|---|---|
| **Federated** | Every node is authoritative for its own data. There is no global state everybody has to agree on. Comparable to email or DNS, not to a blockchain. |
| **A transparency log, not a blockchain** | Every node keeps a local, append-only Merkle log modelled on Certificate Transparency (RFC 6962). Tamper evidence comes from signed tree snapshots and mutual observation, not from consensus. |
| **Erasable** | Erasure under the GDPR is a core requirement, not an afterthought. The log stores only a salted commitment; payload and salt live off-chain and can genuinely be deleted — without a single historical proof becoming invalid. |
| **Post-quantum from day one** | ML-DSA (FIPS 204) and ML-KEM (FIPS 203) exclusively. No RSA, no ECC, no hybrid transition scheme. |
| **Industry-agnostic** | The core knows no industry schema. What may appear in a payload is laid down by an interchangeable schema profile; the first one is `food.v1`. |
| **Not a financial product** | No tradable cryptocurrency, no token with a market price, no exchange. The planned incentive scheme is a closed, non-tradable deposit system. |
| **Not a proof of truth** | OpenWaymark cannot stop anyone from lying at the point of first capture. It makes the lie tamper-evidently documented after the fact, attributable and economically unattractive. See the [threat model](spec/owm-9-threat-model.md). |

## Try it in five minutes

Requires Go 1.25 or newer. Nothing else — no Docker, no outbound network, no database to set up.

```sh
git clone https://gitlab.jens-schendel.com/jagottsicher/openwaymark.git openwaymark
cd openwaymark
go run ./demo
```

The demonstration builds `owmnode`, starts the node in a throwaway directory on two free ports on
`127.0.0.1`, plays through a complete food chain and cleans everything up afterwards. The client
takes the node's word for nothing: it recomputes every identifier and checks every signature,
every commitment and every proof itself.

```
5. Reading the chain back: the client checks everything itself
            #7 handover           Molkerei Alpenrand -> Feinkost Brunner e.K. (DA-2026-08-11-0093)
               assertion, logged 05:45:09, proof 3 nodes
               #6 processing         pasteurise and add rennet -> Mountain cheese, 12 months, by ...
                  assertion, logged 05:45:09, proof 3 nodes
   ok       8 entries: signature, commitment and inclusion proof verified
   ok       public keys fetched over the public API

6. Cold chain: what the sensor says against what was promised
            promised on the freight papers: 2.0 to 6.0 C (Spedition Kühlfracht)
            09:35    7.9 C  BREACH
            10:05    8.4 C  BREACH
   blocked  2 of 7 readings outside the promised range

7. Erasure under Art. 17 GDPR
   ok       payload and salt erased, tombstone appended
   blocked  payload no longer retrievable: HTTP 410 erased
   ok       the proof issued before the erasure still verifies, the tree is unchanged
   ok       consistency proof 8 -> 9: appended only, nothing rewritten

8. Tampering attempts
   blocked  one byte flipped in the entry -> signature invalid
   blocked  altered leaf against the same proof -> does not match the root
   blocked  STH signed with a foreign key -> signature does not match the node
   blocked  split view detected: owm/log: split view: two roots for the same tree size
```

Nine sections, explained one by one in [`demo/README.md`](demo/README.md).

## How it works

### Entry, leaf, tree

Whoever claims something writes an **entry**: serialised deterministically as CBOR
(RFC 8949 §4.2), signed with ML-DSA, addressed by the hash of its content. An entry names its
subject (the good), its issuer, its profile, its parent entries — and, instead of the payload,
only the payload's **salted commitment** `H(salt ‖ payload)`.

From that the node appends a **leaf** to its Merkle log. Over the tree it periodically issues a
**Signed Tree Head**: log identifier, tree size, root hash, timestamp, signed. Two proofs follow
from the tree, and every client can recompute both for itself:

- **Inclusion proof** — this leaf sits in exactly this tree.
- **Consistency proof** — the new tree is the old one plus additions; nothing was rewritten.

### Why erasure and proof do not contradict each other

Personal data is **never** in the leaf, only ever in the off-chain blob. An erasure removes the
payload **and the salt** and appends a tombstone. The tree stays unchanged — which is why **every
STH and every inclusion proof ever issued remains valid unchanged**. Without the salt the payload
cannot be reconstructed even if its value range is small and the attacker guesses the plaintext;
that is the difference from a bare hash.

The historical counter-example: the old SKS keyserver network, append-only without any way to
delete, rendered practically unusable in 2019 by poisoned entries.

### Federation instead of a global chain

There is no double-spending problem, and therefore no reason for an expensive consensus
mechanism. Every node is responsible for its own participants and accepts entries only from keys
in its own directory. Nodes are found over DNS:

```
_openwaymark.example.com. IN TXT "v=owm1; node=https://provenance.example.com"
```

The central attack on a log like this is the **split view**: a node shows two observers two
different trees of the same size. Both signatures are valid — it can only be noticed by someone
who sees both. Against it: targeted gossip between actual supply chain partners (built into the
node itself), and STH gossip to independent monitors ([`monitor/`](monitor/)). Both poll
`GET /owm/v1/sth` through [`gossip/`](gossip/) and run the same detection primitive,
`log.CheckSTHPair`; [`discovery/`](discovery/) resolves a partner's base URL from its domain.

### Profiles

The core knows no industry. A profile lays down by JSON Schema what may appear in a payload, and
is referenced through the profile identifier in the entry. The first profile, `food.v1`, mirrors
the events of GS1 EPCIS 2.0 — production, aggregation, transport, measurement, processing,
handover — so that industry can connect without a translation layer.

A profile version never changes: were `food.v1` different today from yesterday, an entry from
yesterday would be invalid today without anyone having touched it. Changes appear as `food.v2`.

### Cryptography

| | |
|---|---|
| Signatures (nodes, entities) | ML-DSA-65 — 1952 B public key, 3309 B signature |
| Signatures (sensors, bulk entries) | ML-DSA-44 — 1312 B public key, 2420 B signature |
| Encryption (planned, E5) | ML-KEM via `crypto/mlkem` from the standard library |
| Hash | SHA-256, everywhere with domain separation (`OWM/1 entry`, `OWM/1 commit`, …) |
| Serialisation | deterministic CBOR, RFC 8949 §4.2 |

Size is not a side issue but a design constraint: an entry in the demonstration weighs 3407 bytes
on average, its payload 492 bytes. The lion's share is the signature — which is why sensors use
ML-DSA-44 and why batch signing is planned.

## Running your own node

```sh
go build -o owmnode ./node/cmd/owmnode

./owmnode init -config owm.json \
    -operator "Hof Sonnenblick" -contact privacy@example.com \
    -base-url https://provenance.example.com
./owmnode show  -config owm.json
./owmnode serve -config owm.json
```

`init` creates configuration and identity and **never** overwrites an existing one — overwriting
an identity would mean continuing the log under a new identifier, and every STH issued so far
would be from a key nobody has any more.

The node opens two interfaces, both bound to `127.0.0.1` by default:

| | Default | For whom |
|---|---|---|
| Public API `/owm/v1` | `127.0.0.1:8480` | the world, behind a TLS-terminating reverse proxy |
| Administration `/admin/v1` | `127.0.0.1:8481` | the operator, and nobody else |

⚠️ **The administration interface has no authentication, and that is deliberate.** Access control
belongs in the environment: local binding, a Unix socket behind a proxy, a VPN. Whoever reaches
this interface can enrol keys and erase payloads. A home-grown token scheme in the application
code would be weaker than what the operating system and a grown-up proxy can do anyway — and it
would pretend the question had been settled.

Day-to-day operation — enrolling keys, erasing payloads, issuing STHs — goes through the
administration interface rather than through further subcommands: two processes on the same SQLite
file would be a fine way to take the database apart.

Storage is `modernc.org/sqlite`, pure Go without cgo. That allows binaries for ARM to be built
without a cross toolchain — the precondition for a node genuinely being operable on
Raspberry-Pi-class hardware.

Full interface description: [OWM-7](spec/owm-7-node-api.md).

## Repository layout

A single Go module `openwaymark.org/owm` with subpackages. It will be split up only once somebody
wants to pull in `core/` on its own.

| Directory | Content | License |
|---|---|---|
| [`spec/`](spec/) | protocol specification, normative | Apache-2.0 |
| [`core/`](core/) | entry types, deterministic CBOR, ML-DSA, commitments | Apache-2.0 |
| [`log/`](log/) | Merkle log, STH, inclusion and consistency proofs, erasure path | Apache-2.0 |
| [`profiles/`](profiles/) | schema profiles, starting with [`food/`](profiles/food/) | Apache-2.0 |
| [`discovery/`](discovery/) | DNS discovery of a node's base URL and description | Apache-2.0 |
| [`gossip/`](gossip/) | fetch, verify and poll STHs — the split-view detection client | Apache-2.0 |
| [`node/`](node/) | node server and `owmnode` | AGPL-3.0-only |
| [`monitor/`](monitor/) | independent log monitor | AGPL-3.0-only |
| [`client/`](client/) | WASM verifier and web app (planned) | Apache-2.0 |
| [`demo/`](demo/) | end-to-end demonstration against a real node | Apache-2.0 |
| [`testdata/`](testdata/) | test vectors for third-party implementations | Apache-2.0 |

The test vectors are **part of the specification**, not mere test scaffolding: anyone
implementing OpenWaymark in another language checks themselves against them.

## Status and roadmap

**Early development.** The protocol is not stable yet, the data format may change. No version so
far is meant for production use.

| Stage | Content | Status |
|---|---|---|
| E0 | foundation, specification drafts, CI | done |
| E1 | core data model, cryptography, test vectors | done |
| E2 | Merkle log, STH, proofs, erasure path | done |
| E3 | node server, HTTP API, profile `food.v1` | done |
| E4 | federation: DNS discovery, gossip, `monitor/` | done |
| E5 | trust levels, attestations, sensor certificates | next |
| E6 | web app and WASM verifier | open |
| E7/E8 | deposit system and dispute resolution | deliberately deferred |

E7/E8 wait until at least two independently operated nodes carry real data. Only then can cap
heights and time windows be calibrated against measurements instead of guessed. The core is
deliberately built so that it does not depend on them.

## Documentation

| Document | Content |
|---|---|
| [OWM-0](spec/owm-0-overview.md) | protocol overview, terms, identifiers, crypto parameters, discovery |
| [OWM-2](spec/owm-2-log.md) | log, Merkle tree, signed tree heads, proofs, erasure path |
| [OWM-3](spec/owm-3-keys.md) | keys, node identity, directory, rotation |
| [OWM-4](spec/owm-4-profiles.md) | profile mechanism and the food profile `food.v1` |
| [OWM-5](spec/owm-5-federation.md) | federation: DNS discovery, gossip, the independent monitor's contract |
| [OWM-7](spec/owm-7-node-api.md) | node API: submitting, reading, proofs, administration |
| [OWM-9](spec/owm-9-threat-model.md) | threat model, limits of the system |

Package-level explanations live in the README files of the directories
([`node/`](node/README.md), [`profiles/`](profiles/README.md), [`demo/`](demo/README.md)) and in
the comments; the normative version is always the specification.

## Security

The [threat model](spec/owm-9-threat-model.md) describes what OpenWaymark protects against and
what it expressly does not. The three most important limits:

1. **The oracle problem remains.** Whoever lies at the point of first capture is not made honest
   by any signature. The protocol makes the lie attributable and tamper-evidently documented after
   the fact — it does not replace spot-check physical audits.
2. **A split view is only noticed if somebody looks.** `monitor/` exists now, but running one
   cannot be compelled, only made attractive — coverage stays uneven by construction
   ([OWM-9 §6](spec/owm-9-threat-model.md)).
3. **The administration interface is unprotected.** It does not belong on the open internet.

**Please do not report security vulnerabilities as public issues**, but confidentially through the
repository's private security reporting (on GitHub: *Security* tab → *Report a vulnerability*).
Until a fix exists, neither the report nor the reporter is mentioned; afterwards both are named in
the release notes, if desired.

## Contributing

Contributions are welcome — bug reports, criticism of the specification, code, profiles for
further industries, implementations in other languages.

### Branching model

`develop` is where active work lands; `main` reflects what is actually released and stays the
default branch, so a first-time visitor sees the current, stable state rather than work in
progress. Branch a feature off `develop`, open the merge/pull request back into `develop` — not
into `main`. `main` only ever receives merges from `develop`, at release time; on GitLab, CI
enforces this directly — a merge request into `main` from any other source branch fails.

### Prerequisites

Go 1.25 or newer (CIRCL requires it). Nothing else.

### Get this green locally before every contribution

```sh
go build ./...
test -z "$(gofmt -l .)"
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go test -race ./...
go run ./demo
```

That is exactly what the pipeline checks too ([`.gitlab-ci.yml`](.gitlab-ci.yml)), plus a short
fuzz run over the parsers. Parsing is the only place where foreign bytes enter the system —
whoever changes anything there should let the fuzzer run for longer:

```sh
go test ./core/ -run '^$' -fuzz FuzzParseEntry -fuzztime 5m
```

### What to watch out for when changing things

- **Specification first.** Every change to the wire format, to identifiers, to domain separators
  or to the API changes the specification under `spec/` first and the code second. A format that
  exists only in the code is not a protocol.
- **Update the test vectors.** If the serialisation changes, the golden data in `testdata/vectors`
  is regenerated: `go test ./core/ -update`. The diff belongs in the same commit and is the real
  touchstone — it shows whether the change makes old data unreadable.
- **Never put personal data in the leaf in the clear.** Everything personal lives in the off-chain
  blob. That rule is in the specification, not just in the code.
- **Profile versions are immutable.** Changes to `food.v1` are not changes but `food.v2`.
- **An SPDX header in every new file**, matching the area (see [License](#license)). The
  repository follows the [REUSE specification](https://reuse.software/); `REUSE.toml` covers the
  exceptions.
- **No keys, no operational data in the repository.** `.gitignore` covers the usual cases; it does
  not replace thinking.

### Language

Everything in this repository is in English: specification, README files, source comments, commit
messages, program output and error messages.

Program output is additionally **plain text**: no ANSI colours, no boxes, no emoji, no typographic
arrows — the output should copy unchanged into a file, a ticket or a mail and look the same in
every terminal. Error texts start with the package prefix (`owm:`, `owm/log:`, `owm/node:`,
`owm/profiles:`) and continue in lower case — as `staticcheck` requires (ST1005), and so that they
nest.

Proper nouns in test and demonstration data stay as they are: the fictional companies and farms
have German names, and identifiers from the real world (for instance the organic control number
`DE-ÖKO-006`) are quoted, not translated.

### Workflow

1. Open an issue before starting larger work — especially for protocol changes.
2. Branch from `main`, one topic per branch.
3. Commit subject as a short declarative sentence, the *why* in the body, not the *what* (that is
   in the diff).
4. Merge/pull request with a green pipeline.

## Releases and versioning

Two things are versioned separately:

- **The protocol** carries its version in the wire format and in the domain separators (`OWM/1`).
  It only rises when the format breaks.
- **The software** follows [SemVer](https://semver.org/). As long as the major version is `0`,
  anything can change in any minor version — the wire format included.

A release is an annotated Git tag `vX.Y.Z` on `main` with a green pipeline. The release notes name,
in this order:

1. **Format changes** — what is no longer backwards compatible in entries, leaves, STHs or the
   API, and what operators of existing logs have to do.
2. **Security-relevant matters.**
3. Everything else.

The tag also gates the community node deploy: pushing a tag runs the same checks as any other
pipeline, and only then offers a manual "deploy-community" button — a plain push to `main` deploys
nothing by itself.

Builds are made from the tag:

```sh
git clone --branch v0.1.0 https://gitlab.jens-schendel.com/jagottsicher/openwaymark.git openwaymark
cd openwaymark
CGO_ENABLED=0 go build -trimpath -o owmnode ./node/cmd/owmnode
```

`owmnode version` prints commit and Go version, because `go build` embeds both from version
control. Binaries for `linux/amd64` and `linux/arm64` are attached to the release — without cgo,
so that a Raspberry Pi runs the same file a server runs.

A release always contains the matching test vectors. Third-party implementations check themselves
against `testdata/vectors` of exactly that tag.

## License

Split licensing, so that the libraries stay freely embeddable and server operators give their
changes back:

| Area | License |
|---|---|
| `spec/`, `core/`, `log/`, `client/`, `profiles/`, `discovery/`, `gossip/`, `testdata/`, `demo/` | Apache-2.0 |
| `node/`, `monitor/` | AGPL-3.0-only |

Whoever operates a node as a service gives their changes back to the network they run it in.
Whoever merely embeds `core/` or `log/` in their own software — a client, a scanner, a
third-party implementation — is unaffected by that.

Every file carries an SPDX identifier; the full license texts are in [`LICENSES/`](LICENSES/). The
repository follows the [REUSE specification](https://reuse.software/).
