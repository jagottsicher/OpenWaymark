<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `log/` — Append-only log · Apache-2.0

The heart of the protocol: the Merkle tree per RFC 6962 on top of
[`transparency-dev/merkle`](https://github.com/transparency-dev/merkle), inclusion and
consistency proofs, signed tree heads — and the erasure path. A SQLite-backed storage
implementation lives under [`sqlite/`](sqlite/).

The trick it all turns on: what gets erased is the blob and the salt, not the leaf. The tree stays
unchanged, which is why **every STH ever issued remains valid**. That is exactly what reconciles
GDPR erasure with tamper evidence — Certificate Transparency does not need it, because CT never
erases.

`CheckSTHPair` and `ConsistencyProof.Verify` are the primitives an independent observer builds on
to prove a node contradicted itself — see [`discovery/`](../discovery/), [`gossip/`](../gossip/)
and [`monitor/`](../monitor/) for who actually calls them.

Specification: [OWM-2](../spec/owm-2-log.md). Threat model:
[OWM-9 A1, A2, A5](../spec/owm-9-threat-model.md).
