<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `gossip/` — Fetch, verify and poll signed tree heads · Apache-2.0

The client-side half of [OWM-5 §3](../spec/owm-5-federation.md#3-gossip): the shared primitive
both targeted partner gossip (built into [`node/`](../node/)) and independent monitoring
([`monitor/`](../monitor/)) are built from.

- **`Client`** fetches a node's latest STH (`GET /owm/v1/sth`), resolves its signing key fresh on
  every call (`GET /owm/v1/keys/{id}`) rather than caching it — that is what lets a key rotation
  happen without any coordination with whoever is polling — and fetches consistency proofs
  (`GET /owm/v1/proof/consistency`). It never trusts anything the server merely asserts: every STH
  is verified against its signing key, every consistency proof against two already-verified roots.
- **`Watch`** polls a `Client` on an interval and compares each newly verified STH against the last
  one seen for the same log, using `log.CheckSTHPair` and `log.ConsistencyProof.Verify` — the
  primitives [OWM-2 §9](../spec/owm-2-log.md#9-detection-of-misbehaviour) supplies. A contradiction
  becomes a `Finding`, carrying the two conflicting signed STHs as non-repudiable evidence.

A failed fetch is reduced coverage for that cycle, not evidence, and is reported separately from a
`Finding` — see `Watch`'s doc comment for exactly which cases fall on which side of that line.

This package keeps no state across restarts and persists nothing to disk on its own; that is
deliberately the caller's job (see `monitor/findings.go`).
