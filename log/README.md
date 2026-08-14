<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `log/` — Append-only log · Apache-2.0

**Planned (stage E2). No code yet.**

The heart of the protocol: the Merkle tree per RFC 6962 on top of
[`transparency-dev/merkle`](https://github.com/transparency-dev/merkle), inclusion and
consistency proofs, signed tree heads — and the erasure path.

The trick it all turns on: what gets erased is the blob and the salt, not the leaf. The tree stays
unchanged, which is why **every STH ever issued remains valid**. That is exactly what reconciles
GDPR erasure with tamper evidence — Certificate Transparency does not need it, because CT never
erases.

Specification: OWM-2 (still to be written). Threat model:
[OWM-9 A2, A5](../spec/owm-9-threat-model.md).
