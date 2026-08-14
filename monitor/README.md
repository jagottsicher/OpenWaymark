<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

# `monitor/` — Independent log monitor · AGPL-3.0-only

**Planned (stage E4). No code yet.**

Collects STHs from nodes, checks them pairwise for consistency and raises the alarm on divergence.
Deliberately small and self-contained, so that someone other than the observed node can run it —
that is the whole point.

The monitor belongs to the core of the project, not to its accessories. The central attack on a
CT-style log is the **split view**: a node shows two observers two different trees, each
internally consistent. Both histories are correctly signed, both inclusion proofs check out.
Locally this cannot be detected in principle. Without independent observation the attack stays
open — and with it the after-the-fact alteration of the log, because a node that keeps its history
by itself alone can rewrite it along with every STH.

Two STHs from the same node for the same tree size with different root hashes are signed,
undeniable proof of misbehaviour. The node signed it itself.

See [OWM-9 A1 and A2](../spec/owm-9-threat-model.md). The split-view test is the most important
test in the project.
