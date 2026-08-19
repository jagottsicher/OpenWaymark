<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# Demo

A complete supply chain against a **real, running node** — from the milking parlour to the
delicatessen, with a contradicting cold-chain sensor, GDPR erasure and four tampering attempts.

```sh
go run ./demo
```

The program builds `owmnode`, starts it in a throwaway directory on two free ports on
`127.0.0.1`, talks to it over HTTP and nothing else, and clears everything away again at the end.
It needs no outside network and touches nothing that is not its own.

| Flag | Meaning |
|---|---|
| `-keep` | keep the working directory (database, identity, configuration) |
| `-work DIR` | parent directory for the throwaway data |
| `-repo DIR` | repository root, if it cannot be derived from the module |
| `-serve` | after the demonstration, keep the node running and print how to try the [browser verifier](../client/) against it — stop with Ctrl+C |

The output is plain text: no ANSI colours, no box drawing, no emoji, no typographic arrows — it
looks the same in every terminal and can be copied unchanged into a file, a ticket or a mail. The
mark in the fixed left-hand column says what a line is about: `ok` checked and in order,
`blocked` turned away (as intended), `note` a remark. Continuation lines are indented to the same
column, and arrows are written as ASCII `->` and `<-`.

## Why the program imports only `core/` and `log/`

The demo is not part of the node, it is the node's counterpart. It imports only the libraries
under Apache-2.0; the node (AGPL-3.0-only) runs as a process of its own and is addressed over the
public API just as any third-party client would address it.

This is not licence cosmetics but the actual test: whatever the demo cannot get from the public
API, nobody else gets either. That is exactly how it came to light that the API initially handed
out no participant key at all — which would have left a third-party client unable to verify a
single signature.

## What the nine sections show

| | |
|---|---|
| 1 Start the node | The node asserts its identifiers and the client recomputes them: key ID from the key bytes, log ID from the founding key. |
| 2 Participants | Five keys in the directory, sensor on ML-DSA-44. A key from outside is turned away. |
| 3 Supply chain | Eight `food.v1` events — production, aggregation, transport, measurement, processing, handover — linked by parent references. The profile rejects a hand-written cold-chain measurement: measurements need entry type `sensor_reading`. |
| 4 Signed tree head | Signature over the tree state, verified against the node key — not against the human-readable rendering shipped with it. |
| 5 Read the chain back | For each of the eight entries: decode the leaf yourself, the signature against the issuer key fetched over the API, the payload against the commitment, the inclusion proof against the signed root. |
| 6 Cold chain | The promise in the freight papers (2–6 °C) against the sensor readings. Two outliers, signed by two different keys in the same log — a contradiction, not a ruling. |
| 7 Erasure | Payload and salt gone, tombstone appended: the inclusion proof issued before the erasure still holds unchanged, the consistency proof shows pure appending. 200,000 guesses with known plaintext do not hit the commitment. |
| 8 Tampering | A flipped byte, a swapped leaf, an STH signed with a foreign key — and a split view that the node signs validly with its own key. Only someone who sees both trees finds that one. |
| 9 Balance sheet | Sizes: 3407 bytes per entry on average against 488 bytes of payload on average. The lion's share is the post-quantum signature. |

Section 8 is the only one that runs ahead of a live deployment: the split view here is constructed
and detected by hand, in one process, to show the mechanism. What notices it between independently
operated nodes in production is the [monitor](../monitor/) — polling STHs from outside any business
relationship, exactly the gap partner gossip alone cannot close (OWM-9 A1).
