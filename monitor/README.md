<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

# `monitor/` — Independent log monitor · AGPL-3.0-only

Collects STHs from configured targets, checks them for self-contradiction using
[`gossip`](../gossip/), and persists any finding as durable evidence. Deliberately small and
self-contained, so that someone other than the observed node can run it — that is the whole point.

The monitor belongs to the core of the project, not to its accessories. The central attack on a
CT-style log is the **split view**: a node shows two observers two different trees, each
internally consistent. Both histories are correctly signed, both inclusion proofs check out.
Locally this cannot be detected in principle. Without independent observation the attack stays
open — and with it the after-the-fact alteration of the log, because a node that keeps its history
by itself alone can rewrite it along with every STH.

Two STHs from the same node for the same tree size with different root hashes are signed,
undeniable proof of misbehaviour. The node signed it itself.

See [OWM-9 A1 and A2](../spec/owm-9-threat-model.md), [OWM-5 §4](../spec/owm-5-federation.md#4-the-independent-monitors-contract).
`TestSplitViewEndToEnd` in `monitor_test.go` is the most important test in the project.

## Operation

```sh
owmmonitor init [-config owm-monitor.json]   # create a default configuration
owmmonitor run  [-config owm-monitor.json]   # start watching
owmmonitor version
```

There is no admin surface and nothing to serve: a monitor holds no identity of its own and answers
no requests, it only watches.

## Config

```json
{
  "targets": [
    { "name": "acme-farm", "base_url": "https://provenance.acme-farm.example.com" },
    { "name": "partner-dairy", "domain": "provenance.example.org" }
  ],
  "poll_interval": "5m",
  "rediscover_interval": "1h",
  "findings_dir": "findings"
}
```

A target names either a `base_url` directly or a `domain` to resolve via DNS discovery
([OWM-5 §2](../spec/owm-5-federation.md#2-dns-discovery)) — exactly one of the two, so that a
partner's base URL can change without editing this file. `poll_interval` is how often each
target's `/owm/v1/sth` is polled; `rediscover_interval` is how often a `domain` target is
re-resolved (ignored for `base_url` targets).

A finding is written to `findings_dir` as one JSON file per incident — the target, the kind of
contradiction, and the raw canonical bytes of both conflicting signed STHs (plus the consistency
proof, if one was fetched). Nothing in this package ever overwrites or prunes a finding once
written; that persistence is the entire point of running a monitor at all. A plain-text alarm line
is also printed to stdout at the moment of detection.

## Being worth something

A monitor whose presence a node can single out is a monitor a dishonest node can simply exempt from
the split view — a third, separate, permanently-consistent view maintained just for it. Nothing in
the protocol enforces this; it is a property of *how* a monitor is run (network vantage point,
request pattern, absence of advance notice to the observed operator), not of the wire format. See
[OWM-9 §6](../spec/owm-9-threat-model.md).
