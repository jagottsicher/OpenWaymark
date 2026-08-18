<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `discovery/` — Node discovery · Apache-2.0

Resolves an OpenWaymark node from a domain name, the two steps in [OWM-5 §2](../spec/owm-5-federation.md#2-dns-discovery):

1. **`Lookup`** reads the `_openwaymark.<domain>` DNS TXT record and parses `v=owm1; node=<url>`.
   The `v=owm1` tag is what lets a foreign TXT record at the same name be told apart and ignored,
   rather than misread.
2. **`Describe`** fetches `GET <url>/.well-known/openwaymark` and decodes the node's current
   description — log ID, signing key, genesis key, tree size.

`Resolve` does both in one call.

Neither step is cryptographically authenticated on its own. Trust rides on TLS to the resolved base
URL — the same boundary a certificate transparency log's own HTTPS endpoint relies on. Everything
discovered here is a starting point to verify from, not a statement to be trusted; see
[`gossip/`](../gossip/) for what actually checks a node's signed statements.
