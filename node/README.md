<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

# `node/` — Node server · AGPL-3.0-only

The server that keeps a log and is authoritative for its own data. HTTP API for submitting and
reading entries, STH issuance, inclusion and consistency proofs, product history, payload storage
with a real erasure path.

Full description of the interface: [OWM-7](../spec/owm-7-node-api.md).
Identity, key directory and rotation: [OWM-3](../spec/owm-3-keys.md).

## Operation

```sh
go run ./node/cmd/owmnode init  -config owm.json -operator "Hof Sonnenblick" -contact hof@example.com
go run ./node/cmd/owmnode show  -config owm.json
go run ./node/cmd/owmnode serve -config owm.json
```

`init` creates configuration and identity and **never** overwrites an existing one. Overwriting an
identity would mean continuing the log under a new ID — every STH issued so far would then come
from a key nobody has any more.

**`serve` does not require `init` to have run first**, and that is worth knowing before it
surprises you: given a `-config` path that does not exist, `serve` falls back to built-in defaults
silently rather than failing, and the first `Open` call creates a fresh identity and database at
the default paths if none exist yet — no `owm.json` is ever written by `serve` itself. That is
convenient for a five-second local check, but on anything meant to last it means a `serve` run
before `init` commits the log to an identity, a listen address and a database path you never
chose. Run `show -config owm.json` right after the first start if you are not certain which one
happened — it prints the log ID, the identity and database paths, and the addresses actually in
use.

Day-to-day operation — adding keys, erasing payloads, issuing STHs — goes through the admin
interface of the running node, not through further subcommands. Two processes on the same SQLite
file would be one good way to take the database apart.

## Two interfaces

| | Default | Who |
|---|---|---|
| Public API | `127.0.0.1:8480` | the world, behind a TLS-terminating reverse proxy |
| Admin | `127.0.0.1:8481` | the operator |

**The admin interface has no authentication, and that is deliberate.** Access control belongs in
the environment here — binding to localhost, a Unix socket behind a proxy, a VPN. A home-grown
token scheme in application code would be weaker than what the operating system and a fully grown
proxy can do anyway, and it would pretend the question had been settled. Anyone who reaches this
interface can add keys and erase payloads.

In practice, on a node whose operator does not log into it directly — the usual case once it runs
as a service somewhere — that means reaching the admin interface over an SSH tunnel rather than
opening it up:

```sh
ssh -L 8481:127.0.0.1:8481 <user>@<host>
# then, in a second terminal, against your own machine:
curl http://127.0.0.1:8481/admin/v1/keys
```

Nothing about the node needs to know this is happening; the tunnel just makes the operator's own
machine act as if it were on `localhost` on the node's side, which is exactly the trust boundary
this interface was designed around.

The public API binds to localhost by default as well: reaching out onto the network of its own
accord is not something a program should do unasked.

## Running a node reachable from the internet

Getting from "runs on `127.0.0.1`" to "answers `https://provenance.example.com`" has three moving
parts, all outside this package on purpose — the node itself stays a plain HTTP server that trusts
its environment for everything else:

1. **Listen on an address the reverse proxy can actually reach.** If the proxy runs on the same
   host, `127.0.0.1` is correct and nothing changes. If it runs elsewhere — its own machine, a
   separate container — `listen` in the configuration has to name an address that host can route
   to (the node's LAN-facing interface, not `0.0.0.0`: bind to the one address that is meant to be
   reached, not to every address there happens to be). The node speaks plain HTTP only; it has no
   TLS of its own to fall back on if this step is skipped or done differently than intended.
2. **Restrict that address to the proxy**, at the firewall, not in application code. The public API
   has no authentication in front of it (by design — see OWM-7), so binding it to a LAN address
   without also restricting who may reach that address turns "behind a reverse proxy" into
   "additionally reachable in plain HTTP by anyone who can route to that address." A per-host
   firewall rule allowing only the proxy's address on the node's port is the whole fix.
3. **Set `base_url` to the externally visible `https://` URL**, exactly as it should read in
   `.well-known/openwaymark` (OWM-7 §4.1) — this is what a discovering client or gossip peer
   compares the DNS record against (OWM-5 §2), so it has to match both the DNS name and the
   certificate the reverse proxy actually terminates.

None of this is specific to `owmnode`; it is the same shape as putting any plain-HTTP backend
behind a TLS-terminating proxy. What is specific to a federated node is step 3 and what follows
from it — the DNS side (the `_openwaymark` TXT record) is covered in
[OWM-5](../spec/owm-5-federation.md#2-dns-discovery), including the point that is easy to miss: the
domain's own A/CNAME record (however it resolves — directly, through a load balancer, whatever
gets traffic to the proxy) and the `_openwaymark.<domain>` TXT record are two independent DNS
names, and setting up one is not a substitute for the other. A node can be perfectly reachable and
still be undiscoverable, if only the first one was done.

## Whose entries are accepted

Only those from keys in its own directory. A node is authoritative for its own participants and
for nobody else; whoever is not listed there belongs to a different node. It likewise accepts only
profiles it can validate — rejecting a profile you do not know is more honest than accepting it
unchecked.

Erasure attestations (`erasure`) are produced by the node itself and by nobody else. Accepting
them from outside would let somebody claim that something had been erased here.

## Storage

`modernc.org/sqlite` — pure Go, no cgo. That is not a detail: it is the only way to build binaries
for ARM without setting up a cross toolchain, and only then is a node genuinely operable on
Raspberry-Pi-class hardware.

**Licence:** AGPL-3.0-only, differing from the rest of the repository. Whoever runs this software
as a service gives their changes back to the network they run it on. The libraries (`core/`,
`log/`, `client/`) remain under Apache-2.0 and stay freely importable.
