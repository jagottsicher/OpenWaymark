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

The public API binds to localhost by default as well: reaching out onto the network of its own
accord is not something a program should do unasked.

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
