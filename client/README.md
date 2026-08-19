<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `client/` — the WASM verifier and the web app · Apache-2.0

Full normative specification: [`spec/owm-8-client.md`](../spec/owm-8-client.md).

Three parts, one purpose: check a node's answer instead of believing it (OWM-9 A11).

| Directory | Content |
|---|---|
| [`verify/`](verify/) | The actual verification logic — a pure Go library. No cryptography of its own: it orchestrates `core`/`log`/`trust`'s existing `Verify` methods against data fetched through a small `Fetcher` interface. |
| [`wasm/`](wasm/) | `verify/`, compiled to WebAssembly and exposed to JavaScript as one function, `owmVerifySubject(nodeURL, subjectHex)`. Its own Go module (see below). |
| [`web/`](web/) | A static page — plain HTML/CSS/JS, no framework, no build step — that loads the WASM binary and renders what it returns. |

## Try it in one command

```sh
go run ./demo -serve
```

Runs the full demonstration, then keeps the node up and prints a ready `client/web/index.html#node=...&subject=...`
link, plus the values to paste into the form by hand. Build the WASM binary first if you have not
already (below), then open `client/web/index.html` in a browser and either follow the link or paste
the values in.

## Building the WASM binary

```sh
client/wasm/build.sh
```

Drops `verifier.wasm` and a matching `wasm_exec.js` straight into `client/web/` — nothing else to
install, no npm, no bundler. Neither file is committed (`.gitignore`): `wasm_exec.js` is copied
from the Go toolchain that built the `.wasm` next to it, and committing either would only invite
drift between the two.

## Why `client/wasm/` has its own `go.mod`

It is the one package in this repository that only builds for `GOOS=js GOARCH=wasm` — it imports
`syscall/js`, which does not exist for anything else. Without a module boundary of its own, a plain
`go build ./...` from the repository root would try to build it for the host platform and fail
every single time. A nested module — `require`-ing the parent module through a local `replace`
directive pointing at `../..` — is the standard Go answer to exactly this: `go build ./...` at the
root does not descend into a directory carrying its own `go.mod`, so this package simply is not
part of that command's scope. Build and test it explicitly instead:

```sh
cd client/wasm
GOOS=js GOARCH=wasm go build ./...
GOOS=js GOARCH=wasm go vet ./...
```

`client/verify` itself carries no such restriction and is part of the ordinary `go build ./...` /
`go test ./...` at the repository root, same as any other package — confirmed empirically, not
merely asserted: its only dependencies (`cloudflare/circl`, `fxamacker/cbor`,
`transparency-dev/merkle`) are pure Go, no cgo. `modernc.org/sqlite`, the one dependency in this
module that would not cross-compile cleanly to `GOOS=js`, is confined to `log/sqlite` and `node/`
and is never imported by `core`, `log`'s core types, or `trust` — which is exactly why
`client/verify` could be built the way it is at all.

## Known limitations, stated plainly rather than glossed over

- **Schema-driven rendering is not part of the trust boundary.** A dishonest node could serve a
  different profile schema to change how the page *displays* an entry, without touching the
  underlying signature, commitment or inclusion-proof validity at all — those are what this page
  actually verifies. Rendering is convenience; the checks above it are the point.
- **Trust-chain following does not cross node boundaries.** `httpTrustSource` (in `verify/`) walks
  an attestation chain against the same base URL the top-level call was given — an accreditation
  body attesting an entity from a *different* node's log is not followed. The same gap
  `gossip.Client` already has for partner resolution: there is no protocol-level way to resolve a
  bare `LogID` to a URL.
- **No accreditation roots by default.** `client/wasm`'s current build calls `verify.VerifySubject`
  with an empty `trust.RootSet`, so every entity trust level recomputes to `LevelNone` — an honest,
  ordinary result (`trust.Compute`'s own contract), not a bug. Supplying a root set from the page
  itself is a natural follow-up, not built yet.
- **Read-only.** Submitting entries stays business/ERP/scanner-integration territory
  (`POST /owm/v1/entries`), untouched by any of this.

Example payloads and end-to-end test setups are in [`verify/verify_test.go`](verify/verify_test.go).
