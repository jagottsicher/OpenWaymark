// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package log maintains the append-only Merkle log of a node.
//
// The tree construction is unchanged from RFC 6962 (Certificate Transparency),
// computed with github.com/transparency-dev/merkle. Home-grown Merkle code
// would be an avoidable source of error in exactly the part of the system that
// tolerates errors least.
//
// The one difference to CT is erasability. CT never erases and therefore does
// not need it; OpenWaymark has to be able to erase without touching the tree.
// The trick is in Erase: what gets deleted are payload and salt outside the
// log, what gets appended is an erasure witness. The tree stays byte for byte
// as it was, and with it all STHs ever issued and all proofs ever issued stay
// valid.
//
// The package falls into two halves, and the separation is deliberate:
//
//   - Leaf, STH and proof verification depend on no storage at all. This is the
//     half that later runs in the browser compiled to WASM and precisely does
//     not believe the server (OWM-9 A11).
//   - Log and Storage maintain the tree. The SQLite backend deliberately lives
//     in the sqlite subpackage so that it does not end up in the browser
//     verifier.
//
// Specification: spec/owm-2-log.md.
package log
