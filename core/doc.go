// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package core implements the OpenWaymark core data model: entries, their
// deterministic CBOR encoding, post-quantum signatures over ML-DSA and the
// salted payload commitment.
//
// The normative reference is spec/owm-0-overview.md. The test vectors under
// testdata/vectors/ are part of the specification.
//
// An entry says: this entity claims, at this point in time, something about
// this subject, and what is claimed is exactly the payload with this
// commitment. The payload itself never lives here but off-chain — that is the
// only way it stays erasable.
package core
