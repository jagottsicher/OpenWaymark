// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package core implementiert das Kern-Datenmodell von OpenWaymark: Einträge,
// ihre deterministische CBOR-Kodierung, Post-Quantum-Signaturen über ML-DSA und
// das gesalzene Nutzlast-Commitment.
//
// Normative Referenz ist spec/owm-0-overview.md. Die Testvektoren unter
// testdata/vectors/ sind Teil der Spezifikation.
//
// Ein Eintrag sagt: Diese Entität behauptet zu diesem Zeitpunkt etwas über
// dieses Subjekt, und das Behauptete ist genau die Nutzlast mit diesem
// Commitment. Die Nutzlast selbst liegt niemals hier, sondern off-chain —
// nur so bleibt sie löschbar.
package core
