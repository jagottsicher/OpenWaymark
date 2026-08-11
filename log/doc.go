// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package log führt das append-only Merkle-Log einer Node.
//
// Die Baumkonstruktion ist unverändert die aus RFC 6962 (Certificate
// Transparency), gerechnet mit github.com/transparency-dev/merkle. Eigener
// Merkle-Code wäre eine vermeidbare Fehlerquelle in genau dem Teil des Systems,
// der am wenigsten Fehler verträgt.
//
// Der eine Unterschied zu CT ist die Löschbarkeit. CT löscht nie und braucht sie
// deshalb nicht; OpenWaymark muss löschen können, ohne den Baum anzutasten. Der
// Kniff steht in Erase: Gelöscht werden Nutzlast und Salt außerhalb des Logs,
// angehängt wird eine Löschbezeugung. Der Baum bleibt Byte für Byte, wie er war,
// und damit bleiben alle je ausgestellten STHs und alle je ausgestellten Beweise
// gültig.
//
// Das Paket zerfällt in zwei Hälften, und die Trennung ist beabsichtigt:
//
//   - Blatt, STH und Beweisprüfung hängen von keinem Speicher ab. Diese Hälfte
//     ist es, die später nach WASM übersetzt im Browser läuft und dem Server
//     gerade nicht glaubt (OWM-9 A10).
//   - Log und Storage führen den Baum. Die SQLite-Anbindung liegt bewusst im
//     Unterpaket sqlite, damit sie nicht in den Browser-Verifier gerät.
//
// Spezifikation: spec/owm-2-log.md.
package log
