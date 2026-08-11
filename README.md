<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OpenWaymark

**Ein offenes, föderiertes Protokoll für kryptographisch verifizierbare Herkunfts- und
Lieferkettennachweise.**

Website: <https://openwaymark.org/>

OpenWaymark beantwortet für ein beliebiges Gut — ein Ei, einen Diamanten, eine Batteriezelle —
vier Fragen so, dass die Antwort überprüfbar ist statt geglaubt werden zu müssen:

- Woher stammt es?
- Welche Stationen hat es durchlaufen?
- Wer hat das behauptet, und wie gut ist diese Person oder Stelle verifiziert?
- Wurde die Kühlkette eingehalten, ist es bio-zertifiziert, konfliktfrei?

## Was OpenWaymark ist — und was nicht

|  |  |
|---|---|
| **Föderiert** | Jede Node ist autoritativ für ihre eigenen Daten. Kein globaler Zustand, auf den sich alle einigen müssen. Vergleichbar mit E-Mail oder DNS, nicht mit einer Blockchain. |
| **Transparenzlog statt Blockchain** | Jede Node führt ein lokales, append-only Merkle-Log nach dem Vorbild von Certificate Transparency (RFC 6962). Manipulationssicherheit entsteht durch signierte Baum-Snapshots und gegenseitige Beobachtung, nicht durch Konsens. |
| **Löschbar** | DSGVO-Löschung ist eine Kernanforderung, kein Nachtrag. Das Log speichert nur ein gesalzenes Commitment; Nutzlast und Salt liegen off-chain und lassen sich wirklich löschen — ohne dass ein einziger historischer Beweis ungültig wird. |
| **Post-Quantum ab Tag 1** | Ausschließlich ML-DSA (FIPS 204) und ML-KEM (FIPS 203). Kein RSA, kein ECC, kein Hybrid-Übergangsmodell. |
| **Kein Finanzprodukt** | Keine handelbare Kryptowährung, kein Token mit Marktpreis, keine Börse. Das geplante Anreizsystem ist ein geschlossenes, nicht handelbares Pfandsystem. |
| **Kein Wahrheitsbeweis** | OpenWaymark kann nicht verhindern, dass jemand bei der Ersterfassung lügt. Es macht die Lüge nachträglich manipulationssicher dokumentiert, zurechenbar und ökonomisch unattraktiv. Siehe [Angreifermodell](spec/owm-9-threat-model.md). |

## Stand

**Frühe Entwicklung.** Das Protokoll ist noch nicht stabil, das Datenformat kann sich ändern.
Noch keine Version ist für den Produktivbetrieb gedacht.

| Baustein | Verzeichnis | Stand |
|---|---|---|
| Spezifikation | [`spec/`](spec/) | Übersicht und Angreifermodell vorhanden |
| Datenmodell, Krypto, Serialisierung | [`core/`](core/) | in Arbeit |
| Merkle-Log, Beweise, Löschpfad | `log/` | geplant |
| Node-Server | `node/` | geplant |
| Unabhängiger Log-Monitor | `monitor/` | geplant |
| Web-App und WASM-Verifier | `client/` | geplant |
| Schema-Profile (zuerst Lebensmittel) | `profiles/` | geplant |
| Testvektoren für Fremdimplementierungen | [`testdata/`](testdata/) | in Arbeit |

## Bauen und testen

Benötigt Go 1.25 oder neuer (ML-DSA über CIRCL setzt das voraus).

```sh
go build ./...
go test ./...
go vet ./...
```

## Dokumentation

- [`spec/owm-0-overview.md`](spec/owm-0-overview.md) — Protokollübersicht, Begriffe, Kryptoparameter
- [`spec/owm-9-threat-model.md`](spec/owm-9-threat-model.md) — Angreifermodell und Grenzen des Systems
- [`CLAUDE.md`](CLAUDE.md) — Konzeptdokument mit den Grundsatzentscheidungen und ihrer Begründung

## Lizenz

Geteilte Lizenzierung, damit Bibliotheken frei einbindbar bleiben und Serverbetreiber ihre
Änderungen zurückgeben:

| Bereich | Lizenz |
|---|---|
| `spec/`, `core/`, `log/`, `client/`, `profiles/`, `testdata/` | Apache-2.0 |
| `node/`, `monitor/` | AGPL-3.0-only |

Jede Datei trägt einen SPDX-Bezeichner; die vollständigen Lizenztexte liegen in
[`LICENSES/`](LICENSES/). Das Repository folgt der [REUSE-Spezifikation](https://reuse.software/).
