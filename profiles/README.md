<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/` — Schema-Profile · Apache-2.0

**Geplant (Etappe E3). Noch kein Code.**

Der Kern kennt kein Branchenschema. Was in einer Nutzlast stehen darf, legt ein Profil fest, das
über die Profilkennung im Eintrag (`prof`) referenziert wird.

| Profil | Kennung | Stand |
|---|---|---|
| Lebensmittel | `owm.food/1` | erstes Zielprofil |
| EU-Batteriepass | noch offen | Profil Nr. 2, Pflicht ab Februar 2027 |

`food/` orientiert sich an der Ereignissemantik von **GS1 EPCIS 2.0** (ObjectEvent,
AggregationEvent, TransformationEvent, TransactionEvent), statt eine eigene zu erfinden. Der
Grund ist praktisch: Ohne Aggregation, Aufteilung und Umwandlung lässt sich keine reale
Lebensmittelkette abbilden — 1000 Eier werden zu 100 Zehnerpackungen, Milch von drei Höfen wird
ein Käselaib — und mit EPCIS ist die Industrie ohne Übersetzungsschicht anschlussfähig.

Die Graphstruktur dafür steht bereits im Kern: `par` in
[OWM-0 §6.2](../spec/owm-0-overview.md#62-eintragsverweis).
