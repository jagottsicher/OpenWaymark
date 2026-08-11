<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `log/` — Append-only Log · Apache-2.0

**Geplant (Etappe E2). Noch kein Code.**

Das Herzstück des Protokolls: der Merkle-Baum nach RFC 6962 über
[`transparency-dev/merkle`](https://github.com/transparency-dev/merkle), Inklusions- und
Konsistenzbeweise, Signed Tree Heads — und der Löschpfad.

Der Kniff, um den es hier geht: Gelöscht werden Blob und Salt, nicht das Blatt. Der Baum bleibt
unverändert, deshalb bleiben **alle je ausgegebenen STHs gültig**. Genau das macht
DSGVO-Löschbarkeit und Manipulationssicherheit vereinbar — Certificate Transparency braucht es
nicht, weil CT nie löscht.

Spezifikation: OWM-2 (noch zu schreiben). Angreifermodell:
[OWM-9 A2, A5](../spec/owm-9-threat-model.md).
