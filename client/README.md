<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `client/` — Web-App und WASM-Verifier · Apache-2.0

**Geplant (Etappe E6). Noch kein Code.**

Der Verifier wird aus demselben Go-Code nach WASM übersetzt, der auch in der Node läuft — ein
Code-Pfad, zwei Ziele.

Das ist kein Komfortmerkmal, sondern die Bedingung dafür, dass die ganze Beweiskette etwas wert
ist: Der Client prüft Signaturen und Inklusionsbeweise **selbst**, statt dem Server zu glauben.
Ein Client, der dem Server glaubt, macht das Log gegenstandslos — dann hätte man es sich sparen
können. Siehe [OWM-9 A10](../spec/owm-9-threat-model.md).

Dazu: QR-Scan über `BarcodeDetector` mit JS-Fallback, und eine Kettendarstellung, die das
schwächste Glied ausdrücklich markiert statt es zu verstecken.
