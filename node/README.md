<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

# `node/` — Node-Server · AGPL-3.0-only

**Geplant (Etappe E3). Noch kein Code.**

Der Server, der ein Log führt und für seine eigenen Daten autoritativ ist. HTTP-API zum
Einreichen und Lesen von Einträgen, STH-Ausgabe, Inklusions- und Konsistenzbeweise,
Produkthistorie, Blob-Speicher mit echtem Löschpfad.

Speicher über `modernc.org/sqlite` — reines Go, ohne cgo. Das ist kein Detail: Nur so lassen
sich Binaries für ARM bauen, ohne eine Cross-Toolchain einzurichten, und nur dann ist eine Node
auf Raspberry-Pi-Klasse-Hardware wirklich betreibbar.

**Lizenz:** AGPL-3.0-only, abweichend vom übrigen Repository. Wer diese Software als Dienst
betreibt, gibt seine Änderungen an das Netz zurück, in dem er sie einsetzt. Die Bibliotheken
(`core/`, `log/`, `client/`) stehen weiterhin unter Apache-2.0 und bleiben frei einbindbar.
