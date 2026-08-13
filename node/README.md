<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

# `node/` — Node-Server · AGPL-3.0-only

Der Server, der ein Log führt und für seine eigenen Daten autoritativ ist. HTTP-API zum
Einreichen und Lesen von Einträgen, STH-Ausgabe, Inklusions- und Konsistenzbeweise,
Produkthistorie, Nutzlastspeicher mit echtem Löschpfad.

Vollständige Beschreibung der Schnittstelle: [OWM-7](../spec/owm-7-node-api.md).
Identität, Schlüsselverzeichnis und Rotation: [OWM-3](../spec/owm-3-keys.md).

## Betrieb

```sh
go run ./node/cmd/owmnode init  -config owm.json -operator "Hof Sonnenblick" -contact hof@beispiel.de
go run ./node/cmd/owmnode show  -config owm.json
go run ./node/cmd/owmnode serve -config owm.json
```

`init` legt Konfiguration und Identität an und überschreibt **nie** eine bestehende. Eine
Identität zu überschreiben hieße, das Log unter neuer Kennung fortzuführen — alle bisherigen STHs
wären dann von einem Schlüssel, den niemand mehr kennt.

Der laufende Betrieb — Schlüssel aufnehmen, Nutzlasten löschen, STHs ausstellen — geht über die
Verwaltungsschnittstelle der laufenden Node und nicht über weitere Unterbefehle. Zwei Prozesse
auf derselben SQLite-Datei wären ein Weg, sich die Datenbank zu zerlegen.

## Zwei Schnittstellen

| | Voreinstellung | Wer |
|---|---|---|
| Öffentliche API | `127.0.0.1:8480` | die Welt, hinter einem TLS-terminierenden Reverse-Proxy |
| Verwaltung | `127.0.0.1:8481` | die Betreiberin |

**Die Verwaltungsschnittstelle kennt keine Authentifizierung, und das ist Absicht.** Zugangsschutz
gehört hier in die Umgebung — lokale Bindung, Unix-Socket hinter einem Proxy, VPN. Ein
selbstgestricktes Token-Verfahren im Anwendungscode wäre schwächer als das, was Betriebssystem
und ausgewachsener Proxy ohnehin können, und würde vortäuschen, die Frage sei geklärt. Wer diese
Schnittstelle erreicht, kann Schlüssel aufnehmen und Nutzlasten löschen.

Auch die öffentliche API bindet voreingestellt an localhost: Von sich aus ins Netz zu greifen ist
nichts, was ein Programm ungefragt tun sollte.

## Wessen Einträge angenommen werden

Nur die von Schlüsseln im eigenen Verzeichnis. Eine Node ist autoritativ für ihre eigenen
Teilnehmer und für sonst niemanden; wer dort nicht steht, hat eine andere Node. Ebenso nimmt sie
nur Profile an, die sie prüfen kann — ein Profil abzulehnen, das man nicht kennt, ist ehrlicher,
als es ungeprüft anzunehmen.

Löschbezeugungen (`erasure`) erzeugt ausschließlich die Node selbst. Sie von außen anzunehmen
hieße, jemanden behaupten zu lassen, hier sei etwas gelöscht worden.

## Speicher

`modernc.org/sqlite` — reines Go, ohne cgo. Das ist kein Detail: Nur so lassen sich Binaries für
ARM bauen, ohne eine Cross-Toolchain einzurichten, und nur dann ist eine Node auf
Raspberry-Pi-Klasse-Hardware wirklich betreibbar.

**Lizenz:** AGPL-3.0-only, abweichend vom übrigen Repository. Wer diese Software als Dienst
betreibt, gibt seine Änderungen an das Netz zurück, in dem er sie einsetzt. Die Bibliotheken
(`core/`, `log/`, `client/`) stehen weiterhin unter Apache-2.0 und bleiben frei einbindbar.
