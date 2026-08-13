<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# Vorführung

Eine vollständige Lieferkette gegen eine **echte, laufende Node** — vom Melkstand bis zum
Feinkosthändler, mit widersprechendem Kühlkettensensor, DSGVO-Löschung und vier
Manipulationsversuchen.

```sh
go run ./demo
```

Das Programm baut `owmnode`, startet es in einem Wegwerf-Verzeichnis auf zwei freien Ports an
`127.0.0.1`, redet ausschließlich über HTTP mit ihm und räumt am Ende alles wieder weg. Es
braucht kein Netz nach außen und fasst nichts an, was nicht ihm gehört.

| Schalter | Bedeutung |
|---|---|
| `-keep` | Arbeitsverzeichnis (Datenbank, Identität, Konfiguration) behalten |
| `-work DIR` | übergeordnetes Verzeichnis für den Wegwerf-Datenbestand |
| `-repo DIR` | Wurzel des Repositorys, falls nicht aus dem Modul erkennbar |

Die Ausgabe ist Klartext in englischer Sprache, ohne Farben und ohne Sonderzeichen — sie lässt
sich unverändert in eine Datei, ein Ticket oder eine Mail kopieren. Die Marke links sagt, worum es
in der Zeile geht: `ok` geprüft und in Ordnung, `blocked` abgewiesen (so gewollt), `note` Hinweis.

## Warum das Programm nur `core/` und `log/` einbindet

Die Vorführung ist kein Teil der Node, sondern ihr Gegenüber. Sie importiert ausschließlich die
Bibliotheken unter Apache-2.0; die Node (AGPL-3.0-only) läuft als eigener Prozess und wird wie von
einem fremden Client über die öffentliche API angesprochen.

Das ist keine Lizenzkosmetik, sondern die eigentliche Probe: Was die Vorführung nicht über die
öffentliche API bekommt, bekommt auch sonst niemand. Genau so ist aufgefallen, dass die API
zunächst keinen Teilnehmerschlüssel herausgab — womit ein fremder Client keine einzige Signatur
hätte prüfen können.

## Was die neun Abschnitte zeigen

| | |
|---|---|
| 1 Node starten | Die Node behauptet ihre Kennungen, der Client rechnet sie nach: Schlüsselkennung aus den Schlüsselbytes, Log-Kennung aus dem Gründungsschlüssel. |
| 2 Teilnehmer | Fünf Schlüssel im Verzeichnis, Sensor mit ML-DSA-44. Ein Schlüssel von außerhalb wird abgewiesen. |
| 3 Lieferkette | Acht `food.v1`-Ereignisse — Erzeugung, Aggregation, Transport, Messung, Verarbeitung, Übergabe — über Elternverweise verknüpft. Eine handgeschriebene Kühlkettenmessung weist das Profil ab: Messungen brauchen den Eintragstyp `sensor_reading`. |
| 4 Signed Tree Head | Unterschrift des Baumzustands, geprüft gegen den Node-Schlüssel — nicht gegen die mitgelieferte Lesefassung. |
| 5 Kette zurücklesen | Für jeden der acht Einträge: Blatt selbst dekodieren, Signatur gegen den über die API bezogenen Ausstellerschlüssel, Nutzlast gegen das Commitment, Inklusionsbeweis gegen die unterschriebene Wurzel. |
| 6 Kühlkette | Die Zusage im Frachtpapier (2–6 °C) gegen die Sensorwerte. Zwei Ausreißer, signiert von zwei verschiedenen Schlüsseln im selben Log — ein Widerspruch, kein Schiedsspruch. |
| 7 Löschung | Nutzlast und Salt weg, Grabstein angehängt: Der vor der Löschung ausgestellte Inklusionsbeweis gilt unverändert weiter, der Konsistenzbeweis zeigt reines Anhängen. 200 000 Rateversuche mit bekanntem Klartext treffen das Commitment nicht. |
| 8 Manipulation | Gekipptes Byte, ausgetauschtes Blatt, fremd unterschriebener STH — und ein Split View, den die Node mit ihrem eigenen Schlüssel gültig unterschreibt. Den findet nur, wer beide Bäume sieht. |
| 9 Bilanz | Größen: Ø 3407 Byte je Eintrag gegenüber Ø 488 Byte Nutzlast. Der Löwenanteil ist die Post-Quantum-Signatur. |

Abschnitt 8 ist der einzige, der einen Vorgriff enthält: Der Split View wird hier von Hand
konstruiert und erkannt. Wer ihn im Betrieb bemerkt, ist der noch nicht gebaute
[Monitor](../spec/owm-9-threat-model.md).
