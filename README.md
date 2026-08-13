<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OpenWaymark

**Ein offenes, föderiertes Protokoll für kryptographisch verifizierbare Herkunfts- und
Lieferkettennachweise.**

Website: <https://openwaymark.org/> · Lizenz: Apache-2.0 (Bibliotheken) und AGPL-3.0-only (Server)
· Stand: frühe Entwicklung, Format noch nicht stabil

> *Note for English readers:* documentation, specification and source comments are currently in
> German. All program output and error messages are English plain text. Contributions in English
> are welcome — see [Mitarbeiten](#mitarbeiten).

OpenWaymark beantwortet für ein beliebiges Gut — ein Ei, einen Diamanten, eine Batteriezelle —
vier Fragen so, dass die Antwort überprüfbar ist statt geglaubt werden zu müssen:

- Woher stammt es?
- Welche Stationen hat es durchlaufen?
- Wer hat das behauptet, und wie gut ist diese Person oder Stelle verifiziert?
- Wurde die Kühlkette eingehalten, ist es bio-zertifiziert, konfliktfrei?

Die Antwort besteht aus signierten Einträgen in append-only Logs, aus Beweisen, die ein Client
selbst nachrechnet, und aus der Möglichkeit, einer Node zu widersprechen, die lügt.

## Inhalt

- [Was OpenWaymark ist — und was nicht](#was-openwaymark-ist--und-was-nicht)
- [In fünf Minuten ansehen](#in-fünf-minuten-ansehen)
- [Wie es funktioniert](#wie-es-funktioniert)
- [Eigene Node betreiben](#eigene-node-betreiben)
- [Aufbau des Repositorys](#aufbau-des-repositorys)
- [Stand und Fahrplan](#stand-und-fahrplan)
- [Dokumentation](#dokumentation)
- [Sicherheit](#sicherheit)
- [Mitarbeiten](#mitarbeiten)
- [Releases und Versionierung](#releases-und-versionierung)
- [Lizenz](#lizenz)

## Was OpenWaymark ist — und was nicht

|  |  |
|---|---|
| **Föderiert** | Jede Node ist autoritativ für ihre eigenen Daten. Kein globaler Zustand, auf den sich alle einigen müssen. Vergleichbar mit E-Mail oder DNS, nicht mit einer Blockchain. |
| **Transparenzlog statt Blockchain** | Jede Node führt ein lokales, append-only Merkle-Log nach dem Vorbild von Certificate Transparency (RFC 6962). Manipulationssicherheit entsteht durch signierte Baum-Snapshots und gegenseitige Beobachtung, nicht durch Konsens. |
| **Löschbar** | DSGVO-Löschung ist eine Kernanforderung, kein Nachtrag. Das Log speichert nur ein gesalzenes Commitment; Nutzlast und Salt liegen off-chain und lassen sich wirklich löschen — ohne dass ein einziger historischer Beweis ungültig wird. |
| **Post-Quantum ab Tag 1** | Ausschließlich ML-DSA (FIPS 204) und ML-KEM (FIPS 203). Kein RSA, kein ECC, kein Hybrid-Übergangsmodell. |
| **Branchenagnostisch** | Der Kern kennt kein Branchenschema. Was in einer Nutzlast stehen darf, legt ein austauschbares Schema-Profil fest; das erste ist `food.v1`. |
| **Kein Finanzprodukt** | Keine handelbare Kryptowährung, kein Token mit Marktpreis, keine Börse. Das geplante Anreizsystem ist ein geschlossenes, nicht handelbares Pfandsystem. |
| **Kein Wahrheitsbeweis** | OpenWaymark kann nicht verhindern, dass jemand bei der Ersterfassung lügt. Es macht die Lüge nachträglich manipulationssicher dokumentiert, zurechenbar und ökonomisch unattraktiv. Siehe [Angreifermodell](spec/owm-9-threat-model.md). |

## In fünf Minuten ansehen

Benötigt Go 1.25 oder neuer. Sonst nichts — kein Docker, kein Netz nach außen, keine Datenbank
zum Aufsetzen.

```sh
git clone <url-dieses-repositorys> openwaymark
cd openwaymark
go run ./demo
```

Die Vorführung baut `owmnode`, startet die Node in einem Wegwerf-Verzeichnis auf zwei freien Ports
an `127.0.0.1`, spielt eine vollständige Lebensmittelkette durch und räumt am Ende alles wieder
weg. Der Client glaubt der Node dabei kein Wort: Er rechnet jede Kennung nach und prüft jede
Signatur, jedes Commitment und jeden Beweis selbst.

```
5. Reading the chain back: the client checks everything itself
            #7 handover           Molkerei Alpenrand -> Feinkost Brunner e.K. (DA-2026-08-11-0093)
               assertion, logged 13:30:34, proof 3 nodes
               #6 processing         pasteurise and add rennet -> Mountain cheese, 12 months, by ...
                  assertion, logged 13:30:34, proof 3 nodes
   ok       8 entries: signature, commitment and inclusion proof verified
   ok       public keys fetched over the public API

6. Cold chain: what the sensor says against what was promised
            promised on the freight papers: 2.0 to 6.0 C (Spedition Kühlfracht)
            09:35    7.9 C  BREACH
            10:05    8.4 C  BREACH
   blocked  2 of 7 readings outside the promised range

7. Erasure under Art. 17 GDPR
   ok       payload and salt erased, tombstone appended
   blocked  payload no longer retrievable: HTTP 410 erased
   ok       the proof issued before the erasure still verifies, the tree is unchanged
   ok       consistency proof 8 -> 9: appended only, nothing rewritten

8. Tampering attempts
   blocked  one byte flipped in the entry -> signature invalid
   blocked  altered leaf against the same proof -> does not match the root
   blocked  STH signed with a foreign key -> signature does not match the node
   blocked  split view detected: owm/log: split view: two roots for the same tree size
```

Neun Abschnitte, im Einzelnen erklärt in [`demo/README.md`](demo/README.md).

## Wie es funktioniert

### Eintrag, Blatt, Baum

Wer etwas behauptet, schreibt einen **Eintrag**: deterministisch als CBOR serialisiert
(RFC 8949 §4.2), signiert mit ML-DSA, adressiert über den Hash seines Inhalts. Ein Eintrag nennt
sein Subjekt (das Gut), seinen Aussteller, sein Profil, seine Elterneinträge — und statt der
Nutzlast nur deren **gesalzenes Commitment** `H(salt ‖ payload)`.

Die Node hängt daraus ein **Blatt** an ihr Merkle-Log. Über den Baum stellt sie periodisch einen
**Signed Tree Head** aus: Log-Kennung, Baumgröße, Wurzelhash, Zeitstempel, signiert. Aus dem Baum
folgen zwei Beweise, die jeder Client selbst nachrechnen kann:

- **Inklusionsbeweis** — dieses Blatt steckt in genau diesem Baum.
- **Konsistenzbeweis** — der neue Baum ist der alte plus Anhang; nichts wurde umgeschrieben.

### Warum Löschen und Beweisen sich nicht widersprechen

Personenbezogene Daten stehen **nie** im Blatt, sondern ausschließlich im Off-Chain-Blob. Eine
Löschung entfernt Nutzlast **und Salt** und hängt einen Grabstein an. Der Baum bleibt dabei
unverändert — deshalb gelten **alle je ausgestellten STHs und Inklusionsbeweise unverändert
weiter**. Ohne Salt ist die Nutzlast auch dann nicht rekonstruierbar, wenn ihr Wertebereich klein
ist und der Angreifer den Klartext errät; das ist der Unterschied zu einem nackten Hash.

Das historische Gegenbeispiel steht in [CLAUDE.md](CLAUDE.md) §2: das alte SKS-Keyserver-Netz,
append-only ohne Löschmöglichkeit, 2019 durch vergiftete Einträge faktisch unbenutzbar.

### Föderation statt globaler Kette

Es gibt kein Doppelausgabe-Problem, also auch keinen Grund für einen teuren Konsensmechanismus.
Jede Node ist für ihre eigenen Teilnehmer zuständig und nimmt nur Einträge von Schlüsseln aus
ihrem eigenen Verzeichnis an. Gefunden werden Nodes über DNS:

```
_openwaymark.beispiel.de. IN TXT "v=owm1; node=https://provenance.beispiel.de"
```

Der zentrale Angriff auf ein solches Log ist der **Split View**: Eine Node zeigt zwei Beobachtern
zwei verschiedene Bäume derselben Größe. Beide Unterschriften sind gültig — auffallen kann das
nur jemandem, der beide sieht. Dafür sind zwei Dinge vorgesehen: gezieltes Gossip zwischen
tatsächlichen Lieferkettenpartnern und STH-Gossip an unabhängige Monitore
([`monitor/`](monitor/), noch nicht gebaut). Die Erkennungslogik selbst steht bereits in
`log.CheckSTHPair`.

### Profile

Der Kern kennt keine Branche. Ein Profil legt per JSON Schema fest, was in einer Nutzlast stehen
darf, und wird über die Profilkennung im Eintrag referenziert. Das erste Profil `food.v1` bildet
die Ereignisse von GS1 EPCIS 2.0 nach — Erzeugung, Aggregation, Transport, Messung, Verarbeitung,
Übergabe —, damit die Industrie ohne Übersetzungsschicht anschlussfähig ist.

Eine Profilversion ändert sich nie: Wäre `food.v1` heute anders als gestern, wäre ein Eintrag von
gestern heute ungültig, ohne dass ihn jemand angefasst hätte. Änderungen erscheinen als `food.v2`.

### Kryptographie

| | |
|---|---|
| Signaturen (Nodes, Entitäten) | ML-DSA-65 — 1952 B Public Key, 3309 B Signatur |
| Signaturen (Sensoren, Masseneinträge) | ML-DSA-44 — 1312 B Public Key, 2420 B Signatur |
| Verschlüsselung (geplant, E5) | ML-KEM über `crypto/mlkem` der Standardbibliothek |
| Hash | SHA-256, überall mit Domain-Trennung (`OWM/1 entry`, `OWM/1 commit`, …) |
| Serialisierung | deterministisches CBOR, RFC 8949 §4.2 |

Die Größe ist kein Nebenaspekt, sondern eine Entwurfsbedingung: Ein Eintrag der Vorführung wiegt
im Mittel 3407 Byte, seine Nutzlast 488 Byte. Der Löwenanteil ist die Signatur — deshalb ML-DSA-44
für Sensoren und deshalb ist Batch-Signierung vorgesehen.

## Eigene Node betreiben

```sh
go build -o owmnode ./node/cmd/owmnode

./owmnode init -config owm.json \
    -operator "Hof Sonnenblick" -contact datenschutz@beispiel.de \
    -base-url https://provenance.beispiel.de
./owmnode show  -config owm.json
./owmnode serve -config owm.json
```

`init` legt Konfiguration und Identität an und überschreibt **nie** eine bestehende — eine
Identität zu überschreiben hieße, das Log unter neuer Kennung fortzuführen, und alle bisherigen
STHs wären von einem Schlüssel, den niemand mehr kennt.

Die Node öffnet zwei Schnittstellen, beide voreingestellt auf `127.0.0.1`:

| | Voreinstellung | Für wen |
|---|---|---|
| Öffentliche API `/owm/v1` | `127.0.0.1:8480` | die Welt, hinter einem TLS-terminierenden Reverse-Proxy |
| Verwaltung `/admin/v1` | `127.0.0.1:8481` | ausschließlich die Betreiberin |

⚠️ **Die Verwaltungsschnittstelle kennt keine Authentifizierung, und das ist Absicht.**
Zugangsschutz gehört in die Umgebung: lokale Bindung, Unix-Socket hinter einem Proxy, VPN. Wer
diese Schnittstelle erreicht, kann Schlüssel aufnehmen und Nutzlasten löschen. Ein
selbstgestricktes Token-Verfahren im Anwendungscode wäre schwächer als das, was Betriebssystem und
ausgewachsener Proxy ohnehin können — und würde vortäuschen, die Frage sei geklärt.

Der laufende Betrieb — Schlüssel aufnehmen, Nutzlasten löschen, STHs ausstellen — geht über die
Verwaltungsschnittstelle, nicht über weitere Unterbefehle: Zwei Prozesse auf derselben
SQLite-Datei wären ein Weg, sich die Datenbank zu zerlegen.

Gespeichert wird über `modernc.org/sqlite`, reines Go ohne cgo. Damit lassen sich Binaries für ARM
ohne Cross-Toolchain bauen — die Voraussetzung dafür, dass eine Node auf Raspberry-Pi-Klasse
wirklich betreibbar ist.

Vollständige Schnittstellenbeschreibung: [OWM-7](spec/owm-7-node-api.md).

## Aufbau des Repositorys

Ein einziges Go-Modul `openwaymark.org/owm` mit Unterpaketen. Aufgespalten wird erst, wenn jemand
`core/` einzeln einbinden will.

| Verzeichnis | Inhalt | Lizenz |
|---|---|---|
| [`spec/`](spec/) | Protokollspezifikation, normativ | Apache-2.0 |
| [`core/`](core/) | Eintragstypen, deterministisches CBOR, ML-DSA, Commitments | Apache-2.0 |
| [`log/`](log/) | Merkle-Log, STH, Inklusions- und Konsistenzbeweise, Löschpfad | Apache-2.0 |
| [`profiles/`](profiles/) | Schema-Profile, zuerst [`food/`](profiles/food/) | Apache-2.0 |
| [`node/`](node/) | Node-Server und `owmnode` | AGPL-3.0-only |
| [`monitor/`](monitor/) | unabhängiger Log-Monitor (geplant) | AGPL-3.0-only |
| [`client/`](client/) | WASM-Verifier und Web-App (geplant) | Apache-2.0 |
| [`demo/`](demo/) | Ende-zu-Ende-Vorführung gegen eine echte Node | Apache-2.0 |
| [`testdata/`](testdata/) | Testvektoren für Fremdimplementierungen | Apache-2.0 |

Die Testvektoren sind **Teil der Spezifikation**, nicht bloß Testbeiwerk: Wer OpenWaymark in einer
anderen Sprache implementiert, prüft sich daran.

## Stand und Fahrplan

**Frühe Entwicklung.** Das Protokoll ist noch nicht stabil, das Datenformat kann sich ändern.
Noch keine Version ist für den Produktivbetrieb gedacht.

| Etappe | Inhalt | Stand |
|---|---|---|
| E0 | Fundament, Spezifikationsentwürfe, CI | fertig |
| E1 | Kern-Datenmodell, Krypto, Testvektoren | fertig |
| E2 | Merkle-Log, STH, Beweise, Löschpfad | fertig |
| E3 | Node-Server, HTTP-API, Profil `food.v1` | fertig |
| E4 | Föderation: DNS-Discovery, Gossip, `monitor/` | als Nächstes |
| E5 | Trust-Level, Attestierungen, Sensor-Zertifikate | offen |
| E6 | Web-App und WASM-Verifier | offen |
| E7/E8 | Pfandsystem und Streitschlichtung | bewusst vertagt |

E7/E8 warten, bis mindestens zwei fremdbetriebene Nodes echte Daten führen. Erst dann lassen sich
Cap-Höhen und Zeitfenster an Messwerten kalibrieren statt zu raten. Der Kern ist bewusst so
gebaut, dass er nicht davon abhängt.

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [OWM-0](spec/owm-0-overview.md) | Protokollübersicht, Begriffe, Kennungen, Kryptoparameter, Discovery |
| [OWM-2](spec/owm-2-log.md) | Log, Merkle-Baum, Signed Tree Heads, Beweise, Löschpfad |
| [OWM-3](spec/owm-3-keys.md) | Schlüssel, Node-Identität, Verzeichnis, Rotation |
| [OWM-4](spec/owm-4-profiles.md) | Profilmechanismus und Lebensmittelprofil `food.v1` |
| [OWM-7](spec/owm-7-node-api.md) | Node-API: Einreichen, Lesen, Beweise, Verwaltung |
| [OWM-9](spec/owm-9-threat-model.md) | Angreifermodell, Grenzen des Systems |
| [CLAUDE.md](CLAUDE.md) | Konzeptdokument: Grundsatzentscheidungen mit Begründung, verworfene Ansätze |

Paketnahe Erläuterungen stehen in den README-Dateien der Verzeichnisse
([`node/`](node/README.md), [`profiles/`](profiles/README.md), [`demo/`](demo/README.md)) und in
den Kommentaren; die normative Fassung ist immer die Spezifikation.

## Sicherheit

Das [Angreifermodell](spec/owm-9-threat-model.md) beschreibt, wogegen OpenWaymark schützt und
wogegen ausdrücklich nicht. Die drei wichtigsten Grenzen:

1. **Das Orakel-Problem bleibt.** Wer bei der Ersterfassung lügt, wird durch keine Signatur
   ehrlich. Das Protokoll macht die Lüge zurechenbar und nachträglich unveränderbar dokumentiert —
   stichprobenartige physische Audits ersetzt es nicht.
2. **Ein Split View fällt nur auf, wenn jemand hinsieht.** Solange kein Monitor läuft, kann eine
   Node zwei Wahrheiten unterschreiben. Deshalb ist E4 die nächste Etappe.
3. **Die Verwaltungsschnittstelle ist ungeschützt.** Sie gehört nicht ins offene Netz.

**Sicherheitslücken bitte nicht als öffentliches Issue melden**, sondern vertraulich über die
private Sicherheitsmeldung des Repositorys (auf GitHub: Reiter *Security* → *Report a
vulnerability*). Bis eine Behebung vorliegt, bleiben Meldung und Berichterstatterin unerwähnt,
danach wird beides in den Release-Notes genannt, sofern gewünscht.

## Mitarbeiten

Beiträge sind willkommen — Fehlerberichte, Spezifikationskritik, Code, Profile für weitere
Branchen, Implementierungen in anderen Sprachen.

### Voraussetzungen

Go 1.25 oder neuer (CIRCL setzt das voraus). Weiter nichts.

### Vor jedem Beitrag lokal grün bekommen

```sh
go build ./...
test -z "$(gofmt -l .)"
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go test -race ./...
go run ./demo
```

Genau das prüft auch die Pipeline ([`.gitlab-ci.yml`](.gitlab-ci.yml)), zusätzlich zu einem kurzen
Fuzz-Lauf über die Deserialisierer. Die Deserialisierung ist die einzige Stelle, an der fremde
Bytes ins System kommen — wer daran etwas ändert, sollte den Fuzzer länger laufen lassen:

```sh
go test ./core/ -run '^$' -fuzz FuzzParseEntry -fuzztime 5m
```

### Was beim Ändern zu beachten ist

- **Spec zuerst.** Jede Änderung am Drahtformat, an Kennungen, an Domain-Trennern oder an der
  API ändert zuerst die Spezifikation unter `spec/` und dann den Code. Ein Format, das nur im Code
  steht, ist kein Protokoll.
- **Testvektoren nachziehen.** Ändert sich die Serialisierung, werden die goldenen Daten in
  `testdata/vectors` neu erzeugt: `go test ./core/ -update`. Der Diff gehört in denselben Commit
  und ist der eigentliche Prüfstein — er zeigt, ob die Änderung Altdaten unlesbar macht.
- **Nie Klartext-Personendaten ins Blatt.** Alles Personenbezogene lebt im Off-Chain-Blob. Diese
  Regel steht in der Spezifikation, nicht nur im Code.
- **Profilversionen sind unveränderlich.** Änderungen an `food.v1` sind keine Änderungen, sondern
  `food.v2`.
- **SPDX-Kopf in jede neue Datei**, passend zum Bereich (siehe [Lizenz](#lizenz)). Das Repository
  folgt der [REUSE-Spezifikation](https://reuse.software/); `REUSE.toml` regelt die Ausnahmen.
- **Keine Schlüssel, keine Betriebsdaten ins Repository.** `.gitignore` deckt die üblichen Fälle
  ab, das Nachdenken ersetzt es nicht.

### Sprache

| Wo | Sprache |
|---|---|
| Spezifikation, README-Dateien, Quelltextkommentare, Commit-Nachrichten | Deutsch |
| **Alle Programmausgaben und Fehlermeldungen** | **Englisch, Klartext** |

Programmausgabe heißt: Fehlertexte der Bibliotheken, `detail` der HTTP-Fehlerantworten, jede Zeile
von `owmnode` und der Vorführung. Klartext heißt: keine ANSI-Farben, keine Rahmen, keine Emoji,
keine typographischen Pfeile — die Ausgabe soll sich unverändert in eine Datei, ein Ticket oder
eine Mail kopieren lassen und in jedem Terminal gleich aussehen. Fehlertexte beginnen mit dem
Paketpräfix (`owm:`, `owm/log:`, `owm/node:`, `owm/profiles:`) und danach klein — so verlangt es
`staticcheck` (ST1005), und so lassen sie sich verschachteln.

Wer lieber auf Englisch beiträgt: gern. Deutsche Prosa ist der Ist-Zustand, keine Bedingung;
eine spätere Umstellung der Dokumentation auf Englisch ist ausdrücklich denkbar.

### Ablauf

1. Issue aufmachen, bevor größere Arbeit beginnt — besonders bei Protokolländerungen.
2. Branch von `main`, ein Thema pro Branch.
3. Commit-Betreff als knapper Aussagesatz auf Deutsch, im Rumpf das *Warum*, nicht das *Was*
   (das steht im Diff).
4. Merge/Pull Request mit grüner Pipeline.

## Releases und Versionierung

Zwei Dinge werden getrennt versioniert:

- **Das Protokoll** trägt die Version im Drahtformat und in den Domain-Trennern (`OWM/1`). Sie
  steigt nur, wenn sich das Format bricht.
- **Die Software** folgt [SemVer](https://semver.org/lang/de/). Solange die Hauptversion `0` ist,
  kann sich in jeder Minor-Version alles ändern — auch das Drahtformat.

Ein Release ist ein annotiertes Git-Tag `vX.Y.Z` auf `main` mit grüner Pipeline. Die Release-Notes
nennen in dieser Reihenfolge:

1. **Formatänderungen** — was an Einträgen, Blättern, STHs oder der API nicht mehr abwärtskompatibel
   ist, und was Betreiber vorhandener Logs tun müssen.
2. **Sicherheitsrelevantes**.
3. Alles Übrige.

Gebaut wird aus dem Tag:

```sh
git clone --branch v0.1.0 <url-dieses-repositorys> openwaymark
cd openwaymark
CGO_ENABLED=0 go build -trimpath -o owmnode ./node/cmd/owmnode
```

`owmnode version` gibt Commit und Go-Version aus, weil `go build` beides aus der
Versionskontrolle einbettet. Binaries für `linux/amd64` und `linux/arm64` werden an das Release
angehängt — ohne cgo, damit ein Raspberry Pi dieselbe Datei ausführt, die auch ein Server
ausführt.

Ein Release enthält immer die passenden Testvektoren. Fremdimplementierungen prüfen sich gegen
`testdata/vectors` genau dieses Tags.

## Lizenz

Geteilte Lizenzierung, damit Bibliotheken frei einbindbar bleiben und Serverbetreiber ihre
Änderungen zurückgeben:

| Bereich | Lizenz |
|---|---|
| `spec/`, `core/`, `log/`, `client/`, `profiles/`, `testdata/`, `demo/` | Apache-2.0 |
| `node/`, `monitor/` | AGPL-3.0-only |

Wer eine Node als Dienst betreibt, gibt seine Änderungen an das Netz zurück, in dem er sie
einsetzt. Wer nur `core/` oder `log/` in eigene Software einbindet — einen Client, einen Scanner,
eine Fremdimplementierung — bleibt davon unberührt.

Jede Datei trägt einen SPDX-Bezeichner; die vollständigen Lizenztexte liegen in
[`LICENSES/`](LICENSES/). Das Repository folgt der [REUSE-Spezifikation](https://reuse.software/).
