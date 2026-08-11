<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-2 — Log, Merkle-Baum, Signed Tree Heads, Beweise, Löschpfad

**Stand:** Entwurf · **Voraussetzung:** [OWM-0](owm-0-overview.md) · **Angreifermodell:**
[OWM-9](owm-9-threat-model.md)

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind wie in RFC 2119 zu verstehen.

## 1. Zweck und Abgrenzung

Jede Node führt genau ein append-only Log ihrer Einträge. Das Log ist **lokal**: Es gibt keinen
globalen Zustand, auf den sich alle Nodes einigen müssten, und keinen Konsensmechanismus. Die
Manipulationssicherheit entsteht nicht daraus, dass viele Parteien dieselben Daten halten, sondern
daraus, dass eine Node ihre eigene Historie nicht unbemerkt umschreiben kann, sobald sie sie
gegenüber mehr als einem Beobachter bezeugt hat.

Die Baumkonstruktion ist die aus **RFC 6962** (Certificate Transparency) unverändert übernommene.
Abweichungen gäbe es nur um den Preis, die Referenzimplementierung und zwei Jahrzehnte Analyse
aufzugeben; OpenWaymark weicht deshalb nur dort ab, wo es einen Grund gibt — und der eine Grund
ist die Löschbarkeit (§7), die CT nicht kennt, weil CT nie löscht.

**Was dieses Dokument nicht regelt:** Wie Beweise über HTTP übertragen werden (OWM-4), wie
Nachfolgeschlüssel autorisiert werden (OWM-3), wie STHs zwischen Nodes ausgetauscht werden
(OWM-5). Dieses Dokument definiert die Datenstrukturen und die Regeln, nach denen sie geprüft
werden.

## 2. Log-Identität

```
LogID = H("OWM/1 log-id", u16be(alg), genesis_pubkey)
```

32 Byte, abgeleitet vom **Gründungsschlüssel** des Logs, nicht vom jeweils aktuellen. Ein
mitwechselnder Bezeichner würde bei jeder Schlüsselrotation sämtliche je ausgestellten Verweise
auf dieses Log entwerten. Der Gründungsschlüssel wechselt nie.

Die Ableitung macht die Kennung selbstzertifizierend: Wer den Gründungsschlüssel hat, rechnet sie
nach, ohne ein Verzeichnis zu befragen. Welche **Nachfolge**schlüssel für dieses Log signieren
dürfen, beantwortet die Rotationskette im Log selbst (OWM-3) — nicht die Kennung.

## 3. Blatt

Ein Blatt ist eine CBOR-Map mit Ganzzahlschlüsseln, kodiert nach RFC 8949 §4.2.1 (Core
Deterministic), wie in OWM-0 §6.

| Schlüssel | Name | Typ | Pflicht | Bedeutung |
|---|---|---|---|---|
| 1 | `v` | uint | ja | Formatversion, derzeit `1` |
| 2 | `log` | bstr(32) | ja | LogID, siehe §2 |
| 3 | `seq` | uint | ja | Blattindex, beginnend bei 0 |
| 4 | `ts` | int | ja | Aufnahmezeit, Millisekunden seit Unix-Epoche, UTC |
| 5 | `ent` | bstr | ja | kanonische Kodierung des signierten Eintrags (OWM-0 §6.3) |

Ein Blatt MUSS ≤ 128 KiB sein. Der signierte Eintrag steht als **opaker Bytestring** darin und
wird zur Blattbildung nicht neu kodiert — dieselbe Regel und derselbe Grund wie in OWM-0 §6.3.

### 3.1 Warum das Blatt mehr enthält als den Eintrag

**`ent` und nicht nur die Eintragskennung.** Die Eintragskennung deckt die Signatur nicht ab
(OWM-0 §4.3, damit sie unter randomisiertem ML-DSA stabil bleibt). Stünde nur sie im Blatt, wäre
die Signatur nicht Teil des Baums: Eine Node könnte nachträglich eine andere gültige Signatur
desselben Ausstellers unterschieben, oder die Signatur ganz verlieren, ohne dass ein
Inklusionsbeweis das bemerkt. Der Baum MUSS den Eintrag **samt Signatur** binden.

**`seq` und `ts`.** Der Zeitpunkt in `ent` ist die Behauptung des Ausstellers, wann er die Aussage
gemacht hat. `ts` ist die Bezeugung der Node, wann sie sie aufgenommen hat. Die beiden dürfen
auseinanderfallen, und dass sie es dürfen, ist der Punkt: Ein rückdatierter Eintrag lässt sich an
seinem Aufnahmezeitpunkt erkennen. Zusammen mit `seq` und `log` ist ein Blatt eine
nicht abstreitbare Aussage der Node über sich selbst — *dies ist Eintrag Nummer N in Log L,
aufgenommen zum Zeitpunkt T*.

**`log`.** Ohne die Log-Kennung wäre ein Blatt zwischen Logs verschiebbar. Die Kennung kostet
32 Byte und macht jedes Blatt für sich zuordenbar, auch ohne den zugehörigen STH.

Der Preis dieser Entscheidungen: Zwei identische Einträge ergeben zwei verschiedene Blätter, und
das Blatt lässt sich erst nach Vergabe der Sequenznummer bilden. Beides ist gewollt.

### 3.2 Blatthash

```
LeafHash = SHA-256( 0x00 ‖ leaf_bytes )
MTH(l,r) = SHA-256( 0x01 ‖ l ‖ r )
```

Unverändert RFC 6962 §2.1. Die Präfixe `0x00` und `0x01` trennen Blätter von inneren Knoten und
verhindern damit die sicherheitskritische Verwechslung der beiden; das ist eine **andere**
Domänentrennung als die aus OWM-0 §3.3 und ersetzt sie hier bewusst, weil die Kompatibilität zur
CT-Baumkonstruktion höher wiegt. Eine Verwechslung mit CT-Blättern ist ausgeschlossen, weil
`leaf_bytes` in OpenWaymark stets eine CBOR-Map mit den Feldern aus §3 ist.

Der Hash des leeren Baums ist `SHA-256("")`, ebenfalls nach RFC 6962.

## 4. Signed Tree Head

| Schlüssel | Name | Typ | Pflicht | Bedeutung |
|---|---|---|---|---|
| 1 | `v` | uint | ja | Formatversion, derzeit `1` |
| 2 | `log` | bstr(32) | ja | LogID |
| 3 | `size` | uint | ja | Baumgröße, Anzahl Blätter |
| 4 | `ts` | int | ja | Ausstellungszeit, Millisekunden seit Unix-Epoche, UTC |
| 5 | `root` | bstr(32) | ja | Wurzelhash über `size` Blätter |
| 6 | `key` | bstr(32) | ja | Schlüsselkennung des Unterzeichners |

Signiert wird mit dem Kontext `OWM/1 sth` (OWM-0 §3.3). Der Umschlag hat dieselbe Gestalt wie der
signierte Eintrag:

```
SignedSTH = { 1: sth : bstr, 2: alg : uint, 3: sig : bstr }
```

`key` steht **innerhalb** der signierten Struktur und nicht im Umschlag. Sonst ließe sich die
Angabe, welcher Schlüssel unterschrieben hat, unbemerkt austauschen — was gerade während einer
Schlüsselrotation die Frage unbeantwortbar machte, ob der Unterzeichner autorisiert war.

Ein STH über den leeren Baum (`size = 0`) ist gültig und dient als Gründungsbezeugung.

Eine Node SOLLTE STHs in festen Abständen ausstellen, auch wenn nichts angehängt wurde. Ein
schweigendes Log ist von einem angehaltenen Log sonst nicht zu unterscheiden (OWM-9 A3).

## 5. Beweise

### 5.1 Inklusionsbeweis

Belegt, dass ein bestimmtes Blatt an Position `i` in einem Baum der Größe `n` enthalten ist.
Bestandteile: `i`, `n`, der Blatthash und ein Pfad aus ⌈log₂(n)⌉ Knotenhashes. Für eine Million
Blätter sind das 20 Knoten, also 640 Byte — vernachlässigbar neben den 3309 Byte der
ML-DSA-65-Signatur im Blatt selbst.

Ein Prüfer MUSS ihn gegen den Wurzelhash **eines konkreten STH** rechnen und dabei prüfen, dass
`n` die Baumgröße dieses STH ist. Ein Inklusionsbeweis für sich allein sagt nichts aus — er
rechnet nur eine Wurzel aus, und der Angreifer könnte sie mitgeliefert haben.

### 5.2 Konsistenzbeweis

Belegt, dass ein Baum der Größe `n₁` ein Präfix eines Baums der Größe `n₂ ≥ n₁` ist: dass also
zwischen beiden nur angehängt und nichts geändert oder entfernt wurde. Das ist die eigentliche
Zusage des Logs.

### 5.3 Beweise werden nicht signiert

Und brauchen deshalb **kein kanonisches Format**. Ihre Integrität ergibt sich vollständig daraus,
dass sie gegen einen signierten Wurzelhash aufgehen oder eben nicht. Ein manipulierter Beweis
schlägt fehl; ein Beweis in abweichender Kodierung, der aufgeht, ist ein gültiger Beweis.
Die Übertragung regelt OWM-4.

## 6. Anhängen

1. Die Node prüft den signierten Eintrag: Kanonizität, Signatur, Aussteller, Struktur (OWM-0 §6.4).
2. Sie vergibt `seq = aktuelle Baumgröße` und setzt `ts` auf die aktuelle Zeit.
3. Sie bildet das Blatt, berechnet seinen Hash und hängt ihn an den Baum an.
4. Beim nächsten STH ist der Eintrag abgedeckt.

Ein Eintrag KANN mehrfach angehängt werden und ergibt dann mehrere Blätter mit derselben
Eintragskennung. Das Log DARF Duplikate ablehnen, MUSS aber nicht — die Eintragskennung bleibt
für die Zuordnung maßgeblich.

## 7. Löschpfad

Der Teil, den Certificate Transparency nicht hat und nicht braucht.

### 7.1 Was gelöscht wird

**Nutzlast und Salt.** Beide liegen off-chain bei der Node, die sie hält, nie im Log.

**Nicht gelöscht** werden Blatt, Eintrag, Signatur und Baum. Das Log bleibt Byte für Byte, wie es
war.

### 7.2 Ablauf

1. Nutzlast und Salt werden unwiederbringlich gelöscht.
2. Die Node hängt einen `erasure`-Eintrag an (OWM-0 §6.1), signiert mit ihrem eigenen Schlüssel,
   dessen `tgt` den betroffenen Eintrag benennt.
3. Der nächste STH deckt ihn ab.

### 7.3 Warum das trägt

Der Baum bleibt unverändert. Daraus folgt unmittelbar:

- **Alle je ausgestellten STHs bleiben gültig.** Kein Beobachter muss etwas neu bewerten.
- **Alle Inklusionsbeweise bleiben gültig**, auch der des gelöschten Eintrags.
- **Alle Konsistenzbeweise bleiben gültig.** Eine Löschung ist von außen ein gewöhnliches Anhängen.

Und die Nutzlast ist trotzdem weg. Das Commitment ist `HMAC-SHA-256(salt, label ‖ payload)` mit
einem 256-Bit-Salt (OWM-0 §5). Ohne den Salt ist der Wert über den Schlüsselraum gleichverteilt:
Selbst wenn der gesamte Wertebereich aus zwei Möglichkeiten besteht — „bio" oder „nicht bio" —
lässt sich nicht sagen, welche es war. Ein ungesalzener Hash würde hier sofort brechen; das ist
der Grund, warum OpenWaymark salzt und CT nicht.

### 7.4 Was bleibt und was das bedeutet

Nach der Löschung stehen weiterhin dauerhaft im Log: Subjekt-ID, Schlüsselkennung des Ausstellers,
Ausstellungs- und Aufnahmezeit, Profilkennung, Eintragstyp und die Vorgängerverweise. Das ist
Verkehrsdatum und lässt sich nicht entfernen, ohne den Baum zu brechen.

Daraus folgt die harte Regel aus OWM-0 §6, hier wiederholt, weil sie hier ihre Konsequenz hat:

> Kein Feld eines Eintrags DARF Klartext-Personendaten enthalten. Auch die Subjekt-ID nicht — sie
> ist ein opaker Bezeichner und kein Name, keine Anschrift, keine Koordinate.

Wer ableitbare Subjekt-IDs verwendet (OWM-0 §4.2), macht sie durchprobierbar. Wo Verknüpfbarkeit
schadet, MUSS die Subjekt-ID zufällig sein. Verkettung über Verkehrsdaten bleibt möglich und ist
in OWM-9 A9 als hingenommenes Restrisiko geführt.

### 7.5 Grenze im föderierten Netz

Eine Löschung wirkt dort, wo die Daten liegen. Wurde die Nutzlast im Rahmen der Lieferkette an
Partner weitergegeben, erreicht die Löschung deren Kopien **nicht**. Der `erasure`-Eintrag ist für
sie ein Signal, keine Durchsetzung; ob sie folgen, ist eine rechtliche und keine technische Frage.

Das ist keine Eigenheit von OpenWaymark, sondern die Lage in jedem verteilten System, und es wird
hier ausdrücklich festgehalten, statt es zu verschweigen. Die technische Gegenmaßnahme ist
Datensparsamkeit vor der Weitergabe, nicht Löschung danach.

### 7.6 Was nicht löschbar ist

`key_rotation`-Einträge. Ihre Nutzlast ist der Nachfolgeschlüssel; ohne sie ist die Rotationskette
unterbrochen und alle späteren Signaturen sind nicht mehr zuzuordnen. Ein öffentlicher Schlüssel
ist zudem kein personenbezogenes Datum in dem Sinn, dass er durch etwas anderes ersetzt werden
könnte. Eine Node MUSS die Löschung eines `key_rotation`-Eintrags ablehnen.

### 7.7 Grenze im Speicher

Das Protokoll kann garantieren, dass der Baum eine Löschung überlebt. Ob die Bytes tatsächlich vom
Datenträger verschwinden, entscheidet die Betreiberin, nicht das Protokoll.

Eine Node MUSS ihren Nutzlastspeicher so betreiben, dass gelöschte Daten überschrieben und nicht
nur als frei markiert werden — bei SQLite bedeutet das `PRAGMA secure_delete=ON`, bei einem
Dateispeicher das Überschreiben vor dem Entfernen des Verzeichniseintrags. Nicht erreichbar bleiben
damit: Sicherungen, Dateisystem-Snapshots, Journal-/WAL-Dateien früherer Sitzungen und die
Blockremanenz von SSDs.

Für diese Kopien gibt es keine technische Lösung im Log, sondern nur eine Aufbewahrungsfrist: Eine
Node SOLLTE Sicherungen so kurz vorhalten, dass eine Löschung sie innerhalb der zugesagten Frist
einholt, und die Frist veröffentlichen. Wer 90 Tage Sicherungen hält, löscht faktisch mit 90 Tagen
Verzögerung; das ist vertretbar, aber es ist eine Zusage, die eine Node machen muss, und keine, die
das Protokoll für sie machen kann.

## 8. Batch-Signierung

Der Plan führt die Größe von PQ-Signaturen als offenen Punkt: Eine Million Einträge sind rund
3,3 GB allein an ML-DSA-65-Signaturen. Hier die Auflösung.

**Für die Signatur des Logs ist Batch-Signierung bereits das Entwurfsprinzip.** Die Node signiert
STHs, nicht einzelne Blätter. Ein STH deckt beliebig viele Einträge ab, der einzelne Eintrag ist
über seinen Inklusionsbeweis erfasst. Bei stündlichen STHs kostet ein Jahr Logbetrieb rund
29 MB an Node-Signaturen, unabhängig von der Zahl der Einträge. Hier ist nichts hinzuzufügen.

**Die 3,3 GB sind Aussteller-Signaturen, und die lassen sich nicht wegbündeln.** Jeder Eintrag muss
seinem Aussteller einzeln zurechenbar sein, und die Aussteller sind verschiedene Parteien, die
keinen gemeinsamen Batch unterschreiben können. Es bleiben zwei Hebel:

1. **ML-DSA-44 für Sensoren und Masseneinträge** (OWM-0 §3.2): 2420 statt 3309 Byte, rund 27 %
   weniger. Vorgesehen und umgesetzt.
2. **Bündelung beim Aussteller.** Wer viele gleichartige Messwerte erzeugt, baut aus ihnen selbst
   einen Merkle-Baum, legt dessen Wurzel in **eine** Nutzlast und schreibt **einen** Eintrag mit
   **einer** Signatur. Der einzelne Messwert wird über einen Inklusionsbeweis in diesem Unterbaum
   belegt, der off-chain neben der Nutzlast liegt. Aus 8640 Messwerten eines Tagesintervalls wird
   so ein Eintrag statt 8640.

Der zweite Hebel ist der wirksame, und er gehört **nicht in das Log**, sondern in die Profilebene:
Ob und wie gebündelt wird, hängt daran, was gemessen wird und wie fein es einzeln belegbar sein
muss. Das Log sieht in beiden Fällen nur einen Eintrag. Ausgeführt wird das im Lebensmittelprofil
(OWM-4).

## 9. Erkennung von Fehlverhalten

Das Log kann sich nicht selbst überwachen. Was es liefert, sind die Primitive, mit denen ein
unabhängiger Beobachter (OWM-5, `monitor/`) Fehlverhalten **beweisen** kann.

| Beobachtung | Bedeutung |
|---|---|
| Zwei STHs, gleiches Log, gleiche `size`, verschiedene `root` | Split-View. Beweis. |
| Zwei STHs, `size₁ < size₂`, Konsistenzbeweis geht nicht auf | Historie geändert. Beweis. |
| STH mit `size₂ < size₁` bei späterem `ts` | Baum geschrumpft. Beweis. |
| Eintrag ist nicht im Baum, obwohl quittiert | Zurückhalten. Erst mit Quittung beweisbar. |

Die ersten drei sind **nicht abstreitbar**: Die Node hat beide Aussagen selbst unterschrieben. Es
braucht keine Mehrheit, keine Abstimmung und keine vertrauenswürdige dritte Instanz, um sie zu
werten — nur zwei Beobachter, die ihre Sicht vergleichen.

Und genau das ist die Bedingung: **Ein einzelner Beobachter kann einen Split-View prinzipiell
nicht erkennen.** Beide Historien sind in sich stimmig und korrekt signiert. Ohne Austausch
zwischen Beobachtern ist der Angriff offen, und mit ihm die nachträgliche Änderung des Logs. Die
Erkennung ist zudem nachträglich: Sie verhindert den Angriff nicht, sie macht ihn nachweisbar und
damit teuer. Siehe OWM-9 A1 und A2.

## 10. Offene Punkte

- Aufbewahrungsfristen für STHs: Ein Beobachter braucht alte STHs, um überhaupt vergleichen zu
  können. Wie lange eine Node sie vorhalten MUSS, ist noch nicht festgelegt.
- Quittungen beim Anhängen (analog zum SCT in CT), damit das Zurückhalten eines Eintrags beweisbar
  wird und nicht nur behauptbar. Gehört zur Node-API, OWM-4.
- Verhalten bei Erreichen der Blattgrenze von 128 KiB durch sehr breite Aggregationen
  (`par` bis MaxParents = 1024).
