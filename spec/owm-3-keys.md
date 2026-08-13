<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-3 — Schlüssel, Node-Identität, Verzeichnis und Rotation

**Stand:** Entwurf · **Voraussetzung:** [OWM-0](owm-0-overview.md), [OWM-2](owm-2-log.md) ·
**Angreifermodell:** [OWM-9](owm-9-threat-model.md)

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind wie in RFC 2119 zu verstehen.

## 1. Zweck und Abgrenzung

Dieses Dokument beantwortet vier Fragen:

1. Welche Schlüssel gibt es und wie werden sie bezeichnet?
2. Woraus besteht die Identität einer Node und wie liegt sie auf der Platte?
3. Wessen Einträge nimmt eine Node an — und wer entscheidet das?
4. Wie wechselt ein Schlüssel, ohne die bisherigen Aussagen zu entwerten?

**Was dieses Dokument nicht regelt:** wie eine Entität einen Vertrauensgrad erlangt (OWM-6),
wie Schlüssel zwischen Nodes bekannt werden (OWM-5), wie das Verzeichnis über HTTP bedient
wird (OWM-7).

## 2. Verfahren

Ausschließlich Post-Quantum-Signaturen nach FIPS 204 (ML-DSA). Kein RSA, kein ECC, kein
Hybridmodell — die Begründung steht in OWM-0 §5.

| Verfahren | `alg` | Öff. Schlüssel | Signatur | Vorgesehen für |
|---|---|---|---|---|
| ML-DSA-44 | 1 | 1312 B | 2420 B | Sensoren, Masseneinträge |
| ML-DSA-65 | 2 | 1952 B | 3309 B | Node- und Entitätsschlüssel |

Die Wahl ist keine Sicherheitsabstufung, sondern eine Größenabwägung: 889 Byte Unterschied je
Eintrag entscheiden bei einer Node, die stündlich Messreihen aufnimmt, über Jahre den
Speicherbedarf. Eine Node MUSS beide Verfahren prüfen können. Eine Node SOLLTE ihren eigenen
Schlüssel als ML-DSA-65 führen.

Signaturen sind randomisiert (`Sign`, nicht `SignDeterministic`) — ausgenommen die Testvektoren,
die deterministisch erzeugt werden, damit sie überhaupt vergleichbar sind.

## 3. Schlüsselkennung

```
KeyID = H("OWM/1 key-id", u16be(alg), pubkey)
```

32 Byte. `H` ist die längenpräfixierte Hashfunktion aus OWM-0 §4.1; das Verfahren geht mit ein,
damit derselbe Bytestring unter zwei Verfahren nicht dieselbe Kennung erhielte.

Die Kennung ist **selbstzertifizierend**: Wer den öffentlichen Schlüssel hat, rechnet sie nach,
ohne ein Verzeichnis zu befragen. Ein Verzeichnis, das zu einer Kennung einen Schlüssel mit
anderen Bytes ausliefert, ist damit nicht nur unzuverlässig, sondern nachweisbar falsch — eine
Node MUSS diesen Fall als Fehler behandeln und DARF den Schlüssel NICHT verwenden.

## 4. Node-Identität

Eine Node führt **zwei** Schlüsselrollen, und sie auseinanderzuhalten ist der Kern dieses
Abschnitts:

| Rolle | Wechselt | Wofür |
|---|---|---|
| Gründungsschlüssel | nie | Ableitung der LogID (OWM-2 §2) |
| Signierschlüssel | darf und soll | STHs, Löschbezeugungen |

Bei einer neuen Node sind beide derselbe. Nach der ersten Rotation sind sie es nicht mehr, und
die LogID bleibt trotzdem, was sie war. Wäre die LogID an den jeweils aktuellen Schlüssel
gebunden, entwertete jede Rotation sämtliche je ausgestellten Verweise auf dieses Log — QR-Codes
auf Verpackungen eingeschlossen, die niemand mehr einsammeln kann.

### 4.1 Identitätsdatei

Die Identität liegt als JSON-Datei vor:

```json
{
  "alg": "ML-DSA-65",
  "seed": "…64 Hexzeichen…",
  "genesis_public": "…3904 Hexzeichen…",
  "created": "2026-08-11T06:12:00Z",
  "_note": "Diese Datei IST der private Schlüssel der Node. …"
}
```

Gespeichert wird der **Saatwert**, nicht das ausgepackte Schlüsselpaar: FIPS 204 leitet das Paar
deterministisch daraus ab, und 32 Byte Hex sind notierbar, auf Papier sicherbar und im Fehlerfall
von Hand prüfbar. Ein ausgepackter ML-DSA-65-Privatschlüssel ist 4032 Byte und nichts davon.

Anforderungen:

- Die Datei MUSS mit Rechten `0600` angelegt werden, das Verzeichnis mit `0700`.
- Eine Implementierung MUSS das Laden verweigern, wenn Gruppe oder Andere Rechte an der Datei
  haben. Eine weltlesbare Identitätsdatei ist ein stiller Totalverlust: Die Node signiert weiter,
  jeder andere aber auch.
- Eine bestehende Identitätsdatei DARF NICHT überschrieben werden. Der Schreibvorgang MUSS
  `O_EXCL` verwenden.
- `genesis_public` ist redundant, solange nicht rotiert wurde, und wird nach der ersten Rotation
  zur einzigen Quelle der LogID. Weicht der aus dem Saatwert abgeleitete öffentliche Schlüssel
  von `genesis_public` ab, MUSS das Laden fehlschlagen.

### 4.2 Verlust und Kompromittierung

| Fall | Folge |
|---|---|
| Signierschlüssel verloren, Gründungsschlüssel vorhanden | Rotation, Log läuft weiter |
| Gründungsschlüssel verloren, Log vorhanden | LogID nicht mehr nachrechenbar; das Log bleibt lesbar und prüfbar, weil die Rotationskette darin steht |
| Identitätsdatei kompromittiert | Der Angreifer kann STHs zu **beliebigen** Wurzeln ausstellen. Kein interner Mechanismus hilft. |

Der letzte Fall ist A3 aus dem Angreifermodell. Wirksam ist dagegen allein, dass ein Monitor
zwei widersprüchliche STHs derselben Größe sieht (OWM-2 §6.3) — die Node kann ihre Unterschrift
nicht zurückziehen. Deshalb: Die Datei gehört nicht in ein Repository, nicht in ein
ungeschütztes Backup und, wo verfügbar, in ein Hardware-Sicherheitselement statt auf die Platte.

## 5. Schlüsselverzeichnis

Das Verzeichnis einer Node beantwortet genau eine Frage: **Wessen Einträge nimmt diese Node an?**

Es ist damit die Einlasskontrolle des Logs. Vor dem Anhängen MUSS eine Node den öffentlichen
Schlüssel des Ausstellers im eigenen Verzeichnis nachschlagen und den Eintrag abweisen, wenn er
fehlt oder stillgelegt ist. Ein Log ohne diese Prüfung nähme von jedem alles an und wäre als
Herkunftsnachweis wertlos.

Jeder Verzeichniseintrag hält:

| Feld | Bedeutung |
|---|---|
| `key_id` | Kennung nach §3, Primärschlüssel |
| `alg`, `public` | Verfahren und öffentlicher Schlüssel |
| `label` | freier Text der Betreiberin, kein Protokollbestandteil |
| `added_at` | Aufnahmezeit |
| `disabled_at` | Stilllegungszeit, falls stillgelegt |
| `parent` | Vorgängerschlüssel, falls durch Rotation aufgenommen (§6) |

### 5.1 Aufnahme

Aufnehmen darf allein die Betreiberin über die Verwaltungsschnittstelle (OWM-7 §7) — oder das
Protokoll selbst über eine Rotation (§6). Das folgt aus dem föderierten Modell: Eine Node ist
autoritativ für ihre eigenen Teilnehmer und für sonst niemanden. Wer hier nicht steht, hat eine
andere Node.

Die Aufnahme ist **wiederholbar**: Dieselbe Kennung mit denselben Bytes erneut aufzunehmen ist
kein Fehler. Dieselbe Kennung mit **anderen** Bytes ist einer, und zwar ein grundlegender — es
wäre eine SHA-256-Kollision. Eine Implementierung MUSS das melden und DARF den vorhandenen
Schlüssel NICHT ersetzen.

Ein stillgelegter Schlüssel wird durch erneute Aufnahme **nicht** wieder scharf geschaltet. Das
Wiederinbetriebnehmen ist ein eigener, ausdrücklicher Schritt.

### 5.2 Stilllegung

Stilllegen heißt: **keine neuen** Einträge mehr von diesem Schlüssel. Was er früher signiert hat,
bleibt gültig.

Das ist keine Nachlässigkeit, sondern die Bedingung dafür, dass das Log ein Transparenzlog ist.
Ein Log, das rückwirkend Aussagen entwertet, weil ein Schlüssel später stillgelegt wurde,
beantwortete die Frage "war diese Signatur zum Zeitpunkt X gültig?" nicht mehr — und genau diese
Frage ist der einzige Grund, ein Log zu führen. Wer eine **inhaltliche** Aussage zurücknehmen
will, widerruft sie mit einem `revocation`-Eintrag (OWM-0 §3); wer eine Nutzlast loswerden muss,
löscht sie (OWM-2 §7). Beides sind Einträge im Log, keine Löcher darin.

Die Node MUSS ihren **eigenen** Schlüssel im Verzeichnis führen. Sie signiert damit
Löschbezeugungen, und die laufen durch dieselbe Einlasskontrolle wie jeder fremde Eintrag.

### 5.3 Auskunft nach außen

Eine Node MUSS zu einer Kennung den zugehörigen öffentlichen Schlüssel herausgeben
(OWM-7 §4.9). Ohne diese Auskunft könnte ein fremder Client keine einzige Signatur prüfen: Der
Eintrag nennt in `iss` nur die Kennung, und aus ihr ist der Schlüssel nicht zurückzugewinnen.

Herausgegeben werden `alg`, `public`, `added_at`, `disabled_at` und `parent` — **nicht** das
`label`. Das Etikett ist Freitext der Betreiberin und trägt in der Praxis oft einen
Personennamen; es hat in einer öffentlichen Auskunft nichts zu suchen.

Die Auskunft gilt auch für **stillgelegte** Schlüssel, mit gesetztem `disabled_at`. Sonst wäre
alles, was ein Schlüssel vor seiner Stilllegung unterschrieben hat, nicht mehr prüfbar — und
damit wäre §5.2 hinfällig.

Nachgeschlagen wird einzeln über die Kennung. Eine Node MUSS ihr Verzeichnis nicht öffentlich
auflisten und SOLLTE es nicht tun: Die Liste wäre ihr Teilnehmerverzeichnis, und wer eine
Signatur prüfen will, hat die Kennung ohnehin aus dem Eintrag vor sich.

## 6. Rotation

Ein Schlüsselwechsel ist ein Eintrag im Log, kein Vorgang daneben.

```
typ  = key_rotation
subj = KeyID des Nachfolgers
iss  = KeyID des Vorgängers
cmt  = Commitment über die Nutzlast
```

Nutzlast:

```json
{
  "alg": "ML-DSA-65",
  "public": "…Hex des öffentlichen Nachfolgeschlüssels…",
  "label": "Hof Sonnenblick (2027)"
}
```

Regeln:

- Der Eintrag MUSS vom **Vorgänger** signiert sein. Damit ist die Rotation, was sie sein soll:
  eine Aussage des bisherigen Inhabers, im Log festgehalten. Ein Schlüssel, der sich selbst
  ankündigt, ist keine Rotation, sondern eine Neuanmeldung — und die geht über §5.1.
- `subj` MUSS die Kennung des angekündigten Nachfolgers sein. Ohne diese Bindung stünde im Log
  eine Rotation zu Schlüssel A, während die Nutzlast Schlüssel B nennt — und **nach einer
  Löschung der Nutzlast** wäre nicht mehr feststellbar, welcher gemeint war. Die Bindung ist
  genau deshalb Pflicht: Sie ist der Teil der Aussage, der die Löschung überlebt.
- Aussteller und Subjekt MÜSSEN verschieden sein.
- Eine Node MUSS die angekündigte Länge gegen das genannte Verfahren prüfen, statt sie zu erraten.
- Die Node nimmt den Nachfolger mit `parent = iss` ins Verzeichnis auf.

### 6.1 Überlappende Gültigkeit

Der Vorgänger wird durch die Rotation **nicht** stillgelegt.

Beide Schlüssel gelten eine Zeit lang nebeneinander. Sonst bräche jede Rotation den laufenden
Betrieb: Ein Sensor im Kühllaster, der die Ankündigung noch nicht gesehen hat, signiert weiter
mit dem alten Schlüssel, und seine Messreihe fiele aus der Kühlkette heraus — wegen eines
Verwaltungsvorgangs, der mit der Ware nichts zu tun hat. Das Stilllegen des Vorgängers ist ein
eigener, späterer Schritt der Betreiberin (§5.2).

Wie lang die Überlappung sein SOLLTE, hängt davon ab, wie lange ein Gerät im Feld offline sein
kann. Für Sensoren in Transportketten sind Wochen realistisch, nicht Stunden.

### 6.2 Was Rotation nicht leistet

Rotation ist **kein** Widerruf. Wurde ein Schlüssel kompromittiert, sind alle mit ihm signierten
Einträge weiterhin gültig signiert — auch die, die der Angreifer erzeugt hat. Was hilft:

1. Vorgänger stilllegen (§5.2), damit keine neuen dazukommen.
2. Die betroffenen Aussagen einzeln widerrufen (`revocation`, OWM-0 §3).
3. Den Zeitraum benennen, ab dem der Schlüssel als kompromittiert gilt.

Punkt 3 ist der schwierige: Das Log bezeugt, **wann** eine Node einen Eintrag aufgenommen hat
(OWM-2 §3.1), nicht wann ein Schlüssel abhandenkam. Wer den Zeitpunkt später behauptet, als er
war, verschont eigene Einträge; wer ihn früher behauptet, entwertet fremde. Das Protokoll kann
das nicht auflösen — es ist derselbe Grenzfall wie das Orakelproblem (OWM-9), nur auf der
Schlüsselebene.

## 7. Sensorschlüssel

Ein Sensor erhält bei Inbetriebnahme ein eigenes Schlüsselpaar, wo verfügbar in einem
Hardware-Sicherheitselement. Der **Node-Betreiber** nimmt es ins Verzeichnis auf und bindet es
damit an die eigene Identität; es gibt keine zentrale Stelle, die Sensoren zertifiziert.

Der Vertrauensgrad eines Sensors ist nach oben durch den seines Betreibers begrenzt. Die
Einzelheiten dazu — Berechnung, Vererbung, Minimum-Prinzip über die Kette — stehen in OWM-6.

Ein Sensorschlüssel SOLLTE ML-DSA-44 sein (§2) und ausschließlich `sensor_reading`-Einträge
signieren. Eine Node KANN das erzwingen; das Profil kann es verlangen (OWM-4 §5).

## 8. Sicherheitsbetrachtung

| Angriff | Wirkung | Gegenmittel |
|---|---|---|
| Fremder Schlüssel reicht Einträge ein | keine | Verzeichnis weist ab (§5) |
| Kennung zeigt auf andere Bytes | Schlüsselverwechslung | selbstzertifizierende Kennung (§3) |
| Rotation durch den Nachfolger selbst | Übernahme einer Identität | nur der Vorgänger darf ankündigen (§6) |
| Rotation ohne Subjektbindung | Ziel nach Löschung unbestimmbar | `subj` = KeyID des Nachfolgers (§6) |
| Identitätsdatei entwendet | beliebige STHs, Split-View | Dateirechte, HSM; Erkennung nur extern (OWM-9 A3) |
| Stilllegung als Rückdatierung missbraucht | Altaussagen entwertet | Stilllegung wirkt nur vorwärts (§5.2) |
