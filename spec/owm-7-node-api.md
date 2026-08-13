<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-7 — Node-API

**Stand:** Entwurf · **Voraussetzung:** [OWM-0](owm-0-overview.md), [OWM-2](owm-2-log.md),
[OWM-3](owm-3-keys.md) · **Angreifermodell:** [OWM-9](owm-9-threat-model.md)

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind wie in RFC 2119 zu verstehen.

## 1. Zweck

Wie eine Node über HTTP angesprochen wird: Einträge einreichen, Einträge und Nutzlasten lesen,
STHs und Beweise abholen, die Historie eines Subjekts abrufen, Profile und ihre Schemata
beziehen.

Die API überträgt, was OWM-0 und OWM-2 definieren; sie definiert nichts eigenständig
Sicherheitsrelevantes. **Alles, worauf es ankommt, ist bereits signiert, bevor es diese
Schnittstelle erreicht.** Ein Client, der die Signaturen selbst prüft, braucht der Node nichts zu
glauben — und genau darauf ist der Zuschnitt der Antworten ausgelegt.

**Was dieses Dokument nicht regelt:** wie Nodes einander finden und STHs austauschen (OWM-5), wie
Vertrauensgrade zustande kommen (OWM-6).

## 2. Zwei Schnittstellen

| | Präfix | Wer | Bindung |
|---|---|---|---|
| Öffentliche API | `/owm/v1`, `/.well-known/openwaymark` | die Welt | öffentlich, hinter TLS-Proxy |
| Verwaltung | `/admin/v1` | die Betreiberin | lokal, siehe §7 |

Die Trennung ist nicht nur organisatorisch. Eine Löschung nach Art. 17 DSGVO richtet sich an die
Verantwortliche, und die entscheidet darüber — nicht ein anonymer Aufruf von außen. Ebenso nimmt
niemand von außen Schlüssel ins Verzeichnis auf (OWM-3 §5.1). Beide Vorgänge liegen deshalb
hinter `/admin/v1` und nicht hinter einer Berechtigungsprüfung in der öffentlichen API.

Eine Node MUSS beide Schnittstellen an getrennte Adressen binden können. Sie SOLLTE die
öffentliche API hinter einem TLS-terminierenden Reverse-Proxy betreiben; TLS selbst zu
terminieren gehört nicht zu den Aufgaben einer Log-Software.

## 3. Konventionen

**Kodierung.** Alle Antworten sind `application/json; charset=utf-8`, ausgenommen Schemadateien
(`application/schema+json`). Bytefelder stehen

- **hexadezimal**, wo ein Mensch sie vergleichen können muss: Schlüssel, Kennungen, Salt,
  Wurzelhashes;
- **Base64** (Standardalphabet, mit Auffüllung), wo sie opak und groß sind: Eintrag, Blatt,
  Signatur, Nutzlast.

Zeitangaben sind Millisekunden seit der Unix-Epoche, UTC — dasselbe Format wie in Eintrag und
Blatt.

**Unbekannte Felder.** Ein Anfragekörper mit einem unbekannten Feld MUSS abgelehnt werden. Ein
vertipptes Feld ist sonst eine Angabe, die nicht wirkt, während der Einreicher glaubt, sie gesetzt
zu haben.

**Fehler.** Jede Fehlerantwort, auch die des Routers, ist JSON:

```json
{ "error": "rejected", "detail": "owm/profiles: payload does not match the schema: ..." }
```

| Status | `error` | Bedeutung |
|---|---|---|
| 400 | `malformed` | Die Anfrage war schon formal kaputt. |
| 403 | `not_admitted` | Der Aussteller gehört nicht zu dieser Node, oder sein Schlüssel ist stillgelegt. |
| 404 | `not_found` | Kein solcher Eintrag, Endpunkt, Schlüssel oder STH. |
| 405 | `method_not_allowed` | Der Pfad existiert, die Methode nicht. `Allow` nennt die erlaubten. |
| 409 | `conflict` | Widerspruch zum vorhandenen Zustand (z. B. Schlüsselkennung mit anderen Bytes). |
| 410 | `erased` | Die Nutzlast wurde gelöscht. Der Eintrag steht weiterhin im Log. |
| 413 | `too_large` | Nutzlast oder Blatt überschreiten die Grenze. |
| 422 | `rejected` | Die Anfrage war lesbar, der Eintrag wurde geprüft und abgelehnt. |
| 500 | `internal` | Fehler der Node. `detail` bleibt leer. |

Die Unterscheidung, auf die es ankommt: **400 heißt „unlesbar", 422 heißt „geprüft und
abgelehnt", 403 heißt „nicht zuständig".** Nur der mittlere Fall besagt etwas über den Inhalt.
`detail` MUSS bei 500 leer bleiben — interne Meldungen enthalten Pfade und Abfragen.

**410 statt 404 nach einer Löschung.** Eine gelöschte Nutzlast ist nicht dasselbe wie eine, die
es nie gab. 410 sagt: Der Eintrag steht im Baum, sein Beleg ist fort. Die Unterscheidung ist die
Voraussetzung dafür, dass ein Beobachter Löschung und Zurückhalten auseinanderhalten kann
(OWM-9 A3).

## 4. Endpunkte der öffentlichen API

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/.well-known/openwaymark` | Beschreibung der Node |
| POST | `/owm/v1/entries` | Eintrag einreichen |
| GET | `/owm/v1/entries/{entry_id}` | Blatt zu einer Eintragskennung |
| GET | `/owm/v1/entries/{entry_id}/payload` | Nutzlast **und Salt** |
| GET | `/owm/v1/leaves/{seq}` | Blatt zu einer Sequenznummer |
| GET | `/owm/v1/sth[?size=n]` | jüngster oder bestimmter STH |
| GET | `/owm/v1/proof/inclusion?…` | Inklusionsbeweis |
| GET | `/owm/v1/proof/consistency?old=…&new=…` | Konsistenzbeweis |
| GET | `/owm/v1/subjects/{subject_id}` | Historie eines Subjekts |
| GET | `/owm/v1/keys/{key_id}` | öffentlicher Schlüssel eines Ausstellers |
| GET | `/owm/v1/profiles` | geladene Profile |
| GET | `/owm/v1/schema?profile=…&file=…` | einzelne Schemadatei |

### 4.1 Beschreibung der Node

`GET /.well-known/openwaymark` ist der Einstiegspunkt der Föderation: Der DNS-TXT-Eintrag
(OWM-0 §7) verweist auf die Node, diese Antwort sagt, welches Log sie führt, womit sie
unterschreibt und wer für sie verantwortlich ist.

```json
{
  "protocol": "OWM/1",
  "log": "…64 Hexzeichen…",
  "base_url": "https://provenance.beispiel.de",
  "operator": { "name": "…", "contact": "…", "privacy": "…" },
  "key":         { "alg": "ML-DSA-65", "id": "…", "public": "…" },
  "genesis_key": { "alg": "ML-DSA-65", "id": "…", "public": "…" },
  "tree_size": 42,
  "profiles": [ … ],
  "max_payload": 262144,
  "max_leaf": 131072,
  "api": "/owm/v1"
}
```

`genesis_key` steht neben `key`, weil erst er die Log-Kennung nachrechenbar macht (OWM-2 §2,
OWM-3 §4). Nach einer Rotation sind beide verschieden, und ein Client, der nur `key` bekäme,
könnte `log` nicht mehr prüfen.

`operator` ist kein Beiwerk: Wer ein Auskunfts- oder Löschbegehren stellen will, muss erfahren
können, an wen. Eine Node SOLLTE `contact` setzen.

Der Pfad folgt RFC 8615. Die Antwort ist unbeglaubigt — sie beschreibt die Node, sie beweist
nichts. Was sie über den Schlüssel sagt, prüft ein Client, indem er einen STH damit verifiziert.

### 4.2 Eintrag einreichen

```
POST /owm/v1/entries
{
  "entry":   "…Base64 der kanonischen Bytes des signierten Eintrags…",
  "salt":    "…64 Hexzeichen…",
  "payload": "…Base64…"
}
```

Der signierte Eintrag wird als **Bytes** übertragen und von der Node unverändert weitergereicht.
Er DARF NICHT als JSON-Objekt entgegengenommen und serverseitig neu kodiert werden: Die Signatur
gilt für genau diese Bytes, und jede Neukodierung wäre eine Gelegenheit, sie zu verlieren
(OWM-0 §6.3).

`salt` und `payload` entfallen bei einem Eintrag ohne `cmt`. Sonst gilt:

- Eintrag mit `cmt`, aber ohne `payload` → 422. Die Node könnte das Commitment nicht prüfen und
  hätte nichts, worauf es sich bezieht.
- `payload` ohne `cmt` im Eintrag → 422. Die Nutzlast wäre an nichts gebunden.
- `salt` ≠ 32 Byte bei vorhandener `payload` → 400.

**Prüfreihenfolge** — von billig nach teuer, von struktureller nach inhaltlicher Aussage:

1. Eintragstyp: `erasure` wird von außen nicht angenommen (§4.3).
2. Nutzlastgröße gegen `max_payload`.
3. Profil und Schema (OWM-4).
4. Signatur und Aussteller gegen das Schlüsselverzeichnis (OWM-3 §5).
5. Commitment gegen Nutzlast.

Was hier durchkommt, ist wohlgeformt und zurechenbar. **Ob es wahr ist, sagt keine dieser
Prüfungen** — das kann keine Software (OWM-9, Orakelproblem).

Antwort `201 Created`:

```json
{
  "log": "…", "entry_id": "…", "seq": 5,
  "logged_at": 1786000000000,
  "leaf": "…Base64 des Blatts…"
}
```

Das vollständige Blatt kommt zurück, nicht nur seine Sequenznummer: Der Einreicher kann daraus
den Blatthash selbst rechnen und den Inklusionsbeweis anfordern, sobald der nächste STH steht.

### 4.3 Was die öffentliche API nicht annimmt

Eine Node MUSS `erasure`-Einträge von außen ablehnen (403). Eine Löschbezeugung ist eine Tatsache
über den Speicher **dieser** Node (OWM-0 §6.1); sie von außen anzunehmen hieße, jemanden
behaupten zu lassen, hier sei etwas gelöscht worden. Erzeugt wird sie ausschließlich über §7.3.

Ein `key_rotation`-Eintrag wird dagegen angenommen — die Aufnahme des Nachfolgers geschieht
dann durch die Node selbst, nach den Regeln aus OWM-3 §6, und erst **nach** dem Anhängen: Nur
was im Log steht, ist nachvollziehbar begründet.

### 4.4 Blatt lesen

`GET /owm/v1/entries/{entry_id}` und `GET /owm/v1/leaves/{seq}` liefern dieselbe Struktur:

```json
{
  "log": "…", "seq": 5, "logged_at": 1786000000000, "entry_id": "…",
  "leaf":  "…Base64…",
  "entry": "…Base64…",
  "payload_status": "present",
  "decoded": { "v": 1, "typ": "assertion", "prof": "food.v1", "subj": "…", … }
}
```

`decoded` ist **ausdrücklich kein Beweis**, sondern Bequemlichkeit. Verbindlich sind allein die
Bytes in `entry`, gegen die die Signatur geprüft wird. Wer `decoded` glaubt statt den Bytes,
glaubt dem Server — und hat sich damit genau die Eigenschaft weggenommen, für die es das Log
gibt. Eine Implementierung, die `decoded` zur Grundlage einer Prüfung macht, ist nicht konform.

`payload_status` ist `present`, `erased` oder `absent`.

### 4.5 Nutzlast lesen

```
GET /owm/v1/entries/{entry_id}/payload
→ { "entry_id": "…", "salt": "…Hex…", "payload": "…Base64…" }
```

Die Antwort MUSS **Salt und Nutzlast zusammen** liefern. Ohne den Salt ließe sich das Commitment
nicht nachrechnen, und die Nutzlast wäre nur das, was der Server gerade behauptet. Wer beides
hat, prüft `Commitment == HMAC-SHA-256(salt, label ‖ payload)` gegen das `cmt` im signierten
Eintrag — das ist der ganze Zweck des Endpunkts.

Nach einer Löschung: `410 erased`. Salt und Nutzlast sind fort, und zwar beide (OWM-2 §7.1).

### 4.6 STH

`GET /owm/v1/sth` liefert den jüngsten, `?size=n` den zu einer bestimmten Baumgröße.

```json
{ "signed": { … CBOR-Umschlag, Base64 … }, "decoded": { "v":1, "log":"…", "size":6, "ts":…, "root":"…", "key":"…" } }
```

Auch hier ist `decoded` nur Lesehilfe; geprüft wird über `signed`. Ein Client MUSS die Signatur
gegen einen Schlüssel prüfen, den er unabhängig kennt oder über die Rotationskette bis zum
Gründungsschlüssel zurückverfolgt hat.

Eine Node MUSS alte STHs abrufbar halten, solange sie sie vorhält. Ein Beobachter braucht sie,
um überhaupt vergleichen zu können; ohne Zugriff auf frühere Signaturen ist Split-View-Erkennung
gegenstandslos (OWM-2 §9, §10).

### 4.7 Beweise

```
GET /owm/v1/proof/inclusion?entry=<entry_id>[&size=n]
GET /owm/v1/proof/inclusion?seq=<i>[&size=n]
GET /owm/v1/proof/consistency?old=<n₁>[&new=<n₂>]
```

**Fehlt `size` bzw. `new`, gilt die Größe des zuletzt ausgestellten STH — nicht die aktuelle
Baumgröße.** Das ist die wichtigste Festlegung dieses Abschnitts: Ein Beweis gegen eine Größe, zu
der es keine Unterschrift gibt, ist gegen nichts prüfbar. Der Client müsste dem Server glauben,
und genau das soll er nicht müssen. Erst wenn das Log noch keinen STH ausgestellt hat, fällt die
Voreinstellung auf die aktuelle Baumgröße zurück.

Beweise sind **nicht signiert** und brauchen deshalb kein kanonisches Format (OWM-2 §5.3). Ihre
Integrität ergibt sich vollständig daraus, dass sie gegen einen signierten Wurzelhash aufgehen
oder eben nicht. Ein Prüfer MUSS jeden Inklusionsbeweis gegen den Wurzelhash eines konkreten STH
rechnen und dabei prüfen, dass `size` die Baumgröße dieses STH ist.

Ein Inklusionsbeweis bleibt nach der Löschung der Nutzlast gültig — der Baum wurde nicht
angefasst. Diese Eigenschaft ist prüfbar und SOLLTE geprüft werden.

### 4.8 Historie eines Subjekts

`GET /owm/v1/subjects/{subject_id}?limit=&offset=` liefert alle Blätter dieser Node zu einem
Subjekt, nach Sequenznummer aufsteigend.

```json
{ "subject": "…", "log": "…", "total": 3, "offset": 0, "entries": [ … Blätter wie §4.4 … ] }
```

`limit` ist standardmäßig 200 und höchstens 1000. Ein Subjekt kann tausende Messreihen tragen;
eine Antwort, die alles auf einmal liefert, wäre für den Abruf per Telefon unbrauchbar.

**Die Antwort ist die Sicht *einer* Node, nicht die Lieferkette.** Vorgängereinträge in `par`
können in fremden Logs liegen; der Verweis nennt dann eine andere `log_id` (OWM-0 §6.2), und der
Client folgt ihr selbst. Eine Node, die fremde Ketten mitliefert, würde für Aussagen einstehen,
die nicht ihre sind — das föderierte Modell sieht das nicht vor.

### 4.9 Schlüssel eines Ausstellers

`GET /owm/v1/keys/{key_id}` liefert den öffentlichen Schlüssel zu einer Ausstellerkennung.

```json
{ "key_id": "…", "alg": "ML-DSA-65", "public": "…hex…", "added_at": 1786000000000,
  "disabled_at": null, "parent": null }
```

Ohne diesen Endpunkt wäre Schritt 2 der Mindestprüfung (§5) für einen fremden Client
undurchführbar: Ein Eintrag nennt in `iss` nur die Kennung, und die ist der Hash des Schlüssels —
aus ihr lässt sich der Schlüssel nicht zurückgewinnen.

Ein Client MUSS die Kennung aus den gelieferten Bytes selbst nachrechnen (OWM-3 §3). Erst das
macht die Auskunft unabhängig davon, ob die Node die Wahrheit sagt: Eine Node, die zu einer
Kennung andere Bytes liefert, ist damit überführt und nicht bloß verdächtig.

Ein **stillgelegter** Schlüssel wird weiterhin herausgegeben, mit gesetztem `disabled_at`. Was er
früher unterschrieben hat, bleibt prüfbar; würde die Auskunft ihn verschweigen, wäre nach der
ersten Stilllegung jeder ältere Eintrag dieses Ausstellers unprüfbar. Ob ein Schlüssel *heute*
noch einreichen darf, ist eine andere Frage und wird beim Einreichen beantwortet (§4.2).

Nachgeschlagen wird **einzeln und nur über die Kennung**. Eine Auflistung aller Schlüssel gibt es
öffentlich nicht: Sie wäre das Teilnehmerverzeichnis der Node und damit die Antwort auf eine
Frage, die niemand gestellt hat. Wer hier nachschlägt, hat die Kennung aus einem Eintrag, den er
ohnehin schon vor sich hat.

Das Etikett aus dem Verzeichnis (OWM-3 §5) wird **nicht** ausgeliefert. Es ist Freitext der
Betreiberin und trägt in der Praxis oft einen Personennamen; die öffentliche API ist kein Ort, an
dem so etwas nebenbei erscheint.

### 4.10 Profile und Schemata

`GET /owm/v1/profiles` nennt jedes geladene Profil mit `id`, `title`, `schema_digest` und der
Liste seiner Dateien. `GET /owm/v1/schema?profile=…&file=…` liefert eine davon.

Profil und Datei stehen in der **Abfrage** und nicht im Pfad, weil eine Profilkennung selbst
Schrägstriche enthalten darf (`eu/battery.v1`) — im Pfad wäre nicht mehr zu erkennen, wo die
Kennung endet.

Der `schema_digest` macht nachprüfbar, gegen welche Regeln die Node prüft (OWM-4 §3). Zwei Nodes,
die dasselbe Profil nennen, aber verschiedene Digests melden, prüfen verschieden — und das gehört
sichtbar gemacht.

## 5. Was ein Client prüfen muss

Ein Client, der einer Antwort dieser API vertraut, ohne selbst zu rechnen, hat den gesamten
Beweiswert des Systems weggegeben. Die Mindestprüfung:

1. `entry` neu kodieren und mit den empfangenen Bytes vergleichen (Kanonizität, OWM-0 §6.4).
2. Signatur des Eintrags gegen den öffentlichen Schlüssel des Ausstellers prüfen (§4.9) und
   dessen Kennung aus den Schlüsselbytes selbst nachrechnen.
3. `cmt` gegen `salt ‖ payload` nachrechnen.
4. Blatthash aus `leaf` bilden, Inklusionsbeweis gegen den Wurzelhash **eines STH** rechnen.
5. STH-Signatur gegen einen Schlüssel prüfen, der über die Rotationskette am Gründungsschlüssel
   hängt, und `log` gegen die erwartete Log-Kennung.
6. Bei wiederholtem Abruf: Konsistenzbeweis zwischen dem früher gesehenen und dem jetzigen STH.

Schritt 6 ist der, den man am ehesten weglässt und am wenigsten weglassen sollte. Ohne ihn merkt
ein Client nicht, dass die Node ihre Historie umgeschrieben hat; mit ihm merkt er es beim
nächsten Abruf. Und selbst dann gilt: **Ein einzelner Beobachter kann einen Split-View
prinzipiell nicht erkennen** (OWM-2 §9). Dafür braucht es OWM-5.

## 6. Grenzen und Missbrauch

| Grenze | Wert | Wirkung bei Überschreitung |
|---|---|---|
| Blatt | 128 KiB | 413 |
| Nutzlast | konfigurierbar, voreingestellt 256 KiB | 413 |
| Anfragekörper | 2 × (Blatt + Nutzlast) | 413 |
| Historie je Antwort | 1000 Einträge | stillschweigend gekappt |

Eine Nutzlast ist ein Datensatz, kein Dateianhang: Fotos, Laborberichte und Zeugnisse gehören
hinter eine URL, deren Hash in der Nutzlast steht.

Das Anhängen kostet eine Signaturprüfung und einen Schreibvorgang; das Ausstellen eines STH
kostet eine ML-DSA-Signatur. Eine öffentlich erreichbare Node SOLLTE das Einreichen
mengenmäßig begrenzen. Das Protokoll sieht dafür bewusst keinen Mechanismus vor — Ratenbegrenzung
gehört in den Reverse-Proxy, wo sie hingehört, und ein selbstgebauter Ersatz im Anwendungscode
wäre schwächer.

Lesende Endpunkte sind ungeschützt und sollen es sein. Was sie ausliefern, ist der Zweck des
Logs.

## 7. Verwaltungsschnittstelle

| Methode | Pfad | Zweck |
|---|---|---|
| GET | `/admin/v1/keys` | Verzeichnis auflisten |
| POST | `/admin/v1/keys` | Schlüssel aufnehmen |
| GET | `/admin/v1/keys/{key_id}` | einzelnen Eintrag lesen |
| POST | `/admin/v1/keys/{key_id}/disable` | Schlüssel stilllegen |
| POST | `/admin/v1/erasures` | Nutzlast löschen |
| POST | `/admin/v1/sth` | STH sofort ausstellen |

### 7.1 Keine Authentifizierung — mit Absicht

Die Verwaltungsschnittstelle kennt kein Anmeldeverfahren. Das ist eine Entscheidung, keine
Auslassung: Zugangsschutz gehört hier in die Umgebung — eine lokal gebundene Adresse, ein
Unix-Socket hinter einem Reverse-Proxy, ein VPN. Ein selbstgestricktes Token-Verfahren im
Anwendungscode wäre schwächer als das, was Betriebssystem und ausgewachsener Proxy ohnehin
können, und würde vortäuschen, die Frage sei geklärt.

Daraus folgt eine harte Anforderung: **Eine Node MUSS die Verwaltungsschnittstelle
standardmäßig an eine lokale Adresse binden und DARF sie NICHT ungeschützt ins offene Netz
stellen.** Wer sie erreicht, kann Schlüssel aufnehmen und Nutzlasten löschen.

### 7.2 Schlüssel

`POST /admin/v1/keys` nimmt `{ "alg": "ML-DSA-65", "public": "…Hex…", "label": "…", "parent": "…" }`.
Algorithmus und Schlüssellänge werden gegeneinander geprüft: Eine Länge, die nicht zum genannten
Verfahren passt, wird abgelehnt, statt sie zu erraten. Die Wiederaufnahme desselben Schlüssels ist
kein Fehler; dieselbe Kennung mit anderen Bytes ist einer (409). Die Regeln stehen in OWM-3 §5.

Stilllegen wirkt nur vorwärts. Altsignaturen bleiben gültig — die Begründung in OWM-3 §5.2.

### 7.3 Löschen

`POST /admin/v1/erasures` mit `{ "entry_id": "…" }` löscht Nutzlast und Salt unwiederbringlich
und hängt die Löschbezeugung an. Die Antwort enthält den Grabstein als Blatt, damit die
Betreiberin belegen kann, dass und wann gelöscht wurde.

Der Vorgang ist endgültig und **erfolgreich auch dann, wenn er sich nicht rückgängig machen
lässt** — das ist sein Zweck. Was bleibt, ist das Blatt im Baum; alle je ausgestellten STHs und
Inklusionsbeweise gelten weiter (OWM-2 §7).

Die Löschung eines `key_rotation`-Eintrags MUSS abgelehnt werden (OWM-2 §7.6).

### 7.4 STH ausstellen

`POST /admin/v1/sth` stellt sofort einen aus, unabhängig vom eingestellten Abstand. Nützlich für
Tests und dafür, den Zustand vor einer Wartung zu bezeugen.

Eine Node SOLLTE STHs in festem Abstand auch dann ausstellen, wenn nichts angehängt wurde. Der
Abstand ist die Obergrenze dafür, wie lange eine Manipulation unbemerkt bleiben kann — was nicht
unterschrieben wurde, kann ein Beobachter nicht festnageln. Ein schweigendes Log ist von einem
angehaltenen sonst nicht zu unterscheiden (OWM-9 A3).

## 8. Sicherheitsbetrachtung

| Angriff | Wirkung | Gegenmittel |
|---|---|---|
| Node liefert falsche `decoded`-Sicht | Client sieht etwas anderes als das Signierte | verbindlich sind nur die Bytes (§4.4, §5) |
| Node liefert Beweis gegen unsignierte Größe | Beweis gegen nichts | Voreinstellung ist die STH-Größe (§4.7) |
| Node liefert Nutzlast ohne Salt | Commitment nicht nachrechenbar | Salt gehört in dieselbe Antwort (§4.5) |
| Node hält Eintrag zurück | Einreichung verschwindet | derzeit nur bemerkbar, nicht beweisbar (§9) |
| Node zeigt zwei Historien | Split-View | nicht clientseitig lösbar, siehe OWM-5 |
| Verwaltung erreichbar aus dem Netz | fremde Schlüssel, fremde Löschungen | lokale Bindung (§7.1) |
| Massenhaftes Einreichen | Log läuft voll, Signaturlast | Grenzen §6, Ratenbegrenzung im Proxy |

## 9. Offene Punkte

- **Quittungen beim Anhängen**, analog zum SCT in Certificate Transparency. Heute quittiert die
  Node mit dem fertigen Blatt, aber ohne eigene Unterschrift auf der Zusage, es aufzunehmen. Ein
  Einreicher kann deshalb *bemerken*, dass sein Eintrag fehlt, aber nicht *beweisen*, dass die
  Node ihn angenommen hatte. Erst eine signierte Quittung mit Fristzusage macht das Zurückhalten
  beweisbar (OWM-2 §9, letzte Zeile).
- Aufbewahrungsfristen für STHs (OWM-2 §10) — sie bestimmen, wie weit zurück ein Monitor
  überhaupt vergleichen kann.
- Sammelabruf mehrerer Blätter in einer Antwort, für Monitore, die ein ganzes Log durchgehen.
- Bedingter Abruf (`ETag`, `If-None-Match`) für STHs, damit häufiges Nachfragen billig wird.
