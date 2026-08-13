<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-0 — Protokollübersicht

**Status:** Entwurf · **Formatversion:** 1 · **Stand:** 2026-08-10

Dieses Dokument beschreibt die Grundbegriffe, die Kryptoparameter und das Drahtformat der
Einträge. Es ist die normative Referenz für `core/`. Die Testvektoren unter
[`testdata/vectors/`](../testdata/vectors/) sind Teil dieser Spezifikation: eine
Fremdimplementierung gilt als konform, wenn sie die dortigen Vektoren Byte für Byte
reproduziert.

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind im Sinne von RFC 2119 zu lesen.

## 1. Begriffe

| Begriff | Bedeutung |
|---|---|
| **Node** | Server, der ein Log führt und für seine eigenen Daten autoritativ ist. |
| **Entität** | Teilnehmer mit Schlüsselpaar — Betrieb, Behörde, Prüfstelle, Person. |
| **Subjekt** | Das Ding, über das geredet wird: Charge, Einzelstück, Container, Gerät. |
| **Eintrag** (Entry) | Eine signierte Aussage einer Entität über ein Subjekt. |
| **Nutzlast** (Payload) | Die eigentlichen Daten zum Eintrag. Liegen **off-chain**, nicht im Log. |
| **Commitment** | Gesalzener Hash der Nutzlast. Nur er steht im Log. |
| **Log** | Append-only Merkle-Baum einer Node über ihre Einträge. |
| **STH** | Signed Tree Head — signierter Snapshot des Logzustands. |
| **Monitor** | Unabhängige Software, die STHs sammelt und auf Widersprüche prüft. |
| **Profil** | Branchenschema, das Struktur und Pflichtfelder der Nutzlast festlegt. |

Ein Eintrag sagt also im Kern: *Diese Entität behauptet zu diesem Zeitpunkt etwas über dieses
Subjekt, und das Behauptete ist genau die Nutzlast mit diesem Commitment.*

## 2. Warum die Nutzlast nicht ins Log gehört

Das Log ist append-only und wird über STHs nach außen bezeugt. Was einmal drinsteht, kann nicht
mehr entfernt werden, ohne alle je ausgegebenen STHs zu brechen. Personenbezogene Daten dürfen
darum niemals im Log stehen — sonst ist die DSGVO-Löschung technisch unmöglich.

Das Log enthält deshalb ausschließlich das Commitment. Die Nutzlast und der zugehörige Salt
liegen in einem separaten Blob-Speicher derselben Node. Eine Löschung entfernt Blob und Salt;
der Baum bleibt unverändert, alle Beweise bleiben gültig, und das Commitment ist ohne Salt kein
Weg mehr zurück zur Nutzlast.

> **Harte Regel.** Ein Eintrag DARF NICHT Klartext-Personendaten enthalten. Das gilt für jedes
> Feld, insbesondere für die Subjekt-ID: Sie ist ein opaker Bezeichner, kein Name, keine
> Anschrift, keine Koordinate.

Ein bloßer Hash der Nutzlast würde dafür nicht genügen. Bei kleinem Wertebereich — eine
Postleitzahl, eine GPS-Koordinate auf drei Nachkommastellen, ein Name aus einer bekannten Liste —
lässt sich der Klartext durch Durchprobieren zurückrechnen. Der Salt macht diesen Angriff
unmöglich, und weil er mitgelöscht wird, ist die Löschung endgültig.

## 3. Kryptoparameter

Ausschließlich Post-Quantum-Verfahren. Kein RSA, kein ECC, kein Hybridmodell.

| Zweck | Verfahren | Parameter |
|---|---|---|
| Signaturen, Node- und Entitätsschlüssel | ML-DSA-65 (FIPS 204) | Pubkey 1952 B, Signatur 3309 B |
| Signaturen, Sensoren und Masseneinträge | ML-DSA-44 (FIPS 204) | Pubkey 1312 B, Signatur 2420 B |
| Schlüsselkapselung (ab Etappe E5) | ML-KEM-768 (FIPS 203) | — |
| Hash, Commitment, Merkle-Baum | SHA-256 | 32 B |
| Serialisierung | CBOR, Core Deterministic (RFC 8949 §4.2.1) | — |

### 3.1 Warum SHA-256 trotz Post-Quantum-Anspruch

SHA-256 bietet 128 Bit Kollisionsresistenz. Der beste bekannte Quantenangriff auf
Kollisionsresistenz (Brassard–Høyer–Tapp) benötigt Quantenspeicher in einer Größenordnung, die
den Angriff gegenüber klassischen Verfahren nicht praktisch überlegen macht; Grover halbiert
die Urbildsicherheit auf weiterhin ausreichende 128 Bit. SHA-256 ist damit
post-quantum-angemessen — und hält gleichzeitig die Kompatibilität zu RFC 6962, dessen
Baumkonstruktion und Referenzimplementierung OpenWaymark übernimmt.

### 3.2 Warum zwei Signaturstufen

ML-DSA-65 kostet 3309 Byte pro Signatur. Eine Million Einträge sind rund 3,3 GB allein an
Signaturen — auf Hardware der Raspberry-Pi-Klasse, die laut Konzept ausdrücklich unterstützt
werden soll, ist das keine Nebensächlichkeit. ML-DSA-44 (2420 B) ist für Sensormesswerte und
Masseneinträge vorgesehen, deren Einzelwert gering und deren Anzahl hoch ist. Die zweite
Gegenmaßnahme, Bündelung über einen Zwischen-Merkle-Baum beim Aussteller, wird in
[OWM-2 §8](owm-2-log.md#8-batch-signierung) behandelt.

### 3.3 Domänentrennung

Jede Hashberechnung und jede Signatur wird gegen eine Bezeichnung gebunden, damit ein Wert aus
einem Kontext niemals in einem anderen gültig ist.

Für Hashes gilt:

```
H(label, p₁ … pₙ) = SHA-256( u8(len(label)) ‖ label ‖ u64be(len(p₁)) ‖ p₁ ‖ … ‖ u64be(len(pₙ)) ‖ pₙ )
```

`u8` ist ein Byte, `u64be` eine 64-Bit-Ganzzahl in Big-Endian-Reihenfolge. Die
Längenpräfixe machen die Eingabe präfixfrei: keine zwei verschiedenen Argumentlisten erzeugen
denselben Hashinput.

| Bezeichnung | Verwendung |
|---|---|
| `OWM/1 key-id` | Schlüsselkennung aus Algorithmus und öffentlichem Schlüssel |
| `OWM/1 entry-id` | Inhaltsadresse eines Eintrags |
| `OWM/1 subject-id` | Ableitung einer Subjekt-ID aus Namensraum und Wert |
| `OWM/1 commit` | Nutzlast-Commitment |

Signaturen nutzen den Kontextstring aus FIPS 204 (`ctx`) statt eines Präfixes im
Nachrichtentext:

| Kontext | Verwendung |
|---|---|
| `OWM/1 entry` | Signatur über einen Eintrag |
| `OWM/1 sth` | Signatur über einen Signed Tree Head (OWM-2) |

## 4. Kennungen

### 4.1 Schlüsselkennung

```
KeyID = H("OWM/1 key-id", u16be(alg), pubkey)
```

32 Byte. Der Algorithmus geht mit ein, damit derselbe Bytestring unter zwei Verfahren nicht
dieselbe Kennung ergibt.

### 4.2 Subjekt-ID

32 Byte, opak. Sie KANN frei gewählt (zufällig) oder abgeleitet werden:

```
SubjectID = H("OWM/1 subject-id", namespace, value)
```

`namespace` benennt das Kennzeichnungssystem, etwa `gs1:sgtin` oder `owm:batch`; `value` ist der
Bezeichner darin. Die Ableitung ist bequem, aber **keine Vertraulichkeitsmaßnahme**: Wer den
Namensraum und einen kleinen Wertebereich kennt, kann die ID durchprobieren. Wo das
Verknüpfbarkeit erzeugen würde, ist eine zufällige Subjekt-ID zu wählen.

### 4.3 Eintragskennung

```
EntryID = H("OWM/1 entry-id", canonical_cbor(Entry))
```

Die Kennung deckt den Eintrag ab, **nicht** die Signatur. Damit bleibt sie stabil, wenn derselbe
Eintrag erneut oder von mehreren Parteien signiert wird — ML-DSA signiert standardmäßig
randomisiert, eine signaturabhängige Kennung wäre nicht reproduzierbar. Dass ein Blatt im Log
nicht von seiner Signatur getrennt werden kann, stellt die Blattberechnung in OWM-2 sicher, die
über den vollständigen signierten Eintrag geht.

## 5. Nutzlast-Commitment

```
Salt        = 32 zufällige Byte aus einem kryptographischen Zufallsgenerator
Commitment  = HMAC-SHA-256( key = Salt, msg = u8(len("OWM/1 commit")) ‖ "OWM/1 commit" ‖ payload )
```

Jede Nutzlast MUSS einen eigenen, frisch gezogenen Salt bekommen. Ein wiederverwendeter Salt
erlaubt es, gleiche Nutzlasten über Einträge hinweg zu erkennen, und überlebt die Löschung des
einen Eintrags im anderen.

Eigenschaften: **bindend**, weil eine zweite Nutzlast mit gleichem Commitment eine
SHA-256-Kollision erfordert. **Verbergend**, weil ohne den Salt jede Nutzlast gleich plausibel
ist — auch bei einem Wertebereich von wenigen Möglichkeiten.

## 6. Eintragsformat

Ein Eintrag ist eine CBOR-Map mit Ganzzahlschlüsseln, kodiert nach RFC 8949 §4.2.1
(Core Deterministic Encoding).

| Schlüssel | Name | Typ | Pflicht | Bedeutung |
|---|---|---|---|---|
| 1 | `v` | uint | ja | Formatversion, derzeit `1` |
| 2 | `typ` | uint | ja | Eintragstyp, siehe 6.1 |
| 3 | `prof` | tstr | nein | Profilkennung, z. B. `food.v1` (OWM-4 §2) |
| 4 | `subj` | bstr(32) | ja | Subjekt-ID |
| 5 | `iat` | int | ja | Ausstellungszeit, Millisekunden seit Unix-Epoche, UTC |
| 6 | `iss` | bstr(32) | ja | Schlüsselkennung des Ausstellers |
| 7 | `cmt` | bstr(32) | nein | Nutzlast-Commitment |
| 8 | `par` | array | nein | Vorgängereinträge, siehe 6.2 |
| 9 | `tgt` | array | nein | Zieleintrag, nur bei `revocation` und `erasure` |

Optionale Felder werden bei Abwesenheit **weggelassen**. Sie DÜRFEN NICHT als `null` oder als
leerer Wert kodiert werden — sonst gäbe es zwei Kodierungen desselben Eintrags und damit zwei
Inhaltsadressen.

### 6.1 Eintragstypen

| Wert | Typ | Bedeutung |
|---|---|---|
| 1 | `assertion` | Selbstauskunft über ein Subjekt: Erzeugung, Transport, Verarbeitung, Übergabe. |
| 2 | `attestation` | Aussage über eine andere Entität oder einen Schlüssel, etwa eine Zertifizierung. Das Subjekt ist hier die Schlüsselkennung des Bestätigten. |
| 3 | `revocation` | Widerruf eines früheren Eintrags. `tgt` benennt ihn. |
| 4 | `key_rotation` | Ankündigung eines Nachfolgeschlüssels, siehe OWM-3. Die Nutzlast enthält den neuen öffentlichen Schlüssel und ist nicht löschbar. |
| 5 | `sensor_reading` | Automatisch erfasster Messwert, ausgestellt von einem Geräteschlüssel. |
| 6 | `erasure` | Bezeugung, dass Nutzlast und Salt eines früheren Eintrags gelöscht wurden. `tgt` benennt ihn. Siehe OWM-2 §7. |

`revocation` und `erasure` sind ausdrücklich verschiedene Dinge und DÜRFEN NICHT vermischt
werden. Ein Widerruf ist eine **Behauptung über die Welt** — die Aussage war falsch oder gilt
nicht mehr. Eine Löschbezeugung ist eine **Tatsache über den Speicher** — die Aussage steht
weiterhin, aber ihr Beleg ist fort und lässt sich nicht mehr prüfen.

Die Trennung ist nicht kosmetisch. Fielen beide zusammen, würde jede Löschung nach Artikel 17
DSGVO wie ein Eingeständnis aussehen, die Aussage sei falsch gewesen — ein Betroffener, der
sein Recht wahrnimmt, würde damit unfreiwillig den Ruf seines Lieferkettenpartners beschädigen.
Umgekehrt könnte eine Node einen Beleg zurückhalten und das als Löschung ausgeben. Ein Beobachter
muss beides unterscheiden können (OWM-9 A3).

Beide Typen tragen **kein** `cmt`: sie haben keine eigene Nutzlast. Wer einen Grund angeben will,
verweist über `par` auf einen `assertion`-Eintrag, der ihn trägt — Löschgründe sind selbst
oft personenbezogen und gehören deshalb nicht ins Log, sondern hinter ein Commitment.

### 6.2 Eintragsverweis

Ein Verweis ist ein CBOR-Array fester Länge 2:

```
[ entry_id : bstr(32), log_id : bstr(0) | bstr(32) ]
```

`log_id` benennt das Log, in dem der Eintrag zu finden ist, und ist ein Hinweis für den Abruf —
kein Bestandteil der Identität. Ist es unbekannt, steht dort ein leerer Bytestring. Die feste
Arraylänge vermeidet zwei zulässige Kodierungen desselben Verweises.

`par` bildet die Lieferkette als gerichteten azyklischen Graphen ab. Mehrere Vorgänger
bedeuten Zusammenführung — drei Höfe liefern Milch für einen Käselaib. Mehrere Einträge mit
demselben Vorgänger bedeuten Aufteilung — eine Charge wird in Packungen zerlegt. Die
Ereignissemantik darauf legt das jeweilige Profil fest (OWM-4, angelehnt an GS1 EPCIS 2.0).

### 6.3 Signierter Eintrag

```
{ 1: e   : bstr,   ; kanonische CBOR-Kodierung des Eintrags, als Bytestring eingebettet
  2: alg : uint,   ; Signaturalgorithmus
  3: sig : bstr }  ; Signatur über e mit Kontext "OWM/1 entry"
```

Der Eintrag wird als **opaker Bytestring** eingebettet, nicht als verschachtelte Map. Damit
signiert und prüft jede Seite exakt dieselben Bytes; eine erneute Kodierung, die abweichen
könnte, findet nie statt. Die Lehre stammt aus JWS und COSE, wo genau diese Mehrdeutigkeit zu
Sicherheitslücken geführt hat.

| `alg` | Verfahren |
|---|---|
| 1 | ML-DSA-44 |
| 2 | ML-DSA-65 |

Die Signatur geht über den Inhalt von `e`, mit dem FIPS-204-Kontextstring `OWM/1 entry`.

### 6.4 Kanonizität beim Dekodieren

Ein Empfänger MUSS eine Kodierung ablehnen, die nicht kanonisch ist. Die Prüfung ist
mechanisch: dekodieren, neu kodieren, Bytes vergleichen. Ohne sie gäbe es zu einem Eintrag
mehrere gültige Bytefolgen und damit mehrere Inhaltsadressen — und ein Angreifer könnte eine
gültige Signatur an einen abweichend kodierten Eintrag heften.

Ebenfalls abzulehnen: doppelte Map-Schlüssel, Kodierungen unbestimmter Länge und unbekannte
Map-Schlüssel innerhalb des Eintrags.

## 7. Föderation, in einem Absatz

Nodes werden über DNS gefunden:

```
_openwaymark.beispiel.de.  IN TXT  "v=owm1; node=https://provenance.beispiel.de"
```

Das Label ist `_openwaymark`, nicht das generische `_provenance`, und soll später nach RFC 8552
bei der IANA registriert werden. Teilnehmer ohne eigene Domain werden über eine schlanke
Fallback-Registry an eine Community-Node verwiesen; die Registry hält selbst keine Produktdaten.

Nodes tauschen STHs gezielt mit ihren tatsächlichen Lieferkettenpartnern aus und zusätzlich mit
unabhängigen Monitoren. Warum beides nötig ist und was es abwehrt, steht im
[Angreifermodell](owm-9-threat-model.md). Die Einzelheiten folgen in OWM-2 und OWM-5.

## 8. Versionierung

Das Feld `v` benennt die Formatversion des Eintrags. Neue Pflichtfelder oder geänderte
Bedeutungen erhöhen sie. Solange die Version 1 als Entwurf gilt, kann sich das Format ohne
Migrationspfad ändern.

## 9. Weitere Dokumente

| Dokument | Inhalt | Stand |
|---|---|---|
| OWM-0 | Diese Übersicht | Entwurf |
| OWM-1 | Kern-Datenmodell im Detail | in OWM-0 enthalten |
| OWM-2 | [Log, Merkle-Baum, STH, Beweise, Löschpfad](owm-2-log.md) | Entwurf |
| OWM-3 | [Schlüssel, Node-Identität, Verzeichnis und Rotation](owm-3-keys.md) | Entwurf |
| OWM-4 | [Profilmechanismus und Lebensmittelprofil](owm-4-profiles.md) | Entwurf |
| OWM-5 | Föderation, Discovery, Gossip | geplant |
| OWM-6 | Trust-Level und Attestierung | geplant |
| OWM-7 | [Node-API](owm-7-node-api.md) | Entwurf |
| OWM-9 | [Angreifermodell](owm-9-threat-model.md) | Entwurf |
