<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-4 — Profilmechanismus und Lebensmittelprofil `food.v1`

**Stand:** Entwurf · **Voraussetzung:** [OWM-0](owm-0-overview.md) · **Angreifermodell:**
[OWM-9](owm-9-threat-model.md)

Die Schlüsselwörter MUSS, DARF NICHT, SOLLTE und KANN sind wie in RFC 2119 zu verstehen.

## 1. Zweck

**Der Kern kennt keine Branchensemantik.** Ein Eintrag trägt eine Profilkennung wie `food.v1`;
was ein `processing`-Ereignis bedeutet und welche Felder es braucht, legt allein das Profil fest.
Neue Branchen kommen als neues Profil dazu, ohne dass sich am Datenmodell etwas ändert.

Dieses Dokument beschreibt in Teil A den Mechanismus und in Teil B das erste Profil.

---

# Teil A — Der Mechanismus

## 2. Profilkennung

Die Kennung steht im Feld `prof` des Eintrags (OWM-0 §6) und ist optional: Ein Eintrag ohne
Profil ist zulässig und wird nicht geprüft, weil es nichts zu prüfen gibt.

Zulässig sind höchstens 64 Zeichen aus `a–z`, `0–9`, `.`, `/`, `-`, `_`. Kein Großbuchstabe, kein
Leerzeichen, kein Freitext — sonst landen dort früher oder später Steuerzeichen oder Pfadangaben.
Der Schrägstrich erlaubt Namensräume (`eu/battery.v1`).

**Die Version gehört in die Kennung.** Änderungen erscheinen als `food.v2`, nicht als geändertes
`food.v1`.

## 3. Unveränderlichkeit und Schema-Digest

> Eine Profilversion ist unveränderlich. Ist `food.v1` einmal veröffentlicht, ändert sich sein
> Schema nie wieder.

Der Grund ist nicht Ordnungsliebe. Änderte sich das Schema, wäre ein Eintrag von gestern heute
ungültig, obwohl niemand ihn angefasst hat — und ein Monitor könnte nicht mehr nachvollziehen,
wogegen die Node damals geprüft hat. Ein Log, dessen Prüfregeln rückwirkend wandern, bezeugt
nichts Bestimmtes mehr.

Nachprüfbar wird das über den Schema-Digest:

```
SchemaDigest = H("OWM/1 profile-schema", id, name₁, data₁, name₂, data₂, …)
```

`H` ist die längenpräfixierte Hashfunktion aus OWM-0 §3.3; die Dateien gehen **nach Namen
sortiert** ein, jede mit Name und Inhalt, damit sich Namen und Inhalte nicht ineinander schieben
lassen.

Eine Node MUSS den Digest ihrer geladenen Profile veröffentlichen (OWM-7 §4.9). Zwei Nodes, die
dasselbe Profil nennen, aber verschiedene Digests melden, prüfen verschieden — und das gehört
sichtbar gemacht, nicht verborgen. Der Digest ist die einzige Möglichkeit, das von außen
festzustellen.

## 4. Prüfung

Ein Profil besteht aus einem Satz JSON-Schema-Dateien (Draft 2020-12) mit einem Wurzelschema,
üblicherweise `event.json`.

### 4.1 Die Nutzlast wird streng gelesen

Die Bytes der Nutzlast sind durch das Commitment festgeschrieben. Also MUSS jede Implementierung
sie gleich lesen — sonst prüfen zwei Nodes dieselbe Nutzlast gegen verschiedene Werte. Über
JSON hinaus gilt deshalb:

- **Doppelte Objektschlüssel sind ein Fehler.** Die eine Sprache nimmt den letzten Wert, die
  andere den ersten; dieselben Bytes bedeuteten dann Verschiedenes.
- **Text hinter dem obersten Wert ist ein Fehler.**
- **Die Verschachtelung ist auf 32 Ebenen begrenzt.** Der Decoder läuft rekursiv und die Nutzlast
  kommt von außen; ohne Grenze genügt eine Kette aus Klammern, um den Prozess umzubringen. Ein
  Lieferkettenereignis mit dreißig Ebenen gibt es nicht.
- **Der oberste Wert MUSS ein Objekt sein.**

### 4.2 `format` ist eine Prüfung, keine Anmerkung

Im JSON-Schema-Standard ist `format` standardmäßig folgenlos. Für ein Profil ist es genau die
Prüfung, die zählt: Ein Zeitstempel, der keiner ist, gehört nicht ins Log, sondern in die
Fehlermeldung an den Einreicher. Eine Implementierung MUSS `format` durchsetzen.

### 4.3 Keine fremden Schemaquellen

Ein `$ref` auf eine fremde URL würde beim Übersetzen ins Netz greifen. Eine Implementierung MUSS
das ablehnen. Ein Profil, dessen Regeln von einem fremden Server abhängen, ist kein
festgeschriebenes Profil mehr — der Digest aus §3 wäre wertlos, weil sich die tatsächlich
angewandten Regeln jederzeit ändern könnten, ohne dass eine Datei sich ändert.

Alle `$ref` sind relativ und werden innerhalb des Profils aufgelöst.

### 4.4 Regeln über den Eintrag

Manches lässt sich im JSON-Schema nicht ausdrücken, weil das Schema nur die Nutzlast sieht und
nicht den Eintrag. Ein Profil KANN deshalb zusätzliche Regeln festlegen, die beides zusammen
prüfen. Sie laufen erst, wenn die Nutzlast schemakonform ist.

Das Lebensmittelprofil nutzt genau eine solche Regel (§8).

## 5. Was die Prüfung leistet — und was nicht

Sie ist ein **Eingangsfilter, keine Wahrheitsaussage**. Ein schemakonformer Eintrag kann eine
vollständige Lüge sein: Das Schema prüft Form, nicht Wirklichkeit. Es hält Tippfehler, fehlende
Pflichtfelder und Formatverwechslungen aus dem Log fern, damit die Kette später überhaupt
maschinell auswertbar ist.

Die Arbeitsteilung, die man nicht verwechseln darf:

| Frage | Beantwortet durch |
|---|---|
| Hat die Nutzlast die richtige Form? | Profilschema |
| Gehört die Nutzlast zu genau diesem Eintrag? | Commitment (OWM-0 §5) |
| Wer steht dafür ein? | Signatur |
| Stimmt es? | niemand — siehe OWM-9, Orakelproblem |

## 6. Unbekannte Profile

Eine Node MUSS Einträge mit einer Profilkennung ablehnen, die sie nicht geladen hat — auch dann,
wenn kein Commitment vorhanden ist und es nichts zu prüfen gäbe.

Ein Profil abzulehnen, das man nicht prüfen kann, ist ehrlicher, als es ungeprüft anzunehmen: Die
Node behauptet dann nichts, wofür sie nicht einstehen kann. Im föderierten Modell halten andere
Nodes andere Profile; wer `eu/battery.v1` einreichen will, sucht sich eine Node, die es kennt.
Die Nodemetadaten (OWM-7 §4.1) sagen vorab, welche das sind.

---

# Teil B — Das Lebensmittelprofil `food.v1`

## 7. Anlehnung an EPCIS 2.0

Die Ereignisse sind an GS1 EPCIS 2.0 angelehnt statt neu erfunden. EPCIS ist die Sprache, in der
Handel und Logistik Lieferkettenereignisse ohnehin schon beschreiben. Wer daran anknüpft, braucht
keine Übersetzungsschicht; wer sich eine eigene Semantik ausdenkt, hat sie für immer.

| `event` | EPCIS 2.0 | Bedeutung |
|---|---|---|
| `production` | ObjectEvent, action ADD, bizStep commissioning | Ein Gut entsteht: Ernte, Schlachtung, Fang, Abfüllung |
| `aggregation` | AggregationEvent, action ADD/DELETE | Eier in Zehnerpackungen, Kartons auf eine Palette |
| `transport` | ObjectEvent, action OBSERVE, bizStep shipping/receiving | Abgang oder Ankunft |
| `processing` | TransformationEvent | Milch dreier Höfe wird ein Käselaib |
| `handover` | TransactionEvent | Wechsel von Verantwortung oder Eigentum |
| `measurement` | sensorElementList | automatisch erfasste Messreihe |

## 8. Ereignistyp und Eintragstyp

Alle sechs Ereignisse teilen sich **eine** Profilkennung, und der Ereignistyp steht in der
Nutzlast, nicht im Feld `prof`.

Das ist Absicht. Stünde der Ereignistyp in `prof`, wäre nach einer Löschung immer noch sichtbar,
welche Art Ereignis es war — und aus `handover` allein lässt sich einiges schließen. So bleibt
stehen, dass es zu einem Zeitpunkt ein Lebensmittelereignis zu einem Subjekt gab, und nicht mehr.

Die eine Regel über den Eintrag (§4.4) bindet den Ereignistyp an den Eintragstyp:

| `event` | verlangter `typ` |
|---|---|
| `measurement` | `sensor_reading` (5) |
| alle übrigen | `assertion` (1) |

**Eine Messung ist keine Selbstauskunft.** Sie kommt von einem Gerät und wird von einem
Geräteschlüssel signiert. Ohne diese Bindung ließe sich eine von Hand geschriebene Kühlkette
später als Sensorbeleg ausgeben — und der ganze Wert einer Messreihe liegt darin, dass sie einer
menschlichen Selbstauskunft **widersprechen** kann (OWM-9, Orakelproblem).

## 9. Aufbau der Schemata

`event.json` ist das Wurzelschema. Es fordert `event` und `time`, erlaubt `party`, `location` und
`note`, und schaltet über `if/then` das Teilschema des jeweiligen Ereignisses dazu.
`unevaluatedProperties: false` verbietet alles, was weder hier noch dort vorgesehen ist —
`additionalProperties` wäre an dieser Stelle falsch, weil es die Felder der Teilschemata nicht
sähe.

`defs.json` hält die gemeinsamen Bausteine: `subject`, `keyid`, `timestamp`, `date`, `text`,
`party`, `location`, `quantity`, `product`, `certification`, `item`.

### 9.1 Drei Zeiten, die man nicht verwechseln darf

| Feld | Wo | Bedeutung |
|---|---|---|
| `time` | Nutzlast | Zeitpunkt des Ereignisses **in der Wirklichkeit** |
| `iat` | Eintrag | wann der Aussteller die Aussage gemacht hat |
| `ts` | Blatt | wann die Node sie aufgenommen hat |

Dass sie auseinanderfallen dürfen, ist der Punkt: Ein rückdatiertes Ereignis lässt sich an seinem
Aufnahmezeitpunkt erkennen (OWM-2 §3.1).

### 9.2 Anschluss an bestehende Kennungssysteme

Das Profil verwendet GS1-Kennungen, wo es sie gibt — `gtin` für die Ware, `gln` für Betrieb und
Ort — und UN/CEFACT Recommendation 20 für Einheiten (`KGM`, `LTR`, `CEL`, `H87`). Ländercodes
nach ISO 3166-1 alpha-2.

Das ist dieselbe Überlegung wie bei EPCIS: Ein Betrieb, der ohnehin GTINs führt, soll sie nicht
in ein Zweitsystem übersetzen müssen.

## 10. Wie die Kette entsteht

Die Verkettung leistet **nicht** das Profil, sondern das Feld `par` des Eintrags (OWM-0 §6.2).
Das Profil beschreibt nur, was bei einem Schritt geschehen ist.

- **Aggregation** fasst zusammen und lässt sich wieder auflösen (`action: add` / `delete`). Das
  Subjekt des Eintrags ist die übergeordnete Einheit, die Bestandteile stehen in `children`.
- **Verarbeitung** geht weiter: Die Eingänge gehen unter, sie lassen sich nicht wieder
  auseinandernehmen. Die Herkunft bleibt trotzdem verfolgbar, weil die Eingänge in `par` stehen.

Ein Verweis in `par` darf in ein **fremdes** Log zeigen; `log_id` benennt es dann. So läuft eine
Kette über Betriebsgrenzen hinweg, ohne dass eine Node Daten einer anderen halten müsste.

**Transport ist zweiteilig.** Abgang und Ankunft sind zwei Einträge, üblicherweise von zwei
verschiedenen Stellen ausgestellt. Die Übereinstimmung beider Aussagen ist ein Teil des
Nachweises — deshalb ist die Ankunft kein Feld im Abgangsereignis.

**Übergabe ist ein eigenes Ereignis**, kein Nebenfeld des Transports. Sie ist die Stelle, an der
eine Kette üblicherweise reißt.

## 11. Behauptung und Bestätigung

`production.certifications` ist ausdrücklich **das, was die Erzeugerin behauptet**. Eine
Behauptung, keine Prüfung.

Bestätigt wird sie erst durch einen `attestation`-Eintrag der Zertifizierungsstelle über den
Schlüssel der Erzeugerin (OWM-0 §6.1). Ein Client, der ein Bio-Siegel anzeigt, MUSS beides
auseinanderhalten und SOLLTE unbestätigte Selbstauskünfte als solche kennzeichnen. Wie aus
Attestierungen ein Vertrauensgrad wird, steht in OWM-6.

Dasselbe gilt für `transport.conditions`: Das sind **zugesagte** Beförderungsbedingungen. Ob sie
eingehalten wurden, sagen die `measurement`-Einträge — nicht dieses Feld.

## 12. Messreihen

`measurement` verlangt `sensor`, `quantity_kind`, `unit` und `readings` (bis zu 4096 Wertepaare
aus Zeitpunkt und Zahl). `sensor.key` nennt die Schlüsselkennung des Geräts; sein Vertrauensgrad
ist nach oben durch den seines Betreibers begrenzt (OWM-3 §7, OWM-6).

Bei feiner Auflösung wird die Zahl der Einträge zum Speicherproblem. Der Hebel dagegen liegt beim
Aussteller und ist in OWM-2 §8 beschrieben: Wer viele gleichartige Messwerte erzeugt, baut aus
ihnen selbst einen Merkle-Baum, legt dessen Wurzel in **eine** Nutzlast und schreibt **einen**
Eintrag mit **einer** Signatur. Der Einzelwert wird über einen Inklusionsbeweis in diesem
Unterbaum belegt, der off-chain neben der Nutzlast liegt. Aus 8640 Messwerten eines Tages wird so
ein Eintrag statt 8640.

Für `food.v1` gilt: Die Bündelung ist **nicht** Bestandteil des Schemas. Ein gebündelter
Messwertsatz wird als eigene Nutzlastform übertragen, deren Festlegung offen ist (§14). Bis
dahin trägt `readings` die Werte unmittelbar, und die Grenze von 4096 ist die praktische
Obergrenze eines Eintrags.

## 13. Datenschutz im Profil

Die harte Regel aus OWM-0 §2 gilt auch hier, und das Profil ist darauf zugeschnitten:

- **`party` kennt nur Betriebe.** Namen natürlicher Personen gehören nicht hinein. Es gibt kein
  Feld für eine Kontaktperson, und das ist kein Versehen.
- **Alle Felder der Nutzlast sind löschbar**, weil sie hinter dem Commitment liegen. Was bleibt,
  sind Subjekt-ID, Aussteller, Zeiten, Profilkennung, Eintragstyp und Vorgänger (OWM-2 §7.4).
- **`location.geo` ist ein Grenzfall.** Eine Koordinate mit drei Nachkommastellen kann bei einem
  Einzelbetrieb personenbeziehbar sein. Sie liegt in der Nutzlast und ist damit löschbar; wer sie
  gar nicht erst erhebt, ist besser dran. Datensparsamkeit ist die eigentliche Maßnahme, nicht
  die Löschung danach.
- Wo Verknüpfbarkeit über die Subjekt-ID schadet, MUSS sie zufällig gewählt werden und DARF NICHT
  aus der GTIN abgeleitet werden (OWM-0 §4.2).

## 14. Offene Punkte

- **Nutzlastform für gebündelte Messreihen** (§12): Wurzelhash, Baumkonstruktion und die Form des
  off-chain-Beweises sind noch nicht festgelegt. Bis dahin bleibt es bei `readings`.
- **Kein Widerruf-Ereignis im Profil.** Ein falsches Ereignis wird über einen
  `revocation`-Eintrag des Kerns zurückgenommen, nicht über ein Profilfeld. Ob das für die
  Praxis reicht, muss sich zeigen.
- Zuordnung zu bestehenden Codelisten für `process` in `processing` — derzeit Freitext.
- `eu/battery.v1` als zweites Profil (EU-Batteriepass, Pflicht ab Februar 2027). Es ist der
  eigentliche Test dafür, ob der Mechanismus branchenagnostisch ist: Wenn dafür der Kern
  angefasst werden muss, ist Teil A gescheitert.

## 15. Sicherheitsbetrachtung

| Angriff | Wirkung | Gegenmittel |
|---|---|---|
| Node ändert stillschweigend ihr Schema | prüft anders als behauptet | Schema-Digest (§3) |
| `$ref` auf fremden Server | Regeln von außen änderbar | keine fremden Quellen (§4.3) |
| Doppelte Schlüssel in der Nutzlast | zwei Lesarten derselben Bytes | strenges Lesen (§4.1) |
| Tief verschachtelte Nutzlast | Node stirbt am Stapel | Tiefengrenze 32 (§4.1) |
| Handgeschriebene Kühlkette als Sensorbeleg | falsche Beweiskraft | Bindung an `sensor_reading` (§8) |
| Ereignistyp im Feld `prof` | verrät nach Löschung, was geschah | eine Kennung für alle Ereignisse (§8) |
| Selbstauskunft sieht aus wie Zertifikat | Vortäuschung geprüfter Herkunft | Trennung Behauptung/Attestierung (§11) |
