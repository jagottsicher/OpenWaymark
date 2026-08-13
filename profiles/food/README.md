<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/food/` — Lebensmittelprofil `food.v1` · Apache-2.0

Das erste Schema-Profil von OpenWaymark. Die Ereignisse sind an **GS1 EPCIS 2.0** angelehnt statt
neu erfunden: EPCIS ist die Sprache, in der Handel und Logistik Lieferkettenereignisse ohnehin
beschreiben.

| Ereignis (`event`) | EPCIS 2.0 | Bedeutung |
|---|---|---|
| `production` | ObjectEvent, ADD, `commissioning` | Ein Gut entsteht und bekommt seine Kennung |
| `aggregation` | AggregationEvent, ADD/DELETE | Zusammenfassen und Auflösen — Eier in Zehnerpackungen |
| `transport` | ObjectEvent, OBSERVE, `shipping`/`receiving` | Abgang und Ankunft, zwei getrennte Einträge |
| `processing` | TransformationEvent | Aus Eingängen werden andere Güter — Milch wird Käse |
| `handover` | TransactionEvent | Wechsel von Verantwortung oder Eigentum |
| `measurement` | `sensorElementList` | Messreihe eines Geräts, etwa die Kühlkette |

## Eine Kennung, sechs Ereignisse

Der Ereignistyp steht **in der Nutzlast**, nicht in der Profilkennung. Stünde er im Feld `prof`
des Eintrags, bliebe nach einer Löschung sichtbar, welche Art Ereignis es war. So bleibt nur
stehen: Es gab zu einem Zeitpunkt ein Lebensmittelereignis zu einem Subjekt.

## Aggregation und Verarbeitung

Der Unterschied ist der Kern jeder realen Lebensmittelkette:

- **Aggregation** ist umkehrbar. Die Bestandteile bleiben, was sie sind; das Subjekt des Eintrags
  ist die übergeordnete Einheit, die Bestandteile stehen in `children`.
- **Verarbeitung** ist nicht umkehrbar. Die Eingänge gehen unter. Verfolgbar bleibt die Herkunft
  trotzdem, weil die Eingangseinträge im Feld `par` des Eintrags stehen — dort und nur dort
  entsteht der Herkunftsgraph.

## Messungen

`measurement` muss als Eintragstyp `sensor_reading` eingereicht werden, alles andere als
`assertion`. Das prüft nicht das JSON-Schema, sondern eine Profilregel — das Schema sieht den
Eintrag nicht. Ohne diese Bindung ließe sich eine von Hand geschriebene Kühlkette später als
Gerätebeleg ausgeben. Der Wert automatisch erfasster Werte liegt gerade darin, dass sie einer
menschlichen Selbstauskunft **widersprechen** können; siehe
[Angreifermodell](../../spec/owm-9-threat-model.md).

## Personenbezug

Das Profil kennt Betriebe, keine natürlichen Personen: `party` hat Felder für Name, GLN und
Schlüsselkennung eines Unternehmens. Wer dort einen Personennamen einträgt, erzeugt einen
Löschanspruch, wo keiner nötig war. Auch die Subjektkennung darf nicht aus Personendaten
abgeleitet werden — sie ist ein Nachschlageschlüssel und absichtlich erratbar.

## Einheiten und Kennungen

- Mengen: UN/CEFACT Recommendation 20 (`KGM`, `GRM`, `LTR`, `H87` für Stück, `CEL` für °C)
- Waren: GTIN, 8 bis 14 Ziffern
- Orte und Betriebe: GLN, 13 Ziffern
- Länder: ISO 3166-1 alpha-2, Großbuchstaben
- Zeitpunkte: RFC 3339 **mit Zeitzone**

Beispielnutzlasten für jedes Ereignis stehen in [`food_test.go`](food_test.go).
