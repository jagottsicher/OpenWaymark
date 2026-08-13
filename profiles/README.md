<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `profiles/` — Schema-Profile · Apache-2.0

Der Kern kennt kein Branchenschema. Was in einer Nutzlast stehen darf, legt ein Profil fest, das
über die Profilkennung im Eintrag (`prof`) referenziert wird.

| Profil | Kennung | Stand |
|---|---|---|
| [Lebensmittel](food/) | `food.v1` | vorhanden |
| EU-Batteriepass | noch offen | Profil Nr. 2, Pflicht ab Februar 2027 |

Vollständige Beschreibung: [OWM-4](../spec/owm-4-profiles.md).

## Was die Schemaprüfung leistet

Sie ist ein **Eingangsfilter, keine Wahrheitsaussage**. Ein schemakonformer Eintrag kann eine
vollständige Lüge sein — das Schema prüft die Form, nicht die Wirklichkeit. Es hält Tippfehler,
fehlende Pflichtfelder und Formatverwechslungen aus dem Log fern, damit eine Kette später
überhaupt maschinell auswertbar ist. Die Bindung an den Eintrag leistet das Commitment, die
Zurechenbarkeit die Signatur.

## Unveränderlichkeit

Eine Profilversion ändert sich nie. Wäre `food.v1` heute anders als gestern, wäre ein Eintrag von
gestern heute ungültig, ohne dass ihn jemand angefasst hätte — und ein Monitor könnte nicht mehr
nachvollziehen, wogegen eine Node damals geprüft hat. Änderungen erscheinen als `food.v2`.
`Profile.SchemaDigest()` bindet die Kennung an genau den ausgelieferten Satz Schemadateien;
zwei Nodes mit demselben Profilnamen, aber verschiedenen Digests prüfen verschieden.

## Eigenes Profil

```go
//go:embed schema/*.json
var schemaFS embed.FS

sub, _ := fs.Sub(schemaFS, "schema")
p, err := profiles.Load(profiles.Options{
    ID:    "eu/battery.v1",   // Zeichenvorrat wie im Feld prof: a–z 0–9 . / - _
    Title: "EU-Batteriepass",
    FS:    sub,
    Root:  "event.json",
    Rule:  bindEntryType,     // optional: Prüfungen, die den Eintrag betreffen
})
```

Schemata werden nach JSON Schema 2020-12 übersetzt, `format` wird geprüft. Verweise auf fremde
URLs lehnt der Compiler ab: Ein Profil, dessen Regeln von einem fremden Server abhängen, ist kein
festgeschriebenes Profil.

## Strenge beim Lesen der Nutzlast

`Validate` liest strenger als `encoding/json`, und zwar aus einem einzigen Grund — die Bytes der
Nutzlast sind durch das Commitment festgeschrieben, also muss jede Implementierung sie gleich
lesen:

- **doppelte Objektschlüssel** sind ein Fehler (Go nimmt den letzten Wert, andere Sprachen den
  ersten — dieselben Bytes bedeuteten dann Verschiedenes),
- Text hinter dem obersten Wert ist ein Fehler,
- die Verschachtelung ist auf 32 Ebenen begrenzt.
