<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# Testvektoren

Diese Dateien sind **Teil der Spezifikation**, nicht bloß Testbeiwerk. Eine
Fremdimplementierung gilt als konform zu [OWM-0](../../spec/owm-0-overview.md), wenn sie sie
Byte für Byte reproduziert. Alle Bytefolgen sind hexkodiert.

Neu erzeugen — und das heißt: das Protokoll ändern, nicht nur einen Test:

```sh
go test ./core/ -update
```

## `core-v1.json`

| Abschnitt | Prüft |
|---|---|
| `hash_labels` | Den domänengetrennten Hash aus OWM-0 §3.3. Die beiden Fälle `["ab","c"]` und `["a","bc"]` müssen **verschiedene** Ergebnisse liefern — eine Implementierung ohne Längenpräfixe erzeugt hier zweimal denselben Wert und ist damit angreifbar. |
| `subject_ids` | Die Ableitung `SubjectID = H("OWM/1 subject-id", namespace, value)`. |
| `keys` | Schlüsselableitung aus dem Saatwert nach FIPS 204 und die Schlüsselkennung `H("OWM/1 key-id", u16be(alg), pubkey)`. |
| `commitments` | Das gesalzene Nutzlast-Commitment. Der Salt ist hier fest, damit die Vektoren reproduzierbar sind; im Betrieb bekommt **jede** Nutzlast einen frisch gezogenen. |
| `entries` | Die kanonische CBOR-Kodierung, die Inhaltsadresse und den signierten Umschlag — je einmal für jeden Eintragstyp und für beide Signaturstufen. |

### Zu den Signaturen

`signature_deterministic` ist mit dem deterministischen Zweig von FIPS 204 erzeugt und deshalb
reproduzierbar. Im Betrieb wird randomisiert ("hedged") signiert; dort ist jede Signatur anders
und trotzdem gültig. Eine Implementierung, die nur randomisiert signieren kann, prüft diese
Vektoren also durch **Verifikation**, nicht durch Nacherzeugung.

### Reihenfolge der Prüfung

Wer eine eigene Implementierung gegen diese Datei stellt, geht sinnvollerweise von unten nach
oben vor: zuerst `hash_labels`, dann `keys`, dann `commitments`, zuletzt `entries`. Ein Fehler
im Hash schlägt sonst als scheinbarer Signaturfehler durch und kostet unnötig Zeit.
