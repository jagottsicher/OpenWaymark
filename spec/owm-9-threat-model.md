<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# OWM-9 — Angreifermodell

**Status:** Entwurf · **Stand:** 2026-08-10

Dieses Dokument benennt, wogegen OpenWaymark schützt, wogegen ausdrücklich nicht, und welche
Restrisiken bewusst getragen werden. Es ist die Referenz für Sicherheitsentscheidungen im Code:
Jede Gegenmaßnahme hier soll einen Test haben, der ihren Ausfall sichtbar macht.

Ein Satz vorweg, weil er alles andere einordnet: **OpenWaymark beweist nicht, dass eine Aussage
wahr ist. Es beweist, wer sie wann gemacht hat, und dass sie seither nicht verändert wurde.**
Wer das verwechselt, überschätzt das System.

## 1. Werte

| Wert | Warum schützenswert |
|---|---|
| Integrität des Logs | Eine nachträglich änderbare Historie ist wertlos. |
| Zurechenbarkeit von Aussagen | Ohne Zurechenbarkeit gibt es keine Verantwortung und keine Sanktion. |
| Nicht-Äquivokation | Alle Beobachter müssen dieselbe Historie sehen, sonst ist jeder Beweis nur lokal gültig. |
| Löschbarkeit personenbezogener Daten | Rechtliche Pflicht und Bedingung dafür, dass das System überhaupt betrieben werden darf. |
| Verfügbarkeit der Nachweise | Ein Nachweis, der nicht abrufbar ist, hilft im Streitfall nicht. |
| Vertraulichkeit der Nutzlast | Geschäftsgeheimnisse und Personendaten dürfen nicht mit dem Log öffentlich werden. |

## 2. Sicherheitsziele

1. **Anfügungsintegrität.** Ein Eintrag im Log kann nicht unbemerkt verändert oder entfernt werden.
2. **Nicht-Äquivokation.** Eine Node kann nicht dauerhaft zwei verschiedene Historien zeigen, ohne
   dass es auffällt.
3. **Zurechenbarkeit.** Jeder Eintrag trägt eine prüfbare Signatur einer benannten Entität.
4. **Löschbarkeit ohne Beweisverlust.** Nutzlasten sind löschbar, ohne dass ein einziger
   ausgegebener Beweis ungültig wird.
5. **Eigenständige Prüfbarkeit.** Ein Client muss Signaturen und Inklusionsbeweise selbst prüfen
   können und darf dem Server nicht glauben müssen.
6. **Post-Quantum-Haltbarkeit.** Aufgezeichnete Daten bleiben auch dann zurechenbar, wenn später
   ein kryptographisch relevanter Quantenrechner existiert.

## 3. Ausdrückliche Nicht-Ziele

- **Wahrheit der Ersterfassung.** Siehe A4.
- **Globale Konsistenz.** Es gibt kein globales Register aller Güter. Wer nach globalem Konsens
  sucht, sucht das falsche System.
- **Zensurresistenz gegen den eigenen Node-Betreiber.** Wer die Node betreibt, kann Einträge
  verweigern. Siehe A3.
- **Schutz vor physischer Substitution.** Siehe A8.
- **Anonymität der Teilnehmer.** Das Trust-Level-System beruht gerade auf Identifizierbarkeit.
  Anonym ist nur Level 0, und der ist per Definition nichts wert.

## 4. Angreifertypen

| Typ | Fähigkeiten |
|---|---|
| **N — Netzangreifer** | Liest, verzögert, verwirft und fälscht Nachrichten zwischen Teilnehmern. |
| **B — Böswilliger Node-Betreiber** | Volle Kontrolle über eine Node, ihre Schlüssel und ihre Datenbank. |
| **T — Böswilliger Teilnehmer** | Gültige Identität, will falsche Aussagen einbringen. |
| **A — Außenstehender** | Kein Zugang, versucht Daten zu rekonstruieren oder Teilnehmer zu verknüpfen. |
| **Q — Quantenangreifer** | Zeichnet heute auf, bricht klassische Krypto später. |

## 5. Angriffe und Gegenmaßnahmen

| # | Angriff | Typ | Abgedeckt |
|---|---|---|---|
| A1 | Split-View | B | ja, durch Gossip und Monitore |
| A2 | Nachträgliche Änderung des Logs | B | ja, kryptographisch |
| A3 | Zurückhalten von Einträgen | B | teilweise |
| A4 | Lüge bei der Ersterfassung | T | nein, nur gemildert |
| A5 | Rekonstruktion gelöschter Nutzlast | A | ja, durch Salt |
| A6 | Schlüsselkompromittierung | N, B, T | ja, durch Rotation |
| A7 | Sybil-Angriff | T | ja, durch Verifikationskosten |
| A8 | Physische Substitution oder Klonen | T | nein, nur gemildert |
| A9 | Verknüpfung über Metadaten | A | teilweise |
| A10 | Lügender Server gegenüber dem Client | B | ja, durch clientseitige Prüfung |
| A11 | Ausfall einer Node | N, B | teilweise |
| A12 | Heute aufzeichnen, später entschlüsseln | Q | ja, durch PQ-Verfahren |

### A1 — Split-View · **der zentrale Angriff**

Eine böswillige Node zeigt zwei Beobachtern zwei verschiedene, jeweils in sich stimmige Bäume.
Der Lieferant bekommt eine Historie, der Prüfer eine andere. Beide Historien sind korrekt
signiert, beide Inklusionsbeweise gehen auf. Rein lokal ist der Angriff **nicht** erkennbar —
und zwar prinzipiell nicht, nicht bloß mangels Aufwand.

Das ist der Grund, warum Gossip in OpenWaymark **kein Synchronisationsverfahren, sondern eine
Sicherheitsmaßnahme** ist. Im Konzeptdokument stand er unter „Synchronisation"; er gehört hierher.

Gegenmaßnahmen, beide nötig:

- **Gezieltes Partner-Gossip.** Nodes tauschen STHs mit ihren tatsächlichen
  Lieferkettenpartnern aus und prüfen sie auf Konsistenz. Dort liegen Interesse und Kontext, und
  der Aufwand bleibt proportional zur echten Geschäftsbeziehung.
- **STH-Gossip an unabhängige Monitore.** Partner-Gossip allein erkennt keinen Split-View
  *gegenüber Außenstehenden* — die Partner sehen ja beide dieselbe Sicht. Erst ein Monitor, der
  von der Node nicht als solcher erkannt werden kann, schließt diese Lücke.

Was ein aufgedeckter Split-View bedeutet: Zwei STHs derselben Node zur selben Baumgröße mit
verschiedenen Wurzelhashes sind ein signierter, nicht abstreitbarer Beweis für Fehlverhalten.
Die Node hat ihn selbst unterschrieben.

**Grenze, die klar benannt gehört:** Erkennung ist nicht Verhinderung. Ein Split-View wird
nachträglich aufgedeckt, nicht verhindert. Zwischen Angriff und Aufdeckung liegt die
Gossip-Periode. Wer kürzere Fenster braucht, muss häufiger gossippen — es gibt keinen kostenlosen
Weg daran vorbei.

**Test:** Eine absichtlich manipulierte Node, die zwei Beobachtern verschiedene Bäume zeigt, muss
vom Monitor erkannt werden. Das ist der wichtigste Test des Projekts.

### A2 — Nachträgliche Änderung des Logs

Der Betreiber ändert einen alten Eintrag oder streicht ihn.

Abgedeckt durch die Merkle-Struktur: Jede Änderung ändert den Wurzelhash. Ein bereits
ausgegebenes STH ist eine Signatur des Betreibers über den alten Zustand; Konsistenzbeweise
zwischen zwei STHs decken jede Abweichung auf. Die Sicherheit beruht darauf, dass alte STHs
außerhalb der Node existieren — was wiederum A1 voraussetzt. **A1 und A2 hängen zusammen: ohne
Gossip ist auch A2 nicht abgedeckt**, denn eine Node, die ihre eigene Historie allein verwahrt,
kann sie samt aller STHs neu schreiben.

### A3 — Zurückhalten von Einträgen

Eine Node nimmt einen unbequemen Eintrag gar nicht erst an oder liefert ihn nicht aus.

Nur teilweise abgedeckt, und das ist eine bewusste Folge der Föderation. Milderungen:

- Wer einreicht, kann eine Quittung verlangen, die die Node zur Aufnahme innerhalb einer Frist
  verpflichtet — das CT-Muster des Signed Certificate Timestamp. Eine nicht eingelöste Quittung
  ist ein signierter Beweis für Vertragsbruch.
- Ein Gegenüber kann denselben Eintrag bei der eigenen Node einreichen. Eine Lieferbeziehung hat
  zwei Seiten, und beide dürfen dokumentieren.
- Lücken in der Kette sind für den Endprüfer sichtbar: Ein Vorgängerverweis, der ins Leere zeigt,
  ist ein Signal.

**Nicht abgedeckt:** Wer nie einreicht und keinen Partner hat, der es tut, hinterlässt keine Spur.

### A4 — Lüge bei der Ersterfassung · **das Orakelproblem**

Jemand scannt konventionelle Eier und trägt „bio" ein. Alles Nachgelagerte ist kryptographisch
einwandfrei — und inhaltlich falsch.

**Nicht abgedeckt, und durch kein Protokolldesign abdeckbar.** Die Lücke sitzt zwischen
physischer Realität und ihrer digitalen Erfassung, nicht in der Software.

Was das Restrisiko senkt, ohne es zu beseitigen:

- **Zurechenbarkeit.** Die Lüge ist signiert und datiert. Das ist der Unterschied zwischen einem
  Papierzettel und einer Beweisgrundlage.
- **Ökonomischer Einsatz.** Pfandverlust bei bestätigtem Betrug (E7).
- **Sensorik als Gegenprobe.** Ein GPS-Tracker widerspricht einer falschen Standortangabe
  automatisch. Widersprüche zwischen menschlicher Selbstauskunft und Gerätedaten sind maschinell
  auffindbar — genau darauf zielt der Eintragstyp `sensor_reading`.
- **Stichprobenhafte physische Audits durch Dritte.** Dieser Teil bleibt durch Software
  unersetzbar, unabhängig vom Protokolldesign.

Diese Grenze gehört in jede Außenkommunikation des Projekts. Ein System, das mehr verspricht,
als es halten kann, verliert genau dann das Vertrauen, wenn es darauf ankommt.

### A5 — Rekonstruktion gelöschter Nutzlast

Nach einer Löschung versucht jemand, aus dem verbliebenen Commitment die Nutzlast
zurückzurechnen.

Abgedeckt: Das Commitment ist `HMAC-SHA-256(Salt, …)` mit 32 Byte Zufallssalt. Ohne Salt ist
jede Nutzlast gleich plausibel — auch wenn nur zehn Werte in Frage kommen. Der Salt liegt beim
Blob und wird mit ihm gelöscht.

Ein ungesalzener Hash wäre hier ungenügend, und das ist der Punkt, an dem OpenWaymark von
Certificate Transparency abweichen muss: CT braucht keine Salts, weil CT nie löscht.

**Voraussetzungen, die außerhalb der Krypto liegen:** Der Salt muss wirklich verschwinden — auch
aus Backups, Replikaten und Dateisystem-Snapshots. Und Kopien der Nutzlast, die Partner
rechtmäßig erhalten haben, kann keine Löschung bei der Ursprungsnode einholen. Beides sind
Betriebs- und Vertragsfragen, keine Protokollfragen; die Spezifikation muss sie benennen, lösen
kann sie sie nicht.

**Test:** Nach der Löschung ist die Nutzlast auch bei einem Wertebereich von wenigen tausend
Möglichkeiten nicht rekonstruierbar, und der Inklusionsbeweis des Blattes gilt weiter.

### A6 — Schlüsselkompromittierung

Ein privater Schlüssel wird gestohlen. Was gilt für die Signaturen davor?

Abgedeckt durch Key-Rotation als eigenen Eintragstyp:

- Ein `key_rotation`-Eintrag kündigt den Nachfolger an, signiert mit dem alten Schlüssel.
- Gültigkeitsfenster überlappen, damit während der Umstellung nichts abreißt.
- Bei Kompromittierung widerruft ein `revocation`-Eintrag den Schlüssel **mit Zeitpunkt**.
  Signaturen davor bleiben gültig, spätere nicht — der Zeitpunkt ist aus dem Log belegbar, weil
  die Baumposition eine Reihenfolge festlegt, die die Node nicht rückwirkend ändern kann.
- Bei Verlust ohne Vorsorge bleibt nur Neuverifikation über die Node, gegenüber der die Entität
  ursprünglich ihr Trust-Level nachgewiesen hat.

**Nicht abgedeckt:** Der Zeitraum zwischen Diebstahl und Bemerken. Einträge daraus sind
formal gültig. Das entspricht jeder PKI und ist der Grund, warum der Widerruf einen Zeitstempel
trägt statt bloß eines Flags.

### A7 — Sybil-Angriff

Ein Teilnehmer legt viele Identitäten an, um Anreize abzugreifen oder eine Streitschlichtung zu
kippen.

Die Verteidigung ist **nicht** die Bonusformel — die kann Splitting prinzipiell nicht
verhindern, unabhängig von ihrer Konstruktion, weil `log(a)+log(b) > log(a+b)` gilt. Die
Verteidigung sind die Kosten der Identitätsverifikation: Der Bonus-Cap ist an das Trust-Level
gekoppelt. Auf Level 1–2 ist eine weitere Identität billig, aber der Cap niedrig; auf Level 5–6
wäre der Cap hoch, aber eine weitere Identität erfordert eine echte behördliche Prüfung.

Für die Streitschlichtung gilt dasselbe Prinzip: Losverfahren nur unter hoch verifizierten
Teilnehmern, die selbst Einsatz riskieren.

### A8 — Physische Substitution oder Klonen

Der Code wird von einer echten Ware abgelöst und auf eine gefälschte geklebt, oder ein QR-Code
wird schlicht kopiert.

**Nicht abgedeckt** — die Bindung zwischen Bit und Ding ist physisch, nicht kryptographisch. Das
Trust-Level der physisch-digitalen Bindung macht diese Schwäche wenigstens sichtbar statt sie zu
verstecken: gedruckter QR-Code = leicht kopierbar; Einweg-Seriennummer = anfällig für ein
Wettrennen; NFC mit Challenge-Response = praktisch nicht klonbar; PUF = physisch unklonbar.

Der Client MUSS das Bindungsniveau anzeigen. Ein gedruckter QR-Code an einer sonst lückenlosen
Kette darf nicht aussehen wie ein Beweis.

### A9 — Verknüpfung über Metadaten

Ein Außenstehender wertet öffentlich abrufbare Logdaten aus: Wer reicht wann wie viel ein? Damit
lassen sich Liefermengen, Kundenbeziehungen und Betriebsauslastung schätzen — ohne eine einzige
Nutzlast zu sehen.

Nur teilweise abgedeckt. Die Nutzlast ist geschützt, das **Kommunikationsmuster** nicht:
Zeitstempel, Häufigkeit, Verweisstruktur und Aussteller-IDs stehen im Log. Milderungen:
zufällige statt abgeleiteter Subjekt-IDs, Batch-Einreichung zur Verwischung der Zeitstruktur,
selektive Verschlüsselung der Nutzlast per ML-KEM für ausgewählte Partner (E5).

Restrisiko, das getragen wird: Ein Log, das nachprüfbar sein soll, muss beobachtbar sein.
Vollständige Unbeobachtbarkeit und öffentliche Prüfbarkeit schließen einander aus.

### A10 — Lügender Server gegenüber dem Client

Der Server liefert der Web-App eine erfundene Kette samt hübscher Darstellung.

Abgedeckt, aber nur wenn der Client wirklich selbst prüft. Deshalb ist der WASM-Verifier kein
Komfortmerkmal, sondern die Bedingung dafür, dass die ganze Beweiskette überhaupt etwas wert
ist: Der Client prüft Signaturen und Inklusionsbeweise gegen ein STH, das er unabhängig
beziehen kann. Ein Client, der dem Server glaubt, macht A1 bis A3 gegenstandslos — dann hätte
man sich das Log sparen können.

**Test:** Ein absichtlich manipulierter Server muss vom Client abgelehnt werden.

### A11 — Ausfall einer Node

Strom weg, Internet weg, Betreiber gibt auf.

Teilweise abgedeckt. Bereits an Partner weitergegebene Einträge und STHs bleiben dort abrufbar.
Neue Einträge sind während des Ausfalls nicht möglich — das ist der Preis der Föderation und
derselbe wie bei einem ausgefallenen Mailserver.

Für das Anreizsystem gilt asymmetrisch: Ausfall kostet **niemals** Bestand, sondern höchstens
Nachschub. Ein System, das Kleinbetreiber für einen Stromausfall bestraft, schafft genau die
Zentralisierung, die es vermeiden will.

### A12 — Heute aufzeichnen, später brechen

Ein Angreifer speichert heute alles und wartet auf einen Quantenrechner.

Abgedeckt, weil es keine klassische Krypto im Protokoll gibt: ML-DSA-65 und ML-DSA-44 für
Signaturen, ML-KEM-768 für Verschlüsselung, SHA-256 für Hashes (Begründung in
[OWM-0 §3.1](owm-0-overview.md#31-warum-sha-256-trotz-post-quantum-anspruch)). Kein
Hybridmodell, das später abgelegt werden müsste.

Für Signaturen ist „heute aufzeichnen, später brechen" ohnehin weniger dringlich als für
Verschlüsselung — eine später gefälschte Signatur nützt wenig, wenn ihre Position im Baum
bereits durch alte STHs bezeugt ist. Für Nutzlasten, die vertraulich bleiben müssen, ist die
Dringlichkeit real, und genau deshalb gilt PQ ab Tag 1 statt als Migrationsprojekt.

## 6. Bewusst getragene Restrisiken

| Restrisiko | Warum getragen |
|---|---|
| Split-View wird erkannt, nicht verhindert | Verhinderung erforderte globalen Konsens — und damit genau das System, das aus guten Gründen verworfen wurde. |
| Lüge bei der Ersterfassung | Physisch, nicht technisch lösbar. Milderung statt Lösung. |
| Metadaten sind auswertbar | Prüfbarkeit setzt Beobachtbarkeit voraus. |
| Node-Betreiber kann Einträge verweigern | Folge der Autonomie, die die Föderation ausmacht. |
| Löschung erreicht keine rechtmäßig verteilten Kopien | Vertrags- und Betriebsfrage, keine Protokollfrage. |
| Der Betreiber sieht die Nutzlasten seiner Teilnehmer | Community-Nodes erfordern Vertrauen in den Betreiber. Wer das nicht will, betreibt eine eigene Node — das ist der Sinn der Föderation. |

## 7. Was daraus für die Implementierung folgt

1. Gossip ist eine Sicherheitsfunktion. Er darf nicht als optionale Bequemlichkeit gebaut werden.
2. Der Monitor gehört zum Kern des Projekts, nicht zum Zubehör. Ohne ihn ist A1 offen.
3. Der Client prüft selbst. Ein Server-Endpunkt „vertrau mir, ist gültig" darf nicht existieren.
4. Der Salt wird als Geheimnis behandelt, mit demselben Ernst wie ein privater Schlüssel.
5. Zu jeder Gegenmaßnahme in Abschnitt 5 gehört ein Test, der ihren Ausfall sichtbar macht.
