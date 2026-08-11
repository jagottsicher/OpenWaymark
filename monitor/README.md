<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: AGPL-3.0-only
-->

# `monitor/` — Unabhängiger Log-Monitor · AGPL-3.0-only

**Geplant (Etappe E4). Noch kein Code.**

Sammelt STHs von Nodes, prüft sie paarweise auf Konsistenz und schlägt bei Divergenz Alarm.
Bewusst klein und eigenständig, damit ihn jemand anders betreiben kann als die beobachtete Node
— das ist der ganze Punkt.

Der Monitor gehört zum Kern des Projekts, nicht zum Zubehör. Der zentrale Angriff auf ein
CT-artiges Log ist der **Split-View**: Eine Node zeigt zwei Beobachtern zwei verschiedene, jeweils
in sich stimmige Bäume. Beide Historien sind korrekt signiert, beide Inklusionsbeweise gehen auf.
Lokal ist das prinzipiell nicht erkennbar. Ohne unabhängige Beobachtung bleibt der Angriff offen —
und mit ihm auch die nachträgliche Änderung des Logs, denn eine Node, die ihre Historie allein
verwahrt, kann sie samt aller STHs neu schreiben.

Zwei STHs derselben Node zur selben Baumgröße mit verschiedenen Wurzelhashes sind ein signierter,
nicht abstreitbarer Beweis für Fehlverhalten. Die Node hat ihn selbst unterschrieben.

Siehe [OWM-9 A1 und A2](../spec/owm-9-threat-model.md). Der Split-View-Test ist der wichtigste
Test des Projekts.
