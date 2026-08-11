// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// SaltSize ist die Länge des Nutzlast-Salts in Byte.
const SaltSize = 32

// Salt ist der Zufallswert, der eine Nutzlast an ihr Commitment bindet.
//
// Der Salt ist ein Geheimnis und mit derselben Sorgfalt zu behandeln wie ein
// privater Schlüssel. Er entscheidet darüber, ob eine Löschung wirklich
// endgültig ist: Solange er irgendwo liegt — in einem Backup, einem Replikat,
// einem Dateisystem-Snapshot — ist die Nutzlast nachweisbar und damit nicht
// gelöscht.
type Salt [SaltSize]byte

// NewSalt zieht einen frischen Salt.
//
// Jede Nutzlast braucht einen eigenen. Ein wiederverwendeter Salt macht gleiche
// Nutzlasten über Einträge hinweg erkennbar und überlebt die Löschung des einen
// Eintrags im anderen.
func NewSalt() (Salt, error) {
	var s Salt
	if _, err := rand.Read(s[:]); err != nil {
		return s, fmt.Errorf("owm: salt: %w", err)
	}
	return s, nil
}

// Wipe überschreibt den Salt im Speicher. Kein Ersatz für das Löschen aus dem
// Blob-Speicher, aber die richtige Geste am Ende einer Verarbeitung.
func (s *Salt) Wipe() {
	for i := range s {
		s[i] = 0
	}
}

// Commit berechnet das Nutzlast-Commitment:
//
//	HMAC-SHA-256( key = salt, msg = u8(len(label)) ‖ label ‖ payload )
//
// Bindend, weil eine zweite Nutzlast mit gleichem Commitment eine
// SHA-256-Kollision erfordert. Verbergend, weil ohne den Salt jede Nutzlast
// gleich plausibel ist — auch bei einem Wertebereich von wenigen
// Möglichkeiten. Genau daran scheitert ein ungesalzener Hash: Eine
// Postleitzahl oder eine GPS-Koordinate ließe sich schlicht durchprobieren.
func Commit(salt Salt, payload []byte) Commitment {
	m := hmac.New(sha256.New, salt[:])
	m.Write([]byte{byte(len(labelCommit))})
	m.Write([]byte(labelCommit))
	m.Write(payload)
	var c Commitment
	m.Sum(c[:0])
	return c
}

// VerifyCommitment prüft, ob Salt und Nutzlast zum Commitment passen.
func VerifyCommitment(c Commitment, salt Salt, payload []byte) bool {
	got := Commit(salt, payload)
	return hmac.Equal(c[:], got[:])
}
