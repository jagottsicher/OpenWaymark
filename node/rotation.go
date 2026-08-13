// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"openwaymark.org/owm/core"
)

// ErrRotation meldet eine unbrauchbare Schlüsselankündigung.
var ErrRotation = errors.New("owm/node: key announcement is invalid")

// RotationPayload ist die Nutzlast eines key_rotation-Eintrags (OWM-3 §6).
//
// Der Eintrag ist vom bisherigen Schlüssel signiert und benennt den Nachfolger.
// Damit ist die Rotation genau das, was sie sein soll: eine Aussage des alten
// Inhabers, im Log festgehalten und für jeden nachvollziehbar. Ein Nachfolger,
// der sich selbst ankündigt, wäre keine Rotation, sondern eine Neuanmeldung.
type RotationPayload struct {
	Alg    string `json:"alg"`
	Public string `json:"public"`
	Label  string `json:"label,omitempty"`
}

// applyRotation nimmt den angekündigten Nachfolgeschlüssel ins Verzeichnis auf.
//
// Der Vorgänger wird NICHT stillgelegt. Beide Schlüssel gelten eine Zeit lang
// nebeneinander, sonst bräche jede Rotation den laufenden Betrieb: Ein Sensor,
// der die Ankündigung noch nicht gesehen hat, signiert weiter mit dem alten
// Schlüssel. Das Stilllegen ist ein eigener Schritt der Betreiberin.
func (n *Node) applyRotation(ctx context.Context, e *core.Entry, payload []byte) error {
	var p RotationPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("%w: %v", ErrRotation, err)
	}
	alg, err := ParseSigAlg(p.Alg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRotation, err)
	}
	raw, err := hex.DecodeString(p.Public)
	if err != nil {
		return fmt.Errorf("%w: public key: %v", ErrRotation, err)
	}
	pub, err := core.ParsePublicKey(alg, raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrRotation, err)
	}
	// Das Subjekt des Eintrags MUSS die Kennung des Nachfolgers sein. Ohne diese
	// Bindung stünde im Log eine Rotation zu Schlüssel A, während in der
	// Nutzlast Schlüssel B ankündigt wird — und nach einer Löschung der Nutzlast
	// wäre nicht mehr feststellbar, welcher gemeint war.
	if core.SubjectID(pub.ID()) != e.Subject {
		return fmt.Errorf("%w: subject %s, announced was %s", ErrRotation, e.Subject, pub.ID())
	}
	if pub.ID() == e.Issuer {
		return fmt.Errorf("%w: key announces itself", ErrRotation)
	}
	issuer := e.Issuer
	return n.keys.Register(ctx, pub, p.Label, &issuer)
}
