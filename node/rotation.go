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

// ErrRotation reports an unusable key announcement.
var ErrRotation = errors.New("owm/node: key announcement is invalid")

// RotationPayload is the payload of a key_rotation entry (OWM-3 §6).
//
// The entry is signed by the outgoing key and names the successor. That makes
// rotation exactly what it should be: a statement by the old holder, recorded in
// the log and traceable by anyone. A successor announcing itself would not be a
// rotation but a fresh registration.
type RotationPayload struct {
	Alg    string `json:"alg"`
	Public string `json:"public"`
	Label  string `json:"label,omitempty"`
}

// applyRotation takes the announced successor key into the directory.
//
// The predecessor is NOT retired. Both keys are valid side by side for a while,
// otherwise every rotation would break ongoing operation: a sensor that has not
// yet seen the announcement keeps signing with the old key. Retiring is a
// separate step taken by the operator.
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
	// The subject of the entry MUST be the identifier of the successor. Without
	// that binding the log would record a rotation to key A while the payload
	// announces key B — and once the payload is erased it would no longer be
	// possible to tell which one was meant.
	if core.SubjectID(pub.ID()) != e.Subject {
		return fmt.Errorf("%w: subject %s, announced was %s", ErrRotation, e.Subject, pub.ID())
	}
	if pub.ID() == e.Issuer {
		return fmt.Errorf("%w: key announces itself", ErrRotation)
	}
	issuer := e.Issuer
	return n.keys.Register(ctx, pub, p.Label, &issuer)
}
