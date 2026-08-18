// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package trust computes entity trust levels from attestation chains
// (OWM-6). It is pure: no I/O and no state of its own — the caller supplies
// both the attestations to walk (Source) and the accreditation roots to
// walk them towards (RootSet). A trust level is never read off a claim
// directly; it is always recomputed from what the caller already trusts,
// the same "recompute yourself, do not take a node's word for it" stance
// OWM-9 takes everywhere else.
package trust

import "fmt"

// Level is an entity trust level, 0 through 6 (OWM-6 §2). It is never
// self-declared — it is always the result of Compute.
type Level int

const (
	LevelNone       Level = 0 // No verification.
	LevelEmail      Level = 1 // Email confirmed.
	LevelDomain     Level = 2 // Domain control (DNS TXT record).
	LevelRegister   Level = 3 // Trade/company register record.
	LevelCertified  Level = 4 // Industry certification by an independent third party.
	LevelAccredited Level = 5 // State or official accreditation with regular inspection.
	LevelState      Level = 6 // A state body itself.
)

func (l Level) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelEmail:
		return "email"
	case LevelDomain:
		return "domain"
	case LevelRegister:
		return "register"
	case LevelCertified:
		return "certified"
	case LevelAccredited:
		return "accredited"
	case LevelState:
		return "state"
	default:
		return fmt.Sprintf("Level(%d)", int(l))
	}
}

// Valid reports whether l is one of the seven levels OWM-6 §2 defines.
func (l Level) Valid() bool { return l >= LevelNone && l <= LevelState }

// BindingLevel is a physical-digital binding trust level (OWM-6 §5).
//
// Unlike Level it is never computed by this package: no wire mechanism
// asserts it yet (OWM-6 §5 fixes the vocabulary and leaves attaching it to
// an item to whichever schema profile declares it — none does yet). It
// lives here only as the shared vocabulary a profile can adopt, and so
// that Aggregate can apply the minimum principle to it.
type BindingLevel int

const (
	BindingLow      BindingLevel = 0 // Printed static QR code.
	BindingMedium   BindingLevel = 1 // Single-use serial code, scan-locked after first redemption.
	BindingHigh     BindingLevel = 2 // NFC/RFID chip with challenge-response signature.
	BindingVeryHigh BindingLevel = 3 // Physical Unclonable Function (PUF) + chip signature.
)

func (b BindingLevel) String() string {
	switch b {
	case BindingLow:
		return "low"
	case BindingMedium:
		return "medium"
	case BindingHigh:
		return "high"
	case BindingVeryHigh:
		return "very_high"
	default:
		return fmt.Sprintf("BindingLevel(%d)", int(b))
	}
}

// Valid reports whether b is one of the four levels OWM-6 §5 defines.
func (b BindingLevel) Valid() bool { return b >= BindingLow && b <= BindingVeryHigh }
