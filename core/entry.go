// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"errors"
	"fmt"
	"time"
)

// FormatVersion ist die Version des Eintragsformats, die dieses Paket erzeugt
// und akzeptiert.
const FormatVersion = 1

// EntryType benennt die Art der Aussage.
type EntryType uint8

const (
	// EntryTypeAssertion ist die Selbstauskunft über ein Subjekt: Erzeugung,
	// Transport, Verarbeitung, Übergabe.
	EntryTypeAssertion EntryType = 1
	// EntryTypeAttestation ist eine Aussage über eine andere Entität oder einen
	// Schlüssel, etwa eine Zertifizierung. Das Subjekt ist dann die
	// Schlüsselkennung des Bestätigten.
	EntryTypeAttestation EntryType = 2
	// EntryTypeRevocation widerruft einen früheren Eintrag: die Aussage war
	// falsch oder gilt nicht mehr.
	EntryTypeRevocation EntryType = 3
	// EntryTypeKeyRotation kündigt einen Nachfolgeschlüssel an. Die Nutzlast
	// enthält den neuen öffentlichen Schlüssel und wird nicht gelöscht.
	EntryTypeKeyRotation EntryType = 4
	// EntryTypeSensorReading ist ein automatisch erfasster Messwert,
	// ausgestellt von einem Geräteschlüssel.
	EntryTypeSensorReading EntryType = 5
	// EntryTypeErasure bezeugt, dass Nutzlast und Salt eines früheren Eintrags
	// gelöscht wurden — der Grabstein nach einer Löschung.
	//
	// Ausdrücklich kein Widerruf: ein Widerruf ist eine Behauptung über die
	// Welt, eine Löschung eine Tatsache über den Speicher. Die Aussage des
	// gelöschten Eintrags bleibt gültig, nur ihr Beleg ist fort. Ohne diesen
	// eigenen Typ ließe sich rechtmäßige Löschung nicht von böswilligem
	// Zurückhalten unterscheiden (OWM-9 A3).
	EntryTypeErasure EntryType = 6
)

func (t EntryType) String() string {
	switch t {
	case EntryTypeAssertion:
		return "assertion"
	case EntryTypeAttestation:
		return "attestation"
	case EntryTypeRevocation:
		return "revocation"
	case EntryTypeKeyRotation:
		return "key_rotation"
	case EntryTypeSensorReading:
		return "sensor_reading"
	case EntryTypeErasure:
		return "erasure"
	default:
		return fmt.Sprintf("EntryType(%d)", uint8(t))
	}
}

// Valid meldet, ob der Typ von dieser Formatversion unterstützt wird.
func (t EntryType) Valid() bool {
	return t >= EntryTypeAssertion && t <= EntryTypeErasure
}

// RefersToEntry meldet, ob der Typ einen anderen Eintrag benennt und deshalb
// tgt führen muss.
func (t EntryType) RefersToEntry() bool {
	return t == EntryTypeRevocation || t == EntryTypeErasure
}

// maxProfileLen begrenzt die Profilkennung. Sie ist ein Bezeichner, kein
// Freitextfeld.
const maxProfileLen = 64

// MaxParents begrenzt die Zahl direkter Vorgänger eines Eintrags.
//
// Ohne Grenze könnte ein einziger Eintrag beliebig viel Speicher und Rechenzeit
// binden. Die Höhe ist an der Praxis bemessen: Eine Aggregation von tausend
// Einzelstücken auf eine Palette ist ein normales Lieferkettenereignis, mehr als
// tausend direkte Vorgänger in einem Schritt sind es nicht.
const MaxParents = 1024

// ErrTooManyParents meldet die Überschreitung von MaxParents.
var ErrTooManyParents = errors.New("owm: too many parents")

var (
	ErrVersion        = errors.New("owm: unknown format version")
	ErrEntryType      = errors.New("owm: unknown entry type")
	ErrMissingField   = errors.New("owm: missing required field")
	ErrUnexpectedTgt  = errors.New("owm: tgt is only allowed for revocation and erasure")
	ErrProfile        = errors.New("owm: invalid profile identifier")
	ErrIssuerMismatch = errors.New("owm: issuer does not match the key")
	ErrBadSignature   = errors.New("owm: invalid signature")
	ErrAlgMismatch    = errors.New("owm: signature algorithm does not match the key")
)

// EntryRef verweist auf einen anderen Eintrag.
//
// Log ist ein Hinweis für den Abruf und nicht Teil der Identität — derselbe
// Eintrag kann in mehreren Logs liegen. Ist das Log unbekannt, bleibt das Feld
// null.
type EntryRef struct {
	Entry Digest `json:"entry"`
	Log   LogID  `json:"log,omitempty"`
}

// Entry ist eine Aussage einer Entität über ein Subjekt.
//
// Die Nutzlast steht nicht hier, sondern off-chain; im Eintrag steht nur ihr
// Commitment. Kein Feld dieses Typs darf Klartext-Personendaten enthalten —
// auch Subject nicht, das ein opaker Bezeichner ist und kein Name, keine
// Anschrift und keine Koordinate.
type Entry struct {
	Version  uint16    `json:"v"`
	Type     EntryType `json:"typ"`
	Profile  string    `json:"prof,omitempty"`
	Subject  SubjectID `json:"subj"`
	IssuedAt int64     `json:"iat"` // Millisekunden seit Unix-Epoche, UTC
	Issuer   KeyID     `json:"iss"`

	// Commitment ist das gesalzene Commitment der Nutzlast. Nur bei revocation
	// und erasure darf es fehlen — beide brauchen keine eigene Nutzlast.
	Commitment Commitment `json:"cmt,omitempty"`

	// Parents bildet die Lieferkette als gerichteten azyklischen Graphen ab.
	// Mehrere Vorgänger bedeuten Zusammenführung, mehrere Einträge mit
	// demselben Vorgänger bedeuten Aufteilung. Die Ereignissemantik darauf
	// legt das Profil fest.
	Parents []EntryRef `json:"par,omitempty"`

	// Target benennt den betroffenen Eintrag: bei revocation den widerrufenen,
	// bei erasure den, dessen Nutzlast gelöscht wurde.
	Target *EntryRef `json:"tgt,omitempty"`
}

// IssuedAtTime liefert den Ausstellungszeitpunkt als time.Time in UTC.
func (e *Entry) IssuedAtTime() time.Time {
	return time.UnixMilli(e.IssuedAt).UTC()
}

// SetIssuedAt setzt den Ausstellungszeitpunkt auf Millisekundengenauigkeit.
func (e *Entry) SetIssuedAt(t time.Time) {
	e.IssuedAt = t.UTC().UnixMilli()
}

// Validate prüft die strukturellen Regeln aus spec/owm-0-overview.md §6.
// Ob der Inhalt zum Profil passt, prüft der Profilmechanismus, nicht dieses
// Paket.
func (e *Entry) Validate() error {
	if e.Version != FormatVersion {
		return fmt.Errorf("%w: %d", ErrVersion, e.Version)
	}
	if !e.Type.Valid() {
		return fmt.Errorf("%w: %d", ErrEntryType, uint8(e.Type))
	}
	if e.Subject.IsZero() {
		return fmt.Errorf("%w: subj", ErrMissingField)
	}
	if e.Issuer.IsZero() {
		return fmt.Errorf("%w: iss", ErrMissingField)
	}
	if e.IssuedAt <= 0 {
		return fmt.Errorf("%w: iat", ErrMissingField)
	}
	if err := validateProfile(e.Profile); err != nil {
		return err
	}

	// Widerruf und Löschbezeugung brauchen keine eigene Nutzlast; jeder andere
	// Typ ohne Commitment sagt nichts aus.
	if e.Commitment.IsZero() && !e.Type.RefersToEntry() {
		return fmt.Errorf("%w: cmt on %s", ErrMissingField, e.Type)
	}

	switch {
	case e.Type.RefersToEntry() && e.Target == nil:
		return fmt.Errorf("%w: tgt on %s", ErrMissingField, e.Type)
	case !e.Type.RefersToEntry() && e.Target != nil:
		return fmt.Errorf("%w: %s", ErrUnexpectedTgt, e.Type)
	}
	if e.Target != nil && e.Target.Entry.IsZero() {
		return fmt.Errorf("%w: tgt.entry", ErrMissingField)
	}
	if len(e.Parents) > MaxParents {
		return fmt.Errorf("%w: %d, allowed %d", ErrTooManyParents, len(e.Parents), MaxParents)
	}
	for i, p := range e.Parents {
		if p.Entry.IsZero() {
			return fmt.Errorf("%w: par[%d].entry", ErrMissingField, i)
		}
	}
	return nil
}

// validateProfile beschränkt die Profilkennung auf einen Bezeichner-Zeichensatz.
// Sonst landen dort früher oder später Freitext, Steuerzeichen oder
// Pfadangaben.
func validateProfile(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxProfileLen {
		return fmt.Errorf("%w: longer than %d characters", ErrProfile, maxProfileLen)
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '/', r == '-', r == '_':
		default:
			return fmt.Errorf("%w: invalid character %q", ErrProfile, r)
		}
	}
	return nil
}

// ID liefert die Inhaltsadresse des Eintrags.
//
// Die Kennung deckt den Eintrag ab, nicht seine Signatur. Damit bleibt sie
// stabil, wenn derselbe Eintrag erneut oder von mehreren Parteien signiert wird
// — ML-DSA signiert im Normalfall randomisiert, eine signaturabhängige Kennung
// wäre nicht reproduzierbar.
func (e *Entry) ID() (Digest, error) {
	b, err := e.Encode()
	if err != nil {
		return Digest{}, err
	}
	return EntryIDFromBytes(b), nil
}

// EntryIDFromBytes berechnet die Inhaltsadresse aus der bereits kanonisch
// kodierten Form.
func EntryIDFromBytes(canonical []byte) Digest {
	return hashLabeled(labelEntryID, canonical)
}

// SignedEntry ist ein Eintrag mit Signatur.
//
// EntryBytes hält die kanonische Kodierung als opaken Bytestring. Signiert und
// geprüft werden immer genau diese Bytes; eine erneute Kodierung, die abweichen
// könnte, findet nie statt. Die Lehre stammt aus JWS und COSE, wo genau diese
// Mehrdeutigkeit zu Sicherheitslücken geführt hat.
type SignedEntry struct {
	EntryBytes []byte `json:"e"`
	Alg        SigAlg `json:"alg"`
	Signature  []byte `json:"sig"`
}

// SignEntry kodiert den Eintrag kanonisch und signiert ihn.
//
// Der Aussteller im Eintrag muss zum Schlüssel passen; sonst entstünde ein
// Eintrag, der zwar eine gültige Signatur trägt, aber niemandem zurechenbar ist.
func SignEntry(k *PrivateKey, e *Entry) (*SignedEntry, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: private key", ErrMissingField)
	}
	if e.Issuer != k.Public().ID() {
		return nil, fmt.Errorf("%w: iss=%s, key=%s", ErrIssuerMismatch, e.Issuer, k.Public().ID())
	}
	b, err := e.Encode()
	if err != nil {
		return nil, err
	}
	sig, err := k.Sign(SigContextEntry, b)
	if err != nil {
		return nil, err
	}
	return &SignedEntry{EntryBytes: b, Alg: k.Alg(), Signature: sig}, nil
}

// Entry dekodiert den eingebetteten Eintrag und prüft dabei seine Kanonizität.
func (s *SignedEntry) Entry() (*Entry, error) {
	return ParseEntry(s.EntryBytes)
}

// EntryID liefert die Inhaltsadresse des eingebetteten Eintrags.
func (s *SignedEntry) EntryID() Digest {
	return EntryIDFromBytes(s.EntryBytes)
}

// Verify prüft die Signatur gegen den angegebenen öffentlichen Schlüssel.
//
// Geprüft wird ausdrücklich auch, dass der Aussteller im Eintrag die Kennung
// dieses Schlüssels ist. Ohne diese Prüfung ließe sich jeder Eintrag mit einem
// beliebigen Schlüssel „bestätigen" und die Zurechenbarkeit wäre dahin.
func (s *SignedEntry) Verify(pub *PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: public key", ErrMissingField)
	}
	if s.Alg != pub.Alg() {
		return fmt.Errorf("%w: entry %s, key %s", ErrAlgMismatch, s.Alg, pub.Alg())
	}
	e, err := s.Entry()
	if err != nil {
		return err
	}
	if e.Issuer != pub.ID() {
		return fmt.Errorf("%w: iss=%s, key=%s", ErrIssuerMismatch, e.Issuer, pub.ID())
	}
	if !pub.Verify(SigContextEntry, s.EntryBytes, s.Signature) {
		return ErrBadSignature
	}
	return nil
}
