// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Die Testvektoren sind Teil der Spezifikation, nicht bloß Testbeiwerk: Eine
// Fremdimplementierung gilt als konform, wenn sie sie Byte für Byte
// reproduziert. Deshalb liegen sie als lesbare Datei im Repo und werden nicht
// bei jedem Lauf neu erzeugt — eine Änderung an ihnen ist eine Änderung am
// Protokoll und muss im Diff sichtbar werden.
//
//	go test ./core/ -update
var updateVectors = flag.Bool("update", false, "regenerate the test vectors in testdata/vectors")

const vectorPath = "../testdata/vectors/core-v1.json"

type hexBytes []byte

func (h hexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *hexBytes) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	d, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = d
	return nil
}

type vectorFile struct {
	Note          string             `json:"note"`
	Spec          string             `json:"spec"`
	FormatVersion uint16             `json:"format_version"`
	HashLabels    []labelVector      `json:"hash_labels"`
	SubjectIDs    []subjectVector    `json:"subject_ids"`
	Keys          []keyVector        `json:"keys"`
	Commitments   []commitmentVector `json:"commitments"`
	Entries       []entryVector      `json:"entries"`
}

type labelVector struct {
	Label  string     `json:"label"`
	Parts  []hexBytes `json:"parts"`
	Digest hexBytes   `json:"digest"`
}

type subjectVector struct {
	Namespace string   `json:"namespace"`
	Value     string   `json:"value_utf8"`
	SubjectID hexBytes `json:"subject_id"`
}

type keyVector struct {
	Alg       uint16   `json:"alg"`
	AlgName   string   `json:"alg_name"`
	Seed      hexBytes `json:"seed"`
	PublicKey hexBytes `json:"public_key"`
	KeyID     hexBytes `json:"key_id"`
}

type commitmentVector struct {
	Salt       hexBytes `json:"salt"`
	Payload    string   `json:"payload_utf8"`
	Commitment hexBytes `json:"commitment"`
}

type refView struct {
	Entry string `json:"entry"`
	Log   string `json:"log,omitempty"`
}

type entryView struct {
	Version    uint16    `json:"v"`
	Type       uint8     `json:"typ"`
	TypeName   string    `json:"typ_name"`
	Profile    string    `json:"prof,omitempty"`
	Subject    string    `json:"subj"`
	IssuedAt   int64     `json:"iat"`
	Issuer     string    `json:"iss"`
	Commitment string    `json:"cmt,omitempty"`
	Parents    []refView `json:"par,omitempty"`
	Target     *refView  `json:"tgt,omitempty"`
}

type entryVector struct {
	Name  string    `json:"name"`
	Note  string    `json:"note"`
	Entry entryView `json:"entry"`

	Alg       uint16   `json:"alg"`
	AlgName   string   `json:"alg_name"`
	KeySeed   hexBytes `json:"key_seed"`
	EntryCBOR hexBytes `json:"entry_cbor"`
	EntryID   hexBytes `json:"entry_id"`

	// SignatureDeterministic ist mit dem deterministischen Zweig von FIPS 204
	// erzeugt und damit reproduzierbar. Im Betrieb wird randomisiert signiert;
	// dort ist jede Signatur anders und trotzdem gültig.
	SignatureDeterministic hexBytes `json:"signature_deterministic"`
	SignedEntryCBOR        hexBytes `json:"signed_entry_cbor"`
}

func viewRef(r EntryRef) refView {
	v := refView{Entry: r.Entry.String()}
	if !r.Log.IsZero() {
		v.Log = r.Log.String()
	}
	return v
}

func viewEntry(e *Entry) entryView {
	v := entryView{
		Version:  e.Version,
		Type:     uint8(e.Type),
		TypeName: e.Type.String(),
		Profile:  e.Profile,
		Subject:  e.Subject.String(),
		IssuedAt: e.IssuedAt,
		Issuer:   e.Issuer.String(),
	}
	if !e.Commitment.IsZero() {
		v.Commitment = e.Commitment.String()
	}
	for _, p := range e.Parents {
		v.Parents = append(v.Parents, viewRef(p))
	}
	if e.Target != nil {
		r := viewRef(*e.Target)
		v.Target = &r
	}
	return v
}

// vectorFixtures beschreibt die Fälle, die abgedeckt sein müssen: jeder
// Eintragstyp, beide Signaturstufen, mit und ohne optionale Felder.
type vectorFixture struct {
	name  string
	note  string
	alg   SigAlg
	seed  byte
	build func(k *PrivateKey) *Entry
}

func vectorFixtures() []vectorFixture {
	subject := DeriveSubjectID("owm:batch", []byte("2026-08-10-A"))
	payload := []byte(`{"typ":"harvest","lot":"2026-08-10-A"}`)
	parentA := hashLabeled(labelEntryID, []byte("parent a"))
	parentB := hashLabeled(labelEntryID, []byte("parent b"))
	logID := LogID(hashLabeled(labelLogID, []byte("beispiel-log")))

	base := func(k *PrivateKey) *Entry {
		return &Entry{
			Version:    FormatVersion,
			Type:       EntryTypeAssertion,
			Subject:    subject,
			IssuedAt:   testIssuedAt,
			Issuer:     k.Public().ID(),
			Commitment: Commit(fixtureSalt, payload),
		}
	}

	return []vectorFixture{
		{
			name: "assertion-minimal",
			note: "All optional fields are absent. The map has exactly six pairs.",
			alg:  SigAlgMLDSA65, seed: 0x01,
			build: base,
		},
		{
			name: "assertion-with-parents",
			note: "Merge of two parents, one of them with a log hint.",
			alg:  SigAlgMLDSA65, seed: 0x01,
			build: func(k *PrivateKey) *Entry {
				e := base(k)
				e.Profile = "owm.food/1"
				e.Parents = []EntryRef{{Entry: parentA}, {Entry: parentB, Log: logID}}
				return e
			},
		},
		{
			name: "revocation",
			note: "Revocation without a payload: cmt is absent, tgt is set.",
			alg:  SigAlgMLDSA65, seed: 0x01,
			build: func(k *PrivateKey) *Entry {
				e := base(k)
				e.Type = EntryTypeRevocation
				e.Commitment = Commitment{}
				e.Target = &EntryRef{Entry: parentA}
				return e
			},
		},
		{
			name: "erasure",
			note: "Erasure attestation: same shape as the revocation, different statement. " +
				"The payload of the target entry has been erased together with its salt, its leaf stays in the tree.",
			alg: SigAlgMLDSA65, seed: 0x01,
			build: func(k *PrivateKey) *Entry {
				e := base(k)
				e.Type = EntryTypeErasure
				e.Commitment = Commitment{}
				e.Target = &EntryRef{Entry: parentA, Log: logID}
				return e
			},
		},
		{
			name: "key-rotation",
			note: "The payload carries the successor key and is not erased.",
			alg:  SigAlgMLDSA65, seed: 0x01,
			build: func(k *PrivateKey) *Entry {
				e := base(k)
				e.Type = EntryTypeKeyRotation
				e.Subject = SubjectID(k.Public().ID())
				e.Commitment = Commit(fixtureSalt, []byte("successor key"))
				return e
			},
		},
		{
			name: "sensor-reading-mldsa44",
			note: "Device key with ML-DSA-44: 2420 instead of 3309 signature bytes.",
			alg:  SigAlgMLDSA44, seed: 0x02,
			build: func(k *PrivateKey) *Entry {
				e := base(k)
				e.Type = EntryTypeSensorReading
				e.Profile = "owm.food/1"
				e.Commitment = Commit(fixtureSalt, []byte(`{"temp_c":4.2,"t":"2026-01-01T00:00:00Z"}`))
				return e
			},
		},
	}
}

func buildVectors(t *testing.T) *vectorFile {
	t.Helper()

	out := &vectorFile{
		Note: "Test vectors for openwaymark.org/owm/core. Part of the specification: " +
			"a conforming implementation reproduces them byte for byte. " +
			"Generate with: go test ./core/ -update",
		Spec:          "spec/owm-0-overview.md",
		FormatVersion: FormatVersion,
	}

	// Domänengetrennter Hash, inklusive des Falls, in dem sich die
	// Argumentaufteilung verschiebt — dort schlägt eine Implementierung ohne
	// Längenpräfixe fehl.
	for _, c := range []struct {
		label string
		parts [][]byte
	}{
		{"OWM/1 example", nil},
		{"OWM/1 example", [][]byte{{}}},
		{"OWM/1 example", [][]byte{[]byte("ab"), []byte("c")}},
		{"OWM/1 example", [][]byte{[]byte("a"), []byte("bc")}},
	} {
		d := hashLabeled(c.label, c.parts...)
		v := labelVector{Label: c.label, Digest: d[:]}
		v.Parts = []hexBytes{}
		for _, p := range c.parts {
			v.Parts = append(v.Parts, p)
		}
		out.HashLabels = append(out.HashLabels, v)
	}

	for _, c := range []struct{ ns, val string }{
		{"owm:batch", "2026-08-10-A"},
		{"gs1:sgtin", "0614141.812345.6789"},
	} {
		id := DeriveSubjectID(c.ns, []byte(c.val))
		out.SubjectIDs = append(out.SubjectIDs, subjectVector{
			Namespace: c.ns, Value: c.val, SubjectID: id[:],
		})
	}

	for _, c := range []struct {
		alg  SigAlg
		seed byte
	}{{SigAlgMLDSA44, 0x02}, {SigAlgMLDSA65, 0x01}} {
		k := keyFromSeedByte(t, c.alg, c.seed)
		id := k.Public().ID()
		out.Keys = append(out.Keys, keyVector{
			Alg:       uint16(c.alg),
			AlgName:   c.alg.String(),
			Seed:      bytes.Repeat([]byte{c.seed}, c.alg.SeedSize()),
			PublicKey: k.Public().Bytes(),
			KeyID:     id[:],
		})
	}

	for _, payload := range []string{
		"",
		`{"typ":"harvest","lot":"2026-08-10-A"}`,
		"53175",
	} {
		c := Commit(fixtureSalt, []byte(payload))
		out.Commitments = append(out.Commitments, commitmentVector{
			Salt: fixtureSalt[:], Payload: payload, Commitment: c[:],
		})
	}

	for _, f := range vectorFixtures() {
		k := keyFromSeedByte(t, f.alg, f.seed)
		e := f.build(k)

		enc, err := e.Encode()
		if err != nil {
			t.Fatalf("%s: Encode: %v", f.name, err)
		}
		sig, err := k.SignDeterministic(SigContextEntry, enc)
		if err != nil {
			t.Fatalf("%s: SignDeterministic: %v", f.name, err)
		}
		se := &SignedEntry{EntryBytes: enc, Alg: f.alg, Signature: sig}
		seEnc, err := se.Encode()
		if err != nil {
			t.Fatalf("%s: SignedEntry.Encode: %v", f.name, err)
		}
		id := EntryIDFromBytes(enc)

		out.Entries = append(out.Entries, entryVector{
			Name:                   f.name,
			Note:                   f.note,
			Entry:                  viewEntry(e),
			Alg:                    uint16(f.alg),
			AlgName:                f.alg.String(),
			KeySeed:                bytes.Repeat([]byte{f.seed}, f.alg.SeedSize()),
			EntryCBOR:              enc,
			EntryID:                id[:],
			SignatureDeterministic: sig,
			SignedEntryCBOR:        seEnc,
		})
	}

	return out
}

func TestVectors(t *testing.T) {
	got := buildVectors(t)

	if *updateVectors {
		b, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("MarshalIndent: %v", err)
		}
		b = append(b, '\n')
		if err := os.MkdirAll(filepath.Dir(vectorPath), 0o755); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(vectorPath, b, 0o644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		t.Logf("test vectors written: %s", vectorPath)
		return
	}

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("test vectors unreadable (generate with: go test ./core/ -update): %v", err)
	}
	var want vectorFile
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("test vectors unreadable: %v", err)
	}

	if want.FormatVersion != got.FormatVersion {
		t.Fatalf("format version %d in the file, %d in the code", want.FormatVersion, got.FormatVersion)
	}

	compare := func(name string, a, b []byte) {
		t.Helper()
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs\n  file: %x\n  code: %x", name, a, b)
		}
	}

	if len(want.HashLabels) != len(got.HashLabels) {
		t.Fatalf("hash_labels: %d in the file, %d in the code", len(want.HashLabels), len(got.HashLabels))
	}
	for i := range got.HashLabels {
		compare("hash_labels["+got.HashLabels[i].Label+"]", want.HashLabels[i].Digest, got.HashLabels[i].Digest)
	}

	if len(want.SubjectIDs) != len(got.SubjectIDs) {
		t.Fatalf("subject_ids: %d in the file, %d in the code", len(want.SubjectIDs), len(got.SubjectIDs))
	}
	for i := range got.SubjectIDs {
		compare("subject_ids["+got.SubjectIDs[i].Namespace+"]", want.SubjectIDs[i].SubjectID, got.SubjectIDs[i].SubjectID)
	}

	if len(want.Keys) != len(got.Keys) {
		t.Fatalf("keys: %d in the file, %d in the code", len(want.Keys), len(got.Keys))
	}
	for i := range got.Keys {
		n := got.Keys[i].AlgName
		compare("keys["+n+"].public_key", want.Keys[i].PublicKey, got.Keys[i].PublicKey)
		compare("keys["+n+"].key_id", want.Keys[i].KeyID, got.Keys[i].KeyID)
	}

	if len(want.Commitments) != len(got.Commitments) {
		t.Fatalf("commitments: %d in the file, %d in the code", len(want.Commitments), len(got.Commitments))
	}
	for i := range got.Commitments {
		compare("commitments["+got.Commitments[i].Payload+"]", want.Commitments[i].Commitment, got.Commitments[i].Commitment)
	}

	if len(want.Entries) != len(got.Entries) {
		t.Fatalf("entries: %d in the file, %d in the code", len(want.Entries), len(got.Entries))
	}
	for i := range got.Entries {
		n := got.Entries[i].Name
		compare("entries["+n+"].entry_cbor", want.Entries[i].EntryCBOR, got.Entries[i].EntryCBOR)
		compare("entries["+n+"].entry_id", want.Entries[i].EntryID, got.Entries[i].EntryID)
		compare("entries["+n+"].signature_deterministic",
			want.Entries[i].SignatureDeterministic, got.Entries[i].SignatureDeterministic)
		compare("entries["+n+"].signed_entry_cbor", want.Entries[i].SignedEntryCBOR, got.Entries[i].SignedEntryCBOR)
	}
}

// TestVectorsAreSelfConsistent prüft die Datei ohne Rückgriff auf den
// Erzeugungscode — so, wie es eine Fremdimplementierung täte.
func TestVectorsAreSelfConsistent(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Skipf("test vectors missing (generate with: go test ./core/ -update): %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("test vectors unreadable: %v", err)
	}

	keyByAlg := map[SigAlg]*keyVector{}
	for i := range vf.Keys {
		k := &vf.Keys[i]
		alg := SigAlg(k.Alg)
		pub, err := ParsePublicKey(alg, k.PublicKey)
		if err != nil {
			t.Fatalf("keys[%s]: ParsePublicKey: %v", k.AlgName, err)
		}
		id := pub.ID()
		if !bytes.Equal(id[:], k.KeyID) {
			t.Errorf("keys[%s]: identifier does not match the public key", k.AlgName)
		}
		derived, err := NewKeyFromSeed(alg, k.Seed)
		if err != nil {
			t.Fatalf("keys[%s]: NewKeyFromSeed: %v", k.AlgName, err)
		}
		if !bytes.Equal(derived.Public().Bytes(), k.PublicKey) {
			t.Errorf("keys[%s]: seed produces a different public key", k.AlgName)
		}
		keyByAlg[alg] = k
	}

	for i := range vf.Commitments {
		c := &vf.Commitments[i]
		var salt Salt
		if len(c.Salt) != SaltSize {
			t.Fatalf("commitments[%d]: salt has %d bytes", i, len(c.Salt))
		}
		copy(salt[:], c.Salt)
		want, err := DigestFromBytes(c.Commitment)
		if err != nil {
			t.Fatalf("commitments[%d]: %v", i, err)
		}
		if !VerifyCommitment(Commitment(want), salt, []byte(c.Payload)) {
			t.Errorf("commitments[%d]: commitment does not match salt and payload", i)
		}
	}

	for i := range vf.Entries {
		ev := &vf.Entries[i]
		t.Run(ev.Name, func(t *testing.T) {
			alg := SigAlg(ev.Alg)

			e, err := ParseEntry(ev.EntryCBOR)
			if err != nil {
				t.Fatalf("ParseEntry: %v", err)
			}
			again, err := e.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if !bytes.Equal(again, ev.EntryCBOR) {
				t.Error("entry_cbor is not canonical")
			}
			id := EntryIDFromBytes(ev.EntryCBOR)
			if !bytes.Equal(id[:], ev.EntryID) {
				t.Errorf("entry_id does not match entry_cbor")
			}

			kv := keyByAlg[alg]
			if kv == nil {
				t.Fatalf("no key vector for %s", alg)
			}
			pub, err := ParsePublicKey(alg, kv.PublicKey)
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if e.Issuer != pub.ID() {
				t.Error("the issuer in the entry does not match the key vector")
			}

			se, err := ParseSignedEntry(ev.SignedEntryCBOR)
			if err != nil {
				t.Fatalf("ParseSignedEntry: %v", err)
			}
			if !bytes.Equal(se.EntryBytes, ev.EntryCBOR) {
				t.Error("the embedded entry differs from entry_cbor")
			}
			if !bytes.Equal(se.Signature, ev.SignatureDeterministic) {
				t.Error("the signature in the envelope differs from signature_deterministic")
			}
			if err := se.Verify(pub); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}
