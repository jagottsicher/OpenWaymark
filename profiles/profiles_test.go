// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package profiles_test

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles"
)

const minimalSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["a"],
  "properties": { "a": { "type": "string" }, "b": { "$ref": "extra.json" } },
  "unevaluatedProperties": false
}`

const extraSchema = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "integer",
  "minimum": 1
}`

func testFS() fstest.MapFS {
	return fstest.MapFS{
		"event.json": {Data: []byte(minimalSchema)},
		"extra.json": {Data: []byte(extraSchema)},
		"README.md":  {Data: []byte("is ignored")},
	}
}

func testProfile(t *testing.T) *profiles.Profile {
	t.Helper()
	p, err := profiles.Load(profiles.Options{ID: "test.v1", FS: testFS(), Root: "event.json"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

func TestValidate(t *testing.T) {
	p := testProfile(t)
	cases := []struct {
		name    string
		payload string
		ok      bool
	}{
		{"valid", `{"a":"x"}`, true},
		{"valid with $ref", `{"a":"x","b":3}`, true},
		{"missing required field", `{"b":3}`, false},
		{"wrong type", `{"a":1}`, false},
		{"$ref violated", `{"a":"x","b":0}`, false},
		{"unknown field", `{"a":"x","c":true}`, false},
		{"not an object", `["a"]`, false},
		{"broken JSON", `{"a":`, false},
		{"empty", ``, false},
		{"trailing text", `{"a":"x"} {"a":"y"}`, false},
		{"duplicate key", `{"a":"x","a":"y"}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := p.Validate([]byte(c.payload))
			if c.ok && err != nil {
				t.Fatalf("unexpectedly rejected: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("unexpectedly accepted")
			}
		})
	}
}

// Dieselben Bytes müssen überall dasselbe bedeuten. Nimmt eine Implementierung
// bei doppeltem Schlüssel den letzten Wert und eine andere den ersten, sagt
// dieselbe, durch das Commitment festgeschriebene Nutzlast zweierlei.
func TestDuplicateKeyRejected(t *testing.T) {
	p := testProfile(t)
	err := p.Validate([]byte(`{"a":"first","a":"second"}`))
	if !errors.Is(err, profiles.ErrPayload) {
		t.Fatalf("expected ErrPayload, got %v", err)
	}
	if !strings.Contains(err.Error(), `"a"`) {
		t.Fatalf("the error does not name the key: %v", err)
	}
}

// Eine tief verschachtelte Nutzlast darf den Prozess nicht über den Stapel
// hinaustreiben.
func TestDepthLimit(t *testing.T) {
	p := testProfile(t)
	deep := strings.Repeat(`{"a":`, 5000) + `"x"` + strings.Repeat(`}`, 5000)
	if err := p.Validate([]byte(deep)); !errors.Is(err, profiles.ErrPayload) {
		t.Fatalf("expected ErrPayload, got %v", err)
	}
}

func TestSchemaDigestStableAndSensitive(t *testing.T) {
	a := testProfile(t)
	b := testProfile(t)
	if a.SchemaDigest() != b.SchemaDigest() {
		t.Fatal("the same set of files produces different digests")
	}
	if a.SchemaDigest().IsZero() {
		t.Fatal("digest is zero")
	}

	changed := testFS()
	changed["extra.json"] = &fstest.MapFile{Data: []byte(`{"type":"integer","minimum":2}`)}
	c, err := profiles.Load(profiles.Options{ID: "test.v1", FS: changed, Root: "event.json"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.SchemaDigest() == a.SchemaDigest() {
		t.Fatal("changed rules produce the same digest")
	}

	// Auch die Kennung geht ein: dasselbe Schema unter anderem Namen ist ein
	// anderes Profil.
	d, err := profiles.Load(profiles.Options{ID: "test.v2", FS: testFS(), Root: "event.json"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if d.SchemaDigest() == a.SchemaDigest() {
		t.Fatal("a different identifier produces the same digest")
	}
}

func TestLoadRejectsRemoteRef(t *testing.T) {
	fsys := fstest.MapFS{"event.json": {Data: []byte(
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":"https://example.invalid/x.json"}`)}}
	_, err := profiles.Load(profiles.Options{ID: "remote.v1", FS: fsys, Root: "event.json"})
	if err == nil {
		t.Fatal("a reference to the network was accepted")
	}
	if !strings.Contains(err.Error(), "foreign schema source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		opt  profiles.Options
	}{
		{"empty identifier", profiles.Options{FS: testFS(), Root: "event.json"}},
		{"invalid character", profiles.Options{ID: "Food.v1", FS: testFS(), Root: "event.json"}},
		{"no file system", profiles.Options{ID: "test.v1", Root: "event.json"}},
		{"empty file system", profiles.Options{ID: "test.v1", FS: fstest.MapFS{}, Root: "event.json"}},
		{"root missing", profiles.Options{ID: "test.v1", FS: testFS(), Root: "gibtsnicht.json"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := profiles.Load(c.opt); err == nil {
				t.Fatal("unexpectedly accepted")
			}
		})
	}
}

func TestRegistry(t *testing.T) {
	r := profiles.NewRegistry()
	p := testProfile(t)
	if err := r.Add(p); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := r.Add(p); !errors.Is(err, profiles.ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	if err := r.Add(nil); err == nil {
		t.Fatal("nil accepted")
	}
	if got, ok := r.Get("test.v1"); !ok || got != p {
		t.Fatal("profile not found")
	}
	if _, ok := r.Get("food.v1"); ok {
		t.Fatal("unknown profile found")
	}
	if ids := r.IDs(); len(ids) != 1 || ids[0] != "test.v1" {
		t.Fatalf("unexpected identifiers: %v", ids)
	}
	if all := r.All(); len(all) != 1 || all[0] != p {
		t.Fatalf("unexpected profile list: %v", all)
	}
}

func TestRegistryCheck(t *testing.T) {
	r := profiles.NewRegistry()
	if err := r.Add(testProfile(t)); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Ohne Profilkennung gibt es nichts zu prüfen — der Kern schreibt kein
	// Profil vor.
	if err := r.Check(&core.Entry{}, []byte("not json")); err != nil {
		t.Fatalf("entry without a profile rejected: %v", err)
	}
	if err := r.Check(&core.Entry{Profile: "test.v1"}, []byte(`{"a":"x"}`)); err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if err := r.Check(&core.Entry{Profile: "food.v1"}, []byte(`{"a":"x"}`)); !errors.Is(err, profiles.ErrUnknown) {
		t.Fatalf("expected ErrUnknown, got %v", err)
	}
	if err := r.Check(&core.Entry{Profile: "test.v1"}, []byte(`{}`)); !errors.Is(err, profiles.ErrSchema) {
		t.Fatalf("expected ErrSchema, got %v", err)
	}
	if err := r.Check(nil, nil); err == nil {
		t.Fatal("nil entry accepted")
	}
}

func TestRuleRunsAfterSchema(t *testing.T) {
	var seen int
	p, err := profiles.Load(profiles.Options{
		ID:   "test.v1",
		FS:   testFS(),
		Root: "event.json",
		Rule: func(e *core.Entry, payload []byte) error {
			seen++
			if e.Type != core.EntryTypeAssertion {
				return errors.New("wrong entry type")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Schemafehler: die Regel darf gar nicht erst laufen.
	if err := p.Check(&core.Entry{Type: core.EntryTypeAssertion}, []byte(`{}`)); !errors.Is(err, profiles.ErrSchema) {
		t.Fatalf("expected ErrSchema, got %v", err)
	}
	if seen != 0 {
		t.Fatal("rule ran despite the schema error")
	}
	if err := p.Check(&core.Entry{Type: core.EntryTypeAssertion}, []byte(`{"a":"x"}`)); err != nil {
		t.Fatalf("valid entry rejected: %v", err)
	}
	if err := p.Check(&core.Entry{Type: core.EntryTypeSensorReading}, []byte(`{"a":"x"}`)); !errors.Is(err, profiles.ErrEntry) {
		t.Fatalf("expected ErrEntry, got %v", err)
	}
}

func TestFilesAreCopies(t *testing.T) {
	p := testProfile(t)
	files := p.Files()
	if len(files) != 2 {
		t.Fatalf("expected 2 schema files, got %d", len(files))
	}
	if files[0].Name != "event.json" || files[1].Name != "extra.json" {
		t.Fatalf("unexpected names: %v, %v", files[0].Name, files[1].Name)
	}
	files[0].Name = "manipuliert"
	if p.Files()[0].Name != "event.json" {
		t.Fatal("Files hands out the internal data")
	}
}

func TestCheckID(t *testing.T) {
	ok := []string{"food.v1", "eu/battery.v1", "a", "x_y-z.0"}
	for _, id := range ok {
		if err := profiles.CheckID(id); err != nil {
			t.Errorf("%q rejected: %v", id, err)
		}
	}
	bad := []string{"", "Food.v1", "food v1", "food:v1", "ümlaut", strings.Repeat("a", 65)}
	for _, id := range bad {
		if err := profiles.CheckID(id); err == nil {
			t.Errorf("%q accepted", id)
		}
	}
}
