// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package profiles hält den Profilmechanismus von OpenWaymark: die Zuordnung
// von einer Profilkennung im Eintrag zu einem Satz JSON-Schemata, gegen den die
// zugehörige Nutzlast geprüft wird.
//
// Der Kern kennt keine Branchensemantik. Ein Eintrag trägt nur eine
// Profilkennung wie "food.v1"; was ein "processing"-Ereignis bedeutet und
// welche Felder es braucht, legt allein das Profil fest. Neue Branchen kommen
// als neues Profil dazu, ohne dass sich am Datenmodell etwas ändert.
//
// # Was die Schemaprüfung leistet — und was nicht
//
// Sie ist ein Eingangsfilter, keine Wahrheitsaussage. Ein schemakonformer
// Eintrag kann eine vollständige Lüge sein: Das Schema prüft Form, nicht
// Wirklichkeit. Es hält Tippfehler, fehlende Pflichtfelder und
// Formatverwechslungen aus dem Log fern, damit die Kette später überhaupt
// maschinell auswertbar ist. Die Bindung an den Eintrag leistet nicht das
// Schema, sondern das Commitment (core.Commit); die Zurechenbarkeit leistet die
// Signatur. Siehe spec/owm-9-threat-model.md zum Orakelproblem.
//
// # Unveränderlichkeit
//
// Eine Profilversion ist unveränderlich. Ist "food.v1" einmal veröffentlicht,
// ändert sich sein Schema nie wieder — sonst wäre ein Eintrag von gestern
// heute ungültig, obwohl niemand ihn angefasst hat, und ein Monitor könnte
// nicht mehr nachvollziehen, wogegen die Node damals geprüft hat. Änderungen
// erscheinen als neue Kennung ("food.v2"). SchemaDigest macht die verwendeten
// Regeln nachprüfbar.
package profiles

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"openwaymark.org/owm/core"
)

// Fehler dieses Pakets.
var (
	// ErrUnknown meldet eine Profilkennung, die diese Node nicht geladen hat.
	ErrUnknown = errors.New("owm/profiles: unknown profile")
	// ErrDuplicate meldet eine bereits belegte Kennung im Register.
	ErrDuplicate = errors.New("owm/profiles: profile already registered")
	// ErrPayload meldet eine Nutzlast, die kein auswertbares JSON ist.
	ErrPayload = errors.New("owm/profiles: payload is unreadable")
	// ErrSchema meldet eine Nutzlast, die dem Profilschema widerspricht.
	ErrSchema = errors.New("owm/profiles: payload does not match the schema")
	// ErrEntry meldet einen Eintrag, der zur Nutzlast nicht passt.
	ErrEntry = errors.New("owm/profiles: entry does not match the payload")
)

// maxDepth begrenzt die Verschachtelung einer Nutzlast.
//
// Der Decoder unten läuft rekursiv, und die Nutzlast kommt von außen. Ohne
// Grenze genügt eine Kette aus Klammern, um den Stapel wachsen zu lassen, bis
// der Prozess stirbt. Ein Lieferkettenereignis mit dreißig Ebenen gibt es
// nicht; die Grenze kostet keinen realen Anwendungsfall.
const maxDepth = 32

// schemaBase ist der Namensraum, unter dem Profilschemata beim Compiler
// registriert werden. Die URL wird nie abgerufen — sie dient nur als
// Auflösungsbasis für relative $ref.
const schemaBase = "https://openwaymark.org/schema/"

// labelSchemaDigest trennt den Schema-Digest von jedem anderen Hashwert im
// System.
const labelSchemaDigest = "OWM/1 profile-schema"

// Rule prüft profilspezifische Bedingungen, die sich im JSON-Schema nicht
// ausdrücken lassen, weil sie den Eintrag selbst betreffen — etwa dass eine
// Messreihe als Sensorlesung und nicht als Behauptung eingetragen wird.
//
// payload ist bereits schemakonform, wenn die Regel läuft.
type Rule func(e *core.Entry, payload []byte) error

// File ist eine Schemadatei eines Profils, so wie sie ausgeliefert wird.
type File struct {
	Name string
	Data []byte
}

// Profile ist ein geladenes Schema-Profil.
type Profile struct {
	id     string
	title  string
	root   *jsonschema.Schema
	files  []File
	digest core.Digest
	rule   Rule
}

// Options beschreibt ein zu ladendes Profil.
type Options struct {
	// ID ist die Profilkennung, wie sie im Eintrag steht, etwa "food.v1".
	ID string
	// Title ist eine kurze Beschreibung für Menschen.
	Title string
	// FS enthält die Schemadateien; alle *.json darin werden geladen.
	FS fs.FS
	// Root ist der Pfad des Wurzelschemas innerhalb von FS.
	Root string
	// Rule ist optional und prüft den Eintrag gegen die Nutzlast.
	Rule Rule
}

// Load übersetzt die Schemadateien und baut daraus ein Profil.
//
// Fehler hier sind Programmierfehler im Profil selbst, keine Laufzeitfälle:
// Profile werden beim Start geladen, nicht zur Bearbeitungszeit.
func Load(opt Options) (*Profile, error) {
	if err := CheckID(opt.ID); err != nil {
		return nil, err
	}
	if opt.FS == nil {
		return nil, fmt.Errorf("owm/profiles: %s: no file system given", opt.ID)
	}
	files, err := collect(opt.FS)
	if err != nil {
		return nil, fmt.Errorf("owm/profiles: %s: %w", opt.ID, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("owm/profiles: %s: no schema files found", opt.ID)
	}

	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	// "format" ist im Standard nur eine Anmerkung. Für ein Profil ist es genau
	// die Prüfung, die zählt: Ein Zeitstempel, der keiner ist, gehört nicht ins
	// Log, sondern in die Fehlermeldung an den Einreicher.
	c.AssertFormat()
	// Ein $ref auf eine fremde URL würde beim Übersetzen ins Netz greifen. Das
	// soll nicht stillschweigend passieren: Ein Profil, dessen Regeln von einem
	// fremden Server abhängen, ist kein festgeschriebenes Profil mehr.
	c.UseLoader(offlineLoader{})

	base := schemaBase + opt.ID + "/"
	for _, f := range files {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(f.Data))
		if err != nil {
			return nil, fmt.Errorf("owm/profiles: %s: %s: %w", opt.ID, f.Name, err)
		}
		if err := c.AddResource(base+f.Name, doc); err != nil {
			return nil, fmt.Errorf("owm/profiles: %s: %s: %w", opt.ID, f.Name, err)
		}
	}
	root := opt.Root
	if root == "" {
		root = "event.json"
	}
	sch, err := c.Compile(base + root)
	if err != nil {
		return nil, fmt.Errorf("owm/profiles: %s: root schema %s: %w", opt.ID, root, err)
	}

	return &Profile{
		id:     opt.ID,
		title:  opt.Title,
		root:   sch,
		files:  files,
		digest: schemaDigest(opt.ID, files),
		rule:   opt.Rule,
	}, nil
}

// ID gibt die Profilkennung zurück, wie sie im Eintrag steht.
func (p *Profile) ID() string { return p.id }

// Title gibt die Kurzbeschreibung zurück.
func (p *Profile) Title() string { return p.title }

// SchemaDigest bindet die Kennung an genau diesen Satz Schemadateien.
//
// Damit lässt sich von außen feststellen, gegen welche Regeln eine Node prüft.
// Zwei Nodes, die dasselbe Profil nennen, aber verschiedene Digests melden,
// prüfen verschieden — und das gehört sichtbar gemacht, nicht verborgen.
func (p *Profile) SchemaDigest() core.Digest { return p.digest }

// Files gibt die Schemadateien zurück, damit eine Node sie ausliefern kann.
func (p *Profile) Files() []File {
	out := make([]File, len(p.files))
	copy(out, p.files)
	return out
}

// Validate prüft eine Nutzlast gegen das Wurzelschema des Profils.
func (p *Profile) Validate(payload []byte) error {
	doc, err := decodeStrict(payload)
	if err != nil {
		return err
	}
	if err := p.root.Validate(doc); err != nil {
		return fmt.Errorf("%w: %s", ErrSchema, oneLine(err))
	}
	return nil
}

// Check prüft Nutzlast und Eintrag zusammen. Das ist die Prüfung, die eine Node
// vor dem Anhängen ausführt.
func (p *Profile) Check(e *core.Entry, payload []byte) error {
	if err := p.Validate(payload); err != nil {
		return err
	}
	if p.rule == nil {
		return nil
	}
	if err := p.rule(e, payload); err != nil {
		return fmt.Errorf("%w: %w", ErrEntry, err)
	}
	return nil
}

// Registry ordnet Profilkennungen ihren Profilen zu.
//
// Eine Node nimmt ausschließlich Einträge mit einem Profil an, das sie geladen
// hat. Ein Profil abzulehnen, das man nicht prüfen kann, ist ehrlicher als es
// ungeprüft anzunehmen: Die Node behauptet dann nichts, wofür sie nicht
// einstehen kann. Im föderierten Modell halten andere Nodes andere Profile.
type Registry struct {
	mu sync.RWMutex
	by map[string]*Profile
}

// NewRegistry gibt ein leeres Register zurück.
func NewRegistry() *Registry {
	return &Registry{by: make(map[string]*Profile)}
}

// Add nimmt ein Profil auf. Eine Kennung lässt sich nicht überschreiben.
func (r *Registry) Add(p *Profile) error {
	if p == nil {
		return errors.New("owm/profiles: no profile")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.by[p.id]; ok {
		return fmt.Errorf("%w: %s", ErrDuplicate, p.id)
	}
	r.by[p.id] = p
	return nil
}

// Get sucht ein Profil.
func (r *Registry) Get(id string) (*Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.by[id]
	return p, ok
}

// Check prüft Eintrag und Nutzlast gegen das im Eintrag genannte Profil.
//
// Ein Eintrag ohne Profilkennung ist zulässig — der Kern schreibt keines vor —
// und wird durchgelassen, weil es nichts zu prüfen gibt.
func (r *Registry) Check(e *core.Entry, payload []byte) error {
	if e == nil {
		return errors.New("owm/profiles: no entry")
	}
	if e.Profile == "" {
		return nil
	}
	p, ok := r.Get(e.Profile)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknown, e.Profile)
	}
	return p.Check(e, payload)
}

// IDs gibt die geladenen Kennungen sortiert zurück.
func (r *Registry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.by))
	for id := range r.by {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// All gibt alle geladenen Profile nach Kennung sortiert zurück.
func (r *Registry) All() []*Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Profile, 0, len(r.by))
	for _, p := range r.by {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// CheckID prüft eine Profilkennung gegen dieselben Regeln, die der Kern für das
// Feld "prof" im Eintrag anwendet.
func CheckID(id string) error {
	if id == "" {
		return errors.New("owm/profiles: empty identifier")
	}
	if len(id) > 64 {
		return fmt.Errorf("owm/profiles: identifier longer than 64 characters: %q", id)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '/', r == '-', r == '_':
		default:
			return fmt.Errorf("owm/profiles: invalid character %q in identifier %q", r, id)
		}
	}
	return nil
}

// collect liest alle *.json aus fsys, nach Pfad sortiert.
func collect(fsys fs.FS) ([]File, error) {
	var files []File
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		files = append(files, File{Name: path.Clean(p), Data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// schemaDigest hasht Kennung und Dateien längenpräfigiert, damit sich Namen und
// Inhalte nicht ineinander schieben lassen.
func schemaDigest(id string, files []File) core.Digest {
	h := sha256.New()
	h.Write([]byte{byte(len(labelSchemaDigest))})
	h.Write([]byte(labelSchemaDigest))
	var n [8]byte
	write := func(b []byte) {
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	write([]byte(id))
	for _, f := range files {
		write([]byte(f.Name))
		write(f.Data)
	}
	var d core.Digest
	h.Sum(d[:0])
	return d
}

// decodeStrict liest die Nutzlast als JSON-Objekt.
//
// Strenger als encoding/json in drei Punkten, die alle denselben Grund haben:
// Die Bytes der Nutzlast sind durch das Commitment festgeschrieben, also muss
// jede Implementierung sie gleich lesen.
//
//   - Doppelte Schlüssel gelten als Fehler. encoding/json nimmt den letzten
//     Wert, andere Sprachen den ersten — dieselben Bytes bedeuteten dann
//     Verschiedenes.
//   - Text hinter dem obersten Wert gilt als Fehler.
//   - Die Verschachtelung ist begrenzt (maxDepth).
func decodeStrict(payload []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing text after the top-level value", ErrPayload)
	}
	if _, ok := v.(map[string]any); !ok {
		return nil, fmt.Errorf("%w: top-level value is not an object", ErrPayload)
	}
	return v, nil
}

func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nested more than %d levels deep", ErrPayload, maxDepth)
	}
	t, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPayload, err)
	}
	d, ok := t.(json.Delim)
	if !ok {
		return t, nil
	}
	switch d {
	case '{':
		obj := make(map[string]any)
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrPayload, err)
			}
			k, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("%w: object key is not a string", ErrPayload)
			}
			if _, dup := obj[k]; dup {
				return nil, fmt.Errorf("%w: key %q occurs more than once", ErrPayload, k)
			}
			v, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[k] = v
		}
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPayload, err)
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if _, err := dec.Token(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPayload, err)
		}
		return arr, nil
	}
	return nil, fmt.Errorf("%w: unexpected character %q", ErrPayload, d)
}

// offlineLoader lehnt jeden Abruf ab, den ein $ref auslösen würde.
type offlineLoader struct{}

func (offlineLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("owm/profiles: a reference to the foreign schema source %q is not allowed", url)
}

// oneLine macht aus der mehrzeiligen Fehlerausgabe des Validators eine Zeile,
// damit sie in eine HTTP-Antwort und in eine Logzeile passt.
func oneLine(err error) string {
	s := strings.TrimSpace(err.Error())
	s = strings.ReplaceAll(s, "\n", "; ")
	s = strings.Join(strings.Fields(s), " ")
	const max = 400
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
