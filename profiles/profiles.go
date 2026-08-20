// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package profiles holds the profile mechanism of OpenWaymark: the mapping from
// a profile identifier in the entry to a set of JSON schemas the accompanying
// payload is checked against.
//
// The core knows no industry semantics. An entry carries only a profile
// identifier such as "food.v1"; what a "processing" event means and which
// fields it needs is laid down by the profile alone. New industries arrive as a
// new profile, without anything changing in the data model.
//
// # What schema validation does — and what it does not
//
// It is an intake filter, not a statement about truth. An entry that conforms to
// the schema can be a complete lie: the schema checks form, not reality. It
// keeps typos, missing mandatory fields and format mix-ups out of the log so
// that the chain can be evaluated by machine later on at all. What binds the
// payload to the entry is not the schema but the commitment (core.Commit); what
// makes it attributable is the signature. See spec/owm-9-threat-model.md on the
// oracle problem.
//
// # Immutability
//
// A profile version is immutable. Once "food.v1" has been published, its schema
// never changes again — otherwise an entry from yesterday would be invalid today
// although nobody touched it, and a monitor could no longer tell what the node
// checked against back then. Changes appear as a new identifier ("food.v2").
// SchemaDigest makes the rules in use verifiable.
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

// Errors of this package.
var (
	// ErrUnknown reports a profile identifier this node has not loaded.
	ErrUnknown = errors.New("owm/profiles: unknown profile")
	// ErrDuplicate reports an identifier already taken in the registry.
	ErrDuplicate = errors.New("owm/profiles: profile already registered")
	// ErrPayload reports a payload that is not readable JSON.
	ErrPayload = errors.New("owm/profiles: payload is unreadable")
	// ErrSchema reports a payload that contradicts the profile schema.
	ErrSchema = errors.New("owm/profiles: payload does not match the schema")
	// ErrEntry reports an entry that does not go with the payload.
	ErrEntry = errors.New("owm/profiles: entry does not match the payload")
)

// maxDepth limits how deeply a payload may be nested.
//
// The decoder below runs recursively, and the payload comes from outside.
// Without a limit a chain of brackets is enough to make the stack grow until the
// process dies. A supply chain event with thirty levels does not exist; the
// limit costs no real use case.
const maxDepth = 32

// schemaBase is the namespace under which profile schemas are registered with
// the compiler. The URL is never fetched — it only serves as the resolution base
// for relative $ref.
const schemaBase = "https://openwaymark.org/schema/"

// labelSchemaDigest separates the schema digest from every other hash value in
// the system.
const labelSchemaDigest = "OWM/1 profile-schema"

// Rule checks profile-specific conditions that cannot be expressed in the JSON
// schema because they concern the entry itself — such as a series of
// measurements being recorded as a sensor reading and not as an assertion.
//
// payload already conforms to the schema when the rule runs.
type Rule func(e *core.Entry, payload []byte) error

// CrossCheckFunc compares a claim entry's payload against a linked
// sensor_reading entry's payload and reports a human-readable contradiction
// when the device data disagrees with the self-declaration — the "found by
// machine" mitigation OWM-9 A4 names for the oracle problem. ok is false
// when there is nothing to report, whether because the two payloads carry no
// relevant fields or because the sensor data agrees with the claim.
//
// Unlike Rule, this never runs at the node: a claim and its later sensor
// reading typically do not both exist yet at submission time. It runs
// client-side, once a subject's full history is available
// (client/verify.Options.Profiles).
type CrossCheckFunc func(claim, msmt []byte) (finding string, ok bool)

// File is one schema file of a profile, as it is shipped.
type File struct {
	Name string
	Data []byte
}

// Profile is a loaded schema profile.
type Profile struct {
	id         string
	title      string
	root       *jsonschema.Schema
	files      []File
	digest     core.Digest
	rule       Rule
	crossCheck CrossCheckFunc
}

// Options describes a profile to be loaded.
type Options struct {
	// ID is the profile identifier as it appears in the entry, e.g. "food.v1".
	ID string
	// Title is a short description for humans.
	Title string
	// FS holds the schema files; every *.json in it is loaded.
	FS fs.FS
	// Root is the path of the root schema within FS.
	Root string
	// Rule is optional and checks the entry against the payload.
	Rule Rule
	// CrossCheck is optional and compares a claim against a linked sensor
	// reading, client-side (OWM-9 A4). Most profiles have none.
	CrossCheck CrossCheckFunc
}

// Load compiles the schema files and builds a profile from them.
//
// Errors here are programming errors in the profile itself, not runtime cases:
// profiles are loaded at startup, not while processing.
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
	// In the standard "format" is only an annotation. For a profile it is exactly
	// the check that counts: a timestamp that is none does not belong in the log
	// but in the error message to the submitter.
	c.AssertFormat()
	// A $ref to a foreign URL would reach out to the network while compiling.
	// That must not happen silently: a profile whose rules depend on a foreign
	// server is no longer a fixed profile.
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
		id:         opt.ID,
		title:      opt.Title,
		root:       sch,
		files:      files,
		digest:     schemaDigest(opt.ID, files),
		rule:       opt.Rule,
		crossCheck: opt.CrossCheck,
	}, nil
}

// ID returns the profile identifier as it appears in the entry.
func (p *Profile) ID() string { return p.id }

// Title returns the short description.
func (p *Profile) Title() string { return p.title }

// SchemaDigest binds the identifier to exactly this set of schema files.
//
// It lets an outsider find out which rules a node checks against. Two nodes that
// name the same profile but report different digests check differently — and
// that belongs in plain sight, not hidden.
func (p *Profile) SchemaDigest() core.Digest { return p.digest }

// Files returns the schema files so that a node can serve them.
func (p *Profile) Files() []File {
	out := make([]File, len(p.files))
	copy(out, p.files)
	return out
}

// Validate checks a payload against the profile's root schema.
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

// Check validates payload and entry together. This is the check a node runs
// before appending.
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

// CrossCheck compares a claim against a linked sensor reading, both already
// known to be schema-valid. Reports ok=false when the profile defines no
// cross-check at all, or when the defined one finds nothing to report.
func (p *Profile) CrossCheck(claim, msmt []byte) (finding string, ok bool) {
	if p.crossCheck == nil {
		return "", false
	}
	return p.crossCheck(claim, msmt)
}

// Registry maps profile identifiers to their profiles.
//
// A node accepts only entries with a profile it has loaded. Turning away a
// profile one cannot check is more honest than accepting it unchecked: the node
// then claims nothing it cannot stand behind. In the federated model other nodes
// hold other profiles.
type Registry struct {
	mu sync.RWMutex
	by map[string]*Profile
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{by: make(map[string]*Profile)}
}

// Add takes in a profile. An identifier cannot be overwritten.
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

// Get looks up a profile.
func (r *Registry) Get(id string) (*Profile, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.by[id]
	return p, ok
}

// CrossCheck looks up profileID and runs its cross-check, if it has one,
// against claim and msmt. It exists so that *Registry satisfies
// client/verify's ProfileLookup interface without either package importing
// the other — client/verify only ever calls this through that interface.
func (r *Registry) CrossCheck(profileID string, claim, msmt []byte) (finding string, ok bool) {
	p, ok := r.Get(profileID)
	if !ok {
		return "", false
	}
	return p.CrossCheck(claim, msmt)
}

// Check validates entry and payload against the profile named in the entry.
//
// An entry without a profile identifier is admissible — the core prescribes none
// — and passes through, because there is nothing to check.
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

// IDs returns the loaded identifiers, sorted.
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

// All returns all loaded profiles, sorted by identifier.
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

// CheckID validates a profile identifier against the same rules the core
// applies to the "prof" field in the entry.
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

// collect reads every *.json from fsys, sorted by path.
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

// schemaDigest hashes identifier and files with length prefixes so that names
// and contents cannot be slid into one another.
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

// decodeStrict reads the payload as a JSON object.
//
// Stricter than encoding/json in three points that all have the same reason: the
// bytes of the payload are pinned down by the commitment, so every
// implementation has to read them the same way.
//
//   - Duplicate keys count as an error. encoding/json takes the last value,
//     other languages the first — the same bytes would then mean different
//     things.
//   - Text after the top-level value counts as an error.
//   - Nesting is limited (maxDepth).
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

// offlineLoader refuses every fetch a $ref would trigger.
type offlineLoader struct{}

func (offlineLoader) Load(url string) (any, error) {
	return nil, fmt.Errorf("owm/profiles: a reference to the foreign schema source %q is not allowed", url)
}

// oneLine turns the validator's multi-line error output into a single line so
// that it fits into an HTTP response and into a log line.
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
