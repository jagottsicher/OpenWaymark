// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Demonstration of a running OpenWaymark node.
//
// A food chain from the farm to the retailer: eight events, a cold chain sensor
// that contradicts, an erasure under the GDPR and four tampering attempts — all
// against a real node over HTTP.
//
// The program imports only core/ and log/ (Apache-2.0). The node itself
// (AGPL-3.0-only) runs as a process of its own and is addressed exclusively
// through the HTTP interface, the way a third-party client would. That makes the
// demonstration the acid test at the same time: what it cannot get through the
// public API, nobody else gets either.
//
// Everything is created in a throwaway directory that disappears again at the
// end; the node listens on 127.0.0.1 only, on free ports.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

var (
	repoFlag = flag.String("repo", "", "root of the repository (default: module root)")
	keepFlag = flag.Bool("keep", false, "keep the working directory")
	workFlag = flag.String("work", "", "parent directory for the throwaway data")
)

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- Output
//
// Plain text without colours and special characters: the output should be
// copyable unchanged into a file, a ticket or a mail, and it should look the
// same in every terminal. The marks on the left say what a line is about:
// ok = checked and in order, blocked = turned away (as intended), note = remark.

var stepNo int

func section(title string) {
	stepNo++
	fmt.Printf("\n%d. %s\n", stepNo, title)
}
func okf(f string, a ...any)      { fmt.Printf("   ok       %s\n", fmt.Sprintf(f, a...)) }
func blockedf(f string, a ...any) { fmt.Printf("   blocked  %s\n", fmt.Sprintf(f, a...)) }
func notef(f string, a ...any)    { fmt.Printf("   note     %s\n", fmt.Sprintf(f, a...)) }
func linef(f string, a ...any)    { fmt.Printf("            %s\n", fmt.Sprintf(f, a...)) }

func abbr(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ---------------------------------------------------------------- HTTP

type api struct {
	base string
	c    *http.Client
}

func (a api) call(method, path string, body any) (int, []byte) {
	var rd io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		must(err)
		rd = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(method, a.base+path, rd)
	must(err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.c.Do(req)
	must(err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	must(err)
	return resp.StatusCode, raw
}

func (a api) get(path string, out any) {
	st, raw := a.call("GET", path, nil)
	if st != http.StatusOK {
		must(fmt.Errorf("GET %s: %d %s", path, st, raw))
	}
	if out != nil {
		must(json.Unmarshal(raw, out))
	}
}

func (a api) post(path string, body, out any, want int) {
	st, raw := a.call("POST", path, body)
	if st != want {
		must(fmt.Errorf("POST %s: %d %s", path, st, raw))
	}
	if out != nil {
		must(json.Unmarshal(raw, out))
	}
}

// ---------------------------------------------------------------- Response types

type obj = map[string]any

type keyView struct {
	Alg    string     `json:"alg"`
	ID     core.KeyID `json:"id"`
	Public string     `json:"public"`
}

type profileView struct {
	ID           string      `json:"id"`
	Title        string      `json:"title"`
	SchemaDigest core.Digest `json:"schema_digest"`
	Files        []string    `json:"files"`
}

type metaResp struct {
	Protocol string     `json:"protocol"`
	Log      core.LogID `json:"log"`
	BaseURL  string     `json:"base_url"`
	Operator struct {
		Name    string `json:"name"`
		Contact string `json:"contact"`
	} `json:"operator"`
	Key        keyView       `json:"key"`
	Genesis    keyView       `json:"genesis_key"`
	TreeSize   uint64        `json:"tree_size"`
	Profiles   []profileView `json:"profiles"`
	MaxPayload int64         `json:"max_payload"`
	API        string        `json:"api"`
}

type submitReq struct {
	Entry   []byte `json:"entry"`
	Salt    string `json:"salt,omitempty"`
	Payload []byte `json:"payload,omitempty"`
}

type submitResp struct {
	Log      core.LogID  `json:"log"`
	EntryID  core.Digest `json:"entry_id"`
	Seq      uint64      `json:"seq"`
	LoggedAt int64       `json:"logged_at"`
	Leaf     []byte      `json:"leaf"`
}

type leafView struct {
	Log      core.LogID  `json:"log"`
	Seq      uint64      `json:"seq"`
	LoggedAt int64       `json:"logged_at"`
	EntryID  core.Digest `json:"entry_id"`
	Leaf     []byte      `json:"leaf"`
	Entry    []byte      `json:"entry"`
	Payload  string      `json:"payload_status"`
}

type payloadResp struct {
	EntryID core.Digest `json:"entry_id"`
	Salt    string      `json:"salt"`
	Payload []byte      `json:"payload"`
}

type sthResp struct {
	Signed  *owmlog.SignedSTH `json:"signed"`
	Decoded *owmlog.STH       `json:"decoded"`
}

type errResp struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// ---------------------------------------------------------------- State

type party struct {
	label string
	key   *core.PrivateKey
}

func (p *party) id() core.KeyID { return p.key.Public().ID() }

type record struct {
	name    string
	party   *party
	entryID core.Digest
	seq     uint64
	salt    core.Salt
	payload []byte
	entry   []byte
	leaf    []byte
}

type demo struct {
	dir     string
	proc    *exec.Cmd
	logs    *bytes.Buffer
	public  api
	admin   api
	meta    metaResp
	nodePub *core.PublicKey
	local   map[core.KeyID]*core.PublicKey // what the client knows on its own
	records []*record
	byID    map[core.Digest]*record
}

func run() (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				return
			}
			err = fmt.Errorf("%v", r)
		}
	}()

	d := &demo{
		local: map[core.KeyID]*core.PublicKey{},
		byID:  map[core.Digest]*record{},
	}
	defer d.stop()

	fmt.Print("\nOpenWaymark demonstration\n" +
		"One supply chain, one node, and a client that believes nothing it is told.\n")

	d.startNode()
	d.enrollParties()
	d.writeChain()
	d.issueAndCheckSTH()
	d.replayChain()
	d.coldChain()
	d.erase()
	d.tamper()
	d.summary()

	fmt.Print("\nAll checks passed.\n\n")
	return nil
}

// ---------------------------------------------------------------- 1 Start the node

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// repoRoot determines where owmnode is built. Without an argument it asks the Go
// toolchain for the module the current directory belongs to — then the
// demonstration runs from any subdirectory of the repository.
func repoRoot() string {
	if *repoFlag != "" {
		abs, err := filepath.Abs(*repoFlag)
		must(err)
		return abs
	}
	out, err := exec.Command("go", "env", "GOMOD").Output()
	must(err)
	mod := strings.TrimSpace(string(out))
	if mod == "" || mod == os.DevNull {
		must(fmt.Errorf("no Go module found - start inside the repository or pass -repo"))
	}
	return filepath.Dir(mod)
}

func (d *demo) startNode() {
	section("Starting the node")

	root := repoRoot()
	dir, err := os.MkdirTemp(*workFlag, "owm-demo-")
	must(err)
	dir, err = filepath.Abs(dir)
	must(err)
	d.dir = dir

	bin := filepath.Join(dir, "owmnode")
	build := exec.Command("go", "build", "-o", bin, "./node/cmd/owmnode")
	build.Dir = root
	build.Stderr = os.Stderr
	must(build.Run())
	if fi, err := os.Stat(bin); err == nil {
		okf("owmnode built (%.1f MB)", float64(fi.Size())/(1<<20))
	}

	pubAddr := fmt.Sprintf("127.0.0.1:%d", freePort())
	adminAddr := fmt.Sprintf("127.0.0.1:%d", freePort())
	cfgPath := filepath.Join(dir, "owm.json")
	cfg := obj{
		"listen":       pubAddr,
		"admin_listen": adminAddr,
		"database":     filepath.Join(dir, "owm.sqlite"),
		"identity":     filepath.Join(dir, "owm-identity.json"),
		"base_url":     "https://owm.molkerei-alpenrand.example",
		"operator": obj{
			"name":    "Molkerei Alpenrand GmbH",
			"contact": "privacy@alpenrand.example",
		},
		// Zero switches off automatic issuance: in the demonstration every STH is
		// issued at a point one can follow.
		"sth_interval": "0s",
	}
	buf, err := json.MarshalIndent(cfg, "", "  ")
	must(err)
	must(os.WriteFile(cfgPath, buf, 0o600))

	out, err := exec.Command(bin, "init", "-config", cfgPath).CombinedOutput()
	if err != nil {
		must(fmt.Errorf("owmnode init: %v\n%s", err, out))
	}
	okf("identity created")
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		linef("%s", l)
	}

	d.logs = &bytes.Buffer{}
	cmd := exec.Command(bin, "serve", "-config", cfgPath)
	cmd.Stdout = d.logs
	cmd.Stderr = d.logs
	must(cmd.Start())
	d.proc = cmd

	client := &http.Client{Timeout: 30 * time.Second}
	d.public = api{base: "http://" + pubAddr, c: client}
	d.admin = api{base: "http://" + adminAddr, c: client}

	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := client.Get(d.public.base + "/.well-known/openwaymark")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			must(fmt.Errorf("the node never became ready:\n%s", d.logs.String()))
		}
		time.Sleep(50 * time.Millisecond)
	}
	okf("node running: public %s, admin %s", pubAddr, adminAddr)

	d.public.get("/.well-known/openwaymark", &d.meta)
	linef("protocol %s, operator %q", d.meta.Protocol, d.meta.Operator.Name)
	linef("log ID %s", d.meta.Log)

	// The client checks what the node says about itself instead of believing it.
	raw, err := hex.DecodeString(d.meta.Key.Public)
	must(err)
	d.nodePub, err = core.ParsePublicKey(algByName(d.meta.Key.Alg), raw)
	must(err)
	if d.nodePub.ID() != d.meta.Key.ID {
		must(fmt.Errorf("the key ID does not match the key"))
	}
	okf("key ID recomputed by the client: %s (%s, %d bytes)",
		abbr(d.meta.Key.ID.String()), d.meta.Key.Alg, len(raw))

	graw, err := hex.DecodeString(d.meta.Genesis.Public)
	must(err)
	gpub, err := core.ParsePublicKey(algByName(d.meta.Genesis.Alg), graw)
	must(err)
	derived, err := core.DeriveLogID(gpub)
	must(err)
	if derived != d.meta.Log {
		must(fmt.Errorf("the log ID does not match the genesis key"))
	}
	okf("log ID derived from the genesis key, matches")

	for _, p := range d.meta.Profiles {
		okf("profile %s, schema digest %s, %d files", p.ID, abbr(p.SchemaDigest.String()), len(p.Files))
	}
}

func algByName(s string) core.SigAlg {
	switch s {
	case "ML-DSA-44":
		return core.SigAlgMLDSA44
	case "ML-DSA-65":
		return core.SigAlgMLDSA65
	}
	must(fmt.Errorf("unknown algorithm %q", s))
	return 0
}

func (d *demo) stop() {
	if d.proc != nil && d.proc.Process != nil {
		_ = d.proc.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = d.proc.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = d.proc.Process.Kill()
		}
	}
	if d.dir != "" {
		if *keepFlag {
			fmt.Printf("working directory kept: %s\n", d.dir)
			return
		}
		_ = os.RemoveAll(d.dir)
	}
}

// ---------------------------------------------------------------- 2 Participants

func (d *demo) enroll(label string, alg core.SigAlg) *party {
	k, err := core.GenerateKey(alg)
	must(err)
	p := &party{label: label, key: k}
	var out obj
	d.admin.post("/admin/v1/keys", obj{
		"alg":    alg.String(),
		"public": hex.EncodeToString(k.Public().Bytes()),
		"label":  label,
	}, &out, http.StatusCreated)
	d.local[p.id()] = k.Public()
	okf("%-24s %s  %s", label, alg, abbr(p.id().String()))
	return p
}

var (
	farmA, farmB, carrier, sensor, dairy *party
)

func (d *demo) enrollParties() {
	section("Enrolling the participants in the key directory")
	farmA = d.enroll("Hof Sonnenblick", core.SigAlgMLDSA65)
	farmB = d.enroll("Hof Talblick", core.SigAlgMLDSA65)
	carrier = d.enroll("Spedition Kühlfracht", core.SigAlgMLDSA65)
	dairy = d.enroll("Molkerei Alpenrand", core.SigAlgMLDSA65)
	sensor = d.enroll("Data logger TW-7", core.SigAlgMLDSA44)
	linef("sensors sign with ML-DSA-44: 2420 instead of 3309 bytes per signature.")

	// A key that is not in the directory belongs to another node — this one does
	// not accept its entries.
	outsider, err := core.GenerateKey(core.SigAlgMLDSA65)
	must(err)
	raw, err := json.Marshal(obj{
		"event":   "production",
		"time":    "2026-08-10T05:12:00+02:00",
		"product": obj{"name": "Raw milk", "lot": "made up"},
	})
	must(err)
	salt, err := core.NewSalt()
	must(err)
	e := &core.Entry{
		Version:    core.FormatVersion,
		Type:       core.EntryTypeAssertion,
		Profile:    "food.v1",
		Subject:    core.DeriveSubjectID("demo", []byte("outsider")),
		Issuer:     outsider.Public().ID(),
		Commitment: core.Commit(salt, raw),
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(outsider, e)
	must(err)
	enc, err := se.Encode()
	must(err)
	st, body := d.public.call("POST", "/owm/v1/entries", submitReq{
		Entry: enc, Salt: hex.EncodeToString(salt[:]), Payload: raw})
	var er errResp
	_ = json.Unmarshal(body, &er)
	blockedf("unknown key rejected: HTTP %d %s", st, er.Error)
	linef("%s", er.Detail)
}

// ---------------------------------------------------------------- 3 Write the chain

func (d *demo) submit(name string, p *party, typ core.EntryType, subj core.SubjectID, payload obj, parents ...core.Digest) *record {
	raw, err := json.Marshal(payload)
	must(err)
	salt, err := core.NewSalt()
	must(err)

	e := &core.Entry{
		Version:    core.FormatVersion,
		Type:       typ,
		Profile:    "food.v1",
		Subject:    subj,
		Issuer:     p.id(),
		Commitment: core.Commit(salt, raw),
	}
	e.SetIssuedAt(time.Now())
	for _, par := range parents {
		e.Parents = append(e.Parents, core.EntryRef{Entry: par, Log: d.meta.Log})
	}

	se, err := core.SignEntry(p.key, e)
	must(err)
	enc, err := se.Encode()
	must(err)

	var resp submitResp
	d.public.post("/owm/v1/entries", submitReq{
		Entry:   enc,
		Salt:    hex.EncodeToString(salt[:]),
		Payload: raw,
	}, &resp, http.StatusCreated)

	r := &record{
		name: name, party: p, entryID: resp.EntryID, seq: resp.Seq,
		salt: salt, payload: raw, entry: enc, leaf: resp.Leaf,
	}
	d.records = append(d.records, r)
	d.byID[r.entryID] = r
	okf("#%d %-22s %-22s %5d B payload, %5d B entry", resp.Seq, name, p.label, len(raw), len(enc))
	return r
}

var (
	subjMilkA  = core.DeriveSubjectID("gs1:lgtin", []byte("4012345.09876.M-2408-17-A"))
	subjMilkB  = core.DeriveSubjectID("gs1:lgtin", []byte("4012345.09876.M-2408-17-B"))
	subjTank   = core.DeriveSubjectID("gs1:sscc", []byte("340123450000001234"))
	subjCheese = core.DeriveSubjectID("gs1:lgtin", []byte("4012345.05001.K-2408-31"))
)

var chain struct {
	milkA, milkB, aggregation, departure, measurement, arrival, processing, handover *record
}

func (d *demo) writeChain() {
	section("Writing the supply chain: eight events, food.v1")

	chain.milkA = d.submit("production", farmA, core.EntryTypeAssertion, subjMilkA, obj{
		"event": "production",
		"time":  "2026-08-10T05:12:00+02:00",
		"party": obj{"name": "Hof Sonnenblick", "gln": "4012345000009", "key": farmA.id().String()},
		"location": obj{"name": "Milking parlour North", "country": "DE",
			"geo": obj{"lat": 47.8021, "lon": 11.0129}},
		"product": obj{"gtin": "04012345098769", "name": "Raw milk",
			"lot": "M-2408-17-A", "best_before": "2026-08-14"},
		"quantity": obj{"value": 1200, "unit": "LTR"},
		"certifications": []any{obj{
			"scheme": "EU-Bio", "id": "DE-ÖKO-006", "body": "ABCERT AG", "valid_until": "2027-03-31",
		}},
	})

	chain.milkB = d.submit("production", farmB, core.EntryTypeAssertion, subjMilkB, obj{
		"event": "production",
		"time":  "2026-08-10T05:40:00+02:00",
		"party": obj{"name": "Hof Talblick", "gln": "4012345000016", "key": farmB.id().String()},
		"location": obj{"name": "Milking parlour Valley", "country": "DE",
			"geo": obj{"lat": 47.7654, "lon": 11.0873}},
		"product": obj{"gtin": "04012345098769", "name": "Raw milk",
			"lot": "M-2408-17-B", "best_before": "2026-08-14"},
		"quantity": obj{"value": 900, "unit": "LTR"},
		"certifications": []any{obj{
			"scheme": "EU-Bio", "id": "DE-ÖKO-006", "body": "ABCERT AG", "valid_until": "2027-03-31",
		}},
	})

	chain.aggregation = d.submit("aggregation", carrier, core.EntryTypeAssertion, subjTank, obj{
		"event":     "aggregation",
		"time":      "2026-08-10T07:40:00+02:00",
		"party":     obj{"name": "Spedition Kühlfracht", "gln": "4033445000004"},
		"location":  obj{"name": "Collection point South", "country": "DE"},
		"action":    "add",
		"container": obj{"name": "Tanker TW-7", "lot": "TW-7/2026-08-10"},
		"children": []any{
			obj{"subject": subjMilkA.String(), "quantity": obj{"value": 1200, "unit": "LTR"}},
			obj{"subject": subjMilkB.String(), "quantity": obj{"value": 900, "unit": "LTR"}},
		},
	}, chain.milkA.entryID, chain.milkB.entryID)

	chain.departure = d.submit("transport/departure", carrier, core.EntryTypeAssertion, subjTank, obj{
		"event":       "transport",
		"time":        "2026-08-10T08:05:00+02:00",
		"party":       obj{"name": "Spedition Kühlfracht", "gln": "4033445000004"},
		"step":        "departure",
		"carrier":     obj{"name": "Spedition Kühlfracht", "gln": "4033445000004"},
		"from":        obj{"name": "Collection point South", "country": "DE"},
		"to":          obj{"name": "Molkerei Alpenrand", "gln": "4055667000002", "country": "DE"},
		"consignment": "FB-2026-08-10-441",
		"conditions":  obj{"temperature_c": obj{"min": 2, "max": 6}},
	}, chain.aggregation.entryID)

	readings := []any{}
	for _, r := range []struct {
		t string
		v float64
	}{
		{"08:05", 4.1}, {"08:35", 4.3}, {"09:05", 5.0}, {"09:35", 7.9},
		{"10:05", 8.4}, {"10:35", 5.2}, {"11:05", 4.4},
	} {
		readings = append(readings, obj{"t": "2026-08-10T" + r.t + ":00+02:00", "v": r.v})
	}
	chain.measurement = d.submit("measurement", sensor, core.EntryTypeSensorReading, subjTank, obj{
		"event": "measurement",
		"time":  "2026-08-10T11:05:00+02:00",
		"sensor": obj{"id": "TW-7-TEMP-1", "key": sensor.id().String(),
			"model": "Sensirion STS35"},
		"quantity_kind": "temperature",
		"unit":          "CEL",
		"readings":      readings,
	}, chain.departure.entryID)

	chain.arrival = d.submit("transport/arrival", dairy, core.EntryTypeAssertion, subjTank, obj{
		"event":       "transport",
		"time":        "2026-08-10T11:20:00+02:00",
		"party":       obj{"name": "Molkerei Alpenrand", "gln": "4055667000002"},
		"step":        "arrival",
		"carrier":     obj{"name": "Spedition Kühlfracht", "gln": "4033445000004"},
		"from":        obj{"name": "Collection point South", "country": "DE"},
		"to":          obj{"name": "Molkerei Alpenrand", "gln": "4055667000002", "country": "DE"},
		"consignment": "FB-2026-08-10-441",
		"note":        "Goods receipt: the data logger reports a temperature deviation, lot blocked until QA release.",
	}, chain.departure.entryID, chain.measurement.entryID)

	chain.processing = d.submit("processing", dairy, core.EntryTypeAssertion, subjCheese, obj{
		"event":    "processing",
		"time":     "2026-08-11T06:30:00+02:00",
		"party":    obj{"name": "Molkerei Alpenrand", "gln": "4055667000002"},
		"location": obj{"name": "Cheese dairy hall 2", "country": "DE"},
		"process":  "pasteurise and add rennet",
		"inputs": []any{
			obj{"subject": subjTank.String(), "quantity": obj{"value": 2100, "unit": "LTR"}},
		},
		"outputs": []any{
			obj{"subject": subjCheese.String(),
				"product":  obj{"gtin": "04012345050015", "name": "Mountain cheese, 12 months", "lot": "K-2408-31"},
				"quantity": obj{"value": 205, "unit": "KGM"}},
		},
	}, chain.arrival.entryID)

	chain.handover = d.submit("handover", dairy, core.EntryTypeAssertion, subjCheese, obj{
		"event":       "handover",
		"time":        "2026-08-11T09:15:00+02:00",
		"party":       obj{"name": "Molkerei Alpenrand", "gln": "4055667000002"},
		"from":        obj{"name": "Molkerei Alpenrand", "gln": "4055667000002"},
		"to":          obj{"name": "Feinkost Brunner e.K.", "gln": "4066778000005"},
		"transaction": obj{"type": "desadv", "id": "DA-2026-08-11-0093"},
		"items": []any{
			obj{"subject": subjCheese.String(), "quantity": obj{"value": 205, "unit": "KGM"}},
		},
	}, chain.processing.entryID)

	// What the node does not accept: a measurement as a self-declaration.
	salt, err := core.NewSalt()
	must(err)
	raw, err := json.Marshal(obj{
		"event": "measurement", "time": "2026-08-10T11:05:00+02:00",
		"sensor": obj{"id": "made up"}, "quantity_kind": "temperature", "unit": "CEL",
		"readings": []any{obj{"t": "2026-08-10T11:05:00+02:00", "v": 4.0}},
	})
	must(err)
	e := &core.Entry{
		Version: core.FormatVersion, Type: core.EntryTypeAssertion, Profile: "food.v1",
		Subject: subjTank, Issuer: dairy.id(), Commitment: core.Commit(salt, raw),
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(dairy.key, e)
	must(err)
	enc, err := se.Encode()
	must(err)
	st, body := d.public.call("POST", "/owm/v1/entries", submitReq{
		Entry: enc, Salt: hex.EncodeToString(salt[:]), Payload: raw})
	var er errResp
	_ = json.Unmarshal(body, &er)
	blockedf("hand-written cold chain rejected: HTTP %d %s", st, er.Error)
	linef("%s", er.Detail)
}

// ---------------------------------------------------------------- 4 STH

var sth1 *owmlog.STH

func (d *demo) issueAndCheckSTH() {
	section("Issuing a signed tree head and checking it")

	var resp sthResp
	d.admin.post("/admin/v1/sth", nil, &resp, http.StatusOK)

	// What gets checked is the signature, not the readable version supplied with it.
	must(resp.Signed.Verify(d.nodePub))
	s, err := resp.Signed.STH()
	must(err)
	sth1 = s

	okf("signature valid under the node key (%d bytes, ML-DSA-65)", len(resp.Signed.Signature))
	linef("size %d, root %s", s.Size, abbr(s.Root.String()))
	linef("log %s, issued %s", abbr(s.Log.String()), time.UnixMilli(s.IssuedAt).UTC().Format(time.RFC3339))
	if s.Log != d.meta.Log {
		must(fmt.Errorf("the STH belongs to a different log"))
	}
	okf("log ID in the STH matches the node")
}

// ---------------------------------------------------------------- 5 Read the chain back

// publicKeyFor obtains an issuer's public key the way a third-party client
// would: over the public API. If the endpoint is missing, the demonstration
// falls back on its own keys — and says so.
func (d *demo) publicKeyFor(id core.KeyID) (*core.PublicKey, bool) {
	st, raw := d.public.call("GET", "/owm/v1/keys/"+id.String(), nil)
	if st == http.StatusOK {
		var kv struct {
			ID     core.KeyID `json:"key_id"`
			Alg    string     `json:"alg"`
			Public string     `json:"public"`
		}
		if json.Unmarshal(raw, &kv) == nil && kv.Public != "" {
			b, err := hex.DecodeString(kv.Public)
			must(err)
			pub, err := core.ParsePublicKey(algByName(kv.Alg), b)
			must(err)
			// The identifier is recomputed: a node that delivers different
			// bytes is thereby convicted and not merely suspect.
			if pub.ID() != id || kv.ID != id {
				must(fmt.Errorf("the node returns a different key for %s", id))
			}
			return pub, true
		}
	}
	return d.local[id], false
}

func (d *demo) replayChain() {
	section("Reading the chain back: the client checks everything itself")

	// The proof is made against the signed tree state.
	fromAPI := true
	var checked int

	var walk func(id core.Digest, depth int)
	seen := map[core.Digest]bool{}
	walk = func(id core.Digest, depth int) {
		if seen[id] {
			return
		}
		seen[id] = true

		var lv leafView
		d.public.get("/owm/v1/entries/"+id.String(), &lv)

		// 1. Decode the leaf ourselves instead of believing the readable version.
		leaf, err := owmlog.ParseLeaf(lv.Leaf)
		must(err)
		se, err := core.ParseSignedEntry(leaf.Entry)
		must(err)
		e, err := se.Entry()
		must(err)

		// 2. Signature against the issuer's key.
		pub, viaAPI := d.publicKeyFor(e.Issuer)
		if !viaAPI {
			fromAPI = false
		}
		if pub == nil {
			must(fmt.Errorf("no public key for %s", e.Issuer))
		}
		must(se.Verify(pub))

		// 3. Payload against the commitment in the entry.
		var ev obj
		state := ""
		st, raw := d.public.call("GET", "/owm/v1/entries/"+id.String()+"/payload", nil)
		switch st {
		case http.StatusOK:
			var pr payloadResp
			must(json.Unmarshal(raw, &pr))
			var salt core.Salt
			sb, err := hex.DecodeString(pr.Salt)
			must(err)
			copy(salt[:], sb)
			if !core.VerifyCommitment(e.Commitment, salt, pr.Payload) {
				must(fmt.Errorf("the commitment does not match the payload of %s", id))
			}
			must(json.Unmarshal(pr.Payload, &ev))
		case http.StatusGone:
			state = "  [payload erased]"
		default:
			must(fmt.Errorf("unexpected answer for the payload of %s: HTTP %d %s", id, st, raw))
		}

		// 4. Inclusion proof against the root of the STH.
		var p owmlog.InclusionProof
		d.public.get(fmt.Sprintf("/owm/v1/proof/inclusion?entry=%s&size=%d", id, sth1.Size), &p)
		must(p.Verify(owmlog.LeafHashFromBytes(lv.Leaf), sth1))
		checked++

		indent := strings.Repeat("   ", depth)
		linef("%s#%d %s%s", indent, leaf.Seq, describe(e, ev), state)
		linef("%s   %s, logged %s, proof %d nodes", indent, e.Type,
			time.UnixMilli(leaf.LoggedAt).UTC().Format("15:04:05"), len(p.Path))

		for _, par := range e.Parents {
			walk(par.Entry, depth+1)
		}
	}

	walk(chain.handover.entryID, 0)

	okf("%d entries: signature, commitment and inclusion proof verified", checked)
	if fromAPI {
		okf("public keys fetched over the public API")
	} else {
		notef("the public API does not hand out participant keys, so the")
		linef("demonstration falls back to its own copies. A foreign client")
		linef("could not verify anything here.")
	}

	// History of a subject.
	var hist struct {
		Total   int        `json:"total"`
		Entries []leafView `json:"entries"`
	}
	d.public.get("/owm/v1/subjects/"+subjTank.String(), &hist)
	okf("history of the tanker: %d entries from %d issuers",
		hist.Total, countIssuers(hist.Entries))
}

func countIssuers(ls []leafView) int {
	set := map[core.KeyID]bool{}
	for _, l := range ls {
		se, err := core.ParseSignedEntry(l.Entry)
		must(err)
		e, err := se.Entry()
		must(err)
		set[e.Issuer] = true
	}
	return len(set)
}

// describe sums up an event in one line.
func describe(e *core.Entry, ev obj) string {
	if ev == nil {
		return "(content erased)"
	}
	switch ev["event"] {
	case "production":
		return fmt.Sprintf("%-18s %s, %s %s, by %s",
			"production", s(ev, "product", "name"), num(ev, "quantity", "value"),
			s(ev, "quantity", "unit"), s(ev, "party", "name"))
	case "aggregation":
		kids, _ := ev["children"].([]any)
		return fmt.Sprintf("%-18s %s <- %d lots, by %s",
			"aggregation", s(ev, "container", "name"), len(kids), s(ev, "party", "name"))
	case "transport":
		step := "departure"
		if s(ev, "step") == "arrival" {
			step = "arrival"
		}
		return fmt.Sprintf("%-18s %s -> %s, by %s",
			"transport/"+step, s(ev, "from", "name"), s(ev, "to", "name"), s(ev, "party", "name"))
	case "processing":
		outs, _ := ev["outputs"].([]any)
		out := ""
		if len(outs) > 0 {
			out = s(outs[0], "product", "name")
		}
		return fmt.Sprintf("%-18s %s -> %s, by %s",
			"processing", s(ev, "process"), out, s(ev, "party", "name"))
	case "handover":
		return fmt.Sprintf("%-18s %s -> %s (%s)",
			"handover", s(ev, "from", "name"), s(ev, "to", "name"), s(ev, "transaction", "id"))
	case "measurement":
		rs, _ := ev["readings"].([]any)
		return fmt.Sprintf("%-18s %s, %d readings, sensor %s",
			"measurement", s(ev, "quantity_kind"), len(rs), s(ev, "sensor", "id"))
	}
	return e.Type.String()
}

func dig(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}
func s(v any, path ...string) string { x, _ := dig(v, path...).(string); return x }
func num(v any, path ...string) any {
	x := dig(v, path...)
	if f, ok := x.(float64); ok {
		return fmt.Sprintf("%g", f)
	}
	return x
}

// ---------------------------------------------------------------- 6 Cold chain

func (d *demo) coldChain() {
	section("Cold chain: what the sensor says against what was promised")

	promise := d.payloadOf(chain.departure.entryID)
	measured := d.payloadOf(chain.measurement.entryID)

	lower, _ := dig(promise, "conditions", "temperature_c", "min").(float64)
	upper, _ := dig(promise, "conditions", "temperature_c", "max").(float64)
	linef("promised on the freight papers: %.1f to %.1f C (%s)", lower, upper, s(promise, "party", "name"))

	rs, _ := measured["readings"].([]any)
	var breaches int
	for _, r := range rs {
		t := s(r, "t")
		v, _ := dig(r, "v").(float64)
		mark := "within"
		if v < lower || v > upper {
			mark = "BREACH"
			breaches++
		}
		linef("%s  %5.1f C  %s", t[11:16], v, mark)
	}
	if breaches == 0 {
		okf("cold chain held")
		return
	}
	blockedf("%d of %d readings outside the promised range", breaches, len(rs))
	linef("both statements sit signed in the same log, under two different keys.")
	linef("no verdict, only a contradiction that nobody can argue away any more.")
}

func (d *demo) payloadOf(id core.Digest) obj {
	var pr payloadResp
	d.public.get("/owm/v1/entries/"+id.String()+"/payload", &pr)
	var out obj
	must(json.Unmarshal(pr.Payload, &out))
	return out
}

// ---------------------------------------------------------------- 7 Erasure

func (d *demo) erase() {
	section("Erasure under Art. 17 GDPR")

	target := chain.handover
	linef("Feinkost Brunner e.K. asks for erasure: the name of a natural")
	linef("person sits in the payload of handover entry #%d.", target.seq)

	// Beforehand: secure the proof that will be checked afterwards.
	var before owmlog.InclusionProof
	d.public.get(fmt.Sprintf("/owm/v1/proof/inclusion?entry=%s&size=%d", target.entryID, sth1.Size), &before)
	leafHash := owmlog.LeafHashFromBytes(target.leaf)
	must(before.Verify(leafHash, sth1))
	okf("inclusion proof kept from before the erasure (tree size %d)", sth1.Size)

	var out obj
	d.admin.post("/admin/v1/erasures", obj{"entry_id": target.entryID.String()}, &out, http.StatusOK)
	okf("payload and salt erased, tombstone appended")

	st, raw := d.public.call("GET", "/owm/v1/entries/"+target.entryID.String()+"/payload", nil)
	var er errResp
	_ = json.Unmarshal(raw, &er)
	blockedf("payload no longer retrievable: HTTP %d %s", st, er.Error)

	var lv leafView
	d.public.get("/owm/v1/entries/"+target.entryID.String(), &lv)
	linef("leaf #%d is still in the tree, payload status: %s", lv.Seq, lv.Payload)

	// The heart of the matter: the old proof holds unchanged.
	must(before.Verify(leafHash, sth1))
	okf("the proof issued before the erasure still verifies, the tree is unchanged")

	// And the tree has only grown since.
	var resp sthResp
	d.admin.post("/admin/v1/sth", nil, &resp, http.StatusOK)
	must(resp.Signed.Verify(d.nodePub))
	sth2, err := resp.Signed.STH()
	must(err)

	var cp owmlog.ConsistencyProof
	d.public.get(fmt.Sprintf("/owm/v1/proof/consistency?old=%d&new=%d", sth1.Size, sth2.Size), &cp)
	must(cp.Verify(sth1, sth2))
	okf("consistency proof %d -> %d: appended only, nothing rewritten", sth1.Size, sth2.Size)

	// Without the salt the payload cannot be computed back — even if one guesses
	// the plaintext, the key to the commitment is missing.
	se, err := core.ParseSignedEntry(target.entry)
	must(err)
	e, err := se.Entry()
	must(err)
	tries := 200000
	for i := 0; i < tries; i++ {
		var guess core.Salt
		guess[0] = byte(i)
		guess[1] = byte(i >> 8)
		guess[2] = byte(i >> 16)
		if core.VerifyCommitment(e.Commitment, guess, target.payload) {
			must(fmt.Errorf("the commitment was hit with a guessed salt"))
		}
	}
	okf("%d guesses with the plaintext known: no hit (the salt is 2^256 wide)", tries)
}

// ---------------------------------------------------------------- 8 Tampering

func (d *demo) tamper() {
	section("Tampering attempts")

	target := chain.processing

	// a) Alter the entry, keep the signature.
	se, err := core.ParseSignedEntry(target.entry)
	must(err)
	forged := *se
	body := append([]byte(nil), se.EntryBytes...)
	body[len(body)-1] ^= 0x01
	forged.EntryBytes = body
	if forged.Verify(dairy.key.Public()) == nil {
		must(fmt.Errorf("the altered entry was accepted"))
	}
	blockedf("one byte flipped in the entry -> signature invalid")

	// b) Swap the leaf, keep the inclusion proof.
	leaf, err := owmlog.ParseLeaf(target.leaf)
	must(err)
	fenc, err := forged.Encode()
	must(err)
	leaf.Entry = fenc
	fake, err := leaf.Encode()
	must(err)
	var p owmlog.InclusionProof
	d.public.get(fmt.Sprintf("/owm/v1/proof/inclusion?entry=%s&size=%d", target.entryID, sth1.Size), &p)
	if p.Verify(owmlog.LeafHashFromBytes(fake), sth1) == nil {
		must(fmt.Errorf("the altered leaf was covered by the proof"))
	}
	blockedf("altered leaf against the same proof -> does not match the root")

	// c) Sign an STH with a foreign key.
	attacker, err := core.GenerateKey(core.SigAlgMLDSA65)
	must(err)
	rogue := *sth1
	rogue.Root[0] ^= 0xff
	rogue.Key = attacker.Public().ID()
	signed, err := owmlog.SignSTH(attacker, &rogue)
	must(err)
	if signed.Verify(d.nodePub) == nil {
		must(fmt.Errorf("the STH signed with a foreign key was accepted"))
	}
	blockedf("STH signed with a foreign key -> signature does not match the node")

	// d) Split view: the node itself signs two trees of the same size.
	//    Possible because this is our own throwaway node and we can get at its
	//    private key — exactly the case a monitor finds.
	nodeKey := d.readNodeKey()
	evil := *sth1
	evil.Root[0] ^= 0xff
	evilSigned, err := owmlog.SignSTH(nodeKey, &evil)
	must(err)
	must(evilSigned.Verify(d.nodePub)) // validly signed — and false all the same
	evilSTH, err := evilSigned.STH()
	must(err)
	if err := owmlog.CheckSTHPair(sth1, evilSTH); err == nil {
		must(fmt.Errorf("the split view went undetected"))
	} else {
		blockedf("split view detected: %v", err)
		linef("two valid signatures from the same node over the same tree size,")
		linef("with different roots. Only someone who sees both finds it: the monitor.")
	}
}

// readNodeKey reads the private key of the throwaway node from its identity
// file in order to play a malicious operator.
func (d *demo) readNodeKey() *core.PrivateKey {
	raw, err := os.ReadFile(filepath.Join(d.dir, "owm-identity.json"))
	must(err)
	var f struct {
		Alg  string `json:"alg"`
		Seed string `json:"seed"`
	}
	must(json.Unmarshal(raw, &f))
	seed, err := hex.DecodeString(f.Seed)
	must(err)
	k, err := core.NewKeyFromSeed(algByName(f.Alg), seed)
	must(err)
	return k
}

// ---------------------------------------------------------------- 9 Summary

func (d *demo) summary() {
	section("Summary")

	var meta metaResp
	d.public.get("/.well-known/openwaymark", &meta)

	var entryBytes, payloadBytes int
	for _, r := range d.records {
		entryBytes += len(r.entry)
		payloadBytes += len(r.payload)
	}

	linef("leaves in the tree   %d", meta.TreeSize)
	linef("entries written      %d (%d B, avg %d B)", len(d.records), entryBytes, entryBytes/len(d.records))
	linef("payloads             %d B (avg %d B)", payloadBytes, payloadBytes/len(d.records))
	linef("database             %.1f KB", float64(d.dbBytes())/1024)
	linef("the lion's share of an entry is the post-quantum signature:")
	linef("ML-DSA-65 3309 B, ML-DSA-44 2420 B. That is why sensors use 44.")

	if s := d.logs.String(); strings.Contains(s, "panic") {
		fmt.Printf("%s\n", s)
	}
}

// dbBytes counts the database including journal and WAL files: what is still in
// the write-ahead log belongs to the space taken up.
func (d *demo) dbBytes() int64 {
	paths, err := filepath.Glob(filepath.Join(d.dir, "owm.sqlite*"))
	must(err)
	var total int64
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		total += fi.Size()
	}
	return total
}
