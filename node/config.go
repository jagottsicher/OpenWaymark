// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Voreinstellungen.
const (
	DefaultListen      = "127.0.0.1:8480"
	DefaultAdminListen = "127.0.0.1:8481"
	DefaultDatabase    = "owm.sqlite"
	DefaultIdentity    = "owm-identity.json"

	// DefaultMaxPayload begrenzt eine einzelne Nutzlast. Ein Lieferkettenereignis
	// ist ein Datensatz, kein Dateianhang: Fotos, Laborberichte und Zeugnisse
	// gehören hinter eine URL, deren Hash in der Nutzlast steht.
	DefaultMaxPayload = 256 * 1024

	// DefaultSTHInterval ist der Abstand zwischen zwei Signed Tree Heads.
	//
	// Der Abstand bestimmt, wie lange eine Manipulation unentdeckt bleiben kann,
	// und kostet je Ausgabe eine ML-DSA-Signatur. Eine Minute ist für eine Node
	// auf Raspberry-Pi-Klasse unproblematisch und für einen Beobachter
	// engmaschig genug.
	DefaultSTHInterval = time.Minute
)

// Operator beschreibt die verantwortliche Stelle.
//
// Kein Beiwerk: Im föderierten Modell ist jede Betreiberin für ihre eigenen
// Daten datenschutzrechtlich verantwortlich. Wer ein Auskunfts- oder
// Löschbegehren stellen will, muss erfahren können, an wen.
type Operator struct {
	Name    string `json:"name,omitempty"`
	Contact string `json:"contact,omitempty"`
	Privacy string `json:"privacy,omitempty"`
}

// Config konfiguriert eine Node.
type Config struct {
	// Listen ist die Adresse der öffentlichen API.
	//
	// Die Voreinstellung bindet an localhost. Eine Node gehört hinter einen
	// TLS-terminierenden Reverse-Proxy; von sich aus ins Netz zu greifen ist
	// nichts, was ein Programm ungefragt tun sollte.
	Listen string `json:"listen"`

	// AdminListen ist die Adresse der Verwaltungsschnittstelle. Sie kennt keine
	// Authentifizierung und MUSS deshalb lokal gebunden bleiben.
	AdminListen string `json:"admin_listen"`

	// Database ist der Pfad der SQLite-Datei. ":memory:" für Tests.
	Database string `json:"database"`

	// Identity ist der Pfad der Identitätsdatei.
	Identity string `json:"identity"`

	// BaseURL ist die von außen erreichbare Adresse dieser Node, wie sie im
	// DNS-TXT-Eintrag steht.
	BaseURL string `json:"base_url,omitempty"`

	// Operator ist die verantwortliche Stelle.
	Operator Operator `json:"operator,omitempty"`

	// Profiles nennt die Profile, die diese Node annimmt. Leer bedeutet: alle
	// einkompilierten.
	Profiles []string `json:"profiles,omitempty"`

	// MaxPayload begrenzt eine einzelne Nutzlast in Byte.
	MaxPayload int64 `json:"max_payload,omitempty"`

	// STHInterval ist der Abstand zwischen zwei Signed Tree Heads. Null schaltet
	// die selbsttätige Ausgabe ab; dann bleibt der Weg über die
	// Verwaltungsschnittstelle.
	STHInterval Duration `json:"sth_interval,omitempty"`
}

// DefaultConfig liefert die Voreinstellungen.
func DefaultConfig() Config {
	return Config{
		Listen:      DefaultListen,
		AdminListen: DefaultAdminListen,
		Database:    DefaultDatabase,
		Identity:    DefaultIdentity,
		MaxPayload:  DefaultMaxPayload,
		STHInterval: Duration(DefaultSTHInterval),
	}
}

// LoadConfig liest eine JSON-Konfiguration über den Voreinstellungen.
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("owm/node: read configuration: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// Ein vertipptes Feld ist eine Einstellung, die nicht wirkt — und die
	// Betreiberin glaubt, sie hätte sie gesetzt.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("owm/node: read configuration: %w", err)
	}
	return cfg, cfg.Check()
}

// Check füllt Leerstellen mit Voreinstellungen und prüft den Rest.
func (c *Config) Check() error {
	if c.Listen == "" {
		c.Listen = DefaultListen
	}
	if c.Database == "" {
		c.Database = DefaultDatabase
	}
	if c.Identity == "" {
		c.Identity = DefaultIdentity
	}
	if c.MaxPayload <= 0 {
		c.MaxPayload = DefaultMaxPayload
	}
	if c.STHInterval < 0 {
		return fmt.Errorf("owm/node: sth_interval is negative")
	}
	return nil
}

// Duration ist eine time.Duration, die in JSON als Zeichenkette steht ("5m").
// Eine Zahl allein ließe offen, ob Sekunden oder Nanosekunden gemeint sind.
type Duration time.Duration

func (d Duration) Duration() time.Duration { return time.Duration(d) }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("owm/node: duration expects a string such as \"5m\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("owm/node: duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}
