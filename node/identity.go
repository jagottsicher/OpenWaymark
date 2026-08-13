// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"openwaymark.org/owm/core"
)

// ErrIdentityExists meldet eine bereits vorhandene Identitätsdatei.
var ErrIdentityExists = errors.New("owm/node: identity file already exists")

// Identity ist die Identität einer Node: der Schlüssel, mit dem sie STHs und
// Löschbezeugungen unterschreibt, und der Gründungsschlüssel, aus dem die
// Log-Kennung abgeleitet ist.
//
// Beide auseinanderzuhalten ist kein Formalismus. Die Log-Kennung leitet sich
// aus dem Gründungsschlüssel ab und darf sich nie ändern; der Signierschlüssel
// darf und soll sich ändern können. Stünde nur einer in der Datei, wechselte
// mit der ersten Rotation die Kennung des Logs — und jeder je ausgestellte
// Verweis darauf wäre wertlos (OWM-2 §2).
type Identity struct {
	Key     *core.PrivateKey
	Genesis *core.PublicKey
	Created time.Time
}

// identityFile ist die Form auf der Platte.
//
// Gespeichert wird der Saatwert, nicht der ausgepackte Schlüssel: FIPS 204
// leitet das Schlüsselpaar deterministisch daraus ab, und 32 Byte Hex sind
// notierbar, sicherbar und im Fehlerfall von Hand prüfbar.
type identityFile struct {
	Alg           string `json:"alg"`
	Seed          string `json:"seed"`
	GenesisPublic string `json:"genesis_public"`
	Created       string `json:"created"`
	Note          string `json:"_note"`
}

const identityNote = "This file IS the node's private key. Mode 0600, never in a repository, never in an unprotected backup."

// CreateIdentity legt eine neue Identität an und schreibt sie nach path.
//
// Eine vorhandene Datei wird nie überschrieben: Der alte Schlüssel wäre fort,
// die Log-Kennung eine andere, und das bestehende Log damit heimatlos.
func CreateIdentity(path string, alg core.SigAlg) (*Identity, error) {
	if !alg.Valid() {
		return nil, fmt.Errorf("%w: %s", core.ErrUnknownAlg, alg)
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrIdentityExists, path)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("owm/node: check identity: %w", err)
	}

	seed := make([]byte, alg.SeedSize())
	key, err := generateSeededKey(alg, seed)
	if err != nil {
		return nil, err
	}
	id := &Identity{Key: key, Genesis: key.Public(), Created: time.Now().UTC().Truncate(time.Second)}

	f := identityFile{
		Alg:           alg.String(),
		Seed:          hex.EncodeToString(seed),
		GenesisPublic: hex.EncodeToString(key.Public().Bytes()),
		Created:       id.Created.Format(time.RFC3339),
		Note:          identityNote,
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("owm/node: encode identity: %w", err)
	}
	data = append(data, '\n')

	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("owm/node: create directory: %w", err)
		}
	}
	// O_EXCL statt eines zweiten Stat: Zwischen Prüfung und Schreiben könnte
	// sonst jemand anders die Datei anlegen.
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrIdentityExists, path)
		}
		return nil, fmt.Errorf("owm/node: write identity: %w", err)
	}
	if _, err := fh.Write(data); err != nil {
		fh.Close()
		return nil, fmt.Errorf("owm/node: write identity: %w", err)
	}
	if err := fh.Close(); err != nil {
		return nil, fmt.Errorf("owm/node: write identity: %w", err)
	}
	return id, nil
}

// LoadIdentity liest eine Identitätsdatei.
func LoadIdentity(path string) (*Identity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("owm/node: read identity: %w", err)
	}
	// Ein für Gruppe oder Welt lesbarer privater Schlüssel ist kein privater
	// Schlüssel mehr. Lieber der Abbruch beim Start als der stille Weiterbetrieb.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("owm/node: %s has mode %#o, expected 0600", path, mode)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("owm/node: read identity: %w", err)
	}
	var f identityFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("owm/node: read identity: %w", err)
	}
	alg, err := ParseSigAlg(f.Alg)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(f.Seed)
	if err != nil {
		return nil, fmt.Errorf("owm/node: seed: %w", err)
	}
	key, err := core.NewKeyFromSeed(alg, seed)
	if err != nil {
		return nil, fmt.Errorf("owm/node: seed: %w", err)
	}

	genesis := key.Public()
	if f.GenesisPublic != "" {
		rawGenesis, err := hex.DecodeString(f.GenesisPublic)
		if err != nil {
			return nil, fmt.Errorf("owm/node: genesis key: %w", err)
		}
		// Der Gründungsschlüssel kann nach einer Rotation ein anderes Verfahren
		// haben als der aktuelle. Deshalb wird sein Verfahren aus der Länge
		// bestimmt und nicht vom aktuellen Schlüssel geerbt.
		galg, err := algForPublicKeySize(len(rawGenesis))
		if err != nil {
			return nil, fmt.Errorf("owm/node: genesis key: %w", err)
		}
		genesis, err = core.ParsePublicKey(galg, rawGenesis)
		if err != nil {
			return nil, fmt.Errorf("owm/node: genesis key: %w", err)
		}
	}

	created, err := time.Parse(time.RFC3339, f.Created)
	if err != nil {
		created = time.Time{}
	}
	return &Identity{Key: key, Genesis: genesis, Created: created.UTC()}, nil
}

// LoadOrCreateIdentity lädt die Identität oder legt sie beim ersten Start an.
func LoadOrCreateIdentity(path string, alg core.SigAlg) (*Identity, error) {
	id, err := LoadIdentity(path)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	return CreateIdentity(path, alg)
}

// LogID liefert die Kennung des Logs dieser Node.
func (i *Identity) LogID() (core.LogID, error) { return core.DeriveLogID(i.Genesis) }

// ParseSigAlg liest einen Verfahrensnamen, wie ihn SigAlg.String schreibt.
func ParseSigAlg(s string) (core.SigAlg, error) {
	switch s {
	case "ML-DSA-44":
		return core.SigAlgMLDSA44, nil
	case "ML-DSA-65":
		return core.SigAlgMLDSA65, nil
	default:
		return 0, fmt.Errorf("%w: %q", core.ErrUnknownAlg, s)
	}
}

// algForPublicKeySize bestimmt das Verfahren aus der Länge eines gepackten
// öffentlichen Schlüssels. Die beiden Längen unterscheiden sich deutlich
// (1312 gegen 1952 Byte), eine Verwechslung ist ausgeschlossen.
func algForPublicKeySize(n int) (core.SigAlg, error) {
	for _, a := range []core.SigAlg{core.SigAlgMLDSA44, core.SigAlgMLDSA65} {
		if a.PublicKeySize() == n {
			return a, nil
		}
	}
	return 0, fmt.Errorf("%w: not %d bytes", core.ErrKeySize, n)
}

// generateSeededKey füllt seed mit Zufall und leitet daraus den Schlüssel ab.
// Der Saatwert bleibt beim Aufrufer, weil er in die Datei geschrieben wird.
func generateSeededKey(alg core.SigAlg, seed []byte) (*core.PrivateKey, error) {
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("owm/node: randomness: %w", err)
	}
	return core.NewKeyFromSeed(alg, seed)
}
