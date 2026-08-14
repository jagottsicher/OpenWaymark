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

// ErrIdentityExists reports an identity file that is already there.
var ErrIdentityExists = errors.New("owm/node: identity file already exists")

// Identity is a node's identity: the key it signs STHs and erasure witnesses
// with, and the genesis key the log ID is derived from.
//
// Keeping the two apart is not a formality. The log ID derives from the genesis
// key and must never change; the signing key may and should be able to change.
// Were only one of them in the file, the first rotation would change the log's
// identifier — and every reference to it ever issued would be worthless
// (OWM-2 §2).
type Identity struct {
	Key     *core.PrivateKey
	Genesis *core.PublicKey
	Created time.Time
}

// identityFile is the on-disk form.
//
// What gets stored is the seed, not the expanded key: FIPS 204 derives the key
// pair from it deterministically, and 32 bytes of hex can be written down,
// backed up and checked by hand when something goes wrong.
type identityFile struct {
	Alg           string `json:"alg"`
	Seed          string `json:"seed"`
	GenesisPublic string `json:"genesis_public"`
	Created       string `json:"created"`
	Note          string `json:"_note"`
}

const identityNote = "This file IS the node's private key. Mode 0600, never in a repository, never in an unprotected backup."

// CreateIdentity creates a new identity and writes it to path.
//
// An existing file is never overwritten: the old key would be gone, the log ID
// a different one, and the existing log thereby homeless.
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
	// O_EXCL instead of a second stat: between check and write somebody else
	// could otherwise create the file.
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

// LoadIdentity reads an identity file.
func LoadIdentity(path string) (*Identity, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("owm/node: read identity: %w", err)
	}
	// A private key readable by group or world is no longer a private key.
	// Better to abort at startup than to quietly carry on.
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
		// After a rotation the genesis key can use a different algorithm than
		// the current one. Its algorithm is therefore determined from the length
		// rather than inherited from the current key.
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

// LoadOrCreateIdentity loads the identity or creates it on first start.
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

// LogID returns the identifier of this node's log.
func (i *Identity) LogID() (core.LogID, error) { return core.DeriveLogID(i.Genesis) }

// ParseSigAlg reads an algorithm name as SigAlg.String writes it.
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

// algForPublicKeySize determines the algorithm from the length of a packed
// public key. The two lengths differ clearly (1312 against 1952 bytes), so
// there is no room for a mix-up.
func algForPublicKeySize(n int) (core.SigAlg, error) {
	for _, a := range []core.SigAlg{core.SigAlgMLDSA44, core.SigAlgMLDSA65} {
		if a.PublicKeySize() == n {
			return a, nil
		}
	}
	return 0, fmt.Errorf("%w: not %d bytes", core.ErrKeySize, n)
}

// generateSeededKey fills seed with randomness and derives the key from it.
// The seed stays with the caller because it gets written into the file.
func generateSeededKey(alg core.SigAlg, seed []byte) (*core.PrivateKey, error) {
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("owm/node: randomness: %w", err)
	}
	return core.NewKeyFromSeed(alg, seed)
}
