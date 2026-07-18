// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Package fixtureset loads the v0.2 JSON fixtures (DID identities and signed
// attestations) once and caches them in memory, so scenarios and benchmarks pay
// no per-use disk cost. Call Load() from setup; the first call reads disk, all
// later calls return the cached set.
package fixtureset

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

var b64 = base64.RawURLEncoding

// Set is the loaded, cached fixture cast: a key registry with every identity,
// the identities by actor name, and the signed executor attestations by name.
type Set struct {
	Registry     *pic.Registry
	Identities   map[string]*pic.Identity
	Attestations map[string]pic.Attestation
}

// Identity returns the loaded identity for an actor name, or panics if absent
// (a missing fixture is a programming error in the demo, not a runtime input).
func (s *Set) Identity(name string) *pic.Identity {
	id, ok := s.Identities[name]
	if !ok {
		panic("fixtureset: unknown identity " + name)
	}
	return id
}

// Attestation returns the loaded signed attestation for an executor name.
func (s *Set) Attestation(name string) pic.Attestation {
	att, ok := s.Attestations[name]
	if !ok {
		panic("fixtureset: unknown attestation " + name)
	}
	return att
}

var (
	once   sync.Once
	cached *Set
	loaded error
)

// Load reads the fixtures once and returns the cached set on every later call.
func Load() (*Set, error) {
	once.Do(func() { cached, loaded = load(fixturesDir()) })
	return cached, loaded
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	D   string `json:"d"`
}

func load(dir string) (*Set, error) {
	set := &Set{
		Registry:     pic.NewRegistry(),
		Identities:   map[string]*pic.Identity{},
		Attestations: map[string]pic.Attestation{},
	}

	idRoot := filepath.Join(dir, "identities")
	entries, err := os.ReadDir(idRoot)
	if err != nil {
		return nil, fmt.Errorf("read identities: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		raw, err := os.ReadFile(filepath.Join(idRoot, name, "private.jwk"))
		if err != nil {
			return nil, err
		}
		var k jwk
		if err := json.Unmarshal(raw, &k); err != nil {
			return nil, fmt.Errorf("%s private.jwk: %w", name, err)
		}
		seed, err := b64.DecodeString(k.D)
		if err != nil {
			return nil, fmt.Errorf("%s seed: %w", name, err)
		}
		did := k.Kid
		if i := strings.IndexByte(did, '#'); i >= 0 {
			did = did[:i]
		}
		id, err := pic.LoadIdentity(did, k.Kid, seed)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		set.Identities[name] = id
		set.Registry.Add(id)
	}

	attRoot := filepath.Join(dir, "attestations")
	attEntries, err := os.ReadDir(attRoot)
	if err != nil {
		return nil, fmt.Errorf("read attestations: %w", err)
	}
	for _, e := range attEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(attRoot, e.Name()))
		if err != nil {
			return nil, err
		}
		var att pic.Attestation
		if err := json.Unmarshal(raw, &att); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		set.Attestations[strings.TrimSuffix(e.Name(), ".json")] = att
	}
	return set, nil
}

// fixturesDir resolves v0.2/fixtures relative to this source file, so loading
// works from any working directory (demo, tests, benchmarks).
func fixturesDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return filepath.Join("..", "fixtures")
	}
	// file = .../v0.2/golang/fixtureset/load.go
	return filepath.Join(filepath.Dir(file), "..", "..", "fixtures")
}
