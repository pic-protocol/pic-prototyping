// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Command genfixtures deterministically (re)generates the v0.2 fixtures: a DID
// document and Ed25519 key per actor, plus signed attestations for the executor
// hops. Output goes to v0.2/fixtures. Keys are throwaway, for demos and tests.
//
//	go run ./cmd/genfixtures [output-dir]
package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

// actor describes one fixture identity. Executors also get a signed attestation.
type actor struct {
	name       string
	did        string
	role       string // empty for non-executors (principal / issuer)
	execModel  string
	compliance []string
	isExecutor bool
}

// The fixture cast: the origin principal (alice), the attestation issuer
// (org-authority), the snapshot validator, and the executor hops used by the
// Authority-Mixing (Why PIC) and cross-service confused-deputy scenarios.
var actors = []actor{
	{name: "alice", did: "did:web:alice.example"},
	{name: "org-authority", did: "did:web:org-authority.example"},
	{name: "snapshot-issuer", did: "did:web:snapshot.example"},
	{name: "gateway", did: "did:web:gateway.example", role: "gateway", execModel: "deterministic", isExecutor: true},
	{name: "backup-service", did: "did:web:backup.example", role: "backup-service", execModel: "deterministic", compliance: []string{"GDPR"}, isExecutor: true},
	{name: "summary-service", did: "did:web:summary.example", role: "summary-service", execModel: "agentic", isExecutor: true},
	{name: "archive-service", did: "did:web:archive.example", role: "archive-service", execModel: "deterministic", compliance: []string{"GDPR"}, isExecutor: true},
	{name: "storage-service", did: "did:web:storage.example", role: "storage-service", execModel: "deterministic", compliance: []string{"GDPR"}, isExecutor: true},
}

// Fixed, wide validity window so attestations verify regardless of run date.
var (
	fxIssued  = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fxExpires = time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
)

func main() {
	outDir := defaultFixturesDir()
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := run(outDir); err != nil {
		fmt.Fprintln(os.Stderr, "genfixtures:", err)
		os.Exit(1)
	}
	fmt.Printf("fixtures written to %s\n", outDir)
}

func run(outDir string) error {
	// deterministic identities, built first so the issuer key is available.
	ids := map[string]*pic.Identity{}
	for _, a := range actors {
		id, err := pic.LoadIdentity(a.did, a.did+"#key-1", seedFor(a.name))
		if err != nil {
			return err
		}
		ids[a.name] = id
	}
	org := ids["org-authority"]

	for _, a := range actors {
		id := ids[a.name]
		dir := filepath.Join(outDir, "identities", a.name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "did.json"), didDocument(id)); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "private.jwk"), privateJWK(id)); err != nil {
			return err
		}
		if a.isExecutor {
			att, err := pic.SignAttestation(pic.Attestation{
				Subject: id.ID,
				Attributes: pic.ContractAttributes{
					Role:           a.role,
					Compliance:     a.compliance,
					ExecutionModel: a.execModel,
					Environment:    "production",
					Region:         "eu-1",
				},
				IssuedAt:  fxIssued,
				ExpiresAt: fxExpires,
			}, org)
			if err != nil {
				return err
			}
			adir := filepath.Join(outDir, "attestations")
			if err := os.MkdirAll(adir, 0o755); err != nil {
				return err
			}
			if err := writeJSON(filepath.Join(adir, a.name+".json"), att); err != nil {
				return err
			}
		}
	}
	return nil
}

// seedFor derives a deterministic 32-byte Ed25519 seed from the actor name.
func seedFor(name string) []byte {
	sum := sha256.Sum256([]byte("PIC-v0.2-fixture-seed:" + name))
	return sum[:]
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid,omitempty"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
}

func privateJWK(id *pic.Identity) jwk {
	return jwk{Kty: "OKP", Crv: "Ed25519", Kid: id.VerificationMethod, X: id.EncodePublic(), D: id.Seed()}
}

type verificationMethod struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Controller   string `json:"controller"`
	PublicKeyJwk jwk    `json:"publicKeyJwk"`
}

type didDoc struct {
	Context            []string             `json:"@context"`
	ID                 string               `json:"id"`
	VerificationMethod []verificationMethod `json:"verificationMethod"`
	AssertionMethod    []string             `json:"assertionMethod"`
	Authentication     []string             `json:"authentication"`
}

func didDocument(id *pic.Identity) didDoc {
	return didDoc{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: id.ID,
		VerificationMethod: []verificationMethod{{
			ID:           id.VerificationMethod,
			Type:         "Ed25519VerificationKey2020",
			Controller:   id.ID,
			PublicKeyJwk: jwk{Kty: "OKP", Crv: "Ed25519", Kid: id.VerificationMethod, X: id.EncodePublic()},
		}},
		AssertionMethod: []string{id.VerificationMethod},
		Authentication:  []string{id.VerificationMethod},
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// defaultFixturesDir resolves v0.2/fixtures relative to this source file, so the
// generator works regardless of the current working directory.
func defaultFixturesDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "fixtures"
	}
	// file = .../v0.2/golang/cmd/genfixtures/main.go
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "fixtures")
}
