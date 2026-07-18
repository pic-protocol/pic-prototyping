// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func testInvariants() Invariants {
	return Invariants{
		Operations: []string{"read:/user/*", "write:/user/*"},
		ExecutionContract: ExecutionContract{
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
		},
	}
}

func newExecutor(t testing.TB, reg *Registry, org *Identity, id string, now time.Time) (*Identity, Attestation) {
	t.Helper()
	ex, err := NewIdentity(id)
	if err != nil {
		t.Fatalf("NewIdentity: %v", err)
	}
	reg.Add(ex)
	att, err := SignAttestation(Attestation{
		Subject: ex.ID,
		Attributes: ContractAttributes{
			Compliance:     []string{"GDPR"},
			ExecutionModel: "deterministic",
		},
		IssuedAt:  now.Add(-time.Hour),
		ExpiresAt: now.Add(24 * time.Hour),
	}, org)
	if err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	return ex, att
}

// buildChain returns a valid lineage of hops+1 PCAs, its registry, and a
// registered snapshot-issuer identity.
func buildChain(t testing.TB, hops int, now time.Time) (*Registry, []*PCA, *Identity) {
	t.Helper()
	reg := NewRegistry()
	alice, _ := NewIdentity("did:example:alice")
	org, _ := NewIdentity("did:example:org")
	snap, _ := NewIdentity("did:example:snapshot")
	reg.Add(alice)
	reg.Add(org)
	reg.Add(snap)

	pca0, err := MintPCA0(alice, testInvariants(), "", now)
	if err != nil {
		t.Fatalf("MintPCA0: %v", err)
	}
	chain := []*PCA{pca0}
	req := Request{Operation: "read", Target: "/user/file", SecurityDomain: "tenant-1"}
	for i := 0; i < hops; i++ {
		ex, att := newExecutor(t, reg, org, fmt.Sprintf("did:example:hop-%d", i), now)
		p, err := NewProver(ex, att).Continue(chain[len(chain)-1], testInvariants(), req, now)
		if err != nil {
			t.Fatalf("Continue hop %d: %v", i, err)
		}
		chain = append(chain, p)
	}
	return reg, chain, snap
}

func TestOriginAndHopValid(t *testing.T) {
	now := time.Now()
	reg, chain, _ := buildChain(t, 3, now)
	inv, err := NewVerifier(reg, nil).VerifyFullChain(chain, now)
	if err != nil {
		t.Fatalf("valid chain rejected: %v", err)
	}
	if len(inv.Operations) != 2 {
		t.Fatalf("tip authority = %v, want 2 operations", inv.Operations)
	}
}

func TestLineageDerivation(t *testing.T) {
	now := time.Now()
	_, chain, _ := buildChain(t, 0, now)
	pca0 := chain[0]
	want, err := deriveLineageID(pca0)
	if err != nil {
		t.Fatal(err)
	}
	if pca0.LineageID != want {
		t.Fatalf("lineageId mismatch")
	}
	if pca0.BranchID != rootBranchID(pca0.LineageID) {
		t.Fatalf("branchId is not the derived root branch id")
	}
	if !strings.HasPrefix(pca0.LineageID, "sha256:") {
		t.Fatalf("lineageId not a sha256 digest: %q", pca0.LineageID)
	}
}

func TestNonExpansionRejected(t *testing.T) {
	now := time.Now()
	reg := NewRegistry()
	alice, _ := NewIdentity("did:example:alice")
	org, _ := NewIdentity("did:example:org")
	reg.Add(alice)
	reg.Add(org)
	pca0, _ := MintPCA0(alice, testInvariants(), "", now)
	bob, att := newExecutor(t, reg, org, "did:example:bob", now)

	expanded := Invariants{
		Operations:        []string{"read:/user/*", "read:/sys/*"}, // /sys not in origin
		ExecutionContract: testInvariants().ExecutionContract,
	}
	req := Request{Operation: "read", Target: "/sys/secret", SecurityDomain: "sys"}

	// Honest prover refuses to build it.
	if _, err := NewProver(bob, att).Continue(pca0, expanded, req, now); err == nil {
		t.Fatal("honest prover built an expansive successor")
	}
	// A malicious prover can build it, but the Verifier rejects it.
	mal, err := NewProver(bob, att).ContinueMalicious(pca0, expanded, req, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewVerifier(reg, nil).VerifyHop(mal, pca0, now, false); err == nil {
		t.Fatal("verifier accepted an expansive successor")
	}
}

func TestTamperDetected(t *testing.T) {
	now := time.Now()
	reg, chain, _ := buildChain(t, 1, now)
	// Tamper with the signed invariants after the fact.
	chain[1].Invariants.Operations = []string{"read:/user/*", "write:/user/*", "read:/sys/*"}
	if err := NewVerifier(reg, nil).VerifyHop(chain[1], chain[0], now, false); err == nil {
		t.Fatal("tampered PCA passed integrity check")
	}
}

func TestPredecessorBinding(t *testing.T) {
	now := time.Now()
	reg, chain, _ := buildChain(t, 2, now)
	// Validate hop 2 against the wrong predecessor (PCA0 instead of PCA1).
	if err := NewVerifier(reg, nil).VerifyHop(chain[2], chain[0], now, false); err == nil {
		t.Fatal("hop validated against the wrong predecessor")
	}
}

func TestSnapshotMatchesFullChain(t *testing.T) {
	now := time.Now()
	reg, chain, snapIssuer := buildChain(t, 16, now)

	fullInv, err := NewVerifier(reg, nil).VerifyFullChain(chain, now)
	if err != nil {
		t.Fatalf("full chain: %v", err)
	}
	throughIndex := len(chain) - 1 - 4
	snap, err := IssueSnapshot(snapIssuer, reg, chain, throughIndex, now)
	if err != nil {
		t.Fatalf("IssueSnapshot: %v", err)
	}
	snapInv, err := NewVerifier(reg, nil).VerifyFromSnapshot(snap, chain[throughIndex:], now)
	if err != nil {
		t.Fatalf("VerifyFromSnapshot: %v", err)
	}
	if len(snapInv.Operations) != len(fullInv.Operations) {
		t.Fatalf("snapshot tip authority differs from full-chain")
	}
}

func TestSnapshotRefusesInvalidChain(t *testing.T) {
	now := time.Now()
	reg, chain, snapIssuer := buildChain(t, 4, now)
	chain[2].Invariants.Operations = append(chain[2].Invariants.Operations, "read:/sys/*") // break it
	if _, err := IssueSnapshot(snapIssuer, reg, chain, 3, now); err == nil {
		t.Fatal("snapshot issued over an invalid chain")
	}
}

func TestRevocationLineageSuffix(t *testing.T) {
	now := time.Now()
	reg, chain, _ := buildChain(t, 6, now)
	lineageID := chain[0].LineageID

	store := NewRevocationStore()
	store.LineageSuffix(lineageID, 4, "did:example:alice")

	for _, p := range chain {
		err := store.Check(p)
		if p.LineageCounter >= 4 && err == nil {
			t.Fatalf("counter %d should be revoked", p.LineageCounter)
		}
		if p.LineageCounter < 4 && err != nil {
			t.Fatalf("counter %d should be valid: %v", p.LineageCounter, err)
		}
	}
	if _, err := NewVerifier(reg, store).VerifyFullChain(chain, now); err == nil {
		t.Fatal("revoked chain accepted")
	}
}

func TestChallengeSingleUse(t *testing.T) {
	now := time.Now()
	reg, chain, _ := buildChain(t, 1, now)
	env, err := WrapEnvelope(mustIdentity(t, reg), chain[0], chain[1])
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(reg, nil)
	if _, err := v.VerifyEnvelope(env, now); err != nil {
		t.Fatalf("first acceptance failed: %v", err)
	}
	if _, err := v.VerifyEnvelope(env, now); err == nil {
		t.Fatal("single-use challenge accepted twice (replay)")
	}
}

// mustIdentity registers and returns a forwarder identity for envelope tests.
func mustIdentity(t testing.TB, reg *Registry) *Identity {
	t.Helper()
	id, err := NewIdentity("did:example:forwarder")
	if err != nil {
		t.Fatal(err)
	}
	reg.Add(id)
	return id
}
