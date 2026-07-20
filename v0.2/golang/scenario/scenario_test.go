// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package scenario

import (
	"testing"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

func TestAuthorityMixingRejectsComposition(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.AuthorityMixing(now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.HonestAccepted {
		t.Fatalf("honest continuation of the summary lineage rejected: %v", res.HonestErr)
	}
	if res.Composed {
		t.Fatal("cross-lineage composition {read-all, share-files} was accepted — authority mixing not prevented")
	}
	if len(res.LineageBackupAuthority) != 1 || res.LineageBackupAuthority[0] != "read-all" {
		t.Fatalf("backup lineage authority = %v, want [read-all]", res.LineageBackupAuthority)
	}
}

func TestCase1LegitAllowed(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	_, _, res, err := w.Case1Legit(now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified || !res.Authorized {
		t.Fatalf("legitimate system transaction not allowed: %+v", res)
	}
}

func TestCase2HonestBlocked(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	_, _, res, err := w.Case2Honest(now)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("honest forward should verify: %v", res.VerifyErr)
	}
	if res.Authorized {
		t.Fatal("confused-deputy read was authorized — system data would leak")
	}
}

func TestCase2MaliciousRejected(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	_, _, res, err := w.Case2Malicious(now)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified {
		t.Fatal("expansive injection was accepted — non-expansion not enforced")
	}
}

func TestBuildChainVerifies(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	chain, err := w.BuildChain(10, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pic.NewVerifier(w.Set.Registry, nil).VerifyFullChain(chain, now); err != nil {
		t.Fatalf("built chain does not verify: %v", err)
	}
	if len(chain) != 11 {
		t.Fatalf("chain length = %d, want 11", len(chain))
	}
}

func TestSandboxedExecution(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.Guarded(now)
	if err != nil {
		t.Fatal(err)
	}

	// Permit: the guardrail produced an outer PCA1-G continuing PCA0-G, with
	// enforcementResult=permit and a committed multiLineage.
	if res.Permit.Err != "" {
		t.Fatalf("permit crossing errored: %s", res.Permit.Err)
	}
	if res.Permit.OuterPCA == nil || res.Permit.OuterPCA.LineageCounter != 1 {
		t.Fatal("permit did not produce PCA1-G")
	}
	if res.Permit.OuterPCA.ProofOfRelationship.Request.EnforcementResult != "permit" {
		t.Fatal("outer PCA enforcementResult is not permit")
	}
	if res.Permit.OuterPCA.MultiLineage == nil || len(res.Permit.OuterPCA.MultiLineage.CarriedLineages) != 2 {
		t.Fatal("outer PCA does not carry the two carried lineages")
	}

	// Deny and invalid: no authorizing continuation produced.
	if res.Deny.OuterPCA != nil {
		t.Fatal("deny produced an authorizing continuation")
	}
	if res.InvalidPCA.OuterPCA != nil {
		t.Fatal("invalid carried lineage produced an authorizing continuation")
	}

	// Enforced acceptance: permit accepted; bypass and tamper rejected.
	if !res.Receiver.Accepted {
		t.Fatalf("receiver rejected a valid permit: %s", res.Receiver.AcceptErr)
	}
	if !res.Receiver.BypassRejected {
		t.Fatal("bypass (no outer PCA) was not rejected")
	}
	if !res.Receiver.TamperRejected {
		t.Fatal("tampered carried set was not rejected")
	}
}

func TestAcceptGuardedCrossingRejectsUnauthorizedOrigin(t *testing.T) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.Guarded(now)
	if err != nil {
		t.Fatal(err)
	}
	// A receiving hop that does not accept the enforcement origin must reject
	// even a fully valid outer chain (a valid signature is not authorization).
	err = pic.AcceptGuardedCrossing(w.Set.Registry, nil,
		[]string{"did:web:someone-else.example"}, res.Permit.OuterChain, now)
	if err == nil {
		t.Fatal("accepted an outer chain from an unauthorized sandbox origin")
	}
}
