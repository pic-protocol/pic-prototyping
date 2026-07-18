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
