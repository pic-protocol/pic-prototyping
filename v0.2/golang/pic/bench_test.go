// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"testing"
	"time"
)

func BenchmarkMintPCA0(b *testing.B) {
	now := time.Now()
	alice, _ := NewIdentity("did:example:alice")
	inv := testInvariants()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := MintPCA0(alice, inv, "", now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProveHop(b *testing.B) {
	now := time.Now()
	reg := NewRegistry()
	alice, _ := NewIdentity("did:example:alice")
	org, _ := NewIdentity("did:example:org")
	reg.Add(alice)
	reg.Add(org)
	pca0, _ := MintPCA0(alice, testInvariants(), "", now)
	ex, att := newExecutor(b, reg, org, "did:example:hop", now)
	pr := NewProver(ex, att)
	req := Request{Operation: "read", Target: "/user/file", SecurityDomain: "t"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pr.Continue(pca0, testInvariants(), req, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyHop(b *testing.B) {
	now := time.Now()
	reg, chain, _ := buildChain(b, 1, now)
	v := NewVerifier(reg, nil)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.VerifyHop(chain[1], chain[0], now, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyFullChain64(b *testing.B) {
	now := time.Now()
	reg, chain, _ := buildChain(b, 64, now)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewVerifier(reg, nil).VerifyFullChain(chain, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyFromSnapshot64Tail8(b *testing.B) {
	now := time.Now()
	reg, chain, snapIssuer := buildChain(b, 64, now)
	throughIndex := len(chain) - 1 - 8
	snap, err := IssueSnapshot(snapIssuer, reg, chain, throughIndex, now)
	if err != nil {
		b.Fatal(err)
	}
	tail := chain[throughIndex:]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewVerifier(reg, nil).VerifyFromSnapshot(snap, tail, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDigest(b *testing.B) {
	now := time.Now()
	_, chain, _ := buildChain(b, 1, now)
	pca := chain[1]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pca.Digest(); err != nil {
			b.Fatal(err)
		}
	}
}
