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

// These benchmarks run on the real fixtures. The fixtures are loaded once in
// setup (cached by fixtureset.Load), so the timed loop touches no disk.

func BenchmarkVerifyFixtureChain64(b *testing.B) {
	now := time.Now()
	w, err := NewWorld() // loads (and caches) fixtures once
	if err != nil {
		b.Fatal(err)
	}
	chain, err := w.BuildChain(64, now)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pic.NewVerifier(w.Set.Registry, nil).VerifyFullChain(chain, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyFixtureSnapshot64Tail8(b *testing.B) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		b.Fatal(err)
	}
	chain, err := w.BuildChain(64, now)
	if err != nil {
		b.Fatal(err)
	}
	through := len(chain) - 1 - 8
	snap, err := pic.IssueSnapshot(w.Set.Identity("snapshot-issuer"), w.Set.Registry, chain, through, now)
	if err != nil {
		b.Fatal(err)
	}
	tail := chain[through:]
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pic.NewVerifier(w.Set.Registry, nil).VerifyFromSnapshot(snap, tail, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthorityMixing(b *testing.B) {
	now := time.Now()
	w, err := NewWorld()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := w.AuthorityMixing(now); err != nil {
			b.Fatal(err)
		}
	}
}
