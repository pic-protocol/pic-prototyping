// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package scenario

import (
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

// This file reproduces the PIC "Why PIC" page's Authority-Mixing / cross-lineage
// composition example (also Prover/Verifier spec §1.4), using the real fixtures:
//
//   Lineage 1 (summary): origin {read-foo, share-files} -> attenuated to {share-files}
//   Lineage 2 (backup):  origin {read-all,  backup}     -> attenuated to {read-all}
//
// At a shared executor a bug composes read-all (from Lineage 2) with Lineage 1's
// share-files. Under PIC that mixed state is inexpressible: {read-all,share-files}
// is not a non-expansive continuation of Lineage 1's {share-files}.

func summaryOriginInvariants() pic.Invariants {
	return pic.Invariants{
		Operations:        []string{"read-foo", "share-files"},
		ExecutionContract: pic.ExecutionContract{ExecutionModel: "agentic"},
	}
}

func backupOriginInvariants() pic.Invariants {
	return pic.Invariants{
		Operations:        []string{"read-all", "backup"},
		ExecutionContract: pic.ExecutionContract{ExecutionModel: "deterministic"},
	}
}

// MixingResult reports the outcome of the authority-mixing example.
type MixingResult struct {
	LineageBackupAuthority  []string // {read-all}
	LineageSummaryAuthority []string // {share-files}
	HonestAccepted          bool     // honest continuation of the summary lineage
	HonestErr               error
	Composed                bool  // did the composed {read-all, share-files} verify?
	ComposeErr              error // why the composition was rejected
}

// AuthorityMixing builds the two lineages, shows both are individually valid,
// then shows that composing read-all (from the backup lineage) into the summary
// lineage is rejected by PIC while an honest continuation is accepted.
func (w *World) AuthorityMixing(now time.Time) (*MixingResult, error) {
	res := &MixingResult{}

	// Lineage 2 (backup): {read-all, backup} -> {read-all}.
	backup0, err := pic.MintPCA0(w.id("alice"), backupOriginInvariants(), "", now)
	if err != nil {
		return nil, err
	}
	backupReq := pic.Request{Operation: "read-all", Target: "dataset/*", SecurityDomain: "tenant-42"}
	backup1, err := pic.NewProver(w.id("backup-service"), w.att("backup-service")).
		Continue(backup0, pic.Invariants{
			Operations:        []string{"read-all"},
			ExecutionContract: backupOriginInvariants().ExecutionContract,
		}, backupReq, now)
	if err != nil {
		return nil, err
	}
	invA, err := w.verifier().VerifyFullChain([]*pic.PCA{backup0, backup1}, now)
	if err != nil {
		return nil, err
	}
	res.LineageBackupAuthority = invA.Operations

	// Lineage 1 (summary): {read-foo, share-files} -> {share-files}.
	summary0, err := pic.MintPCA0(w.id("alice"), summaryOriginInvariants(), "", now)
	if err != nil {
		return nil, err
	}
	summaryReq := pic.Request{Operation: "share-files", Target: "doc/foo", SecurityDomain: "tenant-42"}
	summary1, err := pic.NewProver(w.id("summary-service"), w.att("summary-service")).
		Continue(summary0, pic.Invariants{
			Operations:        []string{"share-files"},
			ExecutionContract: summaryOriginInvariants().ExecutionContract,
		}, summaryReq, now)
	if err != nil {
		return nil, err
	}
	invB, err := w.verifier().VerifyFullChain([]*pic.PCA{summary0, summary1}, now)
	if err != nil {
		return nil, err
	}
	res.LineageSummaryAuthority = invB.Operations

	// A shared executor continues the summary lineage. Honest: keeps {share-files}.
	archive := pic.NewProver(w.id("archive-service"), w.att("archive-service"))
	honest, err := archive.Continue(summary1, pic.Invariants{
		Operations:        []string{"share-files"},
		ExecutionContract: summaryOriginInvariants().ExecutionContract,
	}, summaryReq, now)
	if err != nil {
		return nil, err
	}
	res.HonestErr = w.verifier().VerifyHop(honest, summary1, now, false)
	res.HonestAccepted = res.HonestErr == nil

	// The bug: compose read-all (borrowed from the backup lineage) with the
	// summary lineage's share-files, and continue the summary lineage.
	composed, err := archive.ContinueMalicious(summary1, pic.Invariants{
		Operations:        []string{"read-all", "share-files"},
		ExecutionContract: summaryOriginInvariants().ExecutionContract,
	}, summaryReq, now)
	if err != nil {
		return nil, err
	}
	res.ComposeErr = w.verifier().VerifyHop(composed, summary1, now, false)
	res.Composed = res.ComposeErr == nil

	return res, nil
}
