// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Command picdemo runs the PIC v0.2 Go prototype scenarios and prints timings.
//
//	go run ./cmd/picdemo [why-pic|confused-deputy|snapshot|revocation|all]
//
// It uses the real v0.2 fixtures (DID identities and signed attestations) loaded
// once into memory. It is non-normative demonstration code; the PIC
// Specification is authoritative.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
	"github.com/pic-protocol/pic-prototyping/v0.2/golang/scenario"
)

func main() {
	which := "all"
	if len(os.Args) > 1 {
		which = os.Args[1]
	}
	now := time.Now()

	steps := map[string]func(time.Time) error{
		"why-pic":         runAuthorityMixing,
		"confused-deputy": runConfusedDeputy,
		"snapshot":        runSnapshot,
		"revocation":      runRevocation,
	}
	order := []string{"why-pic", "confused-deputy", "snapshot", "revocation"}

	var run []string
	if which == "all" {
		run = order
	} else if _, ok := steps[which]; ok {
		run = []string{which}
	} else {
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use: %v or all)\n", which, order)
		os.Exit(2)
	}
	for _, name := range run {
		if err := steps[name](now); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	}
}

func header(title string) { fmt.Printf("\n=== %s ===\n", title) }

// runAuthorityMixing reproduces the "Why PIC" authority-mixing example.
func runAuthorityMixing(now time.Time) error {
	header("Authority Mixing / cross-lineage composition (Why PIC; spec §1.4)")
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	res, err := w.AuthorityMixing(now)
	if err != nil {
		return err
	}
	fmt.Printf("Lineage 2 (backup):  origin {read-all, backup}     -> attenuated to %v  [valid]\n", res.LineageBackupAuthority)
	fmt.Printf("Lineage 1 (summary): origin {read-foo, share-files} -> attenuated to %v  [valid]\n", res.LineageSummaryAuthority)
	fmt.Printf("\nShared executor continues the summary lineage:\n")
	fmt.Printf("  honest    keep {share-files}                 -> %s\n",
		verdict(res.HonestAccepted, "ACCEPTED", "rejected"))
	fmt.Printf("  bug/mix   {read-all (from Lineage 2), share-files} -> %s\n",
		verdict(!res.Composed, "REJECTED — mixed state is inexpressible", "accepted"))
	fmt.Printf("  reason: %v\n", res.ComposeErr)
	fmt.Println("\nread-all belongs to the backup lineage; it has no Proof of Relationship")
	fmt.Println("into the summary lineage, so PIC cannot represent the composed state.")
	return nil
}

// runConfusedDeputy shows the cross-service confused-deputy prevention.
func runConfusedDeputy(now time.Time) error {
	header("Cross-Service Confused Deputy (Alice → Archive → Storage)")
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	_, req, res, err := w.Case1Legit(now)
	if err != nil {
		return err
	}
	fmt.Printf("Case 1  Archive's own transaction, read %s\n", req.Target)
	fmt.Printf("        verified=%v  authorized=%v  -> %s\n",
		res.Verified, res.Authorized, verdict(res.Authorized, "ALLOWED (legitimate)", "denied"))

	_, _, res, err = w.Case2Honest(now)
	if err != nil {
		return err
	}
	fmt.Printf("\nCase 2a Alice's confused-deputy read of /sys/syslog.txt, Archive forwards honestly\n")
	fmt.Printf("        verified=%v  authorized=%v  -> %s\n",
		res.Verified, res.Authorized, verdict(res.Blocked(), "BLOCKED — authorization denied", "leaked"))
	fmt.Printf("        reason: %v\n", res.AuthErr)

	_, _, res, err = w.Case2Malicious(now)
	if err != nil {
		return err
	}
	fmt.Printf("\nCase 2b Compromised Archive injects read:/sys/* into Alice's lineage\n")
	fmt.Printf("        verified=%v  -> %s\n",
		res.Verified, verdict(!res.Verified, "REJECTED — cannot be validated as a continuation", "accepted"))
	fmt.Printf("        reason: %v\n", res.VerifyErr)
	return nil
}

// runSnapshot shows the Snapshot Hash Chain profile cost (§5.2).
func runSnapshot(now time.Time) error {
	header("Snapshot Hash Chain profile (Prover/Verifier spec §5.2)")
	const hops, tail, iters = 128, 8, 50
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	chain, err := w.BuildChain(hops, now)
	if err != nil {
		return err
	}
	throughIndex := len(chain) - 1 - tail
	snap, err := pic.IssueSnapshot(w.Set.Identity("snapshot-issuer"), w.Set.Registry, chain, throughIndex, now)
	if err != nil {
		return err
	}
	tailChain := chain[throughIndex:]

	full := timeIt(iters, func() error {
		_, e := pic.NewVerifier(w.Set.Registry, nil).VerifyFullChain(chain, now)
		return e
	})
	fromSnap := timeIt(iters, func() error {
		_, e := pic.NewVerifier(w.Set.Registry, nil).VerifyFromSnapshot(snap, tailChain, now)
		return e
	})

	fmt.Printf("chain length: %d PCAs (PCA0 + %d hops, real fixture executors)\n", len(chain), hops)
	fmt.Printf("full-chain verify   O(n)          : %10s   (%d hops walked)\n", full, hops)
	fmt.Printf("snapshot at PCA[%d], %d hops after it\n", throughIndex, tail)
	fmt.Printf("verify from snapshot O(since snap) : %10s   (%d hops walked)\n", fromSnap, tail)
	if fromSnap > 0 {
		fmt.Printf("speedup: %.1fx  (both accept the same tip authority)\n", float64(full)/float64(fromSnap))
	}
	return nil
}

// runRevocation shows a LINEAGE-SUFFIX causal cutoff (Revocation spec §3.1).
func runRevocation(now time.Time) error {
	header("Revocation — LINEAGE-SUFFIX causal cutoff (Revocation spec §3.1)")
	const hops = 6
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	chain, err := w.BuildChain(hops, now)
	if err != nil {
		return err
	}
	lineageID := chain[0].LineageID
	if _, err := pic.NewVerifier(w.Set.Registry, nil).VerifyFullChain(chain, now); err != nil {
		return fmt.Errorf("chain unexpectedly invalid before revocation: %w", err)
	}
	fmt.Printf("lineage %s… length %d: fully valid before revocation\n", lineageID[:20], len(chain))

	const fromCounter = 4
	store := pic.NewRevocationStore()
	store.LineageSuffix(lineageID, fromCounter, w.Set.Identity("alice").ID)
	fmt.Printf("issued LINEAGE-SUFFIX(lineage, fromCounter=%d)\n\n", fromCounter)

	for _, p := range chain {
		state := "valid"
		if store.Check(p) != nil {
			state = "REVOKED"
		}
		fmt.Printf("  counter %d : %s\n", p.LineageCounter, state)
	}
	_, err = pic.NewVerifier(w.Set.Registry, store).VerifyFullChain(chain, now)
	fmt.Printf("\nfull-chain verification now: %s\n", verdict(err != nil, "REJECTED at the cutoff", "accepted"))
	fmt.Printf("reason: %v\n", err)
	return nil
}

// timeIt runs fn iters times and returns the average duration.
func timeIt(iters int, fn func() error) time.Duration {
	start := time.Now()
	for i := 0; i < iters; i++ {
		if err := fn(); err != nil {
			panic(err)
		}
	}
	return time.Since(start) / time.Duration(iters)
}

func verdict(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
