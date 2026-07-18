// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Command picdemo runs the PIC v0.2 Go prototype scenarios and prints timings.
//
//	go run ./cmd/picdemo [confused-deputy|snapshot|revocation|all]
//
// It is non-normative demonstration code. The PIC Specification is authoritative.
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

	var err error
	switch which {
	case "confused-deputy":
		err = runConfusedDeputy(now)
	case "snapshot":
		err = runSnapshot(now)
	case "revocation":
		err = runRevocation(now)
	case "all":
		if err = runConfusedDeputy(now); err == nil {
			if err = runSnapshot(now); err == nil {
				err = runRevocation(now)
			}
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use: confused-deputy | snapshot | revocation | all)\n", which)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func header(title string) {
	fmt.Printf("\n=== %s ===\n", title)
}

// runConfusedDeputy shows structural confused-deputy prevention.
func runConfusedDeputy(now time.Time) error {
	header("Cross-Service Confused Deputy (Alice → Bob/Archive → Carol/Storage)")
	w, err := scenario.NewWorld(now)
	if err != nil {
		return err
	}

	// Case 1 — Bob's own system-scoped transaction: authorized.
	_, req, res, err := w.Case1Legit(now)
	if err != nil {
		return err
	}
	fmt.Printf("Case 1  Bob's own transaction, read %s\n", req.Target)
	fmt.Printf("        verified=%v  authorized=%v  -> %s\n",
		res.Verified, res.Authorized, verdict(res.Authorized, "ALLOWED (legitimate)", "denied"))

	// Case 2a — Alice via honest Bob: denied at enforcement (no /sys authority).
	_, _, res, err = w.Case2Honest(now)
	if err != nil {
		return err
	}
	fmt.Printf("\nCase 2a Alice's confused-deputy read of %s, Bob forwards honestly\n", scenarioSysFile)
	fmt.Printf("        verified=%v  authorized=%v  -> %s\n",
		res.Verified, res.Authorized, verdict(res.Blocked(), "BLOCKED — authorization denied", "leaked"))
	fmt.Printf("        reason: %v\n", res.AuthErr)

	// Case 2b — malicious Bob injects /sys authority: rejected by non-expansion.
	_, _, res, err = w.Case2Malicious(now)
	if err != nil {
		return err
	}
	fmt.Printf("\nCase 2b Compromised Bob injects read:/sys/* into Alice's lineage\n")
	fmt.Printf("        verified=%v  -> %s\n",
		res.Verified, verdict(!res.Verified, "REJECTED — cannot be validated as a continuation", "accepted"))
	fmt.Printf("        reason: %v\n", res.VerifyErr)
	fmt.Println("\nConfused deputy is structurally impossible: authority absent from the origin")
	fmt.Println("cannot be authorized (2a) or injected downstream (2b).")
	return nil
}

const scenarioSysFile = "/sys/syslog.txt"

// runSnapshot shows the Snapshot Hash Chain profile cost (§5.2).
func runSnapshot(now time.Time) error {
	header("Snapshot Hash Chain profile (Prover/Verifier spec §5.2)")
	const hops, tail, iters = 128, 8, 50
	w, err := scenario.NewWorld(now)
	if err != nil {
		return err
	}
	chain, err := w.BuildChain(hops, now)
	if err != nil {
		return err
	}
	throughIndex := len(chain) - 1 - tail // snapshot near the tip; `tail` hops remain

	snap, err := pic.IssueSnapshot(w.SnapshotIssuer, w.Registry, chain, throughIndex, now)
	if err != nil {
		return err
	}
	tailChain := chain[throughIndex:] // [PCA[k] … PCA[n]]

	full := timeIt(iters, func() error {
		_, e := pic.NewVerifier(w.Registry, nil).VerifyFullChain(chain, now)
		return e
	})
	fromSnap := timeIt(iters, func() error {
		_, e := pic.NewVerifier(w.Registry, nil).VerifyFromSnapshot(snap, tailChain, now)
		return e
	})

	fmt.Printf("chain length: %d PCAs (PCA0 + %d hops)\n", len(chain), hops)
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
	w, err := scenario.NewWorld(now)
	if err != nil {
		return err
	}
	chain, err := w.BuildChain(hops, now)
	if err != nil {
		return err
	}
	lineageID := chain[0].LineageID

	// Before revocation: the whole chain verifies.
	if _, err := pic.NewVerifier(w.Registry, nil).VerifyFullChain(chain, now); err != nil {
		return fmt.Errorf("chain unexpectedly invalid before revocation: %w", err)
	}
	fmt.Printf("lineage %s… length %d: fully valid before revocation\n", lineageID[:20], len(chain))

	// Issue a cutoff from counter 4 onward.
	const fromCounter = 4
	store := pic.NewRevocationStore()
	store.LineageSuffix(lineageID, fromCounter, w.Alice.ID)
	fmt.Printf("issued LINEAGE-SUFFIX(lineage, fromCounter=%d)\n\n", fromCounter)

	v := pic.NewVerifier(w.Registry, store)
	for _, p := range chain {
		verr := v.Revocations.Check(p)
		state := "valid"
		if verr != nil {
			state = "REVOKED"
		}
		fmt.Printf("  counter %d : %s\n", p.LineageCounter, state)
	}

	// Verifying the full chain now stops at the cutoff.
	_, err = pic.NewVerifier(w.Registry, store).VerifyFullChain(chain, now)
	fmt.Printf("\nfull-chain verification now: %s\n", verdict(err != nil, "REJECTED at the cutoff", "accepted"))
	fmt.Printf("reason: %v\n", err)
	return nil
}

// timeIt runs fn iters times and returns the average duration. It panics on
// error so a broken scenario is loud.
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
