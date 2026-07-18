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
	"encoding/json"
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

	if which == "dump" || which == "flow" {
		onlyJSON := false
		for _, a := range os.Args[2:] {
			if a == "--only-json" || a == "--json" || a == "-j" {
				onlyJSON = true
			}
		}
		var derr error
		if which == "flow" {
			derr = runFlow(now, onlyJSON)
		} else {
			derr = runDump(now, onlyJSON)
		}
		if derr != nil {
			fmt.Fprintln(os.Stderr, "error:", derr)
			os.Exit(1)
		}
		return
	}

	var run []string
	if which == "all" {
		run = order
	} else if _, ok := steps[which]; ok {
		run = []string{which}
	} else {
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use: %v, flow, dump, or all)\n", which, order)
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

// artifact pairs a real signed object with a one-line explanation of what it is.
type artifact struct {
	Explanation string `json:"explanation"`
	Value       any    `json:"value"`
}

// dumpOutput is the single valid JSON document emitted by `dump --only-json`,
// suitable for piping to jq. Every value is produced live on this run.
type dumpOutput struct {
	Description string `json:"description"`
	Artifacts   struct {
		PCA0     artifact `json:"pca0"`
		PCA1     artifact `json:"pca1"`
		Envelope artifact `json:"envelope"`
	} `json:"artifacts"`
	Checks struct {
		PCA0Digest                       string   `json:"pca0Digest"`
		PreviousPcaHashMatchesPCA0Digest bool     `json:"previousPcaHashMatchesPca0Digest"`
		VerifyFullChainOK                bool     `json:"verifyFullChainOk"`
		Authority                        []string `json:"authority"`
		TamperProof                      struct {
			Explanation       string `json:"explanation"`
			EditedSignedField string `json:"editedSignedField"`
			Rejected          bool   `json:"rejected"`
			Reason            string `json:"reason"`
		} `json:"tamperProof"`
	} `json:"checks"`
}

// runDump builds real signed artifacts (PCA0, a successor PCA with its Proof of
// Relationship, and an envelope), verifies them, and runs a live tamper proof:
// editing one signed field makes verification fail, because the Ed25519 signature
// really covers the content. Nothing is precomputed. With onlyJSON it emits a
// single valid JSON document (for jq); otherwise a human-readable report.
func runDump(now time.Time, onlyJSON bool) error {
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	chain, err := w.BuildChain(2, now)
	if err != nil {
		return err
	}
	pca0, pca1 := chain[0], chain[1]
	d0, _ := pca0.Digest()
	env, err := pic.WrapEnvelope(w.Set.Identity("gateway"), pca0, pca1)
	if err != nil {
		return err
	}
	inv, verifyErr := pic.NewVerifier(w.Set.Registry, nil).VerifyFullChain(chain[:2], now)

	// Live tamper proof: edit one signed operation, re-verify, then restore.
	saved := pca1.Invariants.Operations
	pca1.Invariants.Operations = append([]string{"read:/sys/*"}, saved...)
	tamperErr := pic.NewVerifier(w.Set.Registry, nil).VerifyHop(pca1, pca0, now, false)
	pca1.Invariants.Operations = saved

	if onlyJSON {
		var out dumpOutput
		out.Description = "Real PIC v0.2 signed artifacts (Ed25519 + SHA-256 hash chain), produced live on this run — nothing precomputed."
		out.Artifacts.PCA0 = artifact{
			Explanation: "Origin PCA (PCA0): starts the lineage, signed by the origin principal (alice). It carries no Proof of Relationship and no predecessor hash; its invariants are the upper bound of authority for the whole lineage.",
			Value:       pca0,
		}
		out.Artifacts.PCA1 = artifact{
			Explanation: "Successor PCA: continues exactly one predecessor. proofOfRelationship carries previousPcaHash (= PCA0 digest), the continuation-challenge response, the executor request binding, and the executor's signed attestation; a single Ed25519 signature covers the whole PCA.",
			Value:       pca1,
		}
		out.Artifacts.Envelope = artifact{
			Explanation: "Handoff envelope: carries [predecessor, current] together, signed by the forwarder. The digests are a convenience; a Verifier recomputes them from the PCA bytes.",
			Value:       env,
		}
		out.Checks.PCA0Digest = d0
		out.Checks.PreviousPcaHashMatchesPCA0Digest = pca1.ProofOfRelationship.PreviousPcaHash == d0
		out.Checks.VerifyFullChainOK = verifyErr == nil
		out.Checks.Authority = inv.Operations
		out.Checks.TamperProof.Explanation = "Editing one signed field (invariants.operations) and re-verifying: the Ed25519 signature no longer verifies, so the edit is rejected."
		out.Checks.TamperProof.EditedSignedField = "invariants.operations"
		out.Checks.TamperProof.Rejected = tamperErr != nil
		out.Checks.TamperProof.Reason = errString(tamperErr)
		printJSON(out)
		return nil
	}

	header("Inspect real artifacts (dump)")
	fmt.Println("\n--- PCA0 (origin, signed by alice) ---")
	printJSON(pca0)
	fmt.Printf("PCA0 digest (content id): %s\n", d0)
	fmt.Println("\n--- PCA1 (successor: real PoR, previousPcaHash, executor attestation, single signature) ---")
	printJSON(pca1)
	fmt.Printf("PCA1.proofOfRelationship.previousPcaHash == PCA0 digest ? %v\n",
		pca1.ProofOfRelationship.PreviousPcaHash == d0)
	fmt.Println("\n--- Envelope [predecessor, current], signed by the forwarder ---")
	printJSON(env)
	fmt.Printf("\nVerifyFullChain([PCA0, PCA1]) -> ok=%v, authority=%v\n", verifyErr == nil, inv.Operations)
	fmt.Printf("after editing one signed operation -> rejected=%v\n", tamperErr != nil)
	fmt.Printf("reason: %v\n", tamperErr)
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Println("(marshal error:", err, ")")
		return
	}
	fmt.Println(string(b))
}

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
