// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

// Command picdemo runs the PIC v0.2 Go prototype scenarios and prints timings.
//
//	go run ./cmd/picdemo [why-pic|confused-deputy|snapshot|revocation|guardrail|flow|bench|dump|all] [flags] [dump selectors]
//
// Flags:
//
//	--guardrail   load the Execution Guardrail fixtures (sandbox + guardrail +
//	              simulated PDP) and route each scenario's tip crossing through
//	              them; without it, everything behaves exactly as before.
//	--only-json   emit a single JSON document (for jq) instead of the report.
//
// Dump selectors (with `dump`): pca0|hop0, pca1|hop1, envelope, and with
// --guardrail also policy, scopes, mle, pdp, trace, guard, denytrace.
// No selector prints everything.
//
// It uses the real v0.2 fixtures (DID identities, signed attestations, and the
// guardrail policy/scope bindings) loaded once into memory. It is
// non-normative demonstration code; the PIC Specification is authoritative.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
	"github.com/pic-protocol/pic-prototyping/v0.2/golang/scenario"
)

// opts are the run options shared by every command.
type opts struct {
	guardrail bool
	onlyJSON  bool
	selectors []string
}

func main() {
	which := "all"
	var o opts
	positional := []string{}
	for _, a := range os.Args[1:] {
		switch a {
		case "--guardrail", "-g":
			o.guardrail = true
		case "--only-json", "--json", "-j":
			o.onlyJSON = true
		default:
			positional = append(positional, a)
		}
	}
	if len(positional) > 0 {
		which = positional[0]
		o.selectors = positional[1:]
	}
	now := time.Now()

	steps := map[string]func(time.Time, opts) error{
		"why-pic":         runAuthorityMixing,
		"confused-deputy": runConfusedDeputy,
		"snapshot":        runSnapshot,
		"revocation":      runRevocation,
		"guardrail":       runGuardrail,
	}
	order := []string{"why-pic", "confused-deputy", "snapshot", "revocation"}

	switch which {
	case "dump", "flow", "bench":
		var derr error
		switch which {
		case "flow":
			derr = runFlow(now, o)
		case "bench":
			derr = runBench(now, o)
		default:
			derr = runDump(now, o)
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
		if o.guardrail {
			run = append(run, "guardrail")
		}
	} else if _, ok := steps[which]; ok {
		run = []string{which}
	} else {
		fmt.Fprintf(os.Stderr, "unknown scenario %q (use: %v, guardrail, flow, bench, dump, or all)\n", which, order)
		os.Exit(2)
	}
	for _, name := range run {
		if err := steps[name](now, o); err != nil {
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

// dumpItem is one selectable artifact of the dump.
type dumpItem struct {
	key         string
	aliases     []string
	title       string
	explanation string
	value       any
}

func (d dumpItem) matches(sel string) bool {
	sel = strings.ToLower(sel)
	if sel == d.key {
		return true
	}
	for _, a := range d.aliases {
		if sel == a {
			return true
		}
	}
	// prefix selection: `guard` matches guard, `pol` matches policy, ...
	return len(sel) >= 3 && strings.HasPrefix(d.key, sel)
}

// runDump builds real signed artifacts, verifies them, and runs a live tamper
// proof. With --guardrail it also runs the guarded crossing and exposes its
// artifacts (policy, scopes, MLE, PDP exchange, trace, guardrail envelope).
// Selectors filter what is printed: `dump hop1`, `dump --guardrail guard pdp`.
func runDump(now time.Time, o opts) error {
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

	items := []dumpItem{
		{key: "pca0", aliases: []string{"hop0"},
			title:       "PCA0 (origin, signed by alice)",
			explanation: "Origin PCA (PCA0): starts the lineage, signed by the origin principal (alice). It carries no Proof of Relationship and no predecessor hash; its invariants are the upper bound of authority for the whole lineage.",
			value:       pca0},
		{key: "pca1", aliases: []string{"hop1"},
			title:       "PCA1 (successor: real PoR, previousPcaHash, executor attestation, single signature)",
			explanation: "Successor PCA: continues exactly one predecessor. proofOfRelationship carries previousPcaHash (= PCA0 digest), the continuation-challenge response, the executor request binding, and the executor's signed attestation; a single Ed25519 signature covers the whole PCA.",
			value:       pca1},
		{key: "envelope",
			title:       "Envelope [predecessor, current], signed by the forwarder",
			explanation: "Handoff envelope: carries [predecessor, current] together, signed by the forwarder. The digests are a convenience; a Verifier recomputes them from the PCA bytes.",
			value:       env},
	}

	var g *scenario.GuardedResult
	if o.guardrail {
		g, err = w.Guarded(now)
		if err != nil {
			return err
		}
		items = append(items,
			dumpItem{key: "policy",
				title:       "Guardrail policy (fixture, spec-shaped)",
				explanation: "The configured policy the PDP evaluates: an effect and an elementary CEL-like condition over the participants' semantic scopes. The decision defaults to deny.",
				value:       g.Policy},
			dumpItem{key: "scopes",
				title:       "Semantic-scope bindings (policy-controlled mapping)",
				explanation: "Scopes are bound to a Lineage Execution through its origin grantId (or origin issuer): origin-bound metadata the executor cannot self-assert. A scope adds no authority.",
				value:       g.Scopes},
			dumpItem{key: "mle",
				title:       "Multi-Lineage Execution (the runtime carrier)",
				explanation: "n >= 1 Lineage Executions carried together for one proposed transition. The proposed transition consists exclusively of the concrete signed requests carried by the participants; no authority of its own.",
				value:       g.Permit.MLE},
			dumpItem{key: "pdp",
				title:       "PDP exchange (request → decision)",
				explanation: "What the guardrail hands to the (simulated) PDP — participants with scopes and destination — and the decision that comes back. The guardrail enforces it; the PDP is one possible implementation of policy evaluation.",
				value: map[string]any{
					"request":  g.Permit.Trace.PDPRequest,
					"decision": g.Permit.Trace.Decision,
				}},
			dumpItem{key: "trace",
				title:       "Guardrail enforcement trace (validate → evaluate → enforce)",
				explanation: "What the guardrail did, in enforcement order: PCA validation per participant, the PDP call, and the enforced decision.",
				value:       g.Permit.Trace},
			dumpItem{key: "guard", aliases: []string{"guardrail", "guard1"},
				title:       "Guardrail forwarding envelope (two proofs, never nested)",
				explanation: "The permitted crossing travels in this envelope. forwardingProof (sandbox) attributes the presentation; guardrailProof (guardrail DID) attests validation + policy + permit and covers the forwardingProofDigest. Neither replaces the executor signature on any PCA.",
				value:       g.Permit.Envelope},
			dumpItem{key: "denytrace", aliases: []string{"deny"},
				title:       "Deny trace (A + C, external-sharing)",
				explanation: "The same pipeline denying: the PDP finds a participant whose scopes satisfy no policy alternative; the guardrail enforces deny and issues no envelope.",
				value:       g.Deny.Trace},
		)
	}

	// Selector filtering: print only the requested artifacts.
	if len(o.selectors) > 0 {
		var picked []dumpItem
		for _, sel := range o.selectors {
			found := false
			for _, it := range items {
				if it.matches(sel) {
					picked = append(picked, it)
					found = true
				}
			}
			if !found {
				return fmt.Errorf("dump: unknown selector %q (available: %s)", sel, strings.Join(itemKeys(items), ", "))
			}
		}
		if o.onlyJSON {
			out := map[string]artifact{}
			for _, it := range picked {
				out[it.key] = artifact{Explanation: it.explanation, Value: it.value}
			}
			printJSON(out)
			return nil
		}
		for _, it := range picked {
			fmt.Printf("\n--- %s ---\n", it.title)
			fmt.Println(paint(cDim, wrap(it.explanation, 96)))
			printJSON(it.value)
		}
		return nil
	}

	if o.onlyJSON {
		out := struct {
			Description string              `json:"description"`
			Artifacts   map[string]artifact `json:"artifacts"`
			Checks      map[string]any      `json:"checks"`
		}{
			Description: "Real PIC v0.2 signed artifacts (Ed25519 + SHA-256 hash chain), produced live on this run — nothing precomputed.",
			Artifacts:   map[string]artifact{},
			Checks: map[string]any{
				"pca0Digest":                       d0,
				"previousPcaHashMatchesPca0Digest": pca1.ProofOfRelationship.PreviousPcaHash == d0,
				"verifyFullChainOk":                verifyErr == nil,
				"authority":                        inv.Operations,
				"tamperProof": map[string]any{
					"explanation":       "Editing one signed field (invariants.operations) and re-verifying: the Ed25519 signature no longer verifies, so the edit is rejected.",
					"editedSignedField": "invariants.operations",
					"rejected":          tamperErr != nil,
					"reason":            errString(tamperErr),
				},
			},
		}
		for _, it := range items {
			out.Artifacts[it.key] = artifact{Explanation: it.explanation, Value: it.value}
		}
		if g != nil {
			out.Checks["guardrailReceiver"] = g.Receiver
		}
		printJSON(out)
		return nil
	}

	header("Inspect real artifacts (dump)")
	for _, it := range items {
		fmt.Printf("\n--- %s ---\n", it.title)
		printJSON(it.value)
	}
	fmt.Printf("\nPCA0 digest (content id): %s\n", d0)
	fmt.Printf("PCA1.proofOfRelationship.previousPcaHash == PCA0 digest ? %v\n",
		pca1.ProofOfRelationship.PreviousPcaHash == d0)
	fmt.Printf("VerifyFullChain([PCA0, PCA1]) -> ok=%v, authority=%v\n", verifyErr == nil, inv.Operations)
	fmt.Printf("after editing one signed operation -> rejected=%v\n", tamperErr != nil)
	fmt.Printf("reason: %v\n", tamperErr)
	if g != nil {
		renderReceiver(g.Receiver)
	}
	fmt.Println(paint(cDim, "\nselect artifacts: picdemo dump hop1   |   picdemo dump --guardrail guard pdp"))
	return nil
}

func itemKeys(items []dumpItem) []string {
	var keys []string
	for _, it := range items {
		keys = append(keys, it.key)
	}
	return keys
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
func runAuthorityMixing(now time.Time, o opts) error {
	header("Authority Mixing / invalid cross-lineage import (Why PIC; spec §1.4)")
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
	if o.guardrail {
		chain, err := w.BuildChain(2, now)
		if err != nil {
			return err
		}
		return renderTipGuard(w, chain, "s3://backups/tenant-42", now)
	}
	return nil
}

// runConfusedDeputy shows the cross-service confused-deputy prevention.
func runConfusedDeputy(now time.Time, o opts) error {
	header("Cross-Service Confused Deputy (Alice → Archive → Storage)")
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	legitChain, req, res, err := w.Case1Legit(now)
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
	if o.guardrail {
		return renderTipGuard(w, legitChain, "s3://archive/tenant-42", now)
	}
	return nil
}

// runSnapshot shows the Snapshot Hash Chain profile cost (§5.2).
func runSnapshot(now time.Time, o opts) error {
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
	if o.guardrail {
		return renderTipGuard(w, chain[:2], "s3://backups/tenant-42", now)
	}
	return nil
}

// runRevocation shows a LINEAGE-SUFFIX causal cutoff (Revocation spec §3.1).
func runRevocation(now time.Time, o opts) error {
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
	if o.guardrail {
		return renderTipGuard(w, chain[:2], "s3://backups/tenant-42", now)
	}
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
