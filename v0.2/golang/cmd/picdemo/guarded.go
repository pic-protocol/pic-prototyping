// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
	"github.com/pic-protocol/pic-prototyping/v0.2/golang/scenario"
)

// This file renders the Sandboxed Execution of the prototype: the dedicated
// `guardrail` scenario and the compact block the other scenarios append under
// --guardrail. PIC carries PIC: an outer ENFORCE lineage carries the inner
// Multi-Lineage Execution; the guardrail is the next ordinary executor.

// runGuardrail renders the canonical Sandboxed Execution end to end: the outer
// ENFORCE lineage origin, the carried lineages, the guardrail enforcement
// (validate outer → validate carried → evaluate → prove), the signed outer PCA,
// and the receiving-hop enforced-acceptance / bypass / tamper checks.
func runGuardrail(now time.Time, o opts) error {
	w, err := scenario.NewWorld()
	if err != nil {
		return err
	}
	res, err := w.Guarded(now)
	if err != nil {
		return err
	}
	if o.onlyJSON {
		printJSON(res)
		return nil
	}

	header("Sandboxed Execution — PIC carrying PIC (outer ENFORCE lineage)")
	fmt.Println(paint(cDim, wrap(res.Description, 96)))
	fmt.Printf("\npolicy %s: %s iff %s\n",
		paint(cBold, res.Policy.ID), res.Policy.Effect, paint(cCyan, res.Policy.When))

	fmt.Println()
	renderCarried(res.Permit)

	renderMLEBox(res.Permit)
	renderOriginArrow(res.Origin)
	renderGuardrailBox(res.Permit, true)
	renderReceiver(res.Receiver)

	fmt.Printf("\n%s deny case — %s → %s\n", paint(cBold, "▶"),
		res.Deny.Name, res.Deny.MLE.Destination)
	renderGuardrailBox(res.Deny, false)

	fmt.Printf("\n%s invalid carried-lineage case — %s\n", paint(cBold, "▶"), res.InvalidPCA.Name)
	renderGuardrailBox(res.InvalidPCA, false)

	fmt.Println()
	fmt.Println(paint(cDim, "explore the execution:  picdemo exec                     (compact hop view)"))
	fmt.Println(paint(cDim, "                        picdemo exec --lineage all --pca  (every lineage, full PCAs)"))
	fmt.Println(paint(cDim, "inspect real artifacts: picdemo dump --guardrail          (multiLineage, outer PCA, accept)"))
	return nil
}

// renderCarried prints each carried lineage with its grant → scopes binding and
// its tip authority.
func renderCarried(out *scenario.CrossingOutcome) {
	for _, tp := range out.Trace.CarriedLineages {
		var issuer string
		for _, p := range out.MLE.Participants {
			if p.Label == tp.Label {
				issuer = p.Chain[0].Issuer
			}
		}
		fmt.Printf("%s %s  %s\n", paint(cCyan, "●"),
			paint(cBold, "carried lineage "+tp.Label),
			paint(cDim, fmt.Sprintf("origin %s, %d PCAs", issuer, tp.ChainLen)))
		fmt.Printf("    authority %s   grant %s → scopes %s\n",
			paint(cGreen, fmt.Sprint(tp.Authority)), tp.GrantID,
			paint(cYellow, fmt.Sprint(tp.Scopes)))
	}
}

// renderMLEBox draws the Multi-Lineage Execution carrier: the carried lineages
// travel together, authorities remain separate, one proposed transition.
func renderMLEBox(out *scenario.CrossingOutcome) {
	m := out.MLE
	fmt.Println()
	fmt.Printf("┌ %s %s\n", paint(cBold, "MULTI-LINEAGE EXECUTION"),
		paint(cDim, fmt.Sprintf("— proposing %s → %s", m.Proposing, m.Destination)))
	for _, p := range m.Participants {
		tip := p.Tip()
		line := fmt.Sprintf("│   %s: %v", p.Label, tip.Invariants.Operations)
		if por := tip.ProofOfRelationship; por != nil && p.Label == m.Proposing {
			line += paint(cCyan, fmt.Sprintf("   concrete signed request: %s %s", por.Request.Operation, por.Request.Target))
		}
		fmt.Println(line)
	}
	fmt.Println("│   " + paint(cDim, "carried lineages remain independent; authorities never merged"))
	fmt.Println("└" + strings.Repeat("─", 68))
}

// renderOriginArrow shows the authorized sandbox origin minting PCA0-G, the
// origin of the outer ENFORCE lineage.
func renderOriginArrow(origin *pic.PCA) {
	fmt.Println("        " + paint(cDim, "│"))
	fmt.Printf("        %s %s originates the outer ENFORCE lineage %s\n",
		paint(cCyan, "│ sandbox origin"), paint(cActor, origin.Issuer),
		paint(cDim, "(PCA0-G, authority { ENFORCE })"))
	fmt.Println("        " + paint(cCyan, "▼"))
}

// renderGuardrailBox draws the guardrail phases: validate outer, validate
// carried, evaluate, and prove the next outer PCA (permit) or deny.
func renderGuardrailBox(out *scenario.CrossingOutcome, full bool) {
	t := out.Trace
	fmt.Printf("┌ %s %s\n", paint(cBold, "GUARDRAIL"),
		paint(cActor, t.GuardrailExecutor)+paint(cDim, " — ordinary executor of the outer ENFORCE lineage"))

	// 1. validate outer
	fmt.Printf("│ 1 outer      %s continue PCA%d-G → PCA%d-G\n",
		verdict(t.OuterValid, paint(cGreen, "✔"), paint(cReject, "✗")),
		t.OuterPredecessor, t.OuterPredecessor+1)

	// 2. validate carried lineages
	var parts []string
	for _, tp := range t.CarriedLineages {
		mark := paint(cGreen, "✔")
		if !tp.Valid {
			mark = paint(cReject, "✗")
		}
		parts = append(parts, fmt.Sprintf("%s %s (%d PCAs)", tp.Label, mark, tp.ChainLen))
	}
	fmt.Printf("│ 2 carried    %s\n", strings.Join(parts, "   "))
	for _, tp := range t.CarriedLineages {
		if !tp.Valid {
			fmt.Printf("│              %s\n", paint(cReject, tp.Label+": "+tp.Error))
		}
	}

	// 3. evaluate
	if t.PDPCalled {
		var in []string
		for _, p := range t.PDPRequest.Participants {
			in = append(in, fmt.Sprintf("%s%v", p.Label, p.Scopes))
		}
		fmt.Printf("│ 3 evaluate   enforcement fn ← %s  destination %s\n",
			paint(cYellow, strings.Join(in, " ")), t.PDPRequest.Destination)
		fmt.Printf("│              → %s — %s\n", decision(t.Decision.Effect), t.Decision.Reason)
	} else {
		fmt.Printf("│ 3 evaluate   %s\n", paint(cDim, "skipped — deny before policy evaluation"))
	}

	// 4. prove / deny
	if t.Enforced == "permit" {
		fmt.Printf("│ 4 prove      %s → signs PCA%d-G  request.enforcementResult=permit\n",
			decision("permit"), t.OuterCounter)
		fmt.Printf("│              %s\n", paint(cDim, "request.multiLineageDigest "+shortHash(t.MultiLineageDigest)))
	} else {
		fmt.Printf("│ 4 prove      %s — no authorizing continuation produced\n", decision("deny"))
	}
	fmt.Println("└" + strings.Repeat("─", 68))

	if full && t.Enforced == "permit" {
		fmt.Println("        " + paint(cCyan, "▼") + "  " + paint(cDim, "the outer PCA (PCA1-G) is the guardrail decision; no separate envelope, no second signature"))
	}
}

// renderReceiver shows enforced acceptance and the bypass/tamper rejections at
// the receiving hop.
func renderReceiver(rc scenario.ReceiverChecks) {
	fmt.Printf("\n%s receiving hop — enforced acceptance\n", paint(cBold, "▶"))
	fmt.Printf("  outer PCA             %s\n", verdict(rc.Accepted, paint(cGreen, "ACCEPTED — outer PIC valid, origin authorized, ENFORCE, multiLineageDigest ok, permit, fresh"), paint(cReject, "rejected: "+rc.AcceptErr)))
	fmt.Printf("  bypass (no outer PCA) %s\n", verdict(rc.BypassRejected, paint(cReject, "REJECTED"), "accepted (BUG!)"))
	fmt.Printf("                        %s\n", paint(cDim, rc.BypassReason))
	fmt.Printf("  tampered carried set  %s\n", verdict(rc.TamperRejected, paint(cReject, "REJECTED"), "accepted (BUG!)"))
	fmt.Printf("                        %s\n", paint(cDim, rc.TamperReason))
}

// renderTipGuard is the compact --guardrail augmentation the other scenarios
// append: their tip chain becomes carried lineage A and crosses a Sandboxed
// Execution together with the agent's own carried lineage B.
func renderTipGuard(w *scenario.World, chain []*pic.PCA, destination string, now time.Time) error {
	out, rc, err := w.GuardTip(chain, destination, now)
	if err != nil {
		return err
	}
	t := out.Trace
	fmt.Printf("\n%s\n", paint(cBold, "── sandboxed (--guardrail): the scenario's tip crossing goes through an outer ENFORCE lineage ──"))
	var in []string
	for _, tp := range t.CarriedLineages {
		in = append(in, fmt.Sprintf("%s%v", tp.Label, tp.Scopes))
	}
	fmt.Printf("  carried lineages %s → %s\n", paint(cYellow, strings.Join(in, " + ")), destination)
	fmt.Printf("  guardrail %s: outer %s, carried %s, evaluate %s, prove %s\n",
		t.GuardrailExecutor,
		verdict(t.OuterValid, paint(cGreen, "✔"), paint(cReject, "✗")),
		verdict(t.CarriedValid, paint(cGreen, "✔"), paint(cReject, "✗")),
		decision(t.Decision.Effect),
		verdict(t.Enforced == "permit", paint(cGreen, "✔ PCA1-G signed"), paint(cDim, "not produced")))
	if t.Enforced == "permit" {
		fmt.Printf("  receiver: outer PCA %s   bypass %s\n",
			verdict(rc.Accepted, paint(cGreen, "ACCEPTED"), paint(cReject, "rejected")),
			verdict(rc.BypassRejected, paint(cReject, "REJECTED"), "accepted (BUG!)"))
	} else {
		fmt.Printf("  %s\n", paint(cReject, "crossing blocked: "+out.Err))
	}
	return nil
}

// decision paints permit green and deny red, uppercase.
func decision(effect string) string {
	if effect == "permit" {
		return paint(cGreen, "PERMIT")
	}
	return paint(cReject, "DENY")
}
