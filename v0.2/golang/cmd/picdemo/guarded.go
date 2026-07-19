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

// This file renders the guarded crossings of the Execution Guardrail
// prototype: the dedicated `guardrail` scenario and the compact block the
// other scenarios append under --guardrail.

// runGuardrail renders the canonical guarded crossing end to end: the two
// Lineage Executions, the Multi-Lineage Execution, the sandbox presentation,
// the guardrail enforcement (validate → evaluate via PDP → enforce), the
// signed guardrail envelope, and the receiver / bypass / tamper checks.
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

	header("Guarded crossing — sandbox + Execution Guardrail")
	fmt.Println(paint(cDim, wrap(res.Description, 96)))
	fmt.Printf("\npolicy %s: %s iff %s\n",
		paint(cBold, res.Policy.ID), res.Policy.Effect, paint(cCyan, res.Policy.When))

	// The two Lineage Executions of the permit crossing.
	fmt.Println()
	renderParticipants(res.Permit)

	// The guarded path of the permit crossing, step by step.
	renderMLEBox(res.Permit)
	renderSandboxArrow(res.Permit)
	renderGuardrailBox(res.Permit, true)
	renderReceiver(res.Receiver)

	// Deny and invalid-PCA crossings, compact.
	fmt.Printf("\n%s deny case — %s → %s\n", paint(cBold, "▶"),
		res.Deny.Name, res.Deny.MLE.Destination)
	renderGuardrailBox(res.Deny, false)

	fmt.Printf("\n%s invalid-PCA case — %s\n", paint(cBold, "▶"), res.InvalidPCA.Name)
	renderGuardrailBox(res.InvalidPCA, false)

	fmt.Println()
	fmt.Println(paint(cDim, "inspect the real signed artifacts: picdemo dump --guardrail            (everything)"))
	fmt.Println(paint(cDim, "                                   picdemo dump --guardrail guard      (guardrail envelope)"))
	fmt.Println(paint(cDim, "                                   picdemo dump --guardrail pdp policy  (PDP exchange + policy)"))
	return nil
}

// renderParticipants prints each Lineage Execution with its grant → scopes
// binding and its tip authority.
func renderParticipants(out *scenario.CrossingOutcome) {
	for _, tp := range out.Trace.Participants {
		origin := out.MLE
		var issuer string
		for _, p := range origin.Participants {
			if p.Label == tp.Label {
				issuer = p.Chain[0].Issuer
			}
		}
		fmt.Printf("%s %s  %s\n", paint(cCyan, "●"),
			paint(cBold, "Lineage Execution "+tp.Label),
			paint(cDim, fmt.Sprintf("origin %s, %d PCAs", issuer, tp.ChainLen)))
		fmt.Printf("    authority %s   grant %s → scopes %s\n",
			paint(cGreen, fmt.Sprint(tp.Authority)), tp.GrantID,
			paint(cYellow, fmt.Sprint(tp.Scopes)))
	}
}

// renderMLEBox draws the Multi-Lineage Execution carrier: the participants
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
	fmt.Println("│   " + paint(cDim, "authorities remain separate; never merged"))
	fmt.Println("└" + strings.Repeat("─", 68))
}

// renderSandboxArrow shows the sandbox capturing the crossing and signing the
// forwardingProof — the executor cannot skip this step.
func renderSandboxArrow(out *scenario.CrossingOutcome) {
	fmt.Println("        " + paint(cDim, "│"))
	fmt.Printf("        %s %s captures the crossing\n", paint(cCyan, "│ sandbox"),
		paint(cActor, out.Trace.ForwardedBy))
	if out.Envelope != nil {
		fmt.Printf("        %s\n", paint(cDim, "│   forwardingProof signed by "+out.Envelope.ForwardingProof.VerificationMethod))
	} else {
		fmt.Println("        " + paint(cDim, "│   forwardingProof signed (presentation attributed to the sandbox)"))
	}
	fmt.Println("        " + paint(cCyan, "▼"))
}

// renderGuardrailBox draws the enforcement order: validate, evaluate, enforce.
func renderGuardrailBox(out *scenario.CrossingOutcome, full bool) {
	t := out.Trace
	fmt.Printf("┌ %s\n", paint(cBold, "EXECUTION GUARDRAIL")+" "+paint(cActor, "did:web:guardrail.example"))

	// 1. validate
	var parts []string
	for _, tp := range t.Participants {
		mark := paint(cGreen, "✔")
		if !tp.Valid {
			mark = paint(cReject, "✗")
		}
		parts = append(parts, fmt.Sprintf("%s %s (%d PCAs)", tp.Label, mark, tp.ChainLen))
	}
	fmt.Printf("│ 1 validate   %s\n", strings.Join(parts, "   "))
	for _, tp := range t.Participants {
		if !tp.Valid {
			fmt.Printf("│              %s\n", paint(cReject, tp.Label+": "+tp.Error))
		}
	}

	// 2. evaluate
	if t.PDPCalled {
		var in []string
		for _, p := range t.PDPRequest.Participants {
			in = append(in, fmt.Sprintf("%s%v", p.Label, p.Scopes))
		}
		fmt.Printf("│ 2 evaluate   PDP ← participants %s  destination %s\n",
			paint(cYellow, strings.Join(in, " ")), t.PDPRequest.Destination)
		fmt.Printf("│              PDP → %s — %s\n", decision(t.Decision.Effect), t.Decision.Reason)
	} else {
		fmt.Printf("│ 2 evaluate   %s\n", paint(cDim, "skipped — deny enforced without evaluating policy"))
	}

	// 3. enforce
	if out.Envelope != nil {
		fmt.Printf("│ 3 enforce    %s → guardrailProof signed by %s\n",
			decision("permit"), out.Envelope.GuardrailProof.VerificationMethod)
		fmt.Printf("│              %s\n", paint(cDim, "covers forwardingProofDigest "+shortHash(out.Envelope.GuardrailProof.ForwardingProofDigest)))
	} else {
		fmt.Printf("│ 3 enforce    %s — crossing blocked, no envelope issued\n", decision("deny"))
	}
	fmt.Println("└" + strings.Repeat("─", 68))

	if full && out.Envelope != nil {
		fmt.Println("        " + paint(cCyan, "▼") + "  " + paint(cDim, "guardrail forwarding envelope (replaces the ordinary envelope; never nested)"))
	}
}

// renderReceiver shows the sandbox-mode acceptance and the bypass/tamper
// rejections at the receiving hop.
func renderReceiver(rc scenario.ReceiverChecks) {
	fmt.Printf("\n%s receiving hop in sandbox mode\n", paint(cBold, "▶"))
	fmt.Printf("  envelope              %s\n", verdict(rc.EnvelopeAccepted, paint(cGreen, "ACCEPTED — both proofs verify, digests recomputed, freshness ok"), paint(cReject, "rejected: "+rc.EnvelopeErr)))
	fmt.Printf("  bypass (no envelope)  %s\n", verdict(rc.BypassRejected, paint(cReject, "REJECTED"), "accepted (BUG!)"))
	fmt.Printf("                        %s\n", paint(cDim, rc.BypassReason))
	fmt.Printf("  tampered destination  %s\n", verdict(rc.TamperRejected, paint(cReject, "REJECTED"), "accepted (BUG!)"))
	fmt.Printf("                        %s\n", paint(cDim, rc.TamperReason))
}

// renderTipGuard is the compact --guardrail augmentation the other scenarios
// append: their tip chain becomes Lineage Execution A and crosses the guarded
// boundary together with the agent's own Lineage Execution B.
func renderTipGuard(w *scenario.World, chain []*pic.PCA, destination string, now time.Time) error {
	out, rc, err := w.GuardTip(chain, destination, now)
	if err != nil {
		return err
	}
	t := out.Trace
	fmt.Printf("\n%s\n", paint(cBold, "── guarded (--guardrail): the scenario's tip crossing goes through sandbox + guardrail ──"))
	var in []string
	for _, tp := range t.Participants {
		in = append(in, fmt.Sprintf("%s%v", tp.Label, tp.Scopes))
	}
	fmt.Printf("  participants %s → %s\n", paint(cYellow, strings.Join(in, " + ")), destination)
	fmt.Printf("  sandbox %s → forwardingProof %s   guardrail: validate %s, PDP %s, guardrailProof %s\n",
		t.ForwardedBy,
		paint(cGreen, "✔"),
		verdict(t.PCAsValid, paint(cGreen, "✔"), paint(cReject, "✗")),
		decision(t.Decision.Effect),
		verdict(out.Envelope != nil, paint(cGreen, "✔ signed"), paint(cDim, "not issued")))
	if out.Envelope != nil {
		fmt.Printf("  receiver: envelope %s   bypass %s\n",
			verdict(rc.EnvelopeAccepted, paint(cGreen, "ACCEPTED"), paint(cReject, "rejected")),
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
