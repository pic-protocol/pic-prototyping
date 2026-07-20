// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package scenario

import (
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

// This file runs the canonical Sandboxed Execution of the PIC Sandboxed
// Execution Specification: PIC carrying PIC. An AI agent holds the user's
// Lineage Execution A and mints its own Lineage Execution B; the two are
// proposed together as one Multi-Lineage Execution. An authorized sandbox origin
// originates the outer ENFORCE lineage (PCA0-G); the guardrail — an ordinary
// executor of that outer lineage — validates every carried lineage, evaluates
// the enforcement function, and on permit proves the next ordinary outer PCA
// carrying the signed multiLineage. A receiving hop then runs enforced acceptance.

// Grant identifiers bound to semantic scopes by the fixtures.
const (
	GrantUserBackup      = "urn:pic:grant:user-backup"
	GrantAgentS3Writer   = "urn:pic:grant:agent-s3-writer"
	GrantExternalSharing = "urn:pic:grant:external-sharing"
)

// Guardrail builds the fixture guardrail executor: its identity and attestation,
// the enforcement function (simulated PDP over the fixture policy), and the
// fixture scope bindings.
func (w *World) Guardrail() *pic.Guardrail {
	return pic.NewGuardrail(w.id("guardrail"), w.att("guardrail"), w.Set.Registry,
		&pic.LocalPDP{Policy: w.Set.Policy}, w.Set.Policy, w.Set.Scopes)
}

// EnforcementOrigin is the authorized sandbox origin that may mint PCA0-G.
func (w *World) EnforcementOrigin() *pic.Identity { return w.id("enforcement-origin") }

// AcceptedOrigins are the sandbox origins a receiving hop accepts.
func (w *World) AcceptedOrigins() []string { return []string{w.EnforcementOrigin().ID} }

// CrossingOutcome is one guarded crossing: the input Multi-Lineage Execution,
// the guardrail's enforcement trace, and (on permit) the outer ENFORCE lineage
// chain [PCA0-G, PCA1-G] that carries the decision.
type CrossingOutcome struct {
	Name       string                     `json:"name"`
	MLE        *pic.MultiLineageExecution `json:"multiLineageExecution"`
	Trace      *pic.EnforcementTrace      `json:"trace"`
	OuterChain []*pic.PCA                 `json:"outerChain,omitempty"`
	OuterPCA   *pic.PCA                   `json:"outerPca,omitempty"`
	Err        string                     `json:"error,omitempty"`
}

// ReceiverChecks is what a receiving hop does with the permitted crossing — and
// what happens to bypass and tamper attempts, under enforced acceptance.
type ReceiverChecks struct {
	Accepted       bool   `json:"accepted"`
	AcceptErr      string `json:"acceptError,omitempty"`
	BypassRejected bool   `json:"bypassRejected"`
	BypassReason   string `json:"bypassReason"`
	TamperRejected bool   `json:"tamperRejected"`
	TamperReason   string `json:"tamperReason"`
}

// GuardedResult is the full canonical Sandboxed Execution scenario.
type GuardedResult struct {
	Description string              `json:"description"`
	Origin      *pic.PCA            `json:"originPca0G"`
	Policy      pic.Policy          `json:"policy"`
	Scopes      map[string][]string `json:"scopeBindings"`
	Permit      *CrossingOutcome    `json:"permit"`
	Deny        *CrossingOutcome    `json:"deny"`
	InvalidPCA  *CrossingOutcome    `json:"invalidPca"`
	Receiver    ReceiverChecks      `json:"receiver"`
}

// Guarded runs the canonical example end to end. Every PCA and decision is
// really minted, signed, and verified on this call.
func (w *World) Guarded(now time.Time) (*GuardedResult, error) {
	g := w.Guardrail()
	agent := w.id("summary-service") // the AI agent (agentic fixture executor)
	agentAtt := w.att("summary-service")
	contract := pic.ExecutionContract{}

	// Lineage Execution A — user authority: alice grants {read-all, backup}; the
	// agent receives PCA1-A {backup} through a real PoR hop.
	pca0A, err := pic.MintPCA0(w.id("alice"),
		pic.Invariants{Operations: []string{"read-all", "backup"}, ExecutionContract: contract},
		GrantUserBackup, now)
	if err != nil {
		return nil, err
	}
	pca1A, err := pic.NewProver(agent, agentAtt).Continue(pca0A,
		pic.Invariants{Operations: []string{"backup"}, ExecutionContract: contract},
		pic.Request{Operation: "backup", Target: "/user/dataset", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}
	chainA := []*pic.PCA{pca0A, pca1A}

	dest := "s3://backups/tenant-42"
	chainB, err := w.agentLineage(agent, agentAtt, GrantAgentS3Writer,
		[]string{"write:s3/backups/*"},
		pic.Request{Operation: "write", Target: "s3/backups/tenant-42/dataset.tar", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}

	res := &GuardedResult{
		Description: "Canonical Sandboxed Execution (PIC of PIC): an authorized sandbox origin originates the outer ENFORCE lineage (PCA0-G). The AI agent holds the user's Lineage Execution A and its own Lineage Execution B and proposes the S3 write as one Multi-Lineage Execution. The guardrail — an ordinary executor of the outer lineage — validates every carried lineage, evaluates the enforcement function, and on permit proves the next ordinary outer PCA (PCA1-G) carrying the signed multiLineage. Authorities remain separate; nothing is merged.",
		Policy:      w.Set.Policy,
		Scopes:      w.Set.Scopes,
	}

	// Crossing 1 — PERMIT: A (data-protection) + B (data-protection, ai-compliance).
	sePermit, err := pic.Originate(w.EnforcementOrigin(), now)
	if err != nil {
		return nil, err
	}
	res.Origin = sePermit.Origin()
	mle := &pic.MultiLineageExecution{
		Participants: []pic.Participant{
			{Label: "A", Chain: chainA, Role: "user-backup"},
			{Label: "B", Chain: chainB, Role: "agent-s3-writer"},
		},
		Proposing:   "B",
		Destination: dest,
	}
	outer, trace, err := g.Enforce(sePermit, mle, now)
	res.Permit = &CrossingOutcome{Name: "A+B write to S3", MLE: mle, Trace: trace,
		OuterChain: sePermit.Chain, OuterPCA: outer, Err: errStr(err)}

	// Crossing 2 — DENY: A + C (external-sharing); the enforcement condition fails.
	chainC, err := w.agentLineage(agent, agentAtt, GrantExternalSharing,
		[]string{"share-public"},
		pic.Request{Operation: "share-public", Target: "s3/backups/tenant-42/dataset.tar", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}
	seDeny, err := pic.Originate(w.EnforcementOrigin(), now)
	if err != nil {
		return nil, err
	}
	mleDeny := &pic.MultiLineageExecution{
		Participants: []pic.Participant{
			{Label: "A", Chain: chainA, Role: "user-backup"},
			{Label: "C", Chain: chainC, Role: "external-sharing"},
		},
		Proposing:   "C",
		Destination: "https://public.example/share",
	}
	outerDeny, traceDeny, err := g.Enforce(seDeny, mleDeny, now)
	res.Deny = &CrossingOutcome{Name: "A+C public share", MLE: mleDeny, Trace: traceDeny,
		OuterPCA: outerDeny, Err: errStr(err)}

	// Crossing 3 — INVALID carried lineage: a maliciously expanded successor B'.
	// The guardrail denies at validation, without evaluating policy.
	rogue, err := pic.NewProver(agent, agentAtt).ContinueMalicious(chainB[0],
		pic.Invariants{Operations: []string{"write:s3/backups/*", "delete:s3/*"}, ExecutionContract: contract},
		pic.Request{Operation: "delete", Target: "s3/backups/tenant-42", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}
	seBad, err := pic.Originate(w.EnforcementOrigin(), now)
	if err != nil {
		return nil, err
	}
	mleBad := &pic.MultiLineageExecution{
		Participants: []pic.Participant{
			{Label: "A", Chain: chainA, Role: "user-backup"},
			{Label: "B'", Chain: []*pic.PCA{chainB[0], rogue}, Role: "agent-s3-writer"},
		},
		Proposing:   "B'",
		Destination: dest,
	}
	outerBad, traceBad, err := g.Enforce(seBad, mleBad, now)
	res.InvalidPCA = &CrossingOutcome{Name: "A+B' expanded authority", MLE: mleBad, Trace: traceBad,
		OuterPCA: outerBad, Err: errStr(err)}

	// Receiving hop: enforced acceptance of the permitted outer chain, plus
	// bypass (no outer chain) and tamper (edited carried lineage) rejections.
	res.Receiver = w.receiverChecks(res.Permit.OuterChain, now)
	return res, nil
}

// agentLineage mints the agent's own origin under the given grant and continues
// it once with the concrete signed request.
func (w *World) agentLineage(agent *pic.Identity, att pic.Attestation, grant string, ops []string, req pic.Request, now time.Time) ([]*pic.PCA, error) {
	contract := pic.ExecutionContract{}
	pca0, err := pic.MintPCA0(agent, pic.Invariants{Operations: ops, ExecutionContract: contract}, grant, now)
	if err != nil {
		return nil, err
	}
	pca1, err := pic.NewProver(agent, att).Continue(pca0,
		pic.Invariants{Operations: ops, ExecutionContract: contract}, req, now)
	if err != nil {
		return nil, err
	}
	return []*pic.PCA{pca0, pca1}, nil
}

// receiverChecks runs enforced acceptance on a permitted outer chain: accept it,
// reject a bypass (no outer chain), reject a tampered copy (edited carried lineage).
func (w *World) receiverChecks(outerChain []*pic.PCA, now time.Time) ReceiverChecks {
	rc := ReceiverChecks{}
	origins := w.AcceptedOrigins()

	verr := pic.AcceptGuardedCrossing(w.Set.Registry, nil, origins, outerChain, now)
	rc.Accepted = len(outerChain) > 0 && verr == nil
	rc.AcceptErr = errStr(verr)

	berr := pic.AcceptGuardedCrossing(w.Set.Registry, nil, origins, nil, now)
	rc.BypassRejected = berr != nil
	rc.BypassReason = errStr(berr)

	if len(outerChain) > 0 {
		tampered := tamperOuterChain(outerChain)
		terr := pic.AcceptGuardedCrossing(w.Set.Registry, nil, origins, tampered, now)
		rc.TamperRejected = terr != nil
		rc.TamperReason = errStr(terr)
	}
	return rc
}

// tamperOuterChain returns a copy of the outer chain whose tip carries a
// mutated multiLineage (edited destination), so the recomputed multiLineageDigest
// no longer matches the signed request (and the PCA signature no longer verifies).
func tamperOuterChain(outerChain []*pic.PCA) []*pic.PCA {
	out := make([]*pic.PCA, len(outerChain))
	copy(out, outerChain)
	tip := *out[len(out)-1]
	if tip.MultiLineage != nil {
		ml := *tip.MultiLineage
		ctx := ml.Context
		ctx.Destination = "s3://attacker/exfil"
		ml.Context = ctx
		tip.MultiLineage = &ml
	}
	out[len(out)-1] = &tip
	return out
}

// GuardTip carries an existing chain as Lineage Execution A through a Sandboxed
// Execution: the AI agent mints its own Lineage Execution B for the destination
// write and proposes the joint crossing. It is the shared `--guardrail`
// augmentation used by the other scenarios.
func (w *World) GuardTip(chain []*pic.PCA, destination string, now time.Time) (*CrossingOutcome, ReceiverChecks, error) {
	g := w.Guardrail()
	agent := w.id("summary-service")
	chainB, err := w.agentLineage(agent, w.att("summary-service"), GrantAgentS3Writer,
		[]string{"write:s3/backups/*"},
		pic.Request{Operation: "write", Target: "s3/backups/tenant-42/result.tar", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, ReceiverChecks{}, err
	}
	se, err := pic.Originate(w.EnforcementOrigin(), now)
	if err != nil {
		return nil, ReceiverChecks{}, err
	}
	mle := &pic.MultiLineageExecution{
		Participants: []pic.Participant{
			{Label: "A", Chain: chain, Role: "user-backup"},
			{Label: "B", Chain: chainB, Role: "agent-s3-writer"},
		},
		Proposing:   "B",
		Destination: destination,
	}
	outer, trace, err := g.Enforce(se, mle, now)
	out := &CrossingOutcome{Name: "tip crossing", MLE: mle, Trace: trace,
		OuterChain: se.Chain, OuterPCA: outer, Err: errStr(err)}
	if err != nil {
		return out, ReceiverChecks{}, nil
	}
	return out, w.receiverChecks(se.Chain, now), nil
}
