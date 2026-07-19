// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package scenario

import (
	"time"

	"github.com/pic-protocol/pic-prototyping/v0.2/golang/pic"
)

// This file runs the canonical guarded crossing of the PIC Execution Guardrail
// Specification: an AI agent holds the user's Lineage Execution A, mints its
// own Lineage Execution B, and proposes the S3 write as one Multi-Lineage
// Execution. The sandbox presents the crossing, the guardrail validates the
// PCAs, evaluates the policy over the semantic scopes through the (simulated)
// PDP, and enforces permit or deny, signing the guardrail forwarding envelope.

// Grant identifiers bound to semantic scopes by the fixtures.
const (
	GrantUserBackup      = "urn:pic:grant:user-backup"
	GrantAgentS3Writer   = "urn:pic:grant:agent-s3-writer"
	GrantExternalSharing = "urn:pic:grant:external-sharing"
)

// GuardrailSetup wires the fixture guardrail: its identity, the simulated PDP
// loaded with the fixture policy, and the fixture scope bindings.
func (w *World) GuardrailSetup() (*pic.Sandbox, *pic.Guardrail) {
	g := pic.NewGuardrail(w.id("guardrail"), w.Set.Registry,
		&pic.LocalPDP{Policy: w.Set.Policy}, w.Set.Scopes)
	return pic.NewSandbox(w.id("sandbox"), g), g
}

// RecognizedGuardrails are the guardrail authorities a receiving hop in
// sandbox mode accepts.
func (w *World) RecognizedGuardrails() []string {
	return []string{w.id("guardrail").VerificationMethod}
}

// CrossingOutcome is one guarded crossing: the Multi-Lineage Execution
// presented, the guardrail's enforcement trace, and the envelope (on permit).
type CrossingOutcome struct {
	Name     string                     `json:"name"`
	MLE      *pic.MultiLineageExecution `json:"multiLineageExecution"`
	Trace    *pic.EnforcementTrace      `json:"trace"`
	Envelope *pic.GuardrailEnvelope     `json:"guardrailEnvelope,omitempty"`
	Err      string                     `json:"error,omitempty"`
}

// ReceiverChecks is what a receiving hop in sandbox mode does with the
// permitted crossing — and what happens to bypass and tamper attempts.
type ReceiverChecks struct {
	EnvelopeAccepted bool   `json:"envelopeAccepted"`
	EnvelopeErr      string `json:"envelopeError,omitempty"`
	BypassRejected   bool   `json:"bypassRejected"`
	BypassReason     string `json:"bypassReason"`
	TamperRejected   bool   `json:"tamperRejected"`
	TamperReason     string `json:"tamperReason"`
}

// GuardedResult is the full canonical guarded-crossing scenario.
type GuardedResult struct {
	Description string                 `json:"description"`
	Policy      pic.Policy             `json:"policy"`
	Scopes      map[string][]string    `json:"scopeBindings"`
	Permit      *CrossingOutcome       `json:"permit"`
	Deny        *CrossingOutcome       `json:"deny"`
	InvalidPCA  *CrossingOutcome       `json:"invalidPca"`
	Receiver    ReceiverChecks         `json:"receiver"`
}

// Guarded runs the canonical example end to end. Every PCA, proof, and
// envelope is really minted, signed, and verified on this call.
func (w *World) Guarded(now time.Time) (*GuardedResult, error) {
	sandbox, _ := w.GuardrailSetup()
	agent := w.id("summary-service") // the AI agent (agentic fixture executor)
	agentAtt := w.att("summary-service")
	contract := pic.ExecutionContract{} // permissive: the agentic executor conforms

	// Lineage Execution A — user authority: alice grants {read-all, backup};
	// the agent receives PCA1-A {backup} through a real PoR hop.
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

	// Lineage Execution B — agent authority: the agent acts as a permissioned
	// entity of its own and mints the origin for the S3 write, then continues it
	// with the concrete signed request (the proposed crossing).
	dest := "s3://backups/tenant-42"
	chainB, err := w.agentLineage(agent, agentAtt, GrantAgentS3Writer,
		[]string{"write:s3/backups/*"},
		pic.Request{Operation: "write", Target: "s3/backups/tenant-42/dataset.tar", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}

	res := &GuardedResult{
		Description: "Canonical guarded crossing (Execution Guardrail spec): the AI agent holds the user's Lineage Execution A and its own Lineage Execution B, and proposes the S3 write as one Multi-Lineage Execution. The sandbox presents the crossing (forwardingProof); the guardrail validates every PCA, evaluates the policy over the semantic scopes via the simulated PDP, and enforces permit or deny (guardrailProof). Authorities remain separate; nothing is merged.",
		Policy:      w.Set.Policy,
		Scopes:      w.Set.Scopes,
	}

	// Crossing 1 — PERMIT: A (data-protection) + B (data-protection,
	// ai-compliance) satisfy the policy.
	mle := &pic.MultiLineageExecution{
		Participants: []pic.Participant{{Label: "A", Chain: chainA}, {Label: "B", Chain: chainB}},
		Proposing:    "B",
		Destination:  dest,
	}
	env, trace, err := sandbox.Cross(mle, now)
	res.Permit = &CrossingOutcome{Name: "A+B write to S3", MLE: mle, Trace: trace, Envelope: env, Err: errStr(err)}

	// Crossing 2 — DENY: A + C, where C is bound to external-sharing; the
	// policy's semantic condition fails and the PDP denies.
	chainC, err := w.agentLineage(agent, agentAtt, GrantExternalSharing,
		[]string{"share-public"},
		pic.Request{Operation: "share-public", Target: "s3/backups/tenant-42/dataset.tar", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}
	mleDeny := &pic.MultiLineageExecution{
		Participants: []pic.Participant{{Label: "A", Chain: chainA}, {Label: "C", Chain: chainC}},
		Proposing:    "C",
		Destination:  "https://public.example/share",
	}
	envDeny, traceDeny, err := sandbox.Cross(mleDeny, now)
	res.Deny = &CrossingOutcome{Name: "A+C public share", MLE: mleDeny, Trace: traceDeny, Envelope: envDeny, Err: errStr(err)}

	// Crossing 3 — INVALID PCA: a maliciously expanded successor in B'. The
	// guardrail enforces deny at validation, without evaluating policy.
	rogue, err := pic.NewProver(agent, agentAtt).ContinueMalicious(chainB[0],
		pic.Invariants{Operations: []string{"write:s3/backups/*", "delete:s3/*"}, ExecutionContract: contract},
		pic.Request{Operation: "delete", Target: "s3/backups/tenant-42", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, err
	}
	mleBad := &pic.MultiLineageExecution{
		Participants: []pic.Participant{{Label: "A", Chain: chainA}, {Label: "B'", Chain: []*pic.PCA{chainB[0], rogue}}},
		Proposing:    "B'",
		Destination:  dest,
	}
	envBad, traceBad, err := sandbox.Cross(mleBad, now)
	res.InvalidPCA = &CrossingOutcome{Name: "A+B' expanded authority", MLE: mleBad, Trace: traceBad, Envelope: envBad, Err: errStr(err)}

	// Receiving hop in sandbox mode: accepts the permitted envelope, rejects a
	// bypass (no envelope) and a tampered envelope (edited signed field).
	res.Receiver = w.receiverChecks(res.Permit.Envelope, now)
	return res, nil
}

// agentLineage mints the agent's own origin under the given grant and
// continues it once with the concrete signed request.
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

// receiverChecks runs the sandbox-mode acceptance checks on a permitted
// envelope: accept it, reject a bypass, reject a tampered copy.
func (w *World) receiverChecks(env *pic.GuardrailEnvelope, now time.Time) ReceiverChecks {
	rc := ReceiverChecks{}
	recognized := w.RecognizedGuardrails()

	verr := pic.VerifyGuardrailEnvelope(w.Set.Registry, recognized, env, now)
	rc.EnvelopeAccepted = env != nil && verr == nil
	rc.EnvelopeErr = errStr(verr)

	berr := pic.VerifyGuardrailEnvelope(w.Set.Registry, recognized, nil, now)
	rc.BypassRejected = berr != nil
	rc.BypassReason = errStr(berr)

	if env != nil {
		tampered := *env
		tampered.Envelope.CrossingContext.Destination = "s3://attacker/exfil"
		terr := pic.VerifyGuardrailEnvelope(w.Set.Registry, recognized, &tampered, now)
		rc.TamperRejected = terr != nil
		rc.TamperReason = errStr(terr)
	}
	return rc
}

// GuardTip carries an existing chain as Lineage Execution A through the
// guarded pipeline: the AI agent mints its own Lineage Execution B for the
// destination write and proposes the joint crossing. It is the shared
// `--guardrail` augmentation used by the other scenarios.
func (w *World) GuardTip(chain []*pic.PCA, destination string, now time.Time) (*CrossingOutcome, ReceiverChecks, error) {
	sandbox, _ := w.GuardrailSetup()
	agent := w.id("summary-service")
	chainB, err := w.agentLineage(agent, w.att("summary-service"), GrantAgentS3Writer,
		[]string{"write:s3/backups/*"},
		pic.Request{Operation: "write", Target: "s3/backups/tenant-42/result.tar", SecurityDomain: "tenant-42"}, now)
	if err != nil {
		return nil, ReceiverChecks{}, err
	}
	mle := &pic.MultiLineageExecution{
		Participants: []pic.Participant{{Label: "A", Chain: chain}, {Label: "B", Chain: chainB}},
		Proposing:    "B",
		Destination:  destination,
	}
	env, trace, err := sandbox.Cross(mle, now)
	out := &CrossingOutcome{Name: "tip crossing", MLE: mle, Trace: trace, Envelope: env, Err: errStr(err)}
	if err != nil {
		return out, ReceiverChecks{}, nil
	}
	return out, w.receiverChecks(env, now), nil
}
