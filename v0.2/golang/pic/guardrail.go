// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

package pic

import (
	"fmt"
	"strings"
	"time"
)

// This file implements the PIC Execution Guardrail Specification prototype:
// the Multi-Lineage Execution carrier, semantic scopes bound through a
// policy-controlled mapping, a PDP behind a small interface, the sandbox that
// presents crossings (forwardingProof), and the guardrail that enforces them
// and signs the guardrail forwarding envelope (guardrailProof).
//
// It is non-normative; the PIC Execution Guardrail Specification is
// authoritative. The envelope shape mirrors the spec's illustrative JSON.

// GuardrailProfile identifies this illustrative guarded-crossing profile.
const GuardrailProfile = "PIC-Guarded-v0"

// ---------------------------------------------------------------------------
// Multi-Lineage Execution (Guardrail spec §1.2)
// ---------------------------------------------------------------------------

// Participant is one Lineage Execution taking part in a crossing: a label and
// its full PCA chain (PCA0..tip). Each participant keeps its own origin,
// authority context, and continuity; nothing is merged.
type Participant struct {
	Label string `json:"label"`
	Chain []*PCA `json:"chain"`
}

// Tip returns the last PCA of the participant's chain.
func (p Participant) Tip() *PCA { return p.Chain[len(p.Chain)-1] }

// MultiLineageExecution is the uniform runtime carrier of a guarded crossing:
// n >= 1 distinct Lineage Executions carried together for one proposed
// transition. It has no authority of its own; the proposed transition consists
// exclusively of the concrete signed requests carried by the participants.
type MultiLineageExecution struct {
	Participants []Participant `json:"participants"`
	// Proposing is the label of the participant whose tip transition is the
	// proposed crossing (its signed request is the concrete action).
	Proposing   string `json:"proposing"`
	Destination string `json:"destination"`
}

// participant returns the participant with the given label.
func (m *MultiLineageExecution) participant(label string) (Participant, error) {
	for _, p := range m.Participants {
		if p.Label == label {
			return p, nil
		}
	}
	return Participant{}, fmt.Errorf("multi-lineage execution: no participant %q", label)
}

// ---------------------------------------------------------------------------
// Semantic scopes (Guardrail spec §4.2)
// ---------------------------------------------------------------------------

// ScopeBindings is the policy-controlled mapping that binds semantic scopes to
// a Lineage Execution through its origin grantId — origin-bound metadata signed
// inside PCA0 and propagated unchanged, so the binding is not under the
// unilateral control of the executor whose crossing is being evaluated.
// A scope adds no authority; it only informs the guardrail policy decision.
type ScopeBindings map[string][]string

// ScopesOf resolves the semantic scopes of one participant: first from the
// grantId carried by its (already validated) chain, then — as a governance
// fallback — from the origin issuer DID. An unbound origin has no scopes, and
// no scopes means the default-deny policy denies.
func (b ScopeBindings) ScopesOf(p Participant) []string {
	if s := b[p.Chain[0].GrantID]; len(s) > 0 {
		return s
	}
	return b[p.Chain[0].Issuer]
}

// ---------------------------------------------------------------------------
// Policy and PDP (Guardrail spec §4.3; PDP is one possible implementation)
// ---------------------------------------------------------------------------

// Policy mirrors the illustrative policy JSON of the Execution Guardrail
// Specification (§4.3): an effect and a CEL-like condition over the
// participants and their scopes. The decision defaults to deny.
type Policy struct {
	ID        string            `json:"id"`
	Effect    string            `json:"effect"`
	AppliesTo map[string]string `json:"appliesTo"`
	When      string            `json:"when"`
}

// PDPParticipant is the view of one participant the PDP evaluates: its label,
// its bound semantic scopes, and (for context) its tip authority.
type PDPParticipant struct {
	Label     string   `json:"label"`
	Scopes    []string `json:"scopes"`
	Authority []string `json:"authority"`
}

// PDPRequest is what the guardrail hands to the PDP: the participants with
// their scopes and the crossing destination. No authority travels here.
type PDPRequest struct {
	Participants []PDPParticipant `json:"participants"`
	Destination  string           `json:"destination"`
}

// PDPDecision is what the PDP returns: permit or deny, with the evaluated
// policy and a human-readable reason.
type PDPDecision struct {
	PolicyID string `json:"policyId"`
	Effect   string `json:"effect"` // "permit" | "deny"
	Reason   string `json:"reason"`
}

// Permit reports whether the decision is a permit.
func (d PDPDecision) Permit() bool { return d.Effect == "permit" }

// PDP is the policy-evaluation dependency of the guardrail. The guardrail may
// evaluate policy directly or obtain a decision from a component like this one;
// what matters is that the decision is enforced at the boundary.
type PDP interface {
	Evaluate(req PDPRequest) PDPDecision
}

// LocalPDP is the simulated PDP: it evaluates the loaded policy's elementary
// CEL-like condition
//
//	participants.all(l, '<scope>' in l.scopes || '<scope>' in l.scopes ...)
//
// against the participants' semantic scopes. Anything it cannot parse is a
// deny: the decision defaults to deny.
type LocalPDP struct {
	Policy Policy
}

// Evaluate implements PDP with default-deny semantics.
func (p *LocalPDP) Evaluate(req PDPRequest) PDPDecision {
	alts, err := parseAllScopesCondition(p.Policy.When)
	if err != nil {
		return PDPDecision{PolicyID: p.Policy.ID, Effect: "deny",
			Reason: "unsupported policy condition: " + err.Error()}
	}
	for _, part := range req.Participants {
		if !anyScopeIn(alts, part.Scopes) {
			return PDPDecision{PolicyID: p.Policy.ID, Effect: "deny",
				Reason: fmt.Sprintf("participant %q (scopes %v) satisfies none of %v",
					part.Label, part.Scopes, alts)}
		}
	}
	if p.Policy.Effect != "permit" {
		return PDPDecision{PolicyID: p.Policy.ID, Effect: "deny",
			Reason: "matching policy effect is not permit"}
	}
	return PDPDecision{PolicyID: p.Policy.ID, Effect: "permit",
		Reason: fmt.Sprintf("every participant shares one of %v", alts)}
}

// parseAllScopesCondition parses the elementary condition form
// participants.all(l, 'a' in l.scopes || 'b' in l.scopes) and returns the
// scope alternatives {a, b}.
func parseAllScopesCondition(when string) ([]string, error) {
	s := strings.TrimSpace(when)
	const prefix, suffix = "participants.all(l,", ")"
	if !strings.HasPrefix(s, prefix) || !strings.HasSuffix(s, suffix) {
		return nil, fmt.Errorf("expected participants.all(l, ...)")
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(s, prefix), suffix)
	var alts []string
	for _, term := range strings.Split(inner, "||") {
		term = strings.TrimSpace(term)
		const inScopes = "in l.scopes"
		if !strings.HasSuffix(term, inScopes) {
			return nil, fmt.Errorf("unsupported term %q", term)
		}
		lit := strings.TrimSpace(strings.TrimSuffix(term, inScopes))
		if len(lit) < 2 || lit[0] != '\'' || lit[len(lit)-1] != '\'' {
			return nil, fmt.Errorf("expected quoted scope in %q", term)
		}
		alts = append(alts, lit[1:len(lit)-1])
	}
	if len(alts) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	return alts, nil
}

func anyScopeIn(alts, scopes []string) bool {
	for _, a := range alts {
		if contains(scopes, a) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Guardrail forwarding envelope (Guardrail spec §3.3)
// ---------------------------------------------------------------------------

// Freshness bounds the envelope to a short acceptance window with a nonce.
type Freshness struct {
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Nonce     string    `json:"nonce"`
}

// CrossingContext identifies the permitted crossing: the participant labels,
// the destination, a digest of the concrete signed requests, and freshness.
type CrossingContext struct {
	Participants   []string  `json:"participants"`
	Destination    string    `json:"destination"`
	RequestsDigest string    `json:"requestsDigest"`
	Freshness      Freshness `json:"freshness"`
}

// GuardrailEnvelopeBody mirrors the spec's illustrative envelope: the
// forwarder, the proposing transition's predecessor/current PCAs with their
// recomputable digests, the crossing context, and the decision id.
type GuardrailEnvelopeBody struct {
	ForwardedBy       string          `json:"forwardedBy"`
	Predecessor       *PCA            `json:"predecessor"`
	PredecessorDigest string          `json:"predecessorDigest"`
	Current           *PCA            `json:"current"`
	CurrentDigest     string          `json:"currentDigest"`
	CrossingContext   CrossingContext `json:"crossingContext"`
	DecisionID        string          `json:"decisionId"`
}

// GuardrailProof is the guardrail attestation: it covers the envelope body and
// the digest of the forwardingProof, so the guardrail attests exactly the
// crossing the forwarder presented. It is neither a PCA signature nor an
// executor signature.
type GuardrailProof struct {
	Type                  string `json:"type"`
	VerificationMethod    string `json:"verificationMethod"`
	ForwardingProofDigest string `json:"forwardingProofDigest"`
	Signature             string `json:"signature"`
}

// GuardrailEnvelope is the guardrail forwarding envelope: for a guarded
// crossing it replaces (never contains) the ordinary forwarding envelope.
// Forwarding attribution (forwardingProof, by the presenting sandbox) and
// guardrail validation (guardrailProof) are separate attestations over the
// same non-nested envelope.
type GuardrailEnvelope struct {
	Envelope        GuardrailEnvelopeBody `json:"envelope"`
	ForwardingProof *Proof                `json:"forwardingProof"`
	GuardrailProof  *GuardrailProof       `json:"guardrailProof"`
}

// bodySigningBytes are the canonical bytes the forwardingProof covers.
func bodySigningBytes(b GuardrailEnvelopeBody) ([]byte, error) { return canonicalJSON(b) }

// guardrailSigning is what the guardrailProof signature covers: the body plus
// the forwardingProof digest.
type guardrailSigning struct {
	Envelope              GuardrailEnvelopeBody `json:"envelope"`
	ForwardingProofDigest string                `json:"forwardingProofDigest"`
}

// requestsDigest commits to the concrete signed requests of every participant
// (label -> tip PoR request; an origin tip carries no request).
func requestsDigest(m *MultiLineageExecution) (string, error) {
	type signedReq struct {
		Label   string   `json:"label"`
		Request *Request `json:"request,omitempty"`
	}
	var reqs []signedReq
	for _, p := range m.Participants {
		sr := signedReq{Label: p.Label}
		if por := p.Tip().ProofOfRelationship; por != nil {
			r := por.Request
			sr.Request = &r
		}
		reqs = append(reqs, sr)
	}
	return digestOf(reqs)
}

// ---------------------------------------------------------------------------
// Sandbox (Guardrail spec §2.3, §3.2)
// ---------------------------------------------------------------------------

// Sandbox is the trusted execution boundary: the executor selects freely, the
// sandbox captures the resulting crossing and presents the Multi-Lineage
// Execution to the Execution Guardrail. Its identity signs the
// forwardingProof (it is the forwardedBy subject — not the executor).
type Sandbox struct {
	Identity  *Identity
	Guardrail *Guardrail
}

// NewSandbox returns a sandbox around the given guardrail.
func NewSandbox(id *Identity, g *Guardrail) *Sandbox {
	return &Sandbox{Identity: id, Guardrail: g}
}

// PresentedCrossing is the crossing as presented by the sandbox: the envelope
// body, the sandbox's forwardingProof over it, and the full Multi-Lineage
// Execution the guardrail validates.
type PresentedCrossing struct {
	Body            GuardrailEnvelopeBody  `json:"body"`
	ForwardingProof *Proof                 `json:"forwardingProof"`
	MLE             *MultiLineageExecution `json:"multiLineageExecution"`
}

// Present captures the crossing: it builds the envelope body for the proposing
// transition, stamps freshness and the decision id, and signs the
// forwardingProof. The executor cannot skip this step: in the execution model
// the sandbox is the only path to governed external effect.
func (s *Sandbox) Present(m *MultiLineageExecution, now time.Time) (*PresentedCrossing, error) {
	if len(m.Participants) == 0 {
		return nil, fmt.Errorf("sandbox: empty multi-lineage execution")
	}
	prop, err := m.participant(m.Proposing)
	if err != nil {
		return nil, err
	}
	if len(prop.Chain) < 2 {
		return nil, fmt.Errorf("sandbox: proposing participant %q has no transition to present", prop.Label)
	}
	cur := prop.Tip()
	pred := prop.Chain[len(prop.Chain)-2]
	predDigest, err := pred.Digest()
	if err != nil {
		return nil, err
	}
	curDigest, err := cur.Digest()
	if err != nil {
		return nil, err
	}
	reqDigest, err := requestsDigest(m)
	if err != nil {
		return nil, err
	}
	nonce, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	decisionID, err := randomB64(12)
	if err != nil {
		return nil, err
	}
	var labels []string
	for _, p := range m.Participants {
		labels = append(labels, p.Label)
	}
	body := GuardrailEnvelopeBody{
		ForwardedBy:       s.Identity.ID,
		Predecessor:       pred,
		PredecessorDigest: predDigest,
		Current:           cur,
		CurrentDigest:     curDigest,
		CrossingContext: CrossingContext{
			Participants:   labels,
			Destination:    m.Destination,
			RequestsDigest: reqDigest,
			Freshness: Freshness{
				IssuedAt:  now,
				ExpiresAt: now.Add(DefaultChallengeTTL),
				Nonce:     nonce,
			},
		},
		DecisionID: "urn:pic:decision:" + decisionID,
	}
	msg, err := bodySigningBytes(body)
	if err != nil {
		return nil, err
	}
	return &PresentedCrossing{
		Body: body,
		ForwardingProof: &Proof{
			Type:               SignatureType,
			VerificationMethod: s.Identity.VerificationMethod,
			Signature:          s.Identity.sign(msg),
		},
		MLE: m,
	}, nil
}

// Cross presents the crossing and asks the guardrail to enforce it: the whole
// guarded path in one call. It returns the trace in every case; the envelope
// only on permit.
func (s *Sandbox) Cross(m *MultiLineageExecution, now time.Time) (*GuardrailEnvelope, *EnforcementTrace, error) {
	pres, err := s.Present(m, now)
	if err != nil {
		return nil, nil, err
	}
	return s.Guardrail.Enforce(pres, now)
}

// ---------------------------------------------------------------------------
// Execution Guardrail (Guardrail spec §1.3, §4.1)
// ---------------------------------------------------------------------------

// Guardrail is the Execution Guardrail: an externally configured runtime
// control that validates every participating PCA, evaluates configured policy
// over the semantic scopes, and enforces permit or deny. Its identity signs
// the guardrailProof; the signing capability lies outside the executor's reach.
type Guardrail struct {
	Identity    *Identity
	Registry    *Registry
	Revocations *RevocationStore
	PDP         PDP
	Scopes      ScopeBindings
}

// NewGuardrail returns an Execution Guardrail with its own identity, the key
// registry for PCA validation, the policy-evaluation dependency, and the
// scope bindings.
func NewGuardrail(id *Identity, reg *Registry, pdp PDP, scopes ScopeBindings) *Guardrail {
	return &Guardrail{Identity: id, Registry: reg, PDP: pdp, Scopes: scopes}
}

// TraceParticipant is one participant as seen by the guardrail: validated or
// not, its bound scopes, and its tip authority.
type TraceParticipant struct {
	Label     string   `json:"label"`
	GrantID   string   `json:"grantId"`
	Scopes    []string `json:"scopes"`
	Authority []string `json:"authority"`
	ChainLen  int      `json:"chainLen"`
	Valid     bool     `json:"valid"`
	Error     string   `json:"error,omitempty"`
}

// EnforcementTrace records what the guardrail did for one crossing, in
// enforcement order: validate, evaluate, enforce. It backs the demo output.
type EnforcementTrace struct {
	ForwardedBy  string             `json:"forwardedBy"`
	Participants []TraceParticipant `json:"participants"`
	PCAsValid    bool               `json:"pcasValid"`
	PDPCalled    bool               `json:"pdpCalled"`
	PDPRequest   *PDPRequest        `json:"pdpRequest,omitempty"`
	Decision     PDPDecision        `json:"decision"`
	DecisionID   string             `json:"decisionId"`
	Enforced     string             `json:"enforced"` // "permit" | "deny"
}

// Enforce runs the enforcement order of the Execution Guardrail spec (§4.1):
//  1. validate — the forwardingProof and every PCA of every participating
//     Lineage Execution; any invalid PCA enforces deny without evaluating policy;
//  2. evaluate — the configured policy over the participants' semantic scopes;
//  3. enforce — permit signs the guardrail forwarding envelope; deny blocks.
func (g *Guardrail) Enforce(pres *PresentedCrossing, now time.Time) (*GuardrailEnvelope, *EnforcementTrace, error) {
	trace := &EnforcementTrace{
		ForwardedBy: pres.Body.ForwardedBy,
		DecisionID:  pres.Body.DecisionID,
		Enforced:    "deny",
	}

	// forwarding attribution: the presenting component's signature over the body.
	msg, err := bodySigningBytes(pres.Body)
	if err != nil {
		return nil, trace, err
	}
	if pres.ForwardingProof == nil {
		trace.Decision = PDPDecision{Effect: "deny", Reason: "missing forwardingProof"}
		return nil, trace, fmt.Errorf("guardrail: missing forwardingProof")
	}
	if err := g.Registry.verify(pres.ForwardingProof.VerificationMethod, msg, pres.ForwardingProof.Signature); err != nil {
		trace.Decision = PDPDecision{Effect: "deny", Reason: "forwardingProof does not verify"}
		return nil, trace, fmt.Errorf("guardrail: forwardingProof: %w", err)
	}

	// 1. validate every participating PCA (conforming PIC Verifier function).
	trace.PCAsValid = true
	for _, p := range pres.MLE.Participants {
		tp := TraceParticipant{
			Label:     p.Label,
			GrantID:   p.Chain[0].GrantID,
			Scopes:    g.Scopes.ScopesOf(p),
			Authority: p.Tip().Invariants.Operations,
			ChainLen:  len(p.Chain),
			Valid:     true,
		}
		if _, err := NewVerifier(g.Registry, g.Revocations).VerifyFullChain(p.Chain, now); err != nil {
			tp.Valid = false
			tp.Error = err.Error()
			trace.PCAsValid = false
		}
		trace.Participants = append(trace.Participants, tp)
	}
	if !trace.PCAsValid {
		trace.Decision = PDPDecision{Effect: "deny", Reason: "invalid participating PCA: deny enforced without evaluating policy"}
		return nil, trace, fmt.Errorf("guardrail: %s", trace.Decision.Reason)
	}

	// 2. evaluate configured policy over the participants' semantic scopes.
	req := PDPRequest{Destination: pres.MLE.Destination}
	for _, tp := range trace.Participants {
		req.Participants = append(req.Participants, PDPParticipant{
			Label: tp.Label, Scopes: tp.Scopes, Authority: tp.Authority,
		})
	}
	trace.PDPCalled = true
	trace.PDPRequest = &req
	trace.Decision = g.PDP.Evaluate(req)

	// 3. enforce.
	if !trace.Decision.Permit() {
		return nil, trace, fmt.Errorf("guardrail: deny — %s", trace.Decision.Reason)
	}
	trace.Enforced = "permit"
	env, err := g.signEnvelope(pres)
	if err != nil {
		return nil, trace, err
	}
	return env, trace, nil
}

// signEnvelope issues the guardrailProof over the presented body and the
// forwardingProof digest: the guardrail attests exactly the crossing the
// forwarder presented, bound to this decision, not reusable for another.
func (g *Guardrail) signEnvelope(pres *PresentedCrossing) (*GuardrailEnvelope, error) {
	fpDigest, err := digestOf(pres.ForwardingProof)
	if err != nil {
		return nil, err
	}
	msg, err := canonicalJSON(guardrailSigning{Envelope: pres.Body, ForwardingProofDigest: fpDigest})
	if err != nil {
		return nil, err
	}
	return &GuardrailEnvelope{
		Envelope:        pres.Body,
		ForwardingProof: pres.ForwardingProof,
		GuardrailProof: &GuardrailProof{
			Type:                  SignatureType,
			VerificationMethod:    g.Identity.VerificationMethod,
			ForwardingProofDigest: fpDigest,
			Signature:             g.Identity.sign(msg),
		},
	}, nil
}

// VerifyGuardrailEnvelope is what a receiving hop in sandbox mode runs: it
// accepts only guarded crossings. It verifies both attestations over the same
// non-nested envelope, recomputes every digest, checks the proposing
// transition's binding, and enforces freshness. `guardrails` are the
// recognized guardrail authorities.
func VerifyGuardrailEnvelope(reg *Registry, guardrails []string, env *GuardrailEnvelope, now time.Time) error {
	if env == nil {
		return fmt.Errorf("sandbox mode: no guardrail envelope presented (plain delivery is insufficient)")
	}
	body := env.Envelope
	if env.ForwardingProof == nil || env.GuardrailProof == nil {
		return fmt.Errorf("sandbox mode: envelope lacks forwardingProof or guardrailProof")
	}
	// forwardingProof: presentation attributed to forwardedBy.
	msg, err := bodySigningBytes(body)
	if err != nil {
		return err
	}
	if err := reg.verify(env.ForwardingProof.VerificationMethod, msg, env.ForwardingProof.Signature); err != nil {
		return fmt.Errorf("forwardingProof: %w", err)
	}
	if !strings.HasPrefix(env.ForwardingProof.VerificationMethod, body.ForwardedBy) {
		return fmt.Errorf("forwardingProof key does not belong to forwardedBy %q", body.ForwardedBy)
	}
	// guardrailProof: signed by a recognized guardrail authority, covering the
	// body and the forwardingProof digest.
	if !contains(guardrails, env.GuardrailProof.VerificationMethod) {
		return fmt.Errorf("guardrailProof: %q is not a recognized guardrail authority", env.GuardrailProof.VerificationMethod)
	}
	fpDigest, err := digestOf(env.ForwardingProof)
	if err != nil {
		return err
	}
	if env.GuardrailProof.ForwardingProofDigest != fpDigest {
		return fmt.Errorf("guardrailProof: forwardingProofDigest does not match the presented forwardingProof")
	}
	gmsg, err := canonicalJSON(guardrailSigning{Envelope: body, ForwardingProofDigest: fpDigest})
	if err != nil {
		return err
	}
	if err := reg.verify(env.GuardrailProof.VerificationMethod, gmsg, env.GuardrailProof.Signature); err != nil {
		return fmt.Errorf("guardrailProof: %w", err)
	}
	// digests are convenience, not trusted input: recompute and cross-check.
	predDigest, err := body.Predecessor.Digest()
	if err != nil {
		return err
	}
	curDigest, err := body.Current.Digest()
	if err != nil {
		return err
	}
	if body.PredecessorDigest != predDigest || body.CurrentDigest != curDigest {
		return fmt.Errorf("envelope: supplied digest does not match recomputed digest")
	}
	if body.Current.ProofOfRelationship == nil ||
		body.Current.ProofOfRelationship.PreviousPcaHash != predDigest {
		return fmt.Errorf("envelope: current.previousPcaHash does not equal predecessorDigest")
	}
	// freshness: a permit is bound to its crossing and its window.
	f := body.CrossingContext.Freshness
	if now.Before(f.IssuedAt) || !now.Before(f.ExpiresAt) {
		return fmt.Errorf("envelope: outside the freshness window")
	}
	return nil
}
