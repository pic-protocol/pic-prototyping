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

// This file implements the PIC Sandboxed Execution Specification prototype:
// PIC carrying PIC. An outer ordinary PIC lineage whose authority is { ENFORCE }
// (the Sandboxed Execution) carries a Multi-Lineage Execution in the signed
// `multiLineage` profile field; each guardrail is the next ordinary executor of
// that outer lineage. There is no sandbox, no forwarding/guardrail envelope, and
// no second signature system: guardrail approval is the ordinary outer PCA
// signature.
//
// It is non-normative; the PIC Sandboxed Execution Specification is
// authoritative.

// MultiLineageProfile domain-separates the canonical multiLineage digest.
const MultiLineageProfile = "PIC-Multi-Lineage-v0"

// EnforceOperation is the single operation class of this revision.
const EnforceOperation = "ENFORCE"

// ---------------------------------------------------------------------------
// Multi-Lineage Execution (input carrier) and the signed multiLineage field
// ---------------------------------------------------------------------------

// Participant is one carried lineage as the executor selects it: a label and its
// full PCA chain (PCA0..tip). Each keeps its own origin, authority context, and
// continuity; nothing is merged.
type Participant struct {
	Label string `json:"label"`
	Chain []*PCA `json:"chain"`
	Role  string `json:"role,omitempty"`
}

// Tip returns the last PCA of the participant's chain.
func (p Participant) Tip() *PCA { return p.Chain[len(p.Chain)-1] }

// MultiLineageExecution is the input carrier the guardrail evaluates: n >= 1
// independent Lineage Executions proposed together for one transition. It has no
// authority of its own.
type MultiLineageExecution struct {
	Participants []Participant `json:"participants"`
	Proposing    string        `json:"proposing"`
	Destination  string        `json:"destination"`
}

func (m *MultiLineageExecution) participant(label string) (Participant, error) {
	for _, p := range m.Participants {
		if p.Label == label {
			return p, nil
		}
	}
	return Participant{}, fmt.Errorf("multi-lineage execution: no participant %q", label)
}

// CarriedLineage is one element of multiLineage.carriedLineages: an
// independently verifiable PIC lineage representation carried within the
// Multi-Lineage Execution. This profile carries the full chain (full-chain
// validation profile). A carried lineage is not an execution step, a child
// lineage, an additional outer predecessor, or an authority fragment.
type CarriedLineage struct {
	Label string `json:"label"`
	Chain []*PCA `json:"chain"`
	Role  string `json:"role,omitempty"`
}

// CrossingContext is the exact crossing bound by the outer request.
type CrossingContext struct {
	Destination      string    `json:"destination"`
	RequestSetDigest string    `json:"requestSetDigest"`
	PayloadDigest    string    `json:"payloadDigest,omitempty"`
	Freshness        Freshness `json:"freshness"`
}

// Freshness bounds the crossing to a short window with a nonce.
type Freshness struct {
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Nonce     string    `json:"nonce"`
}

// MultiLineage is the signed profile field carried by an outer ENFORCE PCA: the
// inner Multi-Lineage Execution being governed. It is covered by the single PCA
// signature and pinned by request.multiLineageDigest.
type MultiLineage struct {
	CarriedLineages []CarriedLineage `json:"carriedLineages"`
	Context         CrossingContext  `json:"context"`
}

// MultiLineageDigest is H("PIC-Multi-Lineage-v0" || canonical(ml)).
func MultiLineageDigest(ml *MultiLineage) (string, error) {
	b, err := canonicalJSON(ml)
	if err != nil {
		return "", err
	}
	return hashParts([]byte(MultiLineageProfile), b), nil
}

// requestSetDigest commits to the concrete signed requests of every carried
// lineage (label -> tip PoR request; an origin tip carries no request).
func requestSetDigest(m *MultiLineageExecution) (string, error) {
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
// Semantic scopes (Sandboxed Execution spec §2.5, enforcement inputs)
// ---------------------------------------------------------------------------

// ScopeBindings binds semantic scopes to a carried lineage through its origin
// grantId (origin-bound metadata signed inside PCA0), with the origin issuer as
// a governance fallback. Not under the unilateral control of the evaluated
// executor. A scope adds no authority.
type ScopeBindings map[string][]string

// ScopesOf resolves the semantic scopes of one carried lineage.
func (b ScopeBindings) ScopesOf(p Participant) []string {
	if s := b[p.Chain[0].GrantID]; len(s) > 0 {
		return s
	}
	return b[p.Chain[0].Issuer]
}

// ---------------------------------------------------------------------------
// Enforcement function (Policy + PDP). A PDP is one possible implementation.
// ---------------------------------------------------------------------------

// Policy mirrors the illustrative policy JSON: an effect and a CEL-like
// condition over the participants and their scopes. The decision defaults to deny.
type Policy struct {
	ID        string            `json:"id"`
	Effect    string            `json:"effect"`
	AppliesTo map[string]string `json:"appliesTo"`
	When      string            `json:"when"`
}

// PDPParticipant is the view of one carried lineage the enforcement function
// evaluates: its label, bound semantic scopes, and (for context) tip authority.
type PDPParticipant struct {
	Label     string   `json:"label"`
	Scopes    []string `json:"scopes"`
	Authority []string `json:"authority"`
}

// PDPRequest is the committed evaluation input: participants with their scopes
// and the crossing destination. No authority travels here.
type PDPRequest struct {
	Participants []PDPParticipant `json:"participants"`
	Destination  string           `json:"destination"`
}

// PDPDecision is the enforcement result: permit or deny, with the evaluated
// policy and a human-readable reason.
type PDPDecision struct {
	PolicyID string `json:"policyId"`
	Effect   string `json:"effect"` // "permit" | "deny"
	Reason   string `json:"reason"`
}

// Permit reports whether the decision is a permit.
func (d PDPDecision) Permit() bool { return d.Effect == "permit" }

// PDP is the enforcement-function dependency of the guardrail. The profile
// requires an enforcement result; it does not require a specific PDP.
type PDP interface {
	Evaluate(req PDPRequest) PDPDecision
}

// LocalPDP evaluates the loaded policy's elementary CEL-like condition
//
//	participants.all(l, '<scope>' in l.scopes || '<scope>' in l.scopes ...)
//
// against the carried lineages' semantic scopes. Default-deny.
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
				Reason: fmt.Sprintf("carried lineage %q (scopes %v) satisfies none of %v",
					part.Label, part.Scopes, alts)}
		}
	}
	if p.Policy.Effect != "permit" {
		return PDPDecision{PolicyID: p.Policy.ID, Effect: "deny",
			Reason: "matching policy effect is not permit"}
	}
	return PDPDecision{PolicyID: p.Policy.ID, Effect: "permit",
		Reason: fmt.Sprintf("every carried lineage shares one of %v", alts)}
}

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
// Sandboxed Execution (the outer ENFORCE lineage)
// ---------------------------------------------------------------------------

// SandboxedExecution is the outer ordinary PIC lineage whose authority is
// { ENFORCE }. Its origin PCA0-G is minted by an authorized sandbox origin; each
// guardrail hop is an ordinary successor PCA that carries and governs a
// Multi-Lineage Execution.
type SandboxedExecution struct {
	Chain []*PCA `json:"chain"` // [PCA0-G, PCA1-G, ...]
}

// Originate mints PCA0-G: the ordinary origin PCA of the outer ENFORCE lineage,
// signed by the authorized sandbox origin. It carries no PoR and no guardrail
// verdict; it establishes the { ENFORCE } authority and the future guardrail
// execution contract.
func Originate(origin *Identity, now time.Time) (*SandboxedExecution, error) {
	pca0, err := MintPCA0(origin,
		Invariants{
			Operations:        []string{EnforceOperation},
			ExecutionContract: ExecutionContract{Role: "guardrail"},
		}, "", now)
	if err != nil {
		return nil, err
	}
	return &SandboxedExecution{Chain: []*PCA{pca0}}, nil
}

// Origin returns PCA0-G.
func (se *SandboxedExecution) Origin() *PCA { return se.Chain[0] }

// Tip returns the current outer predecessor (the tip of the ENFORCE lineage).
func (se *SandboxedExecution) Tip() *PCA { return se.Chain[len(se.Chain)-1] }

// ---------------------------------------------------------------------------
// Guardrail (an ordinary executor of the outer ENFORCE lineage)
// ---------------------------------------------------------------------------

// Guardrail is an ordinary executor of a Sandboxed Execution. It verifies the
// outer continuation, verifies every carried lineage, applies the enforcement
// function, and — on permit — proves the next ordinary outer PCA.
type Guardrail struct {
	Identity    *Identity
	Attestation Attestation
	Registry    *Registry
	Revocations *RevocationStore
	PDP         PDP
	Policy      Policy
	Scopes      ScopeBindings
}

// NewGuardrail returns a guardrail executor.
func NewGuardrail(id *Identity, att Attestation, reg *Registry, pdp PDP, policy Policy, scopes ScopeBindings) *Guardrail {
	return &Guardrail{Identity: id, Attestation: att, Registry: reg, PDP: pdp, Policy: policy, Scopes: scopes}
}

// TraceParticipant is one carried lineage as seen by the guardrail.
type TraceParticipant struct {
	Label     string   `json:"label"`
	GrantID   string   `json:"grantId"`
	Scopes    []string `json:"scopes"`
	Authority []string `json:"authority"`
	ChainLen  int      `json:"chainLen"`
	Valid     bool     `json:"valid"`
	Error     string   `json:"error,omitempty"`
}

// EnforcementTrace records what the guardrail did for one crossing, in the
// phase order of the profile: validate outer, validate carried, evaluate, prove.
type EnforcementTrace struct {
	GuardrailExecutor  string             `json:"guardrailExecutor"`
	OuterPredecessor   uint64             `json:"outerPredecessorCounter"`
	OuterCounter       uint64             `json:"outerCounter"` // produced PCA[n]-G (permit)
	OuterValid         bool               `json:"outerValid"`
	CarriedLineages    []TraceParticipant `json:"carriedLineages"`
	CarriedValid       bool               `json:"carriedValid"`
	PDPCalled          bool               `json:"pdpCalled"`
	PDPRequest         *PDPRequest        `json:"pdpRequest,omitempty"`
	Decision           PDPDecision        `json:"decision"`
	MultiLineageDigest string             `json:"multiLineageDigest,omitempty"`
	Enforced           string             `json:"enforced"` // "permit" | "deny"
}

// Enforce runs the guardrail Prover/Verifier profile over the outer lineage:
//
//  1. validate the outer predecessor (the ENFORCE lineage so far);
//  2. validate every carried lineage with a conforming PIC Verifier;
//  3. evaluate the enforcement function; any invalid carried lineage or
//     non-permit result is deny before/at policy;
//  4. on permit, prove the next ordinary outer PCA carrying the signed
//     multiLineage and enforcementResult=permit. On deny, no authorizing
//     continuation is produced.
//
// On permit it appends the produced PCA to se.Chain and returns it.
func (g *Guardrail) Enforce(se *SandboxedExecution, mle *MultiLineageExecution, now time.Time) (*PCA, *EnforcementTrace, error) {
	trace := &EnforcementTrace{
		GuardrailExecutor: g.Identity.ID,
		OuterPredecessor:  se.Tip().LineageCounter,
		Enforced:          "deny",
	}
	if len(mle.Participants) == 0 {
		trace.Decision = PDPDecision{Effect: "deny", Reason: "empty multi-lineage execution"}
		return nil, trace, fmt.Errorf("guardrail: %s", trace.Decision.Reason)
	}

	// 1. validate the outer predecessor lineage.
	if _, err := NewVerifier(g.Registry, g.Revocations).VerifyFullChain(se.Chain, now); err != nil {
		trace.Decision = PDPDecision{Effect: "deny", Reason: "invalid outer continuation: " + err.Error()}
		return nil, trace, fmt.Errorf("guardrail: %s", trace.Decision.Reason)
	}
	trace.OuterValid = true

	// 2. validate every carried lineage.
	trace.CarriedValid = true
	for _, p := range mle.Participants {
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
			trace.CarriedValid = false
		}
		trace.CarriedLineages = append(trace.CarriedLineages, tp)
	}
	if !trace.CarriedValid {
		trace.Decision = PDPDecision{Effect: "deny", Reason: "invalid carried lineage: deny before policy evaluation"}
		return nil, trace, fmt.Errorf("guardrail: %s", trace.Decision.Reason)
	}

	// 3. evaluate the enforcement function over the carried lineages' scopes.
	req := PDPRequest{Destination: mle.Destination}
	for _, tp := range trace.CarriedLineages {
		req.Participants = append(req.Participants, PDPParticipant{
			Label: tp.Label, Scopes: tp.Scopes, Authority: tp.Authority,
		})
	}
	trace.PDPCalled = true
	trace.PDPRequest = &req
	trace.Decision = g.PDP.Evaluate(req)
	if !trace.Decision.Permit() {
		return nil, trace, fmt.Errorf("guardrail: deny — %s", trace.Decision.Reason)
	}

	// 4. permit: build multiLineage, commit it, and prove the next outer PCA.
	ml, err := buildMultiLineage(mle, now)
	if err != nil {
		return nil, trace, err
	}
	mld, err := MultiLineageDigest(ml)
	if err != nil {
		return nil, trace, err
	}
	policyCommit, err := digestOf(g.Policy)
	if err != nil {
		return nil, trace, err
	}
	inputsCommit, err := digestOf(req.Participants)
	if err != nil {
		return nil, trace, err
	}
	pred := se.Tip()
	outer, err := NewProver(g.Identity, g.Attestation).ContinueEnforce(pred,
		Invariants{Operations: []string{EnforceOperation}, ExecutionContract: pred.Invariants.ExecutionContract},
		Request{
			Operation:          EnforceOperation,
			Target:             mle.Destination,
			SecurityDomain:     "tenant-42",
			MultiLineageDigest: mld,
			PolicyCommitment:   policyCommit,
			InputsCommitment:   inputsCommit,
			EnforcementResult:  "permit",
		}, ml, now)
	if err != nil {
		return nil, trace, err
	}
	se.Chain = append(se.Chain, outer)
	trace.Enforced = "permit"
	trace.MultiLineageDigest = mld
	trace.OuterCounter = outer.LineageCounter
	return outer, trace, nil
}

// buildMultiLineage assembles the signed multiLineage field from the input
// carrier: the carried lineages (full chains) and the exact crossing context.
func buildMultiLineage(mle *MultiLineageExecution, now time.Time) (*MultiLineage, error) {
	rsd, err := requestSetDigest(mle)
	if err != nil {
		return nil, err
	}
	nonce, err := randomB64(16)
	if err != nil {
		return nil, err
	}
	cls := make([]CarriedLineage, 0, len(mle.Participants))
	for _, p := range mle.Participants {
		cls = append(cls, CarriedLineage{Label: p.Label, Chain: p.Chain, Role: p.Role})
	}
	return &MultiLineage{
		CarriedLineages: cls,
		Context: CrossingContext{
			Destination:      mle.Destination,
			RequestSetDigest: rsd,
			Freshness: Freshness{
				IssuedAt:  now,
				ExpiresAt: now.Add(DefaultChallengeTTL),
				Nonce:     nonce,
			},
		},
	}, nil
}

// ---------------------------------------------------------------------------
// Enforced acceptance (the receiving hop)
// ---------------------------------------------------------------------------

// AcceptGuardedCrossing is what a conforming receiving hop runs: it accepts the
// outer continuation only when every acceptance condition holds. `acceptedOrigins`
// are the authorized sandbox origins (by DID). It recomputes every digest and
// never trusts a supplied one.
func AcceptGuardedCrossing(reg *Registry, rev *RevocationStore, acceptedOrigins []string, outerChain []*PCA, now time.Time) error {
	if len(outerChain) == 0 {
		return fmt.Errorf("enforced acceptance: no Sandboxed Execution presented")
	}
	// ValidOuterPIC.
	if _, err := NewVerifier(reg, rev).VerifyFullChain(outerChain, now); err != nil {
		return fmt.Errorf("enforced acceptance: invalid outer continuation: %w", err)
	}
	// ValidSandboxOrigin: PCA0-G is a valid origin whose issuer is authorized.
	origin := outerChain[0]
	if !origin.IsOrigin() {
		return fmt.Errorf("enforced acceptance: outer chain does not start at PCA0-G")
	}
	if !contains(acceptedOrigins, origin.Issuer) {
		return fmt.Errorf("enforced acceptance: sandbox origin %q is not authorized", origin.Issuer)
	}
	tip := outerChain[len(outerChain)-1]
	if tip.IsOrigin() || tip.ProofOfRelationship == nil {
		return fmt.Errorf("enforced acceptance: no guardrail hop (PCA0-G is not a guardrail decision)")
	}
	// ENFORCE authority and executed operation are separate checks.
	if !contains(tip.Invariants.Operations, EnforceOperation) {
		return fmt.Errorf("enforced acceptance: ENFORCE not in outer authority context")
	}
	if tip.ProofOfRelationship.Request.Operation != EnforceOperation {
		return fmt.Errorf("enforced acceptance: executed request is not ENFORCE")
	}
	// multiLineage present and committed by the request.
	if tip.MultiLineage == nil {
		return fmt.Errorf("enforced acceptance: no multiLineage")
	}
	mld, err := MultiLineageDigest(tip.MultiLineage)
	if err != nil {
		return err
	}
	if tip.ProofOfRelationship.Request.MultiLineageDigest != mld {
		return fmt.Errorf("enforced acceptance: multiLineageDigest does not match recomputed digest")
	}
	// ValidMultiLineage: at least one carried lineage, each independently valid.
	if len(tip.MultiLineage.CarriedLineages) < 1 {
		return fmt.Errorf("enforced acceptance: empty carriedLineages")
	}
	for _, cl := range tip.MultiLineage.CarriedLineages {
		if _, err := NewVerifier(reg, rev).VerifyFullChain(cl.Chain, now); err != nil {
			return fmt.Errorf("enforced acceptance: carried lineage %q invalid: %w", cl.Label, err)
		}
	}
	// enforcementResult must be permit.
	if tip.ProofOfRelationship.Request.EnforcementResult != "permit" {
		return fmt.Errorf("enforced acceptance: enforcementResult is not permit")
	}
	// freshness: the outer tip is within its window.
	if !now.Before(tip.ExpiresAt) {
		return fmt.Errorf("enforced acceptance: outside the freshness window")
	}
	return nil
}
