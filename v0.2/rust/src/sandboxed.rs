// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The PIC Sandboxed Execution prototype: PIC carrying PIC. An outer ordinary
//! PIC lineage whose authority is `{ ENFORCE }` (the Sandboxed Execution)
//! carries a Multi-Lineage Execution in the signed `multiLineage` profile field;
//! each guardrail is the next ordinary executor of that outer lineage. No
//! sandbox, no envelope, no second signature system.
//!
//! Faithful mirror of the Go `pic/sandboxed.go`; JSON shapes are identical.
//! Non-normative.

use crate::crypto::{canonical_json, hash_parts, Registry};
use crate::prover::{mint_pca0, Prover};
use crate::types::{Attestation, ExecutionContract, Invariants, Pca, Request};
use crate::verifier::Verifier;
use crate::{digest_of, random_b64, rfc3339, Identity, PicResult, RevocationStore};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Domain-separates the canonical multiLineage digest.
pub const MULTI_LINEAGE_PROFILE: &str = "PIC-Multi-Lineage-v0";

/// The single operation class of this revision.
pub const ENFORCE_OPERATION: &str = "ENFORCE";

// ---------------------------------------------------------------------------
// Multi-Lineage Execution (input carrier) and the signed multiLineage field
// ---------------------------------------------------------------------------

/// One carried lineage as the executor selects it: a label and its full PCA
/// chain (PCA0..tip). Nothing is merged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub label: String,
    pub chain: Vec<Pca>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
}

impl Participant {
    /// The last PCA of the chain.
    pub fn tip(&self) -> &Pca {
        self.chain.last().expect("participant chain is not empty")
    }
}

/// The input carrier the guardrail evaluates: n >= 1 independent Lineage
/// Executions proposed together for one transition. No authority of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLineageExecution {
    pub participants: Vec<Participant>,
    pub proposing: String,
    pub destination: String,
}

/// One element of `multiLineage.carriedLineages`: an independently verifiable
/// PIC lineage representation carried within the Multi-Lineage Execution (full
/// chain, full-chain validation profile). Not an execution step, a child
/// lineage, an additional outer predecessor, or an authority fragment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarriedLineage {
    pub label: String,
    pub chain: Vec<Pca>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
}

/// The exact crossing bound by the outer request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossingContext {
    pub destination: String,
    #[serde(rename = "requestSetDigest")]
    pub request_set_digest: String,
    #[serde(
        default,
        rename = "payloadDigest",
        skip_serializing_if = "String::is_empty"
    )]
    pub payload_digest: String,
    pub freshness: Freshness,
}

/// Bounds the crossing to a short window with a nonce.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Freshness {
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub nonce: String,
}

/// The signed profile field carried by an outer ENFORCE PCA: the inner
/// Multi-Lineage Execution being governed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLineage {
    #[serde(rename = "carriedLineages")]
    pub carried_lineages: Vec<CarriedLineage>,
    pub context: CrossingContext,
}

/// `H("PIC-Multi-Lineage-v0" || canonical(ml))`.
pub fn multi_lineage_digest(ml: &MultiLineage) -> String {
    let b = canonical_json(ml);
    hash_parts(&[MULTI_LINEAGE_PROFILE.as_bytes(), &b])
}

/// Commits to the concrete signed requests of every carried lineage.
fn request_set_digest(m: &MultiLineageExecution) -> String {
    #[derive(Serialize)]
    struct SignedReq<'a> {
        label: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        request: Option<&'a Request>,
    }
    let reqs: Vec<SignedReq> = m
        .participants
        .iter()
        .map(|p| SignedReq {
            label: &p.label,
            request: p.tip().proof_of_relationship.as_ref().map(|por| &por.request),
        })
        .collect();
    digest_of(&reqs)
}

// ---------------------------------------------------------------------------
// Semantic scopes (enforcement inputs)
// ---------------------------------------------------------------------------

/// Binds semantic scopes to a carried lineage through its origin grantId (or
/// origin issuer DID as a governance fallback). Not under the unilateral control
/// of the evaluated executor. A scope adds no authority.
pub type ScopeBindings = HashMap<String, Vec<String>>;

/// Resolves the semantic scopes of one carried lineage.
pub fn scopes_of(bindings: &ScopeBindings, p: &Participant) -> Vec<String> {
    if let Some(s) = bindings.get(&p.chain[0].grant_id) {
        if !s.is_empty() {
            return s.clone();
        }
    }
    bindings.get(&p.chain[0].issuer).cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Enforcement function (Policy + PDP). A PDP is one possible implementation.
// ---------------------------------------------------------------------------

/// Mirrors the illustrative policy JSON: an effect and a CEL-like condition over
/// the participants and their scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub effect: String,
    #[serde(rename = "appliesTo", default)]
    pub applies_to: HashMap<String, String>,
    pub when: String,
}

/// The view of one carried lineage the enforcement function evaluates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdpParticipant {
    pub label: String,
    pub scopes: Vec<String>,
    pub authority: Vec<String>,
}

/// The committed evaluation input. No authority travels here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdpRequest {
    pub participants: Vec<PdpParticipant>,
    pub destination: String,
}

/// The enforcement result: permit or deny, with the evaluated policy and reason.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdpDecision {
    #[serde(rename = "policyId")]
    pub policy_id: String,
    pub effect: String,
    pub reason: String,
}

impl PdpDecision {
    pub fn permit(&self) -> bool {
        self.effect == "permit"
    }
}

/// The enforcement-function dependency of the guardrail.
pub trait Pdp {
    fn evaluate(&self, req: &PdpRequest) -> PdpDecision;
}

/// Evaluates the loaded policy's elementary CEL-like condition with default-deny.
pub struct LocalPdp {
    pub policy: Policy,
}

impl Pdp for LocalPdp {
    fn evaluate(&self, req: &PdpRequest) -> PdpDecision {
        let alts = match parse_all_scopes_condition(&self.policy.when) {
            Ok(a) => a,
            Err(e) => {
                return PdpDecision {
                    policy_id: self.policy.id.clone(),
                    effect: "deny".into(),
                    reason: format!("unsupported policy condition: {e}"),
                }
            }
        };
        for part in &req.participants {
            if !alts.iter().any(|a| part.scopes.contains(a)) {
                return PdpDecision {
                    policy_id: self.policy.id.clone(),
                    effect: "deny".into(),
                    reason: format!(
                        "carried lineage {:?} (scopes {:?}) satisfies none of {:?}",
                        part.label, part.scopes, alts
                    ),
                };
            }
        }
        if self.policy.effect != "permit" {
            return PdpDecision {
                policy_id: self.policy.id.clone(),
                effect: "deny".into(),
                reason: "matching policy effect is not permit".into(),
            };
        }
        PdpDecision {
            policy_id: self.policy.id.clone(),
            effect: "permit".into(),
            reason: format!("every carried lineage shares one of {alts:?}"),
        }
    }
}

/// Parses `participants.all(l, 'a' in l.scopes || 'b' in l.scopes)`.
fn parse_all_scopes_condition(when: &str) -> PicResult<Vec<String>> {
    let s = when.trim();
    let prefix = "participants.all(l,";
    let Some(rest) = s.strip_prefix(prefix) else {
        return Err("expected participants.all(l, ...)".into());
    };
    let Some(inner) = rest.strip_suffix(')') else {
        return Err("expected participants.all(l, ...)".into());
    };
    let mut alts = Vec::new();
    for term in inner.split("||") {
        let term = term.trim();
        let Some(lit) = term.strip_suffix("in l.scopes") else {
            return Err(format!("unsupported term {term:?}"));
        };
        let lit = lit.trim();
        if lit.len() < 2 || !lit.starts_with('\'') || !lit.ends_with('\'') {
            return Err(format!("expected quoted scope in {term:?}"));
        }
        alts.push(lit[1..lit.len() - 1].to_string());
    }
    if alts.is_empty() {
        return Err("empty condition".into());
    }
    Ok(alts)
}

// ---------------------------------------------------------------------------
// Sandboxed Execution (the outer ENFORCE lineage)
// ---------------------------------------------------------------------------

/// The outer ordinary PIC lineage whose authority is `{ ENFORCE }`. Its origin
/// PCA0-G is minted by an authorized sandbox origin; each guardrail hop is an
/// ordinary successor PCA carrying and governing a Multi-Lineage Execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxedExecution {
    pub chain: Vec<Pca>,
}

impl SandboxedExecution {
    /// Mints PCA0-G: the ordinary origin of the outer ENFORCE lineage, signed by
    /// the authorized sandbox origin. Carries no PoR and no verdict.
    pub fn originate(origin: &Identity, now: DateTime<Utc>) -> SandboxedExecution {
        let pca0 = mint_pca0(
            origin,
            Invariants {
                operations: vec![ENFORCE_OPERATION.to_string()],
                execution_contract: ExecutionContract {
                    role: "guardrail".to_string(),
                    ..Default::default()
                },
            },
            "",
            now,
        );
        SandboxedExecution { chain: vec![pca0] }
    }

    /// PCA0-G.
    pub fn origin(&self) -> &Pca {
        &self.chain[0]
    }

    /// The current outer predecessor (tip of the ENFORCE lineage).
    pub fn tip(&self) -> &Pca {
        self.chain.last().expect("sandboxed chain is not empty")
    }
}

// ---------------------------------------------------------------------------
// Guardrail (an ordinary executor of the outer ENFORCE lineage)
// ---------------------------------------------------------------------------

/// An ordinary executor of a Sandboxed Execution: it verifies the outer
/// continuation, verifies every carried lineage, applies the enforcement
/// function, and — on permit — proves the next ordinary outer PCA.
pub struct Guardrail<'a> {
    pub identity: &'a Identity,
    pub attestation: Attestation,
    pub registry: &'a Registry,
    pub revocations: Option<&'a RevocationStore>,
    pub pdp: &'a dyn Pdp,
    pub policy: Policy,
    pub scopes: &'a ScopeBindings,
}

/// One carried lineage as seen by the guardrail.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceParticipant {
    pub label: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    pub scopes: Vec<String>,
    pub authority: Vec<String>,
    #[serde(rename = "chainLen")]
    pub chain_len: usize,
    pub valid: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// What the guardrail did for one crossing, in phase order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementTrace {
    #[serde(rename = "guardrailExecutor")]
    pub guardrail_executor: String,
    #[serde(rename = "outerPredecessorCounter")]
    pub outer_predecessor: u64,
    #[serde(rename = "outerCounter")]
    pub outer_counter: u64,
    #[serde(rename = "outerValid")]
    pub outer_valid: bool,
    #[serde(rename = "carriedLineages")]
    pub carried_lineages: Vec<TraceParticipant>,
    #[serde(rename = "carriedValid")]
    pub carried_valid: bool,
    #[serde(rename = "pdpCalled")]
    pub pdp_called: bool,
    #[serde(rename = "pdpRequest", skip_serializing_if = "Option::is_none")]
    pub pdp_request: Option<PdpRequest>,
    pub decision: PdpDecision,
    #[serde(
        rename = "multiLineageDigest",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub multi_lineage_digest: String,
    pub enforced: String,
}

impl<'a> Guardrail<'a> {
    pub fn new(
        identity: &'a Identity,
        attestation: Attestation,
        registry: &'a Registry,
        pdp: &'a dyn Pdp,
        policy: Policy,
        scopes: &'a ScopeBindings,
    ) -> Guardrail<'a> {
        Guardrail {
            identity,
            attestation,
            registry,
            revocations: None,
            pdp,
            policy,
            scopes,
        }
    }

    /// Runs the guardrail Prover/Verifier profile over the outer lineage:
    /// validate outer → validate carried → evaluate → prove. On permit it pushes
    /// the produced PCA onto `se.chain` and returns it.
    pub fn enforce(
        &self,
        se: &mut SandboxedExecution,
        mle: &MultiLineageExecution,
        now: DateTime<Utc>,
    ) -> (Option<Pca>, EnforcementTrace) {
        let mut trace = EnforcementTrace {
            guardrail_executor: self.identity.id.clone(),
            outer_predecessor: se.tip().lineage_counter,
            enforced: "deny".into(),
            ..Default::default()
        };
        if mle.participants.is_empty() {
            trace.decision = PdpDecision {
                effect: "deny".into(),
                reason: "empty multi-lineage execution".into(),
                ..Default::default()
            };
            return (None, trace);
        }

        // 1. validate the outer predecessor lineage.
        if let Err(e) = Verifier::new(self.registry, self.revocations).verify_full_chain(&se.chain, now)
        {
            trace.decision = PdpDecision {
                effect: "deny".into(),
                reason: format!("invalid outer continuation: {e}"),
                ..Default::default()
            };
            return (None, trace);
        }
        trace.outer_valid = true;

        // 2. validate every carried lineage.
        trace.carried_valid = true;
        for p in &mle.participants {
            let mut tp = TraceParticipant {
                label: p.label.clone(),
                grant_id: p.chain[0].grant_id.clone(),
                scopes: scopes_of(self.scopes, p),
                authority: p.tip().invariants.operations.clone(),
                chain_len: p.chain.len(),
                valid: true,
                ..Default::default()
            };
            if let Err(e) =
                Verifier::new(self.registry, self.revocations).verify_full_chain(&p.chain, now)
            {
                tp.valid = false;
                tp.error = e;
                trace.carried_valid = false;
            }
            trace.carried_lineages.push(tp);
        }
        if !trace.carried_valid {
            trace.decision = PdpDecision {
                effect: "deny".into(),
                reason: "invalid carried lineage: deny before policy evaluation".into(),
                ..Default::default()
            };
            return (None, trace);
        }

        // 3. evaluate the enforcement function.
        let req = PdpRequest {
            destination: mle.destination.clone(),
            participants: trace
                .carried_lineages
                .iter()
                .map(|tp| PdpParticipant {
                    label: tp.label.clone(),
                    scopes: tp.scopes.clone(),
                    authority: tp.authority.clone(),
                })
                .collect(),
        };
        trace.pdp_called = true;
        trace.decision = self.pdp.evaluate(&req);
        if !trace.decision.permit() {
            trace.pdp_request = Some(req);
            return (None, trace);
        }

        // 4. permit: build multiLineage, commit it, and prove the next outer PCA.
        let ml = build_multi_lineage(mle, now);
        let mld = multi_lineage_digest(&ml);
        let policy_commit = digest_of(&self.policy);
        let inputs_commit = digest_of(&req.participants);
        trace.pdp_request = Some(req);
        let pred = se.tip().clone();
        let outer = Prover::new(self.identity, self.attestation.clone())
            .continue_enforce(
                &pred,
                Invariants {
                    operations: vec![ENFORCE_OPERATION.to_string()],
                    execution_contract: pred.invariants.execution_contract.clone(),
                },
                Request {
                    operation: ENFORCE_OPERATION.to_string(),
                    target: mle.destination.clone(),
                    security_domain: "tenant-42".to_string(),
                    multi_lineage_digest: mld.clone(),
                    policy_commitment: policy_commit,
                    inputs_commitment: inputs_commit,
                    enforcement_result: "permit".to_string(),
                    ..Default::default()
                },
                ml,
                now,
            )
            .expect("enforce continues the outer ENFORCE lineage");
        se.chain.push(outer.clone());
        trace.enforced = "permit".into();
        trace.multi_lineage_digest = mld;
        trace.outer_counter = outer.lineage_counter;
        (Some(outer), trace)
    }
}

/// Assembles the signed multiLineage field from the input carrier.
fn build_multi_lineage(mle: &MultiLineageExecution, now: DateTime<Utc>) -> MultiLineage {
    MultiLineage {
        carried_lineages: mle
            .participants
            .iter()
            .map(|p| CarriedLineage {
                label: p.label.clone(),
                chain: p.chain.clone(),
                role: p.role.clone(),
            })
            .collect(),
        context: CrossingContext {
            destination: mle.destination.clone(),
            request_set_digest: request_set_digest(mle),
            payload_digest: String::new(),
            freshness: Freshness {
                issued_at: rfc3339(now),
                expires_at: rfc3339(now + Duration::minutes(5)),
                nonce: random_b64(16),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Enforced acceptance (the receiving hop)
// ---------------------------------------------------------------------------

/// What a conforming receiving hop runs: accept the outer continuation only when
/// every condition holds. `accepted_origins` are the authorized sandbox origins
/// (by DID). Recomputes every digest; never trusts a supplied one.
pub fn accept_guarded_crossing(
    reg: &Registry,
    rev: Option<&RevocationStore>,
    accepted_origins: &[String],
    outer_chain: &[Pca],
    now: DateTime<Utc>,
) -> PicResult<()> {
    if outer_chain.is_empty() {
        return Err("enforced acceptance: no Sandboxed Execution presented".into());
    }
    // ValidOuterPIC.
    Verifier::new(reg, rev)
        .verify_full_chain(outer_chain, now)
        .map_err(|e| format!("enforced acceptance: invalid outer continuation: {e}"))?;
    // ValidSandboxOrigin.
    let origin = &outer_chain[0];
    if !origin.is_origin() {
        return Err("enforced acceptance: outer chain does not start at PCA0-G".into());
    }
    if !accepted_origins.contains(&origin.issuer) {
        return Err(format!(
            "enforced acceptance: sandbox origin {:?} is not authorized",
            origin.issuer
        ));
    }
    let tip = outer_chain.last().unwrap();
    let Some(por) = &tip.proof_of_relationship else {
        return Err("enforced acceptance: no guardrail hop (PCA0-G is not a guardrail decision)".into());
    };
    // ENFORCE authority and executed operation are separate checks.
    if !tip
        .invariants
        .operations
        .iter()
        .any(|o| o == ENFORCE_OPERATION)
    {
        return Err("enforced acceptance: ENFORCE not in outer authority context".into());
    }
    if por.request.operation != ENFORCE_OPERATION {
        return Err("enforced acceptance: executed request is not ENFORCE".into());
    }
    // multiLineage present and committed by the request.
    let Some(ml) = &tip.multi_lineage else {
        return Err("enforced acceptance: no multiLineage".into());
    };
    if por.request.multi_lineage_digest != multi_lineage_digest(ml) {
        return Err(
            "enforced acceptance: multiLineageDigest does not match recomputed digest".into(),
        );
    }
    // ValidMultiLineage: at least one carried lineage, each independently valid.
    if ml.carried_lineages.is_empty() {
        return Err("enforced acceptance: empty carriedLineages".into());
    }
    for cl in &ml.carried_lineages {
        Verifier::new(reg, rev)
            .verify_full_chain(&cl.chain, now)
            .map_err(|e| format!("enforced acceptance: carried lineage {:?} invalid: {e}", cl.label))?;
    }
    // enforcementResult must be permit.
    if por.request.enforcement_result != "permit" {
        return Err("enforced acceptance: enforcementResult is not permit".into());
    }
    // freshness: the outer tip is within its window.
    if now >= crate::parse_rfc3339(&tip.expires_at) {
        return Err("enforced acceptance: outside the freshness window".into());
    }
    Ok(())
}
