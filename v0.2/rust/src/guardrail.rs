// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The PIC Execution Guardrail prototype: the Multi-Lineage Execution carrier,
//! semantic scopes bound through a policy-controlled mapping, a PDP behind a
//! small trait, the sandbox that presents crossings (`forwardingProof`), and
//! the guardrail that enforces them and signs the guardrail forwarding
//! envelope (`guardrailProof`).
//!
//! Faithful mirror of the Go `pic/guardrail.go`; the JSON shapes are identical,
//! following the spec's illustrative envelope. Non-normative.

use crate::crypto::{canonical_json, Registry};
use crate::types::{Pca, Proof, Request};
use crate::verifier::Verifier;
use crate::{
    digest_of, parse_rfc3339, random_b64, rfc3339, Identity, PicResult, RevocationStore,
    SIGNATURE_TYPE,
};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Identifies this illustrative guarded-crossing profile.
pub const GUARDRAIL_PROFILE: &str = "PIC-Guarded-v0";

// ---------------------------------------------------------------------------
// Multi-Lineage Execution (Guardrail spec §1.2)
// ---------------------------------------------------------------------------

/// One Lineage Execution taking part in a crossing: a label and its full PCA
/// chain (PCA0..tip). Nothing is merged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    pub label: String,
    pub chain: Vec<Pca>,
}

impl Participant {
    /// The last PCA of the participant's chain.
    pub fn tip(&self) -> &Pca {
        self.chain.last().expect("participant chain is not empty")
    }
}

/// The uniform runtime carrier of a guarded crossing: n >= 1 distinct Lineage
/// Executions carried together for one proposed transition. It has no
/// authority of its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiLineageExecution {
    pub participants: Vec<Participant>,
    /// Label of the participant whose tip transition is the proposed crossing.
    pub proposing: String,
    pub destination: String,
}

impl MultiLineageExecution {
    fn participant(&self, label: &str) -> PicResult<&Participant> {
        self.participants
            .iter()
            .find(|p| p.label == label)
            .ok_or_else(|| format!("multi-lineage execution: no participant {label:?}"))
    }
}

// ---------------------------------------------------------------------------
// Semantic scopes (Guardrail spec §4.2)
// ---------------------------------------------------------------------------

/// The policy-controlled mapping binding semantic scopes to a Lineage
/// Execution through its origin grantId (or origin issuer DID as fallback):
/// origin-bound metadata the executor cannot self-assert. A scope adds no
/// authority.
pub type ScopeBindings = HashMap<String, Vec<String>>;

/// Resolves the semantic scopes of one participant: grantId first, then the
/// origin issuer DID. An unbound origin has no scopes (default-deny denies).
pub fn scopes_of(bindings: &ScopeBindings, p: &Participant) -> Vec<String> {
    if let Some(s) = bindings.get(&p.chain[0].grant_id) {
        if !s.is_empty() {
            return s.clone();
        }
    }
    bindings.get(&p.chain[0].issuer).cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Policy and PDP (Guardrail spec §4.3; PDP is one possible implementation)
// ---------------------------------------------------------------------------

/// Mirrors the illustrative policy JSON of the Execution Guardrail spec: an
/// effect and a CEL-like condition over the participants and their scopes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub effect: String,
    #[serde(rename = "appliesTo", default)]
    pub applies_to: HashMap<String, String>,
    pub when: String,
}

/// The view of one participant the PDP evaluates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdpParticipant {
    pub label: String,
    pub scopes: Vec<String>,
    pub authority: Vec<String>,
}

/// What the guardrail hands to the PDP. No authority travels here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdpRequest {
    pub participants: Vec<PdpParticipant>,
    pub destination: String,
}

/// What the PDP returns: permit or deny, with the evaluated policy and reason.
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

/// The policy-evaluation dependency of the guardrail.
pub trait Pdp {
    fn evaluate(&self, req: &PdpRequest) -> PdpDecision;
}

/// The simulated PDP: evaluates the loaded policy's elementary CEL-like
/// condition `participants.all(l, '<scope>' in l.scopes || ...)` with
/// default-deny semantics.
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
                        "participant {:?} (scopes {:?}) satisfies none of {:?}",
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
            reason: format!("every participant shares one of {alts:?}"),
        }
    }
}

/// Parses `participants.all(l, 'a' in l.scopes || 'b' in l.scopes)` into the
/// scope alternatives `{a, b}`.
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
// Guardrail forwarding envelope (Guardrail spec §3.3)
// ---------------------------------------------------------------------------

/// Bounds the envelope to a short acceptance window with a nonce.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Freshness {
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub nonce: String,
}

/// Identifies the permitted crossing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CrossingContext {
    pub participants: Vec<String>,
    pub destination: String,
    #[serde(rename = "requestsDigest")]
    pub requests_digest: String,
    pub freshness: Freshness,
}

/// Mirrors the spec's illustrative envelope body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailEnvelopeBody {
    #[serde(rename = "forwardedBy")]
    pub forwarded_by: String,
    pub predecessor: Pca,
    #[serde(rename = "predecessorDigest")]
    pub predecessor_digest: String,
    pub current: Pca,
    #[serde(rename = "currentDigest")]
    pub current_digest: String,
    #[serde(rename = "crossingContext")]
    pub crossing_context: CrossingContext,
    #[serde(rename = "decisionId")]
    pub decision_id: String,
}

/// The guardrail attestation: covers the envelope body and the digest of the
/// forwardingProof. Neither a PCA signature nor an executor signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailProof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "forwardingProofDigest")]
    pub forwarding_proof_digest: String,
    pub signature: String,
}

/// The guardrail forwarding envelope: replaces (never contains) the ordinary
/// forwarding envelope for a guarded crossing. Two separate attestations over
/// the same non-nested envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardrailEnvelope {
    pub envelope: GuardrailEnvelopeBody,
    #[serde(rename = "forwardingProof")]
    pub forwarding_proof: Proof,
    #[serde(rename = "guardrailProof")]
    pub guardrail_proof: GuardrailProof,
}

/// What the guardrailProof signature covers: the body plus the forwardingProof
/// digest.
#[derive(Serialize)]
struct GuardrailSigning<'a> {
    envelope: &'a GuardrailEnvelopeBody,
    #[serde(rename = "forwardingProofDigest")]
    forwarding_proof_digest: &'a str,
}

/// Commits to the concrete signed requests of every participant.
fn requests_digest(m: &MultiLineageExecution) -> String {
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
// Sandbox (Guardrail spec §2.3, §3.2)
// ---------------------------------------------------------------------------

/// The trusted execution boundary: it captures the crossing the executor
/// selected and presents the Multi-Lineage Execution to the guardrail. Its
/// identity signs the `forwardingProof` (it is the `forwardedBy` subject).
pub struct Sandbox<'a> {
    pub identity: &'a Identity,
    pub guardrail: &'a Guardrail<'a>,
}

/// The crossing as presented by the sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct PresentedCrossing {
    pub body: GuardrailEnvelopeBody,
    #[serde(rename = "forwardingProof")]
    pub forwarding_proof: Proof,
    #[serde(rename = "multiLineageExecution")]
    pub mle: MultiLineageExecution,
}

impl<'a> Sandbox<'a> {
    pub fn new(identity: &'a Identity, guardrail: &'a Guardrail<'a>) -> Sandbox<'a> {
        Sandbox {
            identity,
            guardrail,
        }
    }

    /// Captures the crossing: builds the envelope body for the proposing
    /// transition, stamps freshness and the decision id, and signs the
    /// `forwardingProof`.
    pub fn present(
        &self,
        m: &MultiLineageExecution,
        now: DateTime<Utc>,
    ) -> PicResult<PresentedCrossing> {
        if m.participants.is_empty() {
            return Err("sandbox: empty multi-lineage execution".into());
        }
        let prop = m.participant(&m.proposing)?;
        if prop.chain.len() < 2 {
            return Err(format!(
                "sandbox: proposing participant {:?} has no transition to present",
                prop.label
            ));
        }
        let cur = prop.tip();
        let pred = &prop.chain[prop.chain.len() - 2];
        let body = GuardrailEnvelopeBody {
            forwarded_by: self.identity.id.clone(),
            predecessor: pred.clone(),
            predecessor_digest: pred.digest(),
            current: cur.clone(),
            current_digest: cur.digest(),
            crossing_context: CrossingContext {
                participants: m.participants.iter().map(|p| p.label.clone()).collect(),
                destination: m.destination.clone(),
                requests_digest: requests_digest(m),
                freshness: Freshness {
                    issued_at: rfc3339(now),
                    expires_at: rfc3339(now + Duration::minutes(5)),
                    nonce: random_b64(16),
                },
            },
            decision_id: format!("urn:pic:decision:{}", random_b64(12)),
        };
        let msg = canonical_json(&body);
        Ok(PresentedCrossing {
            forwarding_proof: Proof {
                type_: SIGNATURE_TYPE.to_string(),
                verification_method: self.identity.verification_method.clone(),
                signature: self.identity.sign(&msg),
            },
            body,
            mle: m.clone(),
        })
    }

    /// Presents the crossing and asks the guardrail to enforce it.
    pub fn cross(
        &self,
        m: &MultiLineageExecution,
        now: DateTime<Utc>,
    ) -> PicResult<(Option<GuardrailEnvelope>, EnforcementTrace)> {
        let pres = self.present(m, now)?;
        Ok(self.guardrail.enforce(&pres, now))
    }
}

// ---------------------------------------------------------------------------
// Execution Guardrail (Guardrail spec §1.3, §4.1)
// ---------------------------------------------------------------------------

/// The Execution Guardrail: validates every participating PCA, evaluates
/// configured policy over the semantic scopes, and enforces permit or deny.
/// Its identity signs the `guardrailProof`.
pub struct Guardrail<'a> {
    pub identity: &'a Identity,
    pub registry: &'a Registry,
    pub revocations: Option<&'a RevocationStore>,
    pub pdp: &'a dyn Pdp,
    pub scopes: &'a ScopeBindings,
}

/// One participant as seen by the guardrail.
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

/// What the guardrail did for one crossing, in enforcement order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementTrace {
    #[serde(rename = "forwardedBy")]
    pub forwarded_by: String,
    pub participants: Vec<TraceParticipant>,
    #[serde(rename = "pcasValid")]
    pub pcas_valid: bool,
    #[serde(rename = "pdpCalled")]
    pub pdp_called: bool,
    #[serde(rename = "pdpRequest", skip_serializing_if = "Option::is_none")]
    pub pdp_request: Option<PdpRequest>,
    pub decision: PdpDecision,
    #[serde(rename = "decisionId")]
    pub decision_id: String,
    pub enforced: String,
}

impl<'a> Guardrail<'a> {
    pub fn new(
        identity: &'a Identity,
        registry: &'a Registry,
        pdp: &'a dyn Pdp,
        scopes: &'a ScopeBindings,
    ) -> Guardrail<'a> {
        Guardrail {
            identity,
            registry,
            revocations: None,
            pdp,
            scopes,
        }
    }

    /// Runs the enforcement order (§4.1): validate → evaluate → enforce.
    /// Returns the trace in every case; the envelope only on permit.
    pub fn enforce(
        &self,
        pres: &PresentedCrossing,
        now: DateTime<Utc>,
    ) -> (Option<GuardrailEnvelope>, EnforcementTrace) {
        let mut trace = EnforcementTrace {
            forwarded_by: pres.body.forwarded_by.clone(),
            decision_id: pres.body.decision_id.clone(),
            enforced: "deny".into(),
            ..Default::default()
        };

        // forwarding attribution: the presenting component's signature.
        let msg = canonical_json(&pres.body);
        if self
            .registry
            .verify(
                &pres.forwarding_proof.verification_method,
                &msg,
                &pres.forwarding_proof.signature,
            )
            .is_err()
        {
            trace.decision = PdpDecision {
                effect: "deny".into(),
                reason: "forwardingProof does not verify".into(),
                ..Default::default()
            };
            return (None, trace);
        }

        // 1. validate every participating PCA.
        trace.pcas_valid = true;
        for p in &pres.mle.participants {
            let mut tp = TraceParticipant {
                label: p.label.clone(),
                grant_id: p.chain[0].grant_id.clone(),
                scopes: scopes_of(self.scopes, p),
                authority: p.tip().invariants.operations.clone(),
                chain_len: p.chain.len(),
                valid: true,
                ..Default::default()
            };
            let mut verifier = Verifier::new(self.registry, self.revocations);
            if let Err(e) = verifier.verify_full_chain(&p.chain, now) {
                tp.valid = false;
                tp.error = e;
                trace.pcas_valid = false;
            }
            trace.participants.push(tp);
        }
        if !trace.pcas_valid {
            trace.decision = PdpDecision {
                effect: "deny".into(),
                reason: "invalid participating PCA: deny enforced without evaluating policy".into(),
                ..Default::default()
            };
            return (None, trace);
        }

        // 2. evaluate configured policy over the semantic scopes.
        let req = PdpRequest {
            destination: pres.mle.destination.clone(),
            participants: trace
                .participants
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
        trace.pdp_request = Some(req);

        // 3. enforce.
        if !trace.decision.permit() {
            return (None, trace);
        }
        trace.enforced = "permit".into();
        let env = self.sign_envelope(pres);
        (Some(env), trace)
    }

    /// Issues the guardrailProof over the presented body and the
    /// forwardingProof digest: the permit is bound to this exact crossing.
    fn sign_envelope(&self, pres: &PresentedCrossing) -> GuardrailEnvelope {
        let fp_digest = digest_of(&pres.forwarding_proof);
        let msg = canonical_json(&GuardrailSigning {
            envelope: &pres.body,
            forwarding_proof_digest: &fp_digest,
        });
        GuardrailEnvelope {
            envelope: pres.body.clone(),
            forwarding_proof: pres.forwarding_proof.clone(),
            guardrail_proof: GuardrailProof {
                type_: SIGNATURE_TYPE.to_string(),
                verification_method: self.identity.verification_method.clone(),
                forwarding_proof_digest: fp_digest,
                signature: self.identity.sign(&msg),
            },
        }
    }
}

/// What a receiving hop in sandbox mode runs: it accepts only guarded
/// crossings — both attestations over the same non-nested envelope, digests
/// recomputed, the proposing transition's binding, and freshness.
pub fn verify_guardrail_envelope(
    reg: &Registry,
    guardrails: &[String],
    env: Option<&GuardrailEnvelope>,
    now: DateTime<Utc>,
) -> PicResult<()> {
    let Some(env) = env else {
        return Err(
            "sandbox mode: no guardrail envelope presented (plain delivery is insufficient)"
                .into(),
        );
    };
    let body = &env.envelope;
    // forwardingProof: presentation attributed to forwardedBy.
    let msg = canonical_json(body);
    reg.verify(
        &env.forwarding_proof.verification_method,
        &msg,
        &env.forwarding_proof.signature,
    )
    .map_err(|e| format!("forwardingProof: {e}"))?;
    if !env
        .forwarding_proof
        .verification_method
        .starts_with(&body.forwarded_by)
    {
        return Err(format!(
            "forwardingProof key does not belong to forwardedBy {:?}",
            body.forwarded_by
        ));
    }
    // guardrailProof: recognized authority, covering body + forwardingProof digest.
    if !guardrails.contains(&env.guardrail_proof.verification_method) {
        return Err(format!(
            "guardrailProof: {:?} is not a recognized guardrail authority",
            env.guardrail_proof.verification_method
        ));
    }
    let fp_digest = digest_of(&env.forwarding_proof);
    if env.guardrail_proof.forwarding_proof_digest != fp_digest {
        return Err(
            "guardrailProof: forwardingProofDigest does not match the presented forwardingProof"
                .into(),
        );
    }
    let gmsg = canonical_json(&GuardrailSigning {
        envelope: body,
        forwarding_proof_digest: &fp_digest,
    });
    reg.verify(
        &env.guardrail_proof.verification_method,
        &gmsg,
        &env.guardrail_proof.signature,
    )
    .map_err(|e| format!("guardrailProof: {e}"))?;
    // digests are convenience, not trusted input: recompute and cross-check.
    if body.predecessor_digest != body.predecessor.digest()
        || body.current_digest != body.current.digest()
    {
        return Err("envelope: supplied digest does not match recomputed digest".into());
    }
    match &body.current.proof_of_relationship {
        Some(por) if por.previous_pca_hash == body.predecessor_digest => {}
        _ => {
            return Err(
                "envelope: current.previousPcaHash does not equal predecessorDigest".into(),
            )
        }
    }
    // freshness: a permit is bound to its crossing and its window.
    let f = &body.crossing_context.freshness;
    if now < parse_rfc3339(&f.issued_at) || now >= parse_rfc3339(&f.expires_at) {
        return Err("envelope: outside the freshness window".into());
    }
    Ok(())
}
