// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The canonical Sandboxed Execution of the PIC Sandboxed Execution Specification
//! (PIC of PIC): an authorized sandbox origin originates the outer ENFORCE
//! lineage; the AI agent holds the user's Lineage Execution A and its own
//! Lineage Execution B, proposed together as one Multi-Lineage Execution; the
//! guardrail — an ordinary executor of the outer lineage — validates, evaluates,
//! and on permit proves the next outer PCA. Mirror of Go `scenario/guardrail.go`.

use super::World;
use crate::sandboxed::{
    accept_guarded_crossing, EnforcementTrace, Guardrail, LocalPdp, MultiLineageExecution,
    Participant, SandboxedExecution,
};
use crate::types::{Attestation, ExecutionContract, Invariants, Pca, Request};
use crate::{mint_pca0, Identity, PicResult, Prover};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;

/// Grant identifiers bound to semantic scopes by the fixtures.
pub const GRANT_USER_BACKUP: &str = "urn:pic:grant:user-backup";
pub const GRANT_AGENT_S3_WRITER: &str = "urn:pic:grant:agent-s3-writer";
pub const GRANT_EXTERNAL_SHARING: &str = "urn:pic:grant:external-sharing";

/// One guarded crossing: the input Multi-Lineage Execution, the guardrail's
/// enforcement trace, and (on permit) the outer ENFORCE lineage chain.
#[derive(Serialize)]
pub struct CrossingOutcome {
    pub name: String,
    #[serde(rename = "multiLineageExecution")]
    pub mle: MultiLineageExecution,
    pub trace: EnforcementTrace,
    #[serde(rename = "outerChain", skip_serializing_if = "Vec::is_empty")]
    pub outer_chain: Vec<Pca>,
    #[serde(rename = "outerPca", skip_serializing_if = "Option::is_none")]
    pub outer_pca: Option<Pca>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// What a receiving hop does with the permitted crossing, under enforced
/// acceptance.
#[derive(Default, Serialize)]
pub struct ReceiverChecks {
    pub accepted: bool,
    #[serde(rename = "acceptError", skip_serializing_if = "String::is_empty")]
    pub accept_err: String,
    #[serde(rename = "bypassRejected")]
    pub bypass_rejected: bool,
    #[serde(rename = "bypassReason")]
    pub bypass_reason: String,
    #[serde(rename = "tamperRejected")]
    pub tamper_rejected: bool,
    #[serde(rename = "tamperReason")]
    pub tamper_reason: String,
}

/// The full canonical Sandboxed Execution scenario.
#[derive(Serialize)]
pub struct GuardedResult {
    pub description: String,
    #[serde(rename = "originPca0G")]
    pub origin: Pca,
    pub policy: crate::Policy,
    #[serde(rename = "scopeBindings")]
    pub scopes: HashMap<String, Vec<String>>,
    pub permit: CrossingOutcome,
    pub deny: CrossingOutcome,
    #[serde(rename = "invalidPca")]
    pub invalid_pca: CrossingOutcome,
    pub receiver: ReceiverChecks,
}

impl World {
    /// The authorized sandbox origins a receiving hop accepts.
    pub fn accepted_origins(&self) -> Vec<String> {
        vec![self.id("enforcement-origin").id.clone()]
    }

    /// Runs the canonical example end to end.
    pub fn guarded(&self, now: DateTime<Utc>) -> PicResult<GuardedResult> {
        let pdp = LocalPdp {
            policy: self.set.policy.clone(),
        };
        let guardrail = Guardrail::new(
            self.id("guardrail"),
            self.att("guardrail"),
            &self.set.registry,
            &pdp,
            self.set.policy.clone(),
            &self.set.scopes,
        );
        let origin = self.id("enforcement-origin");
        let agent = self.id("summary-service");
        let agent_att = self.att("summary-service");
        let contract = ExecutionContract::default();

        // Carried lineage A — user authority.
        let pca0_a = mint_pca0(
            self.id("alice"),
            Invariants {
                operations: vec!["read-all".into(), "backup".into()],
                execution_contract: contract.clone(),
            },
            GRANT_USER_BACKUP,
            now,
        );
        let pca1_a = Prover::new(agent, agent_att.clone()).continue_(
            &pca0_a,
            Invariants {
                operations: vec!["backup".into()],
                execution_contract: contract.clone(),
            },
            Request {
                operation: "backup".into(),
                target: "/user/dataset".into(),
                security_domain: "tenant-42".into(),
                ..Default::default()
            },
            now,
        )?;
        let chain_a = vec![pca0_a, pca1_a];

        let dest = "s3://backups/tenant-42";
        let chain_b = self.agent_lineage(
            agent,
            &agent_att,
            GRANT_AGENT_S3_WRITER,
            &["write:s3/backups/*"],
            Request {
                operation: "write".into(),
                target: "s3/backups/tenant-42/dataset.tar".into(),
                security_domain: "tenant-42".into(),
                ..Default::default()
            },
            now,
        )?;

        // Crossing 1 — PERMIT.
        let mut se_permit = SandboxedExecution::originate(origin, now);
        let origin_pca = se_permit.origin().clone();
        let mle = MultiLineageExecution {
            participants: vec![
                participant("A", chain_a.clone(), "user-backup"),
                participant("B", chain_b.clone(), "agent-s3-writer"),
            ],
            proposing: "B".into(),
            destination: dest.into(),
        };
        let (outer, trace) = guardrail.enforce(&mut se_permit, &mle, now);
        let permit = CrossingOutcome {
            name: "A+B write to S3".into(),
            mle,
            error: err_of(&trace, outer.is_some()),
            outer_chain: se_permit.chain.clone(),
            outer_pca: outer,
            trace,
        };

        // Crossing 2 — DENY: A + C (external-sharing).
        let chain_c = self.agent_lineage(
            agent,
            &agent_att,
            GRANT_EXTERNAL_SHARING,
            &["share-public"],
            Request {
                operation: "share-public".into(),
                target: "s3/backups/tenant-42/dataset.tar".into(),
                security_domain: "tenant-42".into(),
                ..Default::default()
            },
            now,
        )?;
        let mut se_deny = SandboxedExecution::originate(origin, now);
        let mle_deny = MultiLineageExecution {
            participants: vec![
                participant("A", chain_a.clone(), "user-backup"),
                participant("C", chain_c, "external-sharing"),
            ],
            proposing: "C".into(),
            destination: "https://public.example/share".into(),
        };
        let (outer_deny, trace_deny) = guardrail.enforce(&mut se_deny, &mle_deny, now);
        let deny = CrossingOutcome {
            name: "A+C public share".into(),
            mle: mle_deny,
            error: err_of(&trace_deny, outer_deny.is_some()),
            outer_chain: Vec::new(),
            outer_pca: outer_deny,
            trace: trace_deny,
        };

        // Crossing 3 — INVALID carried lineage: a maliciously expanded B'.
        let rogue = Prover::new(agent, agent_att.clone()).continue_malicious(
            &chain_b[0],
            Invariants {
                operations: vec!["write:s3/backups/*".into(), "delete:s3/*".into()],
                execution_contract: contract.clone(),
            },
            Request {
                operation: "delete".into(),
                target: "s3/backups/tenant-42".into(),
                security_domain: "tenant-42".into(),
                ..Default::default()
            },
            now,
        )?;
        let mut se_bad = SandboxedExecution::originate(origin, now);
        let mle_bad = MultiLineageExecution {
            participants: vec![
                participant("A", chain_a, "user-backup"),
                participant("B'", vec![chain_b[0].clone(), rogue], "agent-s3-writer"),
            ],
            proposing: "B'".into(),
            destination: dest.into(),
        };
        let (outer_bad, trace_bad) = guardrail.enforce(&mut se_bad, &mle_bad, now);
        let invalid_pca = CrossingOutcome {
            name: "A+B' expanded authority".into(),
            mle: mle_bad,
            error: err_of(&trace_bad, outer_bad.is_some()),
            outer_chain: Vec::new(),
            outer_pca: outer_bad,
            trace: trace_bad,
        };

        let receiver = self.receiver_checks(&permit.outer_chain, now);
        Ok(GuardedResult {
            description: "Canonical Sandboxed Execution (PIC of PIC): an authorized sandbox origin originates the outer ENFORCE lineage (PCA0-G). The AI agent holds the user's Lineage Execution A and its own Lineage Execution B and proposes the S3 write as one Multi-Lineage Execution. The guardrail — an ordinary executor of the outer lineage — validates every carried lineage, evaluates the enforcement function, and on permit proves the next ordinary outer PCA (PCA1-G) carrying the signed multiLineage. Authorities remain separate; nothing is merged.".into(),
            origin: origin_pca,
            policy: self.set.policy.clone(),
            scopes: self.set.scopes.clone(),
            permit,
            deny,
            invalid_pca,
            receiver,
        })
    }

    /// Mints the agent's own origin under the given grant and continues it once
    /// with the concrete signed request.
    fn agent_lineage(
        &self,
        agent: &'static Identity,
        att: &Attestation,
        grant: &str,
        ops: &[&str],
        req: Request,
        now: DateTime<Utc>,
    ) -> PicResult<Vec<Pca>> {
        let inv = Invariants {
            operations: ops.iter().map(|s| s.to_string()).collect(),
            execution_contract: ExecutionContract::default(),
        };
        let pca0 = mint_pca0(agent, inv.clone(), grant, now);
        let pca1 = Prover::new(agent, att.clone()).continue_(&pca0, inv, req, now)?;
        Ok(vec![pca0, pca1])
    }

    /// Enforced acceptance of a permitted outer chain, plus bypass and tamper
    /// rejections.
    pub fn receiver_checks(&self, outer_chain: &[Pca], now: DateTime<Utc>) -> ReceiverChecks {
        let mut rc = ReceiverChecks::default();
        let origins = self.accepted_origins();

        let verr = accept_guarded_crossing(&self.set.registry, None, &origins, outer_chain, now);
        rc.accepted = !outer_chain.is_empty() && verr.is_ok();
        rc.accept_err = verr.err().unwrap_or_default();

        let berr = accept_guarded_crossing(&self.set.registry, None, &origins, &[], now);
        rc.bypass_rejected = berr.is_err();
        rc.bypass_reason = berr.err().unwrap_or_default();

        if !outer_chain.is_empty() {
            let mut tampered = outer_chain.to_vec();
            if let Some(tip) = tampered.last_mut() {
                if let Some(ml) = tip.multi_lineage.as_mut() {
                    ml.context.destination = "s3://attacker/exfil".into();
                }
            }
            let terr = accept_guarded_crossing(&self.set.registry, None, &origins, &tampered, now);
            rc.tamper_rejected = terr.is_err();
            rc.tamper_reason = terr.err().unwrap_or_default();
        }
        rc
    }

    /// Carries an existing chain as carried lineage A through a Sandboxed
    /// Execution (the shared `--guardrail` augmentation).
    pub fn guard_tip(
        &self,
        chain: Vec<Pca>,
        destination: &str,
        now: DateTime<Utc>,
    ) -> PicResult<(CrossingOutcome, ReceiverChecks)> {
        let pdp = LocalPdp {
            policy: self.set.policy.clone(),
        };
        let guardrail = Guardrail::new(
            self.id("guardrail"),
            self.att("guardrail"),
            &self.set.registry,
            &pdp,
            self.set.policy.clone(),
            &self.set.scopes,
        );
        let agent = self.id("summary-service");
        let chain_b = self.agent_lineage(
            agent,
            &self.att("summary-service"),
            GRANT_AGENT_S3_WRITER,
            &["write:s3/backups/*"],
            Request {
                operation: "write".into(),
                target: "s3/backups/tenant-42/result.tar".into(),
                security_domain: "tenant-42".into(),
                ..Default::default()
            },
            now,
        )?;
        let mut se = SandboxedExecution::originate(self.id("enforcement-origin"), now);
        let mle = MultiLineageExecution {
            participants: vec![
                participant("A", chain, "user-backup"),
                participant("B", chain_b, "agent-s3-writer"),
            ],
            proposing: "B".into(),
            destination: destination.into(),
        };
        let (outer, trace) = guardrail.enforce(&mut se, &mle, now);
        let rc = if outer.is_some() {
            self.receiver_checks(&se.chain, now)
        } else {
            ReceiverChecks::default()
        };
        let out = CrossingOutcome {
            name: "tip crossing".into(),
            mle,
            error: err_of(&trace, outer.is_some()),
            outer_chain: se.chain.clone(),
            outer_pca: outer,
            trace,
        };
        Ok((out, rc))
    }
}

fn participant(label: &str, chain: Vec<Pca>, role: &str) -> Participant {
    Participant {
        label: label.into(),
        chain,
        role: role.into(),
    }
}

/// The error string of a denied crossing (empty on permit), mirroring Go.
fn err_of(trace: &EnforcementTrace, permitted: bool) -> String {
    if permitted {
        String::new()
    } else {
        format!("guardrail: deny — {}", trace.decision.reason)
    }
}
