// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The canonical guarded crossing of the PIC Execution Guardrail spec: the AI
//! agent holds the user's Lineage Execution A, mints its own Lineage Execution
//! B, and proposes the S3 write as one Multi-Lineage Execution. Mirror of the
//! Go `scenario/guardrail.go`.

use super::World;
use crate::guardrail::{
    verify_guardrail_envelope, EnforcementTrace, Guardrail, GuardrailEnvelope, LocalPdp,
    MultiLineageExecution, Participant, Sandbox,
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

/// One guarded crossing: the Multi-Lineage Execution presented, the guardrail's
/// enforcement trace, and the envelope (on permit).
#[derive(Serialize)]
pub struct CrossingOutcome {
    pub name: String,
    #[serde(rename = "multiLineageExecution")]
    pub mle: MultiLineageExecution,
    pub trace: EnforcementTrace,
    #[serde(rename = "guardrailEnvelope", skip_serializing_if = "Option::is_none")]
    pub envelope: Option<GuardrailEnvelope>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// What a receiving hop in sandbox mode does with the permitted crossing.
#[derive(Default, Serialize)]
pub struct ReceiverChecks {
    #[serde(rename = "envelopeAccepted")]
    pub envelope_accepted: bool,
    #[serde(rename = "envelopeError", skip_serializing_if = "String::is_empty")]
    pub envelope_err: String,
    #[serde(rename = "bypassRejected")]
    pub bypass_rejected: bool,
    #[serde(rename = "bypassReason")]
    pub bypass_reason: String,
    #[serde(rename = "tamperRejected")]
    pub tamper_rejected: bool,
    #[serde(rename = "tamperReason")]
    pub tamper_reason: String,
}

/// The full canonical guarded-crossing scenario.
#[derive(Serialize)]
pub struct GuardedResult {
    pub description: String,
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
    /// The recognized guardrail authorities a receiving hop accepts.
    pub fn recognized_guardrails(&self) -> Vec<String> {
        vec![self.id("guardrail").verification_method.clone()]
    }

    /// Runs the canonical example end to end. Every PCA, proof, and envelope is
    /// really minted, signed, and verified on this call.
    pub fn guarded(&self, now: DateTime<Utc>) -> PicResult<GuardedResult> {
        let pdp = LocalPdp {
            policy: self.set.policy.clone(),
        };
        let guardrail = Guardrail::new(
            self.id("guardrail"),
            &self.set.registry,
            &pdp,
            &self.set.scopes,
        );
        let sandbox = Sandbox::new(self.id("sandbox"), &guardrail);
        let agent = self.id("summary-service"); // the AI agent (agentic executor)
        let agent_att = self.att("summary-service");
        let contract = ExecutionContract::default();

        // Lineage Execution A — user authority: alice grants {read-all, backup};
        // the agent receives PCA1-A {backup} through a real PoR hop.
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

        // Lineage Execution B — agent authority for the S3 write.
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

        // Crossing 1 — PERMIT: A + B satisfy the policy.
        let mle = MultiLineageExecution {
            participants: vec![
                Participant {
                    label: "A".into(),
                    chain: chain_a.clone(),
                },
                Participant {
                    label: "B".into(),
                    chain: chain_b.clone(),
                },
            ],
            proposing: "B".into(),
            destination: dest.into(),
        };
        let (env, trace) = sandbox.cross(&mle, now)?;
        let permit = CrossingOutcome {
            name: "A+B write to S3".into(),
            mle,
            error: err_of(&trace, env.is_some()),
            trace,
            envelope: env,
        };

        // Crossing 2 — DENY: A + C (external-sharing) fails the policy.
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
        let mle_deny = MultiLineageExecution {
            participants: vec![
                Participant {
                    label: "A".into(),
                    chain: chain_a.clone(),
                },
                Participant {
                    label: "C".into(),
                    chain: chain_c,
                },
            ],
            proposing: "C".into(),
            destination: "https://public.example/share".into(),
        };
        let (env_deny, trace_deny) = sandbox.cross(&mle_deny, now)?;
        let deny = CrossingOutcome {
            name: "A+C public share".into(),
            mle: mle_deny,
            error: err_of(&trace_deny, env_deny.is_some()),
            trace: trace_deny,
            envelope: env_deny,
        };

        // Crossing 3 — INVALID PCA: a maliciously expanded successor in B'.
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
        let mle_bad = MultiLineageExecution {
            participants: vec![
                Participant {
                    label: "A".into(),
                    chain: chain_a,
                },
                Participant {
                    label: "B'".into(),
                    chain: vec![chain_b[0].clone(), rogue],
                },
            ],
            proposing: "B'".into(),
            destination: dest.into(),
        };
        let (env_bad, trace_bad) = sandbox.cross(&mle_bad, now)?;
        let invalid_pca = CrossingOutcome {
            name: "A+B' expanded authority".into(),
            mle: mle_bad,
            error: err_of(&trace_bad, env_bad.is_some()),
            trace: trace_bad,
            envelope: env_bad,
        };

        let receiver = self.receiver_checks(permit.envelope.as_ref(), now);
        Ok(GuardedResult {
            description: "Canonical guarded crossing (Execution Guardrail spec): the AI agent holds the user's Lineage Execution A and its own Lineage Execution B, and proposes the S3 write as one Multi-Lineage Execution. The sandbox presents the crossing (forwardingProof); the guardrail validates every PCA, evaluates the policy over the semantic scopes via the simulated PDP, and enforces permit or deny (guardrailProof). Authorities remain separate; nothing is merged.".into(),
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
        let contract = ExecutionContract::default();
        let inv = Invariants {
            operations: ops.iter().map(|s| s.to_string()).collect(),
            execution_contract: contract,
        };
        let pca0 = mint_pca0(agent, inv.clone(), grant, now);
        let pca1 = Prover::new(agent, att.clone()).continue_(&pca0, inv, req, now)?;
        Ok(vec![pca0, pca1])
    }

    /// Sandbox-mode acceptance checks: accept the permitted envelope, reject a
    /// bypass, reject a tampered copy.
    pub fn receiver_checks(
        &self,
        env: Option<&GuardrailEnvelope>,
        now: DateTime<Utc>,
    ) -> ReceiverChecks {
        let mut rc = ReceiverChecks::default();
        let recognized = self.recognized_guardrails();

        let verr = verify_guardrail_envelope(&self.set.registry, &recognized, env, now);
        rc.envelope_accepted = env.is_some() && verr.is_ok();
        rc.envelope_err = verr.err().unwrap_or_default();

        let berr = verify_guardrail_envelope(&self.set.registry, &recognized, None, now);
        rc.bypass_rejected = berr.is_err();
        rc.bypass_reason = berr.err().unwrap_or_default();

        if let Some(env) = env {
            let mut tampered = env.clone();
            tampered.envelope.crossing_context.destination = "s3://attacker/exfil".into();
            let terr =
                verify_guardrail_envelope(&self.set.registry, &recognized, Some(&tampered), now);
            rc.tamper_rejected = terr.is_err();
            rc.tamper_reason = terr.err().unwrap_or_default();
        }
        rc
    }

    /// Carries an existing chain as Lineage Execution A through the guarded
    /// pipeline (the shared `--guardrail` augmentation).
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
            &self.set.registry,
            &pdp,
            &self.set.scopes,
        );
        let sandbox = Sandbox::new(self.id("sandbox"), &guardrail);
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
        let mle = MultiLineageExecution {
            participants: vec![
                Participant {
                    label: "A".into(),
                    chain,
                },
                Participant {
                    label: "B".into(),
                    chain: chain_b,
                },
            ],
            proposing: "B".into(),
            destination: destination.into(),
        };
        let (env, trace) = sandbox.cross(&mle, now)?;
        let rc = if env.is_some() {
            self.receiver_checks(env.as_ref(), now)
        } else {
            ReceiverChecks::default()
        };
        let out = CrossingOutcome {
            name: "tip crossing".into(),
            mle,
            error: err_of(&trace, env.is_some()),
            trace,
            envelope: env,
        };
        Ok((out, rc))
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
