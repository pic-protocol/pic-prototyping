// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! One end-to-end execution flow: an origin PCA0 whose authority narrows hop by
//! hop as real fixture executors continue it, plus a final rogue attempt that PIC
//! rejects. Backs the `picdemo flow` visualization.

use super::World;
use crate::prover::mint_pca0;
use crate::types::{ExecutionContract, Invariants, Pca, Request};
use crate::{PicResult, Prover};
use chrono::{DateTime, Utc};
use serde::Serialize;

/// One step of the execution flow: who acted, what they did, the authority they
/// carry, what they dropped versus their predecessor, and the signed PCA.
#[derive(Serialize)]
pub struct FlowHop {
    #[serde(rename = "hop")]
    pub index: usize,
    pub actor: String,
    pub action: String,
    pub authority: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<String>,
    #[serde(rename = "lineageCounter")]
    pub lineage_counter: u64,
    #[serde(rename = "previousPcaHash", skip_serializing_if = "String::is_empty")]
    pub previous_hash: String,
    pub generates: Pca,
}

/// A compromised executor trying to re-expand authority; PIC rejects it.
#[derive(Serialize)]
pub struct RogueAttempt {
    pub actor: String,
    pub tried: Vec<String>,
    pub rejected: bool,
    pub reason: String,
}

/// The whole flow: the hops, the verification outcome, and the rejected rogue.
#[derive(Serialize)]
pub struct FlowResult {
    pub description: String,
    pub hops: Vec<FlowHop>,
    #[serde(rename = "verifyOk")]
    pub verify_ok: bool,
    #[serde(rename = "tipAuthority")]
    pub tip_authority: Vec<String>,
    pub rogue: Option<RogueAttempt>,
}

struct Step {
    actor: &'static str,
    action: &'static str,
    op: &'static str,
    ops: Vec<String>,
}

impl World {
    /// Runs the execution flow on the real fixtures. Every PCA is really minted,
    /// signed, and verified on this call.
    pub fn flow(&self, now: DateTime<Utc>) -> PicResult<FlowResult> {
        let contract = ExecutionContract::default(); // permissive; every executor conforms
        let ops0 = vec![
            "read-all".to_string(),
            "backup".to_string(),
            "share-files".to_string(),
        ];

        let pca0 = mint_pca0(
            self.id("alice"),
            Invariants {
                operations: ops0.clone(),
                execution_contract: contract.clone(),
            },
            "",
            now,
        );
        let mut chain = vec![pca0.clone()];

        let mut res = FlowResult {
            description: "Authority created once at the origin (alice) and propagated, only narrowing, through a causal chain of real fixture executors. Each hop produces a signed PCA; the final rogue expansion is rejected.".to_string(),
            hops: vec![FlowHop {
                index: 0,
                actor: "alice".to_string(),
                action: "mint origin PCA0".to_string(),
                authority: ops0,
                dropped: Vec::new(),
                lineage_counter: 0,
                previous_hash: String::new(),
                generates: pca0,
            }],
            verify_ok: false,
            tip_authority: Vec::new(),
            rogue: None,
        };

        let steps = [
            Step {
                actor: "gateway",
                action: "continue: forward (no attenuation)",
                op: "read-all",
                ops: vec![
                    "read-all".to_string(),
                    "backup".to_string(),
                    "share-files".to_string(),
                ],
            },
            Step {
                actor: "backup-service",
                action: "continue: attenuate (drop share-files)",
                op: "backup",
                ops: vec!["read-all".to_string(), "backup".to_string()],
            },
            Step {
                actor: "archive-service",
                action: "continue: attenuate (drop backup)",
                op: "read-all",
                ops: vec!["read-all".to_string()],
            },
            Step {
                actor: "storage-service",
                action: "execute: read under {read-all}",
                op: "read-all",
                ops: vec!["read-all".to_string()],
            },
        ];

        for (i, s) in steps.into_iter().enumerate() {
            let pred = chain.last().unwrap().clone();
            let req = Request {
                operation: s.op.to_string(),
                target: "eu-1/tenant-42/resource".to_string(),
                security_domain: "tenant-42".to_string(),
                ..Default::default()
            };
            let next = Prover::new(self.id(s.actor), self.att(s.actor)).continue_(
                &pred,
                Invariants {
                    operations: s.ops.clone(),
                    execution_contract: contract.clone(),
                },
                req,
                now,
            )?;
            let ph = pred.digest();
            let dropped = diff_ops(&pred.invariants.operations, &s.ops);
            res.hops.push(FlowHop {
                index: i + 1,
                actor: s.actor.to_string(),
                action: s.action.to_string(),
                authority: s.ops.clone(),
                dropped,
                lineage_counter: next.lineage_counter,
                previous_hash: ph,
                generates: next.clone(),
            });
            chain.push(next);
        }

        let mut v = self.verifier();
        match v.verify_full_chain(&chain, now) {
            Ok(inv) => {
                res.verify_ok = true;
                res.tip_authority = inv.operations;
            }
            Err(_) => {
                res.verify_ok = false;
                res.tip_authority = Vec::new();
            }
        }

        // Rogue: a compromised executor tries to re-add 'backup' the lineage dropped.
        let tip = chain.last().unwrap().clone();
        let tried = vec!["read-all".to_string(), "backup".to_string()];
        let rogue = Prover::new(self.id("archive-service"), self.att("archive-service"))
            .continue_malicious(
                &tip,
                Invariants {
                    operations: tried.clone(),
                    execution_contract: contract.clone(),
                },
                Request {
                    operation: "backup".to_string(),
                    target: "eu-1/tenant-42/resource".to_string(),
                    security_domain: "tenant-42".to_string(),
                    ..Default::default()
                },
                now,
            )?;
        let rerr = self.verifier().verify_hop(&rogue, &tip, now, false).err();
        res.rogue = Some(RogueAttempt {
            actor: "archive-service".to_string(),
            tried,
            rejected: rerr.is_some(),
            reason: rerr.unwrap_or_default(),
        });
        Ok(res)
    }
}

/// Returns the operations present in `a` but not in `b`.
fn diff_ops(a: &[String], b: &[String]) -> Vec<String> {
    a.iter().filter(|x| !b.contains(x)).cloned().collect()
}
