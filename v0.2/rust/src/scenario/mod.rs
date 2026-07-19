// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The PIC "Why PIC" examples on top of the `pic` library, using the real v0.2
//! fixtures loaded once into memory: the authority-mixing / cross-lineage
//! composition example, the cross-service confused-deputy example, and the
//! multi-hop chains used by the snapshot and revocation demos.

mod authoritymixing;
pub mod guardrail;
mod flow;

pub use authoritymixing::MixingResult;
pub use flow::{FlowHop, FlowResult, RogueAttempt};

use crate::authority::authorize;
use crate::crypto::Identity;
use crate::fixtureset::{self, Set};
use crate::prover::mint_pca0;
use crate::types::{Attestation, ExecutionContract, Invariants, Pca, Request};
use crate::verifier::Verifier;
use crate::{PicResult, Prover};
use chrono::{DateTime, Utc};

const SYS_FILE: &str = "/sys/syslog.txt";

/// The loaded fixture cast plus the verifier registry.
pub struct World {
    pub set: &'static Set,
}

impl World {
    /// Loads the cached v0.2 fixtures (real DID identities and signed
    /// attestations). The first call reads disk; later calls reuse the cache.
    pub fn new() -> PicResult<World> {
        Ok(World {
            set: fixtureset::load()?,
        })
    }

    pub(crate) fn id(&self, name: &str) -> &'static Identity {
        self.set.identity(name)
    }

    pub(crate) fn att(&self, name: &str) -> Attestation {
        self.set.attestation(name)
    }

    pub(crate) fn verifier(&self) -> Verifier<'static> {
        Verifier::new(&self.set.registry, None)
    }
}

/// The authority Alice grants: user-scoped read/write only.
fn user_invariants() -> Invariants {
    Invariants {
        operations: vec!["read:/user/*".to_string(), "write:/user/*".to_string()],
        execution_contract: ExecutionContract {
            compliance: vec!["GDPR".to_string()],
            execution_model: "deterministic".to_string(),
            ..Default::default()
        },
    }
}

/// A service's own authority: system-scoped read/write.
fn sys_invariants() -> Invariants {
    Invariants {
        operations: vec!["read:/sys/*".to_string(), "write:/sys/*".to_string()],
        execution_contract: ExecutionContract {
            compliance: vec!["GDPR".to_string()],
            execution_model: "deterministic".to_string(),
            ..Default::default()
        },
    }
}

/// The outcome of the storage service processing a request.
#[derive(Default)]
pub struct ProcessResult {
    pub verified: bool,
    pub verify_err: Option<String>,
    pub authorized: bool,
    pub auth_err: Option<String>,
}

impl ProcessResult {
    /// Reports whether the request produced no system-data access.
    pub fn blocked(&self) -> bool {
        !self.verified || !self.authorized
    }
}

impl World {
    /// The storage service (Carol) logic: verify the received chain, enforce
    /// executed-vs-signed on the tip request binding, and authorize the concrete
    /// request against the tip authority (§3.3 check 8, §4.3).
    fn process(&self, chain: &[Pca], executed: &Request, now: DateTime<Utc>) -> ProcessResult {
        let inv = match self.verifier().verify_full_chain(chain, now) {
            Ok(inv) => inv,
            Err(e) => {
                return ProcessResult {
                    verified: false,
                    verify_err: Some(e),
                    ..Default::default()
                }
            }
        };
        let mut res = ProcessResult {
            verified: true,
            ..Default::default()
        };
        if let Some(tip) = chain.last() {
            if let Some(por) = &tip.proof_of_relationship {
                let signed = &por.request;
                if signed.operation != executed.operation || signed.target != executed.target {
                    res.auth_err = Some(format!(
                        "executed-vs-signed mismatch: signed {}:{}, executed {}:{}",
                        signed.operation, signed.target, executed.operation, executed.target
                    ));
                    return res;
                }
            }
        }
        if let Err(e) = authorize(&inv, executed) {
            res.auth_err = Some(e);
            return res;
        }
        res.authorized = true;
        res
    }

    /// The archive service's own transaction: it originates a system-scoped
    /// lineage and reads a system file. It is authorized.
    pub fn case1_legit(&self, now: DateTime<Utc>) -> PicResult<(Vec<Pca>, Request, ProcessResult)> {
        let pca0 = mint_pca0(self.id("archive-service"), sys_invariants(), "", now);
        let chain = vec![pca0];
        let req = Request {
            operation: "read".to_string(),
            target: SYS_FILE.to_string(),
            security_domain: "sys".to_string(),
            ..Default::default()
        };
        let res = self.process(&chain, &req, now);
        Ok((chain, req, res))
    }

    /// Alice's request forwarded honestly by the archive service: it adds no
    /// authority, so the lineage stays user-scoped and the storage service denies
    /// the out-of-scope system read. No system data leaks.
    pub fn case2_honest(
        &self,
        now: DateTime<Utc>,
    ) -> PicResult<(Vec<Pca>, Request, ProcessResult)> {
        let pca0 = mint_pca0(self.id("alice"), user_invariants(), "", now);
        let req = Request {
            operation: "read".to_string(),
            target: SYS_FILE.to_string(),
            security_domain: "sys".to_string(),
            ..Default::default()
        };
        let archive = Prover::new(self.id("archive-service"), self.att("archive-service"));
        let pca1 = archive.continue_(&pca0, user_invariants(), req.clone(), now)?;
        let chain = vec![pca0, pca1];
        let res = self.process(&chain, &req, now);
        Ok((chain, req, res))
    }

    /// A compromised archive service that tries to inject system authority into
    /// Alice's lineage. The successor PCA fails non-expansion at the Verifier.
    pub fn case2_malicious(
        &self,
        now: DateTime<Utc>,
    ) -> PicResult<(Vec<Pca>, Request, ProcessResult)> {
        let pca0 = mint_pca0(self.id("alice"), user_invariants(), "", now);
        let req = Request {
            operation: "read".to_string(),
            target: SYS_FILE.to_string(),
            security_domain: "sys".to_string(),
            ..Default::default()
        };
        let expanded = Invariants {
            operations: vec![
                "read:/user/*".to_string(),
                "write:/user/*".to_string(),
                "read:/sys/*".to_string(),
            ],
            execution_contract: user_invariants().execution_contract,
        };
        let archive = Prover::new(self.id("archive-service"), self.att("archive-service"));
        let pca1 = archive.continue_malicious(&pca0, expanded, req.clone(), now)?;
        let chain = vec![pca0, pca1];
        let res = self.process(&chain, &req, now);
        Ok((chain, req, res))
    }

    /// Creates a lineage of `hops` non-origin PCAs after PCA0 (hops+1 PCAs
    /// total), each produced by a real fixture executor cycled from the set.
    pub fn build_chain(&self, hops: usize, now: DateTime<Utc>) -> PicResult<Vec<Pca>> {
        // The deterministic fixture executors cycled to build long chains.
        const CHAIN_EXECUTORS: [&str; 4] = [
            "gateway",
            "backup-service",
            "archive-service",
            "storage-service",
        ];
        // A permissive origin contract so every cycled executor conforms.
        let inv = Invariants {
            operations: vec!["read:/user/*".to_string()],
            ..Default::default()
        };
        let pca0 = mint_pca0(self.id("alice"), inv.clone(), "", now);
        let mut chain = vec![pca0];
        let req = Request {
            operation: "read".to_string(),
            target: "/user/file".to_string(),
            security_domain: "tenant-42".to_string(),
            ..Default::default()
        };
        for i in 0..hops {
            let name = CHAIN_EXECUTORS[i % CHAIN_EXECUTORS.len()];
            let pred = chain.last().unwrap();
            let next = Prover::new(self.id(name), self.att(name)).continue_(
                pred,
                inv.clone(),
                req.clone(),
                now,
            )?;
            chain.push(next);
        }
        Ok(chain)
    }
}
