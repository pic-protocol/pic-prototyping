// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The PIC "Why PIC" Authority-Mixing / cross-lineage composition example (also
//! Prover/Verifier spec §1.4), using the real fixtures:
//!
//!   Lineage 1 (summary): origin {read-foo, share-files} -> attenuated to {share-files}
//!   Lineage 2 (backup):  origin {read-all,  backup}     -> attenuated to {read-all}
//!
//! At a shared executor a bug composes read-all (from Lineage 2) with Lineage 1's
//! share-files. Under PIC that mixed state is inexpressible.

use super::World;
use crate::prover::mint_pca0;
use crate::types::{ExecutionContract, Invariants, Request};
use crate::{PicResult, Prover};
use chrono::{DateTime, Utc};

fn summary_origin_invariants() -> Invariants {
    Invariants {
        operations: vec!["read-foo".to_string(), "share-files".to_string()],
        execution_contract: ExecutionContract {
            execution_model: "agentic".to_string(),
            ..Default::default()
        },
    }
}

fn backup_origin_invariants() -> Invariants {
    Invariants {
        operations: vec!["read-all".to_string(), "backup".to_string()],
        execution_contract: ExecutionContract {
            execution_model: "deterministic".to_string(),
            ..Default::default()
        },
    }
}

/// Reports the outcome of the authority-mixing example.
#[derive(Default)]
pub struct MixingResult {
    pub lineage_backup_authority: Vec<String>,
    pub lineage_summary_authority: Vec<String>,
    pub honest_accepted: bool,
    pub honest_err: Option<String>,
    pub composed: bool,
    pub compose_err: Option<String>,
}

impl World {
    /// Builds the two lineages, shows both are individually valid, then shows
    /// that composing read-all (from the backup lineage) into the summary lineage
    /// is rejected while an honest continuation is accepted.
    pub fn authority_mixing(&self, now: DateTime<Utc>) -> PicResult<MixingResult> {
        let mut res = MixingResult::default();

        // Lineage 2 (backup): {read-all, backup} -> {read-all}.
        let backup0 = mint_pca0(self.id("alice"), backup_origin_invariants(), "", now);
        let backup_req = Request {
            operation: "read-all".to_string(),
            target: "dataset/*".to_string(),
            security_domain: "tenant-42".to_string(),
            ..Default::default()
        };
        let backup1 = Prover::new(self.id("backup-service"), self.att("backup-service"))
            .continue_(
                &backup0,
                Invariants {
                    operations: vec!["read-all".to_string()],
                    execution_contract: backup_origin_invariants().execution_contract,
                },
                backup_req,
                now,
            )?;
        let inv_a = self
            .verifier()
            .verify_full_chain(&[backup0, backup1], now)?;
        res.lineage_backup_authority = inv_a.operations;

        // Lineage 1 (summary): {read-foo, share-files} -> {share-files}.
        let summary0 = mint_pca0(self.id("alice"), summary_origin_invariants(), "", now);
        let summary_req = Request {
            operation: "share-files".to_string(),
            target: "doc/foo".to_string(),
            security_domain: "tenant-42".to_string(),
            ..Default::default()
        };
        let summary1 = Prover::new(self.id("summary-service"), self.att("summary-service"))
            .continue_(
                &summary0,
                Invariants {
                    operations: vec!["share-files".to_string()],
                    execution_contract: summary_origin_invariants().execution_contract,
                },
                summary_req.clone(),
                now,
            )?;
        // summary0 is not needed after this; summary1 is reused below, so clone it.
        let inv_b = self
            .verifier()
            .verify_full_chain(&[summary0, summary1.clone()], now)?;
        res.lineage_summary_authority = inv_b.operations;

        // A shared executor continues the summary lineage. Honest: keeps {share-files}.
        let archive = Prover::new(self.id("archive-service"), self.att("archive-service"));
        let honest = archive.continue_(
            &summary1,
            Invariants {
                operations: vec!["share-files".to_string()],
                execution_contract: summary_origin_invariants().execution_contract,
            },
            summary_req.clone(),
            now,
        )?;
        res.honest_err = self
            .verifier()
            .verify_hop(&honest, &summary1, now, false)
            .err();
        res.honest_accepted = res.honest_err.is_none();

        // The bug: compose read-all (borrowed from the backup lineage) with the
        // summary lineage's share-files, and continue the summary lineage.
        let composed = archive.continue_malicious(
            &summary1,
            Invariants {
                operations: vec!["read-all".to_string(), "share-files".to_string()],
                execution_contract: summary_origin_invariants().execution_contract,
            },
            summary_req,
            now,
        )?;
        res.compose_err = self
            .verifier()
            .verify_hop(&composed, &summary1, now, false)
            .err();
        res.composed = res.compose_err.is_none();

        Ok(res)
    }
}
