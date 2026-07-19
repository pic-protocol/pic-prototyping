// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The origin-commitment derivation of `lineageId` and the root `branchId`, and
//! the native causal cutoffs (LINEAGE-SUFFIX, BRANCH-SUFFIX, GRANT).

use crate::crypto::hash_parts;
use crate::types::{OriginCore, Pca, Revocation};
use crate::{
    PicResult, BRANCH_ROOT_DOMAIN, LINEAGE_DOMAIN_SEP, STRATEGY_BRANCH_SUFFIX, STRATEGY_GRANT,
    STRATEGY_LINEAGE_SUFFIX,
};

/// Computes `lineageId = H("PIC-Lineage-v0" || 0x00 || canonical(originCore))`
/// from a PCA0 (Revocation spec §2.1). Non-self-referential: it excludes the
/// `lineageId` and `proof` fields.
pub fn derive_lineage_id(p: &Pca) -> String {
    let core = OriginCore {
        profile: &p.profile,
        issuer: &p.issuer,
        origin_nonce: &p.origin_nonce,
        grant_id: &p.grant_id,
        invariants: &p.invariants,
        issued_at: &p.issued_at,
        expires_at: &p.expires_at,
    };
    let b = core.canonical();
    hash_parts(&[LINEAGE_DOMAIN_SEP.as_bytes(), &[0u8], &b])
}

/// `rootBranchId = H("PIC-Root-Branch-v0" || 0x00 || lineageId)` (Revocation spec
/// §2.4).
pub fn root_branch_id(lineage_id: &str) -> String {
    hash_parts(&[BRANCH_ROOT_DOMAIN.as_bytes(), &[0u8], lineage_id.as_bytes()])
}

impl Revocation {
    /// Reports whether this revocation strikes the given PCA (§3.1).
    fn matches(&self, p: &Pca) -> bool {
        match self.strategy.as_str() {
            STRATEGY_LINEAGE_SUFFIX => {
                p.lineage_id == self.lineage_id && p.lineage_counter >= self.from_counter
            }
            STRATEGY_BRANCH_SUFFIX => {
                p.lineage_id == self.lineage_id
                    && p.branch_id == self.branch_id
                    && p.lineage_counter >= self.from_counter
            }
            STRATEGY_GRANT => !self.grant_id.is_empty() && p.grant_id == self.grant_id,
            _ => false,
        }
    }
}

/// An append-only, monotonic set of active revocations (Revocation spec §5.3,
/// §5.4). In this prototype it is an in-memory list.
#[derive(Default)]
pub struct RevocationStore {
    entries: Vec<Revocation>,
}

impl RevocationStore {
    pub fn new() -> RevocationStore {
        RevocationStore {
            entries: Vec::new(),
        }
    }

    /// Appends a revocation (append-only: revocations only accumulate).
    pub fn add(&mut self, r: Revocation) {
        self.entries.push(r);
    }

    /// Appends a LINEAGE-SUFFIX(lineageId, fromCounter) cutoff.
    pub fn lineage_suffix(&mut self, lineage_id: &str, from_counter: u64, issuer: &str) {
        self.add(Revocation {
            strategy: STRATEGY_LINEAGE_SUFFIX.to_string(),
            lineage_id: lineage_id.to_string(),
            from_counter,
            issuer: issuer.to_string(),
            ..Default::default()
        });
    }

    /// Returns an error if any active revocation strikes the PCA; `Ok(())`
    /// otherwise. The lookup is O(1) in lineage length.
    pub fn check(&self, p: &Pca) -> PicResult<()> {
        for r in &self.entries {
            if r.matches(p) {
                return Err(format!(
                    "revoked by {}(lineage={}, branch={}, grant={}, fromCounter={}) at counter {}",
                    r.strategy,
                    short(&r.lineage_id),
                    short(&r.branch_id),
                    r.grant_id,
                    r.from_counter,
                    p.lineage_counter
                ));
            }
        }
        Ok(())
    }
}

/// Truncates a digest for readable messages (matching Go's `short`).
fn short(s: &str) -> String {
    if s.len() <= 14 {
        s.to_string()
    } else {
        format!("{}…", &s[..14])
    }
}
