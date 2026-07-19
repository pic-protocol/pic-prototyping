// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The Verifier: origin validation, ordered per-hop checks (§3.3), full-chain and
//! envelope validation, plus the revocation-coordinate continuity of the
//! Revocation spec §2.3.

use crate::authority::{attenuates, conforms};
use crate::crypto::Registry;
use crate::revocation::{derive_lineage_id, root_branch_id};
use crate::types::{Envelope, Invariants, Pca, Por};
use crate::{parse_rfc3339, PicResult, RevocationStore, REVOCABLE_PROFILE};
use chrono::{DateTime, Utc};
use std::collections::HashSet;

/// Validates PCAs before any authority is exercised (Prover/Verifier spec §3). It
/// resolves keys through a Registry, consults an optional RevocationStore, and
/// keeps per-Verifier state for single-use challenges.
pub struct Verifier<'a> {
    pub registry: &'a Registry,
    pub revocations: Option<&'a RevocationStore>,
    used: HashSet<String>,
}

impl<'a> Verifier<'a> {
    /// Returns a Verifier over the given key registry and (optional) revocation
    /// store.
    pub fn new(registry: &'a Registry, revocations: Option<&'a RevocationStore>) -> Verifier<'a> {
        Verifier {
            registry,
            revocations,
            used: HashSet::new(),
        }
    }

    /// Validates a PCA0 (§3.2) and the revocation-coordinate derivation
    /// (Revocation spec §2.1, §2.4).
    pub fn verify_origin(&self, p: &Pca, now: DateTime<Utc>) -> PicResult<()> {
        if !p.is_origin() {
            return Err("origin validation: PCA carries a Proof of Relationship".to_string());
        }
        let proof = p
            .proof
            .as_ref()
            .ok_or("origin validation: missing signature")?;
        let msg = p.signing_bytes();
        self.registry
            .verify(&p.issuer, &msg, &proof.signature)
            .map_err(|e| format!("origin validation: {e}"))?;
        within_validity(&p.issued_at, &p.expires_at, now)
            .map_err(|e| format!("origin validation: {e}"))?;
        if p.profile != REVOCABLE_PROFILE {
            return Err(format!(
                "origin validation: unknown profile {:?}",
                p.profile
            ));
        }
        if p.lineage_counter != 0 {
            return Err(format!(
                "origin validation: lineageCounter must be 0, got {}",
                p.lineage_counter
            ));
        }
        let want_lineage = derive_lineage_id(p);
        if p.lineage_id != want_lineage {
            return Err(
                "origin validation: lineageId does not match origin commitment".to_string(),
            );
        }
        if p.branch_id != root_branch_id(&p.lineage_id) {
            return Err(
                "origin validation: branchId is not the derived root branch id".to_string(),
            );
        }
        if let Some(rev) = self.revocations {
            rev.check(p)
                .map_err(|e| format!("origin validation: {e}"))?;
        }
        Ok(())
    }

    /// Validates a non-origin PCA against its already-validated predecessor,
    /// performing the ordered checks of §3.3 plus revocation-coordinate
    /// continuity. If `consume` is true, single-use challenges are marked
    /// consumed (live acceptance); re-validation of history passes false.
    pub fn verify_hop(
        &mut self,
        cur: &Pca,
        pred: &Pca,
        now: DateTime<Utc>,
        consume: bool,
    ) -> PicResult<()> {
        if cur.is_origin() {
            return Err("hop validation: PCA carries no Proof of Relationship".to_string());
        }
        let por = cur.proof_of_relationship.as_ref().unwrap();

        // 1. integrity — single signature over the whole PCA.
        let proof = cur.proof.as_ref().ok_or("hop: missing signature")?;
        let msg = cur.signing_bytes();
        self.registry
            .verify(&proof.verification_method, &msg, &proof.signature)
            .map_err(|e| format!("hop integrity: {e}"))?;

        // 2. predecessor binding — previousPcaHash equals the presented predecessor.
        let pred_digest = pred.digest();
        if por.previous_pca_hash != pred_digest {
            return Err(
                "hop binding: previousPcaHash does not match the presented predecessor".to_string(),
            );
        }

        // Revocation-coordinate continuity (Revocation spec §2.3).
        coordinate_continuity(cur, pred).map_err(|e| format!("hop coordinates: {e}"))?;

        // 3. continuation — response carries the predecessor challenge, unexpired,
        //    and (single-use) not already consumed.
        if por.continuation_response.predecessor_challenge != pred.continuation.challenge {
            return Err(
                "hop continuation: response does not answer the predecessor challenge".to_string(),
            );
        }
        if now >= parse_rfc3339(&pred.continuation.expires_at) {
            return Err("hop continuation: predecessor challenge expired".to_string());
        }
        if consume
            && pred.continuation.mode == "single-use"
            && self.used.contains(&pred.continuation.challenge)
        {
            return Err(
                "hop continuation: single-use challenge already consumed (replay)".to_string(),
            );
        }

        // 4. attestation — embedded issuer signature valid, within validity,
        //    subject matches the executor, which matches the PCA signing key.
        self.verify_attestation(por, &proof.verification_method, now)
            .map_err(|e| format!("hop attestation: {e}"))?;

        // 5. conformance — attested attributes satisfy the predecessor contract.
        conforms(
            &por.executor_attestation.attributes,
            &pred.invariants.execution_contract,
        )
        .map_err(|e| format!("hop conformance: {e}"))?;

        // 6. non-expansion — invariants are equal to or more restrictive.
        attenuates(&cur.invariants, &pred.invariants)
            .map_err(|e| format!("hop non-expansion: {e}"))?;

        // 7. temporal — hop window contained in the predecessor's (§6.3).
        temporal_check(cur, pred, now).map_err(|e| format!("hop temporal: {e}"))?;

        // revocation state — is this position cut off?
        if let Some(rev) = self.revocations {
            rev.check(cur).map_err(|e| format!("hop revocation: {e}"))?;
        }

        if consume && pred.continuation.mode == "single-use" {
            self.used.insert(pred.continuation.challenge.clone());
        }
        Ok(())
    }

    fn verify_attestation(&self, por: &Por, pca_vm: &str, now: DateTime<Utc>) -> PicResult<()> {
        let att = &por.executor_attestation;
        let proof = att
            .proof
            .as_ref()
            .ok_or("attestation missing issuer signature")?;
        let msg = att.signing_bytes();
        self.registry
            .verify(&att.issuer, &msg, &proof.signature)
            .map_err(|e| format!("issuer signature: {e}"))?;
        within_validity(&att.issued_at, &att.expires_at, now)
            .map_err(|e| format!("attestation validity: {e}"))?;
        if att.subject != por.executor {
            return Err(format!(
                "attestation subject {:?} does not match executor {:?}",
                att.subject, por.executor
            ));
        }
        // the key that signed the PCA must belong to the executor.
        if !pca_vm.starts_with(&por.executor) {
            return Err(format!(
                "PCA signing key {pca_vm:?} does not belong to executor {:?}",
                por.executor
            ));
        }
        Ok(())
    }

    /// Validates a whole chain from PCA0 to the tip (Full Hash Chain profile,
    /// §5.1): cost O(n). Returns the invariants authorized at the tip. History
    /// re-validation does not consume single-use challenges.
    pub fn verify_full_chain(
        &mut self,
        chain: &[Pca],
        now: DateTime<Utc>,
    ) -> PicResult<Invariants> {
        if chain.is_empty() {
            return Err("empty chain".to_string());
        }
        self.verify_origin(&chain[0], now)?;
        for i in 1..chain.len() {
            self.verify_hop(&chain[i], &chain[i - 1], now, false)
                .map_err(|e| format!("hop {i}: {e}"))?;
        }
        Ok(chain[chain.len() - 1].invariants.clone())
    }

    /// Validates one incremental transition carried in an envelope (§6.8):
    /// envelope signature and digests, then the single hop cur-against-pred,
    /// consuming the predecessor's single-use challenge.
    pub fn verify_envelope(&mut self, env: &Envelope, now: DateTime<Utc>) -> PicResult<Invariants> {
        let body = &env.envelope;
        let (pred, cur) = match (&body.predecessor, &body.current) {
            (Some(p), Some(c)) => (p, c),
            _ => return Err("envelope: missing predecessor or current".to_string()),
        };
        let proof = env.proof.as_ref().ok_or("envelope: missing signature")?;
        let msg = env.signing_bytes();
        self.registry
            .verify(&proof.verification_method, &msg, &proof.signature)
            .map_err(|e| format!("envelope signature: {e}"))?;
        // digests are convenience, not trusted input: recompute and cross-check.
        let pred_digest = pred.digest();
        let cur_digest = cur.digest();
        if body.predecessor_digest != pred_digest || body.current_digest != cur_digest {
            return Err("envelope: supplied digest does not match recomputed digest".to_string());
        }
        let por = cur
            .proof_of_relationship
            .as_ref()
            .ok_or("envelope: current carries no Proof of Relationship")?;
        if por.previous_pca_hash != pred_digest {
            return Err(
                "envelope: current.previousPcaHash does not equal predecessorDigest".to_string(),
            );
        }
        if let Some(rev) = self.revocations {
            rev.check(pred)
                .map_err(|e| format!("envelope predecessor: {e}"))?;
        }
        self.verify_hop(cur, pred, now, true)?;
        Ok(cur.invariants.clone())
    }
}

/// Enforces the hop-by-hop continuity of the revocation coordinates (Revocation
/// spec §2.3).
fn coordinate_continuity(cur: &Pca, pred: &Pca) -> PicResult<()> {
    if cur.profile != pred.profile {
        return Err("profile changed".to_string());
    }
    if cur.lineage_id != pred.lineage_id {
        return Err("lineageId changed".to_string());
    }
    if (cur.grant_id.is_empty()) != (pred.grant_id.is_empty()) || cur.grant_id != pred.grant_id {
        return Err("grantId presence/value changed".to_string());
    }
    if cur.origin_issuer != pred.origin_issuer {
        return Err("originIssuer changed".to_string());
    }
    if cur.branch_id != pred.branch_id {
        return Err(
            "branchId changed without an authorized branch-creation transition".to_string(),
        );
    }
    if cur.lineage_counter != pred.lineage_counter + 1 {
        return Err(format!(
            "lineageCounter must be predecessor+1 ({}), got {}",
            pred.lineage_counter + 1,
            cur.lineage_counter
        ));
    }
    Ok(())
}

fn within_validity(issued_at: &str, expires_at: &str, now: DateTime<Utc>) -> PicResult<()> {
    let issued = parse_rfc3339(issued_at);
    let expires = parse_rfc3339(expires_at);
    if now < issued {
        return Err("not yet valid".to_string());
    }
    if now >= expires {
        return Err("expired".to_string());
    }
    Ok(())
}

fn temporal_check(cur: &Pca, pred: &Pca, now: DateTime<Utc>) -> PicResult<()> {
    if parse_rfc3339(&cur.issued_at) < parse_rfc3339(&pred.issued_at) {
        return Err("issuedAt precedes predecessor".to_string());
    }
    if parse_rfc3339(&cur.expires_at) > parse_rfc3339(&pred.expires_at) {
        return Err("expiresAt exceeds predecessor".to_string());
    }
    within_validity(&cur.issued_at, &cur.expires_at, now)?;
    if parse_rfc3339(&cur.continuation.expires_at) > parse_rfc3339(&pred.expires_at) {
        return Err("emitted challenge outlives the lineage".to_string());
    }
    Ok(())
}
