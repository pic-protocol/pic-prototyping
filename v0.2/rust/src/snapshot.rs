// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The Snapshot Hash Chain profile (Prover/Verifier spec §5.2): a trusted issuer
//! validates the chain up to some `PCA[k]` and signs a snapshot committing to its
//! content id; a downstream Verifier then validates only the hops after it.

use crate::crypto::Registry;
use crate::types::{Invariants, Pca, Proof, Snapshot};
use crate::verifier::Verifier;
use crate::{parse_rfc3339, rfc3339, PicResult, SIGNATURE_TYPE};
use chrono::{DateTime, Duration, Utc};

fn lineage_ttl() -> Duration {
    Duration::hours(24)
}

/// Has a trusted snapshot issuer validate `chain[0..=through_index]` (full-chain)
/// and, only if valid, sign a snapshot committing to `PCA[through_index]` as the
/// valid tip. It refuses to attest an invalid chain.
pub fn issue_snapshot(
    issuer: &crate::Identity,
    reg: &Registry,
    chain: &[Pca],
    through_index: usize,
    now: DateTime<Utc>,
) -> PicResult<Snapshot> {
    if through_index >= chain.len() {
        return Err(format!(
            "snapshot: throughIndex {through_index} out of range"
        ));
    }
    // The issuer re-validates the whole prefix it vouches for.
    Verifier::new(reg, None)
        .verify_full_chain(&chain[..=through_index], now)
        .map_err(|e| format!("snapshot: refusing to attest an invalid chain: {e}"))?;
    let tip = &chain[through_index];
    let dig = tip.digest();
    let mut s = Snapshot {
        lineage_id: tip.lineage_id.clone(),
        through_counter: tip.lineage_counter,
        through_pca_hash: dig,
        issuer: issuer.id.clone(),
        issued_at: rfc3339(now),
        expires_at: rfc3339(now + lineage_ttl()),
        proof: None,
    };
    let msg = s.signing_bytes();
    s.proof = Some(Proof {
        type_: SIGNATURE_TYPE.to_string(),
        verification_method: issuer.verification_method.clone(),
        signature: issuer.sign(&msg),
    });
    Ok(s)
}

impl Verifier<'_> {
    /// Validates a lineage starting from a trusted snapshot (§5.2). `tail` is
    /// `[PCA[k], PCA[k+1], …, PCA[n]]` where `tail[0]` is the snapshotted tip. The
    /// Verifier checks the snapshot signature and that it commits to `tail[0]`,
    /// trusts `tail[0]` as a valid tip without walking back to PCA0, and validates
    /// the hops after it. Cost is O(len(tail)-1).
    pub fn verify_from_snapshot(
        &mut self,
        snap: &Snapshot,
        tail: &[Pca],
        now: DateTime<Utc>,
    ) -> PicResult<Invariants> {
        if tail.is_empty() {
            return Err("snapshot verify: empty tail".to_string());
        }
        let proof = snap
            .proof
            .as_ref()
            .ok_or("snapshot verify: missing signature")?;
        let msg = snap.signing_bytes();
        self.registry
            .verify(&snap.issuer, &msg, &proof.signature)
            .map_err(|e| format!("snapshot verify: {e}"))?;
        if let Err(e) = within(&snap.issued_at, &snap.expires_at, now) {
            return Err(format!("snapshot verify: {e}"));
        }

        let tip = &tail[0];
        let dig = tip.digest();
        if dig != snap.through_pca_hash {
            return Err(
                "snapshot verify: tip digest does not match snapshot commitment".to_string(),
            );
        }
        if tip.lineage_id != snap.lineage_id || tip.lineage_counter != snap.through_counter {
            return Err("snapshot verify: tip coordinates do not match snapshot".to_string());
        }
        // The tip is trusted as a valid chain tip via the snapshot; still honor a
        // revocation that strikes it or its future.
        if let Some(rev) = self.revocations {
            rev.check(tip)
                .map_err(|e| format!("snapshot verify tip: {e}"))?;
        }
        // Validate only the hops after the snapshot: O(hops since snapshot).
        for i in 1..tail.len() {
            self.verify_hop(&tail[i], &tail[i - 1], now, false)
                .map_err(|e| format!("post-snapshot hop {i}: {e}"))?;
        }
        Ok(tail[tail.len() - 1].invariants.clone())
    }
}

fn within(issued_at: &str, expires_at: &str, now: DateTime<Utc>) -> PicResult<()> {
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
