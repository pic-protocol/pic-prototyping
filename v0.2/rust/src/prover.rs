// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Minting and signing: origin PCA0, successor PCAs (with the Prover self-check),
//! signed attestations, and handoff envelopes.

use crate::authority::{attenuates, conforms};
use crate::crypto::{random_b64, Identity};
use crate::revocation::{derive_lineage_id, root_branch_id};
use crate::types::{
    Attestation, Continuation, ContinuationResponse, Envelope, EnvelopeBody, Invariants, Pca, Por,
    Proof, Request,
};
use crate::{parse_rfc3339, rfc3339, PicResult, POR_TYPE, REVOCABLE_PROFILE, SIGNATURE_TYPE};
use chrono::{DateTime, Duration, Utc};

// Durations used by the illustrative profile (§6.1, §6.3).
fn lineage_ttl() -> Duration {
    Duration::hours(24)
}
fn hop_ttl() -> Duration {
    Duration::minutes(5)
}
fn challenge_ttl() -> Duration {
    Duration::minutes(5)
}

/// Computes the single outer signature over the PCA (proof excluded) and attaches
/// it (§2.5).
fn sign_pca(p: &mut Pca, signer: &Identity) {
    let msg = p.signing_bytes();
    p.proof = Some(Proof {
        type_: SIGNATURE_TYPE.to_string(),
        verification_method: signer.verification_method.clone(),
        signature: signer.sign(&msg),
    });
}

/// Returns a copy of `att` signed by its issuer (the conformance evidence of
/// §1.6). The issuer key must be registered so a Verifier can check it.
pub fn sign_attestation(mut att: Attestation, issuer: &Identity) -> Attestation {
    att.issuer = issuer.id.clone();
    let msg = att.signing_bytes();
    att.proof = Some(Proof {
        type_: SIGNATURE_TYPE.to_string(),
        verification_method: issuer.verification_method.clone(),
        signature: issuer.sign(&msg),
    });
    att
}

/// Creates and signs an origin PCA for `issuer` (§1.8), stamped with the
/// revocation coordinates of the revocable profile: a fresh originNonce, the
/// derived lineageId, lineageCounter 0, the root branchId, and originIssuer =
/// issuer. `grant_id` may be empty.
pub fn mint_pca0(issuer: &Identity, inv: Invariants, grant_id: &str, now: DateTime<Utc>) -> Pca {
    let nonce = random_b64(32);
    let challenge = random_b64(32);
    let mut p = Pca {
        profile: REVOCABLE_PROFILE.to_string(),
        lineage_counter: 0,
        grant_id: grant_id.to_string(),
        origin_issuer: issuer.id.clone(),
        issuer: issuer.id.clone(),
        origin_nonce: nonce,
        invariants: inv,
        continuation: Continuation {
            challenge,
            mode: "single-use".to_string(),
            max_uses: 1,
            expires_at: rfc3339(now + challenge_ttl()),
        },
        issued_at: rfc3339(now),
        expires_at: rfc3339(now + lineage_ttl()),
        ..Default::default()
    };
    // Derive the lineage identity from the non-self-referential origin core, then
    // the root branch id (Revocation spec §2.1, §2.4).
    let lineage_id = derive_lineage_id(&p);
    p.branch_id = root_branch_id(&lineage_id);
    p.lineage_id = lineage_id;
    sign_pca(&mut p, issuer);
    p
}

/// Constructs successor PCAs for one executor identity and its attestation.
pub struct Prover<'a> {
    pub executor: &'a Identity,
    pub attestation: Attestation,
}

impl<'a> Prover<'a> {
    pub fn new(executor: &'a Identity, attestation: Attestation) -> Prover<'a> {
        Prover {
            executor,
            attestation,
        }
    }

    /// Builds and signs a successor PCA that continues `pred` with the given
    /// (attenuated) invariants and request binding (§2.1–§2.5). Performs the
    /// Prover self-check of §2.3/§2.4: a Prover MUST NOT emit an expansive
    /// successor.
    pub fn continue_(
        &self,
        pred: &Pca,
        inv: Invariants,
        req: Request,
        now: DateTime<Utc>,
    ) -> PicResult<Pca> {
        self.build(pred, inv, req, None, now, true)
    }

    /// Builds the next ordinary outer PCA of a Sandboxed Execution (PIC Sandboxed
    /// Execution Specification §2.5): continues `pred` on the outer ENFORCE
    /// lineage and carries `ml` in the signed `multiLineage` profile field. The
    /// request MUST already commit to `ml` through `request.multiLineageDigest`.
    pub fn continue_enforce(
        &self,
        pred: &Pca,
        inv: Invariants,
        req: Request,
        ml: crate::sandboxed::MultiLineage,
        now: DateTime<Utc>,
    ) -> PicResult<Pca> {
        self.build(pred, inv, req, Some(ml), now, true)
    }

    /// Builds a successor PCA *without* the Prover self-check, simulating a buggy
    /// or compromised executor (§1.1). PIC's guarantee is that such a PCA still
    /// fails at the next honest Verifier.
    pub fn continue_malicious(
        &self,
        pred: &Pca,
        inv: Invariants,
        req: Request,
        now: DateTime<Utc>,
    ) -> PicResult<Pca> {
        self.build(pred, inv, req, None, now, false)
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        &self,
        pred: &Pca,
        inv: Invariants,
        req: Request,
        ml: Option<crate::sandboxed::MultiLineage>,
        now: DateTime<Utc>,
        enforce: bool,
    ) -> PicResult<Pca> {
        if enforce {
            attenuates(&inv, &pred.invariants)
                .map_err(|e| format!("prover self-check failed: {e}"))?;
            conforms(
                &self.attestation.attributes,
                &pred.invariants.execution_contract,
            )
            .map_err(|e| format!("prover self-check failed: {e}"))?;
        }
        let pred_digest = pred.digest();
        let nonce = random_b64(32);
        let challenge = random_b64(32);

        // Per-hop expiry is the tighter of the hop window and the lineage bound.
        let pred_expires = parse_rfc3339(&pred.expires_at);
        let mut expires = now + hop_ttl();
        if expires > pred_expires {
            expires = pred_expires;
        }
        let mut challenge_expiry = now + challenge_ttl();
        if challenge_expiry > pred_expires {
            challenge_expiry = pred_expires;
        }

        let mut p = Pca {
            // Revocation coordinates propagated unchanged, counter incremented.
            profile: pred.profile.clone(),
            lineage_id: pred.lineage_id.clone(),
            lineage_counter: pred.lineage_counter + 1,
            branch_id: pred.branch_id.clone(),
            grant_id: pred.grant_id.clone(),
            origin_issuer: pred.origin_issuer.clone(),
            proof_of_relationship: Some(Por {
                type_: POR_TYPE.to_string(),
                previous_pca_hash: pred_digest,
                continuation_response: ContinuationResponse {
                    predecessor_challenge: pred.continuation.challenge.clone(),
                    executor_nonce: nonce,
                },
                executor: self.executor.id.clone(),
                request: req,
                executor_attestation: self.attestation.clone(),
            }),
            invariants: inv,
            continuation: Continuation {
                challenge,
                mode: "single-use".to_string(),
                max_uses: 1,
                expires_at: rfc3339(challenge_expiry),
            },
            multi_lineage: ml,
            issued_at: rfc3339(now),
            expires_at: rfc3339(expires),
            ..Default::default()
        };
        sign_pca(&mut p, self.executor);
        Ok(p)
    }
}

/// Produces the signed handoff envelope carrying `pred` and `current` together
/// (§2.5). The forwarder signs the envelope; the two PCAs keep their own
/// signatures.
pub fn wrap_envelope(forwarder: &Identity, pred: &Pca, current: &Pca) -> Envelope {
    let pred_digest = pred.digest();
    let cur_digest = current.digest();
    let mut env = Envelope {
        envelope: EnvelopeBody {
            forwarded_by: forwarder.id.clone(),
            predecessor: Some(pred.clone()),
            predecessor_digest: pred_digest,
            current: Some(current.clone()),
            current_digest: cur_digest,
        },
        proof: None,
    };
    let msg = env.signing_bytes();
    env.proof = Some(Proof {
        type_: SIGNATURE_TYPE.to_string(),
        verification_method: forwarder.verification_method.clone(),
        signature: forwarder.sign(&msg),
    });
    env
}
