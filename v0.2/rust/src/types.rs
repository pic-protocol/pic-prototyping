// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! The signed PIC document types: PCA, Proof of Relationship, Attestation,
//! Envelope, Snapshot, and their components.
//!
//! Field order matches the Go structs so pretty-printed (declaration-order) JSON
//! is identical; the signature/digest bytes are always the *sorted* canonical
//! form computed by [`crate::canonical_json`]. Every Go `,omitempty` tag maps to
//! a `skip_serializing_if`; time fields are RFC3339 `String`s emitted verbatim.

use crate::crypto::canonical_json;
use crate::digest_of;
use serde::{Deserialize, Serialize};

fn is_zero_i64(n: &i64) -> bool {
    *n == 0
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

/// The reference-profile execution contract: the constraints a successor
/// executor must satisfy (Prover/Verifier spec §1.8, §4.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionContract {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<String>,
    #[serde(
        default,
        rename = "executionModel",
        skip_serializing_if = "String::is_empty"
    )]
    pub execution_model: String,
}

/// The signed, non-expansive state of a lineage: the authority that may continue
/// (operations) and the contract executors must satisfy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invariants {
    pub operations: Vec<String>,
    #[serde(rename = "executionContract")]
    pub execution_contract: ExecutionContract,
}

/// The freshness challenge a PCA emits for its next hop (§6.1).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Continuation {
    pub challenge: String,
    pub mode: String,
    #[serde(default, rename = "maxUses", skip_serializing_if = "is_zero_i64")]
    pub max_uses: i64,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// The attested attributes checked against an execution contract by the
/// conformance function (§3.3 check 5, §4.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractAttributes {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compliance: Vec<String>,
    #[serde(
        default,
        rename = "executionModel",
        skip_serializing_if = "String::is_empty"
    )]
    pub execution_model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub environment: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
}

/// A signed attribute attestation: the conformance evidence an executor presents
/// to prove it satisfies the predecessor execution contract (§1.6).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Attestation {
    pub subject: String,
    pub attributes: ContractAttributes,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl Attestation {
    /// The canonical bytes the issuer signature covers: the attestation without
    /// its own proof.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("attestation to_value");
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        serde_json::to_vec(&value).expect("attestation to_vec")
    }
}

/// The request binding: pins authority to the concrete action so enforcement can
/// check executed-vs-signed (§2.3, §3.3 check 8).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Request {
    pub operation: String,
    pub target: String,
    #[serde(rename = "securityDomain")]
    pub security_domain: String,
    #[serde(
        default,
        rename = "requestDigest",
        skip_serializing_if = "String::is_empty"
    )]
    pub request_digest: String,
    #[serde(
        default,
        rename = "payloadDigest",
        skip_serializing_if = "String::is_empty"
    )]
    pub payload_digest: String,

    // Sandboxed Execution profile (outer ENFORCE PCA only).
    #[serde(
        default,
        rename = "multiLineageDigest",
        skip_serializing_if = "String::is_empty"
    )]
    pub multi_lineage_digest: String,
    #[serde(
        default,
        rename = "policyCommitment",
        skip_serializing_if = "String::is_empty"
    )]
    pub policy_commitment: String,
    #[serde(
        default,
        rename = "inputsCommitment",
        skip_serializing_if = "String::is_empty"
    )]
    pub inputs_commitment: String,
    #[serde(
        default,
        rename = "semanticProfile",
        skip_serializing_if = "String::is_empty"
    )]
    pub semantic_profile: String,
    #[serde(
        default,
        rename = "enforcementResult",
        skip_serializing_if = "String::is_empty"
    )]
    pub enforcement_result: String,
}

/// Answers the predecessor's challenge with a fresh local nonce (§2.3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContinuationResponse {
    #[serde(rename = "predecessorChallenge")]
    pub predecessor_challenge: String,
    #[serde(rename = "executorNonce")]
    pub executor_nonce: String,
}

/// Proof of Relationship: binds the current execution to exactly one predecessor
/// (§2.3). Carried in the clear and covered by the PCA signature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Por {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "previousPcaHash")]
    pub previous_pca_hash: String,
    #[serde(rename = "continuationResponse")]
    pub continuation_response: ContinuationResponse,
    pub executor: String,
    pub request: Request,
    #[serde(rename = "executorAttestation")]
    pub executor_attestation: Attestation,
}

/// A single detached signature covering a document as a whole.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    pub signature: String,
}

/// A PIC Context of Authority: the signed document carrying a lineage's
/// invariants at one hop. PCA0 (the origin) carries no PoR and no previous hash.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Pca {
    // Revocation coordinates (Revocation spec §2).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile: String,
    #[serde(
        default,
        rename = "lineageId",
        skip_serializing_if = "String::is_empty"
    )]
    pub lineage_id: String,
    #[serde(rename = "lineageCounter")]
    pub lineage_counter: u64,
    #[serde(default, rename = "branchId", skip_serializing_if = "String::is_empty")]
    pub branch_id: String,
    #[serde(default, rename = "grantId", skip_serializing_if = "String::is_empty")]
    pub grant_id: String,
    #[serde(
        default,
        rename = "originIssuer",
        skip_serializing_if = "String::is_empty"
    )]
    pub origin_issuer: String,

    // Origin (PCA0) only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer: String,
    #[serde(
        default,
        rename = "originNonce",
        skip_serializing_if = "String::is_empty"
    )]
    pub origin_nonce: String,

    // Non-origin only.
    #[serde(
        default,
        rename = "proofOfRelationship",
        skip_serializing_if = "Option::is_none"
    )]
    pub proof_of_relationship: Option<Por>,

    pub invariants: Invariants,
    pub continuation: Continuation,

    /// The signed Sandboxed Execution profile field carried by an outer ENFORCE
    /// PCA (§2.4): the inner Multi-Lineage Execution being governed. Covered by
    /// the single PCA signature; None on every ordinary PCA.
    #[serde(
        default,
        rename = "multiLineage",
        skip_serializing_if = "Option::is_none"
    )]
    pub multi_lineage: Option<crate::sandboxed::MultiLineage>,

    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl Pca {
    /// Reports whether this PCA is a PCA0 (no Proof of Relationship).
    pub fn is_origin(&self) -> bool {
        self.proof_of_relationship.is_none()
    }

    /// The content-addressed id of the complete, signed PCA ("sha256:<hex>" over
    /// its canonical bytes, proof included). This is the value a successor places
    /// in `previousPcaHash` (§2.5).
    pub fn digest(&self) -> String {
        digest_of(self)
    }

    /// The canonical bytes a signature covers: the whole PCA except the outer
    /// proof (a document cannot sign its own signature).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("pca to_value");
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        serde_json::to_vec(&value).expect("pca to_vec")
    }
}

/// The signed handoff wrapper carrying the predecessor and current PCAs together
/// (§2.5). Envelopes are never nested.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Envelope {
    pub envelope: EnvelopeBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl Envelope {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("envelope to_value");
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        serde_json::to_vec(&value).expect("envelope to_vec")
    }
}

/// Carries the two self-contained PCAs and their convenience digests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvelopeBody {
    #[serde(rename = "forwardedBy")]
    pub forwarded_by: String,
    pub predecessor: Option<Pca>,
    #[serde(rename = "predecessorDigest")]
    pub predecessor_digest: String,
    pub current: Option<Pca>,
    #[serde(rename = "currentDigest")]
    pub current_digest: String,
}

/// A signed attestation from a trusted issuer that a lineage's chain is valid up
/// to `PCA[throughCounter]`, whose content id is `throughPcaHash` (§5.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "lineageId")]
    pub lineage_id: String,
    #[serde(rename = "throughCounter")]
    pub through_counter: u64,
    #[serde(rename = "throughPcaHash")]
    pub through_pca_hash: String,
    pub issuer: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}

impl Snapshot {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut value = serde_json::to_value(self).expect("snapshot to_value");
        if let Some(obj) = value.as_object_mut() {
            obj.remove("proof");
        }
        serde_json::to_vec(&value).expect("snapshot to_vec")
    }
}

/// One native causal cutoff. Only the fields relevant to its strategy are set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Revocation {
    pub strategy: String,
    #[serde(
        default,
        rename = "lineageId",
        skip_serializing_if = "String::is_empty"
    )]
    pub lineage_id: String,
    #[serde(default, rename = "branchId", skip_serializing_if = "String::is_empty")]
    pub branch_id: String,
    #[serde(default, rename = "grantId", skip_serializing_if = "String::is_empty")]
    pub grant_id: String,
    #[serde(default, rename = "fromCounter", skip_serializing_if = "is_zero_u64")]
    pub from_counter: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub issuer: String,
}

/// The profile-defined canonical projection of a PCA0 that excludes `lineageId`
/// and `proof`, used to derive `lineageId` (Revocation spec §2.1). All fields are
/// always present (no omitempty), matching the Go `originCore`.
#[derive(Serialize)]
pub(crate) struct OriginCore<'a> {
    pub profile: &'a str,
    pub issuer: &'a str,
    #[serde(rename = "originNonce")]
    pub origin_nonce: &'a str,
    #[serde(rename = "grantId")]
    pub grant_id: &'a str,
    pub invariants: &'a Invariants,
    #[serde(rename = "issuedAt")]
    pub issued_at: &'a str,
    #[serde(rename = "expiresAt")]
    pub expires_at: &'a str,
}

impl OriginCore<'_> {
    pub(crate) fn canonical(&self) -> Vec<u8> {
        canonical_json(self)
    }
}
