/*
 * Copyright Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Mock CAT (Causal Authority for Trust) service.
//!
//! In production, CAT is a separate service that:
//! 1. Receives PoC from executor
//! 2. Validates monotonicity (ops ⊆ predecessor.ops)
//! 3. Verifies attestations
//! 4. Issues new PCA for the next hop

use anyhow::Result;
use ed25519_dalek::SigningKey;
use pic::pca::{
    CatProvenance, Constraints, CoseSigned, ExecutorBinding, ExecutorProvenance,
    Executor, PcaPayload, Provenance, SignedPca, SignedPoc,
    TemporalConstraints,
};
use rand::rngs::OsRng;

/// Mock CAT service for testing.
pub struct MockCat {
    signing_key: SigningKey,
    kid: String,
}

impl MockCat {
    /// Creates a new mock CAT with a random signing key.
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            signing_key,
            kid: "did:web:trustplane.sovereign.example#cat-key-202512".to_string(),
        }
    }

    /// Creates PCA_0 (origin PCA) for the chain.
    pub fn create_pca_0(
        &self,
        p_0: &str,
        ops: Vec<String>,
        executor_binding: ExecutorBinding,
    ) -> Result<Vec<u8>> {
        let pca = PcaPayload {
            hop: 0,
            p_0: p_0.to_string(),
            ops,
            executor: Executor { binding: executor_binding },
            provenance: None,
            constraints: Some(Constraints {
                temporal: Some(TemporalConstraints {
                    iat: Some(chrono::Utc::now().to_rfc3339()),
                    exp: Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
                    nbf: None,
                }),
            }),
        };

        let signed: SignedPca = CoseSigned::sign_ed25519(&pca, &self.kid, &self.signing_key)?;
        Ok(signed.to_bytes()?)
    }

    /// Processes a PoC and returns the new PCA for the next hop.
    ///
    /// In production this would:
    /// 1. Verify PoC signature
    /// 2. Verify predecessor PCA signature
    /// 3. Validate monotonicity (ops ⊆ predecessor.ops)
    /// 4. Verify attestations
    /// 5. Issue new PCA
    pub fn process_poc(&self, poc_bytes: &[u8]) -> Result<Vec<u8>> {
        // Deserialize PoC
        let signed_poc: SignedPoc = CoseSigned::from_bytes(poc_bytes)?;
        let poc = signed_poc.payload_unverified()?;

        // Deserialize predecessor PCA
        let signed_pred: SignedPca = CoseSigned::from_bytes(&poc.predecessor)?;
        let pred_pca = signed_pred.payload_unverified()?;

        // In production: verify signatures, check monotonicity, verify attestations
        // For mock: just create the new PCA

        // Extract executor binding from successor (or use empty if not specified)
        let executor_binding = poc.successor.executor.clone().unwrap_or_default();

        // Create new PCA with incremented hop
        let new_pca = PcaPayload {
            hop: pred_pca.hop + 1,
            p_0: pred_pca.p_0.clone(),
            ops: poc.successor.ops.clone(),
            executor: Executor { binding: executor_binding },
            provenance: Some(Provenance {
                cat: CatProvenance {
                    kid: self.kid.clone(),
                    signature: signed_pred.to_bytes()?.get(..64).unwrap_or(&[0u8; 64]).to_vec(),
                },
                executor: ExecutorProvenance {
                    kid: signed_poc.kid().unwrap_or_default(),
                    signature: poc_bytes.get(..64).unwrap_or(&[0u8; 64]).to_vec(),
                },
            }),
            constraints: poc.successor.constraints.clone().or(pred_pca.constraints.clone()),
        };

        let signed: SignedPca = CoseSigned::sign_ed25519(&new_pca, &self.kid, &self.signing_key)?;
        Ok(signed.to_bytes()?)
    }

    /// Returns the CAT's key identifier.
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl Default for MockCat {
    fn default() -> Self {
        Self::new()
    }
}