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

//! TrustPlane - the Causal Authority for Trust (CAT) in the Sovereign federation.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use pic::pca::{
    CatProvenance, Constraints, CoseSigned, Executor, ExecutorBinding, ExecutorProvenance,
    PcaPayload, Provenance, SignedPca, SignedPoc, TemporalConstraints,
};

use crate::workload::sovereign::registry::Registry;

use super::WorkloadIdentity;

pub struct TrustPlane {
    identity: WorkloadIdentity,
    signing_key: SigningKey,
}

impl TrustPlane {
    pub fn new(identity: WorkloadIdentity) -> Result<Self> {
        let signing_key = identity
            .private_key
            .clone()
            .ok_or_else(|| anyhow!("TrustPlane requires a private key"))?;

        Ok(Self {
            identity,
            signing_key,
        })
    }

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
            executor: Executor {
                binding: executor_binding,
            },
            provenance: None,
            constraints: Some(Constraints {
                temporal: Some(TemporalConstraints {
                    iat: Some(chrono::Utc::now().to_rfc3339()),
                    exp: Some((chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339()),
                    nbf: None,
                }),
            }),
        };

        let signed: SignedPca =
            CoseSigned::sign_ed25519(&pca, &self.identity.kid, &self.signing_key)?;
        Ok(signed.to_bytes()?)
    }

    pub fn process_poc(&self, poc_bytes: &[u8], key_registry: &Registry) -> Result<Vec<u8>> {
        // 1. Deserialize PoC from bytes
        let signed_poc: SignedPoc = CoseSigned::from_bytes(poc_bytes)?;
        
        // 2. Extract executor kid and retrieve public key from registry
        let executor_kid = signed_poc.kid()
            .ok_or_else(|| anyhow!("PoC missing executor kid"))?;
        let executor_key = key_registry.get_verifying_key(&executor_kid)
            .ok_or_else(|| anyhow!("Unknown executor: {}", executor_kid))?;
        
        // 3. VERIFY PoC signature
        let poc = signed_poc.verify_ed25519(&executor_key)
            .map_err(|e| anyhow!("PoC signature verification failed: {}", e))?;

        // 4. Deserialize predecessor PCA from PoC
        let signed_pred: SignedPca = CoseSigned::from_bytes(&poc.predecessor)?;
        
        // 5. Extract CAT kid that signed predecessor and retrieve key
        let pred_cat_kid = signed_pred.kid()
            .ok_or_else(|| anyhow!("Predecessor PCA missing CAT kid"))?;

        let pred_cat_key = key_registry.get_verifying_key(&pred_cat_kid)
            .ok_or_else(|| anyhow!("Unknown CAT: {}", pred_cat_kid))?;
        
        // 6. VERIFY predecessor PCA signature
        let pred_pca: PcaPayload = signed_pred.verify_ed25519(&pred_cat_key)
            .map_err(|e| anyhow!("Predecessor PCA signature verification failed: {}", e))?;

        // 7. p_0 immutability is guaranteed by construction:
        //    new PCA copies p_0 from predecessor, never from PoC
        
        // 8. VERIFY monotonicity: successor ops must be subset of predecessor ops
        for op in &poc.successor.ops {
            if !pred_pca.ops.contains(op) {
                return Err(anyhow!(
                    "Monotonicity violation: '{}' not in predecessor ops {:?}", 
                    op, 
                    pred_pca.ops
                ));
            }
        }

        // 9. VERIFY temporal constraints if present
        if let Some(ref constraints) = poc.successor.constraints {
            if let Some(ref temporal) = constraints.temporal {
                let now = chrono::Utc::now();
                
                // Check expiration
                if let Some(ref exp) = temporal.exp {
                    let exp_time = chrono::DateTime::parse_from_rfc3339(exp)
                        .map_err(|_| anyhow!("Invalid exp timestamp"))?;
                    if now > exp_time {
                        return Err(anyhow!("PCA expired"));
                    }
                }
                
                // Check not-before
                if let Some(ref nbf) = temporal.nbf {
                    let nbf_time = chrono::DateTime::parse_from_rfc3339(nbf)
                        .map_err(|_| anyhow!("Invalid nbf timestamp"))?;
                    if now < nbf_time {
                        return Err(anyhow!("PCA not yet valid"));
                    }
                }
            }
        }

        // 10. Build new PCA with validated data
        let executor_binding = poc.successor.executor.clone().unwrap_or_default();

        let new_pca = PcaPayload {
            hop: pred_pca.hop + 1,
            p_0: pred_pca.p_0.clone(),  // Immutable: always from predecessor
            ops: poc.successor.ops.clone(),
            executor: Executor {
                binding: executor_binding,
            },
            provenance: Some(Provenance {
                cat: CatProvenance {
                    kid: self.identity.kid.clone(),
                    signature: signed_pred
                        .to_bytes()?
                        .get(..64)
                        .unwrap_or(&[0u8; 64])
                        .to_vec(),
                },
                executor: ExecutorProvenance {
                    kid: executor_kid.to_string(),  // ← aggiungi .to_string()
                    signature: poc_bytes.get(..64).unwrap_or(&[0u8; 64]).to_vec(),
                },
            }),
            constraints: poc
                .successor
                .constraints
                .clone()
                .or(pred_pca.constraints.clone()),
        };

        // 11. Sign new PCA with CAT key and return bytes
        let signed: SignedPca =
            CoseSigned::sign_ed25519(&new_pca, &self.identity.kid, &self.signing_key)?;
        Ok(signed.to_bytes()?)
    }

    pub fn kid(&self) -> &str {
        &self.identity.kid
    }

    pub fn did(&self) -> &str {
        &self.identity.did
    }

    pub fn has_real_key(&self) -> bool {
        self.identity.private_key.is_some()
    }
}