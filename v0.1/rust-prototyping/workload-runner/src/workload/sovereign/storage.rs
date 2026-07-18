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

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use pic::pca::{CoseSigned, ExecutorBinding, PocBuilder, SignedPca, SignedPoc};
use std::sync::Arc;

use super::{registry::Registry, Request, Response, WorkloadIdentity};
use crate::workload::instrumentation::{HopTiming, Timer};

pub struct Storage {
    identity: Arc<WorkloadIdentity>,
    signing_key: SigningKey,
    registry: Arc<Registry>,
}

impl Storage {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry
            .get("sovereign-storage")
            .ok_or_else(|| anyhow!("sovereign-storage not found in registry"))?;

        let signing_key = identity
            .private_key
            .clone()
            .unwrap_or_else(|| Self::fallback_key(&identity.kid));

        Ok(Self {
            identity,
            signing_key,
            registry,
        })
    }

    fn fallback_key(kid: &str) -> SigningKey {
        let mut seed = [0u8; 32];
        for (i, byte) in kid.as_bytes().iter().enumerate().take(32) {
            seed[i] = *byte;
        }
        SigningKey::from_bytes(&seed)
    }

    pub fn load() -> Result<Self> {
        let registry = Arc::new(Registry::load()?);
        Self::new(registry)
    }

    pub async fn next(&self, request: Request) -> Result<(Response, Vec<HopTiming>)> {
        let hop_start = Timer::start();
        let mut timing = HopTiming {
            hop_name: "storage".to_string(),
            hop_index: 2,
            ..Default::default()
        };

        self.identity.print();

        let pca_bytes = request
            .pca_bytes
            .as_ref()
            .ok_or_else(|| anyhow!("No PCA received"))?;
        timing.pca_received_size = pca_bytes.len();

        let deser_timer = Timer::start();
        let signed_pca: SignedPca = CoseSigned::from_bytes(pca_bytes)?;
        let pca = signed_pca.payload_unverified()?;
        timing.pca_deserialize = deser_timer.stop();

        println!("   ← Received PCA hop={} ops={:?}", pca.hop, pca.ops);

        let poc_create_timer = Timer::start();
        let executor_binding = ExecutorBinding::new()
            .with("federation", "sovereign.example")
            .with("namespace", "prod")
            .with("service", "storage");

        let poc = PocBuilder::new(pca_bytes.clone())
            .ops(pca.ops.clone())
            .executor(executor_binding)
            .attestation("vp", self.identity.vp_bytes.clone())
            .build()
            .map_err(anyhow::Error::msg)?;
        timing.poc_create = poc_create_timer.stop();

        let poc_ser_timer = Timer::start();
        let signed_poc: SignedPoc =
            CoseSigned::sign_ed25519(&poc, &self.identity.kid, &self.signing_key)?;
        let poc_bytes = signed_poc.to_bytes()?;
        timing.poc_serialize = poc_ser_timer.stop();
        timing.poc_size = poc_bytes.len();

        println!("   → Created PoC ({} bytes) - final hop", poc_bytes.len());

        let tp_timer = Timer::start();
        let new_pca_bytes = self.registry.trustplane().process_poc(&poc_bytes, &self.registry)?;
        timing.trustplane_call = tp_timer.stop();
        timing.pca_new_size = new_pca_bytes.len();

        let logic_timer = Timer::start();
        let output_file = format!("/user/output_{}.txt", timestamp());
        let data = format!("Processed: {}", request.content);
        timing.business_logic = logic_timer.stop();

        println!("   ✓ Written: {}", output_file);

        timing.total = hop_start.stop();

        Ok((Response { output_file, data }, vec![timing]))
    }

    pub fn has_real_key(&self) -> bool {
        self.identity.private_key.is_some()
    }
}

fn timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}