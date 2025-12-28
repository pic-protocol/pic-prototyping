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

use anyhow::Result;
use pic::pca::{CoseSigned, ExecutorBinding, PocBuilder, SignedPca, SignedPoc, SigningAlgorithm};
use std::sync::Arc;

use super::{registry::Registry, Request, Response, WorkloadIdentity};
use crate::workload::instrumentation::{HopTiming, Timer};

pub struct Storage {
    identity: Arc<WorkloadIdentity>,
    registry: Arc<Registry>,
}

impl Storage {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry
            .get("sovereign-storage")
            .ok_or_else(|| anyhow::anyhow!("sovereign-storage not found in registry"))?;
        Ok(Self { identity, registry })
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
            .ok_or_else(|| anyhow::anyhow!("No PCA received"))?;
        timing.pca_received_size = pca_bytes.len();

        // Deserialize PCA
        let deser_timer = Timer::start();
        let signed_pca: SignedPca = CoseSigned::from_bytes(pca_bytes)?;
        let pca = signed_pca.payload_unverified()?;
        timing.pca_deserialize = deser_timer.stop();

        println!("   ← Received PCA hop={} ops={:?}", pca.hop, pca.ops);

        // Create PoC
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

        // Sign PoC with COSE_Sign1
        let poc_ser_timer = Timer::start();
        let signed_poc: SignedPoc = CoseSigned::sign_with(
            &poc,
            &self.identity.kid,
            SigningAlgorithm::EdDSA,
            |_| Ok(vec![0u8; 64]), // Mock signature
        )?;
        let poc_bytes = signed_poc.to_bytes()?;
        timing.poc_serialize = poc_ser_timer.stop();
        timing.poc_size = poc_bytes.len();

        println!("   → Created PoC ({} bytes) - final hop", poc_bytes.len());

        // Call CAT (even on final hop for consistency)
        let cat_timer = Timer::start();
        let new_pca_bytes = self.registry.cat().process_poc(&poc_bytes)?;
        timing.cat_call = cat_timer.stop();
        timing.pca_new_size = new_pca_bytes.len();

        // Business logic - actual storage operation
        let logic_timer = Timer::start();
        let output_file = format!("/user/output_{}.txt", timestamp());
        let data = format!("Processed: {}", request.content);
        timing.business_logic = logic_timer.stop();

        println!("   ✓ Written: {}", output_file);

        timing.total = hop_start.stop();

        Ok((Response { output_file, data }, vec![timing]))
    }
}

fn timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}