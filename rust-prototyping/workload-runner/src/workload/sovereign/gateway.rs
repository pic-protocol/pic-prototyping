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
use pic::pca::ExecutorBinding;
use std::sync::Arc;

use super::{archive::Archive, registry::Registry, Request, Response, WorkloadIdentity};
use crate::workload::instrumentation::{ChainTiming, Timer};

pub struct Gateway {
    identity: Arc<WorkloadIdentity>,
    registry: Arc<Registry>,
}

impl Gateway {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry
            .get("sovereign-gateway")
            .ok_or_else(|| anyhow::anyhow!("sovereign-gateway not found in registry"))?;
        Ok(Self { identity, registry })
    }

    /// Old method for compatibility
    pub fn load() -> Result<Self> {
        let registry = Arc::new(Registry::load()?);
        Self::new(registry)
    }

    pub async fn next(&self, request: Request) -> Result<(Response, ChainTiming)> {
        let chain_start = Timer::start();
        let mut timing = ChainTiming::default();

        self.identity.print();

        // Create PCA_0 (origin)
        let pca_create_timer = Timer::start();

        let executor_binding = ExecutorBinding::new()
            .with("federation", "sovereign.example")
            .with("namespace", "prod")
            .with("service", "gateway");

        let ops = vec!["read:/user/*".to_string(), "write:/user/*".to_string()];
        let p_0 = "https://idp.sovereign.example/users/alice";

        timing.initial_pca_create = pca_create_timer.stop();

        let sign_timer = Timer::start();
        let pca_bytes = self
            .registry
            .cat()
            .create_pca_0(p_0, ops, executor_binding)?;
        timing.initial_pca_sign = sign_timer.stop();
        timing.initial_pca_size = pca_bytes.len();

        println!("   → Created PCA_0 ({} bytes)", pca_bytes.len());
        println!("   → Forwarding to Archive");

        // Forward to next hop with PCA
        let archive = Archive::new(self.registry.clone())?;
        let next_request = Request {
            content: request.content,
            pca_bytes: Some(pca_bytes),
        };

        let (response, hop_timings) = archive.next(next_request).await?;
        timing.hops = hop_timings;
        timing.total = chain_start.stop();

        println!("   ← Received: {}", response.output_file);

        Ok((response, timing))
    }
}