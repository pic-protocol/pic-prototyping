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
use std::collections::HashMap;
use std::sync::Arc;

use super::cat::MockCat;
use super::WorkloadIdentity;

/// Pre-loaded identities registry (in-memory)
pub struct Registry {
    identities: HashMap<String, Arc<WorkloadIdentity>>,
    cat: Arc<MockCat>,
}

impl Registry {
    /// Load all identities into memory once
    pub fn load() -> Result<Self> {
        // Only load executor workloads (not trustplane which is the issuer)
        let names = [
            "sovereign-gateway",
            "sovereign-archive",
            "sovereign-storage",
        ];
        let mut identities = HashMap::new();

        for name in names {
            let identity = WorkloadIdentity::load(name)?;
            identities.insert(name.to_string(), Arc::new(identity));
        }

        println!(
            "📂 Registry: loaded {} identities into memory",
            identities.len()
        );

        let cat = Arc::new(MockCat::new());
        println!("🔐 CAT: initialized with kid {}", cat.kid());

        Ok(Self { identities, cat })
    }

    pub fn get(&self, name: &str) -> Option<Arc<WorkloadIdentity>> {
        self.identities.get(name).cloned()
    }

    pub fn cat(&self) -> Arc<MockCat> {
        self.cat.clone()
    }
}