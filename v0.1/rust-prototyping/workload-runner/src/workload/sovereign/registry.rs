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
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use std::sync::Arc;

use super::trustplane::TrustPlane;
use super::WorkloadIdentity;

pub struct Registry {
    identities: HashMap<String, Arc<WorkloadIdentity>>,
    trustplane: Arc<TrustPlane>,
}

impl Registry {
    /// Load all workload identities and initialize TrustPlane
    pub fn load() -> Result<Self> {
        let names = [
            "sovereign-trustplane",
            "sovereign-gateway",
            "sovereign-archive",
            "sovereign-storage",
        ];
        let mut identities = HashMap::new();

        // Load all workload identities into registry
        for name in names {
            let identity = WorkloadIdentity::load(name)?;
            identities.insert(name.to_string(), Arc::new(identity));
        }

        // Get the trustplane identity from already loaded identities
        // IMPORTANT: Don't reload it - use the same instance to ensure key consistency
        let tp_identity = identities
            .get("sovereign-trustplane")
            .ok_or_else(|| anyhow!("sovereign-trustplane not found in loaded identities"))?;

        // Create TrustPlane using the same identity instance
        // This ensures signing key matches the public key in registry
        let trustplane = Arc::new(TrustPlane::new(tp_identity.as_ref().clone())?);

        println!("📂 Registry: loaded {} identities", identities.len());
        println!("🔐 TrustPlane: {}", trustplane.did());
        println!("🔐 TrustPlane kid: {}", trustplane.kid());
        println!("   Using real key: {}", trustplane.has_real_key());

        Ok(Self {
            identities,
            trustplane,
        })
    }

    /// Lookup verifying key by kid (key identifier)
    /// Searches all loaded identities for matching kid
    pub fn get_verifying_key(&self, kid: &str) -> Option<&VerifyingKey> {
        self.identities
            .values()
            .find(|id| id.kid == kid)
            .and_then(|id| id.public_key.as_ref())
    }

    /// Lookup verifying key by DID
    pub fn get_verifying_key_by_did(&self, did: &str) -> Option<&VerifyingKey> {
        self.identities
            .values()
            .find(|id| id.did == did)
            .and_then(|id| id.public_key.as_ref())
    }

    /// Get workload identity by name
    pub fn get(&self, name: &str) -> Option<Arc<WorkloadIdentity>> {
        self.identities.get(name).cloned()
    }

    /// Get reference to TrustPlane
    pub fn trustplane(&self) -> Arc<TrustPlane> {
        self.trustplane.clone()
    }

    /// Check if a kid is known to the registry
    pub fn is_known_kid(&self, kid: &str) -> bool {
        self.identities.values().any(|id| id.kid == kid)
    }

    /// Get all known kids (useful for debugging)
    pub fn known_kids(&self) -> Vec<&str> {
        self.identities
            .values()
            .map(|id| id.kid.as_str())
            .collect()
    }
}