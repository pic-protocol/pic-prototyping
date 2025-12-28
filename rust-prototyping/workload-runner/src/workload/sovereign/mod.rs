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

pub mod archive;
pub mod cat;
pub mod gateway;
pub mod registry;
pub mod storage;

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures")
        .join("workload-credentials-test-keys")
}

#[derive(Clone)]
pub struct WorkloadIdentity {
    pub name: String,
    pub did: String,
    pub kid: String,
    pub issuer: String,
    pub role: String,
    pub did_doc: serde_json::Value,
    pub vc: serde_json::Value,
    pub vp: serde_json::Value,
    pub vp_bytes: Vec<u8>,
}

impl WorkloadIdentity {
    pub fn load(name: &str) -> Result<Self> {
        let path = fixtures_dir().join(name);

        let did_doc: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(path.join("did.json"))
                .with_context(|| format!("Failed to read did.json for {}", name))?,
        )?;

        let vc: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(path.join("credential.vc.json"))
                .with_context(|| format!("Failed to read credential.vc.json for {}", name))?,
        )?;

        let vp: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(path.join("presentation.vp.json"))
                .with_context(|| format!("Failed to read presentation.vp.json for {}", name))?,
        )?;

        // Serialize VP to bytes for use in attestations
        let vp_bytes = serde_json::to_vec(&vp)?;

        // Extract kid from DID document verification method
        let kid = did_doc["verificationMethod"]
            .as_array()
            .and_then(|methods| methods.first())
            .and_then(|method| method["id"].as_str())
            .unwrap_or("")
            .to_string();

        Ok(Self {
            name: name.to_string(),
            did: did_doc["id"].as_str().unwrap_or("").to_string(),
            kid,
            issuer: vc["issuer"].as_str().unwrap_or("").to_string(),
            role: vc["credentialSubject"]["role"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            did_doc,
            vc,
            vp,
            vp_bytes,
        })
    }

    pub fn print(&self) {
        println!("📦 {}", self.name.to_uppercase());
        println!("   DID: {}", self.did);
        println!("   Issuer: {}", self.issuer);
        println!("   Role: {}", self.role);
    }
}

#[derive(Clone)]
pub struct Request {
    pub content: String,
    /// PCA bytes received from previous hop (None for origin)
    pub pca_bytes: Option<Vec<u8>>,
}

pub struct Response {
    pub output_file: String,
    pub data: String,
}