pub mod gateway;
pub mod archive;
pub mod storage;
pub mod registry;

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
    pub issuer: String,
    pub role: String,
    pub did_doc: serde_json::Value,
    pub vc: serde_json::Value,
}

impl WorkloadIdentity {
    pub fn load(name: &str) -> Result<Self> {
        let path = fixtures_dir().join(name);
        
        let did_doc: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(path.join("did.json"))
                .with_context(|| format!("Failed to read did.json for {}", name))?
        )?;
        
        let vc: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(path.join("credential.vc.json"))
                .with_context(|| format!("Failed to read credential.vc.json for {}", name))?
        )?;

        Ok(Self {
            name: name.to_string(),
            did: did_doc["id"].as_str().unwrap_or("").to_string(),
            issuer: vc["issuer"].as_str().unwrap_or("").to_string(),
            role: vc["credentialSubject"]["role"].as_str().unwrap_or("").to_string(),
            did_doc,
            vc,
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
}

pub struct Response {
    pub output_file: String,
    pub data: String,
}