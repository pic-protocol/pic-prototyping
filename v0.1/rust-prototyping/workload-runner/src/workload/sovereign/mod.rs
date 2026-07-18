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
pub mod gateway;
pub mod registry;
pub mod storage;
pub mod trustplane;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
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
    pub vp: Option<serde_json::Value>,
    pub vp_bytes: Vec<u8>,
    pub public_key: Option<VerifyingKey>,
    pub private_key: Option<SigningKey>,
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

        let vp_path = path.join("presentation.vp.json"); 
        let (vp, vp_bytes) = if vp_path.exists() {
            let vp: serde_json::Value = serde_json::from_str(&fs::read_to_string(&vp_path)?)?;
            let vp_bytes = serde_json::to_vec(&vp)?;
            (Some(vp), vp_bytes)
        } else {
            (None, Vec::new())
        };

        let kid = did_doc["verificationMethod"]
            .as_array()
            .and_then(|methods| methods.first())
            .and_then(|method| method["id"].as_str())
            .unwrap_or("")
            .to_string();

        // Load public key from DID document (JWK format)
        let public_key = Self::load_public_key_from_did(&did_doc);

        // Load private key from file (if exists)
        let private_key = Self::load_private_key(&path);

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
            public_key,
            private_key,
        })
    }

    fn load_public_key_from_did(did_doc: &serde_json::Value) -> Option<VerifyingKey> {
        let method = did_doc["verificationMethod"]
            .as_array()?
            .first()?;

        // Try publicKeyJwk (Ed25519)
        if let Some(jwk) = method.get("publicKeyJwk") {
            if jwk["crv"].as_str() == Some("Ed25519") {
                if let Some(x) = jwk["x"].as_str() {
                    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(x) {
                        if bytes.len() == 32 {
                            let bytes_array: [u8; 32] = bytes.try_into().ok()?;
                            return VerifyingKey::from_bytes(&bytes_array).ok();
                        }
                    }
                }
            }
        }

        // Try publicKeyMultibase
        if let Some(multibase) = method.get("publicKeyMultibase") {
            if let Some(key_str) = multibase.as_str() {
                // Multibase z = base58btc
                if key_str.starts_with('z') {
                    if let Ok(bytes) = bs58::decode(&key_str[1..]).into_vec() {
                        // Ed25519 multicodec prefix is 0xed01
                        if bytes.len() >= 34 && bytes[0] == 0xed && bytes[1] == 0x01 {
                            let key_bytes: [u8; 32] = bytes[2..34].try_into().ok()?;
                            return VerifyingKey::from_bytes(&key_bytes).ok();
                        }
                    }
                }
            }
        }

        None
    }

    fn load_private_key(path: &PathBuf) -> Option<SigningKey> {
        // Try different private key file names
        let key_files = [
            "private-key.json",
            "signing-key.json", 
            "private.jwk",
            "key.json",
            "issuer-key.private.jwk",
            "cat-key.private.jwk",
        ];

        for file in key_files {
            let key_path = path.join(file);
            if key_path.exists() {
                if let Ok(content) = fs::read_to_string(&key_path) {
                    if let Ok(jwk) = serde_json::from_str::<serde_json::Value>(&content) {
                        // JWK with "d" field (private key)
                        if let Some(d) = jwk["d"].as_str() {
                            if let Ok(bytes) = URL_SAFE_NO_PAD.decode(d) {
                                if bytes.len() == 32 {
                                    let bytes_array: [u8; 32] = bytes.try_into().ok()?;
                                    return Some(SigningKey::from_bytes(&bytes_array));
                                }
                            }
                        }
                    }
                }
            }
        }

        // Try raw 32-byte file
        let raw_path = path.join("private-key.bin");
        if raw_path.exists() {
            if let Ok(bytes) = fs::read(&raw_path) {
                if bytes.len() == 32 {
                    let bytes_array: [u8; 32] = bytes.try_into().ok()?;
                    return Some(SigningKey::from_bytes(&bytes_array));
                }
            }
        }

        None
    }

    pub fn print(&self) {
        println!("📦 {}", self.name.to_uppercase());
        println!("   DID: {}", self.did);
        println!("   Issuer: {}", self.issuer);
        println!("   Role: {}", self.role);
        println!("   Has public key: {}", self.public_key.is_some());
        println!("   Has private key: {}", self.private_key.is_some());
    }

    pub fn signing_key(&self) -> Option<&SigningKey> {
        self.private_key.as_ref()
    }

    pub fn verifying_key(&self) -> Option<&VerifyingKey> {
        self.public_key.as_ref()
    }
}

#[derive(Clone)]
pub struct Request {
    pub content: String,
    pub pca_bytes: Option<Vec<u8>>,
}

pub struct Response {
    pub output_file: String,
    pub data: String,
}