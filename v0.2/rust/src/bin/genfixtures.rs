// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Command genfixtures deterministically (re)generates the v0.2 fixtures: a DID
//! document and Ed25519 key per actor, plus signed attestations for the executor
//! hops. Output goes to v0.2/fixtures. Keys are throwaway, for demos and tests.
//!
//!   cargo run --bin genfixtures [output-dir]

use pic::crypto::Identity;
use pic::types::{Attestation, ContractAttributes};
use pic::{sign_attestation, PicResult};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

/// Describes one fixture identity. Executors also get a signed attestation.
struct Actor {
    name: &'static str,
    did: &'static str,
    role: &'static str, // empty for non-executors (principal / issuer)
    exec_model: &'static str,
    compliance: &'static [&'static str],
    is_executor: bool,
}

// The fixture cast: the origin principal (alice), the attestation issuer
// (org-authority), the snapshot validator, and the executor hops.
fn actors() -> Vec<Actor> {
    vec![
        Actor {
            name: "alice",
            did: "did:web:alice.example",
            role: "",
            exec_model: "",
            compliance: &[],
            is_executor: false,
        },
        Actor {
            name: "org-authority",
            did: "did:web:org-authority.example",
            role: "",
            exec_model: "",
            compliance: &[],
            is_executor: false,
        },
        Actor {
            name: "snapshot-issuer",
            did: "did:web:snapshot.example",
            role: "",
            exec_model: "",
            compliance: &[],
            is_executor: false,
        },
        Actor {
            name: "gateway",
            did: "did:web:gateway.example",
            role: "gateway",
            exec_model: "deterministic",
            compliance: &[],
            is_executor: true,
        },
        Actor {
            name: "backup-service",
            did: "did:web:backup.example",
            role: "backup-service",
            exec_model: "deterministic",
            compliance: &["GDPR"],
            is_executor: true,
        },
        Actor {
            name: "summary-service",
            did: "did:web:summary.example",
            role: "summary-service",
            exec_model: "agentic",
            compliance: &[],
            is_executor: true,
        },
        Actor {
            name: "archive-service",
            did: "did:web:archive.example",
            role: "archive-service",
            exec_model: "deterministic",
            compliance: &["GDPR"],
            is_executor: true,
        },
        Actor {
            name: "storage-service",
            did: "did:web:storage.example",
            role: "storage-service",
            exec_model: "deterministic",
            compliance: &["GDPR"],
            is_executor: true,
        },
    ]
}

// Fixed, wide validity window so attestations verify regardless of run date.
const FX_ISSUED: &str = "2026-01-01T00:00:00Z";
const FX_EXPIRES: &str = "2035-01-01T00:00:00Z";

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_fixtures_dir);
    if let Err(e) = run(&out_dir) {
        eprintln!("genfixtures: {e}");
        exit(1);
    }
    println!("fixtures written to {}", out_dir.display());
}

fn run(out_dir: &Path) -> PicResult<()> {
    // deterministic identities, built first so the issuer key is available.
    let mut ids: HashMap<&str, Identity> = HashMap::new();
    for a in actors() {
        let id = Identity::load(a.did, &format!("{}#key-1", a.did), &seed_for(a.name))?;
        ids.insert(a.name, id);
    }
    let org = ids.get("org-authority").expect("org-authority identity");

    for a in actors() {
        let id = ids.get(a.name).expect("identity");
        let dir = out_dir.join("identities").join(a.name);
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        write_json(&dir.join("did.json"), &did_document(id))?;
        write_json(&dir.join("private.jwk"), &private_jwk(id))?;
        if a.is_executor {
            let att = sign_attestation(
                Attestation {
                    subject: id.id.clone(),
                    attributes: ContractAttributes {
                        role: a.role.to_string(),
                        compliance: a.compliance.iter().map(|s| s.to_string()).collect(),
                        execution_model: a.exec_model.to_string(),
                        environment: "production".to_string(),
                        region: "eu-1".to_string(),
                    },
                    issued_at: FX_ISSUED.to_string(),
                    expires_at: FX_EXPIRES.to_string(),
                    ..Default::default()
                },
                org,
            );
            let adir = out_dir.join("attestations");
            fs::create_dir_all(&adir).map_err(|e| e.to_string())?;
            write_json(&adir.join(format!("{}.json", a.name)), &att)?;
        }
    }
    Ok(())
}

/// Derives a deterministic 32-byte Ed25519 seed from the actor name.
fn seed_for(name: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("PIC-v0.2-fixture-seed:{name}").as_bytes());
    h.finalize().into()
}

#[derive(Serialize)]
struct Jwk {
    kty: &'static str,
    crv: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    kid: String,
    x: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    d: String,
}

fn private_jwk(id: &Identity) -> Jwk {
    Jwk {
        kty: "OKP",
        crv: "Ed25519",
        kid: id.verification_method.clone(),
        x: id.encode_public(),
        d: id.seed(),
    }
}

#[derive(Serialize)]
struct VerificationMethod {
    id: String,
    #[serde(rename = "type")]
    type_: &'static str,
    controller: String,
    #[serde(rename = "publicKeyJwk")]
    public_key_jwk: Jwk,
}

#[derive(Serialize)]
struct DidDoc {
    #[serde(rename = "@context")]
    context: Vec<&'static str>,
    id: String,
    #[serde(rename = "verificationMethod")]
    verification_method: Vec<VerificationMethod>,
    #[serde(rename = "assertionMethod")]
    assertion_method: Vec<String>,
    authentication: Vec<String>,
}

fn did_document(id: &Identity) -> DidDoc {
    DidDoc {
        context: vec![
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        id: id.id.clone(),
        verification_method: vec![VerificationMethod {
            id: id.verification_method.clone(),
            type_: "Ed25519VerificationKey2020",
            controller: id.id.clone(),
            public_key_jwk: Jwk {
                kty: "OKP",
                crv: "Ed25519",
                kid: id.verification_method.clone(),
                x: id.encode_public(),
                d: String::new(),
            },
        }],
        assertion_method: vec![id.verification_method.clone()],
        authentication: vec![id.verification_method.clone()],
    }
}

/// Writes `v` as 2-space pretty JSON plus a trailing newline, matching Go's
/// `json.MarshalIndent(v, "", "  ")` + `\n`.
fn write_json<T: Serialize>(path: &Path, v: &T) -> PicResult<()> {
    let mut b = serde_json::to_string_pretty(v).map_err(|e| e.to_string())?;
    b.push('\n');
    fs::write(path, b).map_err(|e| e.to_string())
}

/// Resolves v0.2/fixtures relative to the crate manifest.
fn default_fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
}
