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
use chrono::Utc;
use ssi::claims::jws::JwsPayload;
use ssi::jwk::JWK;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Clone)]
#[allow(dead_code)]
pub struct Identity {
    pub did: String,
    pub signing_key: JWK,
    pub signing_kid: String,
}

/// TrustPlane has two keys: issuer (for VC) + cat (for PCA)
#[derive(Clone)]
#[allow(dead_code)]
pub struct TrustPlaneIdentity {
    pub did: String,
    pub issuer_key: JWK,
    pub issuer_kid: String,
    pub cat_key: JWK,
    pub cat_kid: String,
}

/// Workload identity type for credentialSubject
#[derive(Clone)]
pub struct WorkloadIdentity {
    pub organization: String,
    pub identity_type: WorkloadIdentityType,
}

#[derive(Clone)]
pub enum WorkloadIdentityType {
    Spiffe {
        spiffe_id: String,
    },
    Kubernetes {
        namespace: String,
        service_account: String,
    },
    Did {
        did: String,
    },
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures")
        .join("workload-credentials-test-keys")
}

fn key_id_with_date(did: &str, purpose: &str) -> String {
    let date = Utc::now().format("%Y%m");
    format!("{}#{}-{}", did, purpose, date)
}

fn workload_identity_to_json(identity: &WorkloadIdentity) -> serde_json::Value {
    let mut base = match &identity.identity_type {
        WorkloadIdentityType::Spiffe { spiffe_id } => serde_json::json!({
            "type": "spiffe",
            "spiffeId": spiffe_id
        }),
        WorkloadIdentityType::Kubernetes {
            namespace,
            service_account,
        } => serde_json::json!({
            "type": "kubernetes",
            "namespace": namespace,
            "serviceAccount": service_account
        }),
        WorkloadIdentityType::Did { did } => serde_json::json!({
            "type": "did",
            "did": did
        }),
    };

    base["organization"] = serde_json::Value::String(identity.organization.clone());
    base
}

/// Generate TrustPlane identity with two keys
pub async fn trustplane_gen(
    name: &str,
    domain: &str,
    organization: &str,
) -> Result<TrustPlaneIdentity> {
    let dir = fixtures_dir().join(name);
    fs::create_dir_all(&dir)?;

    let did = format!("did:web:{}", domain);

    // Generate two Ed25519 keys
    let mut issuer_key = JWK::generate_ed25519().expect("failed to generate issuer key");
    let mut cat_key = JWK::generate_ed25519().expect("failed to generate cat key");

    // Set key IDs with date for rotation
    let issuer_kid = key_id_with_date(&did, "issuer-key");
    let cat_kid = key_id_with_date(&did, "cat-key");

    issuer_key.key_id = Some(issuer_kid.clone());
    cat_key.key_id = Some(cat_kid.clone());

    // Create DID Document with both keys
    let did_doc = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": &did,
        "verificationMethod": [
            {
                "id": &issuer_kid,
                "type": "Ed25519VerificationKey2020",
                "controller": &did,
                "publicKeyJwk": serde_json::to_value(&issuer_key.to_public())?
            },
            {
                "id": &cat_kid,
                "type": "Ed25519VerificationKey2020",
                "controller": &did,
                "publicKeyJwk": serde_json::to_value(&cat_key.to_public())?
            }
        ],
        "assertionMethod": [&issuer_kid, &cat_kid],
        "authentication": [&issuer_kid, &cat_kid]
    });

    // Self-issued VC for TrustPlane
    let identity = WorkloadIdentity {
        organization: organization.to_string(),
        identity_type: WorkloadIdentityType::Did { did: did.clone() },
    };

    let vc = create_pic_credential(
        &did,
        name,
        "TrustAnchor",
        &identity,
        &did,
        &issuer_kid,
        &issuer_key,
    )
    .await?;

    // Write files
    fs::write(
        dir.join("issuer-key.private.jwk"),
        serde_json::to_string_pretty(&issuer_key)?,
    )?;
    fs::write(
        dir.join("issuer-key.public.jwk"),
        serde_json::to_string_pretty(&issuer_key.to_public())?,
    )?;
    fs::write(
        dir.join("cat-key.private.jwk"),
        serde_json::to_string_pretty(&cat_key)?,
    )?;
    fs::write(
        dir.join("cat-key.public.jwk"),
        serde_json::to_string_pretty(&cat_key.to_public())?,
    )?;
    fs::write(
        dir.join("did.json"),
        serde_json::to_string_pretty(&did_doc)?,
    )?;
    fs::write(
        dir.join("credential.vc.json"),
        serde_json::to_string_pretty(&vc)?,
    )?;

    println!("📦 {} (TrustPlane/CAT)", name);
    println!("   Organization: {}", organization);
    println!("   DID: {}", did);
    println!("   Issuer kid: {}", issuer_kid);
    println!("   CAT kid: {}", cat_kid);

    Ok(TrustPlaneIdentity {
        did,
        issuer_key,
        issuer_kid,
        cat_key,
        cat_kid,
    })
}

/// Generate workload (executor) identity with VC and VP
pub async fn workload_gen(
    name: &str,
    domain: &str,
    identity: WorkloadIdentity,
    issuer: &TrustPlaneIdentity,
    challenge: Option<&str>,
) -> Result<Identity> {
    let dir = fixtures_dir().join(name);
    fs::create_dir_all(&dir)?;

    let mut signing_key = JWK::generate_ed25519().expect("failed to generate key");
    let did = format!("did:web:{}", domain);
    let signing_kid = key_id_with_date(&did, "key");
    signing_key.key_id = Some(signing_kid.clone());

    // DID Document
    let did_doc = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": &did,
        "verificationMethod": [{
            "id": &signing_kid,
            "type": "Ed25519VerificationKey2020",
            "controller": &did,
            "publicKeyJwk": serde_json::to_value(&signing_key.to_public())?
        }],
        "authentication": [&signing_kid],
        "assertionMethod": [&signing_kid]
    });

    // VC issued by TrustPlane
    let vc = create_pic_credential(
        &did,
        name,
        "Executor",
        &identity,
        &issuer.did,
        &issuer.issuer_kid,
        &issuer.issuer_key,
    )
    .await?;

    // VP signed by holder (this IS the PoP!)
    let vp = create_verifiable_presentation(
        &did,
        &signing_kid,
        &signing_key,
        &vc,
        challenge,
        Some(&issuer.did),
    )
    .await?;

    // Write files
    fs::write(
        dir.join("private.jwk"),
        serde_json::to_string_pretty(&signing_key)?,
    )?;
    fs::write(
        dir.join("public.jwk"),
        serde_json::to_string_pretty(&signing_key.to_public())?,
    )?;
    fs::write(
        dir.join("did.json"),
        serde_json::to_string_pretty(&did_doc)?,
    )?;
    fs::write(
        dir.join("credential.vc.json"),
        serde_json::to_string_pretty(&vc)?,
    )?;
    fs::write(
        dir.join("presentation.vp.json"),
        serde_json::to_string_pretty(&vp)?,
    )?;

    println!("📦 {} (Executor)", name);
    println!("   Organization: {}", identity.organization);
    println!("   DID: {}", did);
    println!("   Signing kid: {}", signing_kid);
    println!("   VC issuer: {}", issuer.issuer_kid);
    println!("   VP: presentation.vp.json (PoP implicit)");

    Ok(Identity {
        did,
        signing_key,
        signing_kid,
    })
}

/// Create PIC Executor Credential
async fn create_pic_credential(
    subject_did: &str,
    name: &str,
    role: &str,
    identity: &WorkloadIdentity,
    issuer_did: &str,
    issuer_kid: &str,
    issuer_key: &JWK,
) -> Result<serde_json::Value> {
    let now = Utc::now().to_rfc3339();
    let credential_id = format!("urn:uuid:{}", Uuid::new_v4());

    let vc_without_proof = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://pic-protocol.org/credentials/v1"
        ],
        "id": credential_id,
        "type": ["VerifiableCredential", "PICExecutorCredential"],
        "issuer": issuer_did,
        "issuanceDate": &now,
        "credentialSubject": {
            "id": subject_did,
            "name": name,
            "role": role,
            "organization": &identity.organization,
            "workloadIdentity": workload_identity_to_json(identity)
        }
    });

    // Sign
    let payload = serde_json::to_vec(&vc_without_proof)?;
    let jws = payload.sign(issuer_key).await?;

    let mut vc = vc_without_proof;
    vc["proof"] = serde_json::json!({
        "type": "Ed25519Signature2020",
        "created": &now,
        "verificationMethod": issuer_kid,
        "proofPurpose": "assertionMethod",
        "jws": jws.as_str()
    });

    Ok(vc)
}

/// Create a Verifiable Presentation wrapping a VC.
///
/// The VP signature by the holder IS the Proof of Possession:
/// - VC says: "this DID has these properties" (signed by issuer)
/// - VP says: "I control this DID" (signed by holder)
///
/// In PIC context, this VP can be used as ExecutorAttestation with type "vp"
/// without needing a separate PoP field.
async fn create_verifiable_presentation(
    holder_did: &str,
    holder_kid: &str,
    holder_key: &JWK,
    verifiable_credential: &serde_json::Value,
    challenge: Option<&str>,
    domain: Option<&str>,
) -> Result<serde_json::Value> {
    let now = Utc::now().to_rfc3339();
    let presentation_id = format!("urn:uuid:{}", Uuid::new_v4());

    let vp_without_proof = serde_json::json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://pic-protocol.org/credentials/v1"
        ],
        "id": presentation_id,
        "type": ["VerifiablePresentation"],
        "holder": holder_did,
        "verifiableCredential": [verifiable_credential]
    });

    // Build proof with optional challenge/domain for freshness binding
    let mut proof = serde_json::json!({
        "type": "Ed25519Signature2020",
        "created": &now,
        "verificationMethod": holder_kid,
        "proofPurpose": "authentication"
    });

    // Challenge binds VP to a specific request (e.g., PCC nonce)
    if let Some(c) = challenge {
        proof["challenge"] = serde_json::Value::String(c.to_string());
    }

    // Domain binds VP to a specific verifier (CAT)
    if let Some(d) = domain {
        proof["domain"] = serde_json::Value::String(d.to_string());
    }

    // Sign the VP (this IS the PoP - holder proves control of private key)
    let payload = serde_json::to_vec(&vp_without_proof)?;
    let jws = payload.sign(holder_key).await?;

    let mut vp = vp_without_proof;
    proof["jws"] = serde_json::Value::String(jws.to_string());
    vp["proof"] = proof;

    Ok(vp)
}

// Example usage
#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Generating PIC test identities...\n");

    // Generate TrustPlanes
    let nomad_tp = trustplane_gen(
        "nomad-trustplane",
        "trustplane.nomad.example.com",
        "Nomad Ltd",
    )
    .await?;

    println!();

    let sovereign_tp = trustplane_gen(
        "sovereign-trustplane",
        "trustplane.sovereign.example.com",
        "Sovereign Ltd",
    )
    .await?;

    println!();

    // Generate Nomad workloads
    let _nomad_gateway = workload_gen(
        "nomad-gateway",
        "gateway.nomad.example.com",
        WorkloadIdentity {
            organization: "Nomad Ltd".to_string(),
            identity_type: WorkloadIdentityType::Kubernetes {
                namespace: "production".to_string(),
                service_account: "gateway-sa".to_string(),
            },
        },
        &nomad_tp,
        Some("pcc-nonce-12345"),
    )
    .await?;

    println!();

    let _nomad_storage = workload_gen(
        "nomad-storage",
        "storage.nomad.example.com",
        WorkloadIdentity {
            organization: "Nomad Ltd".to_string(),
            identity_type: WorkloadIdentityType::Kubernetes {
                namespace: "production".to_string(),
                service_account: "storage-sa".to_string(),
            },
        },
        &nomad_tp,
        Some("pcc-nonce-67890"),
    )
    .await?;

    println!();

    // Generate Sovereign workloads
    let _sovereign_api = workload_gen(
        "sovereign-api",
        "api.sovereign.example.com",
        WorkloadIdentity {
            organization: "Sovereign Ltd".to_string(),
            identity_type: WorkloadIdentityType::Spiffe {
                spiffe_id: "spiffe://sovereign.example.com/ns/prod/sa/api".to_string(),
            },
        },
        &sovereign_tp,
        Some("pcc-nonce-abcdef"),
    )
    .await?;

    println!();

    let _sovereign_processor = workload_gen(
        "sovereign-processor",
        "processor.sovereign.example.com",
        WorkloadIdentity {
            organization: "Sovereign Ltd".to_string(),
            identity_type: WorkloadIdentityType::Spiffe {
                spiffe_id: "spiffe://sovereign.example.com/ns/prod/sa/processor".to_string(),
            },
        },
        &sovereign_tp,
        Some("pcc-nonce-ghijkl"),
    )
    .await?;

    println!("\n✅ All identities generated successfully!");
    println!("\nGenerated files in fixtures/workload-credentials-test-keys/:");
    println!("  nomad-trustplane/");
    println!("  nomad-gateway/");
    println!("  nomad-storage/");
    println!("  sovereign-trustplane/");
    println!("  sovereign-api/");
    println!("  sovereign-processor/");

    Ok(())
}
