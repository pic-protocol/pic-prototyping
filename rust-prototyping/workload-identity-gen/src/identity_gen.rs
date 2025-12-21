use anyhow::Result;
use ssi::jwk::JWK;
use ssi::dids::DIDJWK;
use ssi::claims::jws::JwsPayload;
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

pub enum DidMethod { Key, Web }
pub enum Role { TrustAnchor, Executor }

#[derive(Clone)]
pub struct Identity {
    pub did: String,
    pub jwk: JWK,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()   // rust-prototyping/
        .unwrap()
        .parent()   // pic-prototyping/
        .unwrap()
        .join("fixtures")
        .join("workload-credentials-test-keys")
}

pub async fn identity_gen(
    name: &str,
    method: DidMethod,
    domain: Option<&str>,
    role: Role,
    issuer: Option<&Identity>,
) -> Result<Identity> {
    let dir = fixtures_dir().join(name);
    fs::create_dir_all(&dir)?;

    // Generate Ed25519 key using ssi
    let mut jwk = JWK::generate_ed25519().expect("failed to generate Ed25519 key");

    // Generate DID based on method  
    let did = match method {
        DidMethod::Key => {
            let did_url = DIDJWK::generate_url(&jwk.to_public());
            did_url.to_string()
        }
        DidMethod::Web => {
            format!("did:web:{}", domain.unwrap())
        }
    };

    // Set key ID on JWK
    jwk.key_id = Some(format!("{}#key-1", &did));

    // Create JSON representations
    let private_jwk = serde_json::to_value(&jwk)?;
    let public_jwk = serde_json::to_value(&jwk.to_public())?;

    // Create DID Document
    let did_doc = serde_json::json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
        ],
        "id": &did,
        "verificationMethod": [{
            "id": format!("{}#key-1", &did),
            "type": "Ed25519VerificationKey2020",
            "controller": &did,
            "publicKeyJwk": &public_jwk
        }],
        "authentication": [format!("{}#key-1", &did)],
        "assertionMethod": [format!("{}#key-1", &did)]
    });

    // Determine issuer
    let issuer_did = issuer.as_ref().map(|i| i.did.clone()).unwrap_or(did.clone());
    let issuer_jwk = issuer.as_ref().map(|i| &i.jwk).unwrap_or(&jwk);

    let role_str = match role {
        Role::TrustAnchor => "TrustAnchor",
        Role::Executor => "Executor",
    };

    // Create VC
    let now = chrono::Utc::now().to_rfc3339();
    let credential_id = format!("urn:uuid:{}", Uuid::new_v4());

    let vc_without_proof = serde_json::json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "id": credential_id,
        "type": ["VerifiableCredential", "PICWorkloadCredential"],
        "issuer": &issuer_did,
        "issuanceDate": &now,
        "credentialSubject": {
            "id": &did,
            "name": name,
            "role": role_str
        }
    });

    // Sign VC using ssi JWS
    let proof = sign_with_ssi(&vc_without_proof, &issuer_did, issuer_jwk).await?;
    
    let mut vc = vc_without_proof.clone();
    vc["proof"] = proof;

    // Write files
    fs::write(dir.join("private.jwk"), serde_json::to_string_pretty(&private_jwk)?)?;
    fs::write(dir.join("public.jwk"), serde_json::to_string_pretty(&public_jwk)?)?;
    fs::write(dir.join("did.json"), serde_json::to_string_pretty(&did_doc)?)?;
    fs::write(dir.join("credential.vc.json"), serde_json::to_string_pretty(&vc)?)?;

    println!("📦 {} → {}", name, did);
    Ok(Identity { did, jwk })
}

async fn sign_with_ssi(
    document: &serde_json::Value,
    issuer_did: &str,
    jwk: &JWK,
) -> Result<serde_json::Value> {
    let payload = serde_json::to_vec(document)?;
    let jws = payload.sign(jwk).await?;
    let now = chrono::Utc::now().to_rfc3339();

    Ok(serde_json::json!({
        "type": "Ed25519Signature2020",
        "created": now,
        "verificationMethod": format!("{}#key-1", issuer_did),
        "proofPurpose": "assertionMethod",
        "jws": jws.as_str()
    }))
}