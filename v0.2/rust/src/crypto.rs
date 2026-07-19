// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Ed25519 keys, the key registry, canonical JSON, and SHA-256 digests.

use crate::{PicResult, DIGEST_PREFIX};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Encodes bytes as URL-safe base64 without padding (the profile's encoding).
pub fn b64_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Decodes a URL-safe base64 (no padding) string.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(s)
}

/// An executor, issuer, or principal: an Ed25519 key pair addressed by an
/// identifier (a DID in the examples) and a verification method.
pub struct Identity {
    pub id: String,
    pub verification_method: String,
    signing: SigningKey,
}

impl Identity {
    /// Generates a fresh Ed25519 identity. The verification method is the
    /// identifier with a `#key-1` fragment, matching the spec examples.
    pub fn new(id: &str) -> Identity {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Identity {
            id: id.to_string(),
            verification_method: format!("{id}#key-1"),
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Builds an Identity from an existing Ed25519 seed (32 bytes), for loading
    /// deterministic identities from fixtures. An empty verification method
    /// defaults to `id + "#key-1"`.
    pub fn load(id: &str, verification_method: &str, seed: &[u8]) -> PicResult<Identity> {
        if seed.len() != 32 {
            return Err(format!("seed must be 32 bytes, got {}", seed.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed);
        let vm = if verification_method.is_empty() {
            format!("{id}#key-1")
        } else {
            verification_method.to_string()
        };
        Ok(Identity {
            id: id.to_string(),
            verification_method: vm,
            signing: SigningKey::from_bytes(&arr),
        })
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// A detached signature over `msg` (base64url, no padding).
    pub fn sign(&self, msg: &[u8]) -> String {
        b64_encode(&self.signing.sign(msg).to_bytes())
    }

    /// The base64url of the raw public key (the JWK "x" parameter).
    pub fn encode_public(&self) -> String {
        b64_encode(&self.public_bytes())
    }

    /// The base64url of the 32-byte Ed25519 seed (the JWK "d" parameter). For
    /// fixtures/testing only.
    pub fn seed(&self) -> String {
        b64_encode(&self.signing.to_bytes())
    }
}

/// Resolves a verification method (or bare issuer id) to a public key. It stands
/// in for a DID resolver / key distribution mechanism.
#[derive(Default)]
pub struct Registry {
    keys: HashMap<String, VerifyingKey>,
}

impl Registry {
    pub fn new() -> Registry {
        Registry {
            keys: HashMap::new(),
        }
    }

    /// Registers an identity under both its verification method and its id, so a
    /// Verifier can resolve either form.
    pub fn add(&mut self, id: &Identity) {
        let vk = id.signing.verifying_key();
        self.keys.insert(id.verification_method.clone(), vk);
        self.keys.insert(id.id.clone(), vk);
    }

    /// Checks `sig` (base64url) over `msg` for the key registered under `reference`.
    pub fn verify(&self, reference: &str, msg: &[u8], sig: &str) -> PicResult<()> {
        let vk = self
            .keys
            .get(reference)
            .ok_or_else(|| format!("unknown verification method {reference:?}"))?;
        let raw = b64_decode(sig).map_err(|e| format!("malformed signature: {e}"))?;
        let bytes: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "malformed signature: wrong length".to_string())?;
        let signature = Signature::from_bytes(&bytes);
        vk.verify(msg, &signature)
            .map_err(|_| format!("signature does not verify under {reference:?}"))
    }
}

/// Returns a deterministic JSON encoding of `v`: object keys sorted
/// lexicographically, no insignificant whitespace. This is the reproducible byte
/// representation a hash or signature covers (spec §6.4).
///
/// `serde_json::Value` maps are `BTreeMap` (sorted) when `preserve_order` is off,
/// so `to_value` then `to_vec` yields sorted-keys compact bytes — matching Go's
/// canonicalization for our (ASCII, no `<>&`) data.
pub fn canonical_json<T: Serialize>(v: &T) -> Vec<u8> {
    let value = serde_json::to_value(v).expect("canonical to_value");
    serde_json::to_vec(&value).expect("canonical to_vec")
}

/// Returns "sha256:<hex>" over the canonical encoding of `v`.
pub fn digest_of<T: Serialize>(v: &T) -> String {
    let b = canonical_json(v);
    let mut h = Sha256::new();
    h.update(&b);
    format!("{DIGEST_PREFIX}{}", hex_lower(&h.finalize()))
}

/// Returns "sha256:<hex>" over the concatenation of the given byte parts. Used
/// for lineageId and branchId derivation (Revocation spec).
pub fn hash_parts(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    format!("{DIGEST_PREFIX}{}", hex_lower(&h.finalize()))
}

/// Lowercase hex encoding, matching Go's `hexEncode`.
pub fn hex_lower(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &c in b {
        out.push(HEX[(c >> 4) as usize] as char);
        out.push(HEX[(c & 0x0f) as usize] as char);
    }
    out
}

/// Returns `n` random bytes encoded as base64url (challenges, nonces).
pub fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    b64_encode(&buf)
}
