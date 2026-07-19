// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Loads the shared `v0.2/fixtures` (DID identities and signed attestations) once
//! and caches them, so scenarios and benchmarks pay no per-use disk cost.

use crate::crypto::{b64_decode, Identity, Registry};
use crate::guardrail::{Policy, ScopeBindings};
use crate::types::Attestation;
use crate::PicResult;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The loaded, cached fixture cast: a key registry with every identity, the
/// identities by actor name, the signed executor attestations by name, and the
/// Execution Guardrail fixtures (policy and semantic-scope bindings).
pub struct Set {
    pub registry: Registry,
    pub identities: HashMap<String, Identity>,
    pub attestations: HashMap<String, Attestation>,
    pub policy: Policy,
    pub scopes: ScopeBindings,
}

impl Set {
    /// Returns the loaded identity for an actor name, or panics if absent (a
    /// missing fixture is a programming error in the demo, not runtime input).
    pub fn identity(&self, name: &str) -> &Identity {
        self.identities
            .get(name)
            .unwrap_or_else(|| panic!("fixtureset: unknown identity {name}"))
    }

    /// Returns the loaded signed attestation for an executor name.
    pub fn attestation(&self, name: &str) -> Attestation {
        self.attestations
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("fixtureset: unknown attestation {name}"))
    }
}

#[derive(Deserialize)]
struct Jwk {
    #[serde(default)]
    kid: String,
    #[serde(default)]
    d: String,
}

/// Reads the fixtures once and returns the cached set on every later call.
pub fn load() -> PicResult<&'static Set> {
    static CACHE: OnceLock<Result<Set, String>> = OnceLock::new();
    match CACHE.get_or_init(|| load_from(&fixtures_dir())) {
        Ok(s) => Ok(s),
        Err(e) => Err(e.clone()),
    }
}

fn load_from(dir: &Path) -> Result<Set, String> {
    let mut set = Set {
        registry: Registry::new(),
        identities: HashMap::new(),
        attestations: HashMap::new(),
        policy: Policy::default(),
        scopes: ScopeBindings::new(),
    };

    let id_root = dir.join("identities");
    let entries = fs::read_dir(&id_root).map_err(|e| format!("read identities: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read identities: {e}"))?;
        if !entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = id_root.join(&name).join("private.jwk");
        let raw = fs::read(&path).map_err(|e| format!("{name}: {e}"))?;
        let k: Jwk =
            serde_json::from_slice(&raw).map_err(|e| format!("{name} private.jwk: {e}"))?;
        let seed = b64_decode(&k.d).map_err(|e| format!("{name} seed: {e}"))?;
        let did = match k.kid.split_once('#') {
            Some((before, _)) => before.to_string(),
            None => k.kid.clone(),
        };
        let id = Identity::load(&did, &k.kid, &seed).map_err(|e| format!("{name}: {e}"))?;
        set.registry.add(&id);
        set.identities.insert(name, id);
    }

    let att_root = dir.join("attestations");
    let entries = fs::read_dir(&att_root).map_err(|e| format!("read attestations: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read attestations: {e}"))?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() || !file_name.ends_with(".json") {
            continue;
        }
        let raw = fs::read(entry.path()).map_err(|e| format!("{file_name}: {e}"))?;
        let att: Attestation =
            serde_json::from_slice(&raw).map_err(|e| format!("{file_name}: {e}"))?;
        let key = file_name.trim_end_matches(".json").to_string();
        set.attestations.insert(key, att);
    }

    // Execution Guardrail fixtures: the policy and the scope bindings.
    let praw = fs::read(dir.join("guardrail").join("policy.json"))
        .map_err(|e| format!("read guardrail policy: {e}"))?;
    set.policy =
        serde_json::from_slice(&praw).map_err(|e| format!("guardrail policy.json: {e}"))?;
    let sraw = fs::read(dir.join("guardrail").join("scopes.json"))
        .map_err(|e| format!("read guardrail scopes: {e}"))?;
    #[derive(Deserialize)]
    struct ScopesFile {
        bindings: ScopeBindings,
    }
    let sf: ScopesFile =
        serde_json::from_slice(&sraw).map_err(|e| format!("guardrail scopes.json: {e}"))?;
    set.scopes = sf.bindings;
    Ok(set)
}

/// Resolves `v0.2/fixtures` relative to the crate manifest, so loading works from
/// any working directory. `CARGO_MANIFEST_DIR` is `<repo>/v0.2/rust`.
fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("fixtures")
}
