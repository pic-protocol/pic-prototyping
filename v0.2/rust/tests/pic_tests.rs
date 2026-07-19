// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Ported adversarial tests for the `pic` library: non-expansion rejected, tamper
//! detected, predecessor binding, single-use replay, snapshot matches full-chain,
//! revocation LINEAGE-SUFFIX cutoff, plus the canonical-JSON interop contract.

use chrono::{DateTime, Duration, Utc};
use pic::{
    canonical_json, derive_lineage_id, issue_snapshot, mint_pca0, root_branch_id, sign_attestation,
    wrap_envelope, Attestation, ContractAttributes, ExecutionContract, Identity, Invariants, Pca,
    Prover, Registry, Request, RevocationStore, Verifier,
};

fn test_invariants() -> Invariants {
    Invariants {
        operations: vec!["read:/user/*".to_string(), "write:/user/*".to_string()],
        execution_contract: ExecutionContract {
            compliance: vec!["GDPR".to_string()],
            execution_model: "deterministic".to_string(),
            ..Default::default()
        },
    }
}

fn new_executor(
    reg: &mut Registry,
    org: &Identity,
    id: &str,
    now: DateTime<Utc>,
) -> (Identity, Attestation) {
    let ex = Identity::new(id);
    reg.add(&ex);
    let att = sign_attestation(
        Attestation {
            subject: ex.id.clone(),
            attributes: ContractAttributes {
                compliance: vec!["GDPR".to_string()],
                execution_model: "deterministic".to_string(),
                ..Default::default()
            },
            issued_at: pic::rfc3339(now - Duration::hours(1)),
            expires_at: pic::rfc3339(now + Duration::hours(24)),
            ..Default::default()
        },
        org,
    );
    (ex, att)
}

/// Returns a valid lineage of hops+1 PCAs, its registry, and a registered
/// snapshot-issuer identity.
fn build_chain(hops: usize, now: DateTime<Utc>) -> (Registry, Vec<Pca>, Identity) {
    let mut reg = Registry::new();
    let alice = Identity::new("did:example:alice");
    let org = Identity::new("did:example:org");
    let snap = Identity::new("did:example:snapshot");
    reg.add(&alice);
    reg.add(&org);
    reg.add(&snap);

    let pca0 = mint_pca0(&alice, test_invariants(), "", now);
    let mut chain = vec![pca0];
    let req = Request {
        operation: "read".to_string(),
        target: "/user/file".to_string(),
        security_domain: "tenant-1".to_string(),
        ..Default::default()
    };
    for i in 0..hops {
        let (ex, att) = new_executor(&mut reg, &org, &format!("did:example:hop-{i}"), now);
        let pred = chain.last().unwrap().clone();
        let p = Prover::new(&ex, att)
            .continue_(&pred, test_invariants(), req.clone(), now)
            .expect("continue");
        chain.push(p);
    }
    (reg, chain, snap)
}

#[test]
fn origin_and_hop_valid() {
    let now = Utc::now();
    let (reg, chain, _) = build_chain(3, now);
    let inv = Verifier::new(&reg, None)
        .verify_full_chain(&chain, now)
        .expect("valid chain rejected");
    assert_eq!(
        inv.operations.len(),
        2,
        "tip authority should be 2 operations"
    );
}

#[test]
fn lineage_derivation() {
    let now = Utc::now();
    let (_, chain, _) = build_chain(0, now);
    let pca0 = &chain[0];
    let want = derive_lineage_id(pca0);
    assert_eq!(pca0.lineage_id, want, "lineageId mismatch");
    assert_eq!(
        pca0.branch_id,
        root_branch_id(&pca0.lineage_id),
        "branchId is not the derived root branch id"
    );
    assert!(pca0.lineage_id.starts_with("sha256:"));
}

#[test]
fn non_expansion_rejected() {
    let now = Utc::now();
    let mut reg = Registry::new();
    let alice = Identity::new("did:example:alice");
    let org = Identity::new("did:example:org");
    reg.add(&alice);
    reg.add(&org);
    let pca0 = mint_pca0(&alice, test_invariants(), "", now);
    let (bob, att) = new_executor(&mut reg, &org, "did:example:bob", now);

    let expanded = Invariants {
        operations: vec!["read:/user/*".to_string(), "read:/sys/*".to_string()],
        execution_contract: test_invariants().execution_contract,
    };
    let req = Request {
        operation: "read".to_string(),
        target: "/sys/secret".to_string(),
        security_domain: "sys".to_string(),
        ..Default::default()
    };

    // Honest prover refuses to build it.
    assert!(
        Prover::new(&bob, att.clone())
            .continue_(&pca0, expanded.clone(), req.clone(), now)
            .is_err(),
        "honest prover built an expansive successor"
    );
    // A malicious prover can build it, but the Verifier rejects it.
    let mal = Prover::new(&bob, att)
        .continue_malicious(&pca0, expanded, req, now)
        .expect("malicious build");
    assert!(
        Verifier::new(&reg, None)
            .verify_hop(&mal, &pca0, now, false)
            .is_err(),
        "verifier accepted an expansive successor"
    );
}

#[test]
fn tamper_detected() {
    let now = Utc::now();
    let (reg, mut chain, _) = build_chain(1, now);
    // Tamper with the signed invariants after the fact.
    chain[1].invariants.operations = vec![
        "read:/user/*".to_string(),
        "write:/user/*".to_string(),
        "read:/sys/*".to_string(),
    ];
    let pred = chain[0].clone();
    assert!(
        Verifier::new(&reg, None)
            .verify_hop(&chain[1], &pred, now, false)
            .is_err(),
        "tampered PCA passed integrity check"
    );
}

#[test]
fn predecessor_binding() {
    let now = Utc::now();
    let (reg, chain, _) = build_chain(2, now);
    // Validate hop 2 against the wrong predecessor (PCA0 instead of PCA1).
    assert!(
        Verifier::new(&reg, None)
            .verify_hop(&chain[2], &chain[0], now, false)
            .is_err(),
        "hop validated against the wrong predecessor"
    );
}

#[test]
fn snapshot_matches_full_chain() {
    let now = Utc::now();
    let (reg, chain, snap_issuer) = build_chain(16, now);

    let full_inv = Verifier::new(&reg, None)
        .verify_full_chain(&chain, now)
        .expect("full chain");
    let through_index = chain.len() - 1 - 4;
    let snap =
        issue_snapshot(&snap_issuer, &reg, &chain, through_index, now).expect("IssueSnapshot");
    let snap_inv = Verifier::new(&reg, None)
        .verify_from_snapshot(&snap, &chain[through_index..], now)
        .expect("VerifyFromSnapshot");
    assert_eq!(
        snap_inv.operations.len(),
        full_inv.operations.len(),
        "snapshot tip authority differs from full-chain"
    );
}

#[test]
fn snapshot_refuses_invalid_chain() {
    let now = Utc::now();
    let (reg, mut chain, snap_issuer) = build_chain(4, now);
    chain[2]
        .invariants
        .operations
        .push("read:/sys/*".to_string()); // break it
    assert!(
        issue_snapshot(&snap_issuer, &reg, &chain, 3, now).is_err(),
        "snapshot issued over an invalid chain"
    );
}

#[test]
fn revocation_lineage_suffix() {
    let now = Utc::now();
    let (reg, chain, _) = build_chain(6, now);
    let lineage_id = chain[0].lineage_id.clone();

    let mut store = RevocationStore::new();
    store.lineage_suffix(&lineage_id, 4, "did:example:alice");

    for p in &chain {
        let err = store.check(p);
        if p.lineage_counter >= 4 {
            assert!(
                err.is_err(),
                "counter {} should be revoked",
                p.lineage_counter
            );
        } else {
            assert!(err.is_ok(), "counter {} should be valid", p.lineage_counter);
        }
    }
    assert!(
        Verifier::new(&reg, Some(&store))
            .verify_full_chain(&chain, now)
            .is_err(),
        "revoked chain accepted"
    );
}

#[test]
fn challenge_single_use() {
    let now = Utc::now();
    let (mut reg, chain, _) = build_chain(1, now);
    let forwarder = Identity::new("did:example:forwarder");
    reg.add(&forwarder);
    let env = wrap_envelope(&forwarder, &chain[0], &chain[1]);
    let mut v = Verifier::new(&reg, None);
    assert!(
        v.verify_envelope(&env, now).is_ok(),
        "first acceptance failed"
    );
    assert!(
        v.verify_envelope(&env, now).is_err(),
        "single-use challenge accepted twice (replay)"
    );
}

/// The interop contract: the canonical (signed) bytes of the archive-service
/// attestation MUST equal the exact expected string, byte for byte.
#[test]
fn canonical_json_interop_contract() {
    let att = Attestation {
        subject: "did:web:archive.example".to_string(),
        attributes: ContractAttributes {
            role: "archive-service".to_string(),
            compliance: vec!["GDPR".to_string()],
            execution_model: "deterministic".to_string(),
            environment: "production".to_string(),
            region: "eu-1".to_string(),
        },
        issued_at: "2026-01-01T00:00:00Z".to_string(),
        expires_at: "2035-01-01T00:00:00Z".to_string(),
        issuer: "did:web:org-authority.example".to_string(),
        proof: None,
    };
    let expected = r#"{"attributes":{"compliance":["GDPR"],"environment":"production","executionModel":"deterministic","region":"eu-1","role":"archive-service"},"expiresAt":"2035-01-01T00:00:00Z","issuedAt":"2026-01-01T00:00:00Z","issuer":"did:web:org-authority.example","subject":"did:web:archive.example"}"#;
    assert_eq!(String::from_utf8(canonical_json(&att)).unwrap(), expected);
    // signing_bytes (proof excluded) must match too.
    assert_eq!(String::from_utf8(att.signing_bytes()).unwrap(), expected);
}
