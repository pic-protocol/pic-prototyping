// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Rigorous Criterion benchmarks for the PIC v0.2 Rust prototype, mirroring the
//! Go `pic/bench_test.go` (and `scenario/bench_test.go` for authority-mixing):
//! mint PCA0, prove hop, verify hop, digest, verify full chain (64 hops), verify
//! from snapshot (64, tail 8), and the authority-mixing scenario.
//!
//! Inputs are built once outside the timed loop; `black_box` guards inputs and
//! results so nothing is optimized away.

use chrono::{DateTime, Duration, Utc};
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pic::scenario::World;
use pic::{
    issue_snapshot, mint_pca0, sign_attestation, Attestation, ContractAttributes,
    ExecutionContract, Identity, Invariants, Pca, Prover, Registry, Request, Verifier,
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

/// Builds a valid lineage of `hops`+1 PCAs, its registry, and a registered
/// snapshot-issuer identity (mirrors the Go `buildChain` test helper).
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

fn bench_mint_pca0(c: &mut Criterion) {
    let now = Utc::now();
    let alice = Identity::new("did:example:alice");
    let inv = test_invariants();
    c.bench_function("mint_pca0", |b| {
        b.iter(|| black_box(mint_pca0(black_box(&alice), inv.clone(), "", now)));
    });
}

fn bench_prove_hop(c: &mut Criterion) {
    let now = Utc::now();
    let mut reg = Registry::new();
    let alice = Identity::new("did:example:alice");
    let org = Identity::new("did:example:org");
    reg.add(&alice);
    reg.add(&org);
    let pca0 = mint_pca0(&alice, test_invariants(), "", now);
    let (ex, att) = new_executor(&mut reg, &org, "did:example:hop", now);
    let prover = Prover::new(&ex, att);
    let req = Request {
        operation: "read".to_string(),
        target: "/user/file".to_string(),
        security_domain: "t".to_string(),
        ..Default::default()
    };
    c.bench_function("prove_hop", |b| {
        b.iter(|| {
            black_box(
                prover
                    .continue_(black_box(&pca0), test_invariants(), req.clone(), now)
                    .expect("continue"),
            )
        });
    });
}

fn bench_verify_hop(c: &mut Criterion) {
    let now = Utc::now();
    let (reg, chain, _) = build_chain(1, now);
    c.bench_function("verify_hop", |b| {
        b.iter(|| {
            black_box(
                Verifier::new(&reg, None)
                    .verify_hop(black_box(&chain[1]), black_box(&chain[0]), now, false)
                    .expect("verify_hop"),
            )
        });
    });
}

fn bench_digest(c: &mut Criterion) {
    let now = Utc::now();
    let (_, chain, _) = build_chain(1, now);
    let pca = &chain[1];
    c.bench_function("digest", |b| {
        b.iter(|| black_box(black_box(pca).digest()));
    });
}

fn bench_verify_full_chain_64(c: &mut Criterion) {
    let now = Utc::now();
    let (reg, chain, _) = build_chain(64, now);
    c.bench_function("verify_full_chain_64", |b| {
        b.iter(|| {
            black_box(
                Verifier::new(&reg, None)
                    .verify_full_chain(black_box(&chain), now)
                    .expect("verify_full_chain"),
            )
        });
    });
}

fn bench_verify_from_snapshot_64_tail8(c: &mut Criterion) {
    let now = Utc::now();
    let (reg, chain, snap_issuer) = build_chain(64, now);
    let through_index = chain.len() - 1 - 8;
    let snap = issue_snapshot(&snap_issuer, &reg, &chain, through_index, now).expect("snapshot");
    let tail = &chain[through_index..];
    c.bench_function("verify_from_snapshot_64_tail8", |b| {
        b.iter(|| {
            black_box(
                Verifier::new(&reg, None)
                    .verify_from_snapshot(black_box(&snap), black_box(tail), now)
                    .expect("verify_from_snapshot"),
            )
        });
    });
}

fn bench_authority_mixing(c: &mut Criterion) {
    let now = Utc::now();
    let w = World::new().expect("fixtures load");
    c.bench_function("authority_mixing", |b| {
        b.iter(|| black_box(w.authority_mixing(now).expect("authority_mixing")));
    });
}

criterion_group!(
    benches,
    bench_mint_pca0,
    bench_prove_hop,
    bench_verify_hop,
    bench_digest,
    bench_verify_full_chain_64,
    bench_verify_from_snapshot_64_tail8,
    bench_authority_mixing
);
criterion_main!(benches);
