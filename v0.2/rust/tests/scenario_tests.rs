// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Ported scenario tests running on the real shared fixtures: authority-mixing
//! composition rejected, confused-deputy cases, and chain building.

use chrono::Utc;
use pic::scenario::World;
use pic::Verifier;

#[test]
fn authority_mixing_rejects_composition() {
    let now = Utc::now();
    let w = World::new().expect("world");
    let res = w.authority_mixing(now).expect("authority_mixing");
    assert!(
        res.honest_accepted,
        "honest continuation of the summary lineage rejected: {:?}",
        res.honest_err
    );
    assert!(
        !res.composed,
        "cross-lineage composition {{read-all, share-files}} was accepted"
    );
    assert_eq!(
        res.lineage_backup_authority,
        vec!["read-all".to_string()],
        "backup lineage authority mismatch"
    );
}

#[test]
fn case1_legit_allowed() {
    let now = Utc::now();
    let w = World::new().expect("world");
    let (_, _, res) = w.case1_legit(now).expect("case1");
    assert!(
        res.verified && res.authorized,
        "legitimate system transaction not allowed"
    );
}

#[test]
fn case2_honest_blocked() {
    let now = Utc::now();
    let w = World::new().expect("world");
    let (_, _, res) = w.case2_honest(now).expect("case2 honest");
    assert!(
        res.verified,
        "honest forward should verify: {:?}",
        res.verify_err
    );
    assert!(!res.authorized, "confused-deputy read was authorized");
}

#[test]
fn case2_malicious_rejected() {
    let now = Utc::now();
    let w = World::new().expect("world");
    let (_, _, res) = w.case2_malicious(now).expect("case2 malicious");
    assert!(!res.verified, "expansive injection was accepted");
}

#[test]
fn build_chain_verifies() {
    let now = Utc::now();
    let w = World::new().expect("world");
    let chain = w.build_chain(10, now).expect("build_chain");
    assert!(
        Verifier::new(&w.set.registry, None)
            .verify_full_chain(&chain, now)
            .is_ok(),
        "built chain does not verify"
    );
    assert_eq!(chain.len(), 11, "chain length should be 11");
}
