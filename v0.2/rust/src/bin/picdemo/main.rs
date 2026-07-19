// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Command picdemo runs the PIC v0.2 Rust prototype scenarios and prints timings.
//!
//!   cargo run --bin picdemo -- [why-pic|confused-deputy|snapshot|revocation|flow|dump|bench|all]
//!
//! It uses the real v0.2 fixtures loaded once into memory. It is non-normative
//! demonstration code; the PIC Specification is authoritative.

mod bench;
mod flow;

use chrono::{DateTime, Utc};
use pic::authority::go_slice;
use pic::scenario::World;
use pic::{issue_snapshot, wrap_envelope, Envelope, Pca, Verifier};
use serde::Serialize;
use std::io::IsTerminal;
use std::process::exit;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let which = args.get(1).cloned().unwrap_or_else(|| "all".to_string());
    let now = Utc::now();

    let order = ["why-pic", "confused-deputy", "snapshot", "revocation"];

    if which == "dump" || which == "flow" || which == "bench" {
        let only_json = args[2..]
            .iter()
            .any(|a| a == "--only-json" || a == "--json" || a == "-j");
        let res = match which.as_str() {
            "flow" => flow::run_flow(now, only_json),
            "bench" => bench::run_bench(now, only_json),
            _ => run_dump(now, only_json),
        };
        if let Err(e) = res {
            eprintln!("error: {e}");
            exit(1);
        }
        return;
    }

    let run: Vec<&str> = if which == "all" {
        order.to_vec()
    } else if order.contains(&which.as_str()) {
        vec![match which.as_str() {
            "why-pic" => "why-pic",
            "confused-deputy" => "confused-deputy",
            "snapshot" => "snapshot",
            "revocation" => "revocation",
            _ => unreachable!(),
        }]
    } else {
        eprintln!("unknown scenario {which:?} (use: {order:?}, flow, bench, dump, or all)");
        exit(2);
    };

    for name in run {
        let res = match name {
            "why-pic" => run_authority_mixing(now),
            "confused-deputy" => run_confused_deputy(now),
            "snapshot" => run_snapshot(now),
            "revocation" => run_revocation(now),
            _ => unreachable!(),
        };
        if let Err(e) = res {
            eprintln!("error: {e}");
            exit(1);
        }
    }
}

pub(crate) fn header(title: &str) {
    println!("\n=== {title} ===");
}

// --- ANSI color helpers (shared with flow.rs / bench.rs) --------------------

pub(crate) fn use_color() -> bool {
    std::io::stdout().is_terminal()
}

pub(crate) fn paint(code: &str, s: &str) -> String {
    if !use_color() {
        s.to_string()
    } else {
        format!("\x1b[{code}m{s}\x1b[0m")
    }
}

pub(crate) const C_BOLD: &str = "1";
pub(crate) const C_DIM: &str = "2";
pub(crate) const C_RED: &str = "31";
pub(crate) const C_GREEN: &str = "32";
pub(crate) const C_YELLOW: &str = "33";
pub(crate) const C_CYAN: &str = "36";
pub(crate) const C_ACTOR: &str = "1;36"; // bold cyan
pub(crate) const C_REJECT: &str = "1;31"; // bold red

pub(crate) fn print_json<T: Serialize>(v: &T) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => println!("{s}"),
        Err(e) => println!("(marshal error: {e} )"),
    }
}

fn verdict(ok: bool, yes: &str, no: &str) -> String {
    if ok {
        yes.to_string()
    } else {
        no.to_string()
    }
}

fn reason(e: &Option<String>) -> String {
    e.clone().unwrap_or_else(|| "<nil>".to_string())
}

// --- dump -------------------------------------------------------------------

#[derive(Serialize)]
struct Artifact<'a, T: Serialize> {
    explanation: &'a str,
    value: &'a T,
}

#[derive(Serialize)]
struct DumpArtifacts<'a> {
    pca0: Artifact<'a, Pca>,
    pca1: Artifact<'a, Pca>,
    envelope: Artifact<'a, Envelope>,
}

#[derive(Serialize)]
struct TamperProof {
    explanation: String,
    #[serde(rename = "editedSignedField")]
    edited_signed_field: String,
    rejected: bool,
    reason: String,
}

#[derive(Serialize)]
struct DumpChecks {
    #[serde(rename = "pca0Digest")]
    pca0_digest: String,
    #[serde(rename = "previousPcaHashMatchesPca0Digest")]
    previous_pca_hash_matches_pca0_digest: bool,
    #[serde(rename = "verifyFullChainOk")]
    verify_full_chain_ok: bool,
    authority: Vec<String>,
    #[serde(rename = "tamperProof")]
    tamper_proof: TamperProof,
}

#[derive(Serialize)]
struct DumpOutput<'a> {
    description: String,
    artifacts: DumpArtifacts<'a>,
    checks: DumpChecks,
}

/// Builds real signed artifacts (PCA0, a successor PCA, and an envelope),
/// verifies them, and runs a live tamper proof: editing one signed field makes
/// verification fail because the Ed25519 signature really covers the content.
fn run_dump(now: DateTime<Utc>, only_json: bool) -> Result<(), String> {
    let w = World::new()?;
    let chain = w.build_chain(2, now)?;
    let pca0 = chain[0].clone();
    let pca1 = chain[1].clone();
    let d0 = pca0.digest();
    let env = wrap_envelope(w.set.identity("gateway"), &pca0, &pca1);
    let (inv, verify_err) =
        match Verifier::new(&w.set.registry, None).verify_full_chain(&chain[..2], now) {
            Ok(inv) => (inv.operations, None),
            Err(e) => (Vec::new(), Some(e)),
        };

    // Live tamper proof: edit one signed operation on a copy, re-verify.
    let mut tampered = pca1.clone();
    tampered
        .invariants
        .operations
        .insert(0, "read:/sys/*".to_string());
    let tamper_err = Verifier::new(&w.set.registry, None)
        .verify_hop(&tampered, &pca0, now, false)
        .err();

    if only_json {
        let out = DumpOutput {
            description: "Real PIC v0.2 signed artifacts (Ed25519 + SHA-256 hash chain), produced live on this run — nothing precomputed.".to_string(),
            artifacts: DumpArtifacts {
                pca0: Artifact {
                    explanation: "Origin PCA (PCA0): starts the lineage, signed by the origin principal (alice). It carries no Proof of Relationship and no predecessor hash; its invariants are the upper bound of authority for the whole lineage.",
                    value: &pca0,
                },
                pca1: Artifact {
                    explanation: "Successor PCA: continues exactly one predecessor. proofOfRelationship carries previousPcaHash (= PCA0 digest), the continuation-challenge response, the executor request binding, and the executor's signed attestation; a single Ed25519 signature covers the whole PCA.",
                    value: &pca1,
                },
                envelope: Artifact {
                    explanation: "Handoff envelope: carries [predecessor, current] together, signed by the forwarder. The digests are a convenience; a Verifier recomputes them from the PCA bytes.",
                    value: &env,
                },
            },
            checks: DumpChecks {
                pca0_digest: d0.clone(),
                previous_pca_hash_matches_pca0_digest: pca1
                    .proof_of_relationship
                    .as_ref()
                    .map(|p| p.previous_pca_hash == d0)
                    .unwrap_or(false),
                verify_full_chain_ok: verify_err.is_none(),
                authority: inv.clone(),
                tamper_proof: TamperProof {
                    explanation: "Editing one signed field (invariants.operations) and re-verifying: the Ed25519 signature no longer verifies, so the edit is rejected.".to_string(),
                    edited_signed_field: "invariants.operations".to_string(),
                    rejected: tamper_err.is_some(),
                    reason: tamper_err.clone().unwrap_or_default(),
                },
            },
        };
        print_json(&out);
        return Ok(());
    }

    header("Inspect real artifacts (dump)");
    println!("\n--- PCA0 (origin, signed by alice) ---");
    print_json(&pca0);
    println!("PCA0 digest (content id): {d0}");
    println!("\n--- PCA1 (successor: real PoR, previousPcaHash, executor attestation, single signature) ---");
    print_json(&pca1);
    println!(
        "PCA1.proofOfRelationship.previousPcaHash == PCA0 digest ? {}",
        pca1.proof_of_relationship
            .as_ref()
            .map(|p| p.previous_pca_hash == d0)
            .unwrap_or(false)
    );
    println!("\n--- Envelope [predecessor, current], signed by the forwarder ---");
    print_json(&env);
    println!(
        "\nVerifyFullChain([PCA0, PCA1]) -> ok={}, authority={}",
        verify_err.is_none(),
        go_slice(&inv)
    );
    println!(
        "after editing one signed operation -> rejected={}",
        tamper_err.is_some()
    );
    println!("reason: {}", reason(&tamper_err));
    Ok(())
}

// --- why-pic (authority mixing) ---------------------------------------------

fn run_authority_mixing(now: DateTime<Utc>) -> Result<(), String> {
    header("Authority Mixing / cross-lineage composition (Why PIC; spec §1.4)");
    let w = World::new()?;
    let res = w.authority_mixing(now)?;
    println!(
        "Lineage 2 (backup):  origin {{read-all, backup}}     -> attenuated to {}  [valid]",
        go_slice(&res.lineage_backup_authority)
    );
    println!(
        "Lineage 1 (summary): origin {{read-foo, share-files}} -> attenuated to {}  [valid]",
        go_slice(&res.lineage_summary_authority)
    );
    println!("\nShared executor continues the summary lineage:");
    println!(
        "  honest    keep {{share-files}}                 -> {}",
        verdict(res.honest_accepted, "ACCEPTED", "rejected")
    );
    println!(
        "  bug/mix   {{read-all (from Lineage 2), share-files}} -> {}",
        verdict(
            !res.composed,
            "REJECTED — mixed state is inexpressible",
            "accepted"
        )
    );
    println!("  reason: {}", reason(&res.compose_err));
    println!("\nread-all belongs to the backup lineage; it has no Proof of Relationship");
    println!("into the summary lineage, so PIC cannot represent the composed state.");
    Ok(())
}

// --- confused deputy --------------------------------------------------------

fn run_confused_deputy(now: DateTime<Utc>) -> Result<(), String> {
    header("Cross-Service Confused Deputy (Alice → Archive → Storage)");
    let w = World::new()?;
    let (_, req, res) = w.case1_legit(now)?;
    println!("Case 1  Archive's own transaction, read {}", req.target);
    println!(
        "        verified={}  authorized={}  -> {}",
        res.verified,
        res.authorized,
        verdict(res.authorized, "ALLOWED (legitimate)", "denied")
    );

    let (_, _, res) = w.case2_honest(now)?;
    println!(
        "\nCase 2a Alice's confused-deputy read of /sys/syslog.txt, Archive forwards honestly"
    );
    println!(
        "        verified={}  authorized={}  -> {}",
        res.verified,
        res.authorized,
        verdict(res.blocked(), "BLOCKED — authorization denied", "leaked")
    );
    println!("        reason: {}", reason(&res.auth_err));

    let (_, _, res) = w.case2_malicious(now)?;
    println!("\nCase 2b Compromised Archive injects read:/sys/* into Alice's lineage");
    println!(
        "        verified={}  -> {}",
        res.verified,
        verdict(
            !res.verified,
            "REJECTED — cannot be validated as a continuation",
            "accepted"
        )
    );
    println!("        reason: {}", reason(&res.verify_err));
    Ok(())
}

// --- snapshot ---------------------------------------------------------------

fn run_snapshot(now: DateTime<Utc>) -> Result<(), String> {
    header("Snapshot Hash Chain profile (Prover/Verifier spec §5.2)");
    const HOPS: usize = 128;
    const TAIL: usize = 8;
    const ITERS: u32 = 50;
    let w = World::new()?;
    let chain = w.build_chain(HOPS, now)?;
    let through_index = chain.len() - 1 - TAIL;
    let snap = issue_snapshot(
        w.set.identity("snapshot-issuer"),
        &w.set.registry,
        &chain,
        through_index,
        now,
    )?;
    let tail_chain = &chain[through_index..];

    let full = time_it(ITERS, || {
        Verifier::new(&w.set.registry, None)
            .verify_full_chain(&chain, now)
            .map(|_| ())
    });
    let from_snap = time_it(ITERS, || {
        Verifier::new(&w.set.registry, None)
            .verify_from_snapshot(&snap, tail_chain, now)
            .map(|_| ())
    });

    println!(
        "chain length: {} PCAs (PCA0 + {} hops, real fixture executors)",
        chain.len(),
        HOPS
    );
    println!(
        "full-chain verify   O(n)          : {:>10}   ({} hops walked)",
        fmt_dur(full),
        HOPS
    );
    println!("snapshot at PCA[{}], {} hops after it", through_index, TAIL);
    println!(
        "verify from snapshot O(since snap) : {:>10}   ({} hops walked)",
        fmt_dur(from_snap),
        TAIL
    );
    if from_snap.as_nanos() > 0 {
        println!(
            "speedup: {:.1}x  (both accept the same tip authority)",
            full.as_secs_f64() / from_snap.as_secs_f64()
        );
    }
    Ok(())
}

// --- revocation -------------------------------------------------------------

fn run_revocation(now: DateTime<Utc>) -> Result<(), String> {
    header("Revocation — LINEAGE-SUFFIX causal cutoff (Revocation spec §3.1)");
    const HOPS: usize = 6;
    let w = World::new()?;
    let chain = w.build_chain(HOPS, now)?;
    let lineage_id = chain[0].lineage_id.clone();
    if let Err(e) = Verifier::new(&w.set.registry, None).verify_full_chain(&chain, now) {
        return Err(format!("chain unexpectedly invalid before revocation: {e}"));
    }
    println!(
        "lineage {}… length {}: fully valid before revocation",
        &lineage_id[..20],
        chain.len()
    );

    const FROM_COUNTER: u64 = 4;
    let mut store = pic::RevocationStore::new();
    store.lineage_suffix(&lineage_id, FROM_COUNTER, &w.set.identity("alice").id);
    println!("issued LINEAGE-SUFFIX(lineage, fromCounter={FROM_COUNTER})\n");

    for p in &chain {
        let state = if store.check(p).is_err() {
            "REVOKED"
        } else {
            "valid"
        };
        println!("  counter {} : {}", p.lineage_counter, state);
    }
    let err = Verifier::new(&w.set.registry, Some(&store))
        .verify_full_chain(&chain, now)
        .err();
    println!(
        "\nfull-chain verification now: {}",
        verdict(err.is_some(), "REJECTED at the cutoff", "accepted")
    );
    println!("reason: {}", reason(&err));
    Ok(())
}

// --- timing / formatting helpers --------------------------------------------

/// Runs `fn` `iters` times and returns the average duration.
fn time_it<F: FnMut() -> Result<(), String>>(iters: u32, mut f: F) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        f().expect("timed function failed");
    }
    start.elapsed() / iters
}

/// Formats a duration as ns / µs / ms, matching bench.go's `fmtDur`.
pub(crate) fn fmt_dur(d: Duration) -> String {
    let ns = d.as_nanos() as f64;
    if ns < 1000.0 {
        format!("{} ns", ns as i64)
    } else if ns < 1_000_000.0 {
        format!("{:.1} µs", ns / 1e3)
    } else {
        format!("{:.2} ms", ns / 1e6)
    }
}
