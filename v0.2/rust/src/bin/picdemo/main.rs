// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Command picdemo runs the PIC v0.2 Rust prototype scenarios and prints timings.
//!
//!   cargo run --bin picdemo -- [why-pic|confused-deputy|snapshot|revocation|guardrail|flow|dump|bench|all] [flags] [dump selectors]
//!
//! Flags:
//!   --guardrail   load the Execution Guardrail fixtures (sandbox + guardrail +
//!                 simulated PDP) and route each scenario's tip crossing through
//!                 them; without it, everything behaves exactly as before.
//!   --only-json   emit a single JSON document (for jq) instead of the report.
//!
//! Dump selectors (with `dump`): pca0|hop0, pca1|hop1, envelope, and with
//! --guardrail also policy, scopes, mle, pdp, trace, guard, denytrace.
//!
//! It uses the real v0.2 fixtures loaded once into memory. It is non-normative
//! demonstration code; the PIC Specification is authoritative.

mod bench;
mod flow;
mod guarded;

use chrono::{DateTime, Utc};
use guarded::{render_receiver, render_tip_guard, run_guardrail, wrap};
use pic::authority::go_slice;
use pic::scenario::World;
use pic::{issue_snapshot, wrap_envelope, Verifier};
use serde::Serialize;
use serde_json::Value;
use std::io::IsTerminal;
use std::process::exit;
use std::time::{Duration, Instant};

/// Run options shared by every command.
#[derive(Default, Clone)]
pub(crate) struct Opts {
    pub guardrail: bool,
    pub only_json: bool,
    pub selectors: Vec<String>,
}

fn main() {
    let mut o = Opts::default();
    let mut positional: Vec<String> = Vec::new();
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--guardrail" | "-g" => o.guardrail = true,
            "--only-json" | "--json" | "-j" => o.only_json = true,
            _ => positional.push(a),
        }
    }
    let which = positional
        .first()
        .cloned()
        .unwrap_or_else(|| "all".to_string());
    o.selectors = positional.get(1..).unwrap_or_default().to_vec();
    let now = Utc::now();

    let order = ["why-pic", "confused-deputy", "snapshot", "revocation"];
    let known = ["why-pic", "confused-deputy", "snapshot", "revocation", "guardrail"];

    if which == "dump" || which == "flow" || which == "bench" {
        let res = match which.as_str() {
            "flow" => flow::run_flow(now, &o),
            "bench" => bench::run_bench(now, &o),
            _ => run_dump(now, &o),
        };
        if let Err(e) = res {
            eprintln!("error: {e}");
            exit(1);
        }
        return;
    }

    let run: Vec<&str> = if which == "all" {
        let mut v = order.to_vec();
        if o.guardrail {
            v.push("guardrail");
        }
        v
    } else if known.contains(&which.as_str()) {
        vec![known[known.iter().position(|k| *k == which).unwrap()]]
    } else {
        if looks_like_dump_selector(&which) {
            let mut args = vec![which.clone()];
            args.extend(o.selectors.clone());
            eprintln!(
                "{which:?} is a dump selector, not a scenario — try:\n  picdemo dump --guardrail {}",
                args.join(" ")
            );
            exit(2);
        }
        eprintln!("unknown scenario {which:?} (use: {order:?}, guardrail, flow, bench, dump, or all)");
        exit(2);
    };

    for name in run {
        let res = match name {
            "why-pic" => run_authority_mixing(now, &o),
            "confused-deputy" => run_confused_deputy(now, &o),
            "snapshot" => run_snapshot(now, &o),
            "revocation" => run_revocation(now, &o),
            "guardrail" => run_guardrail(now, &o),
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

/// Reports whether `s` names a dump artifact, so the CLI can suggest the dump
/// command when a selector is passed as a scenario.
fn looks_like_dump_selector(s: &str) -> bool {
    let s = s.trim_start_matches('-').to_lowercase();
    const KEYS: [&str; 13] = [
        "pca0", "pca1", "hop0", "hop1", "envelope", "policy", "scopes", "mle", "pdp", "trace",
        "guard", "denytrace", "deny",
    ];
    KEYS.iter()
        .any(|k| s == *k || (s.len() >= 3 && k.starts_with(&s)))
}

// --- ANSI color helpers (shared with flow.rs / bench.rs / guarded.rs) --------

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

pub(crate) fn verdict(ok: bool, yes: &str, no: &str) -> String {
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
struct Artifact {
    explanation: String,
    value: Value,
}

/// One selectable artifact of the dump.
struct DumpItem {
    key: &'static str,
    aliases: &'static [&'static str],
    title: String,
    explanation: &'static str,
    value: Value,
}

impl DumpItem {
    fn matches(&self, sel: &str) -> bool {
        let sel = sel.to_lowercase();
        sel == self.key
            || self.aliases.contains(&sel.as_str())
            || (sel.len() >= 3 && self.key.starts_with(&sel))
    }
}

fn to_value<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).expect("serialize artifact")
}

/// Builds real signed artifacts, verifies them, and runs a live tamper proof.
/// With --guardrail it also runs the guarded crossing and exposes its
/// artifacts. Selectors filter what is printed: `dump hop1`,
/// `dump --guardrail guard pdp`.
fn run_dump(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
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

    let mut items = vec![
        DumpItem {
            key: "pca0",
            aliases: &["hop0"],
            title: "PCA0 (origin, signed by alice)".into(),
            explanation: "Origin PCA (PCA0): starts the lineage, signed by the origin principal (alice). It carries no Proof of Relationship and no predecessor hash; its invariants are the upper bound of authority for the whole lineage.",
            value: to_value(&pca0),
        },
        DumpItem {
            key: "pca1",
            aliases: &["hop1"],
            title: "PCA1 (successor: real PoR, previousPcaHash, executor attestation, single signature)".into(),
            explanation: "Successor PCA: continues exactly one predecessor. proofOfRelationship carries previousPcaHash (= PCA0 digest), the continuation-challenge response, the executor request binding, and the executor's signed attestation; a single Ed25519 signature covers the whole PCA.",
            value: to_value(&pca1),
        },
        DumpItem {
            key: "envelope",
            aliases: &[],
            title: "Envelope [predecessor, current], signed by the forwarder".into(),
            explanation: "Handoff envelope: carries [predecessor, current] together, signed by the forwarder. The digests are a convenience; a Verifier recomputes them from the PCA bytes.",
            value: to_value(&env),
        },
    ];

    let mut guarded_res = None;
    if o.guardrail {
        let g = w.guarded(now)?;
        items.push(DumpItem {
            key: "policy",
            aliases: &[],
            title: "Guardrail policy (fixture, spec-shaped)".into(),
            explanation: "The configured policy the PDP evaluates: an effect and an elementary CEL-like condition over the participants' semantic scopes. The decision defaults to deny.",
            value: to_value(&g.policy),
        });
        items.push(DumpItem {
            key: "scopes",
            aliases: &[],
            title: "Semantic-scope bindings (policy-controlled mapping)".into(),
            explanation: "Scopes are bound to a Lineage Execution through its origin grantId (or origin issuer): origin-bound metadata the executor cannot self-assert. A scope adds no authority.",
            value: to_value(&g.scopes),
        });
        items.push(DumpItem {
            key: "mle",
            aliases: &[],
            title: "Multi-Lineage Execution (the runtime carrier)".into(),
            explanation: "n >= 1 Lineage Executions carried together for one proposed transition. The proposed transition consists exclusively of the concrete signed requests carried by the participants; no authority of its own.",
            value: to_value(&g.permit.mle),
        });
        items.push(DumpItem {
            key: "pdp",
            aliases: &[],
            title: "PDP exchange (request → decision)".into(),
            explanation: "What the guardrail hands to the (simulated) PDP — participants with scopes and destination — and the decision that comes back. The guardrail enforces it; the PDP is one possible implementation of policy evaluation.",
            value: serde_json::json!({
                "request": g.permit.trace.pdp_request,
                "decision": g.permit.trace.decision,
            }),
        });
        items.push(DumpItem {
            key: "trace",
            aliases: &[],
            title: "Guardrail enforcement trace (validate → evaluate → enforce)".into(),
            explanation: "What the guardrail did, in enforcement order: PCA validation per participant, the PDP call, and the enforced decision.",
            value: to_value(&g.permit.trace),
        });
        items.push(DumpItem {
            key: "guard",
            aliases: &["guardrail", "guard1"],
            title: "Guardrail forwarding envelope (two proofs, never nested)".into(),
            explanation: "The permitted crossing travels in this envelope. forwardingProof (sandbox) attributes the presentation; guardrailProof (guardrail DID) attests validation + policy + permit and covers the forwardingProofDigest. Neither replaces the executor signature on any PCA.",
            value: to_value(&g.permit.envelope),
        });
        items.push(DumpItem {
            key: "denytrace",
            aliases: &["deny"],
            title: "Deny trace (A + C, external-sharing)".into(),
            explanation: "The same pipeline denying: the PDP finds a participant whose scopes satisfy no policy alternative; the guardrail enforces deny and issues no envelope.",
            value: to_value(&g.deny.trace),
        });
        guarded_res = Some(g);
    }

    // Selector filtering: print only the requested artifacts.
    if !o.selectors.is_empty() {
        let mut picked: Vec<&DumpItem> = Vec::new();
        for sel in &o.selectors {
            let matched: Vec<&DumpItem> = items.iter().filter(|it| it.matches(sel)).collect();
            if matched.is_empty() {
                let keys: Vec<&str> = items.iter().map(|it| it.key).collect();
                return Err(format!(
                    "dump: unknown selector {sel:?} (available: {})",
                    keys.join(", ")
                ));
            }
            picked.extend(matched);
        }
        if o.only_json {
            let mut out = serde_json::Map::new();
            for it in picked {
                out.insert(
                    it.key.to_string(),
                    to_value(&Artifact {
                        explanation: it.explanation.to_string(),
                        value: it.value.clone(),
                    }),
                );
            }
            print_json(&Value::Object(out));
            return Ok(());
        }
        for it in picked {
            println!("\n--- {} ---", it.title);
            println!("{}", paint(C_DIM, &wrap(it.explanation, 96)));
            print_json(&it.value);
        }
        return Ok(());
    }

    if o.only_json {
        let mut artifacts = serde_json::Map::new();
        for it in &items {
            artifacts.insert(
                it.key.to_string(),
                serde_json::json!({"explanation": it.explanation, "value": it.value}),
            );
        }
        let mut checks = serde_json::json!({
            "pca0Digest": d0,
            "previousPcaHashMatchesPca0Digest": pca1
                .proof_of_relationship.as_ref()
                .map(|p| p.previous_pca_hash == d0)
                .unwrap_or(false),
            "verifyFullChainOk": verify_err.is_none(),
            "authority": inv,
            "tamperProof": {
                "explanation": "Editing one signed field (invariants.operations) and re-verifying: the Ed25519 signature no longer verifies, so the edit is rejected.",
                "editedSignedField": "invariants.operations",
                "rejected": tamper_err.is_some(),
                "reason": tamper_err.clone().unwrap_or_default(),
            },
        });
        if let Some(g) = &guarded_res {
            checks["guardrailReceiver"] = to_value(&g.receiver);
        }
        print_json(&serde_json::json!({
            "description": "Real PIC v0.2 signed artifacts (Ed25519 + SHA-256 hash chain), produced live on this run — nothing precomputed.",
            "artifacts": artifacts,
            "checks": checks,
        }));
        return Ok(());
    }

    header("Inspect real artifacts (dump)");
    for it in &items {
        println!("\n--- {} ---", it.title);
        print_json(&it.value);
    }
    println!("\nPCA0 digest (content id): {d0}");
    println!(
        "PCA1.proofOfRelationship.previousPcaHash == PCA0 digest ? {}",
        pca1.proof_of_relationship
            .as_ref()
            .map(|p| p.previous_pca_hash == d0)
            .unwrap_or(false)
    );
    println!(
        "VerifyFullChain([PCA0, PCA1]) -> ok={}, authority={}",
        verify_err.is_none(),
        go_slice(&inv)
    );
    println!(
        "after editing one signed operation -> rejected={}",
        tamper_err.is_some()
    );
    println!("reason: {}", reason(&tamper_err));
    if let Some(g) = &guarded_res {
        render_receiver(&g.receiver);
    }
    println!(
        "{}",
        paint(
            C_DIM,
            "\nselect artifacts: picdemo dump hop1   |   picdemo dump --guardrail guard pdp"
        )
    );
    Ok(())
}

// --- why-pic (authority mixing) ---------------------------------------------

fn run_authority_mixing(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
    header("Authority Mixing / invalid cross-lineage import (Why PIC; spec §1.4)");
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
    if o.guardrail {
        let chain = w.build_chain(2, now)?;
        return render_tip_guard(&w, chain, "s3://backups/tenant-42", now);
    }
    Ok(())
}

// --- confused deputy --------------------------------------------------------

fn run_confused_deputy(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
    header("Cross-Service Confused Deputy (Alice → Archive → Storage)");
    let w = World::new()?;
    let (legit_chain, req, res) = w.case1_legit(now)?;
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
    if o.guardrail {
        return render_tip_guard(&w, legit_chain, "s3://archive/tenant-42", now);
    }
    Ok(())
}

// --- snapshot ---------------------------------------------------------------

fn run_snapshot(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
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
    if o.guardrail {
        return render_tip_guard(&w, chain[..2].to_vec(), "s3://backups/tenant-42", now);
    }
    Ok(())
}

// --- revocation -------------------------------------------------------------

fn run_revocation(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
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
    if o.guardrail {
        return render_tip_guard(&w, chain[..2].to_vec(), "s3://backups/tenant-42", now);
    }
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
