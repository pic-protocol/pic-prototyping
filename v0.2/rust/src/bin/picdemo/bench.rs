// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! `picdemo bench`: a self-contained harness that measures the key PIC operations
//! on the real fixtures and prints a colored table (latency, throughput, relative
//! bar), the snapshot-vs-full-chain speedup, and a per-hop block. `--only-json`
//! emits a JSON array.

use crate::{fmt_dur, header, paint, print_json, C_BOLD, C_CYAN, C_DIM, C_GREEN, C_RED, C_YELLOW};
use chrono::{DateTime, Utc};
use pic::prover::mint_pca0;
use pic::scenario::World;
use pic::types::{Invariants, Request};
use pic::{issue_snapshot, wrap_envelope, Prover, Verifier};
use serde::Serialize;
use std::time::{Duration, Instant};

/// Serialized (compact JSON) byte sizes of representative artifacts.
struct PcaSizes {
    pca0: usize,
    successor: usize,
    envelope: usize,
}

/// Byte length of the compact JSON serialization of `v`.
fn json_len<T: Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

/// Renders a byte count as "1,280 B (1.25 KB)".
fn size_str(n: usize) -> String {
    format!("{} B ({:.2} KB)", commas(n as i64), n as f64 / 1024.0)
}

#[derive(Serialize)]
struct BenchRow {
    name: String,
    iters: u64,
    #[serde(rename = "nsPerOp")]
    ns_per_op: f64,
    #[serde(rename = "opsPerSec")]
    ops_per_sec: f64,
}

pub(crate) fn run_bench(now: DateTime<Utc>, o: &crate::Opts) -> Result<(), String> {
    let w = World::new()?;
    let reg = &w.set.registry;
    let inv = Invariants {
        operations: vec!["read:/user/*".to_string()],
        ..Default::default()
    };
    let req = Request {
        operation: "read".to_string(),
        target: "/user/file".to_string(),
        security_domain: "tenant-42".to_string(),
        ..Default::default()
    };

    // Shared setup, done once (not timed).
    let pca0 = mint_pca0(w.set.identity("alice"), inv.clone(), "", now);
    let prover = Prover::new(w.set.identity("gateway"), w.set.attestation("gateway"));
    let pca1 = prover.continue_(&pca0, inv.clone(), req.clone(), now)?;
    let chain = w.build_chain(64, now)?;
    let through = chain.len() - 1 - 8;
    let snap = issue_snapshot(w.set.identity("snapshot-issuer"), reg, &chain, through, now)?;
    let tail = &chain[through..];

    let env = wrap_envelope(w.set.identity("gateway"), &pca0, &pca1);
    let sizes = PcaSizes {
        pca0: json_len(&pca0),
        successor: json_len(&pca1),
        envelope: json_len(&env),
    };

    type Case<'a> = (&'a str, Box<dyn Fn() + 'a>);
    let cases: Vec<Case> = vec![
        (
            "sign PCA0 (Ed25519)",
            Box::new(|| {
                let _ = mint_pca0(w.set.identity("alice"), inv.clone(), "", now);
            }),
        ),
        (
            "prove hop",
            Box::new(|| {
                let _ = prover.continue_(&pca0, inv.clone(), req.clone(), now);
            }),
        ),
        (
            "verify hop",
            Box::new(|| {
                let _ = Verifier::new(reg, None).verify_hop(&pca1, &pca0, now, false);
            }),
        ),
        (
            "digest (SHA-256)",
            Box::new(|| {
                let _ = pca1.digest();
            }),
        ),
        (
            "verify full chain (64 hops)",
            Box::new(|| {
                let _ = Verifier::new(reg, None).verify_full_chain(&chain, now);
            }),
        ),
        (
            "verify from snapshot (tail 8)",
            Box::new(|| {
                let _ = Verifier::new(reg, None).verify_from_snapshot(&snap, tail, now);
            }),
        ),
        (
            "authority-mixing (scenario)",
            Box::new(|| {
                let _ = w.authority_mixing(now);
            }),
        ),
    ];

    let mut rows = Vec::with_capacity(cases.len());
    for (name, f) in &cases {
        let (iters, per) = measure(f.as_ref());
        let ns = per.as_nanos() as f64;
        rows.push(BenchRow {
            name: name.to_string(),
            iters,
            ns_per_op: ns,
            ops_per_sec: 1e9 / ns,
        });
    }

    let mut grows: Vec<BenchRow> = Vec::new();
    let mut genv_size = 0usize;
    if o.guardrail {
        (grows, genv_size) = bench_guardrail(&w, now)?;
    }

    if o.only_json {
        let mut all = rows;
        all.extend(grows);
        print_json(&all);
        return Ok(());
    }
    render_bench(&rows, &sizes);
    if o.guardrail {
        render_guard_bench(&grows, genv_size);
    }
    Ok(())
}

/// Measures the guarded crossing on the canonical A+B example: each component
/// alone, then the whole pipeline end to end.
fn bench_guardrail(w: &World, now: DateTime<Utc>) -> Result<(Vec<BenchRow>, usize), String> {
    use pic::scenario::guardrail::{GRANT_AGENT_S3_WRITER, GRANT_USER_BACKUP};
    use pic::types::ExecutionContract;
    use pic::{Guardrail, LocalPdp, MultiLineageExecution, Participant, Pdp, Sandbox};

    let reg = &w.set.registry;
    let pdp = LocalPdp {
        policy: w.set.policy.clone(),
    };
    let guard = Guardrail::new(w.set.identity("guardrail"), reg, &pdp, &w.set.scopes);
    let sandbox = Sandbox::new(w.set.identity("sandbox"), &guard);
    let agent = w.set.identity("summary-service");
    let agent_att = w.set.attestation("summary-service");
    let contract = ExecutionContract::default();

    let pca0_a = mint_pca0(
        w.set.identity("alice"),
        Invariants {
            operations: vec!["read-all".into(), "backup".into()],
            execution_contract: contract.clone(),
        },
        GRANT_USER_BACKUP,
        now,
    );
    let pca1_a = Prover::new(agent, agent_att.clone()).continue_(
        &pca0_a,
        Invariants {
            operations: vec!["backup".into()],
            execution_contract: contract.clone(),
        },
        Request {
            operation: "backup".into(),
            target: "/user/dataset".into(),
            security_domain: "tenant-42".into(),
            ..Default::default()
        },
        now,
    )?;
    let inv_b = Invariants {
        operations: vec!["write:s3/backups/*".into()],
        execution_contract: contract.clone(),
    };
    let pca0_b = mint_pca0(agent, inv_b.clone(), GRANT_AGENT_S3_WRITER, now);
    let pca1_b = Prover::new(agent, agent_att.clone()).continue_(
        &pca0_b,
        inv_b,
        Request {
            operation: "write".into(),
            target: "s3/backups/tenant-42/dataset.tar".into(),
            security_domain: "tenant-42".into(),
            ..Default::default()
        },
        now,
    )?;
    let mle = MultiLineageExecution {
        participants: vec![
            Participant {
                label: "A".into(),
                chain: vec![pca0_a, pca1_a],
            },
            Participant {
                label: "B".into(),
                chain: vec![pca0_b, pca1_b],
            },
        ],
        proposing: "B".into(),
        destination: "s3://backups/tenant-42".into(),
    };

    let pres = sandbox.present(&mle, now)?;
    let (env, trace) = guard.enforce(&pres, now);
    let env = env.ok_or("bench: guarded crossing unexpectedly denied")?;
    let recognized = w.recognized_guardrails();
    let req = trace.pdp_request.clone().ok_or("bench: no pdp request")?;

    type Case<'a> = (&'a str, Box<dyn Fn() + 'a>);
    let cases: Vec<Case> = vec![
        (
            "sandbox: present (forwardingProof)",
            Box::new(|| {
                let _ = sandbox.present(&mle, now);
            }),
        ),
        (
            "guardrail: validate participants",
            Box::new(|| {
                for p in &mle.participants {
                    let _ = Verifier::new(reg, None).verify_full_chain(&p.chain, now);
                }
            }),
        ),
        (
            "guardrail: PDP evaluate",
            Box::new(|| {
                let _ = pdp.evaluate(&req);
            }),
        ),
        (
            "guardrail: enforce (3 steps)",
            Box::new(|| {
                let _ = guard.enforce(&pres, now);
            }),
        ),
        (
            "receiver: verify envelope",
            Box::new(|| {
                let _ = pic::verify_guardrail_envelope(reg, &recognized, Some(&env), now);
            }),
        ),
        (
            "guarded crossing end to end",
            Box::new(|| {
                let _ = sandbox.cross(&mle, now);
            }),
        ),
    ];
    let mut rows = Vec::with_capacity(cases.len());
    for (name, f) in &cases {
        let (iters, per) = measure(f.as_ref());
        let ns = per.as_nanos() as f64;
        rows.push(BenchRow {
            name: name.to_string(),
            iters,
            ns_per_op: ns,
            ops_per_sec: 1e9 / ns,
        });
    }
    Ok((rows, json_len(&env)))
}

/// Prints the guarded-crossing table plus the decomposition of the end-to-end
/// cost into its components.
fn render_guard_bench(rows: &[BenchRow], env_size: usize) {
    println!();
    println!(
        "  {}{}",
        paint(C_BOLD, "guarded crossing (--guardrail)"),
        paint(C_DIM, "  sandbox → guardrail (validate → PDP → sign) → receiver")
    );
    println!("  {}", paint(C_DIM, &"─".repeat(74)));

    let max_ns = rows.iter().fold(0.0f64, |m, r| m.max(r.ns_per_op));
    for r in rows {
        let lat = fmt_dur(Duration::from_nanos(r.ns_per_op as u64));
        let thr = format!("{}/s", commas(r.ops_per_sec as i64));
        println!(
            "  {} {} {} {}",
            pad(&paint(C_CYAN, &r.name), 32),
            pad_left(&paint(C_YELLOW, &lat), 11),
            pad_left(&paint(C_GREEN, &thr), 14),
            latency_bar(r.ns_per_op, max_ns)
        );
    }
    println!("  {}", paint(C_DIM, &"─".repeat(74)));

    let get = |prefix: &str| -> f64 {
        rows.iter()
            .find(|r| r.name.starts_with(prefix))
            .map(|r| r.ns_per_op)
            .unwrap_or(0.0)
    };
    let present = get("sandbox: present");
    let validate = get("guardrail: validate");
    let pdp = get("guardrail: PDP");
    let enforce = get("guardrail: enforce");
    let receiver = get("receiver:");
    let total = get("guarded crossing");
    let sign = (enforce - validate - pdp).max(0.0);
    if total > 0.0 {
        println!();
        println!(
            "  {}{}",
            paint(C_BOLD, "end-to-end decomposition"),
            paint(C_DIM, "  (share of one guarded crossing)")
        );
        let comp = [
            ("sandbox present + forwardingProof", present),
            ("guardrail validate PCAs", validate),
            ("guardrail PDP evaluate", pdp),
            ("guardrail sign envelope (derived)", sign),
        ];
        for (name, ns) in comp {
            println!(
                "    {} {}  {}",
                pad(name, 36),
                pad_left(&paint(C_YELLOW, &fmt_dur(dur(ns))), 11),
                paint(C_DIM, &format!("{:4.1}%", ns / total * 100.0))
            );
        }
        println!("    {}", paint(C_DIM, &"─".repeat(52)));
        println!(
            "    {} {}   {}",
            pad(&paint(C_BOLD, "guarded crossing total"), 36),
            pad_left(&paint("1;33", &fmt_dur(dur(total))), 11),
            paint(
                C_GREEN,
                &format!("~{} crossings/s", commas((1e9 / total) as i64))
            )
        );
        println!(
            "    {} {}  {}",
            pad("receiver verify (next hop)", 36),
            pad_left(&paint(C_YELLOW, &fmt_dur(dur(receiver))), 11),
            paint(C_DIM, "sandbox mode acceptance")
        );
    }
    println!(
        "\n  {}  guardrail envelope {}",
        paint(C_BOLD, "serialized size"),
        paint(C_YELLOW, &size_str(env_size))
    );
}

/// Runs `f` until at least ~200ms have elapsed and returns the iteration count
/// and the average duration per call.
fn measure(f: &dyn Fn()) -> (u64, Duration) {
    f(); // warm up
    let mut iters: u64 = 1;
    loop {
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_millis(200) || iters >= (1 << 22) {
            return (iters, elapsed / iters as u32);
        }
        iters *= 2;
    }
}

fn render_bench(rows: &[BenchRow], sizes: &PcaSizes) {
    header("Micro-benchmarks on the real fixtures");
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!(
        "{}",
        paint(
            C_DIM,
            &format!(
                "{}/{} · {} CPU · rustc {}",
                std::env::consts::OS,
                std::env::consts::ARCH,
                cpus,
                option_env!("CARGO_PKG_RUST_VERSION").unwrap_or("stable")
            )
        )
    );
    println!();

    let max_ns = rows.iter().fold(0.0f64, |m, r| m.max(r.ns_per_op));

    println!(
        "  {} {} {} {}",
        pad(&paint(C_BOLD, "operation"), 32),
        pad_left(&paint(C_BOLD, "latency"), 11),
        pad_left(&paint(C_BOLD, "throughput"), 14),
        paint(C_BOLD, "relative")
    );
    println!("  {}", paint(C_DIM, &"─".repeat(74)));

    for r in rows {
        let lat = fmt_dur(Duration::from_nanos(r.ns_per_op as u64));
        let thr = format!("{}/s", commas(r.ops_per_sec as i64));
        let bar = latency_bar(r.ns_per_op, max_ns);
        println!(
            "  {} {} {} {}",
            pad(&paint(C_CYAN, &r.name), 32),
            pad_left(&paint(C_YELLOW, &lat), 11),
            pad_left(&paint(C_GREEN, &thr), 14),
            bar
        );
    }
    println!("  {}", paint(C_DIM, &"─".repeat(74)));

    // The headline: snapshot vs full-chain.
    let mut full = 0.0;
    let mut snap = 0.0;
    for r in rows {
        if r.name.starts_with("verify full chain") {
            full = r.ns_per_op;
        }
        if r.name.starts_with("verify from snapshot") {
            snap = r.ns_per_op;
        }
    }
    if full > 0.0 && snap > 0.0 {
        println!(
            "  {} snapshot verify is {} than full-chain — the O(hops since snapshot) win (§5.2)",
            paint(C_GREEN, "▶"),
            paint("1;32", &format!("{:.1}× faster", full / snap))
        );
    }

    // Per-hop cost: one executor receives PCA[n], verifies it, and emits PCA[n+1].
    let mut verify_ns = 0.0;
    let mut prove_ns = 0.0;
    for r in rows {
        if r.name.starts_with("verify hop") {
            verify_ns = r.ns_per_op;
        } else if r.name.starts_with("prove hop") {
            prove_ns = r.ns_per_op;
        }
    }
    if verify_ns > 0.0 && prove_ns > 0.0 {
        let total = verify_ns + prove_ns;
        println!();
        println!(
            "  {}{}",
            paint(C_BOLD, "per hop"),
            paint(
                C_DIM,
                "  (incremental profile: receive PCA[n] → verify → emit PCA[n+1])"
            )
        );
        println!(
            "    {} {}",
            pad("verify received (n)", 22),
            pad_left(&paint(C_YELLOW, &fmt_dur(dur(verify_ns))), 11)
        );
        println!(
            "    {} {}",
            pad("prove / emit (n+1)", 22),
            pad_left(&paint(C_YELLOW, &fmt_dur(dur(prove_ns))), 11)
        );
        println!("    {}", paint(C_DIM, &"─".repeat(34)));
        println!(
            "    {} {}   {}",
            pad(&paint(C_BOLD, "total per hop"), 22),
            pad_left(&paint("1;33", &fmt_dur(dur(total))), 11),
            paint(
                C_GREEN,
                &format!("~{} hops/s", commas((1e9 / total) as i64))
            )
        );
    }

    println!();
    println!(
        "  {}  PCA0 {} · successor {} · envelope {}",
        paint(C_BOLD, "serialized size"),
        paint(C_YELLOW, &size_str(sizes.pca0)),
        paint(C_YELLOW, &size_str(sizes.successor)),
        paint(C_YELLOW, &size_str(sizes.envelope)),
    );

    println!(
        "{}",
        paint(
            C_DIM,
            "  (illustrative visual demo, not rigorous — for real numbers run `task v0-2-rust-bench` (cargo bench))"
        )
    );
}

/// Converts a nanosecond count to a Duration.
fn dur(ns: f64) -> Duration {
    Duration::from_nanos(ns as u64)
}

/// Draws a bar proportional to latency, colored by speed tier.
fn latency_bar(ns: f64, max_ns: f64) -> String {
    const WIDTH: f64 = 26.0;
    let mut n = 1i64;
    if max_ns > 0.0 {
        n = (ns / max_ns * WIDTH) as i64;
    }
    if n < 1 {
        n = 1;
    }
    let color = if ns > 0.5 * max_ns {
        C_RED
    } else if ns > 0.15 * max_ns {
        C_YELLOW
    } else {
        C_GREEN
    };
    paint(color, &"█".repeat(n as usize))
}

/// Formats an integer with thousands separators.
fn commas(n: i64) -> String {
    let neg = n < 0;
    let s = n.abs().to_string();
    let bytes = s.as_bytes();
    let mut out = String::new();
    for (i, c) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*c as char);
    }
    if neg {
        format!("-{out}")
    } else {
        out
    }
}

/// Pads `s` to visible width `w` (accounting for ANSI escapes), right side.
fn pad(s: &str, w: usize) -> String {
    let n = w.saturating_sub(visible_len(s));
    if n == 0 {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(n))
    }
}

/// Pads `s` to visible width `w` on the left.
fn pad_left(s: &str, w: usize) -> String {
    let n = w.saturating_sub(visible_len(s));
    if n == 0 {
        s.to_string()
    } else {
        format!("{}{s}", " ".repeat(n))
    }
}

/// Visible length of `s`, ignoring ANSI escape sequences.
fn visible_len(s: &str) -> usize {
    let mut n = 0;
    let mut in_esc = false;
    for r in s.chars() {
        if r == '\x1b' {
            in_esc = true;
        } else if in_esc && r == 'm' {
            in_esc = false;
        } else if !in_esc {
            n += 1;
        }
    }
    n
}
