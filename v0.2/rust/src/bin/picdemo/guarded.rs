// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Renders the Sandboxed Execution of the prototype: the dedicated `guardrail`
//! scenario and the compact block the other scenarios append under
//! `--guardrail`. PIC carries PIC. Mirror of the Go `cmd/picdemo/guarded.go`.

use crate::{
    header, paint, print_json, verdict, Opts, C_ACTOR, C_BOLD, C_CYAN, C_DIM, C_GREEN, C_REJECT,
    C_YELLOW,
};
use chrono::{DateTime, Utc};
use pic::scenario::guardrail::{CrossingOutcome, ReceiverChecks};
use pic::scenario::World;
use pic::types::Pca;

/// Renders the canonical Sandboxed Execution end to end.
pub(crate) fn run_guardrail(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
    let w = World::new()?;
    let res = w.guarded(now)?;
    if o.only_json {
        print_json(&res);
        return Ok(());
    }

    header("Sandboxed Execution — PIC carrying PIC (outer ENFORCE lineage)");
    println!("{}", paint(C_DIM, &wrap(&res.description, 96)));
    println!(
        "\npolicy {}: {} iff {}",
        paint(C_BOLD, &res.policy.id),
        res.policy.effect,
        paint(C_CYAN, &res.policy.when)
    );

    println!();
    render_carried(&res.permit);
    render_mle_box(&res.permit);
    render_origin_arrow(&res.origin);
    render_guardrail_box(&res.permit, true);
    render_receiver(&res.receiver);

    println!(
        "\n{} deny case — {} → {}",
        paint(C_BOLD, "▶"),
        res.deny.name,
        res.deny.mle.destination
    );
    render_guardrail_box(&res.deny, false);

    println!(
        "\n{} invalid carried-lineage case — {}",
        paint(C_BOLD, "▶"),
        res.invalid_pca.name
    );
    render_guardrail_box(&res.invalid_pca, false);

    println!();
    println!("{}", paint(C_DIM, "explore the execution:  picdemo exec                     (compact hop view)"));
    println!("{}", paint(C_DIM, "                        picdemo exec --lineage all --pca  (every lineage, full PCAs)"));
    println!("{}", paint(C_DIM, "inspect real artifacts: picdemo dump --guardrail          (multiLineage, outer PCA, accept)"));
    Ok(())
}

fn render_carried(out: &CrossingOutcome) {
    for tp in &out.trace.carried_lineages {
        let issuer = out
            .mle
            .participants
            .iter()
            .find(|p| p.label == tp.label)
            .map(|p| p.chain[0].issuer.clone())
            .unwrap_or_default();
        println!(
            "{} {}  {}",
            paint(C_CYAN, "●"),
            paint(C_BOLD, &format!("carried lineage {}", tp.label)),
            paint(C_DIM, &format!("origin {issuer}, {} PCAs", tp.chain_len))
        );
        println!(
            "    authority {}   grant {} → scopes {}",
            paint(C_GREEN, &go_list(&tp.authority)),
            tp.grant_id,
            paint(C_YELLOW, &go_list(&tp.scopes))
        );
    }
}

fn render_mle_box(out: &CrossingOutcome) {
    let m = &out.mle;
    println!();
    println!(
        "┌ {} {}",
        paint(C_BOLD, "MULTI-LINEAGE EXECUTION"),
        paint(
            C_DIM,
            &format!("— proposing {} → {}", m.proposing, m.destination)
        )
    );
    for p in &m.participants {
        let tip = p.tip();
        let mut line = format!("│   {}: {}", p.label, go_list(&tip.invariants.operations));
        if p.label == m.proposing {
            if let Some(por) = &tip.proof_of_relationship {
                line += &paint(
                    C_CYAN,
                    &format!(
                        "   concrete signed request: {} {}",
                        por.request.operation, por.request.target
                    ),
                );
            }
        }
        println!("{line}");
    }
    println!(
        "│   {}",
        paint(C_DIM, "carried lineages remain independent; authorities never merged")
    );
    println!("└{}", "─".repeat(68));
}

fn render_origin_arrow(origin: &Pca) {
    println!("        {}", paint(C_DIM, "│"));
    println!(
        "        {} {} originates the outer ENFORCE lineage {}",
        paint(C_CYAN, "│ sandbox origin"),
        paint(C_ACTOR, &origin.issuer),
        paint(C_DIM, "(PCA0-G, authority { ENFORCE })")
    );
    println!("        {}", paint(C_CYAN, "▼"));
}

fn render_guardrail_box(out: &CrossingOutcome, full: bool) {
    let t = &out.trace;
    println!(
        "┌ {} {}{}",
        paint(C_BOLD, "GUARDRAIL"),
        paint(C_ACTOR, &t.guardrail_executor),
        paint(C_DIM, " — ordinary executor of the outer ENFORCE lineage")
    );

    // 1. validate outer
    println!(
        "│ 1 outer      {} continue PCA{}-G → PCA{}-G",
        verdict(t.outer_valid, &paint(C_GREEN, "✔"), &paint(C_REJECT, "✗")),
        t.outer_predecessor,
        t.outer_predecessor + 1
    );

    // 2. validate carried lineages
    let parts: Vec<String> = t
        .carried_lineages
        .iter()
        .map(|tp| {
            let mark = if tp.valid {
                paint(C_GREEN, "✔")
            } else {
                paint(C_REJECT, "✗")
            };
            format!("{} {} ({} PCAs)", tp.label, mark, tp.chain_len)
        })
        .collect();
    println!("│ 2 carried    {}", parts.join("   "));
    for tp in &t.carried_lineages {
        if !tp.valid {
            println!(
                "│              {}",
                paint(C_REJECT, &format!("{}: {}", tp.label, tp.error))
            );
        }
    }

    // 3. evaluate
    if t.pdp_called {
        let req = t.pdp_request.as_ref().expect("pdp request present");
        let ins: Vec<String> = req
            .participants
            .iter()
            .map(|p| format!("{}{}", p.label, go_list(&p.scopes)))
            .collect();
        println!(
            "│ 3 evaluate   enforcement fn ← {}  destination {}",
            paint(C_YELLOW, &ins.join(" ")),
            req.destination
        );
        println!(
            "│              → {} — {}",
            decision(&t.decision.effect),
            t.decision.reason
        );
    } else {
        println!(
            "│ 3 evaluate   {}",
            paint(C_DIM, "skipped — deny before policy evaluation")
        );
    }

    // 4. prove / deny
    if t.enforced == "permit" {
        println!(
            "│ 4 prove      {} → signs PCA{}-G  request.enforcementResult=permit",
            decision("permit"),
            t.outer_counter
        );
        println!(
            "│              {}",
            paint(
                C_DIM,
                &format!("request.multiLineageDigest {}", short_hash(&t.multi_lineage_digest))
            )
        );
    } else {
        println!(
            "│ 4 prove      {} — no authorizing continuation produced",
            decision("deny")
        );
    }
    println!("└{}", "─".repeat(68));

    if full && t.enforced == "permit" {
        println!(
            "        {}  {}",
            paint(C_CYAN, "▼"),
            paint(
                C_DIM,
                "the outer PCA (PCA1-G) is the guardrail decision; no separate envelope, no second signature"
            )
        );
    }
}

pub(crate) fn render_receiver(rc: &ReceiverChecks) {
    println!("\n{} receiving hop — enforced acceptance", paint(C_BOLD, "▶"));
    println!(
        "  outer PCA             {}",
        verdict(
            rc.accepted,
            &paint(
                C_GREEN,
                "ACCEPTED — outer PIC valid, origin authorized, ENFORCE, multiLineageDigest ok, permit, fresh"
            ),
            &paint(C_REJECT, &format!("rejected: {}", rc.accept_err))
        )
    );
    println!(
        "  bypass (no outer PCA) {}",
        verdict(
            rc.bypass_rejected,
            &paint(C_REJECT, "REJECTED"),
            "accepted (BUG!)"
        )
    );
    println!("                        {}", paint(C_DIM, &rc.bypass_reason));
    println!(
        "  tampered carried set  {}",
        verdict(
            rc.tamper_rejected,
            &paint(C_REJECT, "REJECTED"),
            "accepted (BUG!)"
        )
    );
    println!("                        {}", paint(C_DIM, &rc.tamper_reason));
}

/// The compact `--guardrail` augmentation appended by the other scenarios.
pub(crate) fn render_tip_guard(
    w: &World,
    chain: Vec<Pca>,
    destination: &str,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let (out, rc) = w.guard_tip(chain, destination, now)?;
    let t = &out.trace;
    println!(
        "\n{}",
        paint(
            C_BOLD,
            "── sandboxed (--guardrail): the scenario's tip crossing goes through an outer ENFORCE lineage ──"
        )
    );
    let ins: Vec<String> = t
        .carried_lineages
        .iter()
        .map(|tp| format!("{}{}", tp.label, go_list(&tp.scopes)))
        .collect();
    println!(
        "  carried lineages {} → {}",
        paint(C_YELLOW, &ins.join(" + ")),
        destination
    );
    println!(
        "  guardrail {}: outer {}, carried {}, evaluate {}, prove {}",
        t.guardrail_executor,
        verdict(t.outer_valid, &paint(C_GREEN, "✔"), &paint(C_REJECT, "✗")),
        verdict(t.carried_valid, &paint(C_GREEN, "✔"), &paint(C_REJECT, "✗")),
        decision(&t.decision.effect),
        verdict(
            t.enforced == "permit",
            &paint(C_GREEN, "✔ PCA1-G signed"),
            &paint(C_DIM, "not produced")
        )
    );
    if t.enforced == "permit" {
        println!(
            "  receiver: outer PCA {}   bypass {}",
            verdict(
                rc.accepted,
                &paint(C_GREEN, "ACCEPTED"),
                &paint(C_REJECT, "rejected")
            ),
            verdict(
                rc.bypass_rejected,
                &paint(C_REJECT, "REJECTED"),
                "accepted (BUG!)"
            )
        );
    } else {
        println!(
            "  {}",
            paint(C_REJECT, &format!("crossing blocked: {}", out.error))
        );
    }
    Ok(())
}

fn decision(effect: &str) -> String {
    if effect == "permit" {
        paint(C_GREEN, "PERMIT")
    } else {
        paint(C_REJECT, "DENY")
    }
}

/// Renders a string list Go-style: `[a b c]`.
pub(crate) fn go_list(v: &[String]) -> String {
    format!("[{}]", v.join(" "))
}

pub(crate) fn short_hash(h: &str) -> String {
    if h.len() <= 21 {
        h.to_string()
    } else {
        format!("{}…", &h[..21])
    }
}

/// Soft-wraps `s` to `width` columns.
pub(crate) fn wrap(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut col = 0;
    for (i, wd) in s.split_whitespace().enumerate() {
        if col + wd.len() + 1 > width && col > 0 {
            out.push('\n');
            col = 0;
        } else if i > 0 {
            out.push(' ');
            col += 1;
        }
        out.push_str(wd);
        col += wd.len();
    }
    out
}
