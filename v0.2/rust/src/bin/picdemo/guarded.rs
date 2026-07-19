// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! Renders the guarded crossings of the Execution Guardrail prototype: the
//! dedicated `guardrail` scenario and the compact block the other scenarios
//! append under `--guardrail`. Mirror of the Go `cmd/picdemo/guarded.go`.

use crate::{header, paint, print_json, verdict, Opts, C_ACTOR, C_BOLD, C_CYAN, C_DIM, C_GREEN, C_REJECT, C_YELLOW};
use chrono::{DateTime, Utc};
use pic::scenario::guardrail::{CrossingOutcome, ReceiverChecks};
use pic::scenario::World;
use pic::types::Pca;

/// Renders the canonical guarded crossing end to end.
pub(crate) fn run_guardrail(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
    let w = World::new()?;
    let res = w.guarded(now)?;
    if o.only_json {
        print_json(&res);
        return Ok(());
    }

    header("Guarded crossing — sandbox + Execution Guardrail");
    println!("{}", paint(C_DIM, &wrap(&res.description, 96)));
    println!(
        "\npolicy {}: {} iff {}",
        paint(C_BOLD, &res.policy.id),
        res.policy.effect,
        paint(C_CYAN, &res.policy.when)
    );

    println!();
    render_participants(&res.permit);
    render_mle_box(&res.permit);
    render_sandbox_arrow(&res.permit);
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
        "\n{} invalid-PCA case — {}",
        paint(C_BOLD, "▶"),
        res.invalid_pca.name
    );
    render_guardrail_box(&res.invalid_pca, false);

    println!();
    println!("{}", paint(C_DIM, "inspect the real signed artifacts: picdemo dump --guardrail            (everything)"));
    println!("{}", paint(C_DIM, "                                   picdemo dump --guardrail guard      (guardrail envelope)"));
    println!("{}", paint(C_DIM, "                                   picdemo dump --guardrail pdp policy  (PDP exchange + policy)"));
    Ok(())
}

fn render_participants(out: &CrossingOutcome) {
    for tp in &out.trace.participants {
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
            paint(C_BOLD, &format!("Lineage Execution {}", tp.label)),
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
        paint(C_DIM, "authorities remain separate; never merged")
    );
    println!("└{}", "─".repeat(68));
}

fn render_sandbox_arrow(out: &CrossingOutcome) {
    println!("        {}", paint(C_DIM, "│"));
    println!(
        "        {} {} captures the crossing",
        paint(C_CYAN, "│ sandbox"),
        paint(C_ACTOR, &out.trace.forwarded_by)
    );
    if let Some(env) = &out.envelope {
        println!(
            "        {}",
            paint(
                C_DIM,
                &format!(
                    "│   forwardingProof signed by {}",
                    env.forwarding_proof.verification_method
                )
            )
        );
    }
    println!("        {}", paint(C_CYAN, "▼"));
}

fn render_guardrail_box(out: &CrossingOutcome, full: bool) {
    let t = &out.trace;
    println!(
        "┌ {} {}",
        paint(C_BOLD, "EXECUTION GUARDRAIL"),
        paint(C_ACTOR, "did:web:guardrail.example")
    );

    // 1. validate
    let parts: Vec<String> = t
        .participants
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
    println!("│ 1 validate   {}", parts.join("   "));
    for tp in &t.participants {
        if !tp.valid {
            println!(
                "│              {}",
                paint(C_REJECT, &format!("{}: {}", tp.label, tp.error))
            );
        }
    }

    // 2. evaluate
    if t.pdp_called {
        let req = t.pdp_request.as_ref().expect("pdp request present");
        let ins: Vec<String> = req
            .participants
            .iter()
            .map(|p| format!("{}{}", p.label, go_list(&p.scopes)))
            .collect();
        println!(
            "│ 2 evaluate   PDP ← participants {}  destination {}",
            paint(C_YELLOW, &ins.join(" ")),
            req.destination
        );
        println!(
            "│              PDP → {} — {}",
            decision(&t.decision.effect),
            t.decision.reason
        );
    } else {
        println!(
            "│ 2 evaluate   {}",
            paint(C_DIM, "skipped — deny enforced without evaluating policy")
        );
    }

    // 3. enforce
    if let Some(env) = &out.envelope {
        println!(
            "│ 3 enforce    {} → guardrailProof signed by {}",
            decision("permit"),
            env.guardrail_proof.verification_method
        );
        println!(
            "│              {}",
            paint(
                C_DIM,
                &format!(
                    "covers forwardingProofDigest {}",
                    short_hash(&env.guardrail_proof.forwarding_proof_digest)
                )
            )
        );
    } else {
        println!(
            "│ 3 enforce    {} — crossing blocked, no envelope issued",
            decision("deny")
        );
    }
    println!("└{}", "─".repeat(68));

    if full && out.envelope.is_some() {
        println!(
            "        {}  {}",
            paint(C_CYAN, "▼"),
            paint(
                C_DIM,
                "guardrail forwarding envelope (replaces the ordinary envelope; never nested)"
            )
        );
    }
}

pub(crate) fn render_receiver(rc: &ReceiverChecks) {
    println!("\n{} receiving hop in sandbox mode", paint(C_BOLD, "▶"));
    println!(
        "  envelope              {}",
        verdict(
            rc.envelope_accepted,
            &paint(
                C_GREEN,
                "ACCEPTED — both proofs verify, digests recomputed, freshness ok"
            ),
            &paint(C_REJECT, &format!("rejected: {}", rc.envelope_err))
        )
    );
    println!(
        "  bypass (no envelope)  {}",
        verdict(
            rc.bypass_rejected,
            &paint(C_REJECT, "REJECTED"),
            "accepted (BUG!)"
        )
    );
    println!("                        {}", paint(C_DIM, &rc.bypass_reason));
    println!(
        "  tampered destination  {}",
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
            "── guarded (--guardrail): the scenario's tip crossing goes through sandbox + guardrail ──"
        )
    );
    let ins: Vec<String> = t
        .participants
        .iter()
        .map(|tp| format!("{}{}", tp.label, go_list(&tp.scopes)))
        .collect();
    println!(
        "  participants {} → {}",
        paint(C_YELLOW, &ins.join(" + ")),
        destination
    );
    println!(
        "  sandbox {} → forwardingProof {}   guardrail: validate {}, PDP {}, guardrailProof {}",
        t.forwarded_by,
        paint(C_GREEN, "✔"),
        verdict(t.pcas_valid, &paint(C_GREEN, "✔"), &paint(C_REJECT, "✗")),
        decision(&t.decision.effect),
        verdict(
            out.envelope.is_some(),
            &paint(C_GREEN, "✔ signed"),
            &paint(C_DIM, "not issued")
        )
    );
    if out.envelope.is_some() {
        println!(
            "  receiver: envelope {}   bypass {}",
            verdict(
                rc.envelope_accepted,
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

fn short_hash(h: &str) -> String {
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
