// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! `picdemo exec`: an interactive viewer of a Sandboxed Execution. It shows PIC
//! carrying PIC — the outer ENFORCE lineage carrying an inner Multi-Lineage
//! Execution — as a compact hop diagram, lets you drill into one carried lineage
//! (or the outer lineage, or all), and inspect every PCA. Guardrail on by
//! default; `--no-guardrail` shows the inner lineages alone. Mirror of Go
//! `cmd/picdemo/exec.go`.

use crate::guarded::{go_list, short_hash, wrap};
use crate::{
    header, paint, print_json, Opts, C_ACTOR, C_BOLD, C_CYAN, C_DIM, C_GREEN,
};
use chrono::{DateTime, Utc};
use pic::scenario::World;
use pic::types::Pca;
use serde::Serialize;

/// One carried lineage plus its enforcement metadata.
struct Lin {
    label: String,
    chain: Vec<Pca>,
    grant: String,
    scopes: Vec<String>,
    authority: Vec<String>,
    origin: String,
}

pub(crate) fn run_exec(now: DateTime<Utc>, o: &Opts) -> Result<(), String> {
    // Parse exec flags from the positional args.
    let mut guardrail = true;
    let mut pca = false;
    let mut lineage = String::new();
    let mut i = 0;
    while i < o.selectors.len() {
        let a = &o.selectors[i];
        match a.as_str() {
            "--no-guardrail" => guardrail = false,
            "--guardrail" | "-g" => guardrail = true,
            "--pca" => pca = true,
            "--lineage" | "-l" => {
                if i + 1 < o.selectors.len() {
                    i += 1;
                    lineage = o.selectors[i].clone();
                }
            }
            s if s.starts_with("--lineage=") => {
                lineage = s.trim_start_matches("--lineage=").to_string();
            }
            s if s.starts_with('-') => {
                return Err(format!(
                    "exec: unknown flag {s:?} (use --lineage <A|B|outer|all>, --pca, --no-guardrail)"
                ));
            }
            s => lineage = s.to_string(),
        }
        i += 1;
    }

    let w = World::new()?;
    let res = w.guarded(now)?;
    let c = &res.permit;

    let carried: Vec<Lin> = c
        .mle
        .participants
        .iter()
        .map(|p| {
            let tp = c.trace.carried_lineages.iter().find(|t| t.label == p.label);
            Lin {
                label: p.label.clone(),
                chain: p.chain.clone(),
                origin: p.chain[0].issuer.clone(),
                grant: tp.map(|t| t.grant_id.clone()).unwrap_or_default(),
                scopes: tp.map(|t| t.scopes.clone()).unwrap_or_default(),
                authority: tp.map(|t| t.authority.clone()).unwrap_or_default(),
            }
        })
        .collect();
    let label_list = || {
        carried
            .iter()
            .map(|l| l.label.clone())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let find = |name: &str| carried.iter().find(|l| l.label.eq_ignore_ascii_case(name));

    // --only-json: emit the structured execution.
    if o.only_json {
        #[derive(Serialize)]
        struct CarriedJson<'a> {
            label: &'a str,
            grant: &'a str,
            scopes: &'a [String],
            authority: &'a [String],
            chain: &'a [Pca],
        }
        let cl: Vec<CarriedJson> = carried
            .iter()
            .map(|l| CarriedJson {
                label: &l.label,
                grant: &l.grant,
                scopes: &l.scopes,
                authority: &l.authority,
                chain: &l.chain,
            })
            .collect();
        let mut out = serde_json::json!({
            "mode": if guardrail { "sandboxed" } else { "inner-only (--no-guardrail)" },
            "selection": if lineage.is_empty() { "compact" } else { lineage.as_str() },
            "carriedLineages": cl,
        });
        if guardrail {
            out["outerChain"] = serde_json::to_value(&c.outer_chain).unwrap();
            out["decision"] = serde_json::to_value(&c.trace.decision).unwrap();
        }
        print_json(&out);
        return Ok(());
    }

    // --no-guardrail: inner Multi-Lineage Execution alone (debug).
    if !guardrail {
        header("Execution (--no-guardrail) — inner Multi-Lineage Execution, no Sandboxed Execution");
        println!("{}", paint(C_DIM, &wrap("Debug view: the carried lineages as they would execute without the outer ENFORCE lineage. No guardrail hop, no enforced acceptance — use this to inspect the participants alone.", 96)));
        println!();
        if !lineage.is_empty() && !lineage.eq_ignore_ascii_case("all") {
            let Some(l) = find(&lineage) else {
                return Err(format!("exec: no carried lineage {lineage:?} (have {})", label_list()));
            };
            render_lineage_chain(l, pca);
            return Ok(());
        }
        for (idx, l) in carried.iter().enumerate() {
            if idx > 0 {
                println!();
            }
            render_lineage_chain(l, pca);
        }
        println!("{}", paint(C_DIM, "\nre-enable the guardrail: picdemo exec        (Sandboxed Execution, on by default)"));
        return Ok(());
    }

    // Drill-down selections.
    if lineage.eq_ignore_ascii_case("outer") {
        header("Outer ENFORCE lineage (the Sandboxed Execution)");
        render_outer_chain(&c.outer_chain, pca);
        return Ok(());
    }
    if lineage.eq_ignore_ascii_case("all") {
        header("Sandboxed Execution — every lineage");
        render_outer_chain(&c.outer_chain, pca);
        for l in &carried {
            println!();
            render_lineage_chain(l, pca);
        }
        return Ok(());
    }
    if !lineage.is_empty() {
        let Some(l) = find(&lineage) else {
            return Err(format!(
                "exec: no carried lineage {lineage:?} (have {}, or 'outer'/'all')",
                label_list()
            ));
        };
        header(&format!("Carried lineage {}", l.label));
        render_lineage_chain(l, pca);
        return Ok(());
    }

    // Default: the compact Sandboxed Execution diagram.
    render_exec_compact(&res);
    Ok(())
}

fn render_exec_compact(res: &pic::scenario::guardrail::GuardedResult) {
    let c = &res.permit;
    header("Sandboxed Execution — PIC carrying PIC");
    println!("{}", paint(C_DIM, &wrap("An outer PIC lineage with authority { ENFORCE } carries the inner Multi-Lineage Execution. Each guardrail is the next ordinary executor of that outer lineage; its signed outer PCA is the decision.", 96)));
    println!();

    println!(
        "{}  {}",
        paint(C_BOLD, "SANDBOXED EXECUTION"),
        paint(C_DIM, "· outer PIC lineage · authority { ENFORCE }")
    );
    println!(
        "  {}  {} {}",
        paint(C_CYAN, "PCA0-G"),
        paint(C_DIM, "origin — authorized sandbox origin"),
        paint(C_ACTOR, &res.origin.issuer)
    );
    println!("      {}", paint(C_DIM, "│ PoR"));
    println!("      {}", paint(C_CYAN, "▼"));
    println!(
        "  {}  {} {}   →  {}   →  {}",
        paint(C_CYAN, "PCA1-G"),
        paint(C_DIM, "guardrail"),
        paint(C_ACTOR, &c.trace.guardrail_executor),
        decision(&c.trace.decision.effect),
        c.mle.destination
    );
    println!("      {}", paint(C_DIM, "carries Multi-Lineage Execution:"));
    for (idx, p) in c.mle.participants.iter().enumerate() {
        let branch = if idx == c.mle.participants.len() - 1 {
            "└─"
        } else {
            "├─"
        };
        let tp = c.trace.carried_lineages.iter().find(|t| t.label == p.label);
        let auth = tp.map(|t| go_list(&t.authority)).unwrap_or_default();
        let scopes = tp.map(|t| go_list(&t.scopes)).unwrap_or_default();
        println!(
            "        {} {}  {}  {}  {}",
            paint(C_CYAN, branch),
            paint(C_BOLD, &p.label),
            paint(C_GREEN, &auth),
            paint(pic_yellow(), &scopes),
            paint(
                C_DIM,
                &format!("origin {} · {} PCAs", short(&p.chain[0].issuer), p.chain.len())
            )
        );
    }

    println!(
        "\n{} outer PCA1-G is the guardrail decision — no envelope, no second signature.",
        paint(C_GREEN, "✔")
    );
    println!("{}", paint(C_DIM, "\nexplore:"));
    println!("{}", paint(C_DIM, "  picdemo exec A                 one carried lineage (or B)"));
    println!("{}", paint(C_DIM, "  picdemo exec outer             the outer ENFORCE lineage"));
    println!("{}", paint(C_DIM, "  picdemo exec all --pca         every lineage, full signed PCAs"));
    println!("{}", paint(C_DIM, "  picdemo exec --no-guardrail    inner lineages only (debug)"));
}

fn render_outer_chain(chain: &[Pca], with_pca: bool) {
    println!("{}", paint(C_DIM, "authority { ENFORCE } continues one predecessor per hop; each guardrail signs its own outer PCA"));
    println!();
    for (idx, p) in chain.iter().enumerate() {
        if idx > 0 {
            println!("      {}", paint(C_DIM, "│ PoR"));
            println!("      {}", paint(C_CYAN, "▼"));
        }
        let name = format!("PCA{}-G", p.lineage_counter);
        if p.is_origin() {
            println!(
                "  {}  {}  {}  {}",
                paint(C_CYAN, &name),
                paint(C_BOLD, "origin"),
                paint(C_GREEN, &go_list(&p.invariants.operations)),
                paint(C_DIM, &format!("sandbox origin {}", short(&p.issuer)))
            );
        } else if let Some(por) = &p.proof_of_relationship {
            let verd = if por.request.enforcement_result.is_empty() {
                String::new()
            } else {
                format!("  {}", decision(&por.request.enforcement_result))
            };
            println!(
                "  {}  {}  {}{}",
                paint(C_CYAN, &name),
                paint(C_GREEN, &go_list(&p.invariants.operations)),
                paint(C_DIM, &format!("guardrail {}", short(&por.executor))),
                verd
            );
            println!(
                "      {}",
                paint(
                    C_DIM,
                    &format!(
                        "prevHash {}   request.operation {}",
                        short_hash(&por.previous_pca_hash),
                        por.request.operation
                    )
                )
            );
            if !por.request.multi_lineage_digest.is_empty() {
                println!(
                    "      {}",
                    paint(C_DIM, &format!("multiLineageDigest {}", short_hash(&por.request.multi_lineage_digest)))
                );
            }
            if let Some(ml) = &p.multi_lineage {
                let names: Vec<&str> = ml.carried_lineages.iter().map(|c| c.label.as_str()).collect();
                println!(
                    "      {}",
                    paint(C_DIM, &format!("carries carriedLineages [{}]", names.join(", ")))
                );
            }
        }
        if with_pca {
            println!("      {}", paint(C_DIM, "signed PCA ▾"));
            print_indented(p, "        ");
        }
    }
}

fn render_lineage_chain(l: &Lin, with_pca: bool) {
    println!(
        "{} {}  {}",
        paint(C_CYAN, "●"),
        paint(C_BOLD, &format!("carried lineage {}", l.label)),
        paint(C_DIM, &format!("origin {} · {} PCAs", l.origin, l.chain.len()))
    );
    if !l.grant.is_empty() || !l.scopes.is_empty() {
        println!(
            "  {}",
            paint(
                C_DIM,
                &format!(
                    "grant {} → scopes {} (enforcement input, not self-asserted)",
                    l.grant,
                    go_list(&l.scopes)
                )
            )
        );
    }
    println!();
    for (idx, p) in l.chain.iter().enumerate() {
        if idx > 0 {
            println!("      {}", paint(C_DIM, "│ PoR"));
            println!("      {}", paint(C_CYAN, "▼"));
        }
        let name = format!("PCA{}", p.lineage_counter);
        if p.is_origin() {
            println!(
                "  {}  {}  {}  {}",
                paint(C_CYAN, &name),
                paint(C_BOLD, "origin"),
                paint(C_GREEN, &go_list(&p.invariants.operations)),
                paint(C_DIM, &format!("issuer {}", short(&p.issuer)))
            );
        } else if let Some(por) = &p.proof_of_relationship {
            println!(
                "  {}  {}  {}",
                paint(C_CYAN, &name),
                paint(C_GREEN, &go_list(&p.invariants.operations)),
                paint(C_DIM, &format!("executor {}", short(&por.executor)))
            );
            println!(
                "      {}",
                paint(
                    C_DIM,
                    &format!(
                        "prevHash {}   request {} {}",
                        short_hash(&por.previous_pca_hash),
                        por.request.operation,
                        por.request.target
                    )
                )
            );
        }
        if with_pca {
            println!("      {}", paint(C_DIM, "signed PCA ▾"));
            print_indented(p, "        ");
        }
    }
}

fn decision(effect: &str) -> String {
    if effect == "permit" {
        paint(C_GREEN, "PERMIT")
    } else {
        paint("1;31", "DENY")
    }
}

/// Trims a DID to its last label for compact lines.
fn short(did: &str) -> String {
    let mut s = did;
    if let Some(i) = did.rfind(':') {
        s = &did[i + 1..];
    }
    if let Some(j) = s.find('#') {
        s = &s[..j];
    }
    s.to_string()
}

fn pic_yellow() -> &'static str {
    "33"
}

/// Serializes `v` to pretty JSON, prefixing every line.
fn print_indented<T: Serialize>(v: &T, prefix: &str) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => {
            for line in s.lines() {
                println!("{prefix}{line}");
            }
        }
        Err(_) => println!("{prefix}(marshal error)"),
    }
}
