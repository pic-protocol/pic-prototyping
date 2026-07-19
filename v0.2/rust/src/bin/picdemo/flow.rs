// SPDX-License-Identifier: Apache-2.0
//
// Based on the Provenance Identity Continuity (PIC) Model created by Nicola Gallo.
// Conforms to the PIC Specification published and maintained by Nitro Agility S.r.l.

//! `picdemo flow`: one end-to-end execution flow rendered as colored ASCII boxes
//! and arrows (authority narrowing) with the signed PCA JSON per hop, ending in a
//! rejected rogue expansion. `--only-json` emits the whole flow as one JSON.

use crate::{header, paint, print_json, C_ACTOR, C_BOLD, C_CYAN, C_DIM, C_GREEN, C_RED, C_REJECT};
use chrono::{DateTime, Utc};
use pic::scenario::{FlowHop, RogueAttempt, World};
use serde::Serialize;

pub(crate) fn run_flow(now: DateTime<Utc>, only_json: bool) -> Result<(), String> {
    let w = World::new()?;
    let res = w.flow(now)?;

    if only_json {
        print_json(&res);
        return Ok(());
    }

    header("Execution flow — authority created once, narrowing hop by hop");
    println!("{}", paint(C_DIM, &wrap(&res.description, 92)));
    println!();
    for (i, h) in res.hops.iter().enumerate() {
        if i > 0 {
            println!("        {}", paint(C_DIM, "│"));
            println!("        {}", paint(C_CYAN, "▼"));
        }
        render_hop(h);
    }
    if let Some(r) = &res.rogue {
        render_rogue(r);
    }
    println!(
        "\n{} chain verified end to end — authority at tip = {}",
        paint(C_GREEN, "✔"),
        paint(C_GREEN, &go_vec(&res.tip_authority))
    );
    println!(
        "{}",
        paint(
            C_DIM,
            "each box's JSON above is the real signed PCA that hop produced; run with --only-json | jq for the machine-readable flow."
        )
    );
    Ok(())
}

fn render_hop(h: &FlowHop) {
    println!(
        "{} {}  {}  {} {}",
        paint(C_CYAN, "●"),
        paint(C_BOLD, &format!("hop {}", h.index)),
        paint(C_ACTOR, &h.actor),
        paint(C_DIM, "—"),
        h.action
    );

    let mut line = format!("    authority: {}", paint(C_GREEN, &go_vec(&h.authority)));
    if !h.dropped.is_empty() {
        line += &format!(
            "   {}",
            paint(C_RED, &format!("dropped: {}", h.dropped.join(", ")))
        );
    }
    println!("{line}");

    if !h.previous_hash.is_empty() {
        println!(
            "    {}",
            paint(
                C_DIM,
                &format!(
                    "counter {}   prevHash {}",
                    h.lineage_counter,
                    short_hash(&h.previous_hash)
                )
            )
        );
    } else {
        println!(
            "    {}",
            paint(
                C_DIM,
                &format!("counter {}   origin (no predecessor)", h.lineage_counter)
            )
        );
    }
    println!(
        "    {}",
        paint(C_DIM, &format!("generates PCA{} (signed) ▾", h.index))
    );
    print_indented_json(&h.generates, "      ");
}

fn render_rogue(r: &RogueAttempt) {
    println!("        {}", paint(C_DIM, "│"));
    println!("        {}", paint(C_REJECT, "▼"));
    println!(
        "{} {}  {}  {} tries to re-add dropped authority",
        paint(C_REJECT, "✗"),
        paint(C_BOLD, "hop 5 (rogue)"),
        paint(C_ACTOR, &r.actor),
        paint(C_DIM, "—")
    );
    println!(
        "    tried: {}   {}",
        paint(C_REJECT, &go_vec(&r.tried)),
        paint(
            C_REJECT,
            &bool_str(
                r.rejected,
                "→ REJECTED (non-expansion)",
                "→ accepted (BUG!)"
            )
        )
    );
    println!("    {}", paint(C_DIM, &format!("reason: {}", r.reason)));
}

fn print_indented_json<T: Serialize>(v: &T, prefix: &str) {
    match serde_json::to_string_pretty(v) {
        Ok(s) => {
            let with_prefix = s.replace('\n', &format!("\n{prefix}"));
            println!("{prefix}{with_prefix}");
        }
        Err(_) => println!("{prefix}(marshal error)"),
    }
}

fn short_hash(h: &str) -> String {
    if h.len() <= 21 {
        h.to_string()
    } else {
        format!("{}…", &h[..21])
    }
}

fn bool_str(b: bool, yes: &str, no: &str) -> String {
    if b {
        yes.to_string()
    } else {
        no.to_string()
    }
}

/// Formats a slice the way Go's `%v` prints `[]string`: `[a b c]`.
fn go_vec(v: &[String]) -> String {
    format!("[{}]", v.join(" "))
}

/// Soft-wraps `s` to `width` columns for the intro line.
fn wrap(s: &str, width: usize) -> String {
    let mut out = String::new();
    let mut col = 0usize;
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
