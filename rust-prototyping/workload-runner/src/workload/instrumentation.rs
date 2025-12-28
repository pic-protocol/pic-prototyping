/*
 * Copyright Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Instrumentation for PIC chain execution timing.

use std::time::{Duration, Instant};

/// Timing for a single hop in the PIC chain.
#[derive(Debug, Clone, Default)]
pub struct HopTiming {
    pub hop_name: String,
    pub hop_index: u32,
    pub pca_deserialize: Duration,
    pub poc_create: Duration,
    pub poc_serialize: Duration,
    pub cat_call: Duration,
    pub pca_received_size: usize,
    pub pca_new_size: usize,
    pub poc_size: usize,
    pub business_logic: Duration,
    pub total: Duration,
}

/// Timing for the entire chain execution.
#[derive(Debug, Clone, Default)]
pub struct ChainTiming {
    pub hops: Vec<HopTiming>,
    pub total: Duration,
    pub initial_pca_create: Duration,
    pub initial_pca_sign: Duration,
    pub initial_pca_size: usize,
}

impl ChainTiming {
    pub fn print_summary(&self) {
        println!();
        println!("PIC Chain Execution Timing");
        println!("==========================");
        println!();

        // Initial PCA
        println!("INITIAL PCA (PCA_0)");
        println!("    Create              {}", format_duration(self.initial_pca_create));
        println!("    Sign                {}", format_duration(self.initial_pca_sign));
        println!("    Size                {} bytes", self.initial_pca_size);
        println!();

        // Per-hop breakdown
        println!("PER-HOP BREAKDOWN");
        println!();

        for hop in &self.hops {
            println!("  {} (hop {})", hop.hop_name.to_uppercase(), hop.hop_index);
            println!("    PCA received        {} bytes", hop.pca_received_size);
            println!("    PCA deserialize     {}", format_duration(hop.pca_deserialize));
            println!("    PoC create          {}", format_duration(hop.poc_create));
            println!("    PoC serialize       {}", format_duration(hop.poc_serialize));
            println!("    PoC size            {} bytes", hop.poc_size);
            println!("    CAT call            {}", format_duration(hop.cat_call));
            println!("    PCA new size        {} bytes", hop.pca_new_size);
            println!("    Business logic      {}", format_duration(hop.business_logic));
            println!("    ─────────────────────────────────");
            println!("    HOP TOTAL           {}", format_duration(hop.total));
            println!();
        }

        // Summary
        println!("SUMMARY");
        println!("    Total hops          {}", self.hops.len());
        println!("    Total time          {}", format_duration(self.total));
        if !self.hops.is_empty() {
            println!("    Avg per hop         {}", format_duration(self.total / self.hops.len() as u32));
        }
        println!();

        // Breakdown by category
        let total_pca_deser: Duration = self.hops.iter().map(|h| h.pca_deserialize).sum();
        let total_poc_create: Duration = self.hops.iter().map(|h| h.poc_create).sum();
        let total_poc_ser: Duration = self.hops.iter().map(|h| h.poc_serialize).sum();
        let total_cat: Duration = self.hops.iter().map(|h| h.cat_call).sum();
        let total_logic: Duration = self.hops.iter().map(|h| h.business_logic).sum();

        println!("TIME BY CATEGORY (all hops)");
        println!("    PCA deserialize     {} ({:.1}%)", format_duration(total_pca_deser), pct(total_pca_deser, self.total));
        println!("    PoC create          {} ({:.1}%)", format_duration(total_poc_create), pct(total_poc_create, self.total));
        println!("    PoC serialize       {} ({:.1}%)", format_duration(total_poc_ser), pct(total_poc_ser, self.total));
        println!("    CAT call            {} ({:.1}%)", format_duration(total_cat), pct(total_cat, self.total));
        println!("    Business logic      {} ({:.1}%)", format_duration(total_logic), pct(total_logic, self.total));
        println!();

        // Size summary
        let total_pca_size: usize = self.hops.iter().map(|h| h.pca_new_size).sum();
        let total_poc_size: usize = self.hops.iter().map(|h| h.poc_size).sum();

        println!("SIZE SUMMARY");
        println!("    Initial PCA         {} bytes", self.initial_pca_size);
        println!("    Total PCA (chain)   {} bytes", total_pca_size);
        println!("    Total PoC (chain)   {} bytes", total_poc_size);
        println!("    Total bytes moved   {} bytes", self.initial_pca_size + total_pca_size + total_poc_size);
        println!();
    }
}

/// Timer helper for measuring operations.
pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn start() -> Self {
        Self { start: Instant::now() }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    pub fn stop(self) -> Duration {
        self.start.elapsed()
    }
}

fn format_duration(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns >= 1_000_000_000 {
        format!("{:.2} s", ns as f64 / 1_000_000_000.0)
    } else if ns >= 1_000_000 {
        format!("{:.2} ms", ns as f64 / 1_000_000.0)
    } else if ns >= 1_000 {
        format!("{:.2} µs", ns as f64 / 1_000.0)
    } else {
        format!("{} ns", ns)
    }
}

fn pct(part: Duration, total: Duration) -> f64 {
    if total.as_nanos() == 0 {
        0.0
    } else {
        (part.as_nanos() as f64 / total.as_nanos() as f64) * 100.0
    }
}