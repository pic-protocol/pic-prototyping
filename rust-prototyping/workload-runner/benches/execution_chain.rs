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

//! PIC Chain Execution Benchmark
//!
//! Measures timing breakdown per hop: PCA deserialization, PoC creation,
//! CAT calls, and business logic.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use std::sync::Arc;
use tokio::runtime::Runtime;
use workload_runner::workload::sovereign::{gateway::Gateway, registry::Registry, Request};

/// Print clear benchmark summary
fn print_benchmark_summary(
    name: &str,
    total_ms: f64,
    chains: usize,
    hops_per_chain: usize,
    avg_pca_bytes: usize,
    avg_poc_bytes: usize,
) {
    let per_chain_us = (total_ms * 1000.0) / chains as f64;
    let per_hop_us = per_chain_us / hops_per_chain as f64;
    
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📊 {}", name);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("   Chains executed:     {}", chains);
    println!("   Hops per chain:      {}", hops_per_chain);
    println!("   Total hops:          {}", chains * hops_per_chain);
    println!();
    println!("   ⏱️  Total time:        {:.2} ms", total_ms);
    println!("   ⏱️  Per chain:         {:.2} µs", per_chain_us);
    println!("   ⏱️  Per hop:           {:.2} µs", per_hop_us);
    println!();
    println!("   📦 Avg PCA size:       {} bytes", avg_pca_bytes);
    println!("   📦 Avg PoC size:       {} bytes", avg_poc_bytes);
    println!("   📦 Avg total/hop:      {} bytes", avg_pca_bytes + avg_poc_bytes);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
}

fn bench_pic_chain(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());
    let gateway = Gateway::new(registry).unwrap();

    // Warmup run
    let request = Request {
        content: "warmup".to_string(),
        pca_bytes: None,
    };
    rt.block_on(async { gateway.next(request).await.unwrap() });

    println!();
    println!("🚀 PIC Chain Benchmark - Full Verification Mode");
    println!("   (signature verification, monotonicity check, temporal constraints)");

    let mut group = c.benchmark_group("pic_chain");

    group.bench_function("single_chain", |b| {
        b.iter(|| {
            let request = Request {
                content: "bench".to_string(),
                pca_bytes: None,
            };
            rt.block_on(async { gateway.next(request).await.unwrap() })
        })
    });

    group.finish();
}

fn bench_chain_scaling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());
    let gateway = Gateway::new(registry).unwrap();

    let hops_per_chain = 2; // Gateway -> Archive -> Storage

    let mut group = c.benchmark_group("chain_scaling");

    for num_chains in [1, 5, 10, 20] {
        group.bench_with_input(
            BenchmarkId::new("chains", num_chains),
            &num_chains,
            |b, &chains| {
                b.iter(|| {
                    for _ in 0..chains {
                        let request = Request {
                            content: "bench".to_string(),
                            pca_bytes: None,
                        };
                        rt.block_on(async { gateway.next(request).await.unwrap() });
                    }
                })
            },
        );
    }

    group.finish();

    // Manual timing for clear output with sizes
    println!();
    println!("📈 Scaling Summary (with message sizes)");
    println!("========================================");
    
    for num_chains in [1, 5, 10, 20] {
        let start = std::time::Instant::now();
        let iterations = 50;
        
        let mut total_pca_bytes = 0usize;
        let mut total_poc_bytes = 0usize;
        let mut count = 0usize;
        
        for _ in 0..iterations {
            for _ in 0..num_chains {
                let request = Request {
                    content: "bench".to_string(),
                    pca_bytes: None,
                };
                let (_, timing) = rt.block_on(async { gateway.next(request).await.unwrap() });
                
                // Collect sizes from timing
                total_pca_bytes += timing.initial_pca_size;
                for hop in &timing.hops {
                    total_poc_bytes += hop.poc_size;
                }
                count += 1;
            }
        }
        
        let total = start.elapsed();
        let avg_ms = total.as_secs_f64() * 1000.0 / iterations as f64;
        
        let avg_pca = if count > 0 { total_pca_bytes / count } else { 0 };
        let avg_poc = if count > 0 { total_poc_bytes / count } else { 0 };
        
        print_benchmark_summary(
            &format!("{} chain(s) sequential", num_chains),
            avg_ms,
            num_chains,
            hops_per_chain,
            avg_pca,
            avg_poc,
        );
    }
}

criterion_group!(benches, bench_pic_chain, bench_chain_scaling);
criterion_main!(benches);