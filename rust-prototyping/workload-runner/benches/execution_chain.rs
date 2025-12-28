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
use workload_runner::workload::instrumentation::ChainTiming;
use workload_runner::workload::sovereign::{gateway::Gateway, registry::Registry, Request};

fn print_timing_breakdown() {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().expect("failed to load registry"));
    let gateway = Gateway::new(registry).expect("failed to create gateway");

    let iterations = 100;
    let mut samples: Vec<ChainTiming> = Vec::with_capacity(iterations);

    println!();
    println!("Collecting {} samples...", iterations);

    for _ in 0..iterations {
        let request = Request {
            content: "benchmark".to_string(),
            pca_bytes: None,
        };
        let (_, timing) = rt.block_on(gateway.next(request)).unwrap();
        samples.push(timing);
    }

    let avg_total_ns: f64 =
        samples.iter().map(|t| t.total.as_nanos() as f64).sum::<f64>() / iterations as f64;

    let avg_initial_create_ns: f64 = samples
        .iter()
        .map(|t| t.initial_pca_create.as_nanos() as f64)
        .sum::<f64>()
        / iterations as f64;

    let avg_initial_sign_ns: f64 = samples
        .iter()
        .map(|t| t.initial_pca_sign.as_nanos() as f64)
        .sum::<f64>()
        / iterations as f64;

    println!();
    println!("PIC Chain Benchmark Results ({} iterations)", iterations);
    println!("=============================================");
    println!();
    println!(
        "Average total:        {:>10.2} µs ({:.2} ms)",
        avg_total_ns / 1000.0,
        avg_total_ns / 1_000_000.0
    );
    println!(
        "Initial PCA create:   {:>10.2} µs",
        avg_initial_create_ns / 1000.0
    );
    println!(
        "Initial PCA sign:     {:>10.2} µs",
        avg_initial_sign_ns / 1000.0
    );
    println!();

    if let Some(first) = samples.first() {
        for (i, _) in first.hops.iter().enumerate() {
            let avg_deser: f64 = samples
                .iter()
                .filter_map(|t| t.hops.get(i))
                .map(|h| h.pca_deserialize.as_nanos() as f64)
                .sum::<f64>()
                / iterations as f64;

            let avg_poc_create: f64 = samples
                .iter()
                .filter_map(|t| t.hops.get(i))
                .map(|h| h.poc_create.as_nanos() as f64)
                .sum::<f64>()
                / iterations as f64;

            let avg_poc_ser: f64 = samples
                .iter()
                .filter_map(|t| t.hops.get(i))
                .map(|h| h.poc_serialize.as_nanos() as f64)
                .sum::<f64>()
                / iterations as f64;

            let avg_cat: f64 = samples
                .iter()
                .filter_map(|t| t.hops.get(i))
                .map(|h| h.cat_call.as_nanos() as f64)
                .sum::<f64>()
                / iterations as f64;

            let avg_logic: f64 = samples
                .iter()
                .filter_map(|t| t.hops.get(i))
                .map(|h| h.business_logic.as_nanos() as f64)
                .sum::<f64>()
                / iterations as f64;

            let avg_hop_total: f64 = samples
                .iter()
                .filter_map(|t| t.hops.get(i))
                .map(|h| h.total.as_nanos() as f64)
                .sum::<f64>()
                / iterations as f64;

            let hop_name = &first.hops[i].hop_name;
            println!("Hop {} ({}):", i + 1, hop_name);
            println!("  PCA deserialize:    {:>10.2} µs", avg_deser / 1000.0);
            println!("  PoC create:         {:>10.2} µs", avg_poc_create / 1000.0);
            println!("  PoC serialize:      {:>10.2} µs", avg_poc_ser / 1000.0);
            println!("  CAT call:           {:>10.2} µs", avg_cat / 1000.0);
            println!("  Business logic:     {:>10.2} µs", avg_logic / 1000.0);
            println!("  ─────────────────────────────────");
            println!("  Hop total:          {:>10.2} µs", avg_hop_total / 1000.0);
            println!();
        }
    }

    println!("Detailed breakdown (first sample):");
    if let Some(sample) = samples.first() {
        sample.print_summary();
    }
}

fn bench_pic_chain(c: &mut Criterion) {
    print_timing_breakdown();

    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());
    let gateway = Gateway::new(registry).unwrap();

    let mut group = c.benchmark_group("pic_chain");

    group.bench_function("full_chain", |b| {
        b.iter(|| {
            let request = Request {
                content: "test".to_string(),
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

    let mut group = c.benchmark_group("chain_scaling");

    for iterations in [1, 5, 10] {
        group.bench_with_input(
            BenchmarkId::new("iterations", iterations),
            &iterations,
            |b, &iters| {
                b.iter(|| {
                    for _ in 0..iters {
                        let request = Request {
                            content: "test".to_string(),
                            pca_bytes: None,
                        };
                        rt.block_on(async { gateway.next(request.clone()).await.unwrap() });
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_pic_chain, bench_chain_scaling);
criterion_main!(benches);