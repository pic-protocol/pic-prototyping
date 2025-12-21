use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use tokio::runtime::Runtime;
use std::sync::Arc;
use workload_runner::workload::{
    gateway::Gateway,
    registry::Registry,
    Request, 
    Response
};

/// Benchmark: pre-loaded registry (no disk I/O during execution)
fn bench_with_registry(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    // Load once, reuse
    let registry = Arc::new(Registry::load().expect("failed to load registry"));
    let gateway = Gateway::new(registry).expect("failed to create gateway");

    c.bench_function("chain/full_preloaded", |b| {
        b.iter(|| {
            let request = Request { content: "test".to_string() };
            let _: Response = rt.block_on(async {
                gateway.next(request).await.unwrap()
            });
        })
    });
}

/// Benchmark: cold start (load from disk each time)
fn bench_cold_start(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("chain/full_cold", |b| {
        b.iter(|| {
            let gateway = Gateway::load().unwrap();
            let request = Request { content: "test".to_string() };
            let _: Response = rt.block_on(async {
                gateway.next(request).await.unwrap()
            });
        })
    });
}

/// Benchmark: registry load time
fn bench_registry_load(c: &mut Criterion) {
    c.bench_function("registry/load", |b| {
        b.iter(|| Registry::load().unwrap())
    });
}

/// Benchmark: payload sizes with preloaded registry
fn bench_payload_preloaded(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let registry = Arc::new(Registry::load().unwrap());
    let gateway = Gateway::new(registry).unwrap();
    
    let mut group = c.benchmark_group("payload_preloaded");
    
    for size in [10, 100, 1_000, 10_000] {
        group.bench_with_input(
            BenchmarkId::new("bytes", size),
            &size,
            |b, &size| {
                let content = "x".repeat(size);
                b.iter(|| {
                    let request = Request { content: content.clone() };
                    let _: Response = rt.block_on(async {
                        gateway.next(request).await.unwrap()
                    });
                })
            },
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_with_registry,
    bench_cold_start,
    bench_registry_load,
    bench_payload_preloaded,
);
criterion_main!(benches);
