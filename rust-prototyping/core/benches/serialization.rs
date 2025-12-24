use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use core::{Pca, PcaPayload, Executor, ExecutorId, PrevExecutor, Provenance};

fn sample_pca(ops_count: usize) -> Pca {
    let ops: Vec<String> = (0..ops_count)
        .map(|i| format!("read:/resource/{}", i))
        .collect();

    Pca {
        issuer_id: "https://cat.example.com".into(),
        issuer_sig: vec![0u8; 64],
        payload: PcaPayload {
            p_0: "https://idp.example.com/users/alice".into(),
            ops,
            executor: Executor {
                id: ExecutorId { service: "service-b".into() },
                public_key: vec![0u8; 32],
                key_type: "Ed25519".into(),
            },
            prev_executor: Some(PrevExecutor {
                public_key: vec![0u8; 32],
                key_type: "Ed25519".into(),
            }),
            provenance: Provenance {
                prev: "sha256:abc123def456".into(),
                hop: 2,
            },
        },
    }
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    for ops_count in [1, 5, 10] {
        let pca = sample_pca(ops_count);
        
        group.throughput(Throughput::Elements(1));
        
        group.bench_with_input(
            BenchmarkId::new("cbor", ops_count),
            &pca,
            |b, pca| b.iter(|| pca.to_cbor().unwrap()),
        );

        group.bench_with_input(
            BenchmarkId::new("json", ops_count),
            &pca,
            |b, pca| b.iter(|| pca.to_json().unwrap()),
        );
    }

    group.finish();
}

fn bench_deserialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("deserialize");

    for ops_count in [1, 5, 10] {
        let pca = sample_pca(ops_count);
        let cbor = pca.to_cbor().unwrap();
        let json = pca.to_json().unwrap();

        group.throughput(Throughput::Bytes(cbor.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("cbor", ops_count),
            &cbor,
            |b, cbor| b.iter(|| Pca::from_cbor(cbor).unwrap()),
        );

        group.bench_with_input(
            BenchmarkId::new("json", ops_count),
            &json,
            |b, json| b.iter(|| Pca::from_json(json).unwrap()),
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for ops_count in [1, 5, 10] {
        let pca = sample_pca(ops_count);

        group.bench_with_input(
            BenchmarkId::new("cbor", ops_count),
            &pca,
            |b, pca| {
                b.iter(|| {
                    let bytes = pca.to_cbor().unwrap();
                    Pca::from_cbor(&bytes).unwrap()
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("json", ops_count),
            &pca,
            |b, pca| {
                b.iter(|| {
                    let s = pca.to_json().unwrap();
                    Pca::from_json(&s).unwrap()
                })
            },
        );
    }

    group.finish();
}

fn bench_size_comparison(c: &mut Criterion) {
    println!("\n📊 Size comparison:");
    println!("─────────────────────────────────────────");
    
    for ops_count in [1, 5, 10] {
        let pca = sample_pca(ops_count);
        let cbor = pca.to_cbor().unwrap();
        let json = pca.to_json().unwrap();
        
        println!(
            "ops={:2}: CBOR={:4} bytes, JSON={:4} bytes, savings={:.1}%",
            ops_count,
            cbor.len(),
            json.len(),
            (1.0 - cbor.len() as f64 / json.len() as f64) * 100.0
        );
    }
    println!("─────────────────────────────────────────\n");

    // Dummy bench
    c.bench_function("size/noop", |b| b.iter(|| 1 + 1));
}

criterion_group!(
    benches,
    bench_size_comparison,
    bench_serialization,
    bench_deserialization,
    bench_roundtrip,
);
criterion_main!(benches);
