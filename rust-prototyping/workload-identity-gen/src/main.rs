use anyhow::Result;

mod identity_gen;

use identity_gen::{trustplane_gen, workload_gen, WorkloadIdentityType};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Workload Identity Generator\n");

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PIC Identity Model
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //
    // VC/DID are NOT required. CAT accepts any PoI/PoP: SPIFFE, K8s tokens,
    // cloud tokens, X.509, or W3C VC.
    //
    // DID/VC is interesting for mapping workloads to decentralized AI agent
    // registries. PCA uses CBOR/COSE for compact binary encoding.
    //
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Demo: two federations, each owns its domain
    //
    // - sovereign.example: Enterprise on-prem (SPIFFE)
    // - nomad.example: Cloud-native (Kubernetes)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // Federation: sovereign (on-prem, SPIFFE)
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🌐 Federation: sovereign\n");

    let sovereign_tp = trustplane_gen(
        "sovereign-trustplane",
        "trustplane.sovereign.example",
    ).await?;

    println!();

    for workload in ["gateway", "archive", "storage"] {
        let identity_type = WorkloadIdentityType::Spiffe {
            spiffe_id: format!("spiffe://sovereign.example/{}", workload),
        };

        workload_gen(
            &format!("sovereign-{}", workload),
            &format!("{}.sovereign.example", workload),
            identity_type,
            &sovereign_tp,
        ).await?;
        println!();
    }

    // Federation: nomad (cloud, Kubernetes)
    // Audit service: external, immutable, compliance-ready
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🌐 Federation: nomad\n");

    let nomad_tp = trustplane_gen(
        "nomad-trustplane",
        "trustplane.nomad.example",
    ).await?;

    println!();

    let identity_type = WorkloadIdentityType::Kubernetes {
        namespace: "compliance".to_string(),
        service_account: "audit-logger-sa".to_string(),
    };

    workload_gen(
        "nomad-audit",
        "audit.nomad.example",
        identity_type,
        &nomad_tp,
    ).await?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ Done!");
    println!();
    println!("   sovereign: Gateway → Archive → Storage");
    println!("                                    │");
    println!("                                    └──→ nomad: Audit");
    
    Ok(())
}