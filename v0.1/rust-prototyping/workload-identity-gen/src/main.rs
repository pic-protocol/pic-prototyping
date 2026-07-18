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

use anyhow::Result;

mod identity_gen;

use identity_gen::{trustplane_gen, workload_gen, WorkloadIdentity, WorkloadIdentityType};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Workload Identity Generator\n");

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PIC Identity Model
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //
    // VC/DID are NOT required. CAT accepts any attestation: SPIFFE, K8s tokens,
    // cloud tokens, X.509, or W3C VC/VP.
    //
    // DID/VC is interesting for mapping workloads to decentralized AI agent
    // registries. PCA uses CBOR/COSE for compact binary encoding.
    //
    // VP signature by holder IS the Proof of Possession (PoP implicit).
    //
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // Demo: two federations, each owns its domain
    //
    // - Sovereign Ltd: Enterprise on-prem (SPIFFE)
    // - Nomad Ltd: Cloud-native (Kubernetes)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    // Federation: Sovereign Ltd (on-prem, SPIFFE)
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🌐 Federation: Sovereign Ltd\n");

    let sovereign_tp = trustplane_gen(
        "sovereign-trustplane",
        "trustplane.sovereign.example",
        "Sovereign Ltd",
    )
    .await?;

    println!();

    for workload in ["gateway", "archive", "storage"] {
        let identity = WorkloadIdentity {
            organization: "Sovereign Ltd".to_string(),
            identity_type: WorkloadIdentityType::Spiffe {
                spiffe_id: format!("spiffe://sovereign.example/ns/prod/sa/{}", workload),
            },
        };

        workload_gen(
            &format!("sovereign-{}", workload),
            &format!("{}.sovereign.example", workload),
            identity,
            &sovereign_tp,
            Some(&format!("pcc-nonce-sovereign-{}", workload)),
        )
        .await?;
        println!();
    }

    // Federation: Nomad Ltd (cloud, Kubernetes)
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🌐 Federation: Nomad Ltd\n");

    let nomad_tp =
        trustplane_gen("nomad-trustplane", "trustplane.nomad.example", "Nomad Ltd").await?;

    println!();

    // Audit service: external, immutable, compliance-ready
    let audit_identity = WorkloadIdentity {
        organization: "Nomad Ltd".to_string(),
        identity_type: WorkloadIdentityType::Kubernetes {
            namespace: "compliance".to_string(),
            service_account: "audit-logger-sa".to_string(),
        },
    };

    workload_gen(
        "nomad-audit",
        "audit.nomad.example",
        audit_identity,
        &nomad_tp,
        Some("pcc-nonce-nomad-audit"),
    )
    .await?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ Done!");
    println!();
    println!("Generated files:");
    println!("  - credential.vc.json   (VC issued by TrustPlane)");
    println!("  - presentation.vp.json (VP with implicit PoP)");
    println!("  - private.jwk / public.jwk");
    println!("  - did.json");
    println!();
    println!("PIC chain example:");
    println!();
    println!("   Sovereign Ltd                          Nomad Ltd");
    println!("   ────────────                          ─────────");
    println!("   Gateway → Archive → Storage ──────→ Audit");
    println!("     PCA₀      PCA₁      PCA₂            PCA₃");
    println!();
    println!("   Each executor uses VP as attestation (PoP implicit)");

    Ok(())
}
