use anyhow::Result;

mod identity_gen;

use identity_gen::{identity_gen, DidMethod, Role};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🔐 Workload Identity Generator\n");

    // TrustPlane - Trust Anchor (self-issued)
    let trustplane = identity_gen(
        "trustplane",
        DidMethod::Key,
        None,
        Role::TrustAnchor,
        None,
    ).await?;

    // Gateway - Executor (issued by TrustPlane)
    identity_gen(
        "gateway",
        DidMethod::Web,
        Some("gateway.example"),
        Role::Executor,
        Some(&trustplane),
    ).await?;

    // Archive - Executor (issued by TrustPlane)
    identity_gen(
        "archive",
        DidMethod::Web,
        Some("archive.example"),
        Role::Executor,
        Some(&trustplane),
    ).await?;

    // Storage - Executor (issued by TrustPlane)
    identity_gen(
        "storage",
        DidMethod::Web,
        Some("storage.example"),
        Role::Executor,
        Some(&trustplane),
    ).await?;

    println!("\n✅ Done!");
    Ok(())
}