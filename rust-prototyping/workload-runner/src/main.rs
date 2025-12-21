use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;
use workload_runner::workload::{gateway::Gateway, registry::Registry, Request};

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 PIC Workload Runner\n");

    // Pre-load all identities once
    let start_load = Instant::now();
    let registry = Arc::new(Registry::load()?);
    println!("   ⏱️  Load time: {:?}\n", start_load.elapsed());

    let gateway = Gateway::new(registry)?;
    
    let request = Request {
        content: "Hello from Alice".to_string(),
    };

    let start = Instant::now();
    let response = gateway.next(request).await?;
    let elapsed = start.elapsed();

    println!("\n✅ Execution chain completed!");
    println!("   Output: {}", response.output_file);
    println!("   Data: {}", response.data);
    println!("   ⏱️  Execution time: {:?}", elapsed);
    
    Ok(())
}