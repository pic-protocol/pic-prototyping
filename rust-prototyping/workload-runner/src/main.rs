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
use std::sync::Arc;
use std::time::Instant;
use workload_runner::workload::sovereign::{gateway::Gateway, registry::Registry, Request};

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
        pca_bytes: None, // Origin - no PCA yet
    };

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("🔗 Starting PIC chain execution");
    println!("   ops: [read:/user/*, write:/user/*]");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();

    let (response, timing) = gateway.next(request).await?;

    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ Execution chain completed!");
    println!("   Output: {}", response.output_file);
    println!("   Data: {}", response.data);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    timing.print_summary();

    Ok(())
}