use anyhow::Result;
use std::sync::Arc;
use super::{WorkloadIdentity, Request, Response, registry::Registry};

pub struct Storage {
    identity: Arc<WorkloadIdentity>,
}

impl Storage {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry.get("storage")
            .ok_or_else(|| anyhow::anyhow!("storage not found in registry"))?;
        Ok(Self { identity })
    }
    
    pub fn load() -> Result<Self> {
        let registry = Arc::new(Registry::load()?);
        Self::new(registry)
    }

    async fn process(&self, request: Request) -> Result<Response> {
        let output_file = format!("/user/output_{}.txt", timestamp());
        let data = format!("Processed: {}", request.content);
        Ok(Response { output_file, data })
    }

    pub async fn next(&self, request: Request) -> Result<Response> {
        self.identity.print();
        println!("   → Processing request");
        let response = self.process(request).await?;
        println!("   ✓ Written: {}", response.output_file);
        Ok(response)
    }
}

fn timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}