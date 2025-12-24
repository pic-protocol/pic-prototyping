use anyhow::Result;
use std::sync::Arc;
use super::{WorkloadIdentity, Request, Response, storage::Storage, registry::Registry};

pub struct Archive {
    identity: Arc<WorkloadIdentity>,
    registry: Arc<Registry>,
}

impl Archive {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry.get("sovereign-archive")
            .ok_or_else(|| anyhow::anyhow!("sovereign-archive not found in registry"))?;
        Ok(Self { identity, registry })
    }
    
    pub fn load() -> Result<Self> {
        let registry = Arc::new(Registry::load()?);
        Self::new(registry)
    }

    async fn process(&self, request: Request) -> Result<Response> {
        let storage = Storage::new(self.registry.clone())?;
        storage.next(request).await
    }

    pub async fn next(&self, request: Request) -> Result<Response> {
        self.identity.print();
        println!("   → Forwarding to Storage");
        let response = self.process(request).await?;
        println!("   ← Received: {}", response.output_file);
        Ok(response)
    }
}