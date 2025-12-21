use anyhow::Result;
use std::sync::Arc;
use super::{WorkloadIdentity, Request, Response, archive::Archive, registry::Registry};

pub struct Gateway {
    identity: Arc<WorkloadIdentity>,
    registry: Arc<Registry>,
}

impl Gateway {
    pub fn new(registry: Arc<Registry>) -> Result<Self> {
        let identity = registry.get("gateway")
            .ok_or_else(|| anyhow::anyhow!("gateway not found in registry"))?;
        Ok(Self { identity, registry })
    }
    
    /// Old method for compatibility
    pub fn load() -> Result<Self> {
        let registry = Arc::new(Registry::load()?);
        Self::new(registry)
    }

    async fn process(&self, request: Request) -> Result<Response> {
        let archive = Archive::new(self.registry.clone())?;
        archive.next(request).await
    }


    pub async fn next(&self, request: Request) -> Result<Response> {
        self.identity.print();
        println!("   → Forwarding to Archive");
        let response = self.process(request).await?;
        println!("   ← Received: {}", response.output_file);
        Ok(response)
    }
}