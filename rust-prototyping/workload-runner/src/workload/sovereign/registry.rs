use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use super::WorkloadIdentity;

/// Pre-loaded identities registry (in-memory)
pub struct Registry {
    identities: HashMap<String, Arc<WorkloadIdentity>>,
}

impl Registry {
    /// Load all identities into memory once
    pub fn load() -> Result<Self> {
        let names = [
            "sovereign-trustplane", 
            "sovereign-gateway", 
            "sovereign-archive", 
            "sovereign-storage"
        ];
        let mut identities = HashMap::new();
        
        for name in names {
            let identity = WorkloadIdentity::load(name)?;
            identities.insert(name.to_string(), Arc::new(identity));
        }
        
        println!("📂 Registry: loaded {} identities into memory", identities.len());
        
        Ok(Self { identities })
    }
    
    pub fn get(&self, name: &str) -> Option<Arc<WorkloadIdentity>> {
        self.identities.get(name).cloned()
    }
}