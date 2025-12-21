//! Core library for PIC (Provenance Identity Continuity) model
//! 
//! This crate provides shared types and traits used across the PIC implementation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors that can occur in PIC operations
#[derive(Error, Debug)]
pub enum PicError {
    #[error("Authority monotonicity violation: ops_{0} ⊄ ops_{1}")]
    MonotonicityViolation(usize, usize),

    #[error("Origin immutability violation: p_0 changed from {0} to {1}")]
    OriginViolation(String, String),

    #[error("Executor continuity failed at hop {0}")]
    ExecutorContinuityFailed(usize),

    #[error("Temporal constraint violated")]
    TemporalViolation,

    #[error("Contextual constraint violated")]
    ContextualViolation,

    #[error("Invalid PCA bundle: {0}")]
    InvalidBundle(String),
}

/// Result type for PIC operations
pub type PicResult<T> = Result<T, PicError>;

/// Represents a DID (Decentralized Identifier)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Did(pub String);

impl Did {
    pub fn new(did: impl Into<String>) -> Self {
        Self(did.into())
    }

    pub fn method(&self) -> Option<&str> {
        self.0.strip_prefix("did:")?.split(':').next()
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents an operation in PIC model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Operation(pub String);

/// Represents a resource in PIC model
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Resource(pub String);

/// A privilege is a pair (operation, resource)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Privilege {
    pub operation: Operation,
    pub resource: Resource,
}

/// Authority set - ops_i in PIC model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthoritySet {
    pub privileges: Vec<Privilege>,
}

impl AuthoritySet {
    /// Check if self is a subset of other (monotonicity check)
    pub fn is_subset_of(&self, other: &AuthoritySet) -> bool {
        self.privileges.iter().all(|p| other.privileges.contains(p))
    }
}

/// Execution hop in PIC model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionHop {
    /// Hop index
    pub index: usize,
    /// Origin subject (immutable p_0)
    pub origin: Did,
    /// Current executor
    pub executor: Did,
    /// Previous executor (for continuity verification)
    pub previous_executor: Option<Did>,
    /// Authority at this hop
    pub authority: AuthoritySet,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_did_method() {
        let did = Did::new("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        assert_eq!(did.method(), Some("key"));

        let did_web = Did::new("did:web:example.com");
        assert_eq!(did_web.method(), Some("web"));
    }

    #[test]
    fn test_authority_subset() {
        let ops_0 = AuthoritySet {
            privileges: vec![
                Privilege {
                    operation: Operation("read".into()),
                    resource: Resource("*".into()),
                },
                Privilege {
                    operation: Operation("write".into()),
                    resource: Resource("*".into()),
                },
            ],
        };

        let ops_1 = AuthoritySet {
            privileges: vec![Privilege {
                operation: Operation("read".into()),
                resource: Resource("*".into()),
            }],
        };

        // ops_1 ⊆ ops_0 (monotonicity holds)
        assert!(ops_1.is_subset_of(&ops_0));

        // ops_0 ⊄ ops_1 (reverse doesn't hold)
        assert!(!ops_0.is_subset_of(&ops_1));
    }
}
