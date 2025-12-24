//! PCA (Provenance Causal Authority) model
//!
//! CBOR serialization for efficient binary encoding.

use serde::{Deserialize, Serialize};

/// Executor ID - simple key-value
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutorId {
    pub service: String,
}

/// Executor with cryptographic identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Executor {
    pub id: ExecutorId,
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub key_type: String,
}

/// Previous executor reference
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrevExecutor {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    pub key_type: String,
}

/// Provenance chain link
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Provenance {
    pub prev: String,  // "sha256:..." or empty
    pub hop: u32,
}

/// PCA Payload
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PcaPayload {
    pub p_0: String,
    pub ops: Vec<String>,
    pub executor: Executor,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_executor: Option<PrevExecutor>,
    pub provenance: Provenance,
}

/// Complete PCA
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Pca {
    pub issuer_id: String,
    #[serde(with = "serde_bytes")]
    pub issuer_sig: Vec<u8>,
    pub payload: PcaPayload,
}

impl Pca {
    pub fn to_cbor(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pca() -> Pca {
        Pca {
            issuer_id: "https://cat.example.com".into(),
            issuer_sig: vec![0u8; 64],
            payload: PcaPayload {
                p_0: "https://idp.example.com/users/alice".into(),
                ops: vec!["read:/user/*".into()],
                executor: Executor {
                    id: ExecutorId { service: "service-b".into() },
                    public_key: vec![0u8; 32],
                    key_type: "Ed25519".into(),
                },
                prev_executor: Some(PrevExecutor {
                    public_key: vec![0u8; 32],
                    key_type: "Ed25519".into(),
                }),
                provenance: Provenance {
                    prev: "sha256:abc123".into(),
                    hop: 2,
                },
            },
        }
    }

    #[test]
    fn test_cbor_roundtrip() {
        let pca = sample_pca();
        let cbor = pca.to_cbor().unwrap();
        let decoded = Pca::from_cbor(&cbor).unwrap();
        assert_eq!(pca, decoded);
    }

    #[test]
    fn test_json_roundtrip() {
        let pca = sample_pca();
        let json = pca.to_json().unwrap();
        let decoded = Pca::from_json(&json).unwrap();
        assert_eq!(pca, decoded);
    }

    #[test]
    fn test_cbor_smaller_than_json() {
        let pca = sample_pca();
        let cbor = pca.to_cbor().unwrap();
        let json = pca.to_json().unwrap();
        
        println!("CBOR: {} bytes", cbor.len());
        println!("JSON: {} bytes", json.len());
        println!("Ratio: {:.1}%", (cbor.len() as f64 / json.len() as f64) * 100.0);
        
        assert!(cbor.len() < json.len());
    }

    #[test]
    fn test_hop_0_no_prev() {
        let pca = Pca {
            issuer_id: "https://cat.example.com".into(),
            issuer_sig: vec![0u8; 64],
            payload: PcaPayload {
                p_0: "https://idp.example.com/users/alice".into(),
                ops: vec!["read:/user/*".into(), "write:/user/*".into()],
                executor: Executor {
                    id: ExecutorId { service: "gateway".into() },
                    public_key: vec![0u8; 32],
                    key_type: "Ed25519".into(),
                },
                prev_executor: None,
                provenance: Provenance {
                    prev: "".into(),
                    hop: 0,
                },
            },
        };

        let cbor = pca.to_cbor().unwrap();
        let decoded = Pca::from_cbor(&cbor).unwrap();
        
        assert_eq!(decoded.payload.provenance.hop, 0);
        assert!(decoded.payload.prev_executor.is_none());
    }
}