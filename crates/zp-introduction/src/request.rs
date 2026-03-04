//! Introduction request — the initiator's opening message.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use zp_keys::certificate::Certificate;

/// An introduction request sent by the initiating node.
///
/// Contains the initiator's certificate chain (genesis → operator → agent)
/// and a fresh challenge nonce for replay protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroductionRequest {
    /// Protocol version (for future compatibility).
    pub version: u8,
    /// The initiator's certificate chain, ordered genesis → leaf.
    pub certificate_chain: Vec<Certificate>,
    /// A random nonce the responder must sign to prove liveness.
    pub challenge_nonce: String,
    /// When the request was created.
    pub timestamp: DateTime<Utc>,
    /// Optional human-readable reason for the introduction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl IntroductionRequest {
    /// Create a new introduction request.
    pub fn new(chain: Vec<Certificate>, reason: Option<String>) -> Self {
        let nonce = format!("nonce-{}", uuid::Uuid::now_v7());
        Self {
            version: 1,
            certificate_chain: chain,
            challenge_nonce: nonce,
            timestamp: Utc::now(),
            reason,
        }
    }

    /// Serialize to JSON bytes (for wire transmission).
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::IntroductionError> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::IntroductionError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::IntroductionError> {
        serde_json::from_slice(bytes)
            .map_err(|e| crate::error::IntroductionError::InvalidRequest(e.to_string()))
    }
}
