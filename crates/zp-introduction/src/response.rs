//! Introduction response — the responder's reply.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use zp_keys::certificate::Certificate;

/// The outcome of the responder's policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntroductionDecision {
    /// Introduction accepted — trust established.
    Accepted,
    /// Introduction requires human review before proceeding.
    PendingReview { summary: String },
    /// Introduction denied by policy.
    Denied { reason: String },
}

/// An introduction response from the responder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntroductionResponse {
    /// Protocol version.
    pub version: u8,
    /// The responder's decision.
    pub decision: IntroductionDecision,
    /// The responder's certificate chain (if accepted or pending review).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<Certificate>>,
    /// The challenge nonce from the request, signed by the responder's leaf key.
    /// Proves liveness and chain ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_challenge: Option<String>,
    /// When the response was created.
    pub timestamp: DateTime<Utc>,
}

impl IntroductionResponse {
    /// Create an acceptance response.
    pub fn accept(chain: Vec<Certificate>, signed_challenge: String) -> Self {
        Self {
            version: 1,
            decision: IntroductionDecision::Accepted,
            certificate_chain: Some(chain),
            signed_challenge: Some(signed_challenge),
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a pending-review response.
    pub fn pending_review(summary: String) -> Self {
        Self {
            version: 1,
            decision: IntroductionDecision::PendingReview { summary },
            certificate_chain: None,
            signed_challenge: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a denial response.
    pub fn deny(reason: String) -> Self {
        Self {
            version: 1,
            decision: IntroductionDecision::Denied { reason },
            certificate_chain: None,
            signed_challenge: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::IntroductionError> {
        serde_json::to_vec(self)
            .map_err(|e| crate::error::IntroductionError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::error::IntroductionError> {
        serde_json::from_slice(bytes)
            .map_err(|e| crate::error::IntroductionError::InvalidResponse(e.to_string()))
    }
}
