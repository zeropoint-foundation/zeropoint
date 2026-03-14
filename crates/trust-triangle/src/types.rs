//! Wire types for the Trust Triangle HTTP API.

use serde::{Deserialize, Serialize};
use zp_receipt::Receipt;

/// A data query request from a trusted peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRequest {
    /// The requester's certificate chain (for verification).
    pub initiator_chain: Vec<zp_keys::certificate::Certificate>,
    /// The query string (e.g., a patient ID).
    pub query: String,
    /// Parent receipt ID for chain linkage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
}

/// Response to a data query, including the data, a signed receipt,
/// and the policy decision that governed access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse {
    /// The sanitized data payload.
    pub data: serde_json::Value,
    /// Signed receipt proving this data access.
    pub receipt: Receipt,
    /// Human-readable description of the policy decision.
    pub policy_decision: String,
    /// Number of records redacted by the sanitization policy.
    pub redacted_count: usize,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub node: String,
    pub genesis_fingerprint: String,
    pub status: String,
}
