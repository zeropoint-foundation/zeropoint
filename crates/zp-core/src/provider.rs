//! LLM provider types.

use serde::{Deserialize, Serialize};

/// Unique identifier for an LLM provider.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderId(pub String);

impl ProviderId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }
}

impl std::fmt::Display for ProviderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Capabilities of a provider (for routing decisions).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    /// Is this a local model?
    pub is_local: bool,
    /// Maximum context window size
    pub max_context: usize,
    /// Does it support tool use?
    pub supports_tools: bool,
    /// Relative strength assessment (0.0 to 1.0)
    pub strength: f64,
    /// Provider-specific model name
    pub model_name: String,
}

/// Health status of a provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderHealth {
    Healthy { latency_ms: u64 },
    Degraded { reason: String },
    Unavailable { reason: String },
}

/// Supplies an `Authorization` header value for an outbound substrate request.
///
/// # Why this is a trait, and why it lives here
///
/// Providers in `zp-llm` must authenticate to the substrate's own gate, but
/// `zp-llm` must never reach for Genesis material itself — an inner mechanism
/// that reads the operator's secrets has crossed the seam in the wrong
/// direction (HARNESS-SEAM-2026-08 §1, corollary 3). So `zp-llm` declares the
/// *need* through this trait and the composition root supplies the
/// *capability*. Inner ships the mechanism, outer supplies the content, with
/// the credential as the content.
///
/// The trait lives in `zp-core` because it is the one crate both the declarer
/// and the implementors already depend on. Placing it anywhere else would add
/// a dependency edge purely to express a shape.
///
/// # Contract
///
/// `authorization` returns the complete header *value* (scheme included), or
/// `None` when no credential can be produced. Returning `None` must cause the
/// caller to send the request unauthenticated and be rejected — it must never
/// cause the caller to skip authentication and proceed. Fail closed.
///
/// Implementations bind the signature to `method`, `path` and `body`, so the
/// caller must pass the exact wire bytes it is about to send. Hashing a
/// re-serialization of the same value is the classic way to produce a header
/// that verifies locally and fails remotely.
pub trait RequestSigner: Send + Sync {
    /// Produce the `Authorization` header value for this request.
    ///
    /// `method` is uppercase ASCII ("POST"). `path` is the request path
    /// including any query string, with a leading `/`, excluding scheme,
    /// host and port. `body` is the exact bytes that will be transmitted.
    fn authorization(&self, method: &str, path: &str, body: &[u8]) -> Option<String>;
}
