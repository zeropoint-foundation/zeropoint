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
