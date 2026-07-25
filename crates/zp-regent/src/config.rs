//! Regent configuration types.
//!
//! Lives alongside operator-facing config in zp-config once the
//! Regent config schema stabilizes. For now, self-contained here
//! to iterate without polluting the stable config surface.

use serde::{Deserialize, Serialize};

/// Where the inference API key lives — never in cognitive context.
///
/// The Regent's cognitive path (observation pipeline, reasoning traces,
/// chain receipts) must never contain raw API key material. This enum
/// records *where* the key is stored; the actual value is resolved at
/// HTTP call time and immediately dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiKeySource {
    /// No API key — using Ollama or local inference.
    None,
    /// Key stored in the vault at this path (e.g. "system/regent/inference/api_key").
    Vault(String),
    /// Raw key in memory — legacy/migration only. Will be migrated to Vault on
    /// next self_configure call. Exists so that config.toml-sourced keys work
    /// during the transition period.
    #[serde(rename = "raw_legacy")]
    RawLegacy(String),
}

impl ApiKeySource {
    /// Whether an API key is available (regardless of source).
    pub fn has_key(&self) -> bool {
        !matches!(self, ApiKeySource::None)
    }

    /// Extract the raw key for a single HTTP call. Returns None for Vault
    /// source — those must be resolved through the vault at call time.
    /// Only returns Some for RawLegacy (transition path).
    pub fn raw_key(&self) -> Option<&str> {
        match self {
            ApiKeySource::RawLegacy(k) => Some(k.as_str()),
            _ => None,
        }
    }
}

impl Default for ApiKeySource {
    fn default() -> Self {
        ApiKeySource::None
    }
}

/// Regent cognitive configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegentConfig {
    /// Whether the Regent is active. Default: false (opt-in).
    pub enabled: bool,

    /// Inference endpoint — Ollama local or OpenAI-compatible cloud.
    pub inference_endpoint: String,

    /// Where the inference API key lives. When set to Vault or RawLegacy,
    /// the backend uses OpenAI protocol (/v1/chat/completions with Bearer
    /// auth). When None, uses Ollama protocol (/api/chat).
    pub api_key_source: ApiKeySource,

    /// Model to use for reasoning. Operator-configurable.
    pub reasoning_model: String,

    /// Model to use for fast classification/routing.
    pub routing_model: String,

    /// Maximum context window tokens for reasoning calls.
    pub max_context_tokens: usize,

    /// Cognitive loop interval in seconds. How often the Regent
    /// wakes to perceive chain state, independent of operator input.
    /// Default: 60 (one minute). Set to 0 to disable autonomous wake.
    pub loop_interval_secs: u64,

    /// Cloud escalation mandate. When local inference is insufficient,
    /// the Regent may escalate to cloud — but only within this budget.
    pub cloud_mandate: Option<CloudMandate>,

    /// The Regent's display name. Defaults to "Regent".
    /// Operator can rename via `regent:named` receipt.
    pub display_name: String,
}

impl Default for RegentConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inference_endpoint: "http://127.0.0.1:11434".to_string(),
            api_key_source: ApiKeySource::None,
            reasoning_model: "qwen3:8b".to_string(),
            routing_model: "qwen3:1.7b".to_string(),
            max_context_tokens: 8192,
            loop_interval_secs: 60,
            cloud_mandate: None,
            display_name: "Regent".to_string(),
        }
    }
}

/// Cloud escalation budget — operator-approved, time-bounded, capped.
///
/// The Regent cannot spend cloud tokens without an active mandate.
/// Mandates are receipted: `regent:mandate:issued`, `regent:mandate:spent`,
/// `regent:mandate:exhausted`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMandate {
    /// Maximum tokens to spend in this mandate period.
    pub token_budget: u64,

    /// Tokens already consumed.
    pub tokens_spent: u64,

    /// When this mandate expires (UTC).
    pub expires_at: chrono::DateTime<chrono::Utc>,

    /// Which cloud provider is authorized.
    pub provider: String,

    /// Which model is authorized.
    pub model: String,
}

impl CloudMandate {
    /// Remaining tokens in this mandate.
    pub fn remaining(&self) -> u64 {
        self.token_budget.saturating_sub(self.tokens_spent)
    }

    /// Whether this mandate is still valid (not expired, has budget).
    pub fn is_active(&self) -> bool {
        self.remaining() > 0 && chrono::Utc::now() < self.expires_at
    }
}
