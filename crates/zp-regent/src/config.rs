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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum ApiKeySource {
    /// No API key — using Ollama or local inference.
    #[default]
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

impl RegentConfig {
    /// Construct from the single authority for `reasoning_model` /
    /// `routing_model` (HARNESS-SEAM-2026-08 §4 S4, unification closed
    /// 2026-09-01): `zp_config::ZpConfig`'s `regent_reasoning_model` /
    /// `regent_routing_model` fields, themselves declared exactly once via
    /// `Sourced::default_value` in `crates/zp-config/src/schema.rs`. Every
    /// other construction path in the workspace derives from this (directly,
    /// or transitively through `ServerConfig::from_zp_config` /
    /// `ServerRegentConfig`) or from `RegentConfig::for_tests` below.
    ///
    /// `max_context_tokens` and `cloud_mandate` have no `ZpConfig`
    /// equivalent (not part of the model-election crossing this
    /// unification closes) and are set to fixed operational defaults here,
    /// same as they always were.
    pub fn from_zp_config(cfg: &zp_config::ZpConfig) -> Self {
        Self {
            enabled: cfg.regent_enabled.value,
            inference_endpoint: cfg.regent_inference_endpoint.value.clone(),
            api_key_source: match &cfg.regent_inference_api_key.value {
                Some(key) => ApiKeySource::RawLegacy(key.clone()),
                None => ApiKeySource::None,
            },
            reasoning_model: cfg.regent_reasoning_model.value.clone(),
            routing_model: cfg.regent_routing_model.value.clone(),
            max_context_tokens: 8192,
            loop_interval_secs: cfg.regent_loop_interval_secs.value,
            cloud_mandate: None,
            display_name: cfg.regent_display_name.value.clone(),
        }
    }

    /// Test-only constructor for fixtures that need a valid `RegentConfig`
    /// without resolving a `ZpConfig`. Deliberately named `for_tests` —
    /// that name is meant to be grepped for: it is how a discipline pin
    /// (or a future reader) tells "a test fixture that needs an explicit,
    /// stable model name" apart from "a second declarant competing with
    /// `ZpConfig`'s authority." Not for production call sites.
    ///
    /// Takes the two model names positionally rather than as named fields
    /// so a caller like `RegentConfig::for_tests("qwen3:8b", "qwen3:1.7b")`
    /// never spells out `reasoning_model: "..."` as a struct-literal
    /// shape — the exact shape the S4 discipline pin forbids.
    pub fn for_tests(reasoning_model: impl Into<String>, routing_model: impl Into<String>) -> Self {
        Self {
            enabled: false,
            inference_endpoint: zp_config::REGENT_INFERENCE_ENDPOINT_SENTINEL.to_string(),
            api_key_source: ApiKeySource::None,
            reasoning_model: reasoning_model.into(),
            routing_model: routing_model.into(),
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
