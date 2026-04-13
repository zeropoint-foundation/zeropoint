//! Provider detection and catalog management.
//!
//! Single source of truth for:
//! - Loading the provider catalog (embedded TOML + user overrides)
//! - Detecting which providers have env vars set
//! - Mapping env var names → provider IDs
//! - Inferring provider names from unrecognized var names

use serde::{Deserialize, Serialize};

// ============================================================================
// Types
// ============================================================================

/// A known AI/LLM provider from the TOML catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub id: String,
    pub name: String,
    pub category: String,
    pub env_patterns: Vec<String>,
    #[serde(default)]
    pub key_hint: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub key_url: String,
    #[serde(default)]
    pub docs_url: String,
    #[serde(default)]
    pub supports_org: bool,
    #[serde(default)]
    pub source_url: String,
    #[serde(default)]
    pub last_verified: String,
    #[serde(default)]
    pub coverage: String,

    // ── MVC fields (Phase A) ─────────────────────────────────
    /// Abstract capabilities this provider satisfies (e.g., ["reasoning_llm", "vision"])
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Whether this provider exposes OpenAI-compatible /v1/chat/completions
    #[serde(default)]
    pub openai_compatible: Option<bool>,
    /// Whether ZP proxy can translate OpenAI protocol to this provider's native API
    #[serde(default)]
    pub openai_proxy: Option<bool>,
    /// Whether this is a multi-model routing service (OpenRouter, Abacus)
    #[serde(default)]
    pub aggregator: Option<bool>,
    /// Routing strategy: "intelligent" (auto-selects model) or "explicit" (user picks)
    #[serde(default)]
    pub routing: Option<String>,
}

impl ProviderProfile {
    /// Check if this provider satisfies a given capability.
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// Whether this provider is an aggregator.
    pub fn is_aggregator(&self) -> bool {
        self.aggregator.unwrap_or(false)
    }

    /// Whether this provider speaks OpenAI protocol natively.
    pub fn is_openai_compatible(&self) -> bool {
        self.openai_compatible.unwrap_or(false)
    }

    /// Whether ZP proxy can translate OpenAI protocol for this provider.
    pub fn needs_proxy(&self) -> bool {
        self.openai_proxy.unwrap_or(false) && !self.is_openai_compatible()
    }

    /// Get all providers from a catalog that satisfy a given capability.
    pub fn providers_for_capability<'a>(
        catalog: &'a [ProviderProfile],
        capability: &str,
    ) -> Vec<&'a ProviderProfile> {
        catalog
            .iter()
            .filter(|p| p.has_capability(capability))
            .collect()
    }
}

/// Result of scanning the user's environment against the provider catalog.
#[derive(Debug, Clone, Serialize)]
pub struct DetectedProvider {
    #[serde(flatten)]
    pub profile: ProviderProfile,
    pub detected_vars: Vec<String>,
    pub detected: bool,
}

/// Wrapper for TOML deserialization.
#[derive(Debug, Deserialize)]
struct ProviderCatalogFile {
    #[serde(default)]
    providers: Vec<ProviderProfile>,
}

// ============================================================================
// Embedded catalog
// ============================================================================

const PROVIDERS_DEFAULT_TOML: &str = include_str!("../../zp-server/assets/providers-default.toml");

// ============================================================================
// Catalog loading
// ============================================================================

/// Load the provider catalog: embedded defaults merged with user overrides.
///
/// User overrides in `~/.zeropoint/config/providers.toml` are merged on top
/// of the compiled-in defaults. If a user entry has the same `id` as a default,
/// the user version replaces it entirely. New user entries are appended.
pub fn load_catalog() -> Vec<ProviderProfile> {
    let mut catalog: Vec<ProviderProfile> =
        toml::from_str::<ProviderCatalogFile>(PROVIDERS_DEFAULT_TOML)
            .map(|f| f.providers)
            .unwrap_or_default();

    // Try loading user overrides
    if let Some(home) = dirs::home_dir() {
        let user_path = home
            .join(".zeropoint")
            .join("config")
            .join("providers.toml");
        if let Ok(content) = std::fs::read_to_string(&user_path) {
            if let Ok(user_catalog) = toml::from_str::<ProviderCatalogFile>(&content) {
                for user_provider in user_catalog.providers {
                    if let Some(pos) = catalog.iter().position(|p| p.id == user_provider.id) {
                        catalog[pos] = user_provider;
                    } else {
                        catalog.push(user_provider);
                    }
                }
            }
        }
    }

    catalog
}

// ============================================================================
// Detection
// ============================================================================

/// Match an env var name against the provider catalog.
/// Returns the provider `id` if any pattern matches.
pub fn detect_provider(var_name: &str) -> Option<String> {
    let catalog = load_catalog();

    for provider in &catalog {
        for pattern in &provider.env_patterns {
            if var_name == pattern {
                return Some(provider.id.clone());
            }
        }
    }

    // Local inference runtime env vars (host/endpoint config, not API keys)
    let local_runtimes = [
        ("OLLAMA_HOST", "ollama"),
        ("OLLAMA_BASE_URL", "ollama"),
        ("LM_STUDIO", "lm-studio"),
        ("LOCALAI", "localai"),
    ];
    for (var, name) in &local_runtimes {
        if var_name == *var {
            return Some(name.to_string());
        }
    }

    None
}

/// Best-effort provider inference for variables not in the catalog.
///
/// Strips common suffixes to extract a reasonable provider name.
/// e.g. `HEDERA_OPERATOR_ID` → `hedera`, `IRONCLAW_TOKEN` → `ironclaw`
pub fn infer_provider_from_var(var_name: &str) -> String {
    let lower = var_name.to_lowercase();
    let suffixes = [
        "_api_key",
        "_key",
        "_secret",
        "_token",
        "_id",
        "_password",
        "_pass",
        "_host",
        "_url",
        "_endpoint",
        "_operator_id",
        "_operator_key",
        "_access_key",
        "_secret_key",
        "_account_id",
        "_project_id",
    ];
    for suffix in &suffixes {
        if lower.ends_with(suffix) {
            let prefix = &lower[..lower.len() - suffix.len()];
            if !prefix.is_empty() {
                return prefix.to_string();
            }
        }
    }
    // Fallback: everything before the first underscore
    lower.split('_').next().unwrap_or("unknown").to_string()
}

/// Scan environment variables against the provider catalog.
/// Returns all providers with detection status — detected ones first.
pub fn scan_environment(catalog: &[ProviderProfile]) -> Vec<DetectedProvider> {
    let env_vars: std::collections::HashMap<String, String> = std::env::vars().collect();

    let mut results: Vec<DetectedProvider> = catalog
        .iter()
        .map(|profile| {
            let detected_vars: Vec<String> = profile
                .env_patterns
                .iter()
                .filter(|pattern| env_vars.keys().any(|k| k == pattern.as_str()))
                .cloned()
                .collect();

            let detected = !detected_vars.is_empty();

            DetectedProvider {
                profile: profile.clone(),
                detected_vars,
                detected,
            }
        })
        .collect();

    results.sort_by(|a, b| {
        b.detected
            .cmp(&a.detected)
            .then_with(|| a.profile.category.cmp(&b.profile.category))
            .then_with(|| a.profile.name.cmp(&b.profile.name))
    });

    results
}
