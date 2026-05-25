//! ZeroPoint API Proxy — governance-aware LLM provider proxy.
//!
//! Intercepts API calls to LLM providers, applies policy checks,
//! meters token usage, generates receipts, and forwards to the real
//! provider endpoint. Tools like PentAGI and OpenMAIC configure their
//! `*_BASE_URL` to point here instead of the real provider.
//!
//! ## Flow
//!
//! 1. Tool sends request to `http://localhost:{zp_port}/api/v1/proxy/{provider}/...`
//! 2. ZP applies policy check (rate limits, budget, model allow-list)
//! 3. ZP forwards to real provider endpoint with the tool's API key from headers
//! 4. ZP extracts token usage from provider response
//! 5. ZP generates a signed receipt with cost data
//! 6. ZP logs to audit trail
//! 7. ZP returns response to tool (transparent)
//!
//! ## Design Principles
//!
//! - **Transparent**: Tools don't need code changes — just a URL swap
//! - **Receipt-native**: Every proxied call produces an auditable receipt
//! - **Policy-gated**: Pre-flight checks via GovernanceGate
//! - **Provider-aware**: Extracts token counts from each provider's response format

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::OnceLock;
use tracing::{debug, error, info, warn};
use zp_core::InferenceTier;
use zp_engine::providers::ProviderProfile;

use crate::AppState;

// ============================================================================
// Catalog — loaded once, shared across all proxy requests
// ============================================================================

static PROVIDER_CATALOG: OnceLock<Vec<ProviderProfile>> = OnceLock::new();
/// Layer over PROVIDER_CATALOG that holds a refreshed snapshot after `zp pricing refresh`.
/// The inner `Option` is `None` until the first refresh; `catalog_snapshot()` falls
/// back to PROVIDER_CATALOG when no refresh has been applied.
static REFRESHED_CATALOG: OnceLock<std::sync::RwLock<Option<Vec<ProviderProfile>>>> =
    OnceLock::new();

fn get_catalog() -> &'static Vec<ProviderProfile> {
    PROVIDER_CATALOG.get_or_init(|| zp_engine::providers::load_catalog())
}

/// Return a snapshot of the current catalog, preferring the refreshed version.
fn catalog_snapshot() -> Vec<ProviderProfile> {
    let lock = REFRESHED_CATALOG
        .get_or_init(|| std::sync::RwLock::new(None));
    if let Ok(guard) = lock.read() {
        if let Some(ref refreshed) = *guard {
            return refreshed.clone();
        }
    }
    get_catalog().clone()
}

/// Replace the in-process catalog with a freshly-fetched snapshot.
/// Called by the `POST /api/v1/pricing/refresh` handler after a successful fetch.
pub fn reload_provider_catalog(updated: Vec<ProviderProfile>) {
    let lock = REFRESHED_CATALOG
        .get_or_init(|| std::sync::RwLock::new(None));
    if let Ok(mut guard) = lock.write() {
        *guard = Some(updated);
    }
}

/// Look up a provider profile by proxy provider name.
/// Returns an owned clone so the refreshed catalog (RwLock) can be consulted.
fn catalog_lookup(proxy_provider: &str) -> Option<ProviderProfile> {
    let catalog_id = match proxy_provider {
        "google" => "gemini",
        other => other,
    };
    catalog_snapshot().into_iter().find(|p| p.id == catalog_id)
}

/// Rates for a provider: (input_per_million_usd, output_per_million_usd).
fn provider_rates(proxy_provider: &str) -> (f64, f64) {
    catalog_lookup(proxy_provider)
        .and_then(|p| p.input_per_million_usd.zip(p.output_per_million_usd))
        .unwrap_or((1.0, 4.0))
}

// ============================================================================
// Tier routing — resolves InferenceTier → (provider, model)
// ============================================================================

/// One tier entry from routing.toml.
#[derive(Debug, Clone, Deserialize)]
pub struct TierRoute {
    pub provider: String,
    pub model: String,
}

/// Operator routing configuration loaded from ~/ZeroPoint/config/routing.toml.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RoutingConfig {
    #[serde(default)]
    pub high_stakes: Option<TierRoute>,
    #[serde(default)]
    pub bulk: Option<TierRoute>,
    #[serde(default)]
    pub coding: Option<TierRoute>,
    #[serde(default)]
    pub local: Option<TierRoute>,
    #[serde(default)]
    pub experimental: Option<TierRoute>,
}

// ============================================================================
// Pricing staleness config — loaded from [pricing] section of routing.toml
// ============================================================================

/// Per-host pricing staleness override.
#[derive(Debug, Clone, Deserialize)]
pub struct HostPricingConfig {
    pub stale_days: u64,
}

/// Operator pricing freshness configuration.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PricingConfig {
    /// Days after which pricing is considered stale (global default).
    #[serde(default = "default_stale_days")]
    pub default_stale_days: u64,
    /// Per-host overrides: provider ID → stale threshold.
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, HostPricingConfig>,
}

fn default_stale_days() -> u64 { 30 }

/// TOML wrapper for `[tiers.*]` and `[pricing]` table structure.
#[derive(Debug, Deserialize, Default)]
struct RoutingFile {
    #[serde(default)]
    tiers: RoutingConfig,
    #[serde(default)]
    pricing: PricingConfig,
}

static ROUTING_CONFIG: OnceLock<RoutingConfig> = OnceLock::new();
static PRICING_CONFIG: OnceLock<PricingConfig> = OnceLock::new();

fn get_routing_config() -> &'static RoutingConfig {
    ROUTING_CONFIG.get_or_init(|| {
        // Compiled-in defaults matching the strategic memo's recommended split
        let mut config = RoutingConfig {
            high_stakes: Some(TierRoute {
                provider: "anthropic".to_string(),
                model: "claude-sonnet-4-6".to_string(),
            }),
            bulk: Some(TierRoute {
                provider: "together".to_string(),
                model: "meta-llama/Llama-3.3-70B-Instruct-Turbo".to_string(),
            }),
            coding: Some(TierRoute {
                provider: "abacus".to_string(),
                model: "kimi-2.6-thinking".to_string(),
            }),
            local: Some(TierRoute {
                provider: "ollama".to_string(),
                model: "mistral".to_string(),
            }),
            experimental: Some(TierRoute {
                provider: "deepinfra".to_string(),
                model: "Qwen/Qwen3-72B".to_string(),
            }),
        };

        // Overlay with operator's routing.toml if present
        if let Ok(zp_home) = zp_core::paths::home() {
            let path = zp_home.join("config").join("routing.toml");
            if let Ok(content) = std::fs::read_to_string(&path) {
                match toml::from_str::<RoutingFile>(&content) {
                    Ok(f) => {
                        if f.tiers.high_stakes.is_some() {
                            config.high_stakes = f.tiers.high_stakes;
                        }
                        if f.tiers.bulk.is_some() {
                            config.bulk = f.tiers.bulk;
                        }
                        if f.tiers.coding.is_some() {
                            config.coding = f.tiers.coding;
                        }
                        if f.tiers.local.is_some() {
                            config.local = f.tiers.local;
                        }
                        if f.tiers.experimental.is_some() {
                            config.experimental = f.tiers.experimental;
                        }
                        // Populate pricing config from the same file
                        let _ = PRICING_CONFIG.set(f.pricing);
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to parse routing.toml; using compiled-in defaults");
                    }
                }
            }
        }

        config
    })
}

fn get_pricing_config() -> &'static PricingConfig {
    PRICING_CONFIG.get_or_init(PricingConfig::default)
}

/// Staleness threshold in days for a given provider host ID.
/// Uses per-host override from routing.toml `[pricing.hosts.*]` if present,
/// falling back to the global `default_stale_days`.
pub fn stale_threshold_days(provider_id: &str) -> u64 {
    let cfg = get_pricing_config();
    cfg.hosts
        .get(provider_id)
        .map(|h| h.stale_days)
        .unwrap_or(cfg.default_stale_days)
}

/// Resolve an `InferenceTier` to a `(provider, model)` pair.
/// Returns `None` if the tier has no route configured.
pub fn resolve_tier(tier: &InferenceTier) -> Option<(&'static str, &'static str)> {
    let config = get_routing_config();
    let route = match tier {
        InferenceTier::HighStakes => config.high_stakes.as_ref(),
        InferenceTier::Bulk => config.bulk.as_ref(),
        InferenceTier::Coding => config.coding.as_ref(),
        InferenceTier::Local => config.local.as_ref(),
        InferenceTier::Experimental => config.experimental.as_ref(),
    }?;
    // SAFETY: OnceLock contents live for 'static
    let provider: &'static str = Box::leak(route.provider.clone().into_boxed_str());
    let model: &'static str = Box::leak(route.model.clone().into_boxed_str());
    Some((provider, model))
}

// ============================================================================
// Provider Registry — maps provider names to real base URLs
// ============================================================================

/// Known provider endpoints.
pub fn provider_base_url(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("https://api.openai.com"),
        "anthropic" => Some("https://api.anthropic.com"),
        "groq" => Some("https://api.groq.com/openai"),
        "mistral" => Some("https://api.mistral.ai"),
        "together" => Some("https://api.together.xyz"),
        "deepseek" => Some("https://api.deepseek.com"),
        "fireworks" => Some("https://api.fireworks.ai/inference"),
        "perplexity" => Some("https://api.perplexity.ai"),
        "cohere" => Some("https://api.cohere.ai"),
        "google" => Some("https://generativelanguage.googleapis.com"),
        "openrouter" => Some("https://openrouter.ai/api"),
        "siliconflow" => Some("https://api.siliconflow.cn"),
        // DeepInfra: OpenAI-compatible. Base includes /v1/openai so the proxy
        // path uses "chat/completions" (not the standard "v1/chat/completions").
        "deepinfra" => Some("https://api.deepinfra.com/v1/openai"),
        // Abacus RouteLLM: OpenAI-compatible at routellm subdomain.
        // Base is the full v1 root so the proxy path is "chat/completions".
        "abacus" => Some("https://routellm.abacus.ai/v1"),
        _ => None,
    }
}

// ============================================================================
// Path allowlist — SSRF / path injection prevention (Phase 1.3)
// ============================================================================
// INJ-VULN-06, INJ-VULN-07, SSRF-VULN-02: restrict proxy paths to known
// LLM API endpoints. Without this, an attacker could use the proxy to
// reach arbitrary paths on provider infrastructure or inject query strings.

/// Allowed API path prefixes per provider. Only requests whose path starts
/// with one of these prefixes will be forwarded.
fn allowed_path_prefixes(provider: &str) -> &'static [&'static str] {
    match provider {
        "openai" => &[
            "v1/chat/completions",
            "v1/completions",
            "v1/embeddings",
            "v1/models",
            "v1/moderations",
            "v1/images/generations",
        ],
        "anthropic" => &["v1/messages", "v1/complete"],
        "groq" => &["v1/chat/completions", "v1/models"],
        "mistral" => &["v1/chat/completions", "v1/embeddings", "v1/models"],
        "together" => &["v1/chat/completions", "v1/completions", "v1/embeddings"],
        "deepseek" => &["v1/chat/completions"],
        "fireworks" => &["v1/chat/completions", "v1/completions", "v1/embeddings"],
        "perplexity" => &["chat/completions"],
        "cohere" => &["v1/chat", "v1/generate", "v1/embed", "v2/chat"],
        "google" => &["v1beta/models", "v1/models"],
        "openrouter" => &["v1/chat/completions"],
        "siliconflow" => &["v1/chat/completions"],
        // DeepInfra: base URL already includes /v1/openai, so path omits the v1 prefix.
        "deepinfra" => &["chat/completions", "models"],
        // Abacus RouteLLM: base URL already includes /v1, so path omits the v1 prefix.
        "abacus" => &["chat/completions", "models"],
        _ => &[], // Unknown providers have no allowed paths
    }
}

/// Validate that a proxy path is safe and allowed for the given provider.
///
/// Returns `Ok(sanitized_path)` or `Err(reason)`.
fn validate_proxy_path(provider: &str, path: &str) -> Result<String, String> {
    // Reject empty paths
    if path.is_empty() {
        return Err("Empty path".to_string());
    }

    // INJ-VULN-07: reject percent-encoded characters that could bypass
    // validation (e.g. %3F = ?, %2F = /, %2E = .)
    if path.contains('%') {
        return Err("Percent-encoded characters not allowed in proxy path".to_string());
    }

    // Reject path traversal
    if path.contains("..") {
        return Err("Path traversal not allowed".to_string());
    }

    // Reject query strings (could redirect to unintended endpoints)
    if path.contains('?') || path.contains('#') {
        return Err("Query strings and fragments not allowed in proxy path".to_string());
    }

    // Reject null bytes
    if path.contains('\0') {
        return Err("Null bytes not allowed".to_string());
    }

    // Normalize: strip leading/trailing slashes
    let normalized = path.trim_matches('/');

    // Check against allowlist
    let prefixes = allowed_path_prefixes(provider);
    if prefixes.is_empty() {
        return Err(format!(
            "No allowed paths configured for provider '{}'",
            provider
        ));
    }

    let allowed = prefixes
        .iter()
        .any(|prefix| normalized == *prefix || normalized.starts_with(&format!("{}/", prefix)));

    if !allowed {
        return Err(format!(
            "Path '{}' is not in the allowed list for provider '{}'. Allowed: {:?}",
            normalized, provider, prefixes
        ));
    }

    Ok(normalized.to_string())
}

// ============================================================================
// Token extraction — provider-specific response parsing
// ============================================================================

/// Extracted usage metrics from a provider response.
#[derive(Debug, Clone, Default, Serialize)]
pub struct UsageMetrics {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
    pub model: Option<String>,
}

/// Extract token usage from an OpenAI-format response.
/// Works for OpenAI, Groq, Together, DeepSeek, Fireworks, Perplexity, OpenRouter.
fn extract_openai_usage(body: &Value) -> UsageMetrics {
    let usage = body.get("usage").unwrap_or(&Value::Null);
    UsageMetrics {
        prompt_tokens: usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        completion_tokens: usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        total_tokens: usage
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        model: body
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
}

/// Extract token usage from an Anthropic-format response.
fn extract_anthropic_usage(body: &Value) -> UsageMetrics {
    let usage = body.get("usage").unwrap_or(&Value::Null);
    let input = usage
        .get("input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output = usage
        .get("output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    UsageMetrics {
        prompt_tokens: input,
        completion_tokens: output,
        total_tokens: input + output,
        model: body
            .get("model")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
}

/// Extract usage from any known provider response.
pub fn extract_usage(provider: &str, body: &Value) -> UsageMetrics {
    match provider {
        "anthropic" => extract_anthropic_usage(body),
        // All other providers including deepinfra and abacus use OpenAI format
        _ => extract_openai_usage(body),
    }
}

// ============================================================================
// Provider-specific request transforms
// ============================================================================

/// Abacus RouteLLM rejects tool definitions that include `"strict": true`
/// with HTTP 400. Strip the field from every function object in `tools`
/// before forwarding. No-op if the body has no `tools` array or no `strict`
/// fields — safe to call unconditionally for Abacus requests.
pub fn strip_tool_strict(body_bytes: &[u8]) -> Vec<u8> {
    let Ok(mut body) = serde_json::from_slice::<Value>(body_bytes) else {
        return body_bytes.to_vec();
    };

    if let Some(tools) = body.get_mut("tools").and_then(|t| t.as_array_mut()) {
        for tool in tools.iter_mut() {
            if let Some(func) = tool.get_mut("function").and_then(|f| f.as_object_mut()) {
                func.remove("strict");
            }
        }
    }

    serde_json::to_vec(&body).unwrap_or_else(|_| body_bytes.to_vec())
}

// ============================================================================
// Cost estimation — catalog-driven token pricing
// ============================================================================

/// Inject a model field into an OpenAI-format request body.
/// Used by tier routing to ensure the tier-resolved model reaches the provider.
fn inject_model_into_body(body_bytes: &[u8], model: &str) -> Vec<u8> {
    let Ok(mut body) = serde_json::from_slice::<Value>(body_bytes) else {
        return body_bytes.to_vec();
    };
    if let Some(obj) = body.as_object_mut() {
        obj.insert("model".to_string(), json!(model));
    }
    serde_json::to_vec(&body).unwrap_or_else(|_| body_bytes.to_vec())
}

/// Compute cost in USD from per-million rates and token counts.
/// Rates come from the provider catalog (see `provider_rates`).
pub fn estimate_cost_usd(input_per_m: f64, output_per_m: f64, usage: &UsageMetrics) -> f64 {
    let input_cost = (usage.prompt_tokens as f64 / 1_000_000.0) * input_per_m;
    let output_cost = (usage.completion_tokens as f64 / 1_000_000.0) * output_per_m;
    input_cost + output_cost
}

// ============================================================================
// Proxy handler
// ============================================================================

/// Proxy response wrapper — includes the provider response plus ZP metadata.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyMeta {
    pub receipt_id: String,
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub cost_usd: f64,
    pub provider: String,
    pub model: Option<String>,
}

/// Main proxy handler.
///
/// Route: `POST /api/v1/proxy/*proxy_path`
///
/// The catch-all `proxy_path` is split into `{provider}/{remaining_path}`.
/// Forwards the request to the real provider, extracts usage, generates receipt.
/// The original provider response is returned unmodified to the caller.
/// A `X-ZP-Receipt-Id` header is added with the receipt ID.
pub async fn proxy_handler(
    State(state): State<AppState>,
    Path(proxy_path): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let start = Utc::now();

    // Split the catch-all path into provider and remaining path.
    // proxy_path arrives as "provider/remaining/path" (no leading slash).
    let proxy_path = proxy_path.trim_start_matches('/');
    let (provider, path) = match proxy_path.split_once('/') {
        Some((p, rest)) => (p.to_string(), rest.to_string()),
        None => (proxy_path.to_string(), String::new()),
    };

    // Tier routing: X-ZP-Tier header overrides the URL provider + injects model.
    let (provider, tier_model) = if let Some(tier_val) = headers
        .get("x-zp-tier")
        .and_then(|v| v.to_str().ok())
    {
        let tier = match tier_val {
            "high_stakes" => Some(InferenceTier::HighStakes),
            "bulk" => Some(InferenceTier::Bulk),
            "coding" => Some(InferenceTier::Coding),
            "local" => Some(InferenceTier::Local),
            "experimental" => Some(InferenceTier::Experimental),
            _ => {
                warn!(tier = %tier_val, "Unknown X-ZP-Tier value; ignoring");
                None
            }
        };
        if let Some(t) = tier {
            if let Some((tp, tm)) = resolve_tier(&t) {
                debug!(tier = %tier_val, provider = %tp, model = %tm, "Tier routing resolved");
                (tp.to_string(), Some(tm))
            } else {
                warn!(tier = %tier_val, "No route configured for tier; using URL provider");
                (provider, None)
            }
        } else {
            (provider, None)
        }
    } else {
        (provider, None)
    };

    // 1. Resolve provider base URL
    let base_url = match provider_base_url(&provider) {
        Some(url) => url,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": format!("Unknown provider: {}", provider),
                    "known_providers": ["openai", "anthropic", "groq", "mistral", "together",
                                       "deepseek", "fireworks", "perplexity", "cohere",
                                       "google", "openrouter", "siliconflow",
                                       "deepinfra", "abacus"]
                })),
            )
                .into_response();
        }
    };

    // Phase 1.3: Validate proxy path against provider allowlist.
    // INJ-VULN-06, INJ-VULN-07, SSRF-VULN-02: prevents SSRF via path
    // injection, percent-encoded query string injection, and arbitrary
    // path traversal to non-API endpoints on provider infrastructure.
    let validated_path = match validate_proxy_path(&provider, &path) {
        Ok(p) => p,
        Err(reason) => {
            warn!(provider = %provider, path = %path, reason = %reason, "Proxy path rejected");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "Invalid proxy path",
                    "reason": reason,
                    "provider": provider,
                })),
            )
                .into_response();
        }
    };

    let target_url = format!("{}/{}", base_url, validated_path);
    debug!(provider = %provider, target = %target_url, "Proxying request");

    // 2. Policy check — rate limit via governance gate
    {
        let context = zp_core::PolicyContext {
            action: zp_core::ActionType::ApiCall {
                endpoint: target_url.clone(),
            },
            trust_tier: zp_core::TrustTier::Tier1,
            channel: zp_core::Channel::Api,
            conversation_id: zp_core::ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![format!("proxy/{}", provider)],
            mesh_context: None,
        };
        let actor = zp_core::ActorId::System(format!("proxy:{}", provider));

        let gate_result = state.0.gate.evaluate(&context, actor);

        if gate_result.is_blocked() {
            let reason = match &gate_result.decision {
                zp_core::PolicyDecision::Block { reason, .. } => reason.clone(),
                _ => "Policy denied".to_string(),
            };
            warn!(provider = %provider, reason = %reason, "Proxy request blocked by policy");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "Request blocked by ZeroPoint governance policy",
                    "reason": reason,
                    "provider": provider,
                })),
            )
                .into_response();
        }

        if gate_result.needs_interaction() {
            info!(provider = %provider, "Proxy request flagged for review — allowing");
        }

        // Append the gate's audit entry
        if let Ok(mut audit) = state.0.audit_store.lock() {
            if let Err(e) = audit.append(gate_result.unsealed.clone()) {
                warn!(error = %e, "Failed to append gate audit entry");
            }
        }
    }

    // 3. Forward request to real provider
    let client = reqwest::Client::new();
    let mut req_builder = client.post(&target_url);

    // Forward relevant headers (auth, content-type, provider-specific)
    for (key, value) in headers.iter() {
        let name = key.as_str().to_lowercase();
        match name.as_str() {
            "authorization"
            | "x-api-key"
            | "anthropic-version"
            | "anthropic-beta"
            | "content-type"
            | "accept"
            | "openai-organization"
            | "openai-project" => {
                if let Ok(v) = value.to_str() {
                    req_builder = req_builder.header(key.clone(), v);
                }
            }
            _ => {} // Drop internal headers (host, connection, etc.)
        }
    }

    // Provider-specific request transforms + tier model injection
    let forwarded_body = {
        let mut b = body.to_vec();
        if let Some(model) = tier_model {
            b = inject_model_into_body(&b, model);
        }
        if provider == "abacus" {
            b = strip_tool_strict(&b);
        }
        b
    };
    req_builder = req_builder.body(forwarded_body);

    let response = match req_builder.send().await {
        Ok(resp) => resp,
        Err(e) => {
            error!(provider = %provider, error = %e, "Failed to forward request");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({
                    "error": "Failed to reach provider",
                    "provider": provider,
                    "detail": e.to_string(),
                })),
            )
                .into_response();
        }
    };

    let status = response.status();
    let response_bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            error!(provider = %provider, error = %e, "Failed to read provider response");
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "error": "Failed to read provider response" })),
            )
                .into_response();
        }
    };

    let end = Utc::now();

    // 4. Extract usage metrics from response
    let response_body: Value = serde_json::from_slice(&response_bytes).unwrap_or(Value::Null);
    let usage = extract_usage(&provider, &response_body);
    let (input_per_m, output_per_m) = provider_rates(&provider);
    let cost = estimate_cost_usd(input_per_m, output_per_m, &usage);

    // Collect pricing provenance for receipt extensions
    let provider_profile = catalog_lookup(&provider);
    let pricing_age_days = provider_profile
        .as_ref()
        .and_then(|p| p.pricing_age_days());
    let pricing_source_str = provider_profile.as_ref().map(|p| {
        match &p.pricing_source {
            zp_engine::providers::PricingSource::Fetch { source_url } => {
                format!("fetch:{}", source_url)
            }
            zp_engine::providers::PricingSource::Manual => "manual".to_string(),
            zp_engine::providers::PricingSource::Unknown => "unknown".to_string(),
        }
    });

    // 5. Generate receipt
    let _receipt_id = format!("rcpt-proxy-{}", uuid::Uuid::now_v7());

    let mut receipt_builder = zp_receipt::Receipt::execution("zp-proxy")
        .status(if status.is_success() {
            zp_receipt::Status::Success
        } else {
            zp_receipt::Status::Failed
        })
        .trust_grade(zp_receipt::TrustGrade::C)
        .action(zp_receipt::Action {
            action_type: zp_receipt::ActionType::ApiRequest,
            name: Some(format!("proxy/{}/{}", provider, path)),
            input_hash: None,
            output_hash: None,
            exit_code: Some(status.as_u16() as i32),
            detail: Some(json!({
                "provider": provider,
                "model": usage.model,
                "endpoint": path,
            })),
        })
        .timing(start, end)
        .resources(zp_receipt::Resources {
            cpu_seconds: None,
            memory_peak_bytes: None,
            disk_written_bytes: None,
            network_bytes_sent: Some(response_bytes.len() as u64),
            network_bytes_received: None,
            tokens_input: Some(usage.prompt_tokens),
            tokens_output: Some(usage.completion_tokens),
            cost_usd: Some(cost),
        });

    // Pricing provenance extensions (Commit 5)
    if let Some(ref src) = pricing_source_str {
        receipt_builder = receipt_builder.extension(
            "zp.pricing.source",
            serde_json::Value::String(src.clone()),
        );
    }
    if let Some(age) = pricing_age_days {
        receipt_builder = receipt_builder.extension(
            "zp.pricing.age_days",
            serde_json::Value::Number(age.into()),
        );
        // Emit a staleness warning extension when pricing is stale
        let threshold = stale_threshold_days(&provider);
        if age > threshold {
            receipt_builder = receipt_builder.extension(
                "zp.pricing.stale",
                serde_json::Value::Bool(true),
            );
        }
    }

    let receipt = receipt_builder.finalize();

    info!(
        receipt_id = %receipt.id,
        provider = %provider,
        model = ?usage.model,
        tokens_in = usage.prompt_tokens,
        tokens_out = usage.completion_tokens,
        cost_usd = cost,
        status = %status,
        "Proxied API request"
    );

    // 6. Log to audit trail
    //
    // AUDIT-03: store seals the entry atomically inside a BEGIN IMMEDIATE
    // transaction, so the proxy and tool-lifecycle paths can no longer race
    // even when they go through different AuditStore handles on the same
    // file. Caller does not compute prev_hash any more.
    {
        if let Ok(mut audit) = state.0.audit_store.lock() {
            let unsealed = zp_audit::UnsealedEntry::new(
                zp_core::ActorId::System(format!("proxy:{}", provider)),
                zp_core::AuditAction::ApiCallProxied {
                    provider: provider.clone(),
                    endpoint: path.clone(),
                    tokens_input: usage.prompt_tokens,
                    tokens_output: usage.completion_tokens,
                    cost_usd: cost,
                },
                zp_core::ConversationId::new(),
                zp_core::PolicyDecision::Allow { conditions: vec![] },
                "zp-proxy",
            )
            .with_receipt(receipt.clone());

            if let Err(e) = audit.append(unsealed) {
                warn!(error = %e, "Failed to append proxy audit entry");
            }
        }
    }

    // 7. Return original response with ZP metadata header
    let mut response_headers = HeaderMap::new();
    response_headers.insert("content-type", HeaderValue::from_static("application/json"));
    if let Ok(v) = HeaderValue::from_str(&receipt.id) {
        response_headers.insert("x-zp-receipt-id", v);
    }
    if let Ok(v) = HeaderValue::from_str(&usage.prompt_tokens.to_string()) {
        response_headers.insert("x-zp-tokens-input", v);
    }
    if let Ok(v) = HeaderValue::from_str(&usage.completion_tokens.to_string()) {
        response_headers.insert("x-zp-tokens-output", v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("{:.6}", cost)) {
        response_headers.insert("x-zp-cost-usd", v);
    }

    (
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::OK),
        response_headers,
        response_bytes.to_vec(),
    )
        .into_response()
}

// ============================================================================
// POST /api/v1/pricing/refresh — live pricing refresh endpoint
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PricingRefreshRequest {
    /// Provider host IDs to refresh. Defaults to all hosts with known fetchers.
    #[serde(default)]
    pub hosts: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PricingRefreshResponse {
    pub method: String,
    pub host_ids: Vec<String>,
    pub changed_count: u32,
    pub unchanged_count: u32,
    pub delta_lines: Vec<String>,
    pub source_urls: Vec<String>,
}

pub async fn pricing_refresh_handler(
    State(_state): State<AppState>,
    Json(req): Json<PricingRefreshRequest>,
) -> impl IntoResponse {
    let host_ids = if req.hosts.is_empty() {
        vec!["abacus".to_string()]
    } else {
        req.hosts
    };

    let catalog = catalog_snapshot();
    let result = zp_engine::pricing::refresh_hosts(&catalog, &host_ids, |provider_id| {
        let env_key = format!("{}_API_KEY", provider_id.to_uppercase());
        std::env::var(&env_key).unwrap_or_default()
    })
    .await;

    // Hot-reload the in-process catalog so subsequent proxy requests use
    // updated rates without a server restart.
    reload_provider_catalog(result.updated_profiles.clone());

    info!(
        changed = result.changed_count,
        unchanged = result.unchanged_count,
        hosts = ?result.host_ids,
        "pricing refresh complete"
    );

    Json(PricingRefreshResponse {
        method: result.method,
        host_ids: result.host_ids,
        changed_count: result.changed_count,
        unchanged_count: result.unchanged_count,
        delta_lines: result.delta_lines,
        source_urls: result.source_urls,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_base_urls() {
        assert_eq!(provider_base_url("openai"), Some("https://api.openai.com"));
        assert_eq!(
            provider_base_url("anthropic"),
            Some("https://api.anthropic.com")
        );
        assert_eq!(
            provider_base_url("groq"),
            Some("https://api.groq.com/openai")
        );
        assert_eq!(
            provider_base_url("deepinfra"),
            Some("https://api.deepinfra.com/v1/openai")
        );
        assert_eq!(
            provider_base_url("abacus"),
            Some("https://routellm.abacus.ai/v1")
        );
        assert_eq!(provider_base_url("unknown"), None);
    }

    #[test]
    fn test_strip_tool_strict_removes_field() {
        let body = serde_json::json!({
            "model": "kimi-2.6-thinking",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_weather",
                        "description": "Get weather",
                        "parameters": {},
                        "strict": true
                    }
                }
            ]
        });
        let result = strip_tool_strict(&serde_json::to_vec(&body).unwrap());
        let parsed: Value = serde_json::from_slice(&result).unwrap();
        assert!(
            parsed["tools"][0]["function"].get("strict").is_none(),
            "strict field should be removed"
        );
        assert_eq!(parsed["tools"][0]["function"]["name"], "get_weather");
    }

    #[test]
    fn test_strip_tool_strict_noop_without_tools() {
        let body = serde_json::json!({"model": "kimi", "messages": []});
        let bytes = serde_json::to_vec(&body).unwrap();
        let result = strip_tool_strict(&bytes);
        assert_eq!(result, bytes);
    }

    #[test]
    fn test_extract_openai_usage() {
        let body = json!({
            "model": "gpt-4o-mini",
            "usage": {
                "prompt_tokens": 150,
                "completion_tokens": 50,
                "total_tokens": 200
            }
        });

        let usage = extract_openai_usage(&body);
        assert_eq!(usage.prompt_tokens, 150);
        assert_eq!(usage.completion_tokens, 50);
        assert_eq!(usage.total_tokens, 200);
        assert_eq!(usage.model.as_deref(), Some("gpt-4o-mini"));
    }

    #[test]
    fn test_extract_anthropic_usage() {
        let body = json!({
            "model": "claude-sonnet-4-20250514",
            "usage": {
                "input_tokens": 300,
                "output_tokens": 100
            }
        });

        let usage = extract_anthropic_usage(&body);
        assert_eq!(usage.prompt_tokens, 300);
        assert_eq!(usage.completion_tokens, 100);
        assert_eq!(usage.total_tokens, 400);
        assert_eq!(usage.model.as_deref(), Some("claude-sonnet-4-20250514"));
    }

    #[test]
    fn test_extract_usage_missing_fields() {
        let body = json!({ "id": "chatcmpl-abc123" });
        let usage = extract_openai_usage(&body);
        assert_eq!(usage.prompt_tokens, 0);
        assert_eq!(usage.completion_tokens, 0);
        assert_eq!(usage.model, None);
    }

    #[test]
    fn test_cost_estimation_openai() {
        let usage = UsageMetrics {
            prompt_tokens: 1_000_000,
            completion_tokens: 500_000,
            total_tokens: 1_500_000,
            model: Some("gpt-4o".to_string()),
        };
        // openai catalog rate: $2.50/M input + $10.00/M output
        // 1M * 2.50 + 0.5M * 10.00 = 2.50 + 5.00 = 7.50
        let cost = estimate_cost_usd(2.50, 10.00, &usage);
        assert!((cost - 7.50).abs() < 0.001);
    }

    #[test]
    fn test_cost_estimation_anthropic() {
        let usage = UsageMetrics {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            total_tokens: 2_000_000,
            model: Some("claude-sonnet-4-20250514".to_string()),
        };
        // anthropic catalog rate: $3.00/M input + $15.00/M output
        // 1M * 3 + 1M * 15 = 18.0
        let cost = estimate_cost_usd(3.00, 15.00, &usage);
        assert!((cost - 18.0).abs() < 0.001);
    }

    #[test]
    fn test_cost_estimation_groq_subsidized() {
        let usage = UsageMetrics {
            prompt_tokens: 10_000_000,
            completion_tokens: 5_000_000,
            total_tokens: 15_000_000,
            model: Some("llama-3.1-70b".to_string()),
        };
        // groq catalog rate: $0.05/M input + $0.10/M output
        // 10M * 0.05 + 5M * 0.10 = 0.50 + 0.50 = 1.0
        let cost = estimate_cost_usd(0.05, 0.10, &usage);
        assert!((cost - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_cost_estimation_together_accurate() {
        let usage = UsageMetrics {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            total_tokens: 2_000_000,
            model: Some("meta-llama/Llama-3.3-70B-Instruct-Turbo".to_string()),
        };
        // together catalog rate: $0.20/M input + $0.80/M output
        // 1M * 0.20 + 1M * 0.80 = 1.00
        let cost = estimate_cost_usd(0.20, 0.80, &usage);
        assert!((cost - 1.00).abs() < 0.001);
    }

    #[test]
    fn test_cost_estimation_fallback() {
        let usage = UsageMetrics {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            total_tokens: 2_000_000,
            model: None,
        };
        // fallback: $1.00/M input + $4.00/M output
        let cost = estimate_cost_usd(1.00, 4.00, &usage);
        assert!((cost - 5.00).abs() < 0.001);
    }
}
