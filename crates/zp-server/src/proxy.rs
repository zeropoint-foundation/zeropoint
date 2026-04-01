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
use tracing::{debug, error, info, warn};

use crate::AppState;

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
        _ => None,
    }
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
        prompt_tokens: usage.get("prompt_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        completion_tokens: usage.get("completion_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        total_tokens: usage.get("total_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        model: body.get("model").and_then(|v| v.as_str()).map(|s| s.to_string()),
    }
}

/// Extract token usage from an Anthropic-format response.
fn extract_anthropic_usage(body: &Value) -> UsageMetrics {
    let usage = body.get("usage").unwrap_or(&Value::Null);
    let input = usage.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    let output = usage.get("output_tokens").and_then(|v| v.as_u64()).unwrap_or(0);
    UsageMetrics {
        prompt_tokens: input,
        completion_tokens: output,
        total_tokens: input + output,
        model: body.get("model").and_then(|v| v.as_str()).map(|s| s.to_string()),
    }
}

/// Extract usage from any known provider response.
pub fn extract_usage(provider: &str, body: &Value) -> UsageMetrics {
    match provider {
        "anthropic" => extract_anthropic_usage(body),
        _ => extract_openai_usage(body), // Most providers use OpenAI format
    }
}

// ============================================================================
// Cost estimation — per-provider token pricing
// ============================================================================

/// Rough cost-per-token estimates (USD) for common models.
/// These are approximations for governance/budgeting, not billing.
pub fn estimate_cost_usd(provider: &str, model: Option<&str>, usage: &UsageMetrics) -> f64 {
    let (input_per_m, output_per_m) = match (provider, model) {
        // Anthropic
        (_, Some(m)) if m.contains("claude-3-5-sonnet") || m.contains("claude-sonnet-4") => (3.0, 15.0),
        (_, Some(m)) if m.contains("claude-3-5-haiku") || m.contains("claude-haiku-4") => (0.80, 4.0),
        (_, Some(m)) if m.contains("claude-3-opus") || m.contains("claude-opus-4") => (15.0, 75.0),
        // OpenAI
        (_, Some(m)) if m.contains("gpt-4o-mini") => (0.15, 0.60),
        (_, Some(m)) if m.contains("gpt-4o") => (2.50, 10.0),
        (_, Some(m)) if m.contains("gpt-4-turbo") => (10.0, 30.0),
        (_, Some(m)) if m.contains("o1") => (15.0, 60.0),
        (_, Some(m)) if m.contains("o3") => (10.0, 40.0),
        // Groq (heavily subsidized)
        ("groq", _) => (0.05, 0.10),
        // DeepSeek
        (_, Some(m)) if m.contains("deepseek") => (0.27, 1.10),
        // Fallback: conservative estimate
        _ => (3.0, 15.0),
    };

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
                                       "google", "openrouter", "siliconflow"]
                })),
            )
                .into_response();
        }
    };

    let target_url = format!("{}/{}", base_url, path);
    debug!(provider = %provider, target = %target_url, "Proxying request");

    // 2. Policy check — rate limit via governance gate
    {
        let context = zp_core::PolicyContext {
            action: zp_core::ActionType::ApiCall { endpoint: target_url.clone() },
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
        if let Ok(audit) = state.0.audit_store.lock() {
            if let Err(e) = audit.append(gate_result.audit_entry) {
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
            "authorization" | "x-api-key" | "anthropic-version" | "anthropic-beta"
            | "content-type" | "accept" | "openai-organization" | "openai-project" => {
                if let Ok(v) = value.to_str() {
                    req_builder = req_builder.header(key.clone(), v);
                }
            }
            _ => {} // Drop internal headers (host, connection, etc.)
        }
    }

    req_builder = req_builder.body(body.to_vec());

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
    let cost = estimate_cost_usd(&provider, usage.model.as_deref(), &usage);

    // 5. Generate receipt
    let _receipt_id = format!("rcpt-proxy-{}", uuid::Uuid::now_v7());

    let receipt = zp_receipt::Receipt::execution("zp-proxy")
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
        })
        .finalize();

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
    {
        if let Ok(audit) = state.0.audit_store.lock() {
            let prev_hash = audit
                .get_latest_hash()
                .unwrap_or_else(|_| "genesis".to_string());

            let entry = zp_audit::chain::ChainBuilder::build_entry(
                &prev_hash,
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
                "zp-proxy".to_string(),
                Some(receipt.clone()),
                None,
            );

            if let Err(e) = audit.append(entry) {
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
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_base_urls() {
        assert_eq!(provider_base_url("openai"), Some("https://api.openai.com"));
        assert_eq!(provider_base_url("anthropic"), Some("https://api.anthropic.com"));
        assert_eq!(provider_base_url("groq"), Some("https://api.groq.com/openai"));
        assert_eq!(provider_base_url("unknown"), None);
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
            model: Some("gpt-4o-mini".to_string()),
        };
        let cost = estimate_cost_usd("openai", Some("gpt-4o-mini"), &usage);
        // gpt-4o-mini: $0.15/M input + $0.60/M output
        // 1M * 0.15 + 0.5M * 0.60 = 0.15 + 0.30 = 0.45
        assert!((cost - 0.45).abs() < 0.001);
    }

    #[test]
    fn test_cost_estimation_anthropic() {
        let usage = UsageMetrics {
            prompt_tokens: 1_000_000,
            completion_tokens: 1_000_000,
            total_tokens: 2_000_000,
            model: Some("claude-sonnet-4-20250514".to_string()),
        };
        let cost = estimate_cost_usd("anthropic", Some("claude-sonnet-4-20250514"), &usage);
        // claude-sonnet-4: $3/M input + $15/M output
        // 1M * 3 + 1M * 15 = 18.0
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
        let cost = estimate_cost_usd("groq", Some("llama-3.1-70b"), &usage);
        // groq: $0.05/M input + $0.10/M output
        // 10M * 0.05 + 5M * 0.10 = 0.50 + 0.50 = 1.0
        assert!((cost - 1.0).abs() < 0.001);
    }
}
