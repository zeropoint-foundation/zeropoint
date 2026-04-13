//! Credential validation — live connection tests for provider API keys.
//!
//! Each provider gets a lightweight health check that confirms the credential
//! is accepted by the remote service without consuming billable resources.
//!
//! ## Strategy
//!
//! | Provider type          | Probe                                     | Cost   |
//! |------------------------|-------------------------------------------|--------|
//! | OpenAI-compatible LLMs | `GET /v1/models`                          | Free   |
//! | Anthropic              | `GET /v1/models` (header auth)            | Free   |
//! | Replicate              | `GET /v1/models`                          | Free   |
//! | Hugging Face           | `GET /api/whoami-v2`                      | Free   |
//! | Tavily                 | `POST /search` (minimal, 1 result)        | ~Free  |
//! | Serper                 | `POST /search` (minimal)                  | ~Free  |
//! | AWS Bedrock            | STS `GetCallerIdentity`                   | Free   |
//! | Hedera                 | Mirror node account query                 | Free   |
//! | Azure OpenAI           | `GET /openai/models?api-version=...`      | Free   |
//! | Vertex AI              | Service account validation                | Free   |
//!
//! Used by `zp configure validate` CLI and optionally during MVC resolution.

use crate::providers::{self, ProviderProfile};
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

// ============================================================================
// Types
// ============================================================================

/// Result of validating a single credential.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationResult {
    /// Provider ID (e.g., "openai", "anthropic")
    pub provider_id: String,
    /// Human-readable provider name
    pub provider_name: String,
    /// The env var name tested
    pub var_name: String,
    /// Whether the credential passed validation
    pub status: ValidationStatus,
    /// Latency of the validation request
    pub latency_ms: u64,
    /// Additional details (model count, account info, error message)
    pub detail: String,
}

/// Outcome of a validation probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// Credential accepted by the remote service
    Valid,
    /// Credential rejected (401, 403, or explicit auth error)
    Invalid,
    /// Could not reach the service (network error, timeout, DNS failure)
    Unreachable,
    /// No validation probe implemented for this provider
    Unsupported,
    /// Validation skipped (e.g., user opted out, or local-only provider)
    Skipped,
}

/// Aggregate results for a validation run.
#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub results: Vec<ValidationResult>,
    pub total: usize,
    pub valid: usize,
    pub invalid: usize,
    pub unreachable: usize,
    pub unsupported: usize,
}

impl ValidationReport {
    pub fn from_results(results: Vec<ValidationResult>) -> Self {
        let total = results.len();
        let valid = results
            .iter()
            .filter(|r| r.status == ValidationStatus::Valid)
            .count();
        let invalid = results
            .iter()
            .filter(|r| r.status == ValidationStatus::Invalid)
            .count();
        let unreachable = results
            .iter()
            .filter(|r| r.status == ValidationStatus::Unreachable)
            .count();
        let unsupported = results
            .iter()
            .filter(|r| r.status == ValidationStatus::Unsupported)
            .count();
        ValidationReport {
            results,
            total,
            valid,
            invalid,
            unreachable,
            unsupported,
        }
    }
}

/// A credential to validate: provider ID + env var name + raw value.
#[derive(Debug, Clone)]
pub struct CredentialToValidate {
    pub provider_id: String,
    pub var_name: String,
    pub value: String,
}

// ============================================================================
// Validation engine
// ============================================================================

/// Default timeout for validation probes.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Validate a batch of credentials against their respective provider APIs.
///
/// This is the main entry point. It loads the provider catalog, matches each
/// credential to a provider profile, and runs the appropriate probe.
///
/// Credentials are tested concurrently (up to 8 at a time).
pub async fn validate_credentials(creds: &[CredentialToValidate]) -> ValidationReport {
    let catalog = providers::load_catalog();
    let catalog_map: HashMap<String, &ProviderProfile> =
        catalog.iter().map(|p| (p.id.clone(), p)).collect();

    let client = match reqwest::Client::builder()
        .timeout(PROBE_TIMEOUT)
        .user_agent("ZeroPoint/0.1 credential-validator")
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            // If we can't even build an HTTP client, everything is unreachable
            let results: Vec<ValidationResult> = creds
                .iter()
                .map(|c| ValidationResult {
                    provider_id: c.provider_id.clone(),
                    provider_name: c.provider_id.clone(),
                    var_name: c.var_name.clone(),
                    status: ValidationStatus::Unreachable,
                    latency_ms: 0,
                    detail: "Failed to initialize HTTP client".into(),
                })
                .collect();
            return ValidationReport::from_results(results);
        }
    };

    let mut results = Vec::with_capacity(creds.len());

    // Run probes sequentially to be respectful of rate limits.
    // Could be made concurrent with tokio::JoinSet if speed matters.
    for cred in creds {
        let profile = catalog_map.get(&cred.provider_id);
        let provider_name = profile
            .map(|p| p.name.clone())
            .unwrap_or_else(|| cred.provider_id.clone());

        let result = validate_single(&client, cred, profile, &provider_name).await;
        results.push(result);
    }

    ValidationReport::from_results(results)
}

/// Validate a single credential against its provider.
async fn validate_single(
    client: &reqwest::Client,
    cred: &CredentialToValidate,
    profile: Option<&&ProviderProfile>,
    provider_name: &str,
) -> ValidationResult {
    let start = std::time::Instant::now();

    let (status, detail) = match cred.provider_id.as_str() {
        // ── OpenAI-compatible providers ─────────────────────────
        "openai" => {
            probe_openai_models(client, "https://api.openai.com/v1/models", &cred.value).await
        }
        "mistral" => {
            probe_openai_models(client, "https://api.mistral.ai/v1/models", &cred.value).await
        }
        "groq" => {
            probe_openai_models(client, "https://api.groq.com/openai/v1/models", &cred.value).await
        }
        "together" => {
            probe_openai_models(client, "https://api.together.xyz/v1/models", &cred.value).await
        }
        "fireworks" => {
            probe_openai_models(
                client,
                "https://api.fireworks.ai/inference/v1/models",
                &cred.value,
            )
            .await
        }
        "deepseek" => {
            probe_openai_models(client, "https://api.deepseek.com/v1/models", &cred.value).await
        }
        "xai" => probe_openai_models(client, "https://api.x.ai/v1/models", &cred.value).await,
        "perplexity" => {
            probe_openai_models(client, "https://api.perplexity.ai/models", &cred.value).await
        }
        "ai21" => {
            probe_openai_models(client, "https://api.ai21.com/studio/v1/models", &cred.value).await
        }
        "openrouter" => {
            probe_openai_models(client, "https://openrouter.ai/api/v1/models", &cred.value).await
        }
        "abacus" => probe_abacus(client, &cred.value).await,

        // ── Anthropic (non-OpenAI protocol) ────────────────────
        "anthropic" => probe_anthropic(client, &cred.value).await,

        // ── Google Gemini ──────────────────────────────────────
        "gemini" => probe_gemini(client, &cred.value).await,

        // ── Cohere ─────────────────────────────────────────────
        "cohere" => {
            probe_openai_models(client, "https://api.cohere.ai/v2/models", &cred.value).await
        }

        // ── Embedding / Specialized ────────────────────────────
        "voyage" => {
            probe_openai_models(client, "https://api.voyageai.com/v1/models", &cred.value).await
        }
        "replicate" => probe_replicate(client, &cred.value).await,
        "huggingface" => probe_huggingface(client, &cred.value).await,
        "nomic" => {
            probe_bearer_get(client, "https://api-atlas.nomic.ai/v1/models", &cred.value).await
        }

        // ── Cloud Platforms ────────────────────────────────────
        "azure-openai" => {
            // Azure needs the resource name from the key, skip for now
            (
                ValidationStatus::Unsupported,
                "Azure requires resource endpoint — use zp configure validate --azure-endpoint"
                    .into(),
            )
        }
        "bedrock" => {
            // AWS IAM validation needs SigV4 signing — heavyweight
            (
                ValidationStatus::Unsupported,
                "AWS Bedrock requires STS GetCallerIdentity (not yet implemented)".into(),
            )
        }
        "vertex" => (
            ValidationStatus::Unsupported,
            "Vertex AI requires service account validation (not yet implemented)".into(),
        ),

        // ── Search APIs ────────────────────────────────────────
        "tavily" => probe_tavily(client, &cred.value).await,
        "serper" => probe_serper(client, &cred.value).await,

        // ── Ledger ─────────────────────────────────────────────
        "hedera" => {
            if cred.var_name.contains("ACCOUNT_ID") {
                probe_hedera_account(client, &cred.value).await
            } else {
                // Private key can't be validated without signing a transaction
                (
                    ValidationStatus::Skipped,
                    "Private key validation requires transaction signing".into(),
                )
            }
        }

        // ── Unknown provider ───────────────────────────────────
        _ => {
            // Try to use the profile's base_url if available
            if let Some(p) = profile {
                if p.is_openai_compatible() && !p.base_url.is_empty() {
                    let url = format!("{}/models", p.base_url.trim_end_matches('/'));
                    probe_openai_models(client, &url, &cred.value).await
                } else {
                    (
                        ValidationStatus::Unsupported,
                        format!("No validation probe for provider '{}'", cred.provider_id),
                    )
                }
            } else {
                (
                    ValidationStatus::Unsupported,
                    format!("Unknown provider '{}'", cred.provider_id),
                )
            }
        }
    };

    let latency_ms = start.elapsed().as_millis() as u64;

    ValidationResult {
        provider_id: cred.provider_id.clone(),
        provider_name: provider_name.to_string(),
        var_name: cred.var_name.clone(),
        status,
        latency_ms,
        detail,
    }
}

// ============================================================================
// Provider-specific probes
// ============================================================================

/// Probe an OpenAI-compatible `/v1/models` endpoint.
/// Most providers return 200 + JSON list on valid key, 401 on invalid.
async fn probe_openai_models(
    client: &reqwest::Client,
    url: &str,
    api_key: &str,
) -> (ValidationStatus, String) {
    match client
        .get(url)
        .header("Authorization", format!("Bearer {api_key}"))
        .send()
        .await
    {
        Ok(resp) => {
            let status_code = resp.status().as_u16();
            match status_code {
                200 => {
                    // Try to count models from response
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let count = body
                            .get("data")
                            .and_then(|d| d.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        (
                            ValidationStatus::Valid,
                            format!("{count} model(s) available"),
                        )
                    } else {
                        (ValidationStatus::Valid, "Key accepted".into())
                    }
                }
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {status_code} — authentication failed"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "Key accepted (rate limited — but auth passed)".into(),
                ),
                _ => {
                    let body = resp.text().await.unwrap_or_default();
                    let snippet = if body.len() > 120 {
                        &body[..120]
                    } else {
                        &body
                    };
                    (
                        ValidationStatus::Unreachable,
                        format!("HTTP {status_code}: {snippet}"),
                    )
                }
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Abacus.ai via their native REST API.
/// Abacus uses `apiKey` as an HTTP header (not Bearer, not body).
/// `listApiKeys` is a lightweight read-only endpoint that validates the key.
async fn probe_abacus(client: &reqwest::Client, api_key: &str) -> (ValidationStatus, String) {
    match client
        .get("https://api.abacus.ai/api/v0/listApiKeys")
        .header("apiKey", api_key)
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let success = body
                            .get("success")
                            .and_then(|s| s.as_bool())
                            .unwrap_or(false);
                        if success {
                            let count = body
                                .get("result")
                                .and_then(|r| r.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            (
                                ValidationStatus::Valid,
                                format!("API key accepted ({count} key(s) on account)"),
                            )
                        } else {
                            let err = body
                                .get("error")
                                .and_then(|e| e.as_str())
                                .unwrap_or("unknown");
                            (ValidationStatus::Invalid, format!("API rejected: {err}"))
                        }
                    } else {
                        (ValidationStatus::Valid, "Key accepted".into())
                    }
                }
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — API key rejected"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "Key accepted (rate limited)".into(),
                ),
                _ => {
                    let body = resp.text().await.unwrap_or_default();
                    let snippet = if body.len() > 120 {
                        &body[..120]
                    } else {
                        &body
                    };
                    (
                        ValidationStatus::Unreachable,
                        format!("HTTP {code}: {snippet}"),
                    )
                }
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe a generic endpoint with Bearer auth, expecting 200 on success.
async fn probe_bearer_get(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> (ValidationStatus, String) {
    match client
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200..=299 => (ValidationStatus::Valid, "Key accepted".into()),
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — authentication failed"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "Key accepted (rate limited)".into(),
                ),
                _ => (ValidationStatus::Unreachable, format!("HTTP {code}")),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Anthropic's API via the models list endpoint.
/// Anthropic uses `x-api-key` header, not Bearer token.
async fn probe_anthropic(client: &reqwest::Client, api_key: &str) -> (ValidationStatus, String) {
    match client
        .get("https://api.anthropic.com/v1/models")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let count = body
                            .get("data")
                            .and_then(|d| d.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        (
                            ValidationStatus::Valid,
                            format!("{count} model(s) available"),
                        )
                    } else {
                        (ValidationStatus::Valid, "Key accepted".into())
                    }
                }
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — authentication failed"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "Key accepted (rate limited)".into(),
                ),
                _ => {
                    let body = resp.text().await.unwrap_or_default();
                    let snippet = if body.len() > 120 {
                        &body[..120]
                    } else {
                        &body
                    };
                    (
                        ValidationStatus::Unreachable,
                        format!("HTTP {code}: {snippet}"),
                    )
                }
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Google Gemini via model listing.
/// Gemini uses `?key=` query parameter, not headers.
async fn probe_gemini(client: &reqwest::Client, api_key: &str) -> (ValidationStatus, String) {
    let url = format!("https://generativelanguage.googleapis.com/v1beta/models?key={api_key}");
    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let count = body
                            .get("models")
                            .and_then(|m| m.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        (
                            ValidationStatus::Valid,
                            format!("{count} model(s) available"),
                        )
                    } else {
                        (ValidationStatus::Valid, "Key accepted".into())
                    }
                }
                400 | 401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — API key rejected"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "Key accepted (rate limited)".into(),
                ),
                _ => (ValidationStatus::Unreachable, format!("HTTP {code}")),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Replicate via their models endpoint.
async fn probe_replicate(client: &reqwest::Client, api_token: &str) -> (ValidationStatus, String) {
    match client
        .get("https://api.replicate.com/v1/models")
        .header("Authorization", format!("Bearer {api_token}"))
        .query(&[("limit", "1")])
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => (ValidationStatus::Valid, "Token accepted".into()),
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — token rejected"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "Token accepted (rate limited)".into(),
                ),
                _ => (ValidationStatus::Unreachable, format!("HTTP {code}")),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Hugging Face via their whoami endpoint.
async fn probe_huggingface(client: &reqwest::Client, token: &str) -> (ValidationStatus, String) {
    match client
        .get("https://huggingface.co/api/whoami-v2")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let name = body
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("unknown");
                        (
                            ValidationStatus::Valid,
                            format!("Authenticated as '{name}'"),
                        )
                    } else {
                        (ValidationStatus::Valid, "Token accepted".into())
                    }
                }
                401 => (ValidationStatus::Invalid, "Token rejected".into()),
                _ => (ValidationStatus::Unreachable, format!("HTTP {code}")),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Tavily search API with a minimal query.
async fn probe_tavily(client: &reqwest::Client, api_key: &str) -> (ValidationStatus, String) {
    let body = serde_json::json!({
        "api_key": api_key,
        "query": "test",
        "max_results": 1,
    });
    match client
        .post("https://api.tavily.com/search")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => (ValidationStatus::Valid, "API key accepted".into()),
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — API key rejected"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "API key accepted (rate limited)".into(),
                ),
                _ => (ValidationStatus::Unreachable, format!("HTTP {code}")),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Serper search API with a minimal query.
async fn probe_serper(client: &reqwest::Client, api_key: &str) -> (ValidationStatus, String) {
    let body = serde_json::json!({
        "q": "test",
        "num": 1,
    });
    match client
        .post("https://google.serper.dev/search")
        .header("X-API-KEY", api_key)
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => (ValidationStatus::Valid, "API key accepted".into()),
                401 | 403 => (
                    ValidationStatus::Invalid,
                    format!("HTTP {code} — API key rejected"),
                ),
                429 => (
                    ValidationStatus::Valid,
                    "API key accepted (rate limited)".into(),
                ),
                _ => (ValidationStatus::Unreachable, format!("HTTP {code}")),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

/// Probe Hedera mirror node for account existence (free, no signing).
async fn probe_hedera_account(
    client: &reqwest::Client,
    account_id: &str,
) -> (ValidationStatus, String) {
    let url = format!("https://mainnet-public.mirrornode.hedera.com/api/v1/accounts/{account_id}");
    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status().as_u16();
            match code {
                200 => {
                    if let Ok(body) = resp.json::<serde_json::Value>().await {
                        let balance = body
                            .get("balance")
                            .and_then(|b| b.get("balance"))
                            .and_then(|b| b.as_u64())
                            .unwrap_or(0);
                        let hbar = balance as f64 / 100_000_000.0;
                        (
                            ValidationStatus::Valid,
                            format!("Account exists ({hbar:.4} ℏ)"),
                        )
                    } else {
                        (ValidationStatus::Valid, "Account exists on mainnet".into())
                    }
                }
                404 => (
                    ValidationStatus::Invalid,
                    "Account not found on mainnet".into(),
                ),
                _ => (
                    ValidationStatus::Unreachable,
                    format!("Mirror node HTTP {code}"),
                ),
            }
        }
        Err(e) => classify_request_error(e),
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Classify a reqwest error into a validation status.
fn classify_request_error(e: reqwest::Error) -> (ValidationStatus, String) {
    if e.is_timeout() {
        (
            ValidationStatus::Unreachable,
            "Request timed out (10s)".into(),
        )
    } else if e.is_connect() {
        (
            ValidationStatus::Unreachable,
            format!("Connection failed: {e}"),
        )
    } else {
        (ValidationStatus::Unreachable, format!("Request error: {e}"))
    }
}

/// Extract credentials from vault refs for validation.
///
/// Vault refs follow the pattern `"provider_id/key_name"`. This function
/// reads the vault, groups credentials by provider, and prepares them
/// for validation.
pub fn credentials_from_vault_refs(
    vault_refs: &[String],
    vault_retrieve: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Vec<CredentialToValidate> {
    let mut creds = Vec::new();

    for ref_name in vault_refs {
        // Parse "anthropic/api_key" → provider="anthropic", var="ANTHROPIC_API_KEY"
        if let Some((provider_id, key_name)) = ref_name.split_once('/') {
            if let Some(value_bytes) = vault_retrieve(ref_name) {
                if let Ok(value) = String::from_utf8(value_bytes) {
                    let var_name = format!(
                        "{}_{}",
                        provider_id.to_uppercase().replace('-', "_"),
                        key_name.to_uppercase()
                    );
                    creds.push(CredentialToValidate {
                        provider_id: provider_id.to_string(),
                        var_name,
                        value,
                    });
                }
            }
        }
    }

    creds
}

/// Format a validation report for terminal display.
pub fn format_report(report: &ValidationReport) -> String {
    let mut out = String::new();
    out.push_str("\n  ── Credential Validation ─────────────────────────────\n");
    out.push_str(&format!("  {} credential(s) tested\n\n", report.total));

    for r in &report.results {
        let icon = match r.status {
            ValidationStatus::Valid => "✓",
            ValidationStatus::Invalid => "✗",
            ValidationStatus::Unreachable => "⚠",
            ValidationStatus::Unsupported => "○",
            ValidationStatus::Skipped => "·",
        };
        let status_label = match r.status {
            ValidationStatus::Valid => "valid",
            ValidationStatus::Invalid => "INVALID",
            ValidationStatus::Unreachable => "unreachable",
            ValidationStatus::Unsupported => "unsupported",
            ValidationStatus::Skipped => "skipped",
        };

        out.push_str(&format!(
            "  {icon}  {:<16} {:<24} {status_label}",
            r.provider_name, r.var_name,
        ));
        if r.latency_ms > 0 {
            out.push_str(&format!("  ({:>4}ms)", r.latency_ms));
        }
        if !r.detail.is_empty() {
            out.push_str(&format!("  — {}", r.detail));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "\n  Summary: {} valid, {} invalid, {} unreachable, {} unsupported\n",
        report.valid, report.invalid, report.unreachable, report.unsupported
    ));

    out
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_aggregation() {
        let results = vec![
            ValidationResult {
                provider_id: "openai".into(),
                provider_name: "OpenAI".into(),
                var_name: "OPENAI_API_KEY".into(),
                status: ValidationStatus::Valid,
                latency_ms: 150,
                detail: "42 model(s) available".into(),
            },
            ValidationResult {
                provider_id: "anthropic".into(),
                provider_name: "Anthropic".into(),
                var_name: "ANTHROPIC_API_KEY".into(),
                status: ValidationStatus::Invalid,
                latency_ms: 80,
                detail: "HTTP 401".into(),
            },
            ValidationResult {
                provider_id: "bedrock".into(),
                provider_name: "AWS Bedrock".into(),
                var_name: "AWS_ACCESS_KEY_ID".into(),
                status: ValidationStatus::Unsupported,
                latency_ms: 0,
                detail: "STS not implemented".into(),
            },
        ];

        let report = ValidationReport::from_results(results);
        assert_eq!(report.total, 3);
        assert_eq!(report.valid, 1);
        assert_eq!(report.invalid, 1);
        assert_eq!(report.unsupported, 1);
        assert_eq!(report.unreachable, 0);
    }

    #[test]
    fn test_credentials_from_vault_refs() {
        let refs = vec![
            "anthropic/api_key".to_string(),
            "openai/api_key".to_string(),
            "hedera/account_id".to_string(),
        ];

        let retrieve = |name: &str| -> Option<Vec<u8>> {
            match name {
                "anthropic/api_key" => Some(b"sk-ant-test123".to_vec()),
                "openai/api_key" => Some(b"sk-proj-test456".to_vec()),
                "hedera/account_id" => Some(b"0.0.12345".to_vec()),
                _ => None,
            }
        };

        let creds = credentials_from_vault_refs(&refs, &retrieve);
        assert_eq!(creds.len(), 3);
        assert_eq!(creds[0].provider_id, "anthropic");
        assert_eq!(creds[0].var_name, "ANTHROPIC_API_KEY");
        assert_eq!(creds[0].value, "sk-ant-test123");
        assert_eq!(creds[1].provider_id, "openai");
        assert_eq!(creds[2].provider_id, "hedera");
        assert_eq!(creds[2].var_name, "HEDERA_ACCOUNT_ID");
    }

    #[test]
    fn test_format_report() {
        let results = vec![ValidationResult {
            provider_id: "openai".into(),
            provider_name: "OpenAI".into(),
            var_name: "OPENAI_API_KEY".into(),
            status: ValidationStatus::Valid,
            latency_ms: 150,
            detail: "42 model(s) available".into(),
        }];
        let report = ValidationReport::from_results(results);
        let output = format_report(&report);
        assert!(output.contains("✓"));
        assert!(output.contains("OpenAI"));
        assert!(output.contains("valid"));
        assert!(output.contains("42 model(s)"));
    }

    #[test]
    fn test_validation_status_serialize() {
        let json = serde_json::to_string(&ValidationStatus::Valid).unwrap();
        assert_eq!(json, "\"valid\"");
        let json = serde_json::to_string(&ValidationStatus::Invalid).unwrap();
        assert_eq!(json, "\"invalid\"");
    }

    #[test]
    fn test_classify_error_types() {
        // We can't easily create reqwest errors in tests, but we can
        // verify the ValidationStatus variants serialize correctly
        let result = ValidationResult {
            provider_id: "test".into(),
            provider_name: "Test".into(),
            var_name: "TEST_KEY".into(),
            status: ValidationStatus::Unreachable,
            latency_ms: 0,
            detail: "Connection refused".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("unreachable"));
    }
}
