//! Capability Verification — Tier 1 + Tier 2 post-launch probes.
//!
//! After a tool reaches `health:up`, ZP probes the tool's declared
//! verification endpoints to confirm credentials made it through the
//! tool's internal resolution chain.
//!
//! Tier 1 (`providers_endpoint`):
//!   Queries the tool's provider introspection endpoint.
//!   Emits `tool:providers:resolved:{name}` with loaded/missing detail.
//!
//! Tier 2 (`endpoints`):
//!   Probes per-capability verify endpoints.
//!   Emits `tool:capability:verified|degraded|failed:{name}:{cap}`.
//!
//! The manifest's `[verification]` section declares what to probe.
//! Tools without this section skip verification entirely (Tier 0 only).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zp_audit::AuditStore;
use zp_engine::capability::{ToolManifest, VerificationConfig};

use crate::tool_chain::{emit_tool_receipt, ToolEvent};

/// Result of a full verification run for a single tool.
#[derive(Debug)]
pub struct VerificationResult {
    pub providers_resolved: bool,
    pub loaded_providers: Vec<String>,
    pub missing_providers: Vec<String>,
    pub capabilities: Vec<CapabilityResult>,
}

#[derive(Debug)]
pub struct CapabilityResult {
    pub capability: String,
    pub status: String, // "verified", "degraded", "failed"
    pub detail: String,
}

impl Default for VerificationResult {
    fn default() -> Self {
        Self {
            providers_resolved: false,
            loaded_providers: vec![],
            missing_providers: vec![],
            capabilities: vec![],
        }
    }
}

/// Run Tier 1 + Tier 2 verification for a tool after it reaches health:up.
///
/// This is an async function meant to be spawned as a background task
/// from the launch/health transition path.
pub async fn verify_tool_capabilities(
    tool_name: &str,
    tool_port: u16,
    manifest: &ToolManifest,
    verification: &VerificationConfig,
    audit_store: &Arc<Mutex<AuditStore>>,
) -> VerificationResult {
    let base = format!("http://127.0.0.1:{}", tool_port);
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("verify: failed to build HTTP client: {}", e);
            return VerificationResult::default();
        }
    };

    // Wait for the configured delay to let the tool finish internal init
    let delay = Duration::from_secs(verification.delay_secs);
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }

    let retries = verification.retries;
    let mut result = VerificationResult::default();

    // ── Tier 1: Provider resolution ────────────────────────────────
    if let Some(providers_ep) = &verification.providers_endpoint {
        let url = format!("{}{}", base, providers_ep);
        tracing::info!("verify[{}]: Tier 1 — probing {}", tool_name, url);

        match probe_with_retry(&client, "GET", &url, &Default::default(), None, retries).await {
            ProbeResult::Success(body) => {
                // Parse response to determine which providers loaded.
                // Expected shape: { "provider_id": { ... }, ... }
                // A provider with any content = loaded. Empty object or absent = missing.
                let mut loaded = Vec::new();
                let mut missing = Vec::new();

                if let Some(providers) = body.as_object() {
                    for (id, info) in providers {
                        let has_content = info.as_object().map_or(false, |o| !o.is_empty());
                        if has_content {
                            loaded.push(id.clone());
                        } else {
                            missing.push(id.clone());
                        }
                    }
                }

                let detail = format!(
                    "loaded={},missing={}",
                    if loaded.is_empty() { "none".into() } else { loaded.join("+") },
                    if missing.is_empty() { "none".into() } else { missing.join("+") },
                );

                tracing::info!("verify[{}]: Tier 1 — {}", tool_name, detail);

                emit_tool_receipt(
                    audit_store,
                    &ToolEvent::providers_resolved(tool_name),
                    Some(&detail),
                );

                result.providers_resolved = true;
                result.loaded_providers = loaded;
                result.missing_providers = missing;
            }
            ProbeResult::HttpError(status, body_text) => {
                let detail = format!("status={},body={}", status, truncate(&body_text, 200));
                tracing::warn!("verify[{}]: Tier 1 — HTTP error: {}", tool_name, detail);
                emit_tool_receipt(
                    audit_store,
                    &ToolEvent::providers_resolved(tool_name),
                    Some(&format!("error: {}", detail)),
                );
            }
            ProbeResult::ConnectionError(e) => {
                tracing::warn!("verify[{}]: Tier 1 — connection error: {}", tool_name, e);
                emit_tool_receipt(
                    audit_store,
                    &ToolEvent::providers_resolved(tool_name),
                    Some(&format!("error: {}", e)),
                );
            }
        }
    }

    // ── Tier 2: Per-capability verification ─────────────────────────
    //
    // Build the set of required capabilities so we can distinguish
    // "failed" (required) from "degraded" (optional).
    let required_caps: HashSet<&str> = manifest
        .required
        .iter()
        .map(|r| r.capability.as_str())
        .collect();

    for (capability, endpoint) in &verification.endpoints {
        let url = format!("{}{}", base, endpoint);
        let probe_cfg = verification.probes.get(capability);
        let method = probe_cfg
            .map(|p| p.method.as_str())
            .unwrap_or("GET");
        let headers = probe_cfg
            .map(|p| &p.headers)
            .cloned()
            .unwrap_or_default();
        let body = probe_cfg.and_then(|p| p.body.as_deref());

        tracing::info!(
            "verify[{}]: Tier 2 — probing {} {} ({})",
            tool_name, method, url, capability
        );

        let is_required = required_caps.contains(capability.as_str());

        match probe_with_retry(&client, method, &url, &headers, body, retries).await {
            ProbeResult::Success(_) => {
                let detail = format!("provider=resolved");
                tracing::info!(
                    "verify[{}]: {} — verified", tool_name, capability
                );

                emit_tool_receipt(
                    audit_store,
                    &ToolEvent::capability_verified(tool_name, capability),
                    Some(&detail),
                );

                result.capabilities.push(CapabilityResult {
                    capability: capability.clone(),
                    status: "verified".into(),
                    detail,
                });
            }
            ProbeResult::HttpError(status, body_text) => {
                let detail = format!(
                    "status={},body={}",
                    status,
                    truncate(&body_text, 200)
                );
                let (event_fn, status_str): (fn(&str, &str) -> String, &str) = if is_required {
                    (ToolEvent::capability_failed, "failed")
                } else {
                    (ToolEvent::capability_degraded, "degraded")
                };

                tracing::warn!(
                    "verify[{}]: {} — {} ({})",
                    tool_name, capability, status_str, detail
                );

                emit_tool_receipt(
                    audit_store,
                    &event_fn(tool_name, capability),
                    Some(&detail),
                );

                result.capabilities.push(CapabilityResult {
                    capability: capability.clone(),
                    status: status_str.into(),
                    detail,
                });
            }
            ProbeResult::ConnectionError(e) => {
                let detail = format!("error={}", e);
                let (event_fn, status_str): (fn(&str, &str) -> String, &str) = if is_required {
                    (ToolEvent::capability_failed, "failed")
                } else {
                    (ToolEvent::capability_degraded, "degraded")
                };

                tracing::warn!(
                    "verify[{}]: {} — {} ({})",
                    tool_name, capability, status_str, detail
                );

                emit_tool_receipt(
                    audit_store,
                    &event_fn(tool_name, capability),
                    Some(&detail),
                );

                result.capabilities.push(CapabilityResult {
                    capability: capability.clone(),
                    status: status_str.into(),
                    detail,
                });
            }
        }
    }

    result
}

// ── Internal helpers ───────────────────────────────────────────────────

enum ProbeResult {
    /// 2xx with parsed JSON body
    Success(serde_json::Value),
    /// Non-2xx HTTP response
    HttpError(u16, String),
    /// Network / timeout / connection refused
    ConnectionError(String),
}

/// Send a probe request with retry-on-failure (network errors and 5xx).
///
/// Retries use exponential backoff: 2s, 4s, 8s.
async fn probe_with_retry(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &std::collections::HashMap<String, String>,
    body: Option<&str>,
    max_retries: u32,
) -> ProbeResult {
    let mut attempt = 0;
    loop {
        let result = probe_once(client, method, url, headers, body).await;
        match &result {
            ProbeResult::Success(_) => return result,
            ProbeResult::HttpError(status, _) if *status < 500 => {
                // 4xx errors are definitive — don't retry
                return result;
            }
            _ => {
                // 5xx or connection error — retry with backoff
                attempt += 1;
                if attempt >= max_retries {
                    return result;
                }
                let backoff = Duration::from_secs(2u64.pow(attempt));
                tracing::debug!(
                    "verify: probe {} failed (attempt {}/{}), retrying in {:?}",
                    url, attempt, max_retries, backoff
                );
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// Single probe attempt.
async fn probe_once(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &std::collections::HashMap<String, String>,
    body: Option<&str>,
) -> ProbeResult {
    let mut req = match method.to_uppercase().as_str() {
        "POST" => client.post(url),
        _ => client.get(url),
    };

    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }

    if let Some(body_str) = body {
        req = req
            .header("content-type", "application/json")
            .body(body_str.to_string());
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if resp.status().is_success() {
                // Try to parse as JSON; fall back to empty object
                let json = resp
                    .json::<serde_json::Value>()
                    .await
                    .unwrap_or(serde_json::json!({}));
                ProbeResult::Success(json)
            } else {
                let body_text = resp.text().await.unwrap_or_default();
                ProbeResult::HttpError(status, body_text)
            }
        }
        Err(e) => ProbeResult::ConnectionError(e.to_string()),
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
