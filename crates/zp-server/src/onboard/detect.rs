//! Platform/biometric detection + local inference runtime discovery.

use super::{OnboardEvent, OnboardState};
use serde::Serialize;

/// Detect platform capabilities, biometric hardware, and sovereignty providers.
pub async fn handle_detect(state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Detecting platform capabilities..."));

    // Platform detection
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    // Full sovereignty provider scan — detects all available modes
    let providers = zp_keys::detect_all_providers();

    // Legacy biometric detection for backward-compatible UI fields
    let bio = zp_keys::detect_biometric();
    let bio_type = bio.biometric_type.map(|t| t.to_string());

    // Terminal output summarizing what was found
    let available_providers: Vec<&zp_keys::ProviderCapability> =
        providers.iter().filter(|p| p.available).collect();
    let hw_wallets: Vec<&zp_keys::ProviderCapability> = available_providers
        .iter()
        .filter(|p| p.mode.category() == zp_keys::SovereigntyCategory::HardwareWallet)
        .copied()
        .collect();

    events.push(OnboardEvent::terminal(&format!(
        "Platform: {} | Biometric: {} | Credential store: {} | HW wallets: {}",
        platform,
        bio_type.as_deref().unwrap_or("none"),
        if bio.credential_store_available {
            "available"
        } else {
            "unavailable"
        },
        if hw_wallets.is_empty() {
            "none".to_string()
        } else {
            hw_wallets
                .iter()
                .map(|p| p.mode.display_name())
                .collect::<Vec<_>>()
                .join(", ")
        }
    )));

    state.platform_detected = true;
    state.step = 1;

    // Emit full provider capabilities for the new UI
    let providers_json: Vec<serde_json::Value> = providers
        .iter()
        .map(|p| {
            serde_json::json!({
                "mode": p.mode.to_string(),
                "display_name": p.mode.display_name(),
                "category": format!("{:?}", p.mode.category()),
                "available": p.available,
                "description": p.description,
                "requires_enrollment": p.requires_enrollment,
                "detail": p.detail,
                "requires_hardware": p.mode.requires_hardware(),
                "requires_external_device": p.mode.requires_external_device(),
                "implementation_status": p.implementation_status,
                "ceremony_ready": p.mode.is_ceremony_ready(),
            })
        })
        .collect();

    events.push(OnboardEvent::new(
        "platform",
        serde_json::json!({
            "platform": platform,
            // Legacy fields (backward compat)
            "biometric_available": bio.available,
            "biometric_type": bio_type,
            "credential_store_available": bio.credential_store_available,
            "description": bio.description,
            // New: full provider list
            "sovereignty_providers": providers_json,
        }),
    ));

    events
}

/// A detected local inference runtime.
#[derive(Debug, Clone, Serialize)]
struct LocalRuntime {
    name: String,
    endpoint: String,
    version: Option<String>,
    models: Vec<String>,
}

/// Detect local inference runtimes and system resources.
///
/// Probes common local inference endpoints:
/// - Ollama (localhost:11434) — proprietary API
/// - LM Studio (localhost:1234) — OpenAI-compatible
/// - llama.cpp / LocalAI (localhost:8080) — OpenAI-compatible
/// - Jan (localhost:1337) — OpenAI-compatible
/// - vLLM (localhost:8000) — OpenAI-compatible
pub async fn handle_detect_local_inference(state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    // ── System resource detection ─────────────────────────────
    let system = super::inference::detect_system_resources();
    events.push(OnboardEvent::new(
        "system_resources",
        serde_json::to_value(&system).unwrap_or_default(),
    ));

    // ── Local runtime detection ───────────────────────────────
    let client = reqwest::Client::new();
    let timeout = std::time::Duration::from_secs(2);

    let mut runtimes: Vec<LocalRuntime> = Vec::new();

    // 1. Ollama (proprietary API)
    if let Some(rt) = detect_ollama_runtime(&client, timeout).await {
        runtimes.push(rt);
    }

    // 2. OpenAI-compatible endpoints (LM Studio, llama.cpp, LocalAI, Jan, vLLM)
    let oai_endpoints = [
        (1234, "LM Studio"),
        (8080, "llama.cpp / LocalAI"),
        (1337, "Jan"),
        (8000, "vLLM"),
    ];

    for (port, name) in oai_endpoints {
        if let Some(rt) = detect_openai_compatible_runtime(&client, timeout, port, name).await {
            runtimes.push(rt);
        }
    }

    let available = !runtimes.is_empty();
    state.local_inference_available = available;

    // Flatten all models across runtimes for display
    let all_models: Vec<String> = runtimes.iter().flat_map(|r| r.models.clone()).collect();

    events.push(OnboardEvent::new(
        "local_inference_status",
        serde_json::json!({
            "available": available,
            "runtimes": runtimes,
            "models": all_models,
            "system": system,
        }),
    ));

    // Also emit legacy event name for backwards compat
    if available {
        let primary = &runtimes[0];
        events.push(OnboardEvent::new(
            "ollama_status",
            serde_json::json!({
                "ollama_available": primary.name == "Ollama",
                "ollama_version": primary.version,
                "models": all_models,
                "system": system,
            }),
        ));
    }

    events
}

/// Probe Ollama's proprietary API at localhost:11434.
async fn detect_ollama_runtime(
    client: &reqwest::Client,
    timeout: std::time::Duration,
) -> Option<LocalRuntime> {
    let resp = client
        .get("http://localhost:11434/api/tags")
        .timeout(timeout)
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body = resp.json::<serde_json::Value>().await.ok()?;
    let models: Vec<String> = body
        .get("models")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    m.get("name")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        })
        .unwrap_or_default();

    let version = match client
        .get("http://localhost:11434/api/version")
        .timeout(timeout)
        .send()
        .await
    {
        Ok(vresp) => vresp.json::<serde_json::Value>().await.ok().and_then(|v| {
            v.get("version")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        }),
        Err(_) => None,
    };

    Some(LocalRuntime {
        name: "Ollama".to_string(),
        endpoint: "http://localhost:11434".to_string(),
        version,
        models,
    })
}

/// Probe an OpenAI-compatible /v1/models endpoint.
async fn detect_openai_compatible_runtime(
    client: &reqwest::Client,
    timeout: std::time::Duration,
    port: u16,
    name: &str,
) -> Option<LocalRuntime> {
    let url = format!("http://localhost:{}/v1/models", port);
    let resp = client.get(&url).timeout(timeout).send().await.ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let body = resp.json::<serde_json::Value>().await.ok()?;

    // OpenAI format: { "data": [ { "id": "model-name", ... }, ... ] }
    let models: Vec<String> = body
        .get("data")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| m.get("id").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    Some(LocalRuntime {
        name: name.to_string(),
        endpoint: format!("http://localhost:{}", port),
        version: None,
        models,
    })
}
