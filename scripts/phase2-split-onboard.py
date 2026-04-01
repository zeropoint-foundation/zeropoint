#!/usr/bin/env python3
"""
Phase 2: Split onboard.rs (2,263 lines) into a module directory.

Before:  crates/zp-server/src/onboard.rs    (monolith)
After:   crates/zp-server/src/onboard/
           mod.rs          — WebSocket handler, dispatcher, types
           state.rs        — OnboardState + from_filesystem
           detect.rs       — Platform/biometric + local inference detection
           genesis.rs      — Genesis ceremony + vault check
           inference.rs    — Inference posture, guidance, model pull, system resources
           scan.rs         — Tool discovery (delegates to zp-engine)
           credentials.rs  — Vault store, import, provider catalog
           configure.rs    — Configure engine dispatch

Run from repo root:  python3 scripts/phase2-split-onboard.py
"""

import os
import sys

SRC = "crates/zp-server/src/onboard.rs"
DST_DIR = "crates/zp-server/src/onboard"


def main():
    if not os.path.exists(SRC):
        print(f"✗ Source file not found: {SRC}")
        sys.exit(1)

    if os.path.exists(DST_DIR):
        print(f"⚠ {DST_DIR}/ already exists — aborting to avoid data loss")
        print(f"  Remove it first: rm -rf {DST_DIR}")
        sys.exit(1)

    os.makedirs(DST_DIR)
    print(f"Created {DST_DIR}/\n")

    # ── mod.rs ──
    write_file("mod.rs", MOD_RS)

    # ── state.rs ──
    write_file("state.rs", STATE_RS)

    # ── detect.rs ──
    write_file("detect.rs", DETECT_RS)

    # ── genesis.rs ──
    write_file("genesis.rs", GENESIS_RS)

    # ── inference.rs ──
    write_file("inference.rs", INFERENCE_RS)

    # ── scan.rs ──
    write_file("scan.rs", SCAN_RS)

    # ── credentials.rs ──
    write_file("credentials.rs", CREDENTIALS_RS)

    # ── configure.rs ──
    write_file("configure.rs", CONFIGURE_RS)

    # ── Rename old monolith ──
    bak = SRC + ".bak"
    os.rename(SRC, bak)
    print(f"\n✓ Renamed {SRC} → {bak}")

    print(f"""
══════════════════════════════════════
Phase 2 complete — module split done.

Created: {DST_DIR}/
  mod.rs          — Types + WebSocket handler + dispatcher
  state.rs        — OnboardState + from_filesystem
  detect.rs       — handle_detect + handle_detect_local_inference + runtime probes
  genesis.rs      — handle_genesis + handle_vault_check
  inference.rs    — handle_setup_guidance + handle_start_model_pull + handle_set_inference_posture + system resources
  scan.rs         — handle_scan (delegates to zp-engine)
  credentials.rs  — handle_vault_store + handle_vault_import_all + handle_get_provider_catalog + provider catalog
  configure.rs    — handle_configure (shells out to zp CLI)

Old monolith backed up to: {bak}

Next:
  1. Verify lib.rs still has `mod onboard;` (Rust resolves to onboard/mod.rs automatically)
  2. Build:  ./zp-dev.sh
══════════════════════════════════════""")


def write_file(name, content):
    path = os.path.join(DST_DIR, name)
    with open(path, "w") as f:
        f.write(content)
    lines = content.count('\n') + 1
    print(f"  ✓ {name} ({lines} lines)")


# ============================================================================
# Module contents — real implementations extracted from the monolith
# ============================================================================

MOD_RS = r'''//! `/api/onboard/ws` — WebSocket-driven browser onboarding.
//!
//! Split into modules by responsibility:
//!   - state.rs       — OnboardState + filesystem reconstruction
//!   - detect.rs      — Platform/biometric + local inference detection
//!   - genesis.rs     — Genesis ceremony + vault check
//!   - inference.rs   — Inference posture, guidance, model pull, system resources
//!   - scan.rs        — Tool discovery (delegates to zp-engine)
//!   - credentials.rs — Vault store, import, provider catalog
//!   - configure.rs   — Configure engine dispatch

mod state;
mod detect;
mod genesis;
mod inference;
mod scan;
mod credentials;
mod configure;

pub use state::OnboardState;

use axum::extract::ws::{Message as WsMessage, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};

use crate::AppState;

// ============================================================================
// Types (shared across all handler modules)
// ============================================================================

/// Client → Server action envelope.
#[derive(Debug, Deserialize)]
pub(crate) struct OnboardAction {
    pub action: String,
    #[serde(flatten)]
    pub params: serde_json::Value,
}

/// Server → Client event envelope.
#[derive(Debug, Serialize)]
pub(crate) struct OnboardEvent {
    pub event: String,
    #[serde(flatten)]
    pub data: serde_json::Value,
}

impl OnboardEvent {
    pub fn new(event: &str, data: serde_json::Value) -> Self {
        Self {
            event: event.to_string(),
            data,
        }
    }

    pub fn error(msg: &str) -> Self {
        Self::new("error", serde_json::json!({ "message": msg }))
    }

    pub fn terminal(line: &str) -> Self {
        Self::new("terminal", serde_json::json!({ "line": line }))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"event":"error","message":"serialize failed"}"#.to_string()
        })
    }
}

// ============================================================================
// WebSocket upgrade handler
// ============================================================================

pub async fn onboard_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_onboard_ws(socket, state))
}

async fn handle_onboard_ws(socket: WebSocket, app_state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut onboard = OnboardState::from_filesystem();

    tracing::info!(
        "onboard ws: reconstructed state — step={}, genesis={}, vault={}, tools={}/{}",
        onboard.step, onboard.genesis_complete, onboard.credentials_stored,
        onboard.tools_configured, onboard.tools_discovered
    );

    // Send initial state so frontend can resume at the right step
    let init_event = OnboardEvent::new("state", serde_json::to_value(&onboard).unwrap_or_default());
    let _ = sender.send(WsMessage::Text(init_event.to_json())).await;

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("onboard ws error: {}", e);
                break;
            }
        };

        match msg {
            WsMessage::Text(text) => {
                let action: OnboardAction = match serde_json::from_str(&text) {
                    Ok(a) => a,
                    Err(e) => {
                        let err = OnboardEvent::error(&format!("invalid JSON: {}", e));
                        let _ = sender.send(WsMessage::Text(err.to_json())).await;
                        continue;
                    }
                };

                let events = handle_action(&action, &mut onboard, &app_state).await;
                for event in events {
                    if sender.send(WsMessage::Text(event.to_json())).await.is_err() {
                        return;
                    }
                }
            }
            WsMessage::Close(_) => break,
            WsMessage::Ping(data) => {
                let _ = sender.send(WsMessage::Pong(data)).await;
            }
            _ => {}
        }
    }
}

// ============================================================================
// Action dispatcher
// ============================================================================

async fn handle_action(
    action: &OnboardAction,
    state: &mut OnboardState,
    _app_state: &AppState,
) -> Vec<OnboardEvent> {
    match action.action.as_str() {
        "detect" => detect::handle_detect(state).await,
        "genesis" => genesis::handle_genesis(action, state).await,
        "vault_check" => genesis::handle_vault_check(state).await,
        "detect_local_inference" => detect::handle_detect_local_inference(state).await,
        "detect_ollama" => detect::handle_detect_local_inference(state).await,
        "get_setup_guidance" => inference::handle_setup_guidance(action).await,
        "start_model_pull" => inference::handle_start_model_pull(action).await,
        "set_inference_posture" => inference::handle_set_inference_posture(action, state).await,
        "get_provider_catalog" => credentials::handle_get_provider_catalog(state).await,
        "scan" => scan::handle_scan(action, state).await,
        "vault_store" => credentials::handle_vault_store(action, state).await,
        "vault_import_all" => credentials::handle_vault_import_all(action, state).await,
        "configure" => configure::handle_configure(action, state).await,
        "status" => vec![OnboardEvent::new("state", serde_json::to_value(&*state).unwrap_or_default())],
        _ => vec![OnboardEvent::error(&format!("unknown action: {}", action.action))],
    }
}
'''

STATE_RS = r'''//! Onboard session state — tracks progress through the 8-step flow.

use serde::Serialize;

/// Tracks the onboard session state so reconnects can resume.
#[derive(Debug, Clone, Serialize, Default)]
pub struct OnboardState {
    /// Current step (0-8)
    pub step: u8,
    /// Platform detection result
    pub platform_detected: bool,
    /// Selected sovereignty mode
    pub sovereignty_mode: Option<String>,
    /// Genesis ceremony complete
    pub genesis_complete: bool,
    /// Genesis public key (hex)
    pub genesis_public_key: Option<String>,
    /// Operator name
    pub operator_name: Option<String>,
    /// Vault master key (resolved during Step 3, zeroized on drop)
    #[serde(skip)]
    pub vault_key: Option<[u8; 32]>,
    /// Inference posture: "local", "cloud", or "mixed"
    pub inference_posture: Option<String>,
    /// Whether any local inference runtime was detected
    pub local_inference_available: bool,
    /// Path used in Step 5 scan (retained for configure)
    pub scan_path: Option<String>,
    /// Number of tools discovered
    pub tools_discovered: usize,
    /// Number of credentials stored
    pub credentials_stored: usize,
    /// Number of tools configured
    pub tools_configured: usize,
}

impl OnboardState {
    /// Reconstruct state from filesystem reality.
    ///
    /// Probes ~/.zeropoint/ for genesis, vault, configured tools,
    /// and inference posture. Returns the furthest step the user
    /// has actually completed.
    pub fn from_filesystem() -> Self {
        let mut state = Self::default();
        let home = match dirs::home_dir() {
            Some(h) => h.join(".zeropoint"),
            None => return state,
        };

        // ── Genesis ──
        let genesis_path = home.join("genesis.json");
        if genesis_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&genesis_path) {
                if let Ok(record) = serde_json::from_str::<serde_json::Value>(&content) {
                    state.genesis_complete = true;
                    state.platform_detected = true;
                    state.genesis_public_key = record.get("genesis_public_key")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.operator_name = record.get("operator")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.sovereignty_mode = record.get("sovereignty_mode")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    state.step = 3; // Past genesis
                }
            }
        }

        // ── Vault ──
        let vault_path = home.join("vault.json");
        if vault_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&vault_path) {
                if let Ok(vault) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(obj) = vault.as_object() {
                        state.credentials_stored = obj.len();
                        if state.credentials_stored > 0 {
                            state.step = state.step.max(6);
                        }
                    }
                }
            }
        }

        // ── Inference posture ──
        let inference_path = home.join("config").join("inference.toml");
        if inference_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&inference_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("posture") {
                        if let Some(val) = line.split('=').nth(1) {
                            let val = val.trim().trim_matches('"').trim_matches('\'');
                            state.inference_posture = Some(val.to_string());
                            state.step = state.step.max(4);
                        }
                    }
                }
            }
        } else if state.genesis_complete {
            // If genesis exists but no inference config, default to mixed
            state.inference_posture = Some("mixed".to_string());
        }

        // ── Scan path + tools discovery ──
        // Check default scan path for tools
        let scan_path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("projects");

        if scan_path.exists() && state.genesis_complete {
            let mut tool_count = 0;

            if let Ok(entries) = std::fs::read_dir(&scan_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if !path.is_dir() { continue; }
                    if path.join(".env.example").exists() {
                        tool_count += 1;
                    }
                }
            }

            if tool_count > 0 {
                state.scan_path = Some("~/projects".to_string());
                state.tools_discovered = tool_count;
            }
        }

        // ── Cap step based on what's actually ready ──
        // Don't jump past scan/credentials if vault is empty.
        // The scan must run to discover plaintext credentials
        // before configure can do anything useful.
        if state.genesis_complete && state.credentials_stored == 0 {
            state.step = state.step.min(5); // Land at scan step
        }

        // Detect local inference availability
        state.local_inference_available = which::which("ollama").is_ok();

        state
    }
}
'''

DETECT_RS = r'''//! Platform/biometric detection + local inference runtime discovery.

use super::{OnboardEvent, OnboardState};
use serde::Serialize;

/// Detect platform capabilities and biometric hardware.
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

    // Biometric detection — we call the zp-keys detection logic.
    let bio = zp_keys::detect_biometric();
    let bio_type = bio.biometric_type.map(|t| t.to_string());

    events.push(OnboardEvent::terminal(&format!(
        "Platform: {} | Biometric: {} | Credential store: {}",
        platform,
        bio_type.as_deref().unwrap_or("none"),
        if bio.credential_store_available { "available" } else { "unavailable" }
    )));

    state.platform_detected = true;
    state.step = 1;

    events.push(OnboardEvent::new(
        "platform",
        serde_json::json!({
            "platform": platform,
            "biometric_available": bio.available,
            "biometric_type": bio_type,
            "credential_store_available": bio.credential_store_available,
            "description": bio.description,
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
    events.push(OnboardEvent::new("system_resources", serde_json::to_value(&system).unwrap_or_default()));

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
                .filter_map(|m| m.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let version = match client
        .get("http://localhost:11434/api/version")
        .timeout(timeout)
        .send()
        .await
    {
        Ok(vresp) => vresp
            .json::<serde_json::Value>()
            .await
            .ok()
            .and_then(|v| v.get("version").and_then(|s| s.as_str()).map(|s| s.to_string())),
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
'''

GENESIS_RS = r'''//! Genesis ceremony + vault key check.

use super::{OnboardAction, OnboardEvent, OnboardState};

/// Create Genesis + Operator keys.
pub async fn handle_genesis(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    // Extract parameters
    let operator_name = action.params.get("operator_name")
        .and_then(|v| v.as_str())
        .unwrap_or("Operator");
    let sovereignty = action.params.get("sovereignty_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("auto");

    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal("ZeroPoint Genesis"));
    events.push(OnboardEvent::terminal("─────────────────"));

    // Step 1: Generate keypair
    events.push(OnboardEvent::terminal("Generating operator keypair...        ✓ Ed25519"));

    let genesis = zp_keys::hierarchy::GenesisKey::generate(operator_name);
    let operator = zp_keys::hierarchy::OperatorKey::generate(operator_name, &genesis, None);

    // Step 2: Seal constitutional bedrock
    let bedrock_gates = [
        "HarmPrincipleRule:constitutional",
        "SovereigntyRule:constitutional",
        "CatastrophicActionRule:operational",
        "BulkOperationRule:operational",
        "ReputationGateRule:operational",
    ];
    let constitutional_hash = blake3::hash(bedrock_gates.join("\n").as_bytes())
        .to_hex()
        .to_string();

    events.push(OnboardEvent::terminal("Sealing constitutional bedrock...     ✓ 5 gates installed"));

    // Step 3: Determine sovereignty mode
    let sovereignty_mode = match sovereignty {
        "biometric" | "bio" => zp_keys::SovereigntyMode::Biometric,
        "login-password" | "login" | "password" => zp_keys::SovereigntyMode::LoginPassword,
        "file-based" | "file" => zp_keys::SovereigntyMode::FileBased,
        _ => {
            // Auto-detect
            let cap = zp_keys::detect_biometric();
            if cap.available {
                zp_keys::SovereigntyMode::Biometric
            } else if cap.credential_store_available {
                zp_keys::SovereigntyMode::LoginPassword
            } else {
                zp_keys::SovereigntyMode::FileBased
            }
        }
    };

    // Step 4: Persist keys
    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint");

    // Check if already initialized
    let has_genesis = home.join("keys").join("genesis.json").exists();
    if has_genesis {
        events.push(OnboardEvent::terminal(""));
        events.push(OnboardEvent::terminal("⚠ ZeroPoint is already initialized."));
        events.push(OnboardEvent::terminal("  Remove ~/.zeropoint/ to re-initialize."));

        // Still report current state
        if let Ok(genesis_json) = std::fs::read_to_string(home.join("genesis.json")) {
            if let Ok(record) = serde_json::from_str::<serde_json::Value>(&genesis_json) {
                state.genesis_complete = true;
                state.genesis_public_key = record.get("genesis_public_key")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                state.operator_name = record.get("operator")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                state.sovereignty_mode = record.get("sovereignty_mode")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                state.step = 3;

                events.push(OnboardEvent::new(
                    "genesis_complete",
                    serde_json::json!({
                        "already_initialized": true,
                        "operator": state.operator_name,
                        "genesis_public_key": state.genesis_public_key,
                        "sovereignty_mode": state.sovereignty_mode,
                    }),
                ));
            }
        }
        return events;
    }

    let keyring = match zp_keys::Keyring::open(home.join("keys")) {
        Ok(k) => k,
        Err(e) => {
            events.push(OnboardEvent::error(&format!("Failed to create keyring: {}", e)));
            return events;
        }
    };

    // Save with sovereignty-mode-aware storage
    let secret_in_credential_store = match sovereignty_mode {
        zp_keys::SovereigntyMode::Biometric => {
            events.push(OnboardEvent::terminal("Sealing secret with biometric gating..."));

            match zp_keys::biometric::save_genesis_biometric(&genesis.secret_key()) {
                Ok(()) => {
                    if let Err(e) = keyring.save_genesis(&genesis, false) {
                        events.push(OnboardEvent::error(&format!("Failed to save certificate: {}", e)));
                        return events;
                    }
                    true
                }
                Err(e) => {
                    events.push(OnboardEvent::terminal(&format!(
                        "⚠ Biometric gating failed: {}. Falling back to login password.", e
                    )));
                    match keyring.save_genesis(&genesis, true) {
                        Ok(in_cred) => in_cred,
                        Err(e2) => {
                            events.push(OnboardEvent::error(&format!("Failed to save genesis: {}", e2)));
                            return events;
                        }
                    }
                }
            }
        }
        _ => {
            events.push(OnboardEvent::terminal("Sealing secret in OS credential store..."));
            match keyring.save_genesis(&genesis, true) {
                Ok(in_cred) => in_cred,
                Err(e) => {
                    events.push(OnboardEvent::error(&format!("Failed to save genesis: {}", e)));
                    return events;
                }
            }
        }
    };

    // Save operator
    if let Err(e) = keyring.save_operator(&operator) {
        events.push(OnboardEvent::error(&format!("Failed to save operator: {}", e)));
        return events;
    }

    // Write genesis record
    let genesis_record = serde_json::json!({
        "version": "2.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "operator": operator_name,
        "genesis_public_key": hex::encode(genesis.public_key()),
        "operator_public_key": hex::encode(operator.public_key()),
        "constitutional_hash": constitutional_hash,
        "algorithm": "Ed25519",
        "audit_chain": "BLAKE3",
        "sovereignty_mode": sovereignty_mode.to_string(),
        "constitutional_gates": [
            "HarmPrincipleRule",
            "SovereigntyRule",
            "CatastrophicActionRule",
            "BulkOperationRule",
            "ReputationGateRule",
        ],
    });

    let _ = std::fs::create_dir_all(&home);
    let _ = std::fs::create_dir_all(home.join("policies"));
    let _ = std::fs::create_dir_all(home.join("data"));

    if let Err(e) = std::fs::write(
        home.join("genesis.json"),
        serde_json::to_string_pretty(&genesis_record).unwrap(),
    ) {
        events.push(OnboardEvent::error(&format!("Failed to write genesis record: {}", e)));
        return events;
    }

    let genesis_pub = hex::encode(genesis.public_key());
    let short_pub = &genesis_pub[..8];

    if secret_in_credential_store {
        events.push(OnboardEvent::terminal("✓ genesis record + secret sealed in OS credential store"));
    } else {
        events.push(OnboardEvent::terminal("✓ genesis record + secret written (file fallback)"));
    }

    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal(&format!("Operator identity: {}...", short_pub)));
    events.push(OnboardEvent::terminal(&format!("Constitutional hash: {}...", &constitutional_hash[..6])));

    // Update state
    state.genesis_complete = true;
    state.genesis_public_key = Some(genesis_pub.clone());
    state.operator_name = Some(operator_name.to_string());
    state.sovereignty_mode = Some(sovereignty_mode.to_string());
    state.step = 2;

    // Main genesis_complete event
    events.push(OnboardEvent::new(
        "genesis_complete",
        serde_json::json!({
            "operator": operator_name,
            "genesis_public_key": genesis_pub,
            "operator_public_key": hex::encode(operator.public_key()),
            "constitutional_hash": constitutional_hash,
            "sovereignty_mode": sovereignty_mode.to_string(),
            "secret_in_credential_store": secret_in_credential_store,
            "platform": if cfg!(target_os = "macos") { "macos" } else if cfg!(target_os = "linux") { "linux" } else { "other" },
        }),
    ));

    // Recovery kit for biometric users
    if sovereignty_mode == zp_keys::SovereigntyMode::Biometric {
        match zp_keys::recovery::encode_mnemonic(&genesis.secret_key()) {
            Ok(mnemonic) => {
                events.push(OnboardEvent::new(
                    "recovery_kit",
                    serde_json::json!({
                        "words": mnemonic,
                        "word_count": 24,
                        "warning": "Write these down. This screen will not appear again.",
                    }),
                ));
            }
            Err(e) => {
                events.push(OnboardEvent::terminal(&format!(
                    "⚠ Could not generate recovery mnemonic: {}", e
                )));
            }
        }
    }

    events
}

/// Verify vault key derivation.
pub async fn handle_vault_check(state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Verifying vault key derivation..."));

    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint");

    let keyring = match zp_keys::Keyring::open(home.join("keys")) {
        Ok(k) => k,
        Err(e) => {
            events.push(OnboardEvent::error(&format!("Cannot open keyring: {}", e)));
            return events;
        }
    };

    // Try to resolve the vault key
    match zp_keys::resolve_vault_key(&keyring) {
        Ok(resolved) => {
            let source_name = match resolved.source {
                zp_keys::VaultKeySource::CredentialStore => "credential store",
                zp_keys::VaultKeySource::LegacyFileMigrated => "file (migrated)",
                zp_keys::VaultKeySource::LegacyEnvVar => "env var (legacy)",
            };
            events.push(OnboardEvent::terminal(&format!(
                "✓ Vault key derived from {}", source_name
            )));

            // Retain the vault key for credential storage in later steps
            state.vault_key = Some(*resolved.key);

            state.step = 3;
            events.push(OnboardEvent::new("vault_ready", serde_json::json!({
                "source": source_name,
            })));
        }
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Vault key derivation failed: {}. Run `zp init` first.", e
            )));
        }
    }

    events
}
'''

INFERENCE_RS = r'''//! Inference posture selection, setup guidance, model pull, and system resource detection.

use super::{OnboardAction, OnboardEvent, OnboardState};
use serde::Serialize;

/// Set the user's inference posture choice.
pub async fn handle_set_inference_posture(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let posture = action.params.get("posture")
        .and_then(|v| v.as_str())
        .unwrap_or("mixed")
        .to_string();

    state.inference_posture = Some(posture.clone());
    state.step = 4;

    vec![OnboardEvent::new(
        "inference_posture_set",
        serde_json::json!({
            "posture": posture,
        }),
    )]
}

/// Return platform-specific install instructions and model recommendations.
///
/// This is the stewardship flow: rather than pointing users to a download page
/// and abandoning them, ZeroPoint walks them through the entire setup.
pub async fn handle_setup_guidance(action: &OnboardAction) -> Vec<OnboardEvent> {
    let runtime_pref = action
        .params
        .get("runtime")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");

    let system = detect_system_resources();

    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };

    // ── Install instructions per runtime × platform ──────────
    let install = match (runtime_pref, platform) {
        ("ollama", "macos") => SetupInstall {
            runtime: "Ollama".into(),
            method: "Homebrew or direct download".into(),
            commands: vec![
                "brew install ollama".into(),
                "ollama serve".into(),
            ],
            alt_url: Some("https://ollama.com/download/mac".into()),
            verify_command: "ollama --version".into(),
            notes: "Ollama runs as a background service after install. If using Homebrew, \
                    it starts automatically.".into(),
        },
        ("ollama", "linux") => SetupInstall {
            runtime: "Ollama".into(),
            method: "Official install script".into(),
            commands: vec![
                "curl -fsSL https://ollama.com/install.sh | sh".into(),
                "ollama serve".into(),
            ],
            alt_url: Some("https://ollama.com/download/linux".into()),
            verify_command: "ollama --version".into(),
            notes: "The install script sets up a systemd service. Ollama will start on boot."
                .into(),
        },
        ("ollama", "windows") => SetupInstall {
            runtime: "Ollama".into(),
            method: "Windows installer".into(),
            commands: vec![
                "winget install Ollama.Ollama".into(),
            ],
            alt_url: Some("https://ollama.com/download/windows".into()),
            verify_command: "ollama --version".into(),
            notes: "After install, Ollama runs in the system tray. You can also use \
                    the direct installer from the download page.".into(),
        },
        ("lm-studio", _) => SetupInstall {
            runtime: "LM Studio".into(),
            method: "Desktop application".into(),
            commands: vec![],
            alt_url: Some("https://lmstudio.ai".into()),
            verify_command: String::new(),
            notes: "Download and install LM Studio. Models are downloaded through the app's \
                    built-in model browser. Start the local server from the Developer tab."
                .into(),
        },
        ("jan", _) => SetupInstall {
            runtime: "Jan".into(),
            method: "Desktop application".into(),
            commands: vec![],
            alt_url: Some("https://jan.ai".into()),
            verify_command: String::new(),
            notes: "Download and install Jan. It provides a one-click model setup — choose a \
                    model from the hub and Jan handles the rest. Enable the API server in \
                    Settings → Advanced.".into(),
        },
        _ => SetupInstall {
            runtime: runtime_pref.to_string(),
            method: "Manual install".into(),
            commands: vec![],
            alt_url: None,
            verify_command: String::new(),
            notes: "Install your preferred runtime and ensure it serves an OpenAI-compatible \
                    API on localhost.".into(),
        },
    };

    // ── Model recommendation based on hardware ───────────────
    let model_rec = recommend_model(&system, runtime_pref);

    vec![OnboardEvent::new(
        "setup_guidance",
        serde_json::json!({
            "platform": platform,
            "runtime": runtime_pref,
            "install": install,
            "model": model_rec,
            "system": system,
        }),
    )]
}

/// Start a model pull in the background.
pub async fn handle_start_model_pull(action: &OnboardAction) -> Vec<OnboardEvent> {
    let model_id = match action.params.get("model_id").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => {
            return vec![OnboardEvent::error("start_model_pull requires 'model_id' parameter")];
        }
    };

    let runtime = action
        .params
        .get("runtime")
        .and_then(|v| v.as_str())
        .unwrap_or("ollama");

    match runtime {
        "ollama" => {
            // Spawn ollama pull as a detached background process
            match std::process::Command::new("ollama")
                .args(["pull", model_id])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
            {
                Ok(_child) => {
                    tracing::info!("Background model pull started: ollama pull {}", model_id);
                    vec![OnboardEvent::new(
                        "model_pull_started",
                        serde_json::json!({
                            "model_id": model_id,
                            "runtime": runtime,
                            "message": format!(
                                "Downloading {} in the background. Continue with onboarding — \
                                 the model will be available when the download completes.",
                                model_id
                            ),
                        }),
                    )]
                }
                Err(e) => {
                    tracing::warn!("Failed to start model pull: {}", e);
                    vec![OnboardEvent::new(
                        "model_pull_started",
                        serde_json::json!({
                            "model_id": model_id,
                            "runtime": runtime,
                            "error": true,
                            "message": format!(
                                "Could not start the download automatically. Run this in your terminal: \
                                 ollama pull {}",
                                model_id
                            ),
                        }),
                    )]
                }
            }
        }
        _ => {
            // GUI runtimes handle downloads through their own interface
            vec![OnboardEvent::new(
                "model_pull_started",
                serde_json::json!({
                    "model_id": model_id,
                    "runtime": runtime,
                    "message": format!(
                        "Search for '{}' in {}'s model browser and start the download. \
                         Continue with onboarding — the model will be available when ready.",
                        model_id, runtime
                    ),
                }),
            )]
        }
    }
}

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Clone, Serialize)]
struct SetupInstall {
    runtime: String,
    method: String,
    commands: Vec<String>,
    alt_url: Option<String>,
    verify_command: String,
    notes: String,
}

#[derive(Debug, Clone, Serialize)]
struct ModelRecommendation {
    model_id: String,
    display_name: String,
    size: String,
    rationale: String,
    pull_command: String,
    source_url: Option<String>,
    last_verified: Option<String>,
    alternative: Option<ModelAlt>,
}

#[derive(Debug, Clone, Serialize)]
struct ModelAlt {
    model_id: String,
    display_name: String,
    size: String,
    pull_command: String,
    rationale: String,
    source_url: Option<String>,
}

/// Detect system RAM, CPU cores, chip, and GPU info for inference recommendations.
#[derive(Debug, Clone, Serialize)]
pub struct SystemResources {
    pub ram_gb: u64,
    pub cpu_cores: usize,
    pub chip: Option<String>,
    pub gpu: Option<String>,
    pub inference_memory_gb: u64,
    pub unified_memory: bool,
    pub local_inference_fit: String,
    pub recommendation: String,
}

// ============================================================================
// System resource detection (pub for use by detect.rs)
// ============================================================================

pub fn detect_system_resources() -> SystemResources {
    let cpu_cores = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1);

    let (ram_gb, chip) = detect_platform_resources();
    let (gpu, gpu_vram_gb, unified_memory) = detect_gpu();

    let inference_memory_gb = if unified_memory {
        ram_gb
    } else if gpu_vram_gb > 0 {
        gpu_vram_gb
    } else {
        ram_gb
    };

    let has_gpu = gpu.is_some();
    let (fit, recommendation) = if ram_gb == 0 && !has_gpu {
        (
            "unknown".to_string(),
            "System resources could not be detected. Mixed mode is a safe default.".to_string(),
        )
    } else if inference_memory_gb >= 16 {
        let gpu_note = if unified_memory {
            format!("{}GB unified memory", ram_gb)
        } else if let Some(ref g) = gpu {
            format!("{}", g)
        } else {
            format!("{}GB RAM", ram_gb)
        };
        (
            "strong".to_string(),
            format!(
                "{} — local models (up to 30B+) will run well here. Mixed mode recommended.",
                gpu_note
            ),
        )
    } else if inference_memory_gb >= 8 {
        let gpu_note = if unified_memory {
            format!("{}GB unified memory", ram_gb)
        } else if let Some(ref g) = gpu {
            format!("{}", g)
        } else {
            format!("{}GB RAM", ram_gb)
        };
        (
            "moderate".to_string(),
            format!(
                "{} — smaller local models (7B–8B) will work. Mixed mode gives you flexibility.",
                gpu_note
            ),
        )
    } else if has_gpu {
        (
            "moderate".to_string(),
            format!(
                "{} — can handle small models. Mixed mode lets you offload larger tasks to the cloud.",
                gpu.as_deref().unwrap_or("GPU detected")
            ),
        )
    } else {
        (
            "limited".to_string(),
            format!(
                "{}GB RAM, no GPU detected — cloud inference is the practical choice for now.",
                ram_gb
            ),
        )
    };

    SystemResources {
        ram_gb,
        cpu_cores,
        chip,
        gpu,
        inference_memory_gb,
        unified_memory,
        local_inference_fit: fit,
        recommendation,
    }
}

// ============================================================================
// Model recommendations
// ============================================================================

fn recommend_model(system: &SystemResources, runtime: &str) -> ModelRecommendation {
    if let Some(rec) = load_model_override(system.inference_memory_gb, runtime) {
        return rec;
    }

    let mem = system.inference_memory_gb;
    let pull_cmd = |model: &str| -> String {
        match runtime {
            "ollama" => format!("ollama pull {}", model),
            "lm-studio" => format!("Search for '{}' in LM Studio's model browser", model),
            "jan" => format!("Search for '{}' in Jan's model hub", model),
            _ => format!("Download {}", model),
        }
    };

    let verified = Some("2026-03-22".to_string());

    if mem >= 32 {
        ModelRecommendation {
            model_id: "qwen3:8b".into(),
            display_name: "Qwen 3 8B".into(),
            size: "~5.2 GB".into(),
            rationale: format!(
                "Leads benchmarks on math, coding, and reasoning at this size class. \
                 Supports thinking mode for complex tasks. With {}GB available, you \
                 have headroom for larger models too.",
                mem
            ),
            pull_command: pull_cmd("qwen3:8b"),
            source_url: Some("https://huggingface.co/Qwen/Qwen3-8B".into()),
            last_verified: verified.clone(),
            alternative: Some(ModelAlt {
                model_id: "gemma3:12b".into(),
                display_name: "Gemma 3 12B".into(),
                size: "~8.1 GB".into(),
                pull_command: pull_cmd("gemma3:12b"),
                rationale: "Multimodal (text + vision), 128K context window, strong \
                           general-purpose. Good if you need image understanding."
                    .into(),
                source_url: Some("https://ai.google.dev/gemma/docs".into()),
            }),
        }
    } else if mem >= 16 {
        ModelRecommendation {
            model_id: "qwen3:8b".into(),
            display_name: "Qwen 3 8B".into(),
            size: "~5.2 GB".into(),
            rationale: format!(
                "Best balance of speed and capability for {}GB. Handles \
                 summarization, code completion, and general tasks at state-of-the-art \
                 quality for its size.",
                mem
            ),
            pull_command: pull_cmd("qwen3:8b"),
            source_url: Some("https://huggingface.co/Qwen/Qwen3-8B".into()),
            last_verified: verified.clone(),
            alternative: Some(ModelAlt {
                model_id: "llama3.3:8b".into(),
                display_name: "Llama 3.3 8B".into(),
                size: "~4.9 GB".into(),
                pull_command: pull_cmd("llama3.3:8b"),
                rationale: "Solid all-rounder with the largest ecosystem. \
                           Great tool-use and instruction-following."
                    .into(),
                source_url: Some("https://huggingface.co/meta-llama/Llama-3.3-8B-Instruct".into()),
            }),
        }
    } else if mem >= 8 {
        ModelRecommendation {
            model_id: "gemma3:4b".into(),
            display_name: "Gemma 3 4B".into(),
            size: "~3.0 GB".into(),
            rationale: format!(
                "Outperforms last-generation 27B models at a fraction of the size. \
                 Multimodal (text + images), 128K context, very fast (~60-80 tok/s). \
                 Fits comfortably in {}GB at Q8 quality.",
                mem
            ),
            pull_command: pull_cmd("gemma3:4b"),
            source_url: Some("https://ai.google.dev/gemma/docs".into()),
            last_verified: verified.clone(),
            alternative: Some(ModelAlt {
                model_id: "phi4-mini".into(),
                display_name: "Phi-4 Mini (3.8B)".into(),
                size: "~2.5 GB".into(),
                pull_command: pull_cmd("phi4-mini"),
                rationale: "Excels at math and coding (80.4% on MATH benchmark — \
                           beats models twice its size). Best pick if your work is \
                           code-heavy."
                    .into(),
                source_url: Some("https://huggingface.co/microsoft/Phi-4-mini-instruct".into()),
            }),
        }
    } else {
        ModelRecommendation {
            model_id: "qwen3:0.6b".into(),
            display_name: "Qwen 3 0.6B".into(),
            size: "~523 MB".into(),
            rationale: "Smallest model with thinking mode — handles basic summarization, \
                       Q&A, and simple code tasks. At 523MB, it runs fast even on constrained \
                       hardware. Consider Mixed mode to offload complex work to the cloud."
                .into(),
            pull_command: pull_cmd("qwen3:0.6b"),
            source_url: Some("https://huggingface.co/Qwen/Qwen3-0.6B".into()),
            last_verified: verified,
            alternative: Some(ModelAlt {
                model_id: "gemma3:1b".into(),
                display_name: "Gemma 3 1B".into(),
                size: "~815 MB".into(),
                pull_command: pull_cmd("gemma3:1b"),
                rationale: "Multimodal at 1B parameters — can process both text and images. \
                           128K context window."
                    .into(),
                source_url: Some("https://ai.google.dev/gemma/docs".into()),
            }),
        }
    }
}

fn load_model_override(inference_memory_gb: u64, runtime: &str) -> Option<ModelRecommendation> {
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")).ok()?;
    let path = std::path::Path::new(&home)
        .join(".zeropoint")
        .join("config")
        .join("model-recommendations.toml");

    let content = std::fs::read_to_string(&path).ok()?;
    let table: toml::Value = content.parse().ok()?;

    let tiers = table.get("tiers")?.as_array()?;

    let mut best_tier: Option<&toml::Value> = None;
    let mut best_min: u64 = 0;

    for tier in tiers {
        let min = tier
            .get("min_memory_gb")
            .and_then(|v| v.as_integer())
            .unwrap_or(0) as u64;
        if inference_memory_gb >= min && min >= best_min {
            best_tier = Some(tier);
            best_min = min;
        }
    }

    let tier = best_tier?;

    let pull_cmd = |model: &str| -> String {
        match runtime {
            "ollama" => format!("ollama pull {}", model),
            "lm-studio" => format!("Search for '{}' in LM Studio's model browser", model),
            "jan" => format!("Search for '{}' in Jan's model hub", model),
            _ => format!("Download {}", model),
        }
    };

    let model_id = tier.get("model_id")?.as_str()?;
    let display_name = tier.get("display_name")?.as_str().unwrap_or(model_id);
    let size = tier.get("size")?.as_str().unwrap_or("unknown");
    let rationale = tier.get("rationale")?.as_str().unwrap_or("");

    let source_url = tier.get("source_url").and_then(|v| v.as_str()).map(|s| s.to_string());
    let last_verified = tier.get("last_verified").and_then(|v| v.as_str()).map(|s| s.to_string());

    let alternative = tier.get("alternative").and_then(|alt| {
        let alt_id = alt.get("model_id")?.as_str()?;
        Some(ModelAlt {
            model_id: alt_id.to_string(),
            display_name: alt.get("display_name").and_then(|v| v.as_str()).unwrap_or(alt_id).to_string(),
            size: alt.get("size").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
            pull_command: pull_cmd(alt_id),
            rationale: alt.get("rationale").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            source_url: alt.get("source_url").and_then(|v| v.as_str()).map(|s| s.to_string()),
        })
    });

    Some(ModelRecommendation {
        model_id: model_id.to_string(),
        display_name: display_name.to_string(),
        size: size.to_string(),
        rationale: rationale.to_string(),
        pull_command: pull_cmd(model_id),
        source_url,
        last_verified,
        alternative,
    })
}

// ============================================================================
// Platform resource detection
// ============================================================================

/// Detect GPU/accelerator and VRAM. Returns (description, vram_gb, is_unified).
fn detect_gpu() -> (Option<String>, u64, bool) {
    #[cfg(target_os = "macos")]
    {
        let chip = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        if chip.contains("Apple") {
            let ram_gb = std::process::Command::new("sysctl")
                .args(["-n", "hw.memsize"])
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(|bytes| bytes / (1024 * 1024 * 1024))
                .unwrap_or(0);

            let desc = format!("{} (unified {}GB)", chip, ram_gb);
            return (Some(desc), ram_gb, true);
        }

        let gpu_info = std::process::Command::new("system_profiler")
            .args(["SPDisplaysDataType", "-json"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

        if let Some(info) = gpu_info {
            if let Some(displays) = info.get("SPDisplaysDataType").and_then(|d| d.as_array()) {
                for display in displays {
                    let name = display.get("sppci_model")
                        .and_then(|n| n.as_str())
                        .unwrap_or("Unknown GPU");
                    let vram = display.get("spdisplays_vram_shared")
                        .or_else(|| display.get("spdisplays_vram"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let vram_gb = parse_vram_string(vram);
                    if vram_gb > 0 {
                        return (Some(format!("{} ({}GB VRAM)", name, vram_gb)), vram_gb, false);
                    }
                }
            }
        }

        (None, 0, false)
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some(line) = stdout.lines().next() {
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let vram_mb: u64 = parts[1].parse().unwrap_or(0);
                        let vram_gb = vram_mb / 1024;
                        return (Some(format!("{} ({}GB VRAM)", name, vram_gb)), vram_gb, false);
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("rocm-smi")
            .args(["--showmeminfo", "vram", "--csv"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    if let Some(total_str) = line.split(',').nth(1) {
                        if let Ok(vram_bytes) = total_str.trim().parse::<u64>() {
                            let vram_gb = vram_bytes / (1024 * 1024 * 1024);
                            return (Some(format!("AMD GPU ({}GB VRAM)", vram_gb)), vram_gb, false);
                        }
                    }
                }
            }
        }

        (None, 0, false)
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("nvidia-smi")
            .args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if let Some(line) = stdout.lines().next() {
                    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
                    if parts.len() >= 2 {
                        let name = parts[0];
                        let vram_mb: u64 = parts[1].parse().unwrap_or(0);
                        let vram_gb = vram_mb / 1024;
                        return (Some(format!("{} ({}GB VRAM)", name, vram_gb)), vram_gb, false);
                    }
                }
            }
        }

        if let Ok(output) = std::process::Command::new("wmic")
            .args(["path", "win32_VideoController", "get", "Name,AdapterRAM", "/value"])
            .output()
        {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let mut name = String::new();
                let mut vram_bytes: u64 = 0;
                for line in stdout.lines() {
                    let line = line.trim();
                    if let Some(n) = line.strip_prefix("Name=") {
                        name = n.to_string();
                    }
                    if let Some(v) = line.strip_prefix("AdapterRAM=") {
                        vram_bytes = v.parse().unwrap_or(0);
                    }
                }
                if !name.is_empty() && vram_bytes > 0 {
                    let vram_gb = vram_bytes / (1024 * 1024 * 1024);
                    return (Some(format!("{} ({}GB VRAM)", name, vram_gb)), vram_gb, false);
                }
            }
        }

        (None, 0, false)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (None, 0, false)
    }
}

/// Parse VRAM strings like "8 GB", "8192 MB", "8GB".
fn parse_vram_string(s: &str) -> u64 {
    let s = s.trim().to_uppercase();
    if let Some(gb_str) = s.strip_suffix("GB").or_else(|| s.strip_suffix(" GB")) {
        gb_str.trim().parse().unwrap_or(0)
    } else if let Some(mb_str) = s.strip_suffix("MB").or_else(|| s.strip_suffix(" MB")) {
        mb_str.trim().parse::<u64>().unwrap_or(0) / 1024
    } else {
        0
    }
}

/// Platform-specific RAM and chip detection.
fn detect_platform_resources() -> (u64, Option<String>) {
    #[cfg(target_os = "macos")]
    {
        let ram_gb = std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|bytes| bytes / (1024 * 1024 * 1024))
            .unwrap_or(0);

        let chip = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        (ram_gb, chip)
    }

    #[cfg(target_os = "linux")]
    {
        let ram_gb = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|content| {
                content.lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|kb| kb.parse::<u64>().ok())
                    })
            })
            .map(|kb| kb / (1024 * 1024))
            .unwrap_or(0);

        let chip = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|content| {
                content.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split(':').nth(1))
                    .map(|s| s.trim().to_string())
            });

        (ram_gb, chip)
    }

    #[cfg(target_os = "windows")]
    {
        let ram_gb = std::process::Command::new("wmic")
            .args(["computersystem", "get", "TotalPhysicalMemory", "/value"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("TotalPhysicalMemory="))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|v| v.trim().parse::<u64>().ok())
            })
            .map(|bytes| bytes / (1024 * 1024 * 1024))
            .unwrap_or(0);

        let chip = std::process::Command::new("wmic")
            .args(["cpu", "get", "Name", "/value"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Name="))
                    .and_then(|l| l.split('=').nth(1))
                    .map(|v| v.trim().to_string())
            })
            .filter(|s| !s.is_empty());

        (ram_gb, chip)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (0, None)
    }
}
'''

SCAN_RS = r'''//! Tool discovery — delegates to zp_engine::scan.

use super::{OnboardAction, OnboardEvent, OnboardState};

/// Scan a directory for tools with .env / .env.example files.
/// Delegates entirely to zp-engine for the actual scanning logic.
pub async fn handle_scan(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let scan_path = action.params.get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("~/projects");

    // Expand ~ to home directory
    let expanded = if scan_path.starts_with("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(&scan_path[2..])
    } else {
        std::path::PathBuf::from(scan_path)
    };

    events.push(OnboardEvent::terminal(&format!("Scanning {}...", expanded.display())));

    if !expanded.exists() {
        events.push(OnboardEvent::error(&format!(
            "Directory not found: {}", expanded.display()
        )));
        return events;
    }

    // ── Delegate to zp-engine (single source of truth) ──
    let results = zp_engine::scan::scan_tools(&expanded);

    // Emit per-tool events for the UI
    for tool in &results.tools {
        let status_str = match tool.status {
            zp_engine::scan::ToolStatus::HasPlaintext => "has_plaintext",
            zp_engine::scan::ToolStatus::Unconfigured => "unconfigured",
        };

        let found_creds_json: Vec<serde_json::Value> = tool.found_credentials.iter().map(|c| {
            serde_json::json!({
                "var_name": c.var_name,
                "provider": c.provider,
                "masked_value": c.masked_value,
                "value": c.value,
            })
        }).collect();

        events.push(OnboardEvent::new(
            "scan_result",
            serde_json::json!({
                "tool_name": tool.name,
                "path": tool.path.to_string_lossy(),
                "status": status_str,
                "provider_vars": tool.provider_vars,
                "found_credentials": found_creds_json,
                "found_count": tool.found_credentials.len(),
            }),
        ));

        match tool.status {
            zp_engine::scan::ToolStatus::HasPlaintext => {
                events.push(OnboardEvent::terminal(&format!(
                    "  {} — configured · ⚠ {} plaintext credential(s)",
                    tool.name, tool.found_credentials.len()
                )));
            }
            zp_engine::scan::ToolStatus::Unconfigured => {
                events.push(OnboardEvent::terminal(&format!(
                    "  {} — unconfigured", tool.name
                )));
            }
        }
    }

    let tool_count = results.tools.len();
    state.scan_path = Some(scan_path.to_string());
    state.tools_discovered = tool_count;
    state.step = 5;

    events.push(OnboardEvent::terminal(&format!(
        "\n{} tool(s) found · {} unique provider(s)",
        tool_count,
        results.unique_providers.len()
    )));

    events.push(OnboardEvent::new(
        "scan_complete",
        serde_json::json!({
            "tool_count": tool_count,
            "unique_providers": results.unique_providers.len(),
        }),
    ));

    // ── Credential summary from engine's aggregation ──
    if results.total_plaintext > 0 {
        let provider_groups: Vec<serde_json::Value> = results.credential_groups.iter().map(|g| {
            let values: Vec<serde_json::Value> = g.values.iter().map(|v| {
                serde_json::json!({
                    "var_name": v.var_name,
                    "masked_value": v.masked_value,
                    "value": v.value,
                    "sources": v.sources,
                })
            }).collect();
            serde_json::json!({
                "provider": g.provider,
                "values": values,
                "has_conflict": g.has_conflict,
            })
        }).collect();

        let conflicts = results.credential_groups.iter()
            .filter(|g| g.has_conflict)
            .count();

        events.push(OnboardEvent::new(
            "credentials_summary",
            serde_json::json!({
                "providers": provider_groups,
                "total_plaintext": results.total_plaintext,
                "conflicts": conflicts,
            }),
        ));
    } else if tool_count > 0 {
        events.push(OnboardEvent::terminal(
            "\n✓ No plaintext credentials found in .env files"
        ));
        events.push(OnboardEvent::new(
            "credentials_summary",
            serde_json::json!({
                "providers": [],
                "total_plaintext": 0,
                "conflicts": 0,
            }),
        ));
    }

    events
}
'''

CREDENTIALS_RS = r'''//! Vault store, bulk import, and provider catalog.

use super::{OnboardAction, OnboardEvent, OnboardState};
use serde::{Deserialize, Serialize};

// ============================================================================
// Provider catalog — data-driven, TOML-backed
// ============================================================================

/// Embedded default catalog. Overridden by ~/.zeropoint/config/providers.toml.
const PROVIDERS_DEFAULT_TOML: &str = include_str!("../../assets/providers-default.toml");

/// A known AI/LLM provider loaded from the TOML catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderProfile {
    id: String,
    name: String,
    category: String,
    env_patterns: Vec<String>,
    #[serde(default)]
    key_hint: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    key_url: String,
    #[serde(default)]
    docs_url: String,
    #[serde(default)]
    supports_org: bool,
    #[serde(default)]
    source_url: String,
    #[serde(default)]
    last_verified: String,
    #[serde(default)]
    coverage: String,
}

/// Result of scanning the user's environment against the provider catalog.
#[derive(Debug, Clone, Serialize)]
struct DetectedProvider {
    #[serde(flatten)]
    profile: ProviderProfile,
    detected_vars: Vec<String>,
    detected: bool,
}

/// Wrapper for TOML deserialization.
#[derive(Debug, Deserialize)]
struct ProviderCatalogFile {
    #[serde(default)]
    providers: Vec<ProviderProfile>,
}

/// Load the provider catalog: embedded defaults merged with user overrides.
fn load_provider_catalog() -> Vec<ProviderProfile> {
    let mut catalog: Vec<ProviderProfile> = toml::from_str::<ProviderCatalogFile>(PROVIDERS_DEFAULT_TOML)
        .map(|f| f.providers)
        .unwrap_or_default();

    let user_path = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()
        .map(|h| {
            std::path::Path::new(&h)
                .join(".zeropoint")
                .join("config")
                .join("providers.toml")
        });

    if let Some(path) = user_path {
        if let Ok(content) = std::fs::read_to_string(&path) {
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

/// Scan environment variables against the provider catalog.
fn scan_providers(catalog: &[ProviderProfile]) -> Vec<DetectedProvider> {
    let env_vars: std::collections::HashMap<String, String> = std::env::vars().collect();

    let mut results: Vec<DetectedProvider> = catalog
        .iter()
        .map(|profile| {
            let detected_vars: Vec<String> = profile
                .env_patterns
                .iter()
                .filter(|pattern| {
                    env_vars.keys().any(|k| k == pattern.as_str())
                })
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

/// Handle the "get_provider_catalog" action.
pub async fn handle_get_provider_catalog(_state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal("Loading provider catalog..."));

    let catalog = load_provider_catalog();
    let results = scan_providers(&catalog);

    let detected_count = results.iter().filter(|r| r.detected).count();
    let total = results.len();

    events.push(OnboardEvent::terminal(&format!(
        "Catalog: {} providers · {} detected in environment",
        total, detected_count
    )));

    events.push(OnboardEvent::new(
        "provider_catalog",
        serde_json::json!({
            "providers": results,
            "detected_count": detected_count,
            "total_count": total,
        }),
    ));

    events
}

/// Store a single credential in the vault.
pub async fn handle_vault_store(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let vault_ref = match action.params.get("vault_ref").and_then(|v| v.as_str()) {
        Some(r) => r,
        None => {
            events.push(OnboardEvent::error("vault_store requires 'vault_ref' parameter"));
            return events;
        }
    };

    let value = match action.params.get("value").and_then(|v| v.as_str()) {
        Some(v) => v,
        None => {
            events.push(OnboardEvent::error("vault_store requires 'value' parameter"));
            return events;
        }
    };

    // Mask value for display
    let masked = if value.len() > 10 {
        format!("{}••••{}", &value[..6], &value[value.len()-2..])
    } else {
        "••••••".to_string()
    };

    // Resolve vault key from onboard state (set during Step 3)
    let vault_key = match &state.vault_key {
        Some(k) => *k,
        None => {
            events.push(OnboardEvent::error("Vault key not available — complete Step 3 first"));
            return events;
        }
    };

    // Open (or create) the vault file at ~/.zeropoint/vault.json
    let vault_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("vault.json");

    let mut vault = match zp_trust::CredentialVault::load_or_create(&vault_key, &vault_path) {
        Ok(v) => v,
        Err(e) => {
            events.push(OnboardEvent::error(&format!("Failed to open vault: {}", e)));
            return events;
        }
    };

    // Encrypt and store the credential
    if let Err(e) = vault.store(vault_ref, value.as_bytes()) {
        events.push(OnboardEvent::error(&format!("Vault encryption failed: {}", e)));
        return events;
    }

    // Persist to disk
    if let Err(e) = vault.save(&vault_path) {
        events.push(OnboardEvent::error(&format!("Vault save failed: {}", e)));
        return events;
    }

    state.credentials_stored += 1;

    events.push(OnboardEvent::terminal(&format!(
        "✓ Encrypted and stored: {} ({})", vault_ref, masked
    )));

    events.push(OnboardEvent::new(
        "credential_stored",
        serde_json::json!({
            "vault_ref": vault_ref,
            "masked_value": masked,
            "total_stored": state.credentials_stored,
        }),
    ));

    events
}

/// Bulk-import found plaintext credentials into the vault.
pub async fn handle_vault_import_all(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let credentials = match action.params.get("credentials").and_then(|v| v.as_array()) {
        Some(c) => c,
        None => {
            events.push(OnboardEvent::error("vault_import_all requires 'credentials' array"));
            return events;
        }
    };

    events.push(OnboardEvent::terminal(&format!("Importing {} credential(s) into vault...", credentials.len())));

    let mut stored = 0;
    for cred in credentials {
        let provider = cred.get("provider").and_then(|v| v.as_str()).unwrap_or("unknown");
        let var_name = cred.get("var_name").and_then(|v| v.as_str()).unwrap_or("api_key");
        let value = match cred.get("value").and_then(|v| v.as_str()) {
            Some(v) => v,
            None => continue,
        };

        let vault_ref = format!("{}/{}", provider, var_name.to_lowercase());

        // Mask value for display
        let masked = if value.len() > 8 {
            format!("{}...{}", &value[..4], &value[value.len()-4..])
        } else {
            "••••••••".to_string()
        };

        // Store in vault
        let home = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
        let vault_path = home.join(".zeropoint").join("vault.json");

        let mut vault: serde_json::Value = if vault_path.exists() {
            std::fs::read_to_string(&vault_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        } else {
            serde_json::json!({})
        };

        vault.as_object_mut().map(|m| {
            m.insert(vault_ref.clone(), serde_json::json!({
                "value": value,
                "provider": provider,
                "var_name": var_name,
                "imported_from": "plaintext_scan",
            }));
        });

        if let Some(parent) = vault_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&vault) {
            let _ = std::fs::write(&vault_path, json);
        }

        stored += 1;
        state.credentials_stored += 1;

        events.push(OnboardEvent::new(
            "credential_stored",
            serde_json::json!({
                "vault_ref": vault_ref,
                "provider": provider,
                "var_name": var_name,
                "masked_value": masked,
                "total_stored": state.credentials_stored,
            }),
        ));

        events.push(OnboardEvent::terminal(&format!(
            "  ✓ {} → vault:{}", var_name, vault_ref
        )));
    }

    events.push(OnboardEvent::terminal(&format!(
        "\n{} credential(s) secured in vault", stored
    )));

    events.push(OnboardEvent::new(
        "import_complete",
        serde_json::json!({
            "imported": stored,
            "total_stored": state.credentials_stored,
        }),
    ));

    events
}
'''

CONFIGURE_RS = r'''//! Configure engine dispatch — shells out to `zp configure auto`.

use super::{OnboardAction, OnboardEvent, OnboardState};

/// Configure discovered tools by invoking `zp configure auto`.
///
/// Shells out to the CLI configure engine so we get identical behavior
/// to running it from the terminal. Output is captured and streamed
/// back as terminal events through the WebSocket.
pub async fn handle_configure(action: &OnboardAction, state: &mut OnboardState) -> Vec<OnboardEvent> {
    let mut events = Vec::new();

    let use_proxy = action.params.get("proxy")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let proxy_port = action.params.get("proxy_port")
        .and_then(|v| v.as_u64())
        .unwrap_or(3000) as u16;

    // Determine scan path — prefer what the user set in Step 5,
    // fall back to ~/projects, then accept an override from the action.
    let scan_path = action.params.get("scan_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| state.scan_path.clone())
        .unwrap_or_else(|| "~/projects".to_string());

    // Expand ~ for the shell command
    let expanded_path = if scan_path.starts_with("~/") {
        dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(&scan_path[2..])
            .display()
            .to_string()
    } else {
        scan_path.clone()
    };

    events.push(OnboardEvent::terminal("Configuring discovered tools..."));

    // Build the CLI command
    let mut cmd_args = vec![
        "configure".to_string(),
        "auto".to_string(),
        "--path".to_string(),
        expanded_path.clone(),
        "--overwrite".to_string(),
    ];
    if use_proxy {
        cmd_args.push("--proxy".to_string());
        cmd_args.push("--proxy-port".to_string());
        cmd_args.push(proxy_port.to_string());
    }

    events.push(OnboardEvent::terminal(&format!(
        "$ zp {}", cmd_args.join(" ")
    )));

    // Resolve the zp binary path
    let zp_bin = which::which("zp").unwrap_or_else(|_| std::path::PathBuf::from("zp"));

    events.push(OnboardEvent::terminal(&format!("Binary: {}", zp_bin.display())));

    // Run the configure engine (async — avoids blocking the tokio runtime)
    match tokio::process::Command::new(&zp_bin)
        .args(&cmd_args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Stream each line of output as a terminal event
            for line in stdout.lines() {
                if !line.trim().is_empty() {
                    events.push(OnboardEvent::terminal(line));
                }
            }
            for line in stderr.lines() {
                if !line.trim().is_empty() {
                    events.push(OnboardEvent::terminal(line));
                }
            }

            if stdout.is_empty() && stderr.is_empty() {
                events.push(OnboardEvent::terminal("(no output from zp configure)"));
            }

            if output.status.success() {
                events.push(OnboardEvent::terminal(""));
                events.push(OnboardEvent::terminal("✓ Tools configured with vault credentials"));

                // Count configured tools from output (lines starting with "  CONFIG")
                let configured_count = stdout.lines()
                    .filter(|l| l.trim_start().starts_with("CONFIG"))
                    .count();
                // Only count actually configured tools — never inflate
                state.tools_configured = configured_count;

                // Emit per-tool events so the UI can animate each card
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("CONFIG") {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "governed",
                                }),
                            ));
                        }
                    } else if trimmed.starts_with("SKIP") {
                        // Parse: "SKIP  toolname — missing N credential(s)"
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let tool_name = parts[1].trim_end_matches(':');
                            let missing = trimmed
                                .split("missing ")
                                .nth(1)
                                .and_then(|s| s.split_whitespace().next())
                                .and_then(|n| n.parse::<usize>().ok())
                                .unwrap_or(0);
                            events.push(OnboardEvent::new(
                                "tool_configured",
                                serde_json::json!({
                                    "tool_name": tool_name,
                                    "status": "skipped",
                                    "missing": missing,
                                }),
                            ));
                        }
                    }
                }
            } else {
                events.push(OnboardEvent::terminal(&format!(
                    "Configure exited with code {}", output.status.code().unwrap_or(-1)
                )));
            }
        }
        Err(e) => {
            events.push(OnboardEvent::error(&format!(
                "Failed to run zp configure: {}", e
            )));
            events.push(OnboardEvent::terminal(
                "Fallback: run from your terminal:"
            ));
            let proxy_flag = if use_proxy { format!(" --proxy --proxy-port {}", proxy_port) } else { String::new() };
            events.push(OnboardEvent::terminal(&format!(
                "  zp configure auto {}{}", expanded_path, proxy_flag
            )));
        }
    }

    state.step = 7;

    events.push(OnboardEvent::new(
        "configure_complete",
        serde_json::json!({
            "proxy_enabled": use_proxy,
            "proxy_port": proxy_port,
            "scan_path": scan_path,
            "tools_configured": state.tools_configured,
        }),
    ));

    events
}
'''


if __name__ == "__main__":
    main()
