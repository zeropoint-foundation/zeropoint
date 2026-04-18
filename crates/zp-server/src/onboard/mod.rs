//! `/api/onboard/ws` — WebSocket-driven browser onboarding.
//!
//! Split into modules by responsibility:
//!   - state.rs       — OnboardState + filesystem reconstruction
//!   - detect.rs      — Platform/biometric + local inference detection
//!   - genesis.rs     — Genesis ceremony + vault check
//!   - inference.rs   — Inference posture, guidance, model pull, system resources
//!   - scan.rs        — Tool discovery (delegates to zp-engine)
//!   - credentials.rs — Vault store, import, provider catalog
//!   - configure.rs   — Configure engine dispatch

mod configure;
mod credentials;
mod detect;
mod genesis;
mod inference;
pub mod preflight;
mod scan;
mod state;
pub mod verify;

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
        serde_json::to_string(self)
            .unwrap_or_else(|_| r#"{"event":"error","message":"serialize failed"}"#.to_string())
    }
}

// ============================================================================
// WebSocket upgrade handler
// ============================================================================

/// Query parameters for onboard WebSocket upgrade.
#[derive(Debug, serde::Deserialize)]
pub struct OnboardWsQuery {
    pub token: Option<String>,
    /// When true, sends initial state event and terminal (progress) events.
    /// Browser UI sets this; CLI tools like websocat omit it to get only
    /// result events (platform, genesis_complete, etc.).
    pub ui: Option<bool>,
}

pub async fn onboard_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(query): axum::extract::Query<OnboardWsQuery>,
) -> impl IntoResponse {
    // Post-genesis: reject onboard WebSocket connections
    let home = dirs::home_dir().unwrap_or_default();
    let genesis_path = home.join(".zeropoint").join("genesis.json");
    if genesis_path.exists() {
        return (
            axum::http::StatusCode::FORBIDDEN,
            "Onboarding is disabled after genesis is complete",
        )
            .into_response();
    }

    // AUTH-VULN-06: Require one-time setup token on the WebSocket upgrade.
    // The browser carries the `zp_onboard` cookie set during the page load
    // redirect, so the token never needs to appear in the WS URL.
    if let Some(ref expected) = state.0.onboard_token {
        let client_ip = crate::client_ip_from_headers(&headers);

        if let Some(_retry_after) = state.0.rate_limiter.is_blocked(client_ip) {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts",
            )
                .into_response();
        }

        // Accept token from cookie (primary — set by page handler redirect)
        // or query param (fallback — e.g. CLI-based WS clients).
        let from_cookie = crate::extract_onboard_cookie(&headers)
            .map(|t| crate::constant_time_eq(&t, expected))
            .unwrap_or(false);
        let from_query = query
            .token
            .as_deref()
            .map(|t| crate::constant_time_eq(t, expected))
            .unwrap_or(false);

        if !from_cookie && !from_query {
            let _ = state.0.rate_limiter.record_failure(client_ip);
            return (
                axum::http::StatusCode::FORBIDDEN,
                "Setup token required for onboard WebSocket",
            )
                .into_response();
        }
    }

    let ui_mode = query.ui.unwrap_or(false);
    ws.max_frame_size(128 * 1024) // 128 KB — onboard payloads include credentials
        .max_message_size(256 * 1024)
        .on_upgrade(move |socket| handle_onboard_ws(socket, state, ui_mode))
        .into_response()
}

async fn handle_onboard_ws(socket: WebSocket, app_state: AppState, ui_mode: bool) {
    let (mut sender, mut receiver) = socket.split();
    // Use the cached vault key from AppState (resolved in background at startup)
    // so we never re-prompt the macOS Keychain during the session.
    let cached_vk: Option<&[u8; 32]> = app_state
        .0
        .vault_key
        .get()
        .and_then(|opt| opt.as_ref())
        .map(|v| &*v.key);
    let mut onboard = OnboardState::from_filesystem_with_vault(cached_vk);

    tracing::info!(
        "onboard ws: reconstructed state — step={}, genesis={}, vault={}, tools={}/{}",
        onboard.step,
        onboard.genesis_complete,
        onboard.credentials_stored,
        onboard.tools_configured,
        onboard.tools_discovered
    );

    // Send initial state so frontend can resume at the right step.
    // Only in UI mode — CLI tools (websocat) use one-shot mode and
    // need the first message to be the action response, not unsolicited state.
    if ui_mode {
        let init_event =
            OnboardEvent::new("state", serde_json::to_value(&onboard).unwrap_or_default());
        let _ = sender.send(WsMessage::Text(init_event.to_json())).await;
    }

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
                if ui_mode {
                    // Browser UI: stream events individually for live terminal animation
                    for event in events {
                        if sender.send(WsMessage::Text(event.to_json())).await.is_err() {
                            return;
                        }
                    }
                } else {
                    // CLI / one-shot mode (websocat -1): batch all non-terminal
                    // events into a single JSON object so the client receives
                    // the full result set in one read. Terminal progress events
                    // are dropped — they're only useful for UI animation.
                    let result_events: Vec<&OnboardEvent> =
                        events.iter().filter(|e| e.event != "terminal").collect();
                    if result_events.len() == 1 {
                        // Single result event — send as-is
                        if sender
                            .send(WsMessage::Text(result_events[0].to_json()))
                            .await
                            .is_err()
                        {
                            return;
                        }
                    } else if !result_events.is_empty() {
                        // Multiple result events — merge into one JSON with all fields.
                        // Collect all event names so grep-based checks (e.g. relay
                        // scripts looking for "genesis_complete") find every event
                        // in the combined output.
                        let event_names: Vec<&str> =
                            result_events.iter().map(|e| e.event.as_str()).collect();
                        let mut merged = serde_json::Map::new();
                        merged.insert(
                            "events".to_string(),
                            serde_json::to_value(&event_names).unwrap_or_default(),
                        );
                        for evt in &result_events {
                            // Set `event` to last event name (final result)
                            if let Ok(serde_json::Value::Object(map)) =
                                serde_json::to_value(evt)
                            {
                                for (k, v) in map {
                                    merged.insert(k, v);
                                }
                            }
                            // Also merge flattened data fields
                            if let serde_json::Value::Object(data_map) = &evt.data {
                                for (k, v) in data_map {
                                    merged.insert(k.clone(), v.clone());
                                }
                            }
                        }
                        let merged_json = serde_json::to_string(
                            &serde_json::Value::Object(merged),
                        )
                        .unwrap_or_default();
                        if sender
                            .send(WsMessage::Text(merged_json))
                            .await
                            .is_err()
                        {
                            return;
                        }
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
    // ── Step-ordering enforcement (Phase 0.5: AUTH-VULN-05, AUTHZ-VULN-19/20, INJ-VULN-05) ──
    // Certain actions have prerequisites. Without enforcement, an attacker
    // could skip directly to vault_store or configure without completing
    // the genesis ceremony, injecting credentials or scanning arbitrary paths.
    match action.action.as_str() {
        // ── Actions with no prerequisites ─────────────────────────
        "detect" => detect::handle_detect(state).await,
        "genesis" => genesis::handle_genesis(action, state).await,
        "status" => vec![OnboardEvent::new(
            "heartbeat_ack",
            serde_json::json!({ "ok": true }),
        )],

        // ── Requires genesis_complete ─────────────────────────────
        "sovereignty_upgrade" if state.genesis_complete => {
            genesis::handle_sovereignty_upgrade(action, state).await
        }
        "sovereignty_upgrade" => vec![OnboardEvent::error(
            "Genesis must be completed before sovereignty upgrade",
        )],

        "vault_check" if state.genesis_complete => genesis::handle_vault_check(state).await,
        "vault_check" => vec![OnboardEvent::error(
            "Genesis must be completed before vault check",
        )],

        "detect_local_inference" if state.genesis_complete => {
            detect::handle_detect_local_inference(state).await
        }
        "detect_local_inference" => vec![OnboardEvent::error("Genesis must be completed first")],

        "detect_ollama" if state.genesis_complete => {
            detect::handle_detect_local_inference(state).await
        }
        "detect_ollama" => vec![OnboardEvent::error("Genesis must be completed first")],

        "get_setup_guidance" if state.genesis_complete => {
            inference::handle_setup_guidance(action).await
        }
        "get_setup_guidance" => vec![OnboardEvent::error("Genesis must be completed first")],

        "start_model_pull" if state.genesis_complete => {
            inference::handle_start_model_pull(action).await
        }
        "start_model_pull" => vec![OnboardEvent::error("Genesis must be completed first")],

        "set_inference_posture" if state.genesis_complete => {
            inference::handle_set_inference_posture(action, state).await
        }
        "set_inference_posture" => vec![OnboardEvent::error("Genesis must be completed first")],

        "get_provider_catalog" if state.genesis_complete => {
            credentials::handle_get_provider_catalog(state).await
        }
        "get_provider_catalog" => vec![OnboardEvent::error("Genesis must be completed first")],

        // ── Scan: requires genesis, MUST validate scan_path ───────
        "scan" if state.genesis_complete => {
            // INJ-VULN-05 / AUTHZ-VULN-20: validate scan_path before allowing scan.
            if let Some(scan_path) = action.params.get("scan_path").and_then(|v| v.as_str()) {
                if let Err(reason) = validate_scan_path(scan_path) {
                    return vec![OnboardEvent::error(&format!("🛡 {}", reason))];
                }
            }
            scan::handle_scan(action, state).await
        }
        "scan" => vec![OnboardEvent::error(
            "Genesis must be completed before scanning",
        )],

        // ── Vault store: requires genesis + vault key ─────────────
        "vault_store" if state.genesis_complete => {
            credentials::handle_vault_store(action, state).await
        }
        "vault_store" => vec![OnboardEvent::error(
            "Genesis must be completed before storing credentials",
        )],

        "vault_import_all" if state.genesis_complete => {
            credentials::handle_vault_import_all(action, state).await
        }
        "vault_import_all" => vec![OnboardEvent::error("Genesis must be completed first")],

        "validate_credential" if state.genesis_complete => {
            credentials::handle_validate_credential(action, state).await
        }
        "validate_credential" => vec![OnboardEvent::error("Genesis must be completed first")],

        "validate_all" if state.genesis_complete => {
            credentials::handle_validate_all(action, state).await
        }
        "validate_all" => vec![OnboardEvent::error("Genesis must be completed first")],

        // ── Configure: requires genesis + scan + path validation ──
        "configure" if state.genesis_complete => {
            // AUTHZ-VULN-20: validate scan_path in configure action too.
            if let Some(scan_path) = action.params.get("scan_path").and_then(|v| v.as_str()) {
                if let Err(reason) = validate_scan_path(scan_path) {
                    return vec![OnboardEvent::error(&format!("🛡 {}", reason))];
                }
            }
            configure::handle_configure(action, state).await
        }
        "configure" => vec![OnboardEvent::error(
            "Genesis must be completed before configuring tools",
        )],

        "preflight" => preflight::handle_preflight(state, _app_state).await,

        // Phase 1.8: Hedera DLT onramp — optional external anchoring.
        // The operator can provision a Hedera testnet account during
        // onboarding. If skipped, ZP operates without DLT anchoring.
        "hedera_provision" if state.genesis_complete => {
            // TODO: implement when zp-hedera crate is available.
            // For now, acknowledge the action and note DLT is optional.
            vec![OnboardEvent::new(
                "hedera_status",
                serde_json::json!({
                    "status": "not_available",
                    "message": "DLT anchoring is not yet configured. Your audit chain remains fully functional without external anchoring. This feature will be available in a future update.",
                    "skippable": true,
                }),
            )]
        }
        "hedera_provision" => vec![OnboardEvent::error(
            "Genesis must be completed before DLT provisioning",
        )],

        _ => vec![OnboardEvent::error(&format!(
            "unknown action: {}",
            action.action
        ))],
    }
}

// ── Scan path validation (INJ-VULN-05, AUTHZ-VULN-20) ──────────────────

/// Validate that a scan_path is safe for tool discovery.
///
/// Returns `Ok(())` if the path is within the user's home directory,
/// `Err(reason)` if it points to a system or sensitive location.
fn validate_scan_path(path: &str) -> Result<(), String> {
    let path = path.trim();

    if path.is_empty() {
        return Err("Empty scan path".to_string());
    }

    // Reject path traversal
    if path.contains("..") {
        return Err("Path traversal (..) not allowed in scan path".to_string());
    }

    // Expand tilde
    let expanded = if path.starts_with("~/") || path == "~" {
        match dirs::home_dir() {
            Some(home) => home
                .join(path.strip_prefix("~/").unwrap_or(""))
                .to_string_lossy()
                .to_string(),
            None => path.to_string(),
        }
    } else {
        path.to_string()
    };

    // Block sensitive paths
    let blocked_prefixes = &[
        "/etc",
        "/var",
        "/usr",
        "/bin",
        "/sbin",
        "/boot",
        "/dev",
        "/proc",
        "/sys",
        "/tmp",
        "/root",
        "/lib",
        "/lib64",
        "/opt",
        "/private/etc",
        "/private/var",
        "/private/tmp",
    ];
    let blocked_components = &[
        ".ssh",
        ".gnupg",
        ".aws",
        ".azure",
        ".gcloud",
        ".kube",
        ".docker",
        "id_rsa",
        "id_ed25519",
        ".zeropoint/keys",
    ];

    for prefix in blocked_prefixes {
        if expanded == *prefix || expanded.starts_with(&format!("{}/", prefix)) {
            return Err(format!("System path '{}' cannot be scanned", prefix));
        }
    }

    for component in blocked_components {
        if expanded.contains(component) {
            return Err(format!(
                "Path contains sensitive component '{}' — cannot scan",
                component
            ));
        }
    }

    // Must be under home directory
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        if !expanded.starts_with(home_str.as_ref()) && expanded != "." {
            return Err(format!(
                "Scan path must be within your home directory ({})",
                home_str
            ));
        }
    }

    Ok(())
}
