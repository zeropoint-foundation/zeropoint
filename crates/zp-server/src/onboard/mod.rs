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

mod state;
mod detect;
mod genesis;
mod inference;
mod scan;
mod credentials;
mod configure;
pub mod preflight;

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
    // Use the cached vault key from AppState (resolved once at startup)
    // so we never re-prompt the macOS Keychain during the session.
    let cached_vk: Option<&[u8; 32]> = app_state.0.vault_key.as_ref().map(|v| &*v.key);
    let mut onboard = OnboardState::from_filesystem_with_vault(cached_vk);

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
        "validate_credential" => credentials::handle_validate_credential(action, state).await,
        "validate_all" => credentials::handle_validate_all(action, state).await,
        "configure" => configure::handle_configure(action, state).await,
        "preflight" => preflight::handle_preflight(state).await,
        "status" => vec![OnboardEvent::new("state", serde_json::to_value(&*state).unwrap_or_default())],
        _ => vec![OnboardEvent::error(&format!("unknown action: {}", action.action))],
    }
}
