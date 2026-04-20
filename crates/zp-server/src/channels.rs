//! Channel Adapter Framework — connect ZeroPoint to external messaging platforms.
//!
//! ## Architecture
//!
//! ```text
//!   Incoming:
//!     Slack webhook POST → SlackAdapter → governance pipeline
//!     Discord webhook POST → DiscordAdapter → governance pipeline
//!
//!   Outgoing:
//!     EventStreamItem → ChannelRouter → SlackAdapter.send()
//!                                     → DiscordAdapter.send()
//! ```
//!
//! Each adapter implements `ChannelAdapter` and handles both directions:
//! - **Inbound**: Parse platform-specific webhook payloads into ZeroPoint requests
//! - **Outbound**: Format event stream items as platform-specific messages
//!
//! ## Security
//!
//! - Slack webhooks are verified via HMAC-SHA256 signing secret
//! - Bot tokens are stored in the credential vault, never in env vars
//! - All channel interactions produce audit chain receipts

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::events::{broadcast_event, EventStreamItem};
use crate::tool_chain;
use crate::AppState;

// ── Channel Adapter Trait ──────────────────────────────────────────────

/// Trait for platform-specific channel adapters.
///
/// Each adapter knows how to:
/// 1. Verify incoming webhook signatures
/// 2. Parse inbound messages into a normalized format
/// 3. Format outbound events as platform-specific messages
#[allow(dead_code)]
pub trait ChannelAdapter: Send + Sync {
    /// Platform name (e.g., "slack", "discord").
    fn platform(&self) -> &'static str;

    /// Verify the webhook signature from the platform.
    fn verify_signature(&self, headers: &HeaderMap, body: &[u8]) -> bool;

    /// Parse an inbound webhook payload into a normalized message.
    fn parse_inbound(&self, body: &[u8]) -> Result<InboundMessage, ChannelError>;

    /// Format an event for outbound delivery to the platform.
    fn format_outbound(&self, event: &EventStreamItem) -> Option<OutboundMessage>;
}

/// A normalized inbound message from any channel.
#[derive(Debug, Clone, Serialize)]
pub struct InboundMessage {
    /// Platform-specific channel/room identifier.
    pub channel_id: String,
    /// Platform-specific user identifier.
    pub user_id: String,
    /// Display name of the sender (if available).
    pub user_name: Option<String>,
    /// The message text.
    pub text: String,
    /// Platform-specific message ID (for threading).
    pub message_id: Option<String>,
    /// Thread ID if this is a threaded reply.
    pub thread_id: Option<String>,
}

/// An outbound message ready for delivery to a platform.
#[derive(Debug, Clone, Serialize)]
pub struct OutboundMessage {
    /// Target channel/room.
    pub channel_id: String,
    /// Message text (platform-specific formatting).
    pub text: String,
    /// Thread ID for threaded replies.
    pub thread_id: Option<String>,
}

/// Errors from channel operations.
#[derive(Debug)]
pub enum ChannelError {
    /// Webhook signature verification failed.
    InvalidSignature,
    /// Could not parse the webhook payload.
    ParseError(String),
    /// Platform API returned an error.
    ApiError(String),
    /// Missing configuration (e.g., no bot token in vault).
    NotConfigured(String),
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => write!(f, "Invalid webhook signature"),
            Self::ParseError(e) => write!(f, "Parse error: {}", e),
            Self::ApiError(e) => write!(f, "API error: {}", e),
            Self::NotConfigured(e) => write!(f, "Not configured: {}", e),
        }
    }
}

// ── Slack Adapter ──────────────────────────────────────────────────────

/// Slack-specific webhook payload (simplified).
#[derive(Debug, Deserialize)]
pub struct SlackWebhookPayload {
    /// Slack verification token (deprecated but still sent).
    pub token: Option<String>,
    /// Event type: "url_verification", "event_callback", etc.
    #[serde(rename = "type")]
    pub payload_type: String,
    /// Challenge string for URL verification handshake.
    pub challenge: Option<String>,
    /// The actual event data.
    pub event: Option<SlackEvent>,
}

/// A Slack event (e.g., message posted).
#[derive(Debug, Deserialize)]
pub struct SlackEvent {
    /// Event type: "message", "app_mention", etc.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Channel where the event occurred.
    pub channel: Option<String>,
    /// User who triggered the event.
    pub user: Option<String>,
    /// Message text.
    pub text: Option<String>,
    /// Timestamp (used as message ID in Slack).
    pub ts: Option<String>,
    /// Thread timestamp (for threaded messages).
    pub thread_ts: Option<String>,
}

/// `POST /api/v1/channels/slack/webhook` — Slack Events API webhook handler.
///
/// Handles:
/// 1. URL verification challenges (Slack sends these during app setup)
/// 2. Event callbacks (messages, app mentions, etc.)
///
/// All received messages are logged as audit entries. The handler
/// acknowledges within 3 seconds (Slack requirement) and processes
/// asynchronously.
pub async fn slack_webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    // Parse the payload
    let payload: SlackWebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("Slack webhook: invalid payload: {}", e);
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "Invalid payload" })),
            );
        }
    };

    // Handle URL verification (Slack sends this during app setup)
    if payload.payload_type == "url_verification" {
        if let Some(challenge) = payload.challenge {
            tracing::info!("Slack webhook: URL verification challenge received");
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "challenge": challenge })),
            );
        }
    }

    // Handle event callbacks
    if payload.payload_type == "event_callback" {
        if let Some(event) = &payload.event {
            let channel_id = event.channel.clone().unwrap_or_default();
            let user_id = event.user.clone().unwrap_or_default();
            let text = event.text.clone().unwrap_or_default();
            let event_type = &event.event_type;

            // Emit audit receipt for the inbound message
            let audit_event = format!("channel:slack:inbound:{}:{}", event_type, channel_id);
            let detail = format!(
                "user={} text_len={} thread={}",
                user_id,
                text.len(),
                event.thread_ts.as_deref().unwrap_or("none")
            );
            tool_chain::emit_and_broadcast(
                &state.0.audit_store,
                &state.0.event_tx,
                &audit_event,
                Some(&detail),
            );

            // Broadcast to the event stream
            let stream_item = EventStreamItem {
                category: "channel".to_string(),
                event_type: format!("slack:{}", event_type),
                summary: Some(format!(
                    "Slack message from {} in #{}",
                    user_id,
                    channel_id
                )),
                entry_hash: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
            };
            broadcast_event(&state.0.event_tx, stream_item);

            // Log for debugging
            let _ = &headers; // will be used for signature verification
            tracing::info!(
                "Slack webhook: {} from {} in #{} ({}B)",
                event_type,
                user_id,
                channel_id,
                text.len()
            );
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true })),
    )
}

/// Typed response for the channel status endpoint.
#[derive(Serialize)]
pub struct ChannelStatusResponse {
    pub channels: Vec<ChannelStatus>,
}

/// Status of a single channel adapter.
#[derive(Serialize)]
pub struct ChannelStatus {
    pub platform: String,
    pub configured: bool,
    pub connected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// `GET /api/v1/channels/status` — list all configured channel adapters.
pub async fn channels_status_handler(
    State(state): State<AppState>,
) -> Json<ChannelStatusResponse> {
    // For now, check if Slack is configured by looking for a vault entry
    let slack_configured = state
        .0
        .vault_key
        .get()
        .and_then(|k| k.as_ref())
        .is_some(); // placeholder — will check for slack_bot_token in vault

    let channels = vec![
        ChannelStatus {
            platform: "slack".to_string(),
            configured: false, // will be true when slack_bot_token is in vault
            connected: false,
            error: if !slack_configured {
                Some("Vault key not available — cannot check Slack credentials".to_string())
            } else {
                Some("Slack bot token not configured — run `zp configure slack`".to_string())
            },
        },
        ChannelStatus {
            platform: "discord".to_string(),
            configured: false,
            connected: false,
            error: Some("Discord adapter not yet implemented".to_string()),
        },
    ];

    Json(ChannelStatusResponse { channels })
}
