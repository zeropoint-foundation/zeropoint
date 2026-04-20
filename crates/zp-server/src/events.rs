//! Real-time event streaming — Server-Sent Events for the audit chain.
//!
//! Provides `GET /api/v1/events/stream` as an SSE endpoint that broadcasts
//! audit chain events in real time. This is the foundation for:
//!
//!   - Dashboard live updates (observability panels)
//!   - Channel adapters (Slack/Discord notifications)
//!   - External monitoring integrations
//!
//! ## Architecture
//!
//! ```text
//!   AuditStore::append()
//!       │
//!       ▼
//!   broadcast_event()  ← called after each append
//!       │
//!       ├──► SSE endpoint (dashboard clients)
//!       └──► Channel adapters (Slack, Discord)
//! ```
//!
//! The broadcast channel has a bounded capacity. Slow consumers that fall
//! behind receive a `Lagged` error and miss events — this is by design.
//! The audit chain is the authoritative record; the event stream is
//! best-effort real-time notification.

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::stream::Stream;
use serde::Serialize;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::broadcast;

use crate::AppState;

/// Capacity of the broadcast channel. Events beyond this are dropped
/// for slow consumers (they get `RecvError::Lagged`).
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

/// A single event broadcast to all SSE subscribers.
#[derive(Clone, Debug, Serialize)]
pub struct EventStreamItem {
    /// Event category for SSE `event:` field (e.g., "audit", "tool", "cognition").
    pub category: String,
    /// Short event type (e.g., "tool:launched:ironclaw", "cognition:promoted").
    pub event_type: String,
    /// Human-readable summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Entry hash from the audit chain (if event came from an append).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_hash: Option<String>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

impl EventStreamItem {
    /// Create a new event from an audit chain append.
    pub fn from_audit(event_type: impl Into<String>, entry_hash: Option<String>) -> Self {
        Self {
            category: "audit".to_string(),
            event_type: event_type.into(),
            summary: None,
            entry_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Create a system-level event (startup, shutdown, etc.).
    pub fn system(event_type: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            category: "system".to_string(),
            event_type: event_type.into(),
            summary: Some(summary.into()),
            entry_hash: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Add a summary to an existing event.
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }
}

/// Create a new broadcast channel pair for event streaming.
pub fn event_channel() -> (broadcast::Sender<EventStreamItem>, broadcast::Receiver<EventStreamItem>) {
    broadcast::channel(EVENT_CHANNEL_CAPACITY)
}

/// Broadcast an event to all connected SSE clients.
///
/// Best-effort: if no subscribers are connected, the event is silently dropped.
/// If the channel is full, slow subscribers are lagged (they miss events).
pub fn broadcast_event(tx: &broadcast::Sender<EventStreamItem>, item: EventStreamItem) {
    // send() returns Err if there are no active receivers — that's fine.
    let _ = tx.send(item);
}

/// `GET /api/v1/events/stream` — Server-Sent Events endpoint.
///
/// Streams real-time audit chain events to connected clients. Each event
/// is a JSON-encoded `EventStreamItem` with the SSE `event:` field set
/// to the item's category.
///
/// The stream sends a keepalive comment every 15 seconds to prevent
/// proxy/load-balancer timeouts.
pub async fn event_stream_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.0.event_tx.subscribe();

    let stream = async_stream::stream! {
        let mut rx = rx;
        loop {
            match rx.recv().await {
                Ok(item) => {
                    let data = serde_json::to_string(&item).unwrap_or_default();
                    yield Ok(Event::default()
                        .event(&item.category)
                        .data(data));
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Notify the client that events were missed.
                    let msg = format!("{{\"lagged\":{}}}", n);
                    yield Ok(Event::default()
                        .event("system")
                        .data(msg));
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    )
}
