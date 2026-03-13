//! Web discovery — privacy-preserving pub/sub relay over WebSocket.
//!
//! ## Privacy Architecture
//!
//! The web relay is a **dumb pipe**. It receives announce blobs from connected
//! agents and broadcasts them to all other connected agents. It:
//!
//! - **Does NOT** parse announce payloads (no capability indexing)
//! - **Does NOT** maintain query logs (no search patterns recorded)
//! - **Does NOT** persist any state (memory-only, restart = clean slate)
//! - **Does NOT** track who received what (no delivery receipts)
//!
//! Agents subscribe to the full firehose and filter locally. The relay has
//! no queryable model of who's out there — structurally incapable of surveillance.
//!
//! ## Wire Protocol
//!
//! Over the WebSocket channel, messages are simple framed blobs:
//!
//! ```text
//! [msg_type: u8] [payload_len: u32 BE] [payload: bytes]
//! ```
//!
//! Message types:
//! - `0x01` ANNOUNCE: Agent → Relay, contains signed announce blob
//! - `0x02` PEER_ANNOUNCE: Relay → Agent, forwarded announce blob
//! - `0x03` HEARTBEAT: Bidirectional, empty payload (keeps connection alive)
//!
//! The relay is itself a ZeroPoint node — it has an identity and can produce
//! receipts attesting to its behavior ("I did not censor announcements").
//! But its receipts record behavior, not content.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::discovery::{DiscoveredPeer, DiscoveryBackend, DiscoverySource};
use crate::error::{MeshError, MeshResult};

// ─────────────────────────────────────────────────────────────
// Wire protocol constants
// ─────────────────────────────────────────────────────────────

/// Message type: agent publishes an announce blob.
pub const MSG_ANNOUNCE: u8 = 0x01;
/// Message type: relay forwards a peer's announce blob.
pub const MSG_PEER_ANNOUNCE: u8 = 0x02;
/// Message type: heartbeat (keepalive).
pub const MSG_HEARTBEAT: u8 = 0x03;

/// Frame a message for the wire.
///
/// Format: `[msg_type: u8] [payload_len: u32 BE] [payload]`
pub fn frame_message(msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(1 + 4 + payload.len());
    frame.push(msg_type);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Parse a framed message.
///
/// Returns `(msg_type, payload)` or error if malformed.
pub fn parse_frame(data: &[u8]) -> MeshResult<(u8, Vec<u8>)> {
    if data.len() < 5 {
        return Err(MeshError::InvalidPacket("Frame too short".into()));
    }

    let msg_type = data[0];
    let payload_len = u32::from_be_bytes(
        data[1..5]
            .try_into()
            .map_err(|_| MeshError::InvalidPacket("Bad length bytes".into()))?,
    ) as usize;

    if data.len() < 5 + payload_len {
        return Err(MeshError::InvalidPacket(format!(
            "Frame truncated: expected {} payload bytes, got {}",
            payload_len,
            data.len() - 5
        )));
    }

    Ok((msg_type, data[5..5 + payload_len].to_vec()))
}

// ─────────────────────────────────────────────────────────────
// WebDiscovery configuration
// ─────────────────────────────────────────────────────────────

/// Configuration for the web discovery backend.
#[derive(Debug, Clone)]
pub struct WebDiscoveryConfig {
    /// WebSocket relay URL (e.g., "wss://relay.zeropoint.global/discover").
    pub relay_url: String,
    /// Heartbeat interval.
    pub heartbeat_interval: Duration,
    /// Reconnect delay on disconnect.
    pub reconnect_delay: Duration,
    /// Maximum reconnect delay (exponential backoff cap).
    pub max_reconnect_delay: Duration,
    /// Maximum number of buffered inbound announces before dropping.
    pub inbound_buffer_size: usize,
}

impl Default for WebDiscoveryConfig {
    fn default() -> Self {
        Self {
            relay_url: "wss://relay.zeropoint.global/discover".to_string(),
            heartbeat_interval: Duration::from_secs(30),
            reconnect_delay: Duration::from_secs(1),
            max_reconnect_delay: Duration::from_secs(60),
            inbound_buffer_size: 256,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// WebDiscovery backend
// ─────────────────────────────────────────────────────────────

/// Web discovery backend — connects to a pub/sub relay over WebSocket.
///
/// ## Connection lifecycle
///
/// 1. Connect to relay URL
/// 2. Send heartbeats at configured interval
/// 3. Publish announce blobs when `announce()` is called
/// 4. Buffer inbound PEER_ANNOUNCE messages for `poll_discoveries()`
/// 5. Auto-reconnect with exponential backoff on disconnect
///
/// The backend holds no state about peers — it's a pipe between the
/// relay and the DiscoveryManager. All validation and peer tracking
/// happens in the manager.
pub struct WebDiscovery {
    config: WebDiscoveryConfig,
    active: AtomicBool,
    connected: AtomicBool,
    /// Buffer for inbound announce blobs from the relay.
    inbound: RwLock<Vec<DiscoveredPeer>>,
    /// Channel to send outbound announces to the connection task.
    outbound_tx: RwLock<Option<mpsc::Sender<Vec<u8>>>>,
    /// Stats: announces published (counter only, no content).
    announces_published: AtomicU64,
    /// Stats: announces received (counter only, no content).
    announces_received: AtomicU64,
}

impl WebDiscovery {
    /// Create a new web discovery backend.
    ///
    /// Does not connect immediately — call `start()` to begin the connection.
    pub fn new(config: WebDiscoveryConfig) -> Self {
        Self {
            config,
            active: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            inbound: RwLock::new(Vec::new()),
            outbound_tx: RwLock::new(None),
            announces_published: AtomicU64::new(0),
            announces_received: AtomicU64::new(0),
        }
    }

    /// Create with default configuration.
    pub fn with_relay(relay_url: &str) -> Self {
        Self::new(WebDiscoveryConfig {
            relay_url: relay_url.to_string(),
            ..Default::default()
        })
    }

    /// Start the WebSocket connection.
    ///
    /// Spawns a background task that maintains the connection,
    /// handles heartbeats, and buffers inbound announces.
    ///
    /// In the current implementation, this sets up the channel
    /// infrastructure. Actual WebSocket I/O will use `tokio-tungstenite`
    /// when deployed; for now, the framing protocol and buffer
    /// management are fully functional for integration testing.
    pub async fn start(&self) -> MeshResult<()> {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(self.config.inbound_buffer_size);
        *self.outbound_tx.write().await = Some(tx);
        self.active.store(true, Ordering::Release);

        info!(
            relay_url = %self.config.relay_url,
            "Web discovery backend started"
        );

        Ok(())
    }

    /// Simulate receiving an announce from the relay (for testing).
    ///
    /// In production, this is called by the WebSocket receive loop.
    /// Exposed publicly for integration tests.
    pub async fn inject_announce(&self, payload: Vec<u8>) {
        let discovery = DiscoveredPeer {
            payload,
            source: DiscoverySource::Web,
            discovered_at: Utc::now(),
            hops: 2, // Web relay adds one conceptual hop
        };
        self.inbound.write().await.push(discovery);
        self.announces_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Process a raw framed message from the WebSocket.
    ///
    /// Called by the WebSocket receive loop. Handles message type
    /// dispatch without logging content.
    pub async fn handle_inbound_frame(&self, data: &[u8]) -> MeshResult<()> {
        let (msg_type, payload) = parse_frame(data)?;

        match msg_type {
            MSG_PEER_ANNOUNCE => {
                self.inject_announce(payload).await;
                Ok(())
            }
            MSG_HEARTBEAT => {
                debug!("Web discovery heartbeat received");
                Ok(())
            }
            _ => {
                debug!(msg_type, "Unknown web discovery message type");
                Ok(())
            }
        }
    }

    /// Check if we're currently connected to the relay.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// Get the announce publish count.
    pub fn announces_published(&self) -> u64 {
        self.announces_published.load(Ordering::Relaxed)
    }

    /// Get the announce receive count.
    pub fn announces_received(&self) -> u64 {
        self.announces_received.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl DiscoveryBackend for WebDiscovery {
    fn name(&self) -> &str {
        "web"
    }

    fn source(&self) -> DiscoverySource {
        DiscoverySource::Web
    }

    async fn announce(&self, payload: &[u8]) -> MeshResult<()> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(MeshError::Other("Web discovery not active".into()));
        }

        // Frame the announce for the wire
        let frame = frame_message(MSG_ANNOUNCE, payload);

        // Send via the outbound channel (the connection task picks it up)
        let tx_guard = self.outbound_tx.read().await;
        if let Some(tx) = tx_guard.as_ref() {
            tx.send(frame)
                .await
                .map_err(|_| MeshError::InterfaceError("Outbound channel closed".into()))?;
        }

        self.announces_published.fetch_add(1, Ordering::Relaxed);
        debug!("Announce published to web relay");
        Ok(())
    }

    async fn poll_discoveries(&self) -> MeshResult<Vec<DiscoveredPeer>> {
        let mut inbound = self.inbound.write().await;
        Ok(std::mem::take(&mut *inbound))
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    async fn shutdown(&self) -> MeshResult<()> {
        self.active.store(false, Ordering::Release);
        self.connected.store(false, Ordering::Release);
        *self.outbound_tx.write().await = None;
        info!("Web discovery backend shut down");
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────
// Relay server (the pub/sub relay itself)
// ─────────────────────────────────────────────────────────────

/// The web discovery relay — a minimal pub/sub server with reciprocity enforcement.
///
/// This is the server-side component that agents connect to.
/// It is designed to be **structurally amnesic**:
///
/// - No persistent storage of any kind
/// - No indexing of announce content
/// - No query interface — clients get the full firehose
/// - No delivery tracking — fire-and-forget broadcast
/// - No connection logging beyond connection count
///
/// ## Reciprocity Rule
///
/// To prevent passive scanning, the relay enforces a simple rule:
/// **you must announce before you receive.** A connection that only
/// subscribes without publishing its own announce is structurally
/// suspicious — it's a consumer-only node, a passive scanner.
///
/// The enforcement is:
/// 1. On connect, the client gets a `RelayConnection` handle
/// 2. The handle tracks whether the client has published an announce
/// 3. `receive()` returns `NotYetAnnounced` until the client publishes
/// 4. After the grace period expires, the connection can be terminated
///
/// This means any scanner must first announce itself — exposing its
/// signed identity to every legitimate agent on the network — before
/// it can observe anyone else. Scanners become observable before they
/// can observe.
///
/// ## Behavioral Signals for Reputation
///
/// The relay tracks minimal behavioral counters per connection:
/// - `has_announced`: whether the client published at least one announce
/// - `announces_published`: how many announces the client sent
/// - `time_connected`: how long the connection has been active
///
/// These counters — not content, just behavior — can be emitted as
/// `ReputationSignal`s in the `PolicyCompliance` category. An agent
/// that connects, announces, and participates has a positive signal.
/// An agent that connects, announces once (to pass the gate), then
/// silently consumes has a weaker signal. Over time, the reputation
/// system naturally separates participants from parasites.
///
/// ## Operator guarantees
///
/// Because the relay never parses payloads:
/// - Subpoena-proof: there's nothing to hand over
/// - Compromise-proof: an attacker gains access to zero peer data
/// - Audit-friendly: the relay's receipt chain proves honest behavior
pub struct WebRelayServer {
    /// Current connection count (no identity info, just a number).
    connection_count: AtomicU64,
    /// Total announces relayed (counter, no content).
    announces_relayed: AtomicU64,
    /// Connections rejected for not announcing (counter, no identity).
    reciprocity_rejections: AtomicU64,
    /// Whether the relay is accepting connections.
    active: AtomicBool,
    /// Broadcast channel for forwarding announces to all subscribers.
    /// Messages are raw blobs — the relay never inspects them.
    broadcast_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    /// Grace period: how long a new connection has before it must announce.
    announce_grace_period: Duration,
}

/// A connection handle for a single client on the relay.
///
/// Enforces the reciprocity rule: the client must announce before
/// receiving peer announces. Tracks minimal behavioral counters
/// (no content, no identity) for reputation signal generation.
pub struct RelayConnection {
    /// Whether this client has announced at least once.
    has_announced: AtomicBool,
    /// Number of announces this client has published.
    announces_published: AtomicU64,
    /// When this connection was established.
    connected_at: std::time::Instant,
    /// Broadcast receiver for incoming peer announces.
    receiver: tokio::sync::broadcast::Receiver<Vec<u8>>,
    /// Grace period inherited from the relay.
    grace_period: Duration,
}

/// Behavioral summary for a connection (no content, no identity).
///
/// Emitted when a connection closes. Can be translated into a
/// `ReputationSignal` in the `PolicyCompliance` category.
#[derive(Debug, Clone)]
pub struct ConnectionBehavior {
    /// Whether the client ever announced.
    pub announced: bool,
    /// How many announces the client published.
    pub announces_published: u64,
    /// How long the connection was active.
    pub duration: Duration,
    /// Whether the connection was terminated for not announcing.
    pub reciprocity_violation: bool,
}

impl WebRelayServer {
    /// Create a new relay server.
    ///
    /// `capacity` is the broadcast channel buffer size — how many
    /// announces can be in-flight before lagging subscribers drop messages.
    pub fn new(capacity: usize) -> Self {
        let (broadcast_tx, _) = tokio::sync::broadcast::channel(capacity);
        Self {
            connection_count: AtomicU64::new(0),
            announces_relayed: AtomicU64::new(0),
            reciprocity_rejections: AtomicU64::new(0),
            active: AtomicBool::new(true),
            broadcast_tx,
            announce_grace_period: Duration::from_secs(30),
        }
    }

    /// Create with a custom grace period.
    pub fn with_grace_period(capacity: usize, grace_period: Duration) -> Self {
        let mut server = Self::new(capacity);
        server.announce_grace_period = grace_period;
        server
    }

    /// Handle an inbound announce from a connected agent.
    ///
    /// The relay does exactly ONE thing: broadcast the blob to all
    /// other subscribers. It does not:
    /// - Parse the blob
    /// - Validate the signature (clients do this)
    /// - Record who sent it
    /// - Record who received it
    pub fn relay_announce(&self, payload: Vec<u8>) -> MeshResult<()> {
        if !self.active.load(Ordering::Relaxed) {
            return Err(MeshError::Other("Relay not active".into()));
        }

        // Frame as PEER_ANNOUNCE and broadcast
        let frame = frame_message(MSG_PEER_ANNOUNCE, &payload);

        // broadcast::send returns Err if there are no receivers — that's fine
        let _ = self.broadcast_tx.send(frame);
        self.announces_relayed.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Connect a new client to the relay.
    ///
    /// Returns a `RelayConnection` handle that enforces reciprocity:
    /// the client must call `publish_announce()` before `receive()`
    /// will deliver peer announces.
    pub fn connect(&self) -> RelayConnection {
        self.connection_count.fetch_add(1, Ordering::Relaxed);
        RelayConnection {
            has_announced: AtomicBool::new(false),
            announces_published: AtomicU64::new(0),
            connected_at: std::time::Instant::now(),
            receiver: self.broadcast_tx.subscribe(),
            grace_period: self.announce_grace_period,
        }
    }

    /// Record a disconnection and get the behavioral summary.
    ///
    /// The summary contains no content or identity — just counters.
    /// The caller can translate this into a ReputationSignal if desired.
    pub fn disconnect_with_behavior(&self, conn: &RelayConnection) -> ConnectionBehavior {
        self.connection_count.fetch_sub(1, Ordering::Relaxed);
        let announced = conn.has_announced.load(Ordering::Relaxed);
        let duration = conn.connected_at.elapsed();

        if !announced {
            self.reciprocity_rejections.fetch_add(1, Ordering::Relaxed);
        }

        ConnectionBehavior {
            announced,
            announces_published: conn.announces_published.load(Ordering::Relaxed),
            duration,
            reciprocity_violation: !announced && duration > conn.grace_period,
        }
    }

    /// Simple disconnect (backward-compatible, no behavioral summary).
    pub fn disconnect(&self) {
        self.connection_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Legacy subscribe (without reciprocity enforcement).
    ///
    /// Used for backward compatibility and testing. Prefer `connect()`
    /// for production use.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.connection_count.fetch_add(1, Ordering::Relaxed);
        self.broadcast_tx.subscribe()
    }

    /// Get current connection count (no identity info).
    pub fn connections(&self) -> u64 {
        self.connection_count.load(Ordering::Relaxed)
    }

    /// Get total announces relayed (counter only).
    pub fn announces_relayed(&self) -> u64 {
        self.announces_relayed.load(Ordering::Relaxed)
    }

    /// Get count of reciprocity violations (connections that never announced).
    pub fn reciprocity_rejections(&self) -> u64 {
        self.reciprocity_rejections.load(Ordering::Relaxed)
    }

    /// Shut down the relay.
    pub fn shutdown(&self) {
        self.active.store(false, Ordering::Release);
        info!(
            total_relayed = self.announces_relayed(),
            reciprocity_rejections = self.reciprocity_rejections(),
            "Web relay server shut down"
        );
    }
}

impl RelayConnection {
    /// Publish an announce through this connection.
    ///
    /// Marks this connection as having announced (passing the reciprocity gate).
    /// The relay broadcasts the payload to all other subscribers.
    pub fn publish_announce(&self, relay: &WebRelayServer, payload: Vec<u8>) -> MeshResult<()> {
        self.has_announced.store(true, Ordering::Release);
        self.announces_published.fetch_add(1, Ordering::Relaxed);
        relay.relay_announce(payload)
    }

    /// Receive the next peer announce from the relay.
    ///
    /// **Reciprocity enforced**: returns `Err` if this connection hasn't
    /// announced yet. This prevents passive scanning — you must expose
    /// your own identity before you can observe others.
    ///
    /// During the grace period, returns a specific error so the client
    /// knows it needs to announce. After the grace period, the connection
    /// should be terminated.
    pub fn try_receive(&mut self) -> MeshResult<Vec<u8>> {
        // Reciprocity gate: must announce first
        if !self.has_announced.load(Ordering::Acquire) {
            let elapsed = self.connected_at.elapsed();
            if elapsed > self.grace_period {
                return Err(MeshError::Other(
                    "Reciprocity violation: announce grace period expired".into(),
                ));
            }
            return Err(MeshError::Other(
                "Reciprocity: must announce before receiving".into(),
            ));
        }

        // Past the gate — try to receive
        match self.receiver.try_recv() {
            Ok(frame) => Ok(frame),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {
                Err(MeshError::Other("No announces available".into()))
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                Err(MeshError::Other("Relay channel closed".into()))
            }
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
                warn!(missed = n, "Connection lagged behind relay broadcast");
                // Try again — lagged just means we missed some
                match self.receiver.try_recv() {
                    Ok(frame) => Ok(frame),
                    _ => Err(MeshError::Other("No announces available after lag".into())),
                }
            }
        }
    }

    /// Check if this connection has passed the reciprocity gate.
    pub fn has_announced(&self) -> bool {
        self.has_announced.load(Ordering::Relaxed)
    }

    /// Check if the grace period has expired.
    pub fn grace_period_expired(&self) -> bool {
        !self.has_announced.load(Ordering::Relaxed)
            && self.connected_at.elapsed() > self.grace_period
    }

    /// Get how long this connection has been active.
    pub fn uptime(&self) -> Duration {
        self.connected_at.elapsed()
    }

    /// Get the number of announces this connection has published.
    pub fn announces_published(&self) -> u64 {
        self.announces_published.load(Ordering::Relaxed)
    }
}

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_and_parse() {
        let payload = b"hello, mesh";
        let frame = frame_message(MSG_ANNOUNCE, payload);

        assert_eq!(frame[0], MSG_ANNOUNCE);
        assert_eq!(frame.len(), 1 + 4 + payload.len());

        let (msg_type, parsed) = parse_frame(&frame).unwrap();
        assert_eq!(msg_type, MSG_ANNOUNCE);
        assert_eq!(parsed, payload);
    }

    #[test]
    fn test_frame_empty_payload() {
        let frame = frame_message(MSG_HEARTBEAT, &[]);
        assert_eq!(frame.len(), 5); // 1 type + 4 length + 0 payload

        let (msg_type, parsed) = parse_frame(&frame).unwrap();
        assert_eq!(msg_type, MSG_HEARTBEAT);
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_truncated_frame() {
        let result = parse_frame(&[0x01, 0x00, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_frame_payload_mismatch() {
        // Claims 100 bytes but only has 5
        let bad_frame = vec![0x01, 0x00, 0x00, 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05];
        let result = parse_frame(&bad_frame);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_web_discovery_lifecycle() {
        let web = WebDiscovery::with_relay("wss://test.local/discover");
        assert!(!web.is_active());

        web.start().await.unwrap();
        assert!(web.is_active());

        // Inject an announce (simulating relay delivery)
        web.inject_announce(vec![1, 2, 3, 4]).await;
        assert_eq!(web.announces_received(), 1);

        // Poll should return it
        let discoveries = web.poll_discoveries().await.unwrap();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0].source, DiscoverySource::Web);
        assert_eq!(discoveries[0].hops, 2); // Web adds 1 hop

        // Poll again — should be empty (buffer was drained)
        let discoveries = web.poll_discoveries().await.unwrap();
        assert!(discoveries.is_empty());

        web.shutdown().await.unwrap();
        assert!(!web.is_active());
    }

    #[tokio::test]
    async fn test_web_discovery_handle_frame() {
        let web = WebDiscovery::with_relay("wss://test.local/discover");
        web.start().await.unwrap();

        // Build a PEER_ANNOUNCE frame
        let announce_payload = vec![0xAA; 200]; // Simulated announce blob
        let frame = frame_message(MSG_PEER_ANNOUNCE, &announce_payload);

        web.handle_inbound_frame(&frame).await.unwrap();

        let discoveries = web.poll_discoveries().await.unwrap();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0].payload, announce_payload);
    }

    #[tokio::test]
    async fn test_web_discovery_heartbeat_ignored() {
        let web = WebDiscovery::with_relay("wss://test.local/discover");
        web.start().await.unwrap();

        let frame = frame_message(MSG_HEARTBEAT, &[]);
        web.handle_inbound_frame(&frame).await.unwrap();

        // Heartbeat should not produce a discovery
        let discoveries = web.poll_discoveries().await.unwrap();
        assert!(discoveries.is_empty());
    }

    #[tokio::test]
    async fn test_relay_server_broadcast() {
        let relay = WebRelayServer::new(16);

        // Two subscribers
        let mut sub1 = relay.subscribe();
        let mut sub2 = relay.subscribe();
        assert_eq!(relay.connections(), 2);

        // Relay an announce
        let announce = vec![0xBB; 150];
        relay.relay_announce(announce.clone()).unwrap();

        // Both subscribers should receive the framed message
        let frame1 = sub1.try_recv().unwrap();
        let frame2 = sub2.try_recv().unwrap();
        assert_eq!(frame1, frame2);

        // Parse the frame — should be PEER_ANNOUNCE wrapping the original
        let (msg_type, payload) = parse_frame(&frame1).unwrap();
        assert_eq!(msg_type, MSG_PEER_ANNOUNCE);
        assert_eq!(payload, announce);

        assert_eq!(relay.announces_relayed(), 1);
    }

    #[tokio::test]
    async fn test_relay_server_no_subscribers() {
        let relay = WebRelayServer::new(16);
        assert_eq!(relay.connections(), 0);

        // Should not error even with no subscribers
        relay.relay_announce(vec![0xCC; 100]).unwrap();
        assert_eq!(relay.announces_relayed(), 1);
    }

    #[tokio::test]
    async fn test_relay_server_disconnect() {
        let relay = WebRelayServer::new(16);
        let _sub = relay.subscribe();
        assert_eq!(relay.connections(), 1);

        relay.disconnect();
        assert_eq!(relay.connections(), 0);
    }

    #[tokio::test]
    async fn test_relay_server_shutdown() {
        let relay = WebRelayServer::new(16);
        relay.shutdown();

        let result = relay.relay_announce(vec![0xDD; 50]);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_web_announce_not_active_errors() {
        let web = WebDiscovery::with_relay("wss://test.local/discover");
        // Not started — should error
        let result = web.announce(&[1, 2, 3]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_end_to_end_relay_to_client() {
        // Simulate the full path: agent → relay → other agent
        let relay = WebRelayServer::new(16);
        let client = WebDiscovery::with_relay("wss://test.local/discover");
        client.start().await.unwrap();

        // Agent publishes an announce to the relay
        let announce_blob = vec![0xEE; 200];
        relay.relay_announce(announce_blob.clone()).unwrap();

        // Client receives the broadcast (simulated by subscribe)
        let mut sub = relay.subscribe();

        // Relay another announce
        let announce_blob_2 = vec![0xFF; 180];
        relay.relay_announce(announce_blob_2.clone()).unwrap();

        // Subscriber gets the second one (first was before subscribe)
        let frame = sub.try_recv().unwrap();
        let (_, _payload) = parse_frame(&frame).unwrap();

        // Client processes the frame
        client.handle_inbound_frame(&frame).await.unwrap();

        let discoveries = client.poll_discoveries().await.unwrap();
        assert_eq!(discoveries.len(), 1);
        assert_eq!(discoveries[0].payload, announce_blob_2);
        assert_eq!(discoveries[0].source, DiscoverySource::Web);
    }

    // ── Reciprocity enforcement tests ────────────────────────

    #[tokio::test]
    async fn test_reciprocity_blocks_receive_before_announce() {
        let relay = WebRelayServer::new(16);
        let mut conn = relay.connect();

        assert!(!conn.has_announced());

        // Relay an announce from someone else
        relay.relay_announce(vec![0xAA; 100]).unwrap();

        // Trying to receive without announcing should fail
        let result = conn.try_receive();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("must announce before receiving"));
    }

    #[tokio::test]
    async fn test_reciprocity_allows_receive_after_announce() {
        let relay = WebRelayServer::new(16);
        let mut conn = relay.connect();

        // Announce first (passing the reciprocity gate)
        conn.publish_announce(&relay, vec![0xBB; 100]).unwrap();
        assert!(conn.has_announced());
        assert_eq!(conn.announces_published(), 1);

        // Now relay a peer announce
        relay.relay_announce(vec![0xCC; 150]).unwrap();

        // Should be able to receive now
        let frame = conn.try_receive().unwrap();
        let (msg_type, payload) = parse_frame(&frame).unwrap();
        assert_eq!(msg_type, MSG_PEER_ANNOUNCE);
        assert_eq!(payload, vec![0xCC; 150]);
    }

    #[tokio::test]
    async fn test_reciprocity_grace_period_expiry() {
        // Use a very short grace period for testing
        let relay = WebRelayServer::with_grace_period(16, Duration::from_millis(10));
        let mut conn = relay.connect();

        // Wait past the grace period
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert!(conn.grace_period_expired());

        // Trying to receive should get the "expired" error
        relay.relay_announce(vec![0xDD; 100]).unwrap();
        let result = conn.try_receive();
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("grace period expired"));
    }

    #[tokio::test]
    async fn test_disconnect_behavior_good_citizen() {
        let relay = WebRelayServer::new(16);
        let conn = relay.connect();

        // Good citizen: announces before doing anything
        conn.publish_announce(&relay, vec![0xEE; 100]).unwrap();
        conn.publish_announce(&relay, vec![0xFF; 100]).unwrap();

        let behavior = relay.disconnect_with_behavior(&conn);
        assert!(behavior.announced);
        assert_eq!(behavior.announces_published, 2);
        assert!(!behavior.reciprocity_violation);
    }

    #[tokio::test]
    async fn test_disconnect_behavior_scanner() {
        // Scanner: connects but never announces
        let relay = WebRelayServer::with_grace_period(16, Duration::from_millis(10));
        let conn = relay.connect();

        // Wait past grace period
        tokio::time::sleep(Duration::from_millis(20)).await;

        let behavior = relay.disconnect_with_behavior(&conn);
        assert!(!behavior.announced);
        assert_eq!(behavior.announces_published, 0);
        assert!(behavior.reciprocity_violation);

        // Relay should track the rejection
        assert_eq!(relay.reciprocity_rejections(), 1);
    }

    #[tokio::test]
    async fn test_disconnect_behavior_within_grace() {
        // Connects and disconnects within grace period without announcing
        // Not a violation — they might have been slow or encountered an error
        let relay = WebRelayServer::with_grace_period(16, Duration::from_secs(300));
        let conn = relay.connect();

        let behavior = relay.disconnect_with_behavior(&conn);
        assert!(!behavior.announced);
        assert!(!behavior.reciprocity_violation); // Within grace period
    }

    #[tokio::test]
    async fn test_multiple_connections_independent() {
        let relay = WebRelayServer::new(16);

        let mut conn1 = relay.connect();
        let mut conn2 = relay.connect();
        assert_eq!(relay.connections(), 2);

        // conn1 announces, conn2 doesn't
        conn1.publish_announce(&relay, vec![0x11; 100]).unwrap();

        // Relay a peer announce
        relay.relay_announce(vec![0x22; 100]).unwrap();

        // conn1 can receive (announced), conn2 can't (didn't announce)
        assert!(conn1.try_receive().is_ok());
        assert!(conn2.try_receive().is_err());
    }

    #[tokio::test]
    async fn test_own_announce_visible_to_others() {
        let relay = WebRelayServer::new(16);

        let mut conn1 = relay.connect();
        let mut conn2 = relay.connect();

        // Both announce (satisfying reciprocity)
        conn1.publish_announce(&relay, vec![0xAA; 100]).unwrap();
        conn2.publish_announce(&relay, vec![0xBB; 100]).unwrap();

        // conn1 should see conn2's announce (and possibly its own via broadcast)
        // conn2 should see conn1's announce
        // The broadcast channel delivers to ALL subscribers including the sender
        let frame1 = conn1.try_receive().unwrap();
        let frame2 = conn2.try_receive().unwrap();

        // Both should have received framed messages
        let (t1, _) = parse_frame(&frame1).unwrap();
        let (t2, _) = parse_frame(&frame2).unwrap();
        assert_eq!(t1, MSG_PEER_ANNOUNCE);
        assert_eq!(t2, MSG_PEER_ANNOUNCE);
    }
}
