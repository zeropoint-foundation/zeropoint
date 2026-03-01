//! TCP transport interfaces — Reticulum-compatible HDLC framing over TCP.
//!
//! Provides `TcpServerInterface` and `TcpClientInterface` that speak the
//! Reticulum wire protocol (HDLC-framed packets), making ZeroPoint agents
//! first-class citizens of the Reticulum mesh network.
//!
//! ## Wire Format
//!
//! Reticulum uses HDLC async framing (RFC 1662) over TCP:
//!
//! ```text
//! [FLAG] [escaped_packet_bytes] [FLAG]
//!  0x7E   (byte-stuffed data)    0x7E
//! ```
//!
//! - FLAG byte `0x7E` delimits frames
//! - ESC byte `0x7D` signals the next byte is XOR'd with `0x20`
//! - No length prefix — frame boundaries determined by FLAG bytes
//! - `TCP_NODELAY` enabled for low latency
//!
//! ## Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//! use zp_mesh::tcp::{TcpServerInterface, TcpClientInterface};
//! use zp_mesh::interface::InterfaceType;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Server side: listen for incoming connections
//! let server = TcpServerInterface::bind("127.0.0.1:4242").await?;
//!
//! // Client side: connect to a server
//! let client = TcpClientInterface::connect("127.0.0.1:4242").await?;
//!
//! // Both implement Interface — attach to MeshNode as usual
//! # Ok(())
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::error::{MeshError, MeshResult};
use crate::interface::{Interface, InterfaceConfig, InterfaceStats, InterfaceType};
use crate::packet::Packet;

// ============================================================================
// HDLC Framing (Reticulum wire protocol over TCP)
// ============================================================================

/// HDLC flag byte — frame delimiter.
const HDLC_FLAG: u8 = 0x7E;
/// HDLC escape byte.
const HDLC_ESC: u8 = 0x7D;
/// XOR mask applied to escaped bytes.
const HDLC_ESC_MASK: u8 = 0x20;

/// Escape a raw packet for HDLC transmission.
///
/// Replaces FLAG (0x7E) with [ESC, 0x5E] and ESC (0x7D) with [ESC, 0x5D].
pub fn hdlc_escape(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 8);
    for &byte in data {
        if byte == HDLC_FLAG || byte == HDLC_ESC {
            out.push(HDLC_ESC);
            out.push(byte ^ HDLC_ESC_MASK);
        } else {
            out.push(byte);
        }
    }
    out
}

/// Unescape HDLC-encoded data back to raw bytes.
///
/// Reverses the escape mechanism: [ESC, x] → (x ^ 0x20).
pub fn hdlc_unescape(data: &[u8]) -> MeshResult<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == HDLC_ESC {
            if i + 1 >= data.len() {
                return Err(MeshError::InvalidPacket(
                    "HDLC: escape byte at end of frame".into(),
                ));
            }
            out.push(data[i + 1] ^ HDLC_ESC_MASK);
            i += 2;
        } else {
            out.push(data[i]);
            i += 1;
        }
    }
    Ok(out)
}

/// Wrap raw packet bytes in an HDLC frame: [FLAG] [escaped_data] [FLAG].
pub fn hdlc_frame(packet_bytes: &[u8]) -> Vec<u8> {
    let escaped = hdlc_escape(packet_bytes);
    let mut frame = Vec::with_capacity(escaped.len() + 2);
    frame.push(HDLC_FLAG);
    frame.extend_from_slice(&escaped);
    frame.push(HDLC_FLAG);
    frame
}

/// Stateful HDLC stream decoder.
///
/// Accumulates bytes from TCP reads and yields complete frames.
/// Handles partial reads, frame boundaries spanning read calls,
/// and consecutive FLAG bytes between frames.
pub struct HdlcDecoder {
    buffer: Vec<u8>,
    in_frame: bool,
}

impl Default for HdlcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HdlcDecoder {
    /// Create a new decoder.
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(2048),
            in_frame: false,
        }
    }

    /// Feed raw TCP bytes into the decoder.
    ///
    /// Returns a vector of complete, unescaped frame payloads.
    /// Incomplete frames are buffered internally for the next call.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();

        for &byte in data {
            if byte == HDLC_FLAG {
                if self.in_frame && !self.buffer.is_empty() {
                    // End of frame — unescape and yield
                    match hdlc_unescape(&self.buffer) {
                        Ok(payload) if !payload.is_empty() => {
                            frames.push(payload);
                        }
                        Ok(_) => {
                            // Empty frame, ignore
                        }
                        Err(e) => {
                            debug!("HDLC decode error, dropping frame: {}", e);
                        }
                    }
                    self.buffer.clear();
                }
                // FLAG always starts a new frame context
                self.in_frame = true;
                self.buffer.clear();
            } else if self.in_frame {
                self.buffer.push(byte);
            }
            // Bytes before the first FLAG are discarded (sync)
        }

        frames
    }

    /// Reset the decoder state.
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.in_frame = false;
    }
}

// ============================================================================
// Shared TCP read/write logic
// ============================================================================

/// Read loop: reads from a TCP stream, HDLC-decodes, and sends Packets to channel.
async fn tcp_read_loop(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    packet_tx: mpsc::Sender<Packet>,
    stats: Arc<Stats>,
    name: String,
    shutdown: broadcast::Receiver<()>,
) {
    let mut decoder = HdlcDecoder::new();
    let mut buf = [0u8; 4096];
    let mut shutdown = shutdown;

    loop {
        tokio::select! {
            result = reader.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        debug!("{}: connection closed by peer", name);
                        break;
                    }
                    Ok(n) => {
                        let frames = decoder.feed(&buf[..n]);
                        for frame in frames {
                            stats.bytes_received.fetch_add(frame.len() as u64, Ordering::Relaxed);
                            match Packet::from_bytes(&frame) {
                                Ok(packet) => {
                                    stats.packets_received.fetch_add(1, Ordering::Relaxed);
                                    if packet_tx.send(packet).await.is_err() {
                                        debug!("{}: packet channel closed", name);
                                        return;
                                    }
                                }
                                Err(e) => {
                                    debug!("{}: packet decode error: {}", name, e);
                                    stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("{}: read error: {}", name, e);
                        break;
                    }
                }
            }
            _ = shutdown.recv() => {
                debug!("{}: shutdown signal received", name);
                break;
            }
        }
    }
}

/// Atomic stats counters (avoids needing async mutex for stats).
#[derive(Debug, Default)]
struct Stats {
    packets_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
    packets_dropped: AtomicU64,
}

impl Stats {
    fn snapshot(&self) -> InterfaceStats {
        InterfaceStats {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            packets_dropped: self.packets_dropped.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// TcpServerInterface
// ============================================================================

/// A Reticulum-compatible TCP server interface.
///
/// Listens on a port, accepts multiple client connections, and routes
/// packets between them using HDLC framing. Implements the `Interface`
/// trait for use with `MeshNode`.
pub struct TcpServerInterface {
    config: InterfaceConfig,
    /// Broadcast channel for outgoing HDLC-framed bytes → all clients.
    outbound_tx: broadcast::Sender<Vec<u8>>,
    /// Inbound decoded packets from any connected client.
    inbound_rx: Mutex<mpsc::Receiver<Packet>>,
    /// Whether the server is online.
    online: AtomicBool,
    /// Stats.
    stats: Arc<Stats>,
    /// Shutdown signal.
    shutdown_tx: broadcast::Sender<()>,
    /// Background task handle.
    _accept_task: JoinHandle<()>,
}

impl TcpServerInterface {
    /// Bind a TCP server on the given address.
    ///
    /// Starts accepting connections immediately.
    pub async fn bind(addr: &str) -> MeshResult<Self> {
        let bind_addr: SocketAddr = addr
            .parse()
            .map_err(|e| MeshError::InterfaceError(format!("invalid address: {}", e)))?;

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| MeshError::InterfaceError(format!("TCP bind failed: {}", e)))?;

        let local_addr = listener
            .local_addr()
            .map_err(|e| MeshError::InterfaceError(format!("failed to get local addr: {}", e)))?;

        let config = InterfaceConfig::new(
            format!("tcp-server:{}", local_addr.port()),
            InterfaceType::TcpTunnel,
        );

        let (outbound_tx, _) = broadcast::channel::<Vec<u8>>(256);
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        let online = AtomicBool::new(true);
        let stats = Arc::new(Stats::default());

        // Clone what the accept loop needs
        let accept_outbound = outbound_tx.clone();
        let accept_inbound = inbound_tx.clone();
        let accept_shutdown = shutdown_tx.clone();
        let accept_stats = stats.clone();
        let accept_name = config.name.clone();

        let connections_counter = Arc::new(AtomicU64::new(0));

        let accept_task = tokio::spawn(async move {
            info!("{}: listening on {}", accept_name, local_addr);

            loop {
                let mut shutdown_rx = accept_shutdown.subscribe();

                tokio::select! {
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                // Set TCP options
                                if let Err(e) = stream.set_nodelay(true) {
                                    warn!("{}: failed to set TCP_NODELAY: {}", accept_name, e);
                                }

                                let conn_id = connections_counter.fetch_add(1, Ordering::Relaxed);
                                let client_name = format!("{}:client-{}", accept_name, conn_id);
                                info!("{}: accepted connection from {}", client_name, peer_addr);

                                // Split the stream
                                let (reader, mut writer) = tokio::io::split(stream);

                                // Spawn read task
                                let read_tx = accept_inbound.clone();
                                let read_stats = accept_stats.clone();
                                let read_name = client_name.clone();
                                let read_shutdown = accept_shutdown.subscribe();
                                tokio::spawn(async move {
                                    tcp_read_loop(reader, read_tx, read_stats, read_name, read_shutdown).await;
                                });

                                // Spawn write task (subscribes to broadcast channel)
                                let mut write_rx = accept_outbound.subscribe();
                                let write_name = client_name.clone();
                                let mut write_shutdown = accept_shutdown.subscribe();
                                tokio::spawn(async move {
                                    loop {
                                        tokio::select! {
                                            result = write_rx.recv() => {
                                                match result {
                                                    Ok(frame_bytes) => {
                                                        if writer.write_all(&frame_bytes).await.is_err() {
                                                            debug!("{}: write failed, disconnecting", write_name);
                                                            break;
                                                        }
                                                        if writer.flush().await.is_err() {
                                                            break;
                                                        }
                                                    }
                                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                                        warn!("{}: lagged {} frames", write_name, n);
                                                    }
                                                    Err(broadcast::error::RecvError::Closed) => {
                                                        break;
                                                    }
                                                }
                                            }
                                            _ = write_shutdown.recv() => {
                                                break;
                                            }
                                        }
                                    }
                                    debug!("{}: write task ended", write_name);
                                });
                            }
                            Err(e) => {
                                error!("{}: accept error: {}", accept_name, e);
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("{}: shutting down accept loop", accept_name);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            config,
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            online,
            stats,
            shutdown_tx,
            _accept_task: accept_task,
        })
    }

    /// Get the number of active connections (approximate).
    pub fn connection_count(&self) -> u64 {
        // The broadcast subscriber count gives us active writers
        self.outbound_tx.receiver_count() as u64
    }

    /// Shut down the server.
    pub fn shutdown(&self) {
        self.online.store(false, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(());
    }
}

impl std::fmt::Debug for TcpServerInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpServerInterface")
            .field("name", &self.config.name)
            .field("online", &self.is_online())
            .field("connections", &self.connection_count())
            .finish()
    }
}

#[async_trait]
impl Interface for TcpServerInterface {
    fn config(&self) -> &InterfaceConfig {
        &self.config
    }

    async fn send(&self, packet: &Packet) -> MeshResult<()> {
        let wire_bytes = packet.to_bytes();
        let frame = hdlc_frame(&wire_bytes);

        self.stats
            .bytes_sent
            .fetch_add(wire_bytes.len() as u64, Ordering::Relaxed);
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);

        // Broadcast to all connected clients
        match self.outbound_tx.send(frame) {
            Ok(_) => Ok(()),
            Err(_) => {
                // No subscribers (no clients connected) — not an error, just no-op
                debug!(
                    "{}: no clients connected, packet not sent",
                    self.config.name
                );
                Ok(())
            }
        }
    }

    async fn recv(&self) -> MeshResult<Option<Packet>> {
        let mut rx = self.inbound_rx.lock().await;
        match rx.try_recv() {
            Ok(packet) => Ok(Some(packet)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(None),
        }
    }

    fn is_online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    fn stats(&self) -> InterfaceStats {
        self.stats.snapshot()
    }
}

// ============================================================================
// TcpClientInterface
// ============================================================================

/// A Reticulum-compatible TCP client interface.
///
/// Connects to a TCP server and exchanges HDLC-framed packets.
/// Auto-reconnects on disconnect with exponential backoff.
pub struct TcpClientInterface {
    config: InterfaceConfig,
    /// Channel for outgoing HDLC-framed bytes → server.
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Inbound decoded packets from the server.
    inbound_rx: Mutex<mpsc::Receiver<Packet>>,
    /// Whether we're connected.
    online: Arc<AtomicBool>,
    /// Stats.
    stats: Arc<Stats>,
    /// Shutdown signal.
    shutdown_tx: broadcast::Sender<()>,
    /// Background task handle.
    _connection_task: JoinHandle<()>,
}

impl TcpClientInterface {
    /// Connect to a remote TCP server.
    ///
    /// Spawns a background task that manages the connection lifecycle,
    /// including automatic reconnection with exponential backoff.
    pub async fn connect(addr: &str) -> MeshResult<Self> {
        let remote_addr: SocketAddr = addr
            .parse()
            .map_err(|e| MeshError::InterfaceError(format!("invalid address: {}", e)))?;

        let config = InterfaceConfig::new(
            format!("tcp-client:{}", remote_addr),
            InterfaceType::TcpTunnel,
        );

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);
        let (shutdown_tx, _) = broadcast::channel(1);

        let online = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());

        let conn_online = online.clone();
        let conn_stats = stats.clone();
        let conn_shutdown = shutdown_tx.clone();
        let conn_name = config.name.clone();

        let connection_task = tokio::spawn(async move {
            Self::connection_loop(
                remote_addr,
                outbound_rx,
                inbound_tx,
                conn_online,
                conn_stats,
                conn_shutdown,
                conn_name,
            )
            .await;
        });

        Ok(Self {
            config,
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            online,
            stats,
            shutdown_tx,
            _connection_task: connection_task,
        })
    }

    /// The connection manager loop — connects, runs read/write, reconnects on failure.
    async fn connection_loop(
        remote_addr: SocketAddr,
        mut outbound_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        inbound_tx: mpsc::Sender<Packet>,
        online: Arc<AtomicBool>,
        stats: Arc<Stats>,
        shutdown: broadcast::Sender<()>,
        name: String,
    ) {
        let mut backoff_ms: u64 = 100;
        let max_backoff_ms: u64 = 30_000;

        loop {
            info!("{}: connecting to {}...", name, remote_addr);

            match TcpStream::connect(remote_addr).await {
                Ok(stream) => {
                    // Set TCP options
                    if let Err(e) = stream.set_nodelay(true) {
                        warn!("{}: failed to set TCP_NODELAY: {}", name, e);
                    }

                    info!("{}: connected to {}", name, remote_addr);
                    online.store(true, Ordering::Relaxed);
                    backoff_ms = 100; // Reset backoff on successful connect

                    let (reader, mut writer) = tokio::io::split(stream);

                    // Spawn read task
                    let read_tx = inbound_tx.clone();
                    let read_stats = stats.clone();
                    let read_name = name.clone();
                    let read_shutdown = shutdown.subscribe();
                    let read_handle = tokio::spawn(async move {
                        tcp_read_loop(reader, read_tx, read_stats, read_name, read_shutdown).await;
                    });

                    // Write loop — runs inline, breaks on error or disconnect
                    let mut write_shutdown = shutdown.subscribe();
                    loop {
                        tokio::select! {
                            frame = outbound_rx.recv() => {
                                match frame {
                                    Some(frame_bytes) => {
                                        if writer.write_all(&frame_bytes).await.is_err() {
                                            debug!("{}: write failed", name);
                                            break;
                                        }
                                        if writer.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    None => {
                                        // Channel closed — shutdown
                                        debug!("{}: outbound channel closed", name);
                                        online.store(false, Ordering::Relaxed);
                                        return;
                                    }
                                }
                            }
                            _ = write_shutdown.recv() => {
                                debug!("{}: shutdown during write loop", name);
                                online.store(false, Ordering::Relaxed);
                                return;
                            }
                        }
                    }

                    // If we get here, connection was lost
                    online.store(false, Ordering::Relaxed);
                    read_handle.abort();
                    warn!("{}: disconnected from {}", name, remote_addr);
                }
                Err(e) => {
                    debug!("{}: connect failed: {}", name, e);
                }
            }

            // Exponential backoff before reconnect
            info!("{}: reconnecting in {}ms...", name, backoff_ms);

            let mut reconnect_shutdown = shutdown.subscribe();
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)) => {}
                _ = reconnect_shutdown.recv() => {
                    info!("{}: shutdown during reconnect backoff", name);
                    online.store(false, Ordering::Relaxed);
                    return;
                }
            }

            backoff_ms = (backoff_ms * 2).min(max_backoff_ms);
        }
    }

    /// Shut down the client.
    pub fn shutdown(&self) {
        self.online.store(false, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(());
    }
}

impl std::fmt::Debug for TcpClientInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpClientInterface")
            .field("name", &self.config.name)
            .field("online", &self.is_online())
            .finish()
    }
}

#[async_trait]
impl Interface for TcpClientInterface {
    fn config(&self) -> &InterfaceConfig {
        &self.config
    }

    async fn send(&self, packet: &Packet) -> MeshResult<()> {
        let wire_bytes = packet.to_bytes();
        let frame = hdlc_frame(&wire_bytes);

        self.stats
            .bytes_sent
            .fetch_add(wire_bytes.len() as u64, Ordering::Relaxed);
        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);

        self.outbound_tx
            .send(frame)
            .map_err(|_| MeshError::InterfaceError("TCP client: outbound channel closed".into()))?;

        Ok(())
    }

    async fn recv(&self) -> MeshResult<Option<Packet>> {
        let mut rx = self.inbound_rx.lock().await;
        match rx.try_recv() {
            Ok(packet) => Ok(Some(packet)),
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => Ok(None),
        }
    }

    fn is_online(&self) -> bool {
        self.online.load(Ordering::Relaxed)
    }

    fn stats(&self) -> InterfaceStats {
        self.stats.snapshot()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationHash;
    use crate::identity::MeshIdentity;
    use crate::packet::PacketContext;

    // --- HDLC Codec Tests ---

    #[test]
    fn test_hdlc_escape_no_special_bytes() {
        let data = b"hello world";
        let escaped = hdlc_escape(data);
        assert_eq!(escaped, data);
    }

    #[test]
    fn test_hdlc_escape_flag_byte() {
        let data = vec![0x01, HDLC_FLAG, 0x02];
        let escaped = hdlc_escape(&data);
        assert_eq!(
            escaped,
            vec![0x01, HDLC_ESC, HDLC_FLAG ^ HDLC_ESC_MASK, 0x02]
        );
    }

    #[test]
    fn test_hdlc_escape_esc_byte() {
        let data = vec![0x01, HDLC_ESC, 0x02];
        let escaped = hdlc_escape(&data);
        assert_eq!(
            escaped,
            vec![0x01, HDLC_ESC, HDLC_ESC ^ HDLC_ESC_MASK, 0x02]
        );
    }

    #[test]
    fn test_hdlc_escape_unescape_roundtrip() {
        // Test with all byte values
        let data: Vec<u8> = (0..=255).collect();
        let escaped = hdlc_escape(&data);
        let unescaped = hdlc_unescape(&escaped).unwrap();
        assert_eq!(unescaped, data);
    }

    #[test]
    fn test_hdlc_escape_all_flags() {
        let data = vec![HDLC_FLAG; 10];
        let escaped = hdlc_escape(&data);
        assert_eq!(escaped.len(), 20); // Each FLAG becomes 2 bytes
        let unescaped = hdlc_unescape(&escaped).unwrap();
        assert_eq!(unescaped, data);
    }

    #[test]
    fn test_hdlc_escape_empty() {
        let escaped = hdlc_escape(&[]);
        assert!(escaped.is_empty());
        let unescaped = hdlc_unescape(&[]).unwrap();
        assert!(unescaped.is_empty());
    }

    #[test]
    fn test_hdlc_unescape_trailing_esc_error() {
        let bad = vec![0x01, HDLC_ESC]; // ESC at end with no following byte
        let result = hdlc_unescape(&bad);
        assert!(result.is_err());
    }

    #[test]
    fn test_hdlc_frame_wraps_with_flags() {
        let data = b"test";
        let frame = hdlc_frame(data);
        assert_eq!(frame[0], HDLC_FLAG);
        assert_eq!(*frame.last().unwrap(), HDLC_FLAG);
        assert_eq!(frame.len(), data.len() + 2); // No special bytes to escape
    }

    // --- HDLC Decoder Tests ---

    #[test]
    fn test_decoder_single_frame() {
        let mut decoder = HdlcDecoder::new();
        let frame = hdlc_frame(b"hello");
        let packets = decoder.feed(&frame);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"hello");
    }

    #[test]
    fn test_decoder_multiple_frames_in_one_read() {
        let mut decoder = HdlcDecoder::new();
        let mut data = Vec::new();
        data.extend_from_slice(&hdlc_frame(b"first"));
        data.extend_from_slice(&hdlc_frame(b"second"));
        data.extend_from_slice(&hdlc_frame(b"third"));

        let packets = decoder.feed(&data);
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0], b"first");
        assert_eq!(packets[1], b"second");
        assert_eq!(packets[2], b"third");
    }

    #[test]
    fn test_decoder_partial_frame_reassembly() {
        let mut decoder = HdlcDecoder::new();
        let frame = hdlc_frame(b"split-me");

        // Feed first half
        let mid = frame.len() / 2;
        let packets = decoder.feed(&frame[..mid]);
        assert_eq!(packets.len(), 0); // Not complete yet

        // Feed second half
        let packets = decoder.feed(&frame[mid..]);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"split-me");
    }

    #[test]
    fn test_decoder_data_before_first_flag_discarded() {
        let mut decoder = HdlcDecoder::new();
        let mut data = Vec::new();
        data.extend_from_slice(b"garbage");
        data.extend_from_slice(&hdlc_frame(b"valid"));

        let packets = decoder.feed(&data);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"valid");
    }

    #[test]
    fn test_decoder_consecutive_flags() {
        let mut decoder = HdlcDecoder::new();
        // Multiple FLAGS in a row (between frames) should be handled
        let mut data = Vec::new();
        data.push(HDLC_FLAG);
        data.push(HDLC_FLAG);
        data.push(HDLC_FLAG);
        data.extend_from_slice(b"content");
        data.push(HDLC_FLAG);

        let packets = decoder.feed(&data);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"content");
    }

    #[test]
    fn test_decoder_frame_with_escaped_bytes() {
        let mut decoder = HdlcDecoder::new();
        let original = vec![0x01, HDLC_FLAG, 0x02, HDLC_ESC, 0x03];
        let frame = hdlc_frame(&original);
        let packets = decoder.feed(&frame);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], original);
    }

    #[test]
    fn test_decoder_reset() {
        let mut decoder = HdlcDecoder::new();
        // Start a frame but don't finish it
        let partial = vec![HDLC_FLAG, 0x01, 0x02];
        decoder.feed(&partial);
        decoder.reset();
        // After reset, the partial data should be gone
        let packets = decoder.feed(&[HDLC_FLAG]);
        assert_eq!(packets.len(), 0);
    }

    // --- Helper to make test packets ---

    fn make_test_packet(data: &[u8]) -> Packet {
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());
        Packet::data(dest, data.to_vec(), PacketContext::None).unwrap()
    }

    // --- TCP Integration Tests ---

    #[tokio::test]
    async fn test_server_bind() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        assert!(server.is_online());
        server.shutdown();
    }

    #[tokio::test]
    async fn test_server_client_connect() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client = TcpClientInterface::connect(&addr).await.unwrap();

        // Give the connection time to establish
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(client.is_online());

        client.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_client_to_server_packet() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client = TcpClientInterface::connect(&addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client sends a packet
        let pkt = make_test_packet(b"hello from client");
        client.send(&pkt).await.unwrap();

        // Give time for the packet to arrive
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Server should receive it
        let received = server.recv().await.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().data, b"hello from client");

        client.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_server_to_client_packet() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client = TcpClientInterface::connect(&addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Server sends a packet
        let pkt = make_test_packet(b"hello from server");
        server.send(&pkt).await.unwrap();

        // Give time for the packet to arrive
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client should receive it
        let received = client.recv().await.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().data, b"hello from server");

        client.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_bidirectional_exchange() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client = TcpClientInterface::connect(&addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Client → Server
        let pkt1 = make_test_packet(b"ping");
        client.send(&pkt1).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let received = server.recv().await.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().data, b"ping");

        // Server → Client
        let pkt2 = make_test_packet(b"pong");
        server.send(&pkt2).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let received = client.recv().await.unwrap();
        assert!(received.is_some());
        assert_eq!(received.unwrap().data, b"pong");

        client.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_multiple_clients() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client1 = TcpClientInterface::connect(&addr).await.unwrap();
        let client2 = TcpClientInterface::connect(&addr).await.unwrap();
        let client3 = TcpClientInterface::connect(&addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Server broadcasts to all clients
        let pkt = make_test_packet(b"broadcast");
        server.send(&pkt).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // All three clients should receive the packet
        let r1 = client1.recv().await.unwrap();
        let r2 = client2.recv().await.unwrap();
        let r3 = client3.recv().await.unwrap();
        assert!(r1.is_some());
        assert!(r2.is_some());
        assert!(r3.is_some());
        assert_eq!(r1.unwrap().data, b"broadcast");
        assert_eq!(r2.unwrap().data, b"broadcast");
        assert_eq!(r3.unwrap().data, b"broadcast");

        client1.shutdown();
        client2.shutdown();
        client3.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client = TcpClientInterface::connect(&addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send 5 packets
        for i in 0..5 {
            let pkt = make_test_packet(format!("pkt-{}", i).as_bytes());
            client.send(&pkt).await.unwrap();
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let client_stats = client.stats();
        assert_eq!(client_stats.packets_sent, 5);
        assert!(client_stats.bytes_sent > 0);

        let server_stats = server.stats();
        assert_eq!(server_stats.packets_received, 5);
        assert!(server_stats.bytes_received > 0);

        client.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_wire_format_reticulum_compatible() {
        // Verify that a Reticulum-format packet survives HDLC encode → TCP → decode
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());

        // Build a packet with data that contains HDLC special bytes
        let tricky_data = vec![0x7E, 0x7D, 0x00, 0xFF, 0x7E, 0x7D, 0x5E, 0x5D];
        let pkt = Packet::data(dest, tricky_data.clone(), PacketContext::Receipt).unwrap();

        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let port = server.config.name.split(':').last().unwrap();
        let addr = format!("127.0.0.1:{}", port);

        let client = TcpClientInterface::connect(&addr).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Send the packet with tricky bytes through TCP + HDLC
        client.send(&pkt).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let received = server.recv().await.unwrap();
        assert!(received.is_some());
        let received = received.unwrap();

        // Verify the data survived the HDLC roundtrip intact
        assert_eq!(received.data, tricky_data);
        assert_eq!(received.context as u8, PacketContext::Receipt as u8);

        client.shutdown();
        server.shutdown();
    }

    #[tokio::test]
    async fn test_recv_empty_when_no_packets() {
        let server = TcpServerInterface::bind("127.0.0.1:0").await.unwrap();
        let result = server.recv().await.unwrap();
        assert!(result.is_none());
        server.shutdown();
    }
}
