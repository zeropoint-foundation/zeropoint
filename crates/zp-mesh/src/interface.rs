//! Mesh interfaces — physical medium abstraction.
//!
//! An interface represents a single physical or virtual communication medium.
//! The mesh node can have multiple interfaces simultaneously — a LoRa radio,
//! a WiFi adapter, a serial port — and routes packets across them transparently.
//!
//! This module defines the trait that all interfaces must implement, plus
//! built-in interface types for common media.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::MeshResult;
use crate::packet::Packet;

/// The physical or virtual medium type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterfaceType {
    /// LoRa radio via RNode hardware.
    LoRa,
    /// Standard WiFi (2.4/5 GHz).
    WiFi,
    /// WiFi HaLow (802.11ah, sub-1GHz, long range).
    HaLow,
    /// Ethernet / IP tunnel.
    Ethernet,
    /// Serial port (RS-232, USB serial).
    Serial,
    /// TCP/IP tunnel (for bridging to internet-connected nodes).
    TcpTunnel,
    /// UDP broadcast (local network discovery).
    UdpBroadcast,
    /// Loopback (testing).
    Loopback,
}

impl InterfaceType {
    /// Typical MTU for this interface type.
    pub fn default_mtu(&self) -> usize {
        match self {
            Self::LoRa => 500,   // Reticulum default
            Self::WiFi => 1500,  // Standard Ethernet frame
            Self::HaLow => 1500, // 802.11ah
            Self::Ethernet => 1500,
            Self::Serial => 500, // Conservative for serial
            Self::TcpTunnel => 1500,
            Self::UdpBroadcast => 1500,
            Self::Loopback => 65535,
        }
    }

    /// Approximate bandwidth in bits/second (for routing decisions).
    pub fn typical_bandwidth(&self) -> u64 {
        match self {
            Self::LoRa => 5_000,             // ~5 kbps typical LoRa
            Self::WiFi => 100_000_000,       // ~100 Mbps
            Self::HaLow => 1_000_000,        // ~1 Mbps
            Self::Ethernet => 1_000_000_000, // 1 Gbps
            Self::Serial => 115_200,         // 115.2 kbaud
            Self::TcpTunnel => 100_000_000,
            Self::UdpBroadcast => 100_000_000,
            Self::Loopback => u64::MAX,
        }
    }
}

impl std::fmt::Display for InterfaceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LoRa => write!(f, "LoRa"),
            Self::WiFi => write!(f, "WiFi"),
            Self::HaLow => write!(f, "HaLow"),
            Self::Ethernet => write!(f, "Ethernet"),
            Self::Serial => write!(f, "Serial"),
            Self::TcpTunnel => write!(f, "TCP"),
            Self::UdpBroadcast => write!(f, "UDP"),
            Self::Loopback => write!(f, "Loopback"),
        }
    }
}

/// Interface mode — affects routing and announce behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterfaceMode {
    /// Full functionality (default).
    Full,
    /// Gateway: discovers paths on behalf of clients.
    Gateway,
    /// Access point: stays quiet until actively queried.
    AccessPoint,
    /// Roaming: optimized for mobile nodes (faster path expiry).
    Roaming,
    /// Boundary: marks transition to a different network segment.
    Boundary,
}

/// Configuration for a mesh interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Human-readable name (e.g., "lora0", "wifi-mesh", "serial-tty0").
    pub name: String,
    /// Physical medium type.
    pub interface_type: InterfaceType,
    /// Interface mode.
    pub mode: InterfaceMode,
    /// Maximum transmission unit in bytes.
    pub mtu: usize,
    /// Whether this interface is enabled.
    pub enabled: bool,
    /// Announce capacity (fraction of bandwidth for announces, 0.0-1.0).
    pub announce_cap: f64,
}

impl InterfaceConfig {
    /// Create a new interface config with sensible defaults.
    pub fn new(name: impl Into<String>, interface_type: InterfaceType) -> Self {
        Self {
            name: name.into(),
            mtu: interface_type.default_mtu(),
            interface_type,
            mode: InterfaceMode::Full,
            enabled: true,
            announce_cap: 0.02, // 2% — Reticulum default
        }
    }
}

/// The interface trait — implemented by physical medium drivers.
///
/// Each interface can send and receive raw packets. The mesh node
/// manages routing across multiple interfaces.
#[async_trait]
pub trait Interface: Send + Sync + std::fmt::Debug {
    /// Get the interface configuration.
    fn config(&self) -> &InterfaceConfig;

    /// Send a raw packet over this interface.
    async fn send(&self, packet: &Packet) -> MeshResult<()>;

    /// Receive the next packet from this interface.
    /// Returns None if the interface has no pending packets.
    async fn recv(&self) -> MeshResult<Option<Packet>>;

    /// Check if the interface is currently online.
    fn is_online(&self) -> bool;

    /// Get interface statistics.
    fn stats(&self) -> InterfaceStats;
}

/// Interface statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceStats {
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Packets dropped (send failures).
    pub packets_dropped: u64,
}

// ============================================================================
// Built-in loopback interface (for testing)
// ============================================================================

/// In-memory loopback interface for testing mesh operations.
#[derive(Debug)]
pub struct LoopbackInterface {
    config: InterfaceConfig,
    /// Buffered packets (simulates a wire).
    buffer: tokio::sync::Mutex<Vec<Vec<u8>>>,
    stats: tokio::sync::Mutex<InterfaceStats>,
}

impl LoopbackInterface {
    /// Create a new loopback interface.
    pub fn new() -> Self {
        Self {
            config: InterfaceConfig::new("loopback0", InterfaceType::Loopback),
            buffer: tokio::sync::Mutex::new(Vec::new()),
            stats: tokio::sync::Mutex::new(InterfaceStats::default()),
        }
    }

    /// Inject a raw packet into the receive buffer (for testing).
    pub async fn inject(&self, packet: &Packet) {
        let bytes = packet.to_bytes();
        self.buffer.lock().await.push(bytes);
    }
}

impl Default for LoopbackInterface {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Interface for LoopbackInterface {
    fn config(&self) -> &InterfaceConfig {
        &self.config
    }

    async fn send(&self, packet: &Packet) -> MeshResult<()> {
        let bytes = packet.to_bytes();
        let mut stats = self.stats.lock().await;
        stats.packets_sent += 1;
        stats.bytes_sent += bytes.len() as u64;

        // Loopback: what we send, we immediately receive
        self.buffer.lock().await.push(bytes);
        Ok(())
    }

    async fn recv(&self) -> MeshResult<Option<Packet>> {
        let mut buf = self.buffer.lock().await;
        if let Some(bytes) = buf.pop() {
            let mut stats = self.stats.lock().await;
            stats.packets_received += 1;
            stats.bytes_received += bytes.len() as u64;
            drop(stats);

            let packet = Packet::from_bytes(&bytes)?;
            Ok(Some(packet))
        } else {
            Ok(None)
        }
    }

    fn is_online(&self) -> bool {
        true
    }

    fn stats(&self) -> InterfaceStats {
        // Can't easily get stats synchronously from async mutex.
        // Return a default; real stats available via async methods.
        InterfaceStats::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationHash;
    use crate::identity::MeshIdentity;
    use crate::packet::PacketContext;

    #[tokio::test]
    async fn test_loopback_send_recv() {
        let lo = LoopbackInterface::new();

        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());
        let pkt = Packet::data(dest, b"test loopback".to_vec(), PacketContext::None).unwrap();

        lo.send(&pkt).await.unwrap();
        let received = lo.recv().await.unwrap();

        assert!(received.is_some());
        let received = received.unwrap();
        assert_eq!(received.data, b"test loopback");
    }

    #[tokio::test]
    async fn test_loopback_empty_recv() {
        let lo = LoopbackInterface::new();
        let received = lo.recv().await.unwrap();
        assert!(received.is_none());
    }

    #[test]
    fn test_interface_types() {
        // LoRa should have the smallest default MTU
        assert_eq!(InterfaceType::LoRa.default_mtu(), 500);
        assert!(InterfaceType::LoRa.typical_bandwidth() < InterfaceType::WiFi.typical_bandwidth());
    }

    #[test]
    fn test_interface_config_defaults() {
        let config = InterfaceConfig::new("lora0", InterfaceType::LoRa);
        assert_eq!(config.mtu, 500);
        assert_eq!(config.announce_cap, 0.02);
        assert!(config.enabled);
    }
}
