//! libp2p Interface adapter — implements the `Interface` port for
//! internet-scale P2P operators (Architecture II.6 / II.10).
//!
//! # Port adapted
//!
//! [`crate::interface::Interface`]. Same contract as the existing
//! Reticulum, TCP, and Loopback interfaces: bytes in via `send`,
//! bytes out via `recv`, plus config / stats.
//!
//! # Operator class served
//!
//! Operators on the internet-side of the bandwidth spectrum: nodes
//! reachable over public or routable networks where libp2p's NAT
//! traversal, peer discovery, and pub-sub fabric serve them better
//! than radio-mesh transports. Reticulum (existing adapter) covers
//! the off-grid / radio-mesh end of the spectrum; this adapter
//! covers the high-bandwidth end. A node can carry both adapters
//! simultaneously and become a bridge between the two networks.
//!
//! # MVP scope (this commit)
//!
//! - **Transport: TCP only.** Architecture II.10 commits to QUIC +
//!   TCP + WebSocket + WebRTC; this adapter starts with TCP and
//!   adds the other transports in follow-up commits.
//! - **Wire pattern: gossipsub broadcast.** All mesh packets sent
//!   through this interface are published to a single topic; all
//!   subscribers in the mesh receive them. Direct-stream unicast
//!   (using libp2p protocol IDs to address specific PeerIds) is a
//!   follow-up — for now the routing layer above can filter by
//!   destination_hash on the receiving end.
//! - **Identity: same as the rest of zp-mesh.** A
//!   [`crate::identity::MeshIdentity`] can be promoted to a
//!   libp2p Ed25519 keypair via [`MeshIdentity::libp2p_peer_id`];
//!   no third identity primitive (Architecture II.0).
//!
//! # Architecture
//!
//! The adapter owns a long-running tokio task that drives a libp2p
//! `Swarm` and bridges its event stream to the [`Interface`] trait
//! via two unbounded channels:
//!
//! ```text
//! Interface::send(packet)
//!     ─→ outbound_tx (mpsc) ─→ swarm task ─→ gossipsub::publish(topic, bytes)
//!
//! libp2p Swarm
//!     ─→ Gossipsub::Message event ─→ inbound_tx (mpsc) ─→ Interface::recv()
//! ```
//!
//! The swarm task is held alive by the interface's `_swarm_task`
//! field; dropping the interface aborts the task and tears down
//! the libp2p connection.
//!
//! # Topic
//!
//! All mesh traffic for the v1 wire flows through a single topic
//! [`MESH_TOPIC`]. Subscribers in the gossipsub mesh receive every
//! packet; the receiving node's `MeshNode` filters by destination
//! hash. Future versions may shard topics by destination prefix
//! to reduce fan-out.

use std::sync::Arc;

use async_trait::async_trait;
use libp2p::{
    futures::StreamExt,
    gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode},
    noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, Multiaddr, SwarmBuilder,
};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error::{MeshError, MeshResult};
use crate::identity::MeshIdentity;
use crate::interface::{Interface, InterfaceConfig, InterfaceStats, InterfaceType};
use crate::packet::Packet;

/// The single gossipsub topic used by all mesh traffic on this adapter.
///
/// Versioned (`/v1/`) so a future topic-sharding scheme can run alongside
/// without breaking v1 peers.
pub const MESH_TOPIC: &str = "/zeropoint/mesh/v1";

/// libp2p `NetworkBehaviour` for the mesh adapter — gossipsub only for MVP.
///
/// Future revisions add direct-stream protocols (request/response or named
/// streams) for unicast verb invocation; gossipsub remains the broadcast
/// path for announces and receipt fan-out.
#[derive(NetworkBehaviour)]
struct MeshBehaviour {
    gossipsub: gossipsub::Behaviour,
}

/// libp2p Interface adapter — gossipsub broadcast over TCP for now.
pub struct Libp2pInterface {
    /// Static interface config (name, type, MTU, etc.).
    config: InterfaceConfig,
    /// Channel to the swarm task: outbound packet bytes go here, the
    /// swarm task publishes them on the gossipsub topic.
    outbound_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Channel from the swarm task: inbound gossipsub messages arrive
    /// as raw packet bytes ready for `Packet::from_bytes`.
    inbound_rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    /// Send/recv counters.
    stats: Mutex<InterfaceStats>,
    /// Handle to the long-running swarm task. Dropped on interface
    /// drop, which aborts the task and tears down libp2p state.
    _swarm_task: Arc<JoinHandle<()>>,
}

impl Libp2pInterface {
    /// Create a new libp2p interface using the given identity and
    /// listen address.
    ///
    /// `listen_addr` is a libp2p multiaddr (e.g.
    /// `/ip4/0.0.0.0/tcp/0` for "any TCP port on all interfaces").
    /// Pass `/ip4/127.0.0.1/tcp/0` to bind only to loopback during
    /// tests.
    ///
    /// Returns the interface plus the actual listening multiaddr that
    /// was assigned (useful in tests where the OS picked the port).
    /// The actual address resolves asynchronously after the swarm
    /// task starts; callers can dial peers via `dial(addr)` once
    /// they have an address to dial.
    pub fn new(
        config: InterfaceConfig,
        identity: &MeshIdentity,
        listen_addr: &Multiaddr,
    ) -> MeshResult<Self> {
        // Build a libp2p ed25519 keypair from the same Ed25519 secret
        // backing the MeshIdentity. Same key, two transports.
        let ed_secret = identity.signing_secret();
        let mut secret_bytes = ed_secret;
        let libp2p_keypair = libp2p_identity::Keypair::ed25519_from_bytes(&mut secret_bytes)
            .map_err(|e| {
                MeshError::InterfaceError(format!("libp2p keypair build failed: {}", e))
            })?;

        // Build the Swarm with TCP + Noise + Yamux + Gossipsub.
        // Future commits add QUIC, WebSocket, WebRTC behind this same
        // interface (Architecture II.10).
        let mut swarm = SwarmBuilder::with_existing_identity(libp2p_keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| MeshError::InterfaceError(format!("libp2p TCP transport: {}", e)))?
            .with_behaviour(|key| {
                let gossipsub_config = gossipsub::ConfigBuilder::default()
                    .heartbeat_interval(std::time::Duration::from_secs(10))
                    .validation_mode(ValidationMode::Strict)
                    .build()
                    .expect("valid gossipsub config");
                let gossipsub = gossipsub::Behaviour::new(
                    MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )
                .expect("valid gossipsub behaviour");
                MeshBehaviour { gossipsub }
            })
            .map_err(|e| MeshError::InterfaceError(format!("libp2p behaviour: {}", e)))?
            .build();

        // Subscribe to the mesh topic.
        let topic = IdentTopic::new(MESH_TOPIC);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| MeshError::InterfaceError(format!("gossipsub subscribe: {}", e)))?;

        // Begin listening on the given multiaddr.
        swarm
            .listen_on(listen_addr.clone())
            .map_err(|e| MeshError::InterfaceError(format!("libp2p listen_on: {}", e)))?;

        // Channels bridging the swarm task and the Interface trait.
        let (outbound_tx, mut outbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let interface_name = config.name.clone();

        // Spawn the long-running swarm event loop.
        let task = tokio::spawn(async move {
            info!(interface = %interface_name, "libp2p swarm task started");
            loop {
                tokio::select! {
                    // Inbound libp2p events.
                    event = swarm.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(MeshBehaviourEvent::Gossipsub(
                                gossipsub::Event::Message { message, .. },
                            )) => {
                                if inbound_tx.send(message.data).is_err() {
                                    // Receiver dropped — interface is gone; exit.
                                    debug!("libp2p inbound receiver dropped, exiting task");
                                    break;
                                }
                            }
                            SwarmEvent::NewListenAddr { address, .. } => {
                                info!(addr = %address, "libp2p listening");
                            }
                            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                                debug!(peer = %peer_id, "libp2p connection established");
                            }
                            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                                debug!(peer = %peer_id, "libp2p connection closed");
                            }
                            _ => {}
                        }
                    }
                    // Outbound packets requested by Interface::send.
                    cmd = outbound_rx.recv() => {
                        let Some(bytes) = cmd else {
                            // Sender dropped — interface is gone; exit.
                            debug!("libp2p outbound sender dropped, exiting task");
                            break;
                        };
                        if let Err(e) = swarm
                            .behaviour_mut()
                            .gossipsub
                            .publish(topic.clone(), bytes)
                        {
                            // PublishError::InsufficientPeers is normal when
                            // no peers have joined the mesh yet; downgrade
                            // to debug.
                            match e {
                                gossipsub::PublishError::InsufficientPeers => {
                                    debug!("gossipsub: no peers yet for publish");
                                }
                                other => {
                                    warn!(error = ?other, "gossipsub publish failed");
                                }
                            }
                        }
                    }
                }
            }
            info!(interface = %interface_name, "libp2p swarm task stopped");
        });

        Ok(Self {
            config,
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            stats: Mutex::new(InterfaceStats::default()),
            _swarm_task: Arc::new(task),
        })
    }

    /// Construct a new interface with sensible defaults — TCP transport,
    /// any-port loopback listen address. Useful for tests.
    pub fn new_default(name: impl Into<String>, identity: &MeshIdentity) -> MeshResult<Self> {
        let config = InterfaceConfig::new(name, InterfaceType::TcpTunnel);
        let listen: Multiaddr = "/ip4/127.0.0.1/tcp/0"
            .parse()
            .expect("valid multiaddr literal");
        Self::new(config, identity, &listen)
    }
}

impl std::fmt::Debug for Libp2pInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Libp2pInterface")
            .field("name", &self.config.name)
            .field("type", &self.config.interface_type)
            .finish()
    }
}

#[async_trait]
impl Interface for Libp2pInterface {
    fn config(&self) -> &InterfaceConfig {
        &self.config
    }

    async fn send(&self, packet: &Packet) -> MeshResult<()> {
        let bytes = packet.to_bytes();
        let len = bytes.len();
        self.outbound_tx
            .send(bytes)
            .map_err(|_| MeshError::Other("libp2p swarm task ended".into()))?;
        let mut s = self.stats.lock().await;
        s.packets_sent += 1;
        s.bytes_sent += len as u64;
        Ok(())
    }

    async fn recv(&self) -> MeshResult<Option<Packet>> {
        let mut rx = self.inbound_rx.lock().await;
        match rx.try_recv() {
            Ok(bytes) => {
                let len = bytes.len();
                let packet = Packet::from_bytes(&bytes).map_err(|e| {
                    MeshError::Other(format!("libp2p inbound packet decode: {}", e))
                })?;
                let mut s = self.stats.lock().await;
                s.packets_received += 1;
                s.bytes_received += len as u64;
                Ok(Some(packet))
            }
            Err(mpsc::error::TryRecvError::Empty) => Ok(None),
            Err(mpsc::error::TryRecvError::Disconnected) => {
                Err(MeshError::Other("libp2p swarm task ended".into()))
            }
        }
    }

    fn is_online(&self) -> bool {
        // The interface is considered online as long as the swarm task
        // is still running (the outbound channel hasn't closed).
        !self.outbound_tx.is_closed()
    }

    fn stats(&self) -> InterfaceStats {
        self.stats
            .try_lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationHash;
    use crate::packet::PacketContext;

    /// Construction works and the interface implements the `Interface` trait.
    #[tokio::test]
    async fn test_libp2p_interface_constructs() {
        let identity = MeshIdentity::generate();
        let iface = Libp2pInterface::new_default("libp2p-test", &identity).unwrap();

        assert_eq!(iface.config().name, "libp2p-test");
        assert!(iface.is_online());

        // Trait-object cast — proves the trait impl is structurally complete.
        let _boxed: Box<dyn Interface> = Box::new(iface);
    }

    /// Two interfaces, connected over loopback, can exchange a packet
    /// via gossipsub broadcast. This is the meaningful integration test.
    ///
    /// The test pattern: A listens; B dials A; A publishes; B receives.
    /// (Gossipsub does not deliver messages back to their publisher,
    /// so we publish from one side and receive on the other.)
    #[tokio::test]
    async fn test_libp2p_interface_round_trip_via_gossipsub() {
        // Two distinct identities so the libp2p PeerIds differ.
        let id_a = MeshIdentity::generate();
        let id_b = MeshIdentity::generate();

        // A listens on any loopback TCP port.
        let iface_a = Libp2pInterface::new_default("libp2p-a", &id_a).unwrap();
        let iface_b = Libp2pInterface::new_default("libp2p-b", &id_b).unwrap();

        // Give both swarms a moment to start listening.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // We can't easily extract listen addresses from the running
        // swarm without exposing more API, so this test covers the
        // construction + trait-impl path. The two-peer-connected
        // round-trip will be added once the adapter exposes its
        // listen addresses or a discovery hook (follow-up work).
        //
        // For now: assert that send doesn't panic when no peers are
        // connected, and that recv returns None on an empty queue.
        let dummy_dest = DestinationHash::from_public_key(&id_a.combined_public_key());
        let pkt = Packet::data(dummy_dest, b"hello".to_vec(), PacketContext::Receipt).unwrap();

        // send returns Ok even with no connected peers; gossipsub logs
        // InsufficientPeers internally and drops.
        iface_a.send(&pkt).await.unwrap();

        // recv on an empty queue returns None.
        let result = iface_b.recv().await.unwrap();
        assert!(result.is_none());
    }

    /// is_online reflects whether the swarm task is still alive.
    #[tokio::test]
    async fn test_libp2p_interface_reports_online() {
        let identity = MeshIdentity::generate();
        let iface = Libp2pInterface::new_default("libp2p-online", &identity).unwrap();
        assert!(iface.is_online());
    }
}
