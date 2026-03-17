//! Mesh runtime — the event loop that drives live packet dispatch.
//!
//! The `MeshRuntime` provides a background task that continuously polls all
//! attached interfaces for inbound packets, deserializes them into
//! `MeshEnvelope`s, and dispatches to the appropriate handler on `MeshNode`.
//!
//! ## Design
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │  MeshRuntime                                          │
//! │                                                       │
//! │  loop {                                               │
//! │    for iface in node.interfaces() {                   │
//! │      if let Some(packet) = iface.recv() {             │
//! │        let envelope = MeshEnvelope::from_msgpack(..); │
//! │        match envelope.envelope_type {                 │
//! │          Receipt          → handle receipt            │
//! │          Delegation       → handle delegation         │
//! │          PolicyAdvert..   → handle policy sync        │
//! │          AuditChallenge   → handle audit              │
//! │          ReputationSum..  → handle reputation         │
//! │          ...                                          │
//! │        }                                              │
//! │      }                                                │
//! │    }                                                  │
//! │    yield / sleep                                      │
//! │  }                                                    │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Shutdown
//!
//! Graceful shutdown is signaled via a `tokio::sync::watch` channel.
//! Call `runtime.shutdown()` to stop the event loop, or drop the runtime.
//!
//! ## Callbacks
//!
//! The runtime dispatches most envelope types internally via `MeshNode` methods.
//! For envelope types that require pipeline-level processing (e.g., inbound
//! receipts that need reputation gating), the runtime sends them through an
//! `mpsc` channel that the pipeline can consume.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::envelope::{EnvelopeType, MeshEnvelope};
use crate::identity::PeerIdentity;
use crate::packet::PacketType;
use crate::transport::{AgentCapabilities, MeshNode};

/// An inbound envelope that the runtime dispatched but the consumer
/// may want to process further (e.g., inbound receipts for the pipeline).
#[derive(Debug, Clone)]
pub struct InboundEnvelope {
    /// The deserialized envelope.
    pub envelope: MeshEnvelope,
    /// The sender's destination hash (derived from envelope.sender).
    pub sender_hash: [u8; 16],
    /// Which interface received this packet.
    pub interface_name: String,
}

/// Statistics from the runtime event loop.
#[derive(Debug, Clone, Default)]
pub struct RuntimeStats {
    /// Total packets received across all interfaces.
    pub packets_received: u64,
    /// Total envelopes successfully deserialized.
    pub envelopes_dispatched: u64,
    /// Packets that failed to deserialize.
    pub deserialize_errors: u64,
    /// Announce packets seen (not envelope-dispatched).
    pub announces_seen: u64,
    /// Peers successfully discovered and registered.
    pub peers_discovered: u64,
    /// Non-data packets skipped.
    pub packets_skipped: u64,
}

/// Configuration for the mesh runtime.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// How long to sleep between poll cycles when no packets are available.
    /// Lower values = lower latency but higher CPU usage.
    pub poll_interval: Duration,
    /// Maximum number of packets to process per poll cycle.
    /// Prevents a flood of packets from starving other tasks.
    pub max_packets_per_cycle: usize,
    /// Channel capacity for inbound envelopes sent to the consumer.
    pub inbound_channel_capacity: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(50),
            max_packets_per_cycle: 100,
            inbound_channel_capacity: 256,
        }
    }
}

/// The mesh runtime — drives the MeshNode event loop.
///
/// Polls interfaces for inbound packets, dispatches envelope types
/// to the appropriate MeshNode handlers, and forwards certain
/// envelopes (e.g., inbound receipts) to a consumer channel.
pub struct MeshRuntime {
    /// Handle to the background task.
    task: Option<JoinHandle<()>>,
    /// Shutdown signal sender.
    shutdown_tx: watch::Sender<bool>,
    /// Receiver for inbound envelopes that need pipeline processing.
    inbound_rx: Option<mpsc::Receiver<InboundEnvelope>>,
    /// Runtime stats (shared with the background task).
    stats: Arc<tokio::sync::RwLock<RuntimeStats>>,
}

impl MeshRuntime {
    /// Start the runtime event loop for the given mesh node.
    ///
    /// Returns a `MeshRuntime` that owns the background task and
    /// provides a channel for consuming inbound envelopes.
    pub fn start(node: Arc<MeshNode>, config: RuntimeConfig) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (inbound_tx, inbound_rx) = mpsc::channel(config.inbound_channel_capacity);
        let stats = Arc::new(tokio::sync::RwLock::new(RuntimeStats::default()));

        let task_stats = stats.clone();
        let task = tokio::spawn(async move {
            run_event_loop(node, config, shutdown_rx, inbound_tx, task_stats).await;
        });

        info!("Mesh runtime started");

        Self {
            task: Some(task),
            shutdown_tx,
            inbound_rx: Some(inbound_rx),
            stats,
        }
    }

    /// Start with default configuration.
    pub fn start_default(node: Arc<MeshNode>) -> Self {
        Self::start(node, RuntimeConfig::default())
    }

    /// Take the inbound envelope receiver.
    ///
    /// The caller (typically the pipeline) uses this to receive envelopes
    /// that need further processing (receipts, guard requests, etc.).
    /// Can only be called once — subsequent calls return None.
    pub fn take_inbound_rx(&mut self) -> Option<mpsc::Receiver<InboundEnvelope>> {
        self.inbound_rx.take()
    }

    /// Signal the runtime to shut down gracefully.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        info!("Mesh runtime shutdown signaled");
    }

    /// Get a snapshot of the runtime statistics.
    pub async fn stats(&self) -> RuntimeStats {
        self.stats.read().await.clone()
    }

    /// Check if the runtime task is still running.
    pub fn is_running(&self) -> bool {
        self.task
            .as_ref()
            .map(|t| !t.is_finished())
            .unwrap_or(false)
    }

    /// Wait for the runtime task to complete (after shutdown).
    pub async fn join(mut self) {
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for MeshRuntime {
    fn drop(&mut self) {
        // Signal shutdown on drop
        let _ = self.shutdown_tx.send(true);
    }
}

/// The main event loop — runs in a background task.
async fn run_event_loop(
    node: Arc<MeshNode>,
    config: RuntimeConfig,
    mut shutdown_rx: watch::Receiver<bool>,
    inbound_tx: mpsc::Sender<InboundEnvelope>,
    stats: Arc<tokio::sync::RwLock<RuntimeStats>>,
) {
    info!("Mesh runtime event loop running");

    loop {
        // Check for shutdown
        if *shutdown_rx.borrow() {
            info!("Mesh runtime shutting down");
            break;
        }

        let mut had_packets = false;
        let mut cycle_count = 0;

        // Poll all interfaces
        let interfaces = node.interfaces_snapshot().await;
        for iface in &interfaces {
            if !iface.is_online() || !iface.config().enabled {
                continue;
            }

            // Drain packets from this interface up to the per-cycle limit
            loop {
                if cycle_count >= config.max_packets_per_cycle {
                    break;
                }

                match iface.recv().await {
                    Ok(Some(packet)) => {
                        had_packets = true;
                        cycle_count += 1;
                        {
                            let mut s = stats.write().await;
                            s.packets_received += 1;
                        }

                        let iface_name = iface.config().name.clone();

                        // Handle announce packets specially
                        if packet.header.packet_type == PacketType::Announce {
                            {
                                let mut s = stats.write().await;
                                s.announces_seen += 1;
                            }
                            handle_announce_packet(&node, &packet, &stats).await;
                            continue;
                        }

                        // Only process data packets
                        if packet.header.packet_type != PacketType::Data {
                            let mut s = stats.write().await;
                            s.packets_skipped += 1;
                            continue;
                        }

                        // Attempt to deserialize as a MeshEnvelope
                        match MeshEnvelope::from_msgpack(&packet.data) {
                            Ok(envelope) => {
                                let sender_hash = sender_hash_from_address(&envelope.sender);

                                debug!(
                                    envelope_type = ?envelope.envelope_type,
                                    sender = %envelope.sender,
                                    seq = envelope.seq,
                                    interface = %iface_name,
                                    "Dispatching inbound envelope"
                                );

                                dispatch_envelope(
                                    &node,
                                    &envelope,
                                    &sender_hash,
                                    &iface_name,
                                    &inbound_tx,
                                    &stats,
                                )
                                .await;
                            }
                            Err(e) => {
                                debug!(
                                    error = %e,
                                    interface = %iface_name,
                                    data_len = packet.data.len(),
                                    "Failed to deserialize packet as MeshEnvelope"
                                );
                                let mut s = stats.write().await;
                                s.deserialize_errors += 1;
                            }
                        }
                    }
                    Ok(None) => {
                        // No more packets on this interface
                        break;
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            interface = %iface.config().name,
                            "Error receiving packet from interface"
                        );
                        break;
                    }
                }
            }
        }

        // If no packets were available, sleep before the next poll cycle.
        // If packets were processed, immediately loop again to check for more.
        if !had_packets {
            tokio::select! {
                _ = tokio::time::sleep(config.poll_interval) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Mesh runtime shutting down (during sleep)");
                        break;
                    }
                }
            }
        }
    }

    info!("Mesh runtime event loop stopped");
}

/// Handle an inbound announce packet.
///
/// Announces contain:
/// 1. Combined public key (64 bytes): Ed25519 (32) + X25519 (32)
/// 2. JSON-encoded AgentCapabilities (variable length)
/// 3. Ed25519 signature over the payload (64 bytes)
async fn handle_announce_packet(
    node: &Arc<MeshNode>,
    packet: &crate::packet::Packet,
    stats: &Arc<tokio::sync::RwLock<RuntimeStats>>,
) {
    let payload = &packet.data;

    // Minimum size: 64 (combined key) + 1 (minimal JSON) + 64 (signature)
    if payload.len() < 129 {
        debug!(
            payload_len = payload.len(),
            "Announce packet too small, skipping"
        );
        return;
    }

    // Extract components from the announce payload
    let combined_key_bytes = match <[u8; 64]>::try_from(&payload[..64]) {
        Ok(b) => b,
        Err(_) => {
            warn!("Failed to extract combined key from announce");
            return;
        }
    };

    let signature_start = payload.len() - 64;
    let signature_bytes = match <[u8; 64]>::try_from(&payload[signature_start..]) {
        Ok(b) => b,
        Err(_) => {
            warn!("Failed to extract signature from announce");
            return;
        }
    };

    let announce_data = &payload[64..signature_start];

    // Verify the signature using the Ed25519 public key (first 32 bytes of combined key)
    let signing_key_bytes = &combined_key_bytes[..32];
    let signature_verified = verify_announce_signature(
        signing_key_bytes,
        &payload[..signature_start],
        &signature_bytes,
    );

    if !signature_verified {
        debug!("Announce signature verification failed, skipping");
        return;
    }

    // Parse AgentCapabilities from JSON
    let capabilities: AgentCapabilities = match serde_json::from_slice(announce_data) {
        Ok(caps) => caps,
        Err(e) => {
            debug!(error = %e, "Failed to parse AgentCapabilities from announce");
            return;
        }
    };

    // Create PeerIdentity from combined key (use hops=1 for directly-received announces)
    let peer_identity = match PeerIdentity::from_combined_key(&combined_key_bytes, 1) {
        Ok(pi) => pi,
        Err(e) => {
            warn!(error = %e, "Failed to create PeerIdentity from announce");
            return;
        }
    };

    // Register the peer with the node
    node.register_peer(peer_identity, Some(capabilities.clone()))
        .await;

    debug!(
        peer_address = %hex::encode(&combined_key_bytes[..32]),
        agent_name = %capabilities.name,
        "Peer discovered and registered from announce"
    );

    {
        let mut s = stats.write().await;
        s.peers_discovered += 1;
    }
}

/// Verify an Ed25519 signature over announce data.
fn verify_announce_signature(signing_key: &[u8], data: &[u8], signature: &[u8; 64]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let Ok(key_array): Result<[u8; 32], _> = signing_key.try_into() else {
        return false;
    };

    let Ok(verifying_key) = VerifyingKey::from_bytes(&key_array) else {
        return false;
    };

    let sig = Signature::from_bytes(signature);
    verifying_key.verify(data, &sig).is_ok()
}

/// Dispatch a single envelope to the appropriate handler.
async fn dispatch_envelope(
    node: &Arc<MeshNode>,
    envelope: &MeshEnvelope,
    sender_hash: &[u8; 16],
    interface_name: &str,
    inbound_tx: &mpsc::Sender<InboundEnvelope>,
    stats: &Arc<tokio::sync::RwLock<RuntimeStats>>,
) {
    let result = match envelope.envelope_type {
        // --- Receipts: forward to pipeline via channel ---
        EnvelopeType::Receipt | EnvelopeType::ReceiptChain => {
            forward_to_pipeline(envelope, sender_hash, interface_name, inbound_tx).await;
            Ok(())
        }

        // --- Delegations: handle + forward to pipeline ---
        EnvelopeType::Delegation => match node.handle_delegation_envelope(envelope).await {
            Ok(_grant) => {
                forward_to_pipeline(envelope, sender_hash, interface_name, inbound_tx).await;
                Ok(())
            }
            Err(e) => Err(e),
        },

        // --- Guard requests/responses: forward to pipeline ---
        EnvelopeType::GuardRequest | EnvelopeType::GuardResponse => {
            forward_to_pipeline(envelope, sender_hash, interface_name, inbound_tx).await;
            Ok(())
        }

        // --- Agent announce: log and forward to pipeline ---
        EnvelopeType::AgentAnnounce => {
            forward_to_pipeline(envelope, sender_hash, interface_name, inbound_tx).await;
            Ok(())
        }

        // --- Policy sync: handled internally by MeshNode ---
        EnvelopeType::PolicyAdvertisement
        | EnvelopeType::PolicyPullRequest
        | EnvelopeType::PolicyPullResponse
        | EnvelopeType::PolicyProposal
        | EnvelopeType::PolicyVote
        | EnvelopeType::PolicyAgreement
        | EnvelopeType::PolicyChunk => node.handle_policy_envelope(envelope, sender_hash).await,

        // --- Audit: handled internally by MeshNode ---
        EnvelopeType::AuditChallenge
        | EnvelopeType::AuditResponse
        | EnvelopeType::AuditAttestation => node.handle_audit_envelope(envelope, sender_hash).await,

        // --- Reputation: handled internally by MeshNode ---
        EnvelopeType::ReputationSummary => {
            node.handle_reputation_envelope(envelope, sender_hash).await
        }
    };

    match result {
        Ok(()) => {
            let mut s = stats.write().await;
            s.envelopes_dispatched += 1;
        }
        Err(e) => {
            warn!(
                envelope_type = ?envelope.envelope_type,
                sender = %envelope.sender,
                error = %e,
                "Failed to dispatch envelope"
            );
        }
    }
}

/// Forward an envelope to the pipeline consumer via the mpsc channel.
async fn forward_to_pipeline(
    envelope: &MeshEnvelope,
    sender_hash: &[u8; 16],
    interface_name: &str,
    inbound_tx: &mpsc::Sender<InboundEnvelope>,
) {
    let inbound = InboundEnvelope {
        envelope: envelope.clone(),
        sender_hash: *sender_hash,
        interface_name: interface_name.to_string(),
    };

    if let Err(e) = inbound_tx.try_send(inbound) {
        warn!(
            error = %e,
            envelope_type = ?envelope.envelope_type,
            "Inbound envelope channel full or closed, dropping envelope"
        );
    }
}

/// Derive a 16-byte destination hash from a hex address string.
///
/// If the address is a valid 32-char hex string, decode it.
/// Otherwise, hash it and take the first 16 bytes.
pub fn sender_hash_from_address(address: &str) -> [u8; 16] {
    if address.len() == 32 {
        if let Ok(bytes) = hex::decode(address) {
            if bytes.len() == 16 {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(&bytes);
                return hash;
            }
        }
    }
    // Fallback: hash the address string
    let full_hash = blake3::hash(address.as_bytes());
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&full_hash.as_bytes()[..16]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::DestinationHash;
    use crate::envelope::CompactReceipt;
    use crate::identity::MeshIdentity;
    use crate::interface::LoopbackInterface;
    use crate::packet::{Packet, PacketContext};
    use crate::transport::{AgentCapabilities, AgentTransport};
    use std::sync::Arc;

    /// Helper: create a MeshNode with a loopback interface and return both.
    async fn setup_node_with_loopback() -> (Arc<MeshNode>, Arc<LoopbackInterface>) {
        let id = MeshIdentity::generate();
        let node = Arc::new(MeshNode::new(id));
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;
        (node, lo)
    }

    /// Helper: create a receipt envelope packet and inject it into the loopback.
    async fn inject_receipt_packet(lo: &LoopbackInterface, sender_id: &MeshIdentity) {
        let receipt = zp_receipt::Receipt::execution("test-peer")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .finalize();
        let compact = CompactReceipt::from_receipt(&receipt);
        let envelope = MeshEnvelope::receipt(sender_id, &compact, 1).unwrap();
        let envelope_bytes = envelope.to_msgpack().unwrap();

        let dest = DestinationHash::from_public_key(&sender_id.combined_public_key());
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;
    }

    #[tokio::test]
    async fn test_runtime_starts_and_stops() {
        let (node, _lo) = setup_node_with_loopback().await;

        let runtime = MeshRuntime::start_default(node);
        assert!(runtime.is_running());

        runtime.shutdown();
        // Give it a moment to stop
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!runtime.is_running());
    }

    #[tokio::test]
    async fn test_runtime_dispatches_receipt() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node,
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let mut inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject a receipt packet
        let sender_id = MeshIdentity::generate();
        inject_receipt_packet(&lo, &sender_id).await;

        // Wait for dispatch
        let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .expect("timeout waiting for inbound envelope")
            .expect("channel closed");

        assert_eq!(inbound.envelope.envelope_type, EnvelopeType::Receipt);
        assert_eq!(inbound.interface_name, "loopback0");

        runtime.shutdown();
    }

    #[tokio::test]
    async fn test_runtime_dispatches_policy_advertisement() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node.clone(),
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let _inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject a policy advertisement packet
        let sender_id = MeshIdentity::generate();
        let ad = crate::policy_sync::PolicyAdvertisement {
            modules: vec![crate::policy_sync::PolicyModuleInfo {
                name: "test_policy".to_string(),
                content_hash: "abc123".to_string(),
                size_bytes: 100,
                min_tier: 0,
            }],
            sender_tier: 1,
        };
        let envelope = MeshEnvelope::policy_advertisement(&sender_id, &ad, 1).unwrap();
        let envelope_bytes = envelope.to_msgpack().unwrap();
        let dest = DestinationHash::from_public_key(&sender_id.combined_public_key());
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;

        // Wait for dispatch
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Policy advertisements are handled internally — check stats
        let stats = runtime.stats().await;
        assert!(stats.envelopes_dispatched >= 1);

        // Check the node stored the advertisement
        let sender_hash = sender_hash_from_address(&sender_id.address());
        let stored = node.peer_policy_advertisement(&sender_hash).await;
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().modules[0].name, "test_policy");

        runtime.shutdown();
    }

    #[tokio::test]
    async fn test_runtime_dispatches_reputation_summary() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node.clone(),
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let _inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject a reputation summary packet
        let sender_id = MeshIdentity::generate();
        let summary = crate::reputation::CompactReputationSummary {
            peer: "target_peer".to_string(),
            sc: 0.85,
            gr: "E".to_string(),
            ps: 10,
            ns: 1,
            ts: 1700000000,
        };
        let envelope = MeshEnvelope::reputation_summary(&sender_id, &summary, 1).unwrap();
        let envelope_bytes = envelope.to_msgpack().unwrap();
        let dest = DestinationHash::from_public_key(&sender_id.combined_public_key());
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;

        // Wait for dispatch
        tokio::time::sleep(Duration::from_millis(200)).await;

        let stats = runtime.stats().await;
        assert!(stats.envelopes_dispatched >= 1);

        // Check the node stored the summary
        let sender_hash = sender_hash_from_address(&sender_id.address());
        let stored = node.received_summaries_from(&sender_hash).await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].peer, "target_peer");

        runtime.shutdown();
    }

    #[tokio::test]
    async fn test_runtime_handles_multiple_packets() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node,
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let mut inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject 5 receipt packets from different senders
        for _ in 0..5 {
            let sender_id = MeshIdentity::generate();
            inject_receipt_packet(&lo, &sender_id).await;
        }

        // Collect all 5 inbound envelopes
        let mut received = Vec::new();
        for _ in 0..5 {
            let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
                .await
                .expect("timeout")
                .expect("closed");
            received.push(inbound);
        }

        assert_eq!(received.len(), 5);
        for env in &received {
            assert_eq!(env.envelope.envelope_type, EnvelopeType::Receipt);
        }

        let stats = runtime.stats().await;
        assert_eq!(stats.packets_received, 5);

        runtime.shutdown();
    }

    #[tokio::test]
    async fn test_runtime_stats_count_errors() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node,
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let _inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject a packet with garbage data that won't deserialize
        let id = MeshIdentity::generate();
        let dest = DestinationHash::from_public_key(&id.combined_public_key());
        let packet =
            Packet::data(dest, b"not-valid-msgpack".to_vec(), PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(200)).await;

        let stats = runtime.stats().await;
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.deserialize_errors, 1);
        assert_eq!(stats.envelopes_dispatched, 0);

        runtime.shutdown();
    }

    #[tokio::test]
    async fn test_runtime_graceful_join() {
        let (node, _lo) = setup_node_with_loopback().await;

        let runtime = MeshRuntime::start(
            node,
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );

        runtime.shutdown();

        // join() should complete quickly after shutdown
        let join_result = tokio::time::timeout(Duration::from_secs(2), runtime.join()).await;
        assert!(join_result.is_ok(), "Runtime did not join within timeout");
    }

    #[tokio::test]
    async fn test_runtime_drop_signals_shutdown() {
        let (node, _lo) = setup_node_with_loopback().await;

        let runtime = MeshRuntime::start(
            node,
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );

        let _task = runtime.task.as_ref().unwrap().abort_handle();
        drop(runtime);

        // The task should eventually finish (Drop sends shutdown signal)
        tokio::time::sleep(Duration::from_millis(200)).await;
        // AbortHandle doesn't give us is_finished, but the task should have stopped
        // This test mainly verifies that Drop doesn't panic.
    }

    #[tokio::test]
    async fn test_sender_hash_from_valid_address() {
        let id = MeshIdentity::generate();
        let addr = id.address();
        assert_eq!(addr.len(), 32); // hex-encoded 16 bytes

        let hash = sender_hash_from_address(&addr);
        let expected = hex::decode(&addr).unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[tokio::test]
    async fn test_sender_hash_from_invalid_address() {
        let hash = sender_hash_from_address("short");
        // Should fall back to blake3 hash
        assert_ne!(hash, [0u8; 16]);
    }

    #[tokio::test]
    async fn test_runtime_dispatches_audit_attestation() {
        use chrono::DateTime;
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node.clone(),
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let _inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject an audit attestation
        let sender_id = MeshIdentity::generate();
        let attestation = zp_audit::PeerAuditAttestation {
            id: "att-runtime-test".to_string(),
            peer: "peer-abc".to_string(),
            oldest_hash: "aaa".to_string(),
            newest_hash: "bbb".to_string(),
            entries_verified: 3,
            chain_valid: true,
            signatures_valid: 1,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };
        let envelope = MeshEnvelope::audit_attestation(&sender_id, &attestation, 1).unwrap();
        let envelope_bytes = envelope.to_msgpack().unwrap();
        let dest = DestinationHash::from_public_key(&sender_id.combined_public_key());
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;

        // Wait for dispatch
        tokio::time::sleep(Duration::from_millis(200)).await;

        let stats = runtime.stats().await;
        assert!(stats.envelopes_dispatched >= 1);

        // Check attestation was stored
        let sender_hash = sender_hash_from_address(&sender_id.address());
        let stored = node.peer_attestations(&sender_hash).await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, "att-runtime-test");

        runtime.shutdown();
    }

    #[tokio::test]
    async fn test_runtime_dispatches_delegation() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node.clone(),
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let mut inbound_rx = runtime.take_inbound_rx().unwrap();

        // Inject a delegation envelope
        let sender_id = MeshIdentity::generate();
        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "rcpt-1".to_string(),
        );
        let compact = crate::envelope::CompactDelegation::from_grant(&grant);
        let envelope = MeshEnvelope::delegation(&sender_id, &compact, 1).unwrap();
        let envelope_bytes = envelope.to_msgpack().unwrap();
        let dest = DestinationHash::from_public_key(&sender_id.combined_public_key());
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt).unwrap();
        lo.inject(&packet).await;

        // The delegation should both be stored on the node AND forwarded to pipeline
        let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .expect("timeout")
            .expect("closed");
        assert_eq!(inbound.envelope.envelope_type, EnvelopeType::Delegation);

        // Check that the node stored the delegation chain
        let chain = node.get_delegation_chain(&grant.id).await;
        assert!(chain.is_some());

        runtime.shutdown();
    }

    /// Helper: create an announce packet and inject it into the loopback.
    async fn inject_announce_packet(
        lo: &LoopbackInterface,
        sender_id: &MeshIdentity,
        capabilities: &AgentCapabilities,
    ) {
        use crate::packet::PacketType;

        let announce_data = serde_json::to_vec(capabilities).unwrap();

        // Build announce: combined public key + capabilities + signature
        let combined_key = sender_id.combined_public_key();
        let mut payload = Vec::with_capacity(64 + announce_data.len() + 64);
        payload.extend_from_slice(&combined_key);
        payload.extend_from_slice(&announce_data);

        // Sign the announce payload
        let signature = sender_id.sign(&payload);
        payload.extend_from_slice(&signature);

        // Create announce packet with the signed payload
        let dest = DestinationHash::from_public_key(&combined_key);
        let mut packet = Packet::announce(dest, payload).unwrap();
        // Ensure packet type is set correctly
        packet.header.packet_type = PacketType::Announce;

        lo.inject(&packet).await;
    }

    #[tokio::test]
    async fn test_runtime_handles_announce_discovery() {
        let (node, lo) = setup_node_with_loopback().await;

        let mut runtime = MeshRuntime::start(
            node.clone(),
            RuntimeConfig {
                poll_interval: Duration::from_millis(10),
                ..Default::default()
            },
        );
        let _inbound_rx = runtime.take_inbound_rx().unwrap();

        // Create a test peer identity and capabilities
        let peer_id = MeshIdentity::generate();
        let capabilities = AgentCapabilities {
            name: "test-agent".to_string(),
            version: "1.0.0".to_string(),
            receipt_types: vec!["execution".to_string()],
            skills: vec!["shell".to_string()],
            actor_type: "agent".to_string(),
            trust_tier: "tier0".to_string(),
        };

        // Inject an announce packet
        inject_announce_packet(&lo, &peer_id, &capabilities).await;

        // Wait for processing
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Verify the peer was registered
        let peers = node.known_peers().await;
        assert!(!peers.is_empty(), "Peer should be registered");

        let peer = peers.iter().find(|p| p.address == peer_id.address());
        assert!(peer.is_some(), "Specific peer should be found");
        assert_eq!(peer.unwrap().hops, 1);

        // Verify capabilities were stored
        let peer_caps = peer.unwrap().capabilities.as_ref();
        assert!(peer_caps.is_some());
        assert_eq!(peer_caps.unwrap().name, "test-agent");
        assert_eq!(peer_caps.unwrap().version, "1.0.0");

        // Check stats
        let stats = runtime.stats().await;
        assert_eq!(stats.announces_seen, 1);
        assert_eq!(stats.peers_discovered, 1);

        runtime.shutdown();
    }
}
