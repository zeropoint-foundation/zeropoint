//! Agent transport — the bridge between ZeroPoint and the mesh.
//!
//! Defines the `AgentTransport` trait that any transport layer must implement,
//! and provides `MeshNode` as the Reticulum-compatible implementation.
//!
//! ## Design
//!
//! The `AgentTransport` trait is intentionally simple — it abstracts over
//! the details of link establishment, routing, and packet encoding.
//! A pipeline or agent interacts with it at the level of:
//!
//! - **Announce**: "I exist, here are my capabilities"
//! - **Send receipt**: "Here is proof of what I did"
//! - **Request receipt**: "Show me proof of what you did"
//! - **Delegate**: "Please do this work for me"
//!
//! The `MeshNode` handles the rest: identity management, link caching,
//! interface multiplexing, announce propagation, and packet routing.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::capability_exchange::{CapabilityPolicy, CapabilityRequest, NegotiationResult};
use crate::destination::{Destination, DestinationHash};
use crate::envelope::{CompactReceipt, MeshEnvelope};
use crate::error::{MeshError, MeshResult};
use crate::identity::{MeshIdentity, PeerIdentity};
use crate::interface::Interface;
use crate::link::Link;
use crate::packet::{Packet, PacketContext};
use crate::policy_sync::{
    self, PolicyAdvertisement, PolicyAgreement, PolicyChunk, PolicyModuleInfo, PolicyProposal,
    PolicyPullRequest, TransferState,
};

/// Agent capabilities announced to the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// Human-readable agent name.
    pub name: String,
    /// Agent version.
    pub version: String,
    /// Supported receipt types.
    pub receipt_types: Vec<String>,
    /// Available skills/tools.
    pub skills: Vec<String>,
    /// Actor type (human, codex, agent).
    pub actor_type: String,
    /// Trust tier this agent operates at.
    pub trust_tier: String,
}

/// The transport trait — implemented by any agent communication layer.
///
/// This is the interface that `zp-pipeline` and other consumers use.
/// It abstracts over the physical transport completely.
#[async_trait]
pub trait AgentTransport: Send + Sync {
    /// Get our mesh address.
    fn address(&self) -> String;

    /// Announce our presence and capabilities to the mesh.
    async fn announce(&self, capabilities: &AgentCapabilities) -> MeshResult<()>;

    /// Send a receipt to a specific destination.
    async fn send_receipt(
        &self,
        destination: &str,
        receipt: &zp_receipt::Receipt,
    ) -> MeshResult<()>;

    /// Broadcast a receipt to all known peers.
    async fn broadcast_receipt(&self, receipt: &zp_receipt::Receipt) -> MeshResult<()>;

    /// Get the list of known peers.
    async fn known_peers(&self) -> Vec<PeerInfo>;

    /// Check if a destination is reachable.
    async fn is_reachable(&self, destination: &str) -> bool;
}

/// Information about a known peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Hex address.
    pub address: String,
    /// Number of hops away.
    pub hops: u8,
    /// Last time we heard from this peer.
    pub last_seen: chrono::DateTime<Utc>,
    /// Their announced capabilities (if known).
    pub capabilities: Option<AgentCapabilities>,
    /// Whether we have an active link to this peer.
    pub has_link: bool,
}

/// A mesh node — the runtime for agent mesh communication.
///
/// Manages identity, interfaces, routing, and peer tracking.
/// Implements `AgentTransport` for use by the pipeline.
pub struct MeshNode {
    /// Our cryptographic identity.
    identity: MeshIdentity,
    /// Our agent destination.
    destination: Destination,
    /// Attached interfaces.
    interfaces: RwLock<Vec<Arc<dyn Interface>>>,
    /// Known peers (destination hash → peer identity).
    pub(crate) peers: RwLock<HashMap<[u8; 16], PeerIdentity>>,
    /// Peer capabilities (destination hash → capabilities).
    pub(crate) peer_capabilities: RwLock<HashMap<[u8; 16], AgentCapabilities>>,
    /// Active links (link id → link).
    links: RwLock<HashMap<[u8; 16], Link>>,
    /// Sequence counter for envelope ordering.
    sequence: RwLock<u64>,

    // --- Phase 3: Policy propagation state ---
    /// Policy advertisements received from peers (peer dest hash → ad).
    peer_policies: RwLock<HashMap<[u8; 16], PolicyAdvertisement>>,
    /// Active chunked transfers (content hash → transfer state).
    active_transfers: RwLock<HashMap<String, TransferState>>,
    /// Policy agreements per peer (peer dest hash → agreement).
    pub(crate) policy_agreements: RwLock<HashMap<[u8; 16], PolicyAgreement>>,

    // --- Phase 3 Step 2: Delegation state ---
    /// Delegation chains received from peers, keyed by leaf grant ID.
    pub(crate) delegation_chains: RwLock<HashMap<String, Vec<zp_core::CapabilityGrant>>>,

    // --- Phase 3 Step 3: Collective audit state ---
    /// Peer audit attestations (peer dest hash → attestations received).
    pub(crate) peer_audit_attestations:
        RwLock<HashMap<[u8; 16], Vec<zp_audit::PeerAuditAttestation>>>,

    // --- Phase 3 Step 4: Reputation state ---
    /// Per-peer reputation ledgers (peer dest hash → reputation).
    pub(crate) peer_reputations: RwLock<HashMap<[u8; 16], crate::reputation::PeerReputation>>,
    /// Reputation summaries received from other peers (peer dest hash → summaries).
    received_reputation_summaries:
        RwLock<HashMap<[u8; 16], Vec<crate::reputation::CompactReputationSummary>>>,
}

impl MeshNode {
    /// Create a new mesh node with the given identity.
    pub fn new(identity: MeshIdentity) -> Self {
        let destination = Destination::agent(&identity.combined_public_key());

        info!(
            address = %identity.address(),
            "Mesh node created"
        );

        Self {
            identity,
            destination,
            interfaces: RwLock::new(Vec::new()),
            peers: RwLock::new(HashMap::new()),
            peer_capabilities: RwLock::new(HashMap::new()),
            links: RwLock::new(HashMap::new()),
            sequence: RwLock::new(0),
            peer_policies: RwLock::new(HashMap::new()),
            active_transfers: RwLock::new(HashMap::new()),
            policy_agreements: RwLock::new(HashMap::new()),
            delegation_chains: RwLock::new(HashMap::new()),
            peer_audit_attestations: RwLock::new(HashMap::new()),
            peer_reputations: RwLock::new(HashMap::new()),
            received_reputation_summaries: RwLock::new(HashMap::new()),
        }
    }

    /// Create from a zp-trust Signer (promotes existing identity to mesh).
    pub fn from_signer(signer: &zp_trust::Signer) -> MeshResult<Self> {
        let identity = MeshIdentity::from_signer(signer)?;
        Ok(Self::new(identity))
    }

    /// Attach a physical interface to this node.
    pub async fn attach_interface(&self, interface: Arc<dyn Interface>) {
        let config = interface.config();
        info!(
            name = %config.name,
            interface_type = %config.interface_type,
            mtu = config.mtu,
            "Interface attached"
        );
        self.interfaces.write().await.push(interface);
    }

    /// Get a snapshot of all attached interfaces (for the runtime event loop).
    pub async fn interfaces_snapshot(&self) -> Vec<Arc<dyn Interface>> {
        self.interfaces.read().await.clone()
    }

    /// Get our identity.
    pub fn identity(&self) -> &MeshIdentity {
        &self.identity
    }

    /// Get our destination.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Register a peer we've learned about (from announce or handshake).
    pub async fn register_peer(&self, peer: PeerIdentity, capabilities: Option<AgentCapabilities>) {
        let dest_hash = peer.destination_hash;
        debug!(
            address = %peer.address(),
            hops = peer.hops,
            "Peer registered"
        );
        self.peers.write().await.insert(dest_hash, peer);
        if let Some(caps) = capabilities {
            self.peer_capabilities.write().await.insert(dest_hash, caps);
        }
    }

    /// Look up a registered peer by address string (hex-encoded destination hash).
    ///
    /// Returns `None` if the peer hasn't been registered (via announce or
    /// prior handshake). Use `register_peer()` first.
    pub async fn peer_by_address(&self, address: &str) -> Option<PeerIdentity> {
        let dest = DestinationHash::from_hex(address).ok()?;
        self.peers.read().await.get(&dest.0).cloned()
    }

    /// Establish a link using an address string.
    ///
    /// Resolves the address to a registered `PeerIdentity`, initiates the
    /// handshake, and negotiates capabilities. The peer must have been
    /// previously registered via `register_peer()` (typically from an
    /// announce packet).
    ///
    /// This is the primary entry point for bridge code that only has an
    /// address string rather than a full `MeshIdentity`.
    pub async fn establish_link_by_address(
        &self,
        peer_address: &str,
        _our_policy: &CapabilityPolicy,
        _our_request: &CapabilityRequest,
        _their_request: &CapabilityRequest,
    ) -> MeshResult<NegotiationResult> {
        let dest = DestinationHash::from_hex(peer_address).map_err(|_| {
            MeshError::InvalidPacket(format!("invalid peer address: {}", peer_address))
        })?;

        let peer_identity = self
            .peers
            .read()
            .await
            .get(&dest.0)
            .cloned()
            .ok_or_else(|| {
                MeshError::NoPeer(format!(
                    "peer {} not found in registry — has it announced?",
                    peer_address
                ))
            })?;

        // Initiate the handshake from our side
        let (mut link, request_data) = Link::initiate(&self.identity, dest);

        // Build peer's combined key for Link::accept simulation
        // In a real async deployment, steps 2-3 would go over the wire.
        // For now, we have the peer's public keys from their announcement
        // and can complete the initiator side of the handshake.
        link.set_remote_signing_key(peer_identity.signing_key);

        // Send the LinkRequest packet to the peer
        let packet = Packet::link_request(dest, request_data.to_bytes())?;
        self.send_on_interfaces(&packet).await?;

        // NOTE: In the current synchronous test harness, Link::accept() is
        // called locally. In the async mesh runtime, the responder's
        // LinkProof arrives via the packet dispatcher. For now we store the
        // pending link and return a "pending" result — the runtime's inbound
        // handler will complete the handshake when the proof arrives.
        info!(
            link_id = %link.id_hex(),
            peer = peer_address,
            "Link request sent, awaiting proof"
        );

        self.links.write().await.insert(link.id, link);

        // Return a partial result — the link is Pending until the proof arrives.
        // Grants will be populated when the runtime completes the handshake.
        Ok(NegotiationResult {
            initiator_grants: vec![],
            responder_grants: vec![],
            denied: vec![],
            effective_tier: zp_core::TrustTier::Tier0,
        })
    }

    /// Establish a link with capability negotiation.
    ///
    /// Performs the 3-packet handshake with a peer, then negotiates
    /// capabilities based on the provided policy and request.
    ///
    /// Returns the negotiation result. The link (with stored grants)
    /// is added to the node's active links.
    pub async fn establish_link(
        &self,
        peer: &MeshIdentity,
        our_policy: &CapabilityPolicy,
        our_request: &CapabilityRequest,
        their_request: &CapabilityRequest,
    ) -> MeshResult<NegotiationResult> {
        let peer_dest = DestinationHash::from_public_key(&peer.combined_public_key());

        // Step 1: Initiate the handshake
        let (mut link, request_data) = Link::initiate(&self.identity, peer_dest);

        // Step 2: Peer accepts (in a real deployment this goes over the wire)
        let (_peer_link, proof, _peer_keys) = Link::accept(peer, &request_data)?;

        // Step 3: Set remote signing key and complete handshake
        link.set_remote_signing_key(peer.signing_public_key());
        let _keys = link.complete_handshake(&self.identity, &proof, &request_data)?;

        // Step 4: Negotiate capabilities on the active link
        let receipt_id = format!("link-{}", hex::encode(link.id));
        let result =
            link.negotiate_capabilities(our_policy, our_request, their_request, &receipt_id)?;

        info!(
            link_id = %link.id_hex(),
            local_grants = result.initiator_grants.len(),
            remote_grants = result.responder_grants.len(),
            denied = result.denied.len(),
            effective_tier = ?result.effective_tier,
            "Link established with capabilities"
        );

        // Store the link
        self.links.write().await.insert(link.id, link);

        Ok(result)
    }

    /// Get a snapshot of active link capabilities for a given peer.
    pub async fn link_grants_for_peer(
        &self,
        peer_address: &str,
    ) -> Option<(
        Vec<zp_core::capability_grant::CapabilityGrant>,
        Vec<zp_core::capability_grant::CapabilityGrant>,
    )> {
        let links = self.links.read().await;
        let dest = DestinationHash::from_hex(peer_address).ok()?;
        links
            .values()
            .find(|l| l.remote_destination == dest && l.is_active())
            .map(|l| (l.local_grants.clone(), l.remote_grants.clone()))
    }

    /// Get the next sequence number.
    async fn next_seq(&self) -> u64 {
        let mut seq = self.sequence.write().await;
        *seq += 1;
        *seq
    }

    /// Send a packet out on all suitable interfaces.
    async fn send_on_interfaces(&self, packet: &Packet) -> MeshResult<()> {
        let interfaces = self.interfaces.read().await;
        if interfaces.is_empty() {
            return Err(MeshError::NoInterfaces);
        }

        let mut sent = false;
        for iface in interfaces.iter() {
            if iface.is_online() && iface.config().enabled {
                let wire_size = packet.wire_size();
                if wire_size <= iface.config().mtu {
                    match iface.send(packet).await {
                        Ok(()) => {
                            sent = true;
                            debug!(
                                interface = %iface.config().name,
                                size = wire_size,
                                "Packet sent"
                            );
                        }
                        Err(e) => {
                            warn!(
                                interface = %iface.config().name,
                                error = %e,
                                "Send failed on interface"
                            );
                        }
                    }
                } else {
                    debug!(
                        interface = %iface.config().name,
                        wire_size,
                        mtu = iface.config().mtu,
                        "Packet too large for interface, skipping"
                    );
                }
            }
        }

        if sent {
            Ok(())
        } else {
            Err(MeshError::InterfaceError("no interface could send".into()))
        }
    }

    // =========================================================================
    // Phase 3: Policy Propagation
    // =========================================================================

    /// Broadcast a policy advertisement to all known peers.
    ///
    /// Builds a signed PolicyAdvertisement envelope and sends it
    /// to every registered peer over all attached interfaces.
    pub async fn advertise_policies(
        &self,
        modules: Vec<PolicyModuleInfo>,
        our_tier: u8,
    ) -> MeshResult<()> {
        let peers = self.peers.read().await;
        let peer_hashes: Vec<[u8; 16]> = peers.keys().copied().collect();
        drop(peers);

        if peer_hashes.is_empty() {
            debug!("No peers to advertise policies to");
            return Ok(());
        }

        let ad = PolicyAdvertisement {
            modules,
            sender_tier: our_tier,
        };

        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::policy_advertisement(&self.identity, &ad, seq)?;
        let envelope_bytes = envelope.to_msgpack()?;

        for dest_hash in &peer_hashes {
            let dest = DestinationHash(*dest_hash);
            let packet = Packet::data(dest, envelope_bytes.clone(), PacketContext::Receipt)?;
            if let Err(e) = self.send_on_interfaces(&packet).await {
                warn!(
                    peer = %hex::encode(dest_hash),
                    error = %e,
                    "Failed to send policy advertisement to peer"
                );
            }
        }

        info!(
            peer_count = peer_hashes.len(),
            "Policy advertisement broadcast complete"
        );

        Ok(())
    }

    /// Send a policy pull request to a specific peer.
    ///
    /// Requests the given content hashes from the peer. The peer will
    /// respond with a PolicyPullResponse followed by PolicyChunks.
    pub async fn request_policies(
        &self,
        peer: &[u8; 16],
        hashes: Vec<String>,
        our_tier: u8,
    ) -> MeshResult<()> {
        let pull_request = PolicyPullRequest {
            content_hashes: hashes,
            requester_tier: our_tier,
        };

        let payload = rmp_serde::to_vec_named(&pull_request)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;
        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::new(
            &self.identity,
            crate::envelope::EnvelopeType::PolicyPullRequest,
            payload,
            seq,
        )?;
        let envelope_bytes = envelope.to_msgpack()?;

        let dest = DestinationHash(*peer);
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt)?;
        self.send_on_interfaces(&packet).await?;

        debug!(
            peer = %hex::encode(peer),
            "Policy pull request sent"
        );

        Ok(())
    }

    /// Propose a set of policies to govern a link with a peer.
    ///
    /// Sends a PolicyProposal envelope. The peer should reply with a PolicyVote.
    pub async fn propose_policy_agreement(
        &self,
        peer: &[u8; 16],
        hashes: Vec<String>,
        our_tier: u8,
    ) -> MeshResult<String> {
        let proposal_id = policy_sync::new_proposal_id();

        let proposal = PolicyProposal {
            proposal_id: proposal_id.clone(),
            proposed_hashes: hashes,
            proposer_tier: our_tier,
        };

        let payload = rmp_serde::to_vec_named(&proposal)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;
        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::new(
            &self.identity,
            crate::envelope::EnvelopeType::PolicyProposal,
            payload,
            seq,
        )?;
        let envelope_bytes = envelope.to_msgpack()?;

        let dest = DestinationHash(*peer);
        let packet = Packet::data(dest, envelope_bytes, PacketContext::Receipt)?;
        self.send_on_interfaces(&packet).await?;

        info!(
            proposal_id = %proposal_id,
            peer = %hex::encode(peer),
            "Policy proposal sent"
        );

        Ok(proposal_id)
    }

    /// Handle an inbound policy-related envelope.
    ///
    /// Routes to the correct handler based on envelope type.
    /// Stores state in `peer_policies`, `active_transfers`, or `policy_agreements`.
    pub async fn handle_policy_envelope(
        &self,
        envelope: &MeshEnvelope,
        sender_hash: &[u8; 16],
    ) -> MeshResult<()> {
        match envelope.envelope_type {
            crate::envelope::EnvelopeType::PolicyAdvertisement => {
                let ad: PolicyAdvertisement = rmp_serde::from_slice(&envelope.payload)
                    .map_err(|e| MeshError::Serialization(e.to_string()))?;
                info!(
                    sender = %hex::encode(sender_hash),
                    module_count = ad.modules.len(),
                    "Received policy advertisement"
                );
                self.peer_policies.write().await.insert(*sender_hash, ad);
            }
            crate::envelope::EnvelopeType::PolicyChunk => {
                let chunk: PolicyChunk = rmp_serde::from_slice(&envelope.payload)
                    .map_err(|e| MeshError::Serialization(e.to_string()))?;
                let hash = chunk.content_hash.clone();
                let mut transfers = self.active_transfers.write().await;
                let state = transfers.entry(hash.clone()).or_insert_with(|| {
                    TransferState::new(chunk.content_hash.clone(), 0, chunk.total_chunks)
                });
                state.receive_chunk(&chunk);

                if state.is_complete() {
                    info!(
                        content_hash = %hash,
                        "Policy chunk transfer complete"
                    );
                }
            }
            crate::envelope::EnvelopeType::PolicyAgreement => {
                let agreement: PolicyAgreement = rmp_serde::from_slice(&envelope.payload)
                    .map_err(|e| MeshError::Serialization(e.to_string()))?;
                info!(
                    sender = %hex::encode(sender_hash),
                    enforced = agreement.enforced.len(),
                    "Received policy agreement"
                );
                self.policy_agreements
                    .write()
                    .await
                    .insert(*sender_hash, agreement);
            }
            _ => {
                debug!(
                    envelope_type = ?envelope.envelope_type,
                    "Unhandled envelope type in policy handler"
                );
            }
        }
        Ok(())
    }

    /// Remove incomplete transfers older than `max_age`.
    pub async fn cleanup_stale_transfers(&self, max_age: chrono::Duration) {
        let cutoff = Utc::now() - max_age;
        let mut transfers = self.active_transfers.write().await;
        let before = transfers.len();
        transfers.retain(|_hash, state| state.started_at > cutoff);
        let removed = before - transfers.len();
        if removed > 0 {
            info!(removed, "Cleaned up stale policy transfers");
        }
    }

    /// Get a snapshot of the policy advertisement from a specific peer.
    pub async fn peer_policy_advertisement(&self, peer: &[u8; 16]) -> Option<PolicyAdvertisement> {
        self.peer_policies.read().await.get(peer).cloned()
    }

    /// Get a snapshot of the policy agreement with a specific peer.
    pub async fn peer_policy_agreement(&self, peer: &[u8; 16]) -> Option<PolicyAgreement> {
        self.policy_agreements.read().await.get(peer).cloned()
    }

    /// Check if a chunked transfer is complete.
    pub async fn is_transfer_complete(&self, content_hash: &str) -> bool {
        self.active_transfers
            .read()
            .await
            .get(content_hash)
            .map(|s| s.is_complete())
            .unwrap_or(false)
    }

    // =========================================================================
    // Phase 3 Step 2: Capability Delegation
    // =========================================================================

    /// Send a delegation envelope to a specific peer.
    ///
    /// Wraps a `CapabilityGrant` (the delegated child grant) in a signed
    /// Delegation envelope and sends it to the specified peer.
    pub async fn send_delegation(
        &self,
        peer: &[u8; 16],
        grant: &zp_core::CapabilityGrant,
    ) -> MeshResult<()> {
        let compact = crate::envelope::CompactDelegation::from_grant(grant);
        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::delegation(&self.identity, &compact, seq)?;

        let packet_data = envelope.to_msgpack()?;
        let dest = DestinationHash(*peer);
        let packet = Packet::data(dest, packet_data, PacketContext::Receipt)?;

        info!(
            grant_id = %grant.id,
            depth = grant.delegation_depth,
            "Sending delegation to peer"
        );

        self.send_on_interfaces(&packet).await
    }

    /// Handle an inbound delegation envelope from a peer.
    ///
    /// Deserializes the grant, stores it in the delegation chains map,
    /// and returns the grant for further processing.
    pub async fn handle_delegation_envelope(
        &self,
        envelope: &MeshEnvelope,
    ) -> MeshResult<zp_core::CapabilityGrant> {
        let compact = envelope.extract_delegation()?;
        let grant = compact.to_grant();

        debug!(
            grant_id = %grant.id,
            depth = grant.delegation_depth,
            "Received delegation from peer"
        );

        // Store in our delegation chains
        let leaf_id = grant.id.clone();
        self.delegation_chains
            .write()
            .await
            .insert(leaf_id, vec![grant.clone()]);

        Ok(grant)
    }

    /// Store a full delegation chain received from a peer.
    ///
    /// The chain should be ordered root → leaf. It is verified before storage.
    pub async fn store_delegation_chain(
        &self,
        chain: Vec<zp_core::CapabilityGrant>,
    ) -> MeshResult<()> {
        // Verify the chain
        let verified = zp_core::DelegationChain::verify(chain.clone(), false)
            .map_err(|e| MeshError::InvalidPacket(format!("invalid delegation chain: {}", e)))?;

        let leaf_id = verified.leaf().id.clone();

        info!(
            leaf_id = %leaf_id,
            depth = verified.current_depth(),
            chain_len = verified.len(),
            "Delegation chain stored"
        );

        self.delegation_chains.write().await.insert(leaf_id, chain);

        Ok(())
    }

    /// Get a stored delegation chain by the leaf grant ID.
    pub async fn get_delegation_chain(
        &self,
        leaf_grant_id: &str,
    ) -> Option<Vec<zp_core::CapabilityGrant>> {
        self.delegation_chains
            .read()
            .await
            .get(leaf_grant_id)
            .cloned()
    }

    /// List all stored delegation chain leaf IDs.
    pub async fn delegation_chain_ids(&self) -> Vec<String> {
        self.delegation_chains
            .read()
            .await
            .keys()
            .cloned()
            .collect()
    }

    // =========================================================================
    // Phase 3 Step 3: Collective Audit
    // =========================================================================

    /// Send an audit challenge to a specific peer.
    ///
    /// Wraps an `AuditChallenge` in a signed envelope and sends it.
    pub async fn send_audit_challenge(
        &self,
        peer: &[u8; 16],
        challenge: &zp_audit::AuditChallenge,
    ) -> MeshResult<()> {
        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::audit_challenge(&self.identity, challenge, seq)?;
        let packet_data = envelope.to_msgpack()?;
        let dest = DestinationHash(*peer);
        let packet = Packet::data(dest, packet_data, PacketContext::Receipt)?;

        info!(
            challenge_id = %challenge.id,
            peer = %hex::encode(peer),
            "Sending audit challenge"
        );

        self.send_on_interfaces(&packet).await
    }

    /// Send an audit response to a specific peer.
    ///
    /// Wraps an `AuditResponse` in a signed envelope and sends it.
    pub async fn send_audit_response(
        &self,
        peer: &[u8; 16],
        response: &zp_audit::AuditResponse,
    ) -> MeshResult<()> {
        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::audit_response(&self.identity, response, seq)?;
        let packet_data = envelope.to_msgpack()?;
        let dest = DestinationHash(*peer);
        let packet = Packet::data(dest, packet_data, PacketContext::Receipt)?;

        debug!(
            challenge_id = %response.challenge_id,
            entries = response.entries.len(),
            "Sending audit response"
        );

        self.send_on_interfaces(&packet).await
    }

    /// Broadcast a peer audit attestation to all known peers.
    ///
    /// After verifying a peer's audit chain, share the attestation
    /// with the mesh so others can build a reputation map.
    pub async fn broadcast_audit_attestation(
        &self,
        attestation: &zp_audit::PeerAuditAttestation,
    ) -> MeshResult<()> {
        let peers = self.peers.read().await;
        let peer_hashes: Vec<[u8; 16]> = peers.keys().copied().collect();
        drop(peers);

        if peer_hashes.is_empty() {
            debug!("No peers to broadcast audit attestation to");
            return Ok(());
        }

        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::audit_attestation(&self.identity, attestation, seq)?;
        let envelope_bytes = envelope.to_msgpack()?;

        for dest_hash in &peer_hashes {
            let dest = DestinationHash(*dest_hash);
            let packet = Packet::data(dest, envelope_bytes.clone(), PacketContext::Receipt)?;
            if let Err(e) = self.send_on_interfaces(&packet).await {
                warn!(
                    peer = %hex::encode(dest_hash),
                    error = %e,
                    "Failed to broadcast audit attestation"
                );
            }
        }

        info!(
            attestation_id = %attestation.id,
            peer_count = peer_hashes.len(),
            "Audit attestation broadcast complete"
        );

        Ok(())
    }

    /// Handle an inbound audit-related envelope.
    ///
    /// Routes to the correct handler based on envelope type.
    /// Stores attestations in `peer_audit_attestations`.
    pub async fn handle_audit_envelope(
        &self,
        envelope: &MeshEnvelope,
        sender_hash: &[u8; 16],
    ) -> MeshResult<()> {
        match envelope.envelope_type {
            crate::envelope::EnvelopeType::AuditChallenge => {
                let challenge = envelope.extract_audit_challenge()?;
                info!(
                    challenge_id = %challenge.id,
                    sender = %hex::encode(sender_hash),
                    "Received audit challenge"
                );
                // The caller is responsible for building and sending the response.
                // We just log it here; in a full implementation, we'd invoke
                // the audit store to build a response.
            }
            crate::envelope::EnvelopeType::AuditResponse => {
                let response = envelope.extract_audit_response()?;
                info!(
                    challenge_id = %response.challenge_id,
                    entries = response.entries.len(),
                    sender = %hex::encode(sender_hash),
                    "Received audit response"
                );
                // Verify the chain and produce an attestation
                let attestation =
                    zp_audit::verify_peer_chain(&hex::encode(sender_hash), &response.entries);

                // Store the attestation
                self.peer_audit_attestations
                    .write()
                    .await
                    .entry(*sender_hash)
                    .or_default()
                    .push(attestation);
            }
            crate::envelope::EnvelopeType::AuditAttestation => {
                let attestation = envelope.extract_audit_attestation()?;
                info!(
                    attestation_id = %attestation.id,
                    peer = %attestation.peer,
                    chain_valid = attestation.chain_valid,
                    sender = %hex::encode(sender_hash),
                    "Received audit attestation"
                );
                // Store the attestation under the sender
                self.peer_audit_attestations
                    .write()
                    .await
                    .entry(*sender_hash)
                    .or_default()
                    .push(attestation);
            }
            _ => {
                debug!(
                    envelope_type = ?envelope.envelope_type,
                    "Unhandled envelope type in audit handler"
                );
            }
        }
        Ok(())
    }

    /// Get all audit attestations received from a specific peer.
    pub async fn peer_attestations(&self, peer: &[u8; 16]) -> Vec<zp_audit::PeerAuditAttestation> {
        self.peer_audit_attestations
            .read()
            .await
            .get(peer)
            .cloned()
            .unwrap_or_default()
    }

    /// Store an audit attestation for a peer.
    ///
    /// Used by the pipeline bridge to store attestations produced
    /// from `handle_audit_response` without going through the envelope path.
    pub async fn store_attestation(
        &self,
        peer: &[u8; 16],
        attestation: zp_audit::PeerAuditAttestation,
    ) {
        self.peer_audit_attestations
            .write()
            .await
            .entry(*peer)
            .or_default()
            .push(attestation);
    }

    /// Get all audit attestations across all peers.
    pub async fn all_attestations(&self) -> HashMap<[u8; 16], Vec<zp_audit::PeerAuditAttestation>> {
        self.peer_audit_attestations.read().await.clone()
    }

    // =========================================================================
    // Phase 3 Step 4: Reputation
    // =========================================================================

    /// Record a reputation signal for a peer.
    pub async fn record_reputation_signal(
        &self,
        peer: &[u8; 16],
        signal: crate::reputation::ReputationSignal,
    ) {
        self.peer_reputations
            .write()
            .await
            .entry(*peer)
            .or_default()
            .record(signal);
    }

    /// Compute the current reputation score for a peer.
    pub async fn compute_peer_reputation(
        &self,
        peer: &[u8; 16],
    ) -> crate::reputation::ReputationScore {
        let peer_hex = hex::encode(peer);
        let weights = crate::reputation::ReputationWeights::default();
        let now = chrono::Utc::now();

        let reps = self.peer_reputations.read().await;
        match reps.get(peer) {
            Some(rep) => rep.compute_score(&peer_hex, &weights, now),
            None => {
                let empty = crate::reputation::PeerReputation::new();
                empty.compute_score(&peer_hex, &weights, now)
            }
        }
    }

    /// Compute reputation scores for all known peers.
    pub async fn all_peer_reputations(
        &self,
    ) -> HashMap<[u8; 16], crate::reputation::ReputationScore> {
        let weights = crate::reputation::ReputationWeights::default();
        let now = chrono::Utc::now();
        let reps = self.peer_reputations.read().await;
        let peers = self.peers.read().await;

        let mut scores = HashMap::new();
        for peer_hash in peers.keys() {
            let peer_hex = hex::encode(peer_hash);
            let score = match reps.get(peer_hash) {
                Some(rep) => rep.compute_score(&peer_hex, &weights, now),
                None => {
                    let empty = crate::reputation::PeerReputation::new();
                    empty.compute_score(&peer_hex, &weights, now)
                }
            };
            scores.insert(*peer_hash, score);
        }
        scores
    }

    /// Read-only access to the peer reputations map.
    ///
    /// Returns a read guard for direct score computation with custom weights.
    pub async fn peer_reputations_read(
        &self,
    ) -> tokio::sync::RwLockReadGuard<'_, HashMap<[u8; 16], crate::reputation::PeerReputation>>
    {
        self.peer_reputations.read().await
    }

    /// Broadcast our reputation view of a specific peer to the mesh.
    pub async fn broadcast_reputation_summary(&self, about_peer: &[u8; 16]) -> MeshResult<()> {
        let score = self.compute_peer_reputation(about_peer).await;
        let summary = crate::reputation::CompactReputationSummary::from_score(&score);

        let peers = self.peers.read().await;
        let peer_hashes: Vec<[u8; 16]> = peers.keys().copied().collect();
        drop(peers);

        if peer_hashes.is_empty() {
            debug!("No peers to broadcast reputation summary to");
            return Ok(());
        }

        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::reputation_summary(&self.identity, &summary, seq)?;
        let envelope_bytes = envelope.to_msgpack()?;

        for dest_hash in &peer_hashes {
            let dest = DestinationHash(*dest_hash);
            let packet = Packet::data(dest, envelope_bytes.clone(), PacketContext::Receipt)?;
            if let Err(e) = self.send_on_interfaces(&packet).await {
                warn!(
                    peer = %hex::encode(dest_hash),
                    error = %e,
                    "Failed to broadcast reputation summary"
                );
            }
        }

        info!(
            about_peer = %hex::encode(about_peer),
            grade = %score.grade,
            "Reputation summary broadcast complete"
        );

        Ok(())
    }

    /// Handle an inbound reputation summary envelope.
    pub async fn handle_reputation_envelope(
        &self,
        envelope: &MeshEnvelope,
        sender_hash: &[u8; 16],
    ) -> MeshResult<()> {
        let summary = envelope.extract_reputation_summary()?;
        info!(
            about_peer = %summary.peer,
            grade = %summary.gr,
            score = summary.sc,
            sender = %hex::encode(sender_hash),
            "Received reputation summary"
        );

        self.received_reputation_summaries
            .write()
            .await
            .entry(*sender_hash)
            .or_default()
            .push(summary);

        Ok(())
    }

    /// Get reputation summaries received from a specific peer.
    pub async fn received_summaries_from(
        &self,
        sender: &[u8; 16],
    ) -> Vec<crate::reputation::CompactReputationSummary> {
        self.received_reputation_summaries
            .read()
            .await
            .get(sender)
            .cloned()
            .unwrap_or_default()
    }

    /// Automatically record reputation signals from audit attestation storage.
    ///
    /// Call this after handling audit envelopes to keep reputation in sync.
    pub async fn update_reputation_from_attestations(&self, peer: &[u8; 16]) {
        let attestations = self.peer_attestations(peer).await;
        for att in &attestations {
            let signal = crate::reputation::signal_from_attestation(att);
            self.record_reputation_signal(peer, signal).await;
        }
    }
}

impl std::fmt::Debug for MeshNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshNode")
            .field("address", &self.identity.address())
            .field("destination", &self.destination.to_string())
            .finish()
    }
}

#[async_trait]
impl AgentTransport for MeshNode {
    fn address(&self) -> String {
        self.identity.address()
    }

    async fn announce(&self, capabilities: &AgentCapabilities) -> MeshResult<()> {
        // Seam 17: announce payload is signed; preimage routes through
        // the canonical helper for deterministic round-trip with verifiers.
        let announce_data = zp_core::canonical_bytes_of(capabilities)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;

        // Build announce: combined public key + capabilities + signature
        let combined_key = self.identity.combined_public_key();
        let mut payload = Vec::with_capacity(64 + announce_data.len() + 64);
        payload.extend_from_slice(&combined_key);
        payload.extend_from_slice(&announce_data);

        // Sign the announce payload
        let signature = self.identity.sign(&payload);
        payload.extend_from_slice(&signature);

        let packet = Packet::announce(self.destination.hash, payload)?;

        info!(
            address = %self.identity.address(),
            capabilities = capabilities.name,
            "Announcing on mesh"
        );

        self.send_on_interfaces(&packet).await
    }

    async fn send_receipt(
        &self,
        destination: &str,
        receipt: &zp_receipt::Receipt,
    ) -> MeshResult<()> {
        let dest_hash = DestinationHash::from_hex(destination)?;

        // Compact the receipt
        let compact = CompactReceipt::from_receipt(receipt);
        let seq = self.next_seq().await;
        let envelope = MeshEnvelope::receipt(&self.identity, &compact, seq)?;
        let envelope_bytes = envelope.to_msgpack()?;

        let packet = Packet::data(dest_hash, envelope_bytes, PacketContext::Receipt)?;

        debug!(
            receipt_id = %receipt.id,
            destination = destination,
            size = packet.wire_size(),
            "Sending receipt over mesh"
        );

        self.send_on_interfaces(&packet).await
    }

    async fn broadcast_receipt(&self, receipt: &zp_receipt::Receipt) -> MeshResult<()> {
        let peers = self.peers.read().await;
        let peer_hashes: Vec<[u8; 16]> = peers.keys().copied().collect();
        drop(peers);

        if peer_hashes.is_empty() {
            debug!("No peers to broadcast to");
            return Ok(());
        }

        for dest_hash in peer_hashes {
            let hex = hex::encode(dest_hash);
            if let Err(e) = self.send_receipt(&hex, receipt).await {
                warn!(destination = %hex, error = %e, "Broadcast to peer failed");
            }
        }

        Ok(())
    }

    async fn known_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.read().await;
        let caps = self.peer_capabilities.read().await;
        let links = self.links.read().await;

        peers
            .values()
            .map(|peer| {
                let has_link = links.values().any(|l| {
                    l.remote_destination == DestinationHash(peer.destination_hash) && l.is_active()
                });

                PeerInfo {
                    address: peer.address(),
                    hops: peer.hops,
                    last_seen: peer.last_announced,
                    capabilities: caps.get(&peer.destination_hash).cloned(),
                    has_link,
                }
            })
            .collect()
    }

    async fn is_reachable(&self, destination: &str) -> bool {
        if let Ok(hash) = DestinationHash::from_hex(destination) {
            self.peers.read().await.contains_key(&hash.0)
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::LoopbackInterface;

    fn test_capabilities() -> AgentCapabilities {
        AgentCapabilities {
            name: "test-agent".into(),
            version: "0.1.0".into(),
            receipt_types: vec!["execution".into(), "intent".into()],
            skills: vec!["shell".into(), "python".into()],
            actor_type: "agent".into(),
            trust_tier: "tier0".into(),
        }
    }

    #[tokio::test]
    async fn test_mesh_node_creation() {
        let id = MeshIdentity::generate();
        let node = MeshNode::new(id);
        assert!(!node.address().is_empty());
        assert_eq!(node.address().len(), 32);
    }

    #[tokio::test]
    async fn test_mesh_node_from_signer() {
        let signer = zp_trust::Signer::generate();
        let node = MeshNode::from_signer(&signer).unwrap();

        // The signing public key should match
        let mesh_pub = node.identity().signing_public_key();
        assert_eq!(mesh_pub, signer.public_key());
    }

    #[tokio::test]
    async fn test_announce_on_loopback() {
        let id = MeshIdentity::generate();
        let node = MeshNode::new(id);

        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let caps = test_capabilities();
        node.announce(&caps).await.unwrap();

        // The announce should be in the loopback buffer
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());

        let pkt = received.unwrap();
        assert_eq!(pkt.header.packet_type, crate::packet::PacketType::Announce);
    }

    #[tokio::test]
    async fn test_send_receipt_over_mesh() {
        let alice_id = MeshIdentity::generate();
        let bob_id = MeshIdentity::generate();

        let alice_node = MeshNode::new(alice_id);
        let lo = Arc::new(LoopbackInterface::new());
        alice_node.attach_interface(lo.clone()).await;

        // Register bob as a known peer
        let bob_peer = PeerIdentity::from_combined_key(&bob_id.combined_public_key(), 1).unwrap();
        alice_node.register_peer(bob_peer, None).await;

        // Create a test receipt
        let receipt = zp_receipt::Receipt::execution("test-agent")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .finalize();

        // Send it
        let bob_addr = bob_id.address();
        alice_node.send_receipt(&bob_addr, &receipt).await.unwrap();

        // Verify it arrived on the loopback
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());

        let pkt = received.unwrap();
        assert_eq!(pkt.context as u8, PacketContext::Receipt as u8);

        // Decode the envelope and extract the receipt
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        let compact = envelope.extract_receipt().unwrap();
        assert!(compact.id.starts_with("rcpt-"));
        assert_eq!(compact.st, "success");
        assert_eq!(compact.tg, "C");
    }

    #[tokio::test]
    async fn test_broadcast_receipt() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        // Add two peers
        for _ in 0..2 {
            let peer_id = MeshIdentity::generate();
            let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
            node.register_peer(peer, None).await;
        }

        let receipt = zp_receipt::Receipt::execution("broadcaster")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::D)
            .finalize();

        node.broadcast_receipt(&receipt).await.unwrap();

        // Should have 2 packets in loopback (one per peer)
        let p1 = lo.recv().await.unwrap();
        let p2 = lo.recv().await.unwrap();
        assert!(p1.is_some());
        assert!(p2.is_some());
    }

    #[tokio::test]
    async fn test_known_peers() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 3).unwrap();
        let caps = test_capabilities();
        node.register_peer(peer, Some(caps.clone())).await;

        let peers = node.known_peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].hops, 3);
        assert!(peers[0].capabilities.is_some());
        assert_eq!(peers[0].capabilities.as_ref().unwrap().name, "test-agent");
    }

    #[tokio::test]
    async fn test_reachability() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        let peer_id = MeshIdentity::generate();
        let peer_addr = peer_id.address();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        node.register_peer(peer, None).await;

        assert!(node.is_reachable(&peer_addr).await);
        assert!(!node.is_reachable("0000000000000000000000000000dead").await);
    }

    #[tokio::test]
    async fn test_no_interfaces_error() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        let receipt = zp_receipt::Receipt::execution("test")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::D)
            .finalize();

        let result = node
            .send_receipt("0000000000000000000000000000dead", &receipt)
            .await;
        assert!(result.is_err());
    }

    // ====================================================================
    // Link Establishment with Capability Negotiation (Phase 2 Step 2)
    // ====================================================================

    use crate::capability_exchange::{CapabilityPolicy, CapabilityRequest};
    use zp_core::capability_grant::GrantedCapability;
    use zp_core::policy::TrustTier;

    #[tokio::test]
    async fn test_establish_link_with_capabilities() {
        let alice_id = MeshIdentity::generate();
        let bob_id = MeshIdentity::generate();
        let alice_node = MeshNode::new(alice_id);

        let policy = CapabilityPolicy::allow_all();
        let our_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::MeshSend {
                destinations: vec!["*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        let result = alice_node
            .establish_link(&bob_id, &policy, &our_request, &their_request)
            .await
            .unwrap();

        // We granted MeshSend to peer
        assert!(!result.responder_grants.is_empty());
        // We got Read from peer (they offered Read, we requested Read)
        assert!(!result.initiator_grants.is_empty());

        // Verify the link is stored
        let links = alice_node.links.read().await;
        assert_eq!(links.len(), 1);
        let link = links.values().next().unwrap();
        assert!(link.is_active());
        assert!(!link.remote_grants.is_empty());
    }

    #[tokio::test]
    async fn test_establish_link_deny_all_policy() {
        let alice_id = MeshIdentity::generate();
        let bob_id = MeshIdentity::generate();
        let alice_node = MeshNode::new(alice_id);

        let policy = CapabilityPolicy::deny_all();
        let our_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };
        let their_request = CapabilityRequest {
            requested: vec![
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                GrantedCapability::Write {
                    scope: vec!["*".to_string()],
                },
            ],
            offered: vec![],
            claimed_tier: TrustTier::Tier2,
        };

        let result = alice_node
            .establish_link(&bob_id, &policy, &our_request, &their_request)
            .await
            .unwrap();

        // Everything denied — link is active but with no grants
        assert!(result.responder_grants.is_empty());
        assert_eq!(result.denied.len(), 2);
        assert_eq!(result.effective_tier, TrustTier::Tier0);
    }

    // ====================================================================
    // Policy Propagation (Phase 3 Step 1)
    // ====================================================================

    use crate::envelope::EnvelopeType;
    use crate::policy_sync::{PolicyAdvertisement, PolicyAgreement, PolicyChunk, PolicyModuleInfo};

    fn sample_policy_info(name: &str) -> PolicyModuleInfo {
        PolicyModuleInfo {
            name: name.to_string(),
            content_hash: blake3::hash(name.as_bytes()).to_hex().to_string(),
            size_bytes: 500,
            min_tier: 0,
        }
    }

    #[tokio::test]
    async fn test_advertise_policies_broadcasts() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        // Register two peers
        for _ in 0..2 {
            let peer_id = MeshIdentity::generate();
            let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
            node.register_peer(peer, None).await;
        }

        let modules = vec![sample_policy_info("safety_gate")];
        node.advertise_policies(modules, 1).await.unwrap();

        // Should have sent 2 packets (one per peer)
        let p1 = lo.recv().await.unwrap();
        let p2 = lo.recv().await.unwrap();
        assert!(p1.is_some());
        assert!(p2.is_some());

        // Decode one and verify it's a PolicyAdvertisement envelope
        let pkt = p1.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::PolicyAdvertisement);
    }

    #[tokio::test]
    async fn test_request_policies_sends_pull_request() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        node.request_policies(&peer_hash, vec!["abc123".to_string()], 1)
            .await
            .unwrap();

        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
        let pkt = received.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::PolicyPullRequest);
    }

    #[tokio::test]
    async fn test_handle_advertisement_stores_peer_info() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xABu8; 16];

        let ad = PolicyAdvertisement {
            modules: vec![sample_policy_info("test_policy")],
            sender_tier: 2,
        };

        let envelope = MeshEnvelope::policy_advertisement(&sender_id, &ad, 1).unwrap();
        node.handle_policy_envelope(&envelope, &sender_hash)
            .await
            .unwrap();

        let stored = node.peer_policy_advertisement(&sender_hash).await;
        assert!(stored.is_some());
        let stored = stored.unwrap();
        assert_eq!(stored.modules.len(), 1);
        assert_eq!(stored.modules[0].name, "test_policy");
        assert_eq!(stored.sender_tier, 2);
    }

    #[tokio::test]
    async fn test_propose_policy_agreement_sends_proposal() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let proposal_id = node
            .propose_policy_agreement(&peer_hash, vec!["hash_a".into(), "hash_b".into()], 2)
            .await
            .unwrap();

        assert!(proposal_id.starts_with("pprop-"));

        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
        let pkt = received.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::PolicyProposal);
    }

    #[tokio::test]
    async fn test_handle_policy_chunk_and_completion() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xCDu8; 16];

        let data = vec![0xCAu8, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD];
        let content_hash = blake3::hash(&data).to_hex().to_string();

        // Send 2 chunks
        let chunk0 = PolicyChunk {
            content_hash: content_hash.clone(),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![0xCA, 0xFE, 0xBA],
        };
        let chunk1 = PolicyChunk {
            content_hash: content_hash.clone(),
            chunk_index: 1,
            total_chunks: 2,
            data: vec![0xBE, 0xDE, 0xAD],
        };

        let env0 = MeshEnvelope::policy_chunk(&sender_id, &chunk0, 1).unwrap();
        node.handle_policy_envelope(&env0, &sender_hash)
            .await
            .unwrap();
        assert!(!node.is_transfer_complete(&content_hash).await);

        let env1 = MeshEnvelope::policy_chunk(&sender_id, &chunk1, 2).unwrap();
        node.handle_policy_envelope(&env1, &sender_hash)
            .await
            .unwrap();
        assert!(node.is_transfer_complete(&content_hash).await);
    }

    #[tokio::test]
    async fn test_cleanup_stale_transfers() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        // Manually insert a stale transfer
        {
            let mut transfers = node.active_transfers.write().await;
            let mut state = TransferState::new("stale_hash".to_string(), 100, 3);
            // Backdate the started_at to make it stale
            state.started_at = Utc::now() - chrono::Duration::hours(2);
            transfers.insert("stale_hash".to_string(), state);

            // Also insert a fresh one
            let fresh = TransferState::new("fresh_hash".to_string(), 100, 3);
            transfers.insert("fresh_hash".to_string(), fresh);
        }

        // Cleanup anything older than 1 hour
        node.cleanup_stale_transfers(chrono::Duration::hours(1))
            .await;

        let transfers = node.active_transfers.read().await;
        assert_eq!(transfers.len(), 1);
        assert!(transfers.contains_key("fresh_hash"));
        assert!(!transfers.contains_key("stale_hash"));
    }

    #[tokio::test]
    async fn test_handle_policy_agreement_stores() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xEFu8; 16];

        let agreement = PolicyAgreement {
            proposal_id: "pprop-test".to_string(),
            enforced: vec!["hash_a".to_string()],
            rejected: vec!["hash_b".to_string()],
        };

        let payload = rmp_serde::to_vec_named(&agreement).unwrap();
        let envelope =
            MeshEnvelope::new(&sender_id, EnvelopeType::PolicyAgreement, payload, 1).unwrap();

        node.handle_policy_envelope(&envelope, &sender_hash)
            .await
            .unwrap();

        let stored = node.peer_policy_agreement(&sender_hash).await;
        assert!(stored.is_some());
        let stored = stored.unwrap();
        assert_eq!(stored.enforced, vec!["hash_a"]);
        assert_eq!(stored.rejected, vec!["hash_b"]);
    }

    #[tokio::test]
    async fn test_establish_link_empty_negotiation() {
        let alice_id = MeshIdentity::generate();
        let bob_id = MeshIdentity::generate();
        let alice_node = MeshNode::new(alice_id);

        let policy = CapabilityPolicy::allow_all();
        let empty = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };

        let result = alice_node
            .establish_link(&bob_id, &policy, &empty, &empty)
            .await
            .unwrap();

        // No grants requested = no grants issued
        assert!(result.responder_grants.is_empty());
        assert!(result.initiator_grants.is_empty());
        assert!(result.denied.is_empty());

        // But link is still active
        let links = alice_node.links.read().await;
        assert_eq!(links.len(), 1);
        assert!(links.values().next().unwrap().is_active());
    }

    // ====================================================================
    // Phase 3 Step 2: Delegation transport tests
    // ====================================================================

    #[tokio::test]
    async fn test_send_delegation_creates_packet() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        // Create a delegation grant
        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_1".to_string(),
        );

        let child = grant
            .delegate(
                "charlie".to_string(),
                zp_core::GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "receipt_2".to_string(),
            )
            .unwrap();

        let result = node.send_delegation(&peer_hash, &child).await;
        assert!(result.is_ok());

        // Verify a packet was sent
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
        let pkt = received.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::Delegation);
    }

    #[tokio::test]
    async fn test_handle_delegation_envelope_stores() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();

        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_1".to_string(),
        );

        let compact = crate::envelope::CompactDelegation::from_grant(&grant);
        let envelope = MeshEnvelope::delegation(&sender_id, &compact, 1).unwrap();

        let received = node.handle_delegation_envelope(&envelope).await.unwrap();
        assert_eq!(received.id, grant.id);

        // Should be stored
        let chain = node.get_delegation_chain(&grant.id).await;
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_store_delegation_chain_verifies() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        let root = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_root".to_string(),
        );

        let child = root
            .delegate(
                "charlie".to_string(),
                zp_core::GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "receipt_child".to_string(),
            )
            .unwrap();

        let leaf_id = child.id.clone();
        node.store_delegation_chain(vec![root, child])
            .await
            .unwrap();

        let chain = node.get_delegation_chain(&leaf_id).await;
        assert!(chain.is_some());
        assert_eq!(chain.unwrap().len(), 2);

        let ids = node.delegation_chain_ids().await;
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], leaf_id);
    }

    // ====================================================================
    // Phase 3 Step 3: Collective Audit transport tests
    // ====================================================================

    #[tokio::test]
    async fn test_send_audit_challenge_creates_packet() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let challenge = zp_audit::AuditChallenge::recent(5);
        node.send_audit_challenge(&peer_hash, &challenge)
            .await
            .unwrap();

        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
        let pkt = received.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::AuditChallenge);
    }

    #[tokio::test]
    async fn test_send_audit_response_creates_packet() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let response = zp_audit::AuditResponse {
            challenge_id: "chal-test".to_string(),
            entries: vec![],
            chain_tip: "tip_hash".to_string(),
            total_available: 0,
            has_more: false,
        };
        node.send_audit_response(&peer_hash, &response)
            .await
            .unwrap();

        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
        let pkt = received.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::AuditResponse);
    }

    #[tokio::test]
    async fn test_handle_audit_response_stores_attestation() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xAAu8; 16];

        // Build a response with some compact entries
        let response = zp_audit::AuditResponse {
            challenge_id: "chal-abc".to_string(),
            entries: vec![
                zp_audit::CompactAuditEntry {
                    id: "e1".to_string(),
                    ts: 1000,
                    ph: "genesis".to_string(),
                    eh: "hash1".to_string(),
                    ac: "s:test".to_string(),
                    at: "tool".to_string(),
                    pd: "allow".to_string(),
                    pm: "default".to_string(),
                    sg: None,
                },
                zp_audit::CompactAuditEntry {
                    id: "e2".to_string(),
                    ts: 1001,
                    ph: "hash1".to_string(),
                    eh: "hash2".to_string(),
                    ac: "s:test".to_string(),
                    at: "msg".to_string(),
                    pd: "allow".to_string(),
                    pm: "default".to_string(),
                    sg: None,
                },
            ],
            chain_tip: "hash2".to_string(),
            total_available: 2,
            has_more: false,
        };

        let envelope = MeshEnvelope::audit_response(&sender_id, &response, 1).unwrap();
        node.handle_audit_envelope(&envelope, &sender_hash)
            .await
            .unwrap();

        // Should have stored an attestation
        let attestations = node.peer_attestations(&sender_hash).await;
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].chain_valid);
        assert_eq!(attestations[0].entries_verified, 2);
    }

    #[tokio::test]
    async fn test_handle_audit_attestation_stores() {
        use chrono::DateTime;
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xBBu8; 16];

        let attestation = zp_audit::PeerAuditAttestation {
            id: "att-xyz".to_string(),
            peer: "peer-target".to_string(),
            oldest_hash: "aaa".to_string(),
            newest_hash: "bbb".to_string(),
            entries_verified: 10,
            chain_valid: true,
            signatures_valid: 5,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };

        let envelope = MeshEnvelope::audit_attestation(&sender_id, &attestation, 1).unwrap();
        node.handle_audit_envelope(&envelope, &sender_hash)
            .await
            .unwrap();

        let stored = node.peer_attestations(&sender_hash).await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, "att-xyz");
        assert_eq!(stored[0].peer, "peer-target");
        assert!(stored[0].chain_valid);
    }

    #[tokio::test]
    async fn test_broadcast_audit_attestation() {
        use chrono::DateTime;
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        // Register two peers
        for _ in 0..2 {
            let peer_id = MeshIdentity::generate();
            let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
            node.register_peer(peer, None).await;
        }

        let attestation = zp_audit::PeerAuditAttestation {
            id: "att-broadcast".to_string(),
            peer: "peer-verified".to_string(),
            oldest_hash: "first".to_string(),
            newest_hash: "last".to_string(),
            entries_verified: 3,
            chain_valid: true,
            signatures_valid: 1,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };

        node.broadcast_audit_attestation(&attestation)
            .await
            .unwrap();

        // Should have 2 packets (one per peer)
        let p1 = lo.recv().await.unwrap();
        let p2 = lo.recv().await.unwrap();
        assert!(p1.is_some());
        assert!(p2.is_some());

        // Decode one and verify
        let pkt = p1.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(envelope.envelope_type, EnvelopeType::AuditAttestation);
    }

    #[tokio::test]
    async fn test_handle_audit_response_broken_chain() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xCCu8; 16];

        // Build a response with broken chain links
        let response = zp_audit::AuditResponse {
            challenge_id: "chal-broken".to_string(),
            entries: vec![
                zp_audit::CompactAuditEntry {
                    id: "e1".to_string(),
                    ts: 1000,
                    ph: "genesis".to_string(),
                    eh: "hash1".to_string(),
                    ac: "s:test".to_string(),
                    at: "tool".to_string(),
                    pd: "allow".to_string(),
                    pm: "default".to_string(),
                    sg: None,
                },
                zp_audit::CompactAuditEntry {
                    id: "e2".to_string(),
                    ts: 1001,
                    ph: "TAMPERED".to_string(), // broken link!
                    eh: "hash2".to_string(),
                    ac: "s:test".to_string(),
                    at: "msg".to_string(),
                    pd: "allow".to_string(),
                    pm: "default".to_string(),
                    sg: None,
                },
            ],
            chain_tip: "hash2".to_string(),
            total_available: 2,
            has_more: false,
        };

        let envelope = MeshEnvelope::audit_response(&sender_id, &response, 1).unwrap();
        node.handle_audit_envelope(&envelope, &sender_hash)
            .await
            .unwrap();

        // Attestation should exist but chain_valid should be false
        let attestations = node.peer_attestations(&sender_hash).await;
        assert_eq!(attestations.len(), 1);
        assert!(!attestations[0].chain_valid);
    }

    #[tokio::test]
    async fn test_all_attestations() {
        use chrono::DateTime;
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender1 = MeshIdentity::generate();
        let sender2 = MeshIdentity::generate();
        let hash1 = [0x11u8; 16];
        let hash2 = [0x22u8; 16];

        let att1 = zp_audit::PeerAuditAttestation {
            id: "att-1".to_string(),
            peer: "p1".to_string(),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 1,
            chain_valid: true,
            signatures_valid: 0,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };
        let att2 = zp_audit::PeerAuditAttestation {
            id: "att-2".to_string(),
            peer: "p2".to_string(),
            oldest_hash: "c".to_string(),
            newest_hash: "d".to_string(),
            entries_verified: 2,
            chain_valid: true,
            signatures_valid: 1,
            timestamp: DateTime::from_timestamp(1700000000, 0).unwrap(),
            signature: None,
        };

        let env1 = MeshEnvelope::audit_attestation(&sender1, &att1, 1).unwrap();
        let env2 = MeshEnvelope::audit_attestation(&sender2, &att2, 2).unwrap();

        node.handle_audit_envelope(&env1, &hash1).await.unwrap();
        node.handle_audit_envelope(&env2, &hash2).await.unwrap();

        let all = node.all_attestations().await;
        assert_eq!(all.len(), 2);
        assert!(all.contains_key(&hash1));
        assert!(all.contains_key(&hash2));
    }

    // ====================================================================
    // Phase 3 Step 4: Reputation transport tests
    // ====================================================================

    #[tokio::test]
    async fn test_record_and_compute_reputation() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let peer_hash = [0xAAu8; 16];

        // Record some signals
        let n = chrono::Utc::now();
        node.record_reputation_signal(
            &peer_hash,
            crate::reputation::signal_from_receipt("r1", true, n),
        )
        .await;
        node.record_reputation_signal(
            &peer_hash,
            crate::reputation::signal_from_delegation("d1", true, n),
        )
        .await;

        let score = node.compute_peer_reputation(&peer_hash).await;
        assert!(score.score > 0.5);
        assert_eq!(score.positive_signals, 2);
        assert_eq!(score.negative_signals, 0);
    }

    #[tokio::test]
    async fn test_compute_unknown_peer_reputation() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let unknown = [0xFFu8; 16];

        let score = node.compute_peer_reputation(&unknown).await;
        assert_eq!(score.grade, crate::reputation::ReputationGrade::Unknown);
    }

    #[tokio::test]
    async fn test_broadcast_reputation_summary() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        // Register a peer
        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let _peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        // Record some signals about a different peer (the "about" peer)
        let about_hash = [0xBBu8; 16];
        let n = chrono::Utc::now();
        node.record_reputation_signal(
            &about_hash,
            crate::reputation::signal_from_receipt("r1", true, n),
        )
        .await;

        node.broadcast_reputation_summary(&about_hash)
            .await
            .unwrap();

        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
        let pkt = received.unwrap();
        let envelope = MeshEnvelope::from_msgpack(&pkt.data).unwrap();
        assert_eq!(
            envelope.envelope_type,
            crate::envelope::EnvelopeType::ReputationSummary
        );
    }

    #[tokio::test]
    async fn test_handle_reputation_envelope_stores() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let sender_id = MeshIdentity::generate();
        let sender_hash = [0xCCu8; 16];

        let summary = crate::reputation::CompactReputationSummary {
            peer: "target_peer".to_string(),
            sc: 0.85,
            gr: "E".to_string(),
            ps: 10,
            ns: 1,
            ts: 1700000000,
        };

        let envelope = MeshEnvelope::reputation_summary(&sender_id, &summary, 1).unwrap();
        node.handle_reputation_envelope(&envelope, &sender_hash)
            .await
            .unwrap();

        let stored = node.received_summaries_from(&sender_hash).await;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].peer, "target_peer");
        assert!((stored[0].sc - 0.85).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_all_peer_reputations() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        // Register two peers
        let peer1_id = MeshIdentity::generate();
        let peer1 = PeerIdentity::from_combined_key(&peer1_id.combined_public_key(), 1).unwrap();
        let hash1 = peer1.destination_hash;
        node.register_peer(peer1, None).await;

        let peer2_id = MeshIdentity::generate();
        let peer2 = PeerIdentity::from_combined_key(&peer2_id.combined_public_key(), 2).unwrap();
        let hash2 = peer2.destination_hash;
        node.register_peer(peer2, None).await;

        // Record signals for peer1 only
        let n = chrono::Utc::now();
        node.record_reputation_signal(
            &hash1,
            crate::reputation::signal_from_receipt("r1", true, n),
        )
        .await;

        let all = node.all_peer_reputations().await;
        assert_eq!(all.len(), 2);
        // Peer1 should have signals, peer2 should be unknown
        assert!(all[&hash1].positive_signals > 0);
        assert_eq!(
            all[&hash2].grade,
            crate::reputation::ReputationGrade::Unknown
        );
    }

    #[tokio::test]
    async fn test_update_reputation_from_attestations() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);
        let peer_hash = [0xDDu8; 16];
        let sender_id = MeshIdentity::generate();

        // Simulate receiving an audit response that creates an attestation
        let response = zp_audit::AuditResponse {
            challenge_id: "chal-rep".to_string(),
            entries: vec![zp_audit::CompactAuditEntry {
                id: "e1".to_string(),
                ts: 1000,
                ph: "genesis".to_string(),
                eh: "hash1".to_string(),
                ac: "s:test".to_string(),
                at: "tool".to_string(),
                pd: "allow".to_string(),
                pm: "default".to_string(),
                sg: None,
            }],
            chain_tip: "hash1".to_string(),
            total_available: 1,
            has_more: false,
        };

        let envelope = MeshEnvelope::audit_response(&sender_id, &response, 1).unwrap();
        node.handle_audit_envelope(&envelope, &peer_hash)
            .await
            .unwrap();

        // Now update reputation from attestations
        node.update_reputation_from_attestations(&peer_hash).await;

        let score = node.compute_peer_reputation(&peer_hash).await;
        // Should have a positive audit signal
        assert!(score.positive_signals > 0);
    }

    #[tokio::test]
    async fn test_store_delegation_chain_rejects_invalid() {
        let node_id = MeshIdentity::generate();
        let node = MeshNode::new(node_id);

        // Create a chain with broken link
        let root = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        );

        let mut fake_child = zp_core::CapabilityGrant::new(
            "bob".to_string(),
            "charlie".to_string(),
            zp_core::GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r2".to_string(),
        );
        fake_child.parent_grant_id = Some("wrong-parent-id".to_string());
        fake_child.delegation_depth = 1;

        let result = node.store_delegation_chain(vec![root, fake_child]).await;
        assert!(result.is_err());
    }
}
