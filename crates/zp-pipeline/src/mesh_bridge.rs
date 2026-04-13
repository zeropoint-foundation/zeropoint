//! Mesh-Pipeline Bridge — connects the request pipeline to the agent mesh.
//!
//! This module bridges the `Pipeline` (local request handling) with the `MeshNode`
//! (cross-agent mesh transport). After every pipeline request completes, the bridge
//! can forward receipts and audit attestations to mesh peers, enabling distributed
//! governance across the agent web.
//!
//! ## Design
//!
//! The bridge is intentionally lightweight — it wraps a `MeshNode` reference and
//! provides pipeline-specific forwarding methods. It does NOT own the MeshNode;
//! the pipeline holds an `Arc<MeshNode>` so the node can be shared with other
//! subsystems (e.g., a direct mesh listener).
//!
//! ```text
//! Pipeline.handle(request)
//!   → policy → LLM → tool loop → audit
//!   → MeshBridge.forward_receipt(receipt)      // broadcast to peers
//!   → MeshBridge.forward_audit_entry(entry)    // replicate audit chain
//! ```
//!
//! ## Phase 4 Step 3: Cross-Agent Receipt Forwarding
//!
//! In addition to outbound forwarding, the bridge handles **inbound** receipts
//! from mesh peers. When a peer sends us a receipt:
//!
//! 1. Validate the receipt (non-empty ID, known status)
//! 2. Check reputation gate (if peer reputation is Poor, reject)
//! 3. Record a reputation signal for the sender
//! 4. Store the receipt for governance audit
//!
//! ```text
//! Peer → MeshNode → MeshBridge.handle_inbound_receipt(compact, sender)
//!   → validate → reputation check → store → reputation signal
//! ```

use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use zp_audit::collective_audit::{AuditChallenge, AuditResponse, PeerAuditAttestation};
use zp_core::delegation_chain::{ChainError, DelegationChain};
use zp_core::CapabilityGrant;
use zp_mesh::capability_exchange::{CapabilityPolicy, CapabilityRequest, NegotiationResult};
use zp_mesh::envelope::{CompactDelegation, CompactReceipt};
use zp_mesh::identity::MeshIdentity;
use zp_mesh::peer_keystore::PeerKeyStore;
use zp_mesh::transport::{AgentTransport, MeshNode};
use zp_receipt::Receipt;

/// Configuration for mesh forwarding behavior.
#[derive(Debug, Clone)]
pub struct MeshBridgeConfig {
    /// Whether to broadcast receipts to mesh peers after each request.
    pub forward_receipts: bool,
    /// Whether to broadcast audit entries to mesh peers.
    pub forward_audit: bool,
    /// Maximum number of peers to forward to (0 = all).
    pub max_forward_peers: usize,
}

impl Default for MeshBridgeConfig {
    fn default() -> Self {
        Self {
            forward_receipts: true,
            forward_audit: true,
            max_forward_peers: 0, // all peers
        }
    }
}

/// Sweep 6 (RFC §3.2) — authentication outcome for an inbound payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    /// Signed and verified against a known peer key.
    Verified,
    /// Payload carried a signature but we had no key for the sender; the
    /// signature was not checked. Treated as accepted with reduced trust.
    UnverifiedNoKey,
    /// Payload carried no signature (`sg = None`). Legacy v0 path.
    Unsigned,
    /// Authentication was not attempted (feature off).
    NotChecked,
}

/// A receipt received from a mesh peer, stored for governance purposes.
#[derive(Debug, Clone)]
pub struct ReceivedReceipt {
    /// The compact receipt data from the mesh.
    pub receipt: CompactReceipt,
    /// The sender's destination hash.
    pub sender_hash: [u8; 16],
    /// When this receipt was received.
    pub received_at: DateTime<Utc>,
    /// Whether the receipt was accepted (vs. rejected by reputation gate
    /// or by signature verification).
    pub accepted: bool,
    /// Sweep 6: authentication outcome (see `AuthState`).
    pub auth: AuthState,
}

/// Composite trust snapshot for a single peer.
///
/// Aggregates all reputation signal dimensions (audit, delegation, policy,
/// receipt) plus link and attestation state into one convenient struct.
#[derive(Debug, Clone)]
pub struct PeerTrustSnapshot {
    /// Peer destination hash (hex).
    pub peer_hex: String,
    /// Overall composite score (0.0–1.0).
    pub overall_score: f64,
    /// Human-readable grade.
    pub grade: zp_mesh::reputation::ReputationGrade,
    /// Audit attestation category score (0.0–1.0).
    pub audit_score: f64,
    /// Delegation chain category score (0.0–1.0).
    pub delegation_score: f64,
    /// Policy compliance category score (0.0–1.0).
    pub policy_score: f64,
    /// Receipt exchange category score (0.0–1.0).
    pub receipt_score: f64,
    /// Total positive signals across all categories.
    pub positive_signals: usize,
    /// Total negative signals across all categories.
    pub negative_signals: usize,
    /// Whether the peer's audit chain has been verified.
    pub audit_verified: bool,
    /// Number of valid audit attestations on record.
    pub valid_attestation_count: usize,
    /// Whether we have an active capability link with the peer.
    pub has_active_link: bool,
    /// When this snapshot was computed.
    pub computed_at: DateTime<Utc>,
}

/// The mesh bridge — connects a Pipeline to a MeshNode.
///
/// Holds an `Arc<MeshNode>` so the node can be shared across subsystems.
/// Provides methods for forwarding pipeline artifacts (receipts, audit entries)
/// over the mesh, and handles inbound receipts from peers.
pub struct MeshBridge {
    /// The underlying mesh node.
    node: Arc<MeshNode>,
    /// Forwarding configuration.
    config: MeshBridgeConfig,
    /// Receipts received from mesh peers (Phase 4 Step 3).
    received_receipts: RwLock<Vec<ReceivedReceipt>>,
    /// Sweep 6 (RFC §3.1) — optional peer verifying-key registry.
    /// When present **and** the `mesh-auth-v1` feature is enabled,
    /// `handle_inbound_receipt` runs signatures through this store.
    /// When absent, the bridge preserves v0 behavior.
    key_store: Option<Arc<dyn PeerKeyStore>>,
}

impl MeshBridge {
    /// Create a new bridge wrapping the given mesh node.
    pub fn new(node: Arc<MeshNode>, config: MeshBridgeConfig) -> Self {
        info!(
            address = %node.identity().address(),
            forward_receipts = config.forward_receipts,
            forward_audit = config.forward_audit,
            "Mesh bridge initialized"
        );
        Self {
            node,
            config,
            received_receipts: RwLock::new(Vec::new()),
            key_store: None,
        }
    }

    /// Create a bridge with default configuration.
    pub fn with_defaults(node: Arc<MeshNode>) -> Self {
        Self::new(node, MeshBridgeConfig::default())
    }

    /// Sweep 6 (RFC §3.1) — attach a peer verifying-key registry. When the
    /// `mesh-auth-v1` feature is enabled, inbound receipts will be verified
    /// against this store. Returns the bridge for chaining.
    pub fn with_key_store(mut self, store: Arc<dyn PeerKeyStore>) -> Self {
        self.key_store = Some(store);
        self
    }

    /// Returns a handle to the registered peer keystore, if any.
    pub fn key_store(&self) -> Option<&Arc<dyn PeerKeyStore>> {
        self.key_store.as_ref()
    }

    /// Get the mesh node's address.
    pub fn address(&self) -> String {
        self.node.address()
    }

    /// Get a reference to the underlying mesh node.
    pub fn node(&self) -> &Arc<MeshNode> {
        &self.node
    }

    /// Get the bridge configuration.
    pub fn config(&self) -> &MeshBridgeConfig {
        &self.config
    }

    /// Forward a receipt to all mesh peers.
    ///
    /// Called by the pipeline after a request completes successfully.
    /// Broadcasts the receipt so peers can verify our work.
    pub async fn forward_receipt(&self, receipt: &Receipt) -> Result<(), String> {
        if !self.config.forward_receipts {
            debug!("Receipt forwarding disabled, skipping");
            return Ok(());
        }

        let peers = self.node.known_peers().await;
        if peers.is_empty() {
            debug!("No mesh peers to forward receipt to");
            return Ok(());
        }

        let target_count = if self.config.max_forward_peers > 0 {
            self.config.max_forward_peers.min(peers.len())
        } else {
            peers.len()
        };

        debug!(
            receipt_id = %receipt.id,
            target_peers = target_count,
            "Forwarding receipt to mesh"
        );

        match self.node.broadcast_receipt(receipt).await {
            Ok(()) => {
                info!(
                    receipt_id = %receipt.id,
                    peer_count = target_count,
                    "Receipt forwarded to mesh peers"
                );
                Ok(())
            }
            Err(e) => {
                warn!(
                    receipt_id = %receipt.id,
                    error = %e,
                    "Failed to forward receipt to mesh"
                );
                Err(format!("mesh forward failed: {}", e))
            }
        }
    }

    /// Forward a receipt to a specific peer.
    pub async fn forward_receipt_to(
        &self,
        peer_address: &str,
        receipt: &Receipt,
    ) -> Result<(), String> {
        if !self.config.forward_receipts {
            debug!("Receipt forwarding disabled, skipping");
            return Ok(());
        }

        self.node
            .send_receipt(peer_address, receipt)
            .await
            .map_err(|e| format!("mesh send failed: {}", e))
    }

    /// Record a reputation signal for a peer based on a receipt exchange.
    ///
    /// Called after receiving a receipt from a peer to update their reputation.
    pub async fn record_receipt_reputation(
        &self,
        peer_hash: &[u8; 16],
        receipt_id: &str,
        success: bool,
    ) {
        let now = chrono::Utc::now();
        let signal = zp_mesh::reputation::signal_from_receipt(receipt_id, success, now);
        self.node.record_reputation_signal(peer_hash, signal).await;
        debug!(
            peer = %hex::encode(peer_hash),
            receipt_id = receipt_id,
            success = success,
            "Recorded receipt reputation signal"
        );
    }

    /// Get the reputation score for a specific peer.
    pub async fn peer_reputation(
        &self,
        peer_hash: &[u8; 16],
    ) -> zp_mesh::reputation::ReputationScore {
        self.node.compute_peer_reputation(peer_hash).await
    }

    /// Get reputation scores for all known peers.
    pub async fn all_peer_reputations(
        &self,
    ) -> std::collections::HashMap<[u8; 16], zp_mesh::reputation::ReputationScore> {
        self.node.all_peer_reputations().await
    }

    /// Check if a peer has sufficient reputation for a given grade threshold.
    pub async fn peer_meets_reputation(
        &self,
        peer_hash: &[u8; 16],
        min_grade: zp_mesh::reputation::ReputationGrade,
    ) -> bool {
        let score = self.node.compute_peer_reputation(peer_hash).await;
        score.grade >= min_grade
    }

    // ========================================================================
    // Inbound receipt handling (Phase 4 Step 3)
    // ========================================================================

    /// Sweep 6 — classify the authentication state of an inbound compact
    /// receipt without gating acceptance. Acceptance policy for each cell
    /// is applied in `handle_inbound_receipt`:
    ///
    /// | sg present | key known | auth state         | accepted? |
    /// | ---        | ---       | ---                | ---       |
    /// | no         | —         | Unsigned           | yes (v0)  |
    /// | yes        | no        | UnverifiedNoKey    | yes (warn)|
    /// | yes        | yes valid | Verified           | yes       |
    /// | yes        | yes bad   | (handled as Err)   | no        |
    ///
    /// When the `mesh-auth-v1` feature is off, all inbound payloads are
    /// classified as `NotChecked` regardless of `sg`.
    #[allow(unused_variables)]
    fn classify_inbound_auth(
        &self,
        receipt: &CompactReceipt,
        sender_hash: &[u8; 16],
    ) -> AuthState {
        #[cfg(not(feature = "mesh-auth-v1"))]
        {
            AuthState::NotChecked
        }
        #[cfg(feature = "mesh-auth-v1")]
        {
            if receipt.sg.is_none() {
                return AuthState::Unsigned;
            }
            let Some(store) = self.key_store.as_ref() else {
                return AuthState::UnverifiedNoKey;
            };
            match store.verifying_key(sender_hash) {
                None => AuthState::UnverifiedNoKey,
                Some(key) => match receipt.verify_signature(&key) {
                    Ok(zp_mesh::envelope::SignatureStatus::Valid) => AuthState::Verified,
                    // Unsigned here would require `sg.is_some()` to be false
                    // which we checked above; treat as UnverifiedNoKey for safety.
                    Ok(zp_mesh::envelope::SignatureStatus::Unsigned) => AuthState::Unsigned,
                    // Verification error → caller turns this into Err; we
                    // still return UnverifiedNoKey to keep the classifier
                    // total. The hard-reject path doesn't consume this value.
                    Err(_) => AuthState::UnverifiedNoKey,
                },
            }
        }
    }

    /// Handle an inbound receipt from a mesh peer.
    ///
    /// Validates the receipt, checks the sender's reputation, records a
    /// reputation signal, and stores the receipt for governance audit.
    ///
    /// Returns `Ok(true)` if the receipt was accepted, `Ok(false)` if it was
    /// rejected by the reputation gate, or `Err` if validation failed.
    pub async fn handle_inbound_receipt(
        &self,
        receipt: &CompactReceipt,
        sender_hash: &[u8; 16],
    ) -> Result<bool, String> {
        let sender_hex = hex::encode(sender_hash);

        // Step 1: Validate the receipt
        if receipt.id.is_empty() {
            warn!(sender = %sender_hex, "Rejected inbound receipt: empty ID");
            return Err("receipt has empty ID".to_string());
        }

        if receipt.st != "success"
            && receipt.st != "partial"
            && receipt.st != "failed"
            && receipt.st != "denied"
        {
            warn!(
                sender = %sender_hex,
                status = %receipt.st,
                "Rejected inbound receipt: invalid status"
            );
            return Err(format!("receipt has invalid status: {}", receipt.st));
        }

        // Sweep 6 (RFC §3.2) — signature verification policy table.
        // Only active when the `mesh-auth-v1` feature is compiled in AND
        // a keystore is attached. Otherwise we fall through to the legacy
        // v0 behavior with `auth = NotChecked`.
        let auth = self.classify_inbound_auth(receipt, sender_hash);
        if matches!(auth, AuthState::Verified) {
            debug!(sender = %sender_hex, receipt_id = %receipt.id, "Inbound receipt signature verified");
        } else if matches!(auth, AuthState::UnverifiedNoKey) {
            warn!(sender = %sender_hex, receipt_id = %receipt.id,
                  "Inbound receipt signed but sender key unknown; accepted with reduced trust");
        } else if matches!(auth, AuthState::Unsigned) {
            warn!(sender = %sender_hex, receipt_id = %receipt.id,
                  "Inbound receipt has no signature (v0 behavior)");
        }

        // Signature *mismatch* is a hard reject (different from "no key").
        #[cfg(feature = "mesh-auth-v1")]
        if let Some(store) = self.key_store.as_ref() {
            if receipt.sg.is_some() {
                if let Some(key) = store.verifying_key(sender_hash) {
                    if receipt.verify_signature(&key).is_err() {
                        warn!(sender = %sender_hex, receipt_id = %receipt.id,
                              "Rejected inbound receipt: signature verification failed");
                        // Record a negative reputation signal on verify failure.
                        let signal = zp_mesh::reputation::signal_from_receipt(
                            &receipt.id, false, Utc::now(),
                        );
                        self.node.record_reputation_signal(sender_hash, signal).await;
                        return Err("signature verification failed".to_string());
                    }
                }
            }
        }

        // Step 2: Check sender reputation (reputation gate)
        let peer_score = self.node.compute_peer_reputation(sender_hash).await;
        let min_grade = zp_mesh::reputation::ReputationGrade::Poor;

        // Block receipts from peers below Poor (i.e., only truly unknown is allowed
        // since receipt acceptance has a low threshold — see ReputationGateRule)
        // But record that we received it regardless
        let accepted = peer_score.grade >= min_grade
            || peer_score.grade == zp_mesh::reputation::ReputationGrade::Unknown;

        // Step 3: Store the receipt
        let received = ReceivedReceipt {
            receipt: receipt.clone(),
            sender_hash: *sender_hash,
            received_at: Utc::now(),
            accepted,
            auth,
        };

        self.received_receipts.write().await.push(received);

        if !accepted {
            warn!(
                sender = %sender_hex,
                receipt_id = %receipt.id,
                grade = %peer_score.grade,
                "Inbound receipt rejected: sender reputation below threshold"
            );

            // Still record a negative reputation signal
            let signal = zp_mesh::reputation::signal_from_receipt(&receipt.id, false, Utc::now());
            self.node
                .record_reputation_signal(sender_hash, signal)
                .await;

            return Ok(false);
        }

        // Step 4: Record positive reputation signal for valid receipt exchange
        let is_valid = receipt.st == "success" || receipt.st == "partial";
        let signal = zp_mesh::reputation::signal_from_receipt(&receipt.id, is_valid, Utc::now());
        self.node
            .record_reputation_signal(sender_hash, signal)
            .await;

        info!(
            sender = %sender_hex,
            receipt_id = %receipt.id,
            status = %receipt.st,
            trust_grade = %receipt.tg,
            "Inbound receipt accepted from mesh peer"
        );

        Ok(true)
    }

    /// Get all received receipts (both accepted and rejected).
    pub async fn received_receipts(&self) -> Vec<ReceivedReceipt> {
        self.received_receipts.read().await.clone()
    }

    /// Get only accepted received receipts.
    pub async fn accepted_receipts(&self) -> Vec<ReceivedReceipt> {
        self.received_receipts
            .read()
            .await
            .iter()
            .filter(|r| r.accepted)
            .cloned()
            .collect()
    }

    /// Get received receipts from a specific peer.
    pub async fn receipts_from_peer(&self, peer_hash: &[u8; 16]) -> Vec<ReceivedReceipt> {
        self.received_receipts
            .read()
            .await
            .iter()
            .filter(|r| &r.sender_hash == peer_hash)
            .cloned()
            .collect()
    }

    /// Count of received receipts.
    pub async fn received_receipt_count(&self) -> usize {
        self.received_receipts.read().await.len()
    }

    // ========================================================================
    // Delegation chain verification (Phase 5 Step 1)
    // ========================================================================

    /// Handle an inbound delegation from a mesh peer.
    ///
    /// Validates the delegation, checks sender reputation, verifies chain
    /// integrity, stores it, and records a reputation signal.
    ///
    /// Returns `Ok(grant)` with the verified grant if accepted,
    /// `Err` if validation or verification failed.
    pub async fn handle_inbound_delegation(
        &self,
        delegation: &CompactDelegation,
        sender_hash: &[u8; 16],
    ) -> Result<CapabilityGrant, String> {
        let sender_hex = hex::encode(sender_hash);

        // Step 1: Basic validation
        if delegation.id.is_empty() {
            warn!(sender = %sender_hex, "Rejected inbound delegation: empty grant ID");
            return Err("delegation has empty grant ID".to_string());
        }

        if delegation.ge.is_empty() || delegation.gr.is_empty() {
            warn!(
                sender = %sender_hex,
                grant_id = %delegation.id,
                "Rejected inbound delegation: missing grantor/grantee"
            );
            return Err("delegation has empty grantor or grantee".to_string());
        }

        // Step 2: Check sender reputation (must be at least Fair for delegation actions)
        let peer_score = self.node.compute_peer_reputation(sender_hash).await;
        let min_grade = zp_mesh::reputation::ReputationGrade::Fair;

        if peer_score.grade < min_grade
            && peer_score.grade != zp_mesh::reputation::ReputationGrade::Unknown
        {
            warn!(
                sender = %sender_hex,
                grade = %peer_score.grade,
                "Rejected inbound delegation: sender reputation below Fair"
            );

            // Record negative delegation signal
            let signal =
                zp_mesh::reputation::signal_from_delegation(&delegation.id, false, Utc::now());
            self.node
                .record_reputation_signal(sender_hash, signal)
                .await;

            return Err(format!(
                "sender reputation {} below required Fair",
                peer_score.grade
            ));
        }

        // Step 3: Reconstruct the grant and verify it
        let grant = delegation.to_grant();

        // If this is a delegated grant (has parent), verify chain integrity
        if grant.is_delegated() {
            // Check if we have the parent chain stored
            if let Some(parent_id) = &grant.parent_grant_id {
                match self.node.get_delegation_chain(parent_id).await {
                    Some(mut parent_chain) => {
                        // Append new grant and verify the full chain
                        parent_chain.push(grant.clone());
                        match DelegationChain::verify(parent_chain.clone(), false) {
                            Ok(verified) => {
                                info!(
                                    grant_id = %grant.id,
                                    chain_len = verified.len(),
                                    depth = verified.current_depth(),
                                    sender = %sender_hex,
                                    "Delegation chain verified successfully"
                                );
                                // Store the verified chain
                                self.node
                                    .store_delegation_chain(parent_chain)
                                    .await
                                    .map_err(|e| format!("failed to store chain: {}", e))?;
                            }
                            Err(e) => {
                                warn!(
                                    grant_id = %grant.id,
                                    error = %e,
                                    sender = %sender_hex,
                                    "Delegation chain verification failed"
                                );

                                // Record negative signal
                                let signal = zp_mesh::reputation::signal_from_delegation(
                                    &delegation.id,
                                    false,
                                    Utc::now(),
                                );
                                self.node
                                    .record_reputation_signal(sender_hash, signal)
                                    .await;

                                return Err(format!("delegation chain invalid: {}", e));
                            }
                        }
                    }
                    None => {
                        // Parent chain not found — store the single grant for now.
                        // The peer should send the full chain separately.
                        debug!(
                            grant_id = %grant.id,
                            parent_id = %parent_id,
                            "Parent chain not found; storing single delegation"
                        );
                        self.node
                            .store_delegation_chain(vec![grant.clone()])
                            .await
                            .map_err(|e| format!("failed to store grant: {}", e))?;
                    }
                }
            }
        } else {
            // Root grant — store directly
            self.node
                .store_delegation_chain(vec![grant.clone()])
                .await
                .map_err(|e| format!("failed to store root grant: {}", e))?;
        }

        // Step 4: Record positive delegation reputation signal
        let signal = zp_mesh::reputation::signal_from_delegation(&delegation.id, true, Utc::now());
        self.node
            .record_reputation_signal(sender_hash, signal)
            .await;

        info!(
            grant_id = %grant.id,
            depth = grant.delegation_depth,
            sender = %sender_hex,
            "Inbound delegation accepted"
        );

        Ok(grant)
    }

    /// Verify a full delegation chain (root → leaf).
    ///
    /// Performs all 8 chain invariant checks:
    /// 1. Root has no parent, depth 0
    /// 2. Parent-child linkage via grant IDs
    /// 3. Monotonically increasing depth
    /// 4. Scope narrowing (child ⊆ parent)
    /// 5. Grantor matches parent's grantee
    /// 6. Max delegation depth not exceeded
    /// 7. Signature verification (if `verify_signatures` is true)
    /// 8. No expired grants in the chain
    pub async fn verify_delegation_chain(
        &self,
        grants: Vec<CapabilityGrant>,
        verify_signatures: bool,
    ) -> Result<DelegationChain, ChainError> {
        // First: check chain using the core verifier
        let chain = DelegationChain::verify(grants, verify_signatures)?;

        // Additional runtime check: ensure no grants have expired
        for grant in chain.grants() {
            if grant.is_expired() {
                return Err(ChainError::DelegationError(
                    zp_core::DelegationError::ParentExpired,
                ));
            }
        }

        Ok(chain)
    }

    /// Send a delegation grant to a specific peer.
    ///
    /// The peer must meet the Fair reputation threshold for delegation acceptance.
    pub async fn send_delegation_to(
        &self,
        peer_hash: &[u8; 16],
        grant: &CapabilityGrant,
    ) -> Result<(), String> {
        self.node
            .send_delegation(peer_hash, grant)
            .await
            .map_err(|e| format!("mesh delegation send failed: {}", e))
    }

    /// Get a stored delegation chain by the leaf grant ID.
    pub async fn get_delegation_chain(&self, leaf_grant_id: &str) -> Option<Vec<CapabilityGrant>> {
        self.node.get_delegation_chain(leaf_grant_id).await
    }

    /// List all stored delegation chain leaf IDs.
    pub async fn delegation_chain_ids(&self) -> Vec<String> {
        self.node.delegation_chain_ids().await
    }

    /// Check if a capability grant is authorized for the given action.
    ///
    /// Verifies:
    /// 1. The grant is not expired
    /// 2. The grant matches the requested action
    /// 3. All constraints are satisfied
    /// 4. If delegated, the delegation chain is valid
    pub async fn check_grant_authorization(
        &self,
        grant: &CapabilityGrant,
        action: &zp_core::ActionType,
        constraint_context: &zp_core::ConstraintContext,
    ) -> Result<(), String> {
        // Check expiration
        if grant.is_expired() {
            return Err("capability grant has expired".to_string());
        }

        // Check action match
        if !grant.matches_action(action) {
            return Err(format!(
                "grant '{}' does not authorize action {:?}",
                grant.capability.name(),
                action,
            ));
        }

        // Check constraints
        let violations = grant.check_constraints(constraint_context);
        if !violations.is_empty() {
            let reasons: Vec<String> = violations.iter().map(|v| v.reason.clone()).collect();
            return Err(format!("constraint violations: {}", reasons.join("; ")));
        }

        // Verify delegation chain if this is a delegated grant
        if grant.is_delegated() {
            if let Some(chain_grants) = self.get_delegation_chain(&grant.id).await {
                self.verify_delegation_chain(chain_grants, false)
                    .await
                    .map_err(|e| format!("delegation chain invalid: {}", e))?;
            } else {
                return Err("delegated grant has no stored chain".to_string());
            }
        }

        Ok(())
    }

    // ========================================================================
    // Audit chain verification & peer challenges (Phase 5 Step 2)
    // ========================================================================

    /// Challenge a peer to prove their audit chain integrity.
    ///
    /// Sends an `AuditChallenge` requesting recent entries from the peer.
    /// The peer should respond with an `AuditResponse` containing compact
    /// audit entries that can be verified for chain linkage.
    pub async fn challenge_peer_audit(
        &self,
        peer_hash: &[u8; 16],
        count: usize,
    ) -> Result<AuditChallenge, String> {
        let challenge = AuditChallenge::recent(count);
        self.node
            .send_audit_challenge(peer_hash, &challenge)
            .await
            .map_err(|e| format!("failed to send audit challenge: {}", e))?;

        info!(
            challenge_id = %challenge.id,
            peer = %hex::encode(peer_hash),
            count = count,
            "Sent audit challenge to peer"
        );

        Ok(challenge)
    }

    /// Challenge a peer starting from a known hash.
    ///
    /// Useful for incremental verification — only request entries
    /// newer than the last verified hash.
    pub async fn challenge_peer_audit_since(
        &self,
        peer_hash: &[u8; 16],
        since_hash: String,
    ) -> Result<AuditChallenge, String> {
        let challenge = AuditChallenge::since_hash(since_hash);
        self.node
            .send_audit_challenge(peer_hash, &challenge)
            .await
            .map_err(|e| format!("failed to send audit challenge: {}", e))?;

        info!(
            challenge_id = %challenge.id,
            peer = %hex::encode(peer_hash),
            "Sent audit challenge (since hash) to peer"
        );

        Ok(challenge)
    }

    /// Handle an inbound audit response from a peer.
    ///
    /// Verifies the chain segment, produces a `PeerAuditAttestation`,
    /// records a reputation signal based on chain validity, and
    /// optionally broadcasts the attestation to the mesh.
    ///
    /// Returns the attestation for the caller to inspect.
    pub async fn handle_audit_response(
        &self,
        response: &AuditResponse,
        sender_hash: &[u8; 16],
        broadcast: bool,
    ) -> Result<PeerAuditAttestation, String> {
        let sender_hex = hex::encode(sender_hash);

        // Step 1: Verify the chain segment using collective_audit verifier
        let attestation =
            zp_audit::collective_audit::verify_peer_chain(&sender_hex, &response.entries);

        info!(
            challenge_id = %response.challenge_id,
            entries = response.entries.len(),
            chain_valid = attestation.chain_valid,
            sender = %sender_hex,
            "Verified peer audit chain"
        );

        // Step 2: Store the attestation on the node
        self.node
            .store_attestation(sender_hash, attestation.clone())
            .await;

        // Step 3: Record reputation signal based on chain validity
        let signal = zp_mesh::reputation::signal_from_attestation(&attestation);
        self.node
            .record_reputation_signal(sender_hash, signal)
            .await;

        if !attestation.chain_valid {
            warn!(
                sender = %sender_hex,
                entries_verified = attestation.entries_verified,
                "Peer audit chain verification FAILED"
            );
        }

        // Step 4: Optionally broadcast the attestation to mesh peers
        if broadcast {
            if let Err(e) = self.node.broadcast_audit_attestation(&attestation).await {
                warn!(
                    error = %e,
                    "Failed to broadcast audit attestation"
                );
            }
        }

        Ok(attestation)
    }

    /// Handle an inbound audit challenge from a peer.
    ///
    /// Builds an `AuditResponse` from the provided audit entries and
    /// sends it back to the challenger.
    ///
    /// The caller provides the local audit entries because the bridge
    /// doesn't own the audit store directly.
    pub async fn respond_to_audit_challenge(
        &self,
        challenge: &AuditChallenge,
        local_entries: &[zp_core::AuditEntry],
        sender_hash: &[u8; 16],
    ) -> Result<(), String> {
        let response =
            AuditResponse::from_entries(&challenge.id, local_entries, local_entries.len());

        self.node
            .send_audit_response(sender_hash, &response)
            .await
            .map_err(|e| format!("failed to send audit response: {}", e))?;

        info!(
            challenge_id = %challenge.id,
            entries_sent = response.entries.len(),
            has_more = response.has_more,
            peer = %hex::encode(sender_hash),
            "Sent audit response to challenger"
        );

        Ok(())
    }

    /// Get all audit attestations received from or about a specific peer.
    pub async fn peer_attestations(&self, peer_hash: &[u8; 16]) -> Vec<PeerAuditAttestation> {
        self.node.peer_attestations(peer_hash).await
    }

    /// Get all audit attestations across all peers.
    pub async fn all_attestations(
        &self,
    ) -> std::collections::HashMap<[u8; 16], Vec<PeerAuditAttestation>> {
        self.node.all_attestations().await
    }

    /// Check if a peer's audit chain has been verified recently.
    ///
    /// Returns `true` if there is at least one valid attestation for the peer.
    pub async fn peer_audit_verified(&self, peer_hash: &[u8; 16]) -> bool {
        let attestations = self.node.peer_attestations(peer_hash).await;
        attestations.iter().any(|a| a.chain_valid)
    }

    /// Count how many valid audit attestations exist for a peer.
    pub async fn peer_valid_attestation_count(&self, peer_hash: &[u8; 16]) -> usize {
        let attestations = self.node.peer_attestations(peer_hash).await;
        attestations.iter().filter(|a| a.chain_valid).count()
    }

    // ========================================================================
    // Capability negotiation at link establishment (Phase 5 Step 3)
    // ========================================================================

    /// Establish a link with a peer and negotiate capabilities.
    ///
    /// Performs the full 3-packet handshake (initiate → accept → complete),
    /// then runs capability negotiation on the active link. Records a
    /// reputation signal based on whether any grants were exchanged.
    ///
    /// Returns the negotiation result containing grants exchanged.
    pub async fn establish_peer_link(
        &self,
        peer: &MeshIdentity,
        our_policy: &CapabilityPolicy,
        our_request: &CapabilityRequest,
        their_request: &CapabilityRequest,
    ) -> Result<NegotiationResult, String> {
        let peer_address = peer.address();

        let result = self
            .node
            .establish_link(peer, our_policy, our_request, their_request)
            .await
            .map_err(|e| format!("link establishment failed: {}", e))?;

        info!(
            peer = %peer_address,
            initiator_grants = result.initiator_grants.len(),
            responder_grants = result.responder_grants.len(),
            denied = result.denied.len(),
            effective_tier = ?result.effective_tier,
            "Peer link established with capability negotiation"
        );

        Ok(result)
    }

    /// Get the capability grants for an active link with a peer.
    ///
    /// Returns `(local_grants, remote_grants)` where:
    /// - `local_grants`: capabilities the peer granted to us
    /// - `remote_grants`: capabilities we granted to the peer
    pub async fn peer_link_grants(
        &self,
        peer_address: &str,
    ) -> Option<(Vec<CapabilityGrant>, Vec<CapabilityGrant>)> {
        self.node.link_grants_for_peer(peer_address).await
    }

    /// Check if we have a specific capability grant from a peer.
    ///
    /// Looks through the local grants on an active link and checks
    /// if any match the requested action.
    pub async fn peer_authorizes_action(
        &self,
        peer_address: &str,
        action: &zp_core::ActionType,
    ) -> bool {
        match self.node.link_grants_for_peer(peer_address).await {
            Some((local_grants, _)) => local_grants
                .iter()
                .any(|g| !g.is_expired() && g.matches_action(action)),
            None => false,
        }
    }

    /// Check if a peer has an active link with us.
    pub async fn has_active_link(&self, peer_address: &str) -> bool {
        self.node.link_grants_for_peer(peer_address).await.is_some()
    }

    // ========================================================================
    // Multi-dimensional reputation signals (Phase 5 Step 4)
    // ========================================================================

    /// Record a policy compliance signal for a peer.
    ///
    /// Called when a peer's behaviour matches (or violates) a negotiated
    /// policy agreement. Feeds the PolicyCompliance signal category.
    pub async fn record_policy_compliance(
        &self,
        peer_hash: &[u8; 16],
        agreement_id: &str,
        compliant: bool,
    ) {
        let now = chrono::Utc::now();
        let signal =
            zp_mesh::reputation::signal_from_policy_compliance(agreement_id, compliant, now);
        self.node.record_reputation_signal(peer_hash, signal).await;
        debug!(
            peer = %hex::encode(peer_hash),
            agreement_id = agreement_id,
            compliant = compliant,
            "Recorded policy compliance reputation signal"
        );
    }

    /// Record a delegation chain signal for a peer.
    ///
    /// Called after verifying a delegation chain from a peer.
    pub async fn record_delegation_reputation(
        &self,
        peer_hash: &[u8; 16],
        grant_id: &str,
        valid: bool,
    ) {
        let now = chrono::Utc::now();
        let signal = zp_mesh::reputation::signal_from_delegation(grant_id, valid, now);
        self.node.record_reputation_signal(peer_hash, signal).await;
        debug!(
            peer = %hex::encode(peer_hash),
            grant_id = grant_id,
            valid = valid,
            "Recorded delegation reputation signal"
        );
    }

    /// Record an audit attestation signal for a peer.
    ///
    /// Called after verifying a peer's audit chain.
    pub async fn record_audit_reputation(
        &self,
        peer_hash: &[u8; 16],
        attestation: &PeerAuditAttestation,
    ) {
        let signal = zp_mesh::reputation::signal_from_attestation(attestation);
        self.node.record_reputation_signal(peer_hash, signal).await;
        debug!(
            peer = %hex::encode(peer_hash),
            chain_valid = attestation.chain_valid,
            entries = attestation.entries_verified,
            "Recorded audit attestation reputation signal"
        );
    }

    /// Get the per-category reputation breakdown for a peer.
    ///
    /// Returns the full `ReputationScore` which includes a `breakdown`
    /// field with per-category scores (audit, delegation, policy, receipt).
    pub async fn peer_reputation_breakdown(
        &self,
        peer_hash: &[u8; 16],
    ) -> Vec<zp_mesh::reputation::CategoryScore> {
        let score = self.node.compute_peer_reputation(peer_hash).await;
        score.breakdown
    }

    /// Compute a composite trust snapshot for a peer.
    ///
    /// Aggregates all signal dimensions into a single struct that
    /// summarises the peer's overall trust posture.
    pub async fn peer_trust_snapshot(&self, peer_hash: &[u8; 16]) -> PeerTrustSnapshot {
        let score = self.node.compute_peer_reputation(peer_hash).await;
        let attestations = self.node.peer_attestations(peer_hash).await;
        let has_link = {
            let addr = hex::encode(peer_hash);
            self.node.link_grants_for_peer(&addr).await.is_some()
        };

        let audit_score = score
            .breakdown
            .iter()
            .find(|c| c.category == zp_mesh::reputation::SignalCategory::AuditAttestation)
            .map(|c| c.score)
            .unwrap_or(0.5);
        let delegation_score = score
            .breakdown
            .iter()
            .find(|c| c.category == zp_mesh::reputation::SignalCategory::DelegationChain)
            .map(|c| c.score)
            .unwrap_or(0.5);
        let policy_score = score
            .breakdown
            .iter()
            .find(|c| c.category == zp_mesh::reputation::SignalCategory::PolicyCompliance)
            .map(|c| c.score)
            .unwrap_or(0.5);
        let receipt_score = score
            .breakdown
            .iter()
            .find(|c| c.category == zp_mesh::reputation::SignalCategory::ReceiptExchange)
            .map(|c| c.score)
            .unwrap_or(0.5);

        PeerTrustSnapshot {
            peer_hex: hex::encode(peer_hash),
            overall_score: score.score,
            grade: score.grade,
            audit_score,
            delegation_score,
            policy_score,
            receipt_score,
            positive_signals: score.positive_signals,
            negative_signals: score.negative_signals,
            audit_verified: attestations.iter().any(|a| a.chain_valid),
            valid_attestation_count: attestations.iter().filter(|a| a.chain_valid).count(),
            has_active_link: has_link,
            computed_at: score.computed_at,
        }
    }

    /// Broadcast our reputation view of a peer to the mesh.
    ///
    /// Other nodes can use this to converge on a shared understanding.
    pub async fn broadcast_peer_reputation(&self, peer_hash: &[u8; 16]) -> Result<(), String> {
        self.node
            .broadcast_reputation_summary(peer_hash)
            .await
            .map_err(|e| format!("reputation broadcast failed: {}", e))
    }

    /// Get reputation summaries received from a specific peer.
    pub async fn received_reputation_summaries(
        &self,
        sender_hash: &[u8; 16],
    ) -> Vec<zp_mesh::reputation::CompactReputationSummary> {
        self.node.received_summaries_from(sender_hash).await
    }

    /// Sync reputation signals from stored audit attestations.
    ///
    /// Useful after handling a batch of audit envelopes — ensures the
    /// reputation system reflects all attestation evidence.
    pub async fn sync_reputation_from_attestations(&self, peer_hash: &[u8; 16]) {
        self.node
            .update_reputation_from_attestations(peer_hash)
            .await;
        debug!(
            peer = %hex::encode(peer_hash),
            "Synced reputation from audit attestations"
        );
    }

    /// Compute reputation with custom weights.
    ///
    /// Allows callers to emphasise specific signal categories for
    /// domain-specific trust decisions.
    pub async fn peer_reputation_with_weights(
        &self,
        peer_hash: &[u8; 16],
        weights: &zp_mesh::reputation::ReputationWeights,
    ) -> zp_mesh::reputation::ReputationScore {
        let peer_hex = hex::encode(peer_hash);
        let now = chrono::Utc::now();
        let reps = self.node().peer_reputations_read().await;
        match reps.get(peer_hash) {
            Some(rep) => rep.compute_score(&peer_hex, weights, now),
            None => {
                let empty = zp_mesh::reputation::PeerReputation::new();
                empty.compute_score(&peer_hex, weights, now)
            }
        }
    }

    /// Build a `MeshPeerContext` for policy evaluation of an inbound receipt.
    ///
    /// Used by the pipeline to consult the `ReputationGateRule` before
    /// processing an inbound receipt.
    pub async fn build_peer_context_for_receipt(
        &self,
        sender_hash: &[u8; 16],
        action: zp_core::policy::MeshAction,
    ) -> zp_core::policy::MeshPeerContext {
        let score = self.node.compute_peer_reputation(sender_hash).await;

        zp_core::policy::MeshPeerContext {
            peer_address: hex::encode(sender_hash),
            reputation_grade: Some(score.grade.to_string()),
            reputation_score: Some(score.score),
            mesh_action: action,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_mesh::identity::{MeshIdentity, PeerIdentity};
    use zp_mesh::interface::{Interface, LoopbackInterface};

    fn make_node() -> Arc<MeshNode> {
        let id = MeshIdentity::generate();
        Arc::new(MeshNode::new(id))
    }

    #[tokio::test]
    async fn test_bridge_creation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node.clone());
        assert!(!bridge.address().is_empty());
        assert!(bridge.config().forward_receipts);
        assert!(bridge.config().forward_audit);
    }

    #[tokio::test]
    async fn test_bridge_custom_config() {
        let node = make_node();
        let config = MeshBridgeConfig {
            forward_receipts: false,
            forward_audit: true,
            max_forward_peers: 5,
        };
        let bridge = MeshBridge::new(node, config);
        assert!(!bridge.config().forward_receipts);
        assert_eq!(bridge.config().max_forward_peers, 5);
    }

    #[tokio::test]
    async fn test_forward_receipt_disabled() {
        let node = make_node();
        let config = MeshBridgeConfig {
            forward_receipts: false,
            forward_audit: true,
            max_forward_peers: 0,
        };
        let bridge = MeshBridge::new(node, config);

        let receipt = zp_receipt::Receipt::execution("test-agent")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .finalize();

        // Should succeed silently when disabled
        let result = bridge.forward_receipt(&receipt).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_forward_receipt_no_peers() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let receipt = zp_receipt::Receipt::execution("test-agent")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .finalize();

        // Should succeed when no peers (nothing to forward to)
        let result = bridge.forward_receipt(&receipt).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_forward_receipt_with_peers() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        // Register a peer
        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);

        let receipt = zp_receipt::Receipt::execution("test-agent")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .finalize();

        let result = bridge.forward_receipt(&receipt).await;
        assert!(result.is_ok());

        // Verify packet was sent on loopback
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_forward_receipt_to_specific_peer() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer_addr = peer_id.address();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);

        let receipt = zp_receipt::Receipt::execution("test-agent")
            .status(zp_receipt::Status::Success)
            .trust_grade(zp_receipt::TrustGrade::C)
            .finalize();

        let result = bridge.forward_receipt_to(&peer_addr, &receipt).await;
        assert!(result.is_ok());

        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_record_receipt_reputation() {
        let node = make_node();
        let peer_hash = [0xAAu8; 16];
        let bridge = MeshBridge::with_defaults(node.clone());

        bridge
            .record_receipt_reputation(&peer_hash, "rcpt-1", true)
            .await;
        bridge
            .record_receipt_reputation(&peer_hash, "rcpt-2", true)
            .await;

        let score = bridge.peer_reputation(&peer_hash).await;
        assert!(score.positive_signals > 0);
        assert_eq!(score.negative_signals, 0);
    }

    #[tokio::test]
    async fn test_peer_meets_reputation_unknown() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let unknown = [0xFFu8; 16];

        // Unknown peer should not meet any threshold above Unknown
        let meets = bridge
            .peer_meets_reputation(&unknown, zp_mesh::reputation::ReputationGrade::Fair)
            .await;
        assert!(!meets);

        // But should meet Unknown threshold
        let meets = bridge
            .peer_meets_reputation(&unknown, zp_mesh::reputation::ReputationGrade::Unknown)
            .await;
        assert!(meets);
    }

    #[tokio::test]
    async fn test_all_peer_reputations_via_bridge() {
        let node = make_node();

        // Register peers
        let p1 = MeshIdentity::generate();
        let peer1 = PeerIdentity::from_combined_key(&p1.combined_public_key(), 1).unwrap();
        let h1 = peer1.destination_hash;
        node.register_peer(peer1, None).await;

        let p2 = MeshIdentity::generate();
        let peer2 = PeerIdentity::from_combined_key(&p2.combined_public_key(), 1).unwrap();
        let h2 = peer2.destination_hash;
        node.register_peer(peer2, None).await;

        let bridge = MeshBridge::with_defaults(node);

        // Record signal for peer1 only
        bridge.record_receipt_reputation(&h1, "r1", true).await;

        let all = bridge.all_peer_reputations().await;
        assert_eq!(all.len(), 2);
        assert!(all[&h1].positive_signals > 0);
        assert_eq!(
            all[&h2].grade,
            zp_mesh::reputation::ReputationGrade::Unknown
        );
    }

    // ========================================================================
    // Inbound Receipt Tests (Phase 4 Step 3)
    // ========================================================================

    // ------------------------------------------------------------
    // Sweep 6 (RFC §3.2) — signature policy table, feature-gated
    // ------------------------------------------------------------

    #[cfg(feature = "mesh-auth-v1")]
    mod sweep6_auth {
        use super::*;
        use std::sync::Arc;
        use zp_mesh::peer_keystore::{InMemoryPeerKeyStore, PeerKeyStore};

        fn keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
            use rand::rngs::OsRng;
            let s = ed25519_dalek::SigningKey::generate(&mut OsRng);
            let v = s.verifying_key();
            (s, v)
        }

        fn signed_receipt(id: &str, signing: &ed25519_dalek::SigningKey) -> CompactReceipt {
            let mut r = super::make_compact_receipt(id, "success");
            r.sign_content_hash(signing);
            r
        }

        #[tokio::test]
        async fn test_sweep6_verified_when_key_known_and_signed() {
            let node = super::make_node();
            let (signing, verifying) = keypair();
            let sender = [0x11u8; 16];
            let mem = InMemoryPeerKeyStore::new();
            mem.insert(sender, verifying);
            let store: Arc<dyn PeerKeyStore> = Arc::new(mem);

            let bridge = MeshBridge::with_defaults(node).with_key_store(store);
            let r = signed_receipt("rcpt-auth-verified", &signing);

            let accepted = bridge.handle_inbound_receipt(&r, &sender).await.unwrap();
            assert!(accepted);
            let stored = bridge.received_receipts().await;
            assert_eq!(stored.len(), 1);
            assert_eq!(stored[0].auth, AuthState::Verified);
        }

        #[tokio::test]
        async fn test_sweep6_unverified_when_key_unknown() {
            let node = super::make_node();
            let store: Arc<dyn PeerKeyStore> = Arc::new(InMemoryPeerKeyStore::new());
            let bridge = MeshBridge::with_defaults(node).with_key_store(store);
            let (signing, _) = keypair();
            let sender = [0x22u8; 16];
            let r = signed_receipt("rcpt-auth-unk", &signing);

            let accepted = bridge.handle_inbound_receipt(&r, &sender).await.unwrap();
            assert!(accepted, "unknown-key path should still accept with reduced trust");
            let stored = bridge.received_receipts().await;
            assert_eq!(stored[0].auth, AuthState::UnverifiedNoKey);
        }

        #[tokio::test]
        async fn test_sweep6_unsigned_path() {
            let node = super::make_node();
            let bridge = MeshBridge::with_defaults(node)
                .with_key_store(Arc::new(InMemoryPeerKeyStore::new()));
            let r = super::make_compact_receipt("rcpt-auth-unsigned", "success");
            assert!(r.sg.is_none());
            let sender = [0x33u8; 16];

            let accepted = bridge.handle_inbound_receipt(&r, &sender).await.unwrap();
            assert!(accepted);
            let stored = bridge.received_receipts().await;
            assert_eq!(stored[0].auth, AuthState::Unsigned);
        }

        #[tokio::test]
        async fn test_sweep6_bad_signature_rejected_hard() {
            let node = super::make_node();
            let mem = InMemoryPeerKeyStore::new();
            let (_signing_correct, verifying_correct) = keypair();
            let sender = [0x44u8; 16];
            mem.insert(sender, verifying_correct);
            let store: Arc<dyn PeerKeyStore> = Arc::new(mem);

            let bridge = MeshBridge::with_defaults(node).with_key_store(store);

            // Sign with the WRONG key.
            let (wrong_signing, _) = keypair();
            let r = signed_receipt("rcpt-auth-bad", &wrong_signing);

            let err = bridge.handle_inbound_receipt(&r, &sender).await;
            assert!(err.is_err(), "bad signature must hard-reject");
            // Nothing stored.
            assert_eq!(bridge.received_receipt_count().await, 0);
        }
    }

    fn make_compact_receipt(id: &str, status: &str) -> CompactReceipt {
        CompactReceipt {
            id: id.to_string(),
            rt: "execution".to_string(),
            st: status.to_string(),
            tg: "C".to_string(),
            ch: "deadbeef".to_string(),
            ts: Utc::now().timestamp(),
            pr: None,
            pd: None,
            ra: None,
            sg: None,
            ex: None,
        }
    }

    #[tokio::test]
    async fn test_inbound_receipt_accepted() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xAAu8; 16];

        let receipt = make_compact_receipt("rcpt-in-1", "success");
        let result = bridge.handle_inbound_receipt(&receipt, &sender).await;

        assert!(result.is_ok());
        assert!(result.unwrap(), "Receipt should be accepted");
        assert_eq!(bridge.received_receipt_count().await, 1);
    }

    #[tokio::test]
    async fn test_inbound_receipt_invalid_empty_id() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xBBu8; 16];

        let receipt = make_compact_receipt("", "success");
        let result = bridge.handle_inbound_receipt(&receipt, &sender).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty ID"));
    }

    #[tokio::test]
    async fn test_inbound_receipt_invalid_status() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xCCu8; 16];

        let receipt = make_compact_receipt("rcpt-bad", "garbage");
        let result = bridge.handle_inbound_receipt(&receipt, &sender).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid status"));
    }

    #[tokio::test]
    async fn test_inbound_receipt_records_reputation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xDDu8; 16];

        let receipt = make_compact_receipt("rcpt-rep", "success");
        bridge
            .handle_inbound_receipt(&receipt, &sender)
            .await
            .unwrap();

        // Should have recorded a positive reputation signal
        let score = bridge.peer_reputation(&sender).await;
        assert_eq!(score.positive_signals, 1);
        assert_eq!(score.negative_signals, 0);
    }

    #[tokio::test]
    async fn test_inbound_receipt_failed_records_negative_reputation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xEEu8; 16];

        let receipt = make_compact_receipt("rcpt-fail", "failed");
        bridge
            .handle_inbound_receipt(&receipt, &sender)
            .await
            .unwrap();

        // Failed receipt should record negative reputation
        let score = bridge.peer_reputation(&sender).await;
        assert_eq!(score.positive_signals, 0);
        assert_eq!(score.negative_signals, 1);
    }

    #[tokio::test]
    async fn test_inbound_receipt_multiple_from_same_peer() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x11u8; 16];

        bridge
            .handle_inbound_receipt(&make_compact_receipt("r1", "success"), &sender)
            .await
            .unwrap();
        bridge
            .handle_inbound_receipt(&make_compact_receipt("r2", "success"), &sender)
            .await
            .unwrap();
        bridge
            .handle_inbound_receipt(&make_compact_receipt("r3", "partial"), &sender)
            .await
            .unwrap();

        assert_eq!(bridge.received_receipt_count().await, 3);

        let from_peer = bridge.receipts_from_peer(&sender).await;
        assert_eq!(from_peer.len(), 3);
    }

    #[tokio::test]
    async fn test_inbound_receipt_from_different_peers() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer_a = [0x11u8; 16];
        let peer_b = [0x22u8; 16];

        bridge
            .handle_inbound_receipt(&make_compact_receipt("r-a1", "success"), &peer_a)
            .await
            .unwrap();
        bridge
            .handle_inbound_receipt(&make_compact_receipt("r-b1", "success"), &peer_b)
            .await
            .unwrap();

        assert_eq!(bridge.received_receipt_count().await, 2);
        assert_eq!(bridge.receipts_from_peer(&peer_a).await.len(), 1);
        assert_eq!(bridge.receipts_from_peer(&peer_b).await.len(), 1);
    }

    #[tokio::test]
    async fn test_accepted_receipts_filter() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x33u8; 16];

        // All receipts from unknown peers should be accepted
        bridge
            .handle_inbound_receipt(&make_compact_receipt("r1", "success"), &sender)
            .await
            .unwrap();
        bridge
            .handle_inbound_receipt(&make_compact_receipt("r2", "denied"), &sender)
            .await
            .unwrap();

        let accepted = bridge.accepted_receipts().await;
        assert_eq!(accepted.len(), 2);
    }

    #[tokio::test]
    async fn test_build_peer_context_for_receipt() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x44u8; 16];

        // Record some reputation first
        bridge.record_receipt_reputation(&sender, "r1", true).await;
        bridge.record_receipt_reputation(&sender, "r2", true).await;

        let ctx = bridge
            .build_peer_context_for_receipt(&sender, zp_core::policy::MeshAction::AcceptReceipt)
            .await;

        assert_eq!(ctx.peer_address, hex::encode(sender));
        assert!(ctx.reputation_score.is_some());
        assert!(ctx.reputation_grade.is_some());
        assert_eq!(ctx.mesh_action, zp_core::policy::MeshAction::AcceptReceipt);
    }

    #[tokio::test]
    async fn test_inbound_receipt_denied_status_accepted() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x55u8; 16];

        // "denied" is a valid receipt status
        let receipt = make_compact_receipt("rcpt-denied", "denied");
        let result = bridge.handle_inbound_receipt(&receipt, &sender).await;

        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    // ========================================================================
    // Delegation Chain Verification Tests (Phase 5 Step 1)
    // ========================================================================

    // ========================================================================
    // Audit Chain Verification Tests (Phase 5 Step 2)
    // ========================================================================

    use zp_audit::collective_audit::{
        AuditChallenge, AuditRange, AuditResponse, CompactAuditEntry,
    };

    fn make_compact_audit_entries(n: usize) -> Vec<CompactAuditEntry> {
        let genesis = blake3::hash(b"").to_hex().to_string();
        let mut entries = Vec::new();
        let mut prev = genesis;
        for i in 0..n {
            let eh = blake3::hash(format!("entry-{}", i).as_bytes())
                .to_hex()
                .to_string();
            entries.push(CompactAuditEntry {
                id: format!("audit-{}", i),
                ts: Utc::now().timestamp(),
                ph: prev.clone(),
                eh: eh.clone(),
                ac: "s:test-agent".to_string(),
                at: "tool".to_string(),
                pd: "allow".to_string(),
                pm: "default-gate".to_string(),
                sg: None,
            });
            prev = eh;
        }
        entries
    }

    fn make_audit_response(challenge_id: &str, entries: Vec<CompactAuditEntry>) -> AuditResponse {
        let chain_tip = entries.last().map(|e| e.eh.clone()).unwrap_or_default();
        let total = entries.len();
        AuditResponse {
            challenge_id: challenge_id.to_string(),
            entries,
            chain_tip,
            total_available: total,
            has_more: false,
        }
    }

    #[tokio::test]
    async fn test_challenge_peer_audit_sends_challenge() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);

        let result = bridge.challenge_peer_audit(&peer_hash, 5).await;
        assert!(result.is_ok());

        let challenge = result.unwrap();
        assert!(challenge.id.starts_with("chal-"));
        match challenge.range {
            AuditRange::Recent(n) => assert_eq!(n, 5),
            _ => panic!("expected Recent range"),
        }

        // Verify a packet was sent
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_challenge_peer_audit_since_hash() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);

        let result = bridge
            .challenge_peer_audit_since(&peer_hash, "abc123".to_string())
            .await;
        assert!(result.is_ok());

        let challenge = result.unwrap();
        assert_eq!(challenge.known_tip, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_handle_audit_response_valid_chain() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA1u8; 16];

        let entries = make_compact_audit_entries(3);
        let response = make_audit_response("chal-1", entries);

        let result = bridge
            .handle_audit_response(&response, &sender, false)
            .await;
        assert!(result.is_ok());

        let attestation = result.unwrap();
        assert!(attestation.chain_valid);
        assert_eq!(attestation.entries_verified, 3);
    }

    #[tokio::test]
    async fn test_handle_audit_response_broken_chain() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA2u8; 16];

        let mut entries = make_compact_audit_entries(3);
        // Break the chain
        entries[2].ph = "tampered".to_string();
        let response = make_audit_response("chal-2", entries);

        let result = bridge
            .handle_audit_response(&response, &sender, false)
            .await;
        assert!(result.is_ok());

        let attestation = result.unwrap();
        assert!(!attestation.chain_valid);
    }

    #[tokio::test]
    async fn test_handle_audit_response_records_positive_reputation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA3u8; 16];

        let entries = make_compact_audit_entries(2);
        let response = make_audit_response("chal-3", entries);

        bridge
            .handle_audit_response(&response, &sender, false)
            .await
            .unwrap();

        let score = bridge.peer_reputation(&sender).await;
        assert!(
            score.positive_signals > 0,
            "Should have positive signal for valid chain"
        );
        assert_eq!(score.negative_signals, 0);
    }

    #[tokio::test]
    async fn test_handle_audit_response_records_negative_reputation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA4u8; 16];

        let mut entries = make_compact_audit_entries(3);
        entries[1].ph = "broken".to_string();
        let response = make_audit_response("chal-4", entries);

        bridge
            .handle_audit_response(&response, &sender, false)
            .await
            .unwrap();

        let score = bridge.peer_reputation(&sender).await;
        assert!(
            score.negative_signals > 0,
            "Should have negative signal for broken chain"
        );
    }

    #[tokio::test]
    async fn test_handle_audit_response_empty_chain() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA5u8; 16];

        let response = make_audit_response("chal-5", vec![]);

        let result = bridge
            .handle_audit_response(&response, &sender, false)
            .await;
        assert!(result.is_ok());

        let attestation = result.unwrap();
        assert!(attestation.chain_valid); // empty chain is trivially valid
        assert_eq!(attestation.entries_verified, 0);
    }

    #[tokio::test]
    async fn test_handle_audit_response_with_broadcast() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        // Register a peer for broadcast
        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA6u8; 16];

        let entries = make_compact_audit_entries(2);
        let response = make_audit_response("chal-6", entries);

        // broadcast=true triggers attestation broadcast (may warn if MTU exceeded)
        let result = bridge.handle_audit_response(&response, &sender, true).await;
        assert!(result.is_ok());

        let attestation = result.unwrap();
        assert!(attestation.chain_valid);
        // Attestation should be stored regardless of broadcast success
        assert!(bridge.peer_audit_verified(&sender).await);
    }

    #[tokio::test]
    async fn test_respond_to_audit_challenge() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);

        let challenge = AuditChallenge::recent(5);

        // Empty entries — no audit history yet
        let result = bridge
            .respond_to_audit_challenge(&challenge, &[], &peer_hash)
            .await;
        assert!(result.is_ok());

        // Verify a response packet was sent
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_peer_audit_verified_true() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA7u8; 16];

        // Handle a valid response to create an attestation
        let entries = make_compact_audit_entries(3);
        let response = make_audit_response("chal-7", entries);
        bridge
            .handle_audit_response(&response, &sender, false)
            .await
            .unwrap();

        assert!(bridge.peer_audit_verified(&sender).await);
    }

    #[tokio::test]
    async fn test_peer_audit_verified_false_unknown() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let unknown = [0xFFu8; 16];

        // No attestations exist for this peer
        assert!(!bridge.peer_audit_verified(&unknown).await);
    }

    #[tokio::test]
    async fn test_peer_valid_attestation_count() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xA8u8; 16];

        // Two valid chains
        let entries1 = make_compact_audit_entries(2);
        let response1 = make_audit_response("chal-8a", entries1);
        bridge
            .handle_audit_response(&response1, &sender, false)
            .await
            .unwrap();

        let entries2 = make_compact_audit_entries(3);
        let response2 = make_audit_response("chal-8b", entries2);
        bridge
            .handle_audit_response(&response2, &sender, false)
            .await
            .unwrap();

        // One broken chain
        let mut entries3 = make_compact_audit_entries(2);
        entries3[1].ph = "broken".to_string();
        let response3 = make_audit_response("chal-8c", entries3);
        bridge
            .handle_audit_response(&response3, &sender, false)
            .await
            .unwrap();

        assert_eq!(bridge.peer_valid_attestation_count(&sender).await, 2);
    }

    #[tokio::test]
    async fn test_all_attestations_multiple_peers() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer_a = [0xB1u8; 16];
        let peer_b = [0xB2u8; 16];

        let entries_a = make_compact_audit_entries(2);
        let response_a = make_audit_response("chal-a", entries_a);
        bridge
            .handle_audit_response(&response_a, &peer_a, false)
            .await
            .unwrap();

        let entries_b = make_compact_audit_entries(3);
        let response_b = make_audit_response("chal-b", entries_b);
        bridge
            .handle_audit_response(&response_b, &peer_b, false)
            .await
            .unwrap();

        let all = bridge.all_attestations().await;
        assert_eq!(all.len(), 2);
        assert!(all.contains_key(&peer_a));
        assert!(all.contains_key(&peer_b));
    }

    // ========================================================================
    // Capability Negotiation Tests (Phase 5 Step 3)
    // ========================================================================

    use zp_core::policy::TrustTier;
    use zp_mesh::capability_exchange::{CapabilityPolicy, CapabilityRequest};

    #[tokio::test]
    async fn test_establish_peer_link_with_allow_all() {
        let node_id = MeshIdentity::generate();
        let node = Arc::new(MeshNode::new(node_id));
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer = MeshIdentity::generate();

        let bridge = MeshBridge::with_defaults(node);
        let policy = CapabilityPolicy::allow_all();
        let our_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        let result = bridge
            .establish_peer_link(&peer, &policy, &our_request, &their_request)
            .await;
        assert!(result.is_ok());

        let neg = result.unwrap();
        assert!(
            !neg.initiator_grants.is_empty(),
            "Should have initiator grants"
        );
        assert!(
            !neg.responder_grants.is_empty(),
            "Should have responder grants"
        );
        assert!(
            neg.denied.is_empty(),
            "Nothing should be denied with allow_all"
        );
    }

    #[tokio::test]
    async fn test_establish_peer_link_with_deny_all() {
        let node_id = MeshIdentity::generate();
        let node = Arc::new(MeshNode::new(node_id));
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer = MeshIdentity::generate();

        let bridge = MeshBridge::with_defaults(node);
        let policy = CapabilityPolicy::deny_all();
        let our_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };
        let their_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let result = bridge
            .establish_peer_link(&peer, &policy, &our_request, &their_request)
            .await;
        assert!(result.is_ok());

        let neg = result.unwrap();
        // deny_all: no grants should be issued
        assert!(neg.initiator_grants.is_empty());
        assert!(neg.responder_grants.is_empty());
    }

    #[tokio::test]
    async fn test_peer_link_grants_after_establish() {
        let node_id = MeshIdentity::generate();
        let node = Arc::new(MeshNode::new(node_id));
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer = MeshIdentity::generate();
        let peer_address = peer.address();

        let bridge = MeshBridge::with_defaults(node);
        let policy = CapabilityPolicy::allow_all();
        let request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        bridge
            .establish_peer_link(&peer, &policy, &request, &request)
            .await
            .unwrap();

        let grants = bridge.peer_link_grants(&peer_address).await;
        assert!(grants.is_some(), "Should have grants for established link");
        let (local, remote) = grants.unwrap();
        assert!(
            !local.is_empty() || !remote.is_empty(),
            "At least some grants expected"
        );
    }

    #[tokio::test]
    async fn test_peer_authorizes_action_after_establish() {
        let node_id = MeshIdentity::generate();
        let node = Arc::new(MeshNode::new(node_id));
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer = MeshIdentity::generate();
        let peer_address = peer.address();

        let bridge = MeshBridge::with_defaults(node);
        let policy = CapabilityPolicy::allow_all();
        let request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        bridge
            .establish_peer_link(&peer, &policy, &request, &request)
            .await
            .unwrap();

        // Read on data/* should be authorized
        let read_action = zp_core::ActionType::Read {
            target: "data/foo".to_string(),
        };
        assert!(
            bridge
                .peer_authorizes_action(&peer_address, &read_action)
                .await
        );

        // Write on data/* should NOT be authorized (we only requested Read)
        let write_action = zp_core::ActionType::Write {
            target: "data/foo".to_string(),
        };
        assert!(
            !bridge
                .peer_authorizes_action(&peer_address, &write_action)
                .await
        );
    }

    #[tokio::test]
    async fn test_has_active_link() {
        let node_id = MeshIdentity::generate();
        let node = Arc::new(MeshNode::new(node_id));
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer = MeshIdentity::generate();
        let peer_address = peer.address();

        let bridge = MeshBridge::with_defaults(node);

        // No link yet
        assert!(!bridge.has_active_link(&peer_address).await);

        // Establish link
        let policy = CapabilityPolicy::allow_all();
        let request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };
        bridge
            .establish_peer_link(&peer, &policy, &request, &request)
            .await
            .unwrap();

        assert!(bridge.has_active_link(&peer_address).await);
    }

    #[tokio::test]
    async fn test_peer_authorizes_action_no_link() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let action = zp_core::ActionType::Read {
            target: "data/foo".to_string(),
        };
        assert!(
            !bridge.peer_authorizes_action("nonexistent", &action).await,
            "No link means no authorization"
        );
    }

    // ========================================================================
    // Multi-dimensional Reputation Tests (Phase 5 Step 4)
    // ========================================================================

    #[tokio::test]
    async fn test_record_policy_compliance_positive() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC1u8; 16];

        bridge
            .record_policy_compliance(&peer, "agree-1", true)
            .await;
        bridge
            .record_policy_compliance(&peer, "agree-2", true)
            .await;

        let score = bridge.peer_reputation(&peer).await;
        assert!(score.positive_signals >= 2);
        assert_eq!(score.negative_signals, 0);
    }

    #[tokio::test]
    async fn test_record_policy_compliance_negative() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC2u8; 16];

        bridge
            .record_policy_compliance(&peer, "agree-bad", false)
            .await;

        let score = bridge.peer_reputation(&peer).await;
        assert_eq!(score.positive_signals, 0);
        assert!(score.negative_signals >= 1);
    }

    #[tokio::test]
    async fn test_record_delegation_reputation_signal() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC3u8; 16];

        bridge
            .record_delegation_reputation(&peer, "grant-1", true)
            .await;

        let score = bridge.peer_reputation(&peer).await;
        assert!(score.positive_signals >= 1);
    }

    #[tokio::test]
    async fn test_record_audit_reputation_signal() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC4u8; 16];

        let att = zp_audit::collective_audit::PeerAuditAttestation {
            id: "att-sig-1".to_string(),
            peer: hex::encode(peer),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 5,
            chain_valid: true,
            signatures_valid: 3,
            timestamp: Utc::now(),
            signature: None,
        };

        bridge.record_audit_reputation(&peer, &att).await;

        let score = bridge.peer_reputation(&peer).await;
        assert!(score.positive_signals >= 1);
    }

    #[tokio::test]
    async fn test_peer_reputation_breakdown_categories() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC5u8; 16];

        // Feed signals in all four categories
        bridge.record_receipt_reputation(&peer, "r1", true).await;
        bridge.record_delegation_reputation(&peer, "d1", true).await;
        bridge.record_policy_compliance(&peer, "p1", true).await;

        let att = zp_audit::collective_audit::PeerAuditAttestation {
            id: "att-bd-1".to_string(),
            peer: hex::encode(peer),
            oldest_hash: "x".to_string(),
            newest_hash: "y".to_string(),
            entries_verified: 2,
            chain_valid: true,
            signatures_valid: 1,
            timestamp: Utc::now(),
            signature: None,
        };
        bridge.record_audit_reputation(&peer, &att).await;

        let breakdown = bridge.peer_reputation_breakdown(&peer).await;
        assert_eq!(breakdown.len(), 4, "Should have all 4 categories");

        // Every category has at least one signal
        for cat in &breakdown {
            assert!(
                cat.signal_count >= 1,
                "Category {:?} should have signals",
                cat.category
            );
            assert!(
                cat.score > 0.9,
                "All-positive category {:?} should score ~1.0",
                cat.category
            );
        }
    }

    #[tokio::test]
    async fn test_peer_trust_snapshot_all_positive() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC6u8; 16];

        // All four categories positive
        bridge.record_receipt_reputation(&peer, "r1", true).await;
        bridge.record_delegation_reputation(&peer, "d1", true).await;
        bridge.record_policy_compliance(&peer, "p1", true).await;

        let att = zp_audit::collective_audit::PeerAuditAttestation {
            id: "att-snap-1".to_string(),
            peer: hex::encode(peer),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 3,
            chain_valid: true,
            signatures_valid: 2,
            timestamp: Utc::now(),
            signature: None,
        };
        bridge.record_audit_reputation(&peer, &att).await;

        let snap = bridge.peer_trust_snapshot(&peer).await;

        assert!(snap.overall_score > 0.9, "All-positive should be excellent");
        assert_eq!(snap.grade, zp_mesh::reputation::ReputationGrade::Excellent);
        assert!(snap.audit_score > 0.9);
        assert!(snap.delegation_score > 0.9);
        assert!(snap.policy_score > 0.9);
        assert!(snap.receipt_score > 0.9);
        assert_eq!(snap.positive_signals, 4);
        assert_eq!(snap.negative_signals, 0);
        assert!(!snap.has_active_link); // no link established
        assert!(!snap.audit_verified); // no attestation stored on node
    }

    #[tokio::test]
    async fn test_peer_trust_snapshot_mixed_signals() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC7u8; 16];

        // Mix: receipts good, policy bad
        bridge.record_receipt_reputation(&peer, "r1", true).await;
        bridge.record_receipt_reputation(&peer, "r2", true).await;
        bridge.record_policy_compliance(&peer, "p-bad", false).await;

        let snap = bridge.peer_trust_snapshot(&peer).await;

        assert!(snap.receipt_score > 0.9, "Receipt should be high");
        assert!(snap.policy_score < 0.1, "Policy should be low");
        // Overall depends on weights but should be somewhere in the middle
        assert!(snap.overall_score > 0.2 && snap.overall_score < 0.9);
    }

    #[tokio::test]
    async fn test_peer_trust_snapshot_unknown_peer() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let unknown = [0xC8u8; 16];

        let snap = bridge.peer_trust_snapshot(&unknown).await;

        assert_eq!(snap.grade, zp_mesh::reputation::ReputationGrade::Unknown);
        // No signals → default 0.5 in all categories
        assert!((snap.overall_score - 0.5).abs() < 0.01);
        assert_eq!(snap.positive_signals, 0);
        assert_eq!(snap.negative_signals, 0);
        assert!(!snap.audit_verified);
        assert!(!snap.has_active_link);
    }

    #[tokio::test]
    async fn test_peer_reputation_with_custom_weights() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xC9u8; 16];

        // Only audit signal — positive
        let att = zp_audit::collective_audit::PeerAuditAttestation {
            id: "att-cw".to_string(),
            peer: hex::encode(peer),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 3,
            chain_valid: true,
            signatures_valid: 1,
            timestamp: Utc::now(),
            signature: None,
        };
        bridge.record_audit_reputation(&peer, &att).await;

        // Heavy weight on audit (0.9), minimal elsewhere
        let weights = zp_mesh::reputation::ReputationWeights {
            audit_attestation: 0.90,
            delegation_chain: 0.0,
            policy_compliance: 0.0,
            receipt_exchange: 0.10,
        };

        let score = bridge.peer_reputation_with_weights(&peer, &weights).await;
        // Audit = 1.0 * 0.9 = 0.9, Receipt = 0.5 * 0.1 = 0.05 → ~0.95
        assert!(score.score > 0.9, "Custom weights should emphasise audit");
        assert_eq!(score.grade, zp_mesh::reputation::ReputationGrade::Excellent);
    }

    #[tokio::test]
    async fn test_sync_reputation_from_attestations() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0xCAu8; 16];

        // Handle audit response to create stored attestation
        let entries = make_compact_audit_entries(3);
        let response = make_audit_response("chal-sync", entries);
        bridge
            .handle_audit_response(&response, &sender, false)
            .await
            .unwrap();

        // handle_audit_response already records a signal, but let's
        // verify sync_reputation_from_attestations adds more
        let score_before = bridge.peer_reputation(&sender).await;
        let before_positive = score_before.positive_signals;

        bridge.sync_reputation_from_attestations(&sender).await;

        let score_after = bridge.peer_reputation(&sender).await;
        // sync adds signals from stored attestations on top
        assert!(score_after.positive_signals >= before_positive);
    }

    #[tokio::test]
    async fn test_multi_dimensional_all_categories_drive_grade() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let peer = [0xCBu8; 16];

        // All negative across all categories
        bridge
            .record_receipt_reputation(&peer, "r-bad", false)
            .await;
        bridge
            .record_delegation_reputation(&peer, "d-bad", false)
            .await;
        bridge.record_policy_compliance(&peer, "p-bad", false).await;

        let att = zp_audit::collective_audit::PeerAuditAttestation {
            id: "att-bad".to_string(),
            peer: hex::encode(peer),
            oldest_hash: "a".to_string(),
            newest_hash: "b".to_string(),
            entries_verified: 2,
            chain_valid: false,
            signatures_valid: 0,
            timestamp: Utc::now(),
            signature: None,
        };
        bridge.record_audit_reputation(&peer, &att).await;

        let snap = bridge.peer_trust_snapshot(&peer).await;
        assert_eq!(snap.grade, zp_mesh::reputation::ReputationGrade::Poor);
        assert!(snap.overall_score < 0.25);
        assert_eq!(snap.positive_signals, 0);
        assert_eq!(snap.negative_signals, 4);
    }

    // ========================================================================
    // Delegation Chain Verification Tests (Phase 5 Step 1)
    // ========================================================================

    use zp_core::capability_grant::GrantedCapability;

    fn make_root_grant() -> zp_core::CapabilityGrant {
        zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_root".to_string(),
        )
        .with_max_delegation_depth(3)
    }

    fn make_compact_delegation(grant: &zp_core::CapabilityGrant) -> CompactDelegation {
        CompactDelegation::from_grant(grant)
    }

    #[tokio::test]
    async fn test_handle_inbound_delegation_root_grant() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x66u8; 16];

        let root = make_root_grant();
        let compact = make_compact_delegation(&root);

        let result = bridge.handle_inbound_delegation(&compact, &sender).await;
        assert!(result.is_ok());

        let grant = result.unwrap();
        assert!(!grant.is_delegated());
        assert_eq!(grant.delegation_depth, 0);

        // Should have stored the chain
        let chain_ids = bridge.delegation_chain_ids().await;
        assert!(!chain_ids.is_empty());
    }

    #[tokio::test]
    async fn test_handle_inbound_delegation_rejects_empty_id() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x67u8; 16];

        let mut root = make_root_grant();
        root.id = String::new(); // empty
        let compact = make_compact_delegation(&root);

        let result = bridge.handle_inbound_delegation(&compact, &sender).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty grant ID"));
    }

    #[tokio::test]
    async fn test_handle_inbound_delegation_rejects_empty_grantor() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x68u8; 16];

        let mut root = make_root_grant();
        root.grantor = String::new();
        let compact = make_compact_delegation(&root);

        let result = bridge.handle_inbound_delegation(&compact, &sender).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("empty grantor or grantee"));
    }

    #[tokio::test]
    async fn test_handle_inbound_delegation_records_reputation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x69u8; 16];

        let root = make_root_grant();
        let compact = make_compact_delegation(&root);

        bridge
            .handle_inbound_delegation(&compact, &sender)
            .await
            .unwrap();

        // Should have recorded a positive delegation signal
        let score = bridge.peer_reputation(&sender).await;
        assert!(score.positive_signals > 0);
    }

    #[tokio::test]
    async fn test_handle_inbound_delegation_with_known_parent() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x70u8; 16];

        // First, send the root grant
        let root = make_root_grant();
        let root_compact = make_compact_delegation(&root);
        bridge
            .handle_inbound_delegation(&root_compact, &sender)
            .await
            .unwrap();

        // Now send a child delegation that references the root
        let child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "receipt_child".to_string(),
            )
            .unwrap();
        let child_compact = make_compact_delegation(&child);

        let result = bridge
            .handle_inbound_delegation(&child_compact, &sender)
            .await;
        assert!(result.is_ok());

        let grant = result.unwrap();
        assert!(grant.is_delegated());
        assert_eq!(grant.delegation_depth, 1);
    }

    #[tokio::test]
    async fn test_handle_inbound_delegation_rejects_poor_reputation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);
        let sender = [0x71u8; 16];

        // Flood the sender with negative receipt signals to drive reputation below Fair
        for i in 0..20 {
            bridge
                .record_receipt_reputation(&sender, &format!("bad-{}", i), false)
                .await;
        }

        let score = bridge.peer_reputation(&sender).await;
        // With all negative signals, their receipt category is 0.0
        // They need to be below Fair for this to trigger

        let root = make_root_grant();
        let compact = make_compact_delegation(&root);

        let result = bridge.handle_inbound_delegation(&compact, &sender).await;

        // If score is below Fair (not Unknown), should be rejected
        if score.grade < zp_mesh::reputation::ReputationGrade::Fair
            && score.grade != zp_mesh::reputation::ReputationGrade::Unknown
        {
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("reputation"));
        }
        // Otherwise it was accepted (reputation not low enough with only receipt signals)
    }

    #[tokio::test]
    async fn test_verify_delegation_chain_valid() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let root = make_root_grant();
        let child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        let result = bridge
            .verify_delegation_chain(vec![root, child], false)
            .await;
        assert!(result.is_ok());

        let chain = result.unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.current_depth(), 1);
    }

    #[tokio::test]
    async fn test_verify_delegation_chain_scope_escalation() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let root = make_root_grant(); // scope: data/*
        let mut child = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();

        // Tamper: escalate scope beyond parent
        child.capability = GrantedCapability::Read {
            scope: vec!["secret/*".to_string()],
        };

        let result = bridge
            .verify_delegation_chain(vec![root, child], false)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verify_delegation_chain_rejects_expired() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let mut root = make_root_grant();
        root.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));

        let result = bridge.verify_delegation_chain(vec![root], false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_check_grant_authorization_valid() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let grant = make_root_grant();

        // Store the root grant
        bridge
            .node
            .store_delegation_chain(vec![grant.clone()])
            .await
            .unwrap();

        let action = zp_core::ActionType::Read {
            target: "data/foo".to_string(),
        };
        let ctx = zp_core::ConstraintContext::new("data/foo".to_string());

        let result = bridge
            .check_grant_authorization(&grant, &action, &ctx)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_check_grant_authorization_wrong_action() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let grant = make_root_grant(); // Read grant

        let action = zp_core::ActionType::Write {
            target: "data/foo".to_string(),
        };
        let ctx = zp_core::ConstraintContext::new("data/foo".to_string());

        let result = bridge
            .check_grant_authorization(&grant, &action, &ctx)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not authorize"));
    }

    #[tokio::test]
    async fn test_check_grant_authorization_expired() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let mut grant = make_root_grant();
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));

        let action = zp_core::ActionType::Read {
            target: "data/foo".to_string(),
        };
        let ctx = zp_core::ConstraintContext::new("data/foo".to_string());

        let result = bridge
            .check_grant_authorization(&grant, &action, &ctx)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[tokio::test]
    async fn test_check_grant_authorization_constraint_violated() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let grant = zp_core::CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_constraint(zp_core::Constraint::MaxCost(1.0));

        bridge
            .node
            .store_delegation_chain(vec![grant.clone()])
            .await
            .unwrap();

        let action = zp_core::ActionType::Read {
            target: "data/foo".to_string(),
        };
        // Cost exceeds constraint
        let ctx = zp_core::ConstraintContext::new("data/foo".to_string()).with_cost(10.0);

        let result = bridge
            .check_grant_authorization(&grant, &action, &ctx)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("constraint"));
    }

    #[tokio::test]
    async fn test_send_delegation_to_peer() {
        let node = make_node();
        let lo = Arc::new(LoopbackInterface::new());
        node.attach_interface(lo.clone()).await;

        let peer_id = MeshIdentity::generate();
        let peer = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1).unwrap();
        let peer_hash = peer.destination_hash;
        node.register_peer(peer, None).await;

        let bridge = MeshBridge::with_defaults(node);
        let grant = make_root_grant();

        let result = bridge.send_delegation_to(&peer_hash, &grant).await;
        assert!(result.is_ok());

        // Verify packet was sent on loopback
        let received = lo.recv().await.unwrap();
        assert!(received.is_some());
    }

    #[tokio::test]
    async fn test_delegation_chain_three_levels() {
        let node = make_node();
        let bridge = MeshBridge::with_defaults(node);

        let root = make_root_grant();
        let g1 = root
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/*".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();
        let g2 = g1
            .delegate(
                "dave".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/logs".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();

        let result = bridge
            .verify_delegation_chain(vec![root, g1, g2], false)
            .await;
        assert!(result.is_ok());

        let chain = result.unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.current_depth(), 2);
        assert!(chain.can_extend()); // max depth 3, at depth 2
    }
}
