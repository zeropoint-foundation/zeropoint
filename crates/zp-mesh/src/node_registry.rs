//! Fleet node registry — tracks fleet-wide node status, health, and capabilities.
//!
//! The `NodeRegistry` maintains a live view of all known ZeroPoint nodes in a fleet,
//! tracking heartbeat timestamps, trust tiers, policy versions, and online/offline
//! status. Nodes register via heartbeat and are marked stale after a configurable
//! timeout.
//!
//! ## Design
//!
//! ```text
//! ┌──────────────────────────────────────────┐
//! │  NodeRegistry                             │
//! │                                           │
//! │  node_id → FleetNode {                    │
//! │    status: Online | Stale | Offline,      │
//! │    trust_tier, policy_version,            │
//! │    last_heartbeat, capabilities,          │
//! │    endpoint                               │
//! │  }                                        │
//! │                                           │
//! │  heartbeat() → register / refresh         │
//! │  sweep()     → mark stale / offline       │
//! │  summary()   → fleet-wide status          │
//! └──────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// How long before a node is considered stale (no heartbeat received).
pub const DEFAULT_STALE_TIMEOUT_SECS: u64 = 90;

/// How long after going stale before a node is marked offline.
pub const DEFAULT_OFFLINE_TIMEOUT_SECS: u64 = 300;

/// Node operational status within the fleet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeStatus {
    /// Actively sending heartbeats.
    Online,
    /// Heartbeat overdue but within offline threshold.
    Stale,
    /// No heartbeat for extended period — assumed down.
    Offline,
}

impl std::fmt::Display for NodeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeStatus::Online => write!(f, "online"),
            NodeStatus::Stale => write!(f, "stale"),
            NodeStatus::Offline => write!(f, "offline"),
        }
    }
}

/// Fleet membership attestation status (T4).
///
/// Tracks whether a node's membership is backed by a chain-attested
/// `FleetMembershipGranted` receipt, or whether it's an unattested
/// legacy node that registered via heartbeat alone.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "membership_type")]
pub enum MembershipStatus {
    /// Node has a valid FleetMembershipGranted receipt on the genesis chain.
    Attested {
        /// Receipt ID of the FleetMembershipGranted receipt.
        receipt_id: String,
    },
    /// Node is heartbeating but has no membership receipt (legacy/pre-T4).
    #[default]
    Unattested,
    /// Membership receipt was revoked — node should be ejected from trusted operations.
    Revoked {
        /// Receipt ID of the revoked FleetMembershipGranted receipt.
        receipt_id: String,
        /// When the membership was revoked.
        revoked_at: String,
    },
}

impl MembershipStatus {
    /// Whether this status represents a trusted membership.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Attested { .. })
    }

    /// Whether this status represents a security concern.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// Human-readable summary for `zp doctor` and `zp fleet status` output.
    pub fn summary(&self) -> String {
        match self {
            Self::Attested { receipt_id } => {
                let short_id = if receipt_id.len() > 12 {
                    format!("{}...", &receipt_id[..12])
                } else {
                    receipt_id.clone()
                };
                format!("Attested ({})", short_id)
            }
            Self::Unattested => "Unattested (no membership receipt)".into(),
            Self::Revoked {
                receipt_id,
                revoked_at,
            } => {
                let short_id = if receipt_id.len() > 12 {
                    format!("{}...", &receipt_id[..12])
                } else {
                    receipt_id.clone()
                };
                format!("REVOKED ({}, at {})", short_id, revoked_at)
            }
        }
    }
}

/// A node in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetNode {
    /// Unique node identifier (hex-encoded destination hash).
    pub node_id: String,
    /// Human-readable node name.
    pub name: String,
    /// Current operational status.
    pub status: NodeStatus,
    /// Trust tier the node operates at.
    pub trust_tier: u8,
    /// Policy version hash the node is running.
    pub policy_version: String,
    /// Network endpoint (e.g., "10.0.1.5:9473" or mesh destination hash).
    pub endpoint: String,
    /// Node capabilities (e.g., ["receipts", "delegation", "policy-sync"]).
    pub capabilities: Vec<String>,
    /// When this node first registered.
    pub registered_at: DateTime<Utc>,
    /// Last heartbeat timestamp.
    pub last_heartbeat: DateTime<Utc>,
    /// Number of heartbeats received since registration.
    pub heartbeat_count: u64,
    /// Fleet membership attestation status (T4).
    #[serde(default)]
    pub membership_status: MembershipStatus,

    // ── Seam 3 — Fleet/node identity authentication ──────────────
    /// Hex-encoded 32-byte Ed25519 public key bound to this `node_id`.
    ///
    /// Established on the *first* signed heartbeat (TOFU — Trust On
    /// First Use). Every subsequent signed heartbeat from this
    /// `node_id` MUST verify against this stored key; a mismatch
    /// indicates a squat / impersonation attempt and the verifier
    /// rejects with `HeartbeatError::PublicKeyMismatch`.
    ///
    /// Empty string for nodes registered via the legacy
    /// `record_unverified` path (test fixtures only — production
    /// always goes through `verify_and_record`).
    #[serde(default)]
    pub public_key: String,

    /// Highest sequence number observed in a verified heartbeat from
    /// this node. Receivers reject any heartbeat with `seq <= last_seq`
    /// to prevent replay of older signed payloads.
    #[serde(default)]
    pub last_seq: u64,

    /// Timestamp from the last verified heartbeat. Surfaced for
    /// diagnostics; the freshness check uses the receiver-side clock
    /// against `signed_at` directly with a `±REPLAY_WINDOW` tolerance.
    #[serde(default)]
    pub last_signed_at: Option<DateTime<Utc>>,
}

/// Heartbeat payload sent by fleet nodes to register or refresh.
///
/// In production, this is wrapped in a [`SignedHeartbeat`] envelope
/// (Seam 3) — the unsigned `NodeHeartbeat` alone is no longer accepted
/// at the `/api/v1/fleet/heartbeat` endpoint. Tests can still pass
/// a bare `NodeHeartbeat` to [`NodeRegistry::record_unverified`] (a
/// `test-support`-gated convenience for exercising the registry's
/// non-auth concerns like `sweep`, `summary`, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeat {
    /// Unique node identifier.
    pub node_id: String,
    /// Human-readable name.
    pub name: String,
    /// Trust tier.
    pub trust_tier: u8,
    /// Policy version hash.
    pub policy_version: String,
    /// Reachable endpoint.
    pub endpoint: String,
    /// Node capabilities.
    pub capabilities: Vec<String>,
}

/// Signed heartbeat envelope — what actually goes on the wire.
///
/// # The wire (Seam 3)
///
/// The signed-and-canonicalized form of a fleet heartbeat. Wraps
/// [`NodeHeartbeat`] with anti-replay metadata and a cryptographic
/// identity claim that's verified at the receiver. Closes the
/// auth-bypass hole at `/api/v1/fleet/heartbeat` where the handler
/// previously trusted client-supplied `node_id` and `trust_tier`.
///
/// ## Trust model — TOFU (Trust On First Use)
///
/// The first signed heartbeat the receiver sees for a given `node_id`
/// establishes the binding between that ID and `public_key`. Every
/// subsequent heartbeat from the same `node_id` MUST verify against
/// the *stored* public key; a mismatch indicates a squat or
/// impersonation attempt and is rejected with
/// `HeartbeatError::PublicKeyMismatch`.
///
/// Operator-attested registration (a `FleetMembershipGranted`
/// receipt that names `(node_id, public_key)` ahead of the first
/// heartbeat) is a future strengthening — it pre-populates the
/// binding so there's no TOFU window. The `MembershipStatus` enum
/// already supports the `Attested { receipt_id }` upgrade path.
///
/// ## Replay protection
///
/// - **`signed_at`** — issuer-side wall-clock timestamp. Receivers
///   reject anything outside `±HEARTBEAT_REPLAY_WINDOW` (5 minutes).
///
/// - **`seq`** — monotonically-increasing per-node counter. Receivers
///   reject any heartbeat with `seq <= last_seq` for this node. Senders
///   are responsible for persisting `seq` across restarts.
///
/// ## Wire format
///
/// The signature covers the canonical bytes of a `HeartbeatPreimage`
/// (everything except the signature itself). Tampering with any field
/// inside the preimage — `node_id`, `trust_tier`, `seq`, `signed_at`,
/// `public_key` — invalidates the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedHeartbeat {
    /// The unsigned heartbeat payload (node identity claim + status).
    pub heartbeat: NodeHeartbeat,
    /// Monotonically increasing per-node counter.
    pub seq: u64,
    /// Issuer-side timestamp (UTC).
    pub signed_at: DateTime<Utc>,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Hex-encoded 64-byte Ed25519 signature over the canonical
    /// preimage bytes.
    pub signature: String,
}

/// What the signature covers — every field of [`SignedHeartbeat`]
/// except the signature itself. Defined as a separate struct so the
/// canonical-bytes serialization is unambiguous and the discipline
/// matches Seam 20 (hash-then-sign).
///
/// Only `Serialize` is needed; the preimage is computed at signing
/// and verifying time but never deserialized from the wire.
#[derive(Debug, Serialize)]
struct HeartbeatPreimage<'a> {
    pub heartbeat: &'a NodeHeartbeat,
    pub seq: u64,
    pub signed_at: DateTime<Utc>,
    pub public_key: &'a str,
}

/// Tolerance window for heartbeat timestamps. Heartbeats outside
/// `now ± HEARTBEAT_REPLAY_WINDOW` are rejected.
///
/// Five minutes leaves room for moderate clock skew across fleet
/// members while keeping the per-node monotonic-seq cache bounded.
pub const HEARTBEAT_REPLAY_WINDOW: chrono::Duration = chrono::Duration::minutes(5);

/// Errors from verifying a [`SignedHeartbeat`] (Seam 3).
#[derive(Debug, thiserror::Error)]
pub enum HeartbeatError {
    /// Timestamp outside the acceptable window. `skew_secs` is
    /// signed: positive = past, negative = future.
    #[error("Heartbeat timestamp outside replay window: skew {skew_secs}s")]
    TimestampSkewed { skew_secs: i64 },

    /// Sequence number regressed (replay of an older heartbeat).
    #[error("Heartbeat sequence regression: got {got}, last was {last}")]
    SequenceRegression { got: u64, last: u64 },

    /// The node_id is already bound to a different public key.
    /// Indicates a squat or impersonation attempt.
    #[error("Public key does not match stored binding for this node_id")]
    PublicKeyMismatch,

    /// The supplied public key bytes are not a valid Ed25519 key
    /// (e.g. wrong length, not a curve point).
    #[error("Invalid public key bytes")]
    InvalidPublicKey,

    /// The supplied signature bytes are malformed (wrong length,
    /// invalid base64/hex, etc.).
    #[error("Invalid signature encoding")]
    InvalidSignature,

    /// Signature verifies neither against the stored binding (for
    /// known nodes) nor against the body's `public_key` (for TOFU).
    #[error("Heartbeat signature does not verify")]
    SignatureMismatch,

    /// Internal serialization failure when computing the preimage.
    #[error("Heartbeat preimage serialization failed: {0}")]
    SerializationFailed(String),
}

/// Fleet-wide summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    /// Total registered nodes.
    pub total_nodes: usize,
    /// Currently online.
    pub online: usize,
    /// Heartbeat overdue.
    pub stale: usize,
    /// Assumed offline.
    pub offline: usize,
    /// Distinct policy versions in fleet.
    pub policy_versions: Vec<String>,
    /// Timestamp of this summary.
    pub timestamp: String,
}

/// Configuration for the node registry.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Seconds without heartbeat before marking stale.
    pub stale_timeout: Duration,
    /// Seconds without heartbeat before marking offline.
    pub offline_timeout: Duration,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            stale_timeout: Duration::from_secs(DEFAULT_STALE_TIMEOUT_SECS),
            offline_timeout: Duration::from_secs(DEFAULT_OFFLINE_TIMEOUT_SECS),
        }
    }
}

/// Fleet node registry — maintains live view of all nodes.
#[derive(Debug, Clone)]
pub struct NodeRegistry {
    nodes: Arc<RwLock<HashMap<String, FleetNode>>>,
    config: RegistryConfig,
}

impl NodeRegistry {
    /// Create a new empty registry with default config.
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            config: RegistryConfig::default(),
        }
    }

    /// Create a registry with custom timeouts.
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Process a signed heartbeat — verifies the signature, applies
    /// TOFU on first sight, registers/refreshes the node on success.
    /// This is the production-canonical entry point (Seam 3).
    ///
    /// Verification, in order:
    ///
    /// 1. **Timestamp window.** `signed_at` must be within
    ///    `±HEARTBEAT_REPLAY_WINDOW` of the receiver's current clock.
    ///    Catches both ancient replays and future-dated payloads.
    /// 2. **Public key + signature decode.** Hex-decoded to fixed
    ///    arrays; malformed encodings are rejected before any
    ///    cryptographic work.
    /// 3. **TOFU vs known-binding split.**
    ///    - *Unknown `node_id`*: verify the signature against the
    ///      body's `public_key`. On success, record the binding.
    ///    - *Known `node_id`*: verify against the *stored* public key,
    ///      not the body's. If `body.public_key != stored.public_key`,
    ///      reject as `PublicKeyMismatch` (squat attempt) without
    ///      even attempting verification.
    /// 4. **Sequence monotonicity** (known nodes only): reject any
    ///    `seq <= last_seq`. Catches replay of older heartbeats from
    ///    the legitimate node.
    /// 5. **State update**: refresh status/capabilities, advance
    ///    `last_seq` and `last_signed_at`.
    pub async fn verify_and_record(&self, signed: SignedHeartbeat) -> Result<(), HeartbeatError> {
        // 1. Timestamp window
        let now = Utc::now();
        let skew = now.signed_duration_since(signed.signed_at);
        let skew_abs = if skew < chrono::Duration::zero() {
            -skew
        } else {
            skew
        };
        if skew_abs > HEARTBEAT_REPLAY_WINDOW {
            return Err(HeartbeatError::TimestampSkewed {
                skew_secs: skew.num_seconds(),
            });
        }

        // 2. Decode public key + signature
        let pk_bytes =
            hex::decode(&signed.public_key).map_err(|_| HeartbeatError::InvalidPublicKey)?;
        let pk_array: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| HeartbeatError::InvalidPublicKey)?;

        let sig_bytes =
            hex::decode(&signed.signature).map_err(|_| HeartbeatError::InvalidSignature)?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| HeartbeatError::InvalidSignature)?;

        // 3. Compute canonical preimage bytes (Seam 17 + 20)
        let preimage = HeartbeatPreimage {
            heartbeat: &signed.heartbeat,
            seq: signed.seq,
            signed_at: signed.signed_at,
            public_key: &signed.public_key,
        };
        let preimage_bytes = zp_core::canonical_bytes_of(&preimage)
            .map_err(|e| HeartbeatError::SerializationFailed(e.to_string()))?;

        // 4. Look up registry; split TOFU vs known-binding paths
        let mut nodes = self.nodes.write().await;
        let node_id = signed.heartbeat.node_id.clone();

        if let Some(existing) = nodes.get_mut(&node_id) {
            // KNOWN node — strict checks against stored binding.

            // a) Public-key binding must match. If body claims a
            //    different key for the same node_id, that's a squat.
            //    Reject before any signature work.
            if !existing.public_key.is_empty() && existing.public_key != signed.public_key {
                return Err(HeartbeatError::PublicKeyMismatch);
            }

            // b) Signature must verify against the stored key (or
            //    the body's, equivalent here since we've matched).
            zp_receipt::verify::verify_signature(&pk_array, &preimage_bytes, &sig_array)
                .map_err(|_| HeartbeatError::SignatureMismatch)?;

            // c) Sequence must increase strictly.
            if signed.seq <= existing.last_seq {
                return Err(HeartbeatError::SequenceRegression {
                    got: signed.seq,
                    last: existing.last_seq,
                });
            }

            // d) Apply update — refresh status/capabilities, advance
            //    auth state.
            existing.status = NodeStatus::Online;
            existing.name = signed.heartbeat.name;
            existing.trust_tier = signed.heartbeat.trust_tier;
            existing.policy_version = signed.heartbeat.policy_version;
            existing.endpoint = signed.heartbeat.endpoint;
            existing.capabilities = signed.heartbeat.capabilities;
            existing.last_heartbeat = now;
            existing.heartbeat_count += 1;
            existing.public_key = signed.public_key;
            existing.last_seq = signed.seq;
            existing.last_signed_at = Some(signed.signed_at);
            debug!(
                node_id = %existing.node_id,
                count = existing.heartbeat_count,
                seq = signed.seq,
                "fleet node heartbeat refreshed (verified)"
            );
        } else {
            // UNKNOWN node — TOFU. Verify against body.public_key.
            // On success, record the binding.
            zp_receipt::verify::verify_signature(&pk_array, &preimage_bytes, &sig_array)
                .map_err(|_| HeartbeatError::SignatureMismatch)?;

            let new_node = FleetNode {
                node_id: node_id.clone(),
                name: signed.heartbeat.name,
                status: NodeStatus::Online,
                trust_tier: signed.heartbeat.trust_tier,
                policy_version: signed.heartbeat.policy_version,
                endpoint: signed.heartbeat.endpoint,
                capabilities: signed.heartbeat.capabilities,
                registered_at: now,
                last_heartbeat: now,
                heartbeat_count: 1,
                membership_status: MembershipStatus::Unattested,
                public_key: signed.public_key,
                last_seq: signed.seq,
                last_signed_at: Some(signed.signed_at),
            };
            info!(
                node_id = %new_node.node_id,
                name = %new_node.name,
                "new fleet node registered (TOFU)"
            );
            nodes.insert(node_id, new_node);
        }
        Ok(())
    }

    /// Test-only legacy path: register or refresh a node WITHOUT
    /// signature verification. Production code MUST use
    /// [`Self::verify_and_record`]; this exists so existing tests
    /// (and future tests of non-auth concerns like `sweep`,
    /// `summary`, `prune`) can populate the registry without
    /// constructing signed envelopes.
    ///
    /// Inside `zp-mesh`, callable from tests directly. External
    /// crates must enable the `test-support` feature to access this
    /// method. Production builds must NOT enable that feature.
    #[cfg(any(test, feature = "test-support"))]
    pub async fn record_unverified(&self, hb: NodeHeartbeat) {
        let mut nodes = self.nodes.write().await;
        let now = Utc::now();

        if let Some(node) = nodes.get_mut(&hb.node_id) {
            node.status = NodeStatus::Online;
            node.trust_tier = hb.trust_tier;
            node.policy_version = hb.policy_version;
            node.endpoint = hb.endpoint;
            node.capabilities = hb.capabilities;
            node.last_heartbeat = now;
            node.heartbeat_count += 1;
            debug!(
                node_id = %node.node_id,
                count = node.heartbeat_count,
                "node heartbeat refreshed (unverified — test path)"
            );
        } else {
            let node = FleetNode {
                node_id: hb.node_id.clone(),
                name: hb.name,
                status: NodeStatus::Online,
                trust_tier: hb.trust_tier,
                policy_version: hb.policy_version,
                endpoint: hb.endpoint,
                capabilities: hb.capabilities,
                registered_at: now,
                last_heartbeat: now,
                heartbeat_count: 1,
                membership_status: MembershipStatus::Unattested,
                public_key: String::new(),
                last_seq: 0,
                last_signed_at: None,
            };
            info!(
                node_id = %node.node_id,
                name = %node.name,
                "new fleet node registered (unverified — test path)"
            );
            nodes.insert(node.node_id.clone(), node);
        }
    }

    /// Sweep all nodes — mark stale or offline based on heartbeat age.
    pub async fn sweep(&self) {
        let mut nodes = self.nodes.write().await;
        let now = Utc::now();

        for node in nodes.values_mut() {
            let age = now
                .signed_duration_since(node.last_heartbeat)
                .to_std()
                .unwrap_or(Duration::ZERO);

            if age >= self.config.offline_timeout {
                if node.status != NodeStatus::Offline {
                    warn!(node_id = %node.node_id, age_secs = age.as_secs(), "node marked offline");
                    node.status = NodeStatus::Offline;
                }
            } else if age >= self.config.stale_timeout && node.status != NodeStatus::Stale {
                warn!(node_id = %node.node_id, age_secs = age.as_secs(), "node marked stale");
                node.status = NodeStatus::Stale;
            }
        }
    }

    /// Get a snapshot of all nodes.
    pub async fn list_nodes(&self) -> Vec<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes.values().cloned().collect()
    }

    /// Get a single node by ID.
    pub async fn get_node(&self, node_id: &str) -> Option<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }

    /// Get online nodes only.
    pub async fn online_nodes(&self) -> Vec<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.status == NodeStatus::Online)
            .cloned()
            .collect()
    }

    /// Get nodes running a specific policy version.
    pub async fn nodes_with_policy(&self, version: &str) -> Vec<FleetNode> {
        let nodes = self.nodes.read().await;
        nodes
            .values()
            .filter(|n| n.policy_version == version)
            .cloned()
            .collect()
    }

    /// Remove a node from the registry.
    pub async fn deregister(&self, node_id: &str) -> bool {
        let mut nodes = self.nodes.write().await;
        let removed = nodes.remove(node_id).is_some();
        if removed {
            info!(node_id = %node_id, "node deregistered from fleet");
        }
        removed
    }

    /// Generate fleet-wide summary statistics.
    pub async fn summary(&self) -> FleetSummary {
        let nodes = self.nodes.read().await;
        let mut online = 0;
        let mut stale = 0;
        let mut offline = 0;
        let mut versions = std::collections::HashSet::new();

        for node in nodes.values() {
            match node.status {
                NodeStatus::Online => online += 1,
                NodeStatus::Stale => stale += 1,
                NodeStatus::Offline => offline += 1,
            }
            versions.insert(node.policy_version.clone());
        }

        FleetSummary {
            total_nodes: nodes.len(),
            online,
            stale,
            offline,
            policy_versions: versions.into_iter().collect(),
            timestamp: Utc::now().to_rfc3339(),
        }
    }
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_heartbeat(id: &str, name: &str) -> NodeHeartbeat {
        NodeHeartbeat {
            node_id: id.to_string(),
            name: name.to_string(),
            trust_tier: 1,
            policy_version: "v3.0.0-abc123".to_string(),
            endpoint: format!("10.0.1.{}:9473", id),
            capabilities: vec!["receipts".to_string(), "delegation".to_string()],
        }
    }

    #[tokio::test]
    async fn heartbeat_registers_new_node() {
        let registry = NodeRegistry::new();
        registry
            .record_unverified(test_heartbeat("node-1", "Alpha"))
            .await;

        let nodes = registry.list_nodes().await;
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].node_id, "node-1");
        assert_eq!(nodes[0].name, "Alpha");
        assert_eq!(nodes[0].status, NodeStatus::Online);
        assert_eq!(nodes[0].heartbeat_count, 1);
    }

    #[tokio::test]
    async fn heartbeat_refreshes_existing_node() {
        let registry = NodeRegistry::new();
        registry
            .record_unverified(test_heartbeat("node-1", "Alpha"))
            .await;
        registry
            .record_unverified(test_heartbeat("node-1", "Alpha"))
            .await;

        let node = registry.get_node("node-1").await.unwrap();
        assert_eq!(node.heartbeat_count, 2);
        assert_eq!(node.status, NodeStatus::Online);
    }

    #[tokio::test]
    async fn sweep_marks_stale_and_offline() {
        let config = RegistryConfig {
            stale_timeout: Duration::from_secs(0), // immediate for testing
            offline_timeout: Duration::from_secs(0),
        };
        let registry = NodeRegistry::with_config(config);
        registry
            .record_unverified(test_heartbeat("node-1", "Alpha"))
            .await;

        // After sweep with zero timeouts, node should be offline
        registry.sweep().await;
        let node = registry.get_node("node-1").await.unwrap();
        assert_eq!(node.status, NodeStatus::Offline);
    }

    #[tokio::test]
    async fn deregister_removes_node() {
        let registry = NodeRegistry::new();
        registry
            .record_unverified(test_heartbeat("node-1", "Alpha"))
            .await;
        assert!(registry.deregister("node-1").await);
        assert!(registry.get_node("node-1").await.is_none());
        assert!(!registry.deregister("node-1").await); // already gone
    }

    #[tokio::test]
    async fn summary_counts_by_status() {
        let registry = NodeRegistry::new();
        registry.record_unverified(test_heartbeat("n1", "A")).await;
        registry.record_unverified(test_heartbeat("n2", "B")).await;
        registry.record_unverified(test_heartbeat("n3", "C")).await;

        let summary = registry.summary().await;
        assert_eq!(summary.total_nodes, 3);
        assert_eq!(summary.online, 3);
        assert_eq!(summary.stale, 0);
        assert_eq!(summary.offline, 0);
    }

    #[tokio::test]
    async fn online_nodes_filters_correctly() {
        let config = RegistryConfig {
            stale_timeout: Duration::from_secs(0),
            offline_timeout: Duration::from_secs(9999),
        };
        let registry = NodeRegistry::with_config(config);
        registry.record_unverified(test_heartbeat("n1", "A")).await;

        // Sweep makes it stale (not offline since offline_timeout is large)
        registry.sweep().await;

        // Now add a fresh node
        registry.record_unverified(test_heartbeat("n2", "B")).await;

        let online = registry.online_nodes().await;
        assert_eq!(online.len(), 1);
        assert_eq!(online[0].node_id, "n2");
    }

    #[tokio::test]
    async fn nodes_with_policy_filters_by_version() {
        let registry = NodeRegistry::new();
        registry.record_unverified(test_heartbeat("n1", "A")).await;

        let mut hb2 = test_heartbeat("n2", "B");
        hb2.policy_version = "v2.9.0-old".to_string();
        registry.record_unverified(hb2).await;

        let v3_nodes = registry.nodes_with_policy("v3.0.0-abc123").await;
        assert_eq!(v3_nodes.len(), 1);
        assert_eq!(v3_nodes[0].node_id, "n1");
    }

    #[test]
    fn membership_status_defaults_to_unattested() {
        let status = MembershipStatus::default();
        assert!(matches!(status, MembershipStatus::Unattested));
        assert!(!status.is_trusted());
        assert!(!status.is_revoked());
    }

    #[test]
    fn membership_status_attested() {
        let status = MembershipStatus::Attested {
            receipt_id: "fmgr-abc123def456".into(),
        };
        assert!(status.is_trusted());
        assert!(!status.is_revoked());
        assert!(status.summary().contains("Attested"));
        assert!(status.summary().contains("fmgr-abc123d"));
    }

    #[test]
    fn membership_status_revoked() {
        let status = MembershipStatus::Revoked {
            receipt_id: "fmgr-abc123def456".into(),
            revoked_at: "2026-05-01T00:00:00Z".into(),
        };
        assert!(!status.is_trusted());
        assert!(status.is_revoked());
        assert!(status.summary().contains("REVOKED"));
    }

    #[tokio::test]
    async fn new_node_is_unattested() {
        let registry = NodeRegistry::new();
        registry
            .record_unverified(test_heartbeat("node-1", "Alpha"))
            .await;

        let node = registry.get_node("node-1").await.unwrap();
        assert!(matches!(
            node.membership_status,
            MembershipStatus::Unattested
        ));
    }

    // ─────────────────────────────────────────────────────────────
    // Seam 3 — Fleet/node identity authentication
    // ─────────────────────────────────────────────────────────────

    /// Helper: sign a heartbeat with a freshly-generated key (or a
    /// supplied one). Returns the SigningKey + a SignedHeartbeat,
    /// ready to feed to `verify_and_record`.
    fn sign_heartbeat(
        signing_key: &ed25519_dalek::SigningKey,
        heartbeat: NodeHeartbeat,
        seq: u64,
        signed_at: DateTime<Utc>,
    ) -> SignedHeartbeat {
        use ed25519_dalek::Signer;
        let public_key = hex::encode(signing_key.verifying_key().to_bytes());
        let preimage = HeartbeatPreimage {
            heartbeat: &heartbeat,
            seq,
            signed_at,
            public_key: &public_key,
        };
        let preimage_bytes =
            zp_core::canonical_bytes_of(&preimage).expect("canonical preimage serializes");
        let signature = signing_key.sign(&preimage_bytes);
        SignedHeartbeat {
            heartbeat,
            seq,
            signed_at,
            public_key,
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn fresh_signing_key() -> ed25519_dalek::SigningKey {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn tofu_first_heartbeat_registers_and_binds_key() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();
        let signed = sign_heartbeat(&key, test_heartbeat("node-tofu", "Alpha"), 1, Utc::now());
        let expected_pk = signed.public_key.clone();

        registry
            .verify_and_record(signed)
            .await
            .expect("first heartbeat should TOFU-register");

        let node = registry.get_node("node-tofu").await.expect("registered");
        assert_eq!(node.public_key, expected_pk, "TOFU should record the key");
        assert_eq!(node.last_seq, 1);
        assert!(node.last_signed_at.is_some());
    }

    #[tokio::test]
    async fn second_heartbeat_with_same_key_and_higher_seq_accepts() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();

        let h1 = sign_heartbeat(&key, test_heartbeat("node-1", "A"), 1, Utc::now());
        registry.verify_and_record(h1).await.unwrap();

        let h2 = sign_heartbeat(&key, test_heartbeat("node-1", "A"), 2, Utc::now());
        registry
            .verify_and_record(h2)
            .await
            .expect("monotonic seq from same key accepts");

        let node = registry.get_node("node-1").await.unwrap();
        assert_eq!(node.last_seq, 2);
        assert_eq!(node.heartbeat_count, 2);
    }

    #[tokio::test]
    async fn squat_attempt_with_different_key_is_rejected() {
        let registry = NodeRegistry::new();
        let legitimate = fresh_signing_key();
        let attacker = fresh_signing_key();

        // Legitimate node TOFU-registers
        let h1 = sign_heartbeat(
            &legitimate,
            test_heartbeat("node-squat", "Real"),
            1,
            Utc::now(),
        );
        registry.verify_and_record(h1).await.unwrap();

        // Attacker tries to send a heartbeat for the same node_id
        // with a different keypair. Even though the attacker's
        // signature is valid against their own key, the registry
        // already has a binding for node-squat — rejection.
        let h_attack = sign_heartbeat(
            &attacker,
            test_heartbeat("node-squat", "Imposter"),
            2,
            Utc::now(),
        );
        let result = registry.verify_and_record(h_attack).await;
        assert!(matches!(result, Err(HeartbeatError::PublicKeyMismatch)));

        // Original node still has the original binding
        let node = registry.get_node("node-squat").await.unwrap();
        assert_eq!(node.name, "Real");
    }

    #[tokio::test]
    async fn tampered_signature_is_rejected_on_first_heartbeat() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();
        let mut signed = sign_heartbeat(&key, test_heartbeat("node-tamper", "X"), 1, Utc::now());
        // Flip a byte of the signature
        let mut sig_bytes = hex::decode(&signed.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        signed.signature = hex::encode(&sig_bytes);

        let result = registry.verify_and_record(signed).await;
        assert!(matches!(result, Err(HeartbeatError::SignatureMismatch)));
        assert!(
            registry.get_node("node-tamper").await.is_none(),
            "tampered TOFU must not register"
        );
    }

    #[tokio::test]
    async fn stale_timestamp_outside_window_is_rejected() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();
        let stale = Utc::now() - chrono::Duration::minutes(10);
        let signed = sign_heartbeat(&key, test_heartbeat("node-stale", "X"), 1, stale);

        let result = registry.verify_and_record(signed).await;
        assert!(matches!(
            result,
            Err(HeartbeatError::TimestampSkewed { .. })
        ));
    }

    #[tokio::test]
    async fn future_dated_timestamp_outside_window_is_rejected() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();
        let future = Utc::now() + chrono::Duration::minutes(10);
        let signed = sign_heartbeat(&key, test_heartbeat("node-future", "X"), 1, future);

        let result = registry.verify_and_record(signed).await;
        assert!(matches!(
            result,
            Err(HeartbeatError::TimestampSkewed { .. })
        ));
    }

    #[tokio::test]
    async fn sequence_regression_is_rejected() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();

        let h1 = sign_heartbeat(&key, test_heartbeat("node-seq", "X"), 5, Utc::now());
        registry.verify_and_record(h1).await.unwrap();

        // Replay an OLDER seq (3 < 5)
        let h_old = sign_heartbeat(&key, test_heartbeat("node-seq", "X"), 3, Utc::now());
        let result = registry.verify_and_record(h_old).await;
        assert!(matches!(
            result,
            Err(HeartbeatError::SequenceRegression { got: 3, last: 5 })
        ));

        // Same seq is also rejected (must be strictly greater)
        let h_same = sign_heartbeat(&key, test_heartbeat("node-seq", "X"), 5, Utc::now());
        let result = registry.verify_and_record(h_same).await;
        assert!(matches!(
            result,
            Err(HeartbeatError::SequenceRegression { got: 5, last: 5 })
        ));
    }

    #[tokio::test]
    async fn malformed_public_key_is_rejected() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();
        let mut signed = sign_heartbeat(&key, test_heartbeat("node-bad-pk", "X"), 1, Utc::now());
        signed.public_key = "not-hex-at-all".to_string();
        let result = registry.verify_and_record(signed).await;
        assert!(matches!(result, Err(HeartbeatError::InvalidPublicKey)));
    }

    #[tokio::test]
    async fn malformed_signature_encoding_is_rejected() {
        let registry = NodeRegistry::new();
        let key = fresh_signing_key();
        let mut signed = sign_heartbeat(&key, test_heartbeat("node-bad-sig", "X"), 1, Utc::now());
        signed.signature = "zzz-not-hex".to_string();
        let result = registry.verify_and_record(signed).await;
        assert!(matches!(result, Err(HeartbeatError::InvalidSignature)));
    }
}
