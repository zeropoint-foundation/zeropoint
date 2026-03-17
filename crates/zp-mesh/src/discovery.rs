//! Dual discovery — unified peer discovery across multiple transport backends.
//!
//! ZeroPoint agents can discover peers via two independent mechanisms:
//!
//! 1. **Web**: A privacy-preserving pub/sub relay over WebSocket. The relay is
//!    ephemeral (memory-only state, no logs) and structurally incapable of
//!    surveillance — it forwards announce blobs without parsing them.
//!
//! 2. **Reticulum**: Broadcast announce packets over mesh interfaces (LoRa, TCP,
//!    serial, WiFi). Fully decentralized — no server, no infrastructure dependency.
//!
//! Both backends share the same identity and wire format: a 64-byte combined
//! public key, JSON-encoded capabilities, and an Ed25519 signature. A peer
//! discovered via web and a peer discovered via Reticulum end up in the same
//! peer table with the same destination hash.
//!
//! ## Privacy Architecture
//!
//! The web relay uses a pub/sub model:
//!
//! - Agents **publish** signed announce blobs to the relay
//! - The relay **broadcasts** all announces to all subscribers
//! - Agents **filter locally** for peers they care about
//! - The relay **never queries, indexes, or retains** any announce data
//! - State is memory-only with short TTLs — restart = clean slate
//!
//! This makes the relay structurally amnesic: privacy is a property of the
//! architecture, not a policy promise.
//!
//! ## Design
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │  DiscoveryManager                                 │
//! │                                                   │
//! │  ┌─────────────────┐  ┌────────────────────────┐ │
//! │  │  WebDiscovery    │  │  ReticulumDiscovery    │ │
//! │  │  (pub/sub relay) │  │  (broadcast announces) │ │
//! │  └────────┬────────┘  └───────────┬────────────┘ │
//! │           │                        │              │
//! │           └───────────┬────────────┘              │
//! │                       ▼                           │
//! │              Unified Peer Table                   │
//! │         (same PeerIdentity, same hash)            │
//! └──────────────────────────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::{MeshError, MeshResult};
use crate::identity::{MeshIdentity, PeerIdentity};
use crate::transport::AgentCapabilities;

// ─────────────────────────────────────────────────────────────
// Discovery types
// ─────────────────────────────────────────────────────────────

/// How a peer was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// Discovered via the web pub/sub relay.
    Web,
    /// Discovered via Reticulum mesh announce.
    Reticulum,
}

impl std::fmt::Display for DiscoverySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Web => write!(f, "web"),
            Self::Reticulum => write!(f, "reticulum"),
        }
    }
}

/// A peer discovered by any backend.
///
/// The payload is the raw announce blob — same format regardless of source:
/// `[combined_key(64)] + [capabilities_json] + [signature(64)]`
///
/// The DiscoveryManager validates and registers the peer; backends just deliver bytes.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Raw announce payload (combined_key + caps_json + signature).
    pub payload: Vec<u8>,
    /// Which backend discovered this peer.
    pub source: DiscoverySource,
    /// When the discovery event occurred.
    pub discovered_at: chrono::DateTime<Utc>,
    /// Estimated hop distance (1 for direct, higher for relayed).
    pub hops: u8,
}

/// Configuration for a discovery backend.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to re-announce (seconds).
    pub announce_interval_secs: u64,
    /// How long before a peer entry expires (seconds).
    pub peer_ttl_secs: u64,
    /// Whether this backend is enabled.
    pub enabled: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            announce_interval_secs: 300, // 5 minutes
            peer_ttl_secs: 900,          // 15 minutes
            enabled: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────
// DiscoveryBackend trait
// ─────────────────────────────────────────────────────────────

/// A discovery backend — any mechanism that can announce our presence
/// and deliver peer discoveries.
///
/// Backends are intentionally simple: they push raw announce payloads out
/// and pull discovered peer payloads in. They don't parse capabilities,
/// don't verify signatures, and don't manage the peer table — that's the
/// DiscoveryManager's job.
///
/// This separation means a backend can be a dumb relay (web) or a broadcast
/// medium (Reticulum) without knowing anything about ZeroPoint's identity model.
#[async_trait]
pub trait DiscoveryBackend: Send + Sync {
    /// Backend name (for logging and metrics).
    fn name(&self) -> &str;

    /// Which source type this backend represents.
    fn source(&self) -> DiscoverySource;

    /// Announce ourselves on this backend.
    ///
    /// The payload is the signed announce blob:
    /// `[combined_key(64)] + [capabilities_json] + [signature(64)]`
    ///
    /// Backends transmit this blob as-is. They MUST NOT parse, log, or
    /// retain the payload beyond the minimum needed for transmission.
    async fn announce(&self, payload: &[u8]) -> MeshResult<()>;

    /// Poll for newly discovered peers.
    ///
    /// Returns all discoveries since the last poll. Backends SHOULD
    /// clear their internal buffer after returning to avoid duplicates.
    ///
    /// Returns an empty vec if no new peers have been found.
    async fn poll_discoveries(&self) -> MeshResult<Vec<DiscoveredPeer>>;

    /// Check if this backend is currently operational.
    fn is_active(&self) -> bool;

    /// Shut down the backend cleanly.
    async fn shutdown(&self) -> MeshResult<()>;
}

// ─────────────────────────────────────────────────────────────
// DiscoveryManager
// ─────────────────────────────────────────────────────────────

/// Tracks per-source metadata for a discovered peer.
#[derive(Debug, Clone)]
struct PeerDiscoveryRecord {
    /// Which backends have seen this peer.
    sources: Vec<DiscoverySource>,
    /// Last announce timestamp per source.
    last_seen: HashMap<DiscoverySource, chrono::DateTime<Utc>>,
    /// The most recent capabilities.
    capabilities: Option<AgentCapabilities>,
    /// Minimum hops across all sources.
    best_hops: u8,
}

/// Manages discovery across all backends.
///
/// The DiscoveryManager is the single point that:
/// - Fans out our announce to all active backends
/// - Polls all backends for new discoveries
/// - Validates announce payloads (signature verification)
/// - Registers validated peers with the MeshNode
/// - Deduplicates peers seen via multiple backends
/// - Expires stale entries
///
/// It does NOT store query patterns or search history.
/// It does NOT index peers by capability.
/// Peer records are ephemeral — they exist only to prevent duplicate
/// registration and to track TTLs.
pub struct DiscoveryManager {
    /// Active discovery backends.
    backends: RwLock<Vec<Box<dyn DiscoveryBackend>>>,
    /// Per-peer discovery records, keyed by destination hash.
    /// This is the ONLY state the manager retains, and it's memory-only.
    peer_records: RwLock<HashMap<[u8; 16], PeerDiscoveryRecord>>,
    /// Our cached announce payload (rebuilt on each announce cycle).
    cached_announce: RwLock<Option<Vec<u8>>>,
    /// Peer TTL — entries older than this are pruned.
    peer_ttl: Duration,
    /// Discovery event count (for stats, no content logged).
    discoveries_total: RwLock<u64>,
}

impl DiscoveryManager {
    /// Create a new discovery manager.
    pub fn new(peer_ttl: Duration) -> Self {
        Self {
            backends: RwLock::new(Vec::new()),
            peer_records: RwLock::new(HashMap::new()),
            cached_announce: RwLock::new(None),
            peer_ttl,
            discoveries_total: RwLock::new(0),
        }
    }
}

impl Default for DiscoveryManager {
    /// Create with default settings (15-minute peer TTL).
    fn default() -> Self {
        Self::new(Duration::from_secs(900))
    }
}

impl DiscoveryManager {
    /// Register a discovery backend.
    pub async fn add_backend(&self, backend: Box<dyn DiscoveryBackend>) {
        info!(backend = backend.name(), "Discovery backend registered");
        self.backends.write().await.push(backend);
    }

    /// Build and cache the signed announce payload for our identity.
    ///
    /// Format: `[combined_key(64)] + [capabilities_json] + [ed25519_signature(64)]`
    /// The signature covers `combined_key + capabilities_json`.
    pub fn build_announce_payload(
        identity: &MeshIdentity,
        capabilities: &AgentCapabilities,
    ) -> MeshResult<Vec<u8>> {
        let caps_json = serde_json::to_vec(capabilities)
            .map_err(|e| MeshError::Serialization(e.to_string()))?;

        let combined_key = identity.combined_public_key();
        let mut payload = Vec::with_capacity(64 + caps_json.len() + 64);
        payload.extend_from_slice(&combined_key);
        payload.extend_from_slice(&caps_json);

        // Sign the payload (key + caps, not including the signature itself)
        let signature = identity.sign(&payload);
        payload.extend_from_slice(&signature);

        Ok(payload)
    }

    /// Announce our presence on all active backends.
    ///
    /// Builds the signed payload once and fans it out.
    pub async fn announce_all(
        &self,
        identity: &MeshIdentity,
        capabilities: &AgentCapabilities,
    ) -> MeshResult<()> {
        let payload = Self::build_announce_payload(identity, capabilities)?;

        // Cache for potential re-announce
        *self.cached_announce.write().await = Some(payload.clone());

        let backends = self.backends.read().await;
        let mut any_sent = false;

        for backend in backends.iter() {
            if backend.is_active() {
                match backend.announce(&payload).await {
                    Ok(()) => {
                        debug!(backend = backend.name(), "Announce sent");
                        any_sent = true;
                    }
                    Err(e) => {
                        warn!(
                            backend = backend.name(),
                            error = %e,
                            "Failed to announce on backend"
                        );
                    }
                }
            }
        }

        if any_sent {
            Ok(())
        } else {
            Err(MeshError::Other("No active discovery backends".into()))
        }
    }

    /// Poll all backends for new peer discoveries.
    ///
    /// Validates each discovery (signature check), deduplicates, and returns
    /// the list of newly-validated peers ready for registration.
    ///
    /// This method does NOT register peers with MeshNode — the caller
    /// (typically the runtime) does that, preserving the separation of concerns.
    pub async fn poll_all(&self) -> Vec<ValidatedDiscovery> {
        let backends = self.backends.read().await;
        let mut results = Vec::new();

        for backend in backends.iter() {
            if !backend.is_active() {
                continue;
            }

            match backend.poll_discoveries().await {
                Ok(discoveries) => {
                    for disc in discoveries {
                        match self.validate_discovery(&disc).await {
                            Ok(Some(validated)) => {
                                results.push(validated);
                            }
                            Ok(None) => {
                                // Duplicate or already-known peer, skip silently
                            }
                            Err(e) => {
                                debug!(
                                    backend = backend.name(),
                                    error = %e,
                                    "Invalid discovery payload, skipping"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        backend = backend.name(),
                        error = %e,
                        "Failed to poll discoveries"
                    );
                }
            }
        }

        if !results.is_empty() {
            let mut total = self.discoveries_total.write().await;
            *total += results.len() as u64;
        }

        results
    }

    /// Validate a raw discovery: verify signature, parse capabilities,
    /// check for duplicates, update records.
    ///
    /// Returns `Ok(Some(validated))` for new/updated peers,
    /// `Ok(None)` for known duplicates, `Err` for invalid payloads.
    async fn validate_discovery(
        &self,
        disc: &DiscoveredPeer,
    ) -> MeshResult<Option<ValidatedDiscovery>> {
        let payload = &disc.payload;

        // Minimum: 64 (key) + 1 (json) + 64 (sig)
        if payload.len() < 129 {
            return Err(MeshError::InvalidPacket(format!(
                "Announce payload too small: {} bytes",
                payload.len()
            )));
        }

        // Extract components
        let combined_key: [u8; 64] = payload[..64]
            .try_into()
            .map_err(|_| MeshError::InvalidPacket("Bad combined key".into()))?;

        let sig_start = payload.len() - 64;
        let signature: [u8; 64] = payload[sig_start..]
            .try_into()
            .map_err(|_| MeshError::InvalidPacket("Bad signature".into()))?;

        let caps_json = &payload[64..sig_start];

        // Verify Ed25519 signature
        let signing_key = &combined_key[..32];
        if !verify_announce_signature(signing_key, &payload[..sig_start], &signature) {
            return Err(MeshError::SignatureVerificationFailed);
        }

        // Parse capabilities
        let capabilities: AgentCapabilities = serde_json::from_slice(caps_json)?;

        // Build PeerIdentity
        let peer = PeerIdentity::from_combined_key(&combined_key, disc.hops)?;
        let dest_hash = peer.destination_hash;

        // Check for duplicate / update records
        let mut records = self.peer_records.write().await;
        let is_new = if let Some(record) = records.get_mut(&dest_hash) {
            // Known peer — update source tracking
            if !record.sources.contains(&disc.source) {
                record.sources.push(disc.source);
            }
            record.last_seen.insert(disc.source, disc.discovered_at);
            if disc.hops < record.best_hops {
                record.best_hops = disc.hops;
            }
            record.capabilities = Some(capabilities.clone());
            false
        } else {
            // New peer
            let mut last_seen = HashMap::new();
            last_seen.insert(disc.source, disc.discovered_at);
            records.insert(
                dest_hash,
                PeerDiscoveryRecord {
                    sources: vec![disc.source],
                    last_seen,
                    capabilities: Some(capabilities.clone()),
                    best_hops: disc.hops,
                },
            );
            true
        };

        if is_new {
            info!(
                peer_address = %hex::encode(dest_hash),
                source = %disc.source,
                agent_name = %capabilities.name,
                "New peer discovered"
            );
        }

        Ok(Some(ValidatedDiscovery {
            peer,
            capabilities,
            source: disc.source,
            is_new,
            hops: disc.hops,
        }))
    }

    /// Prune expired peer records.
    ///
    /// Entries whose last_seen across ALL sources is older than `peer_ttl`
    /// are removed. This is the only "forgetting" the manager does — and it
    /// happens by time, not by action.
    pub async fn prune_expired(&self) -> usize {
        let now = Utc::now();
        let ttl_chrono = chrono::Duration::from_std(self.peer_ttl)
            .unwrap_or_else(|_| chrono::Duration::seconds(900));

        let mut records = self.peer_records.write().await;
        let before = records.len();

        records.retain(|_dest, record| {
            // Keep if ANY source has seen the peer within TTL
            record
                .last_seen
                .values()
                .any(|ts| now.signed_duration_since(*ts) < ttl_chrono)
        });

        let pruned = before - records.len();
        if pruned > 0 {
            debug!(
                pruned,
                remaining = records.len(),
                "Pruned expired peer records"
            );
        }
        pruned
    }

    /// Get the count of known peers across all sources.
    pub async fn peer_count(&self) -> usize {
        self.peer_records.read().await.len()
    }

    /// Get total discoveries processed (counter only — no content).
    pub async fn total_discoveries(&self) -> u64 {
        *self.discoveries_total.read().await
    }

    /// Get the list of active backend names.
    pub async fn active_backends(&self) -> Vec<String> {
        self.backends
            .read()
            .await
            .iter()
            .filter(|b| b.is_active())
            .map(|b| b.name().to_string())
            .collect()
    }

    /// Shut down all backends.
    pub async fn shutdown(&self) {
        let backends = self.backends.read().await;
        for backend in backends.iter() {
            if let Err(e) = backend.shutdown().await {
                warn!(backend = backend.name(), error = %e, "Backend shutdown error");
            }
        }
        info!("All discovery backends shut down");
    }
}

// ─────────────────────────────────────────────────────────────
// Validated discovery output
// ─────────────────────────────────────────────────────────────

/// A validated, signature-checked discovery ready for peer registration.
#[derive(Debug, Clone)]
pub struct ValidatedDiscovery {
    /// The peer identity (combined key, destination hash).
    pub peer: PeerIdentity,
    /// Parsed agent capabilities.
    pub capabilities: AgentCapabilities,
    /// Which backend discovered this peer.
    pub source: DiscoverySource,
    /// Whether this is a genuinely new peer (vs. re-announcement).
    pub is_new: bool,
    /// Hop distance.
    pub hops: u8,
}

// ─────────────────────────────────────────────────────────────
// Signature verification (shared with runtime.rs)
// ─────────────────────────────────────────────────────────────

/// Verify an Ed25519 signature over announce data.
///
/// Used by both the DiscoveryManager and the runtime's direct announce handler.
pub fn verify_announce_signature(signing_key: &[u8], data: &[u8], signature: &[u8; 64]) -> bool {
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

// ─────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// A mock discovery backend for testing.
    struct MockBackend {
        backend_name: String,
        backend_source: DiscoverySource,
        active: AtomicBool,
        announced: RwLock<Vec<Vec<u8>>>,
        pending_discoveries: RwLock<Vec<DiscoveredPeer>>,
    }

    impl MockBackend {
        fn new(name: &str, source: DiscoverySource) -> Self {
            Self {
                backend_name: name.to_string(),
                backend_source: source,
                active: AtomicBool::new(true),
                announced: RwLock::new(Vec::new()),
                pending_discoveries: RwLock::new(Vec::new()),
            }
        }

        #[allow(dead_code)]
        async fn inject_discovery(&self, payload: Vec<u8>, hops: u8) {
            self.pending_discoveries.write().await.push(DiscoveredPeer {
                payload,
                source: self.backend_source,
                discovered_at: Utc::now(),
                hops,
            });
        }
    }

    #[async_trait]
    impl DiscoveryBackend for MockBackend {
        fn name(&self) -> &str {
            &self.backend_name
        }

        fn source(&self) -> DiscoverySource {
            self.backend_source
        }

        async fn announce(&self, payload: &[u8]) -> MeshResult<()> {
            self.announced.write().await.push(payload.to_vec());
            Ok(())
        }

        async fn poll_discoveries(&self) -> MeshResult<Vec<DiscoveredPeer>> {
            let mut pending = self.pending_discoveries.write().await;
            Ok(std::mem::take(&mut *pending))
        }

        fn is_active(&self) -> bool {
            self.active.load(Ordering::Relaxed)
        }

        async fn shutdown(&self) -> MeshResult<()> {
            self.active.store(false, Ordering::Relaxed);
            Ok(())
        }
    }

    fn make_test_identity_and_caps() -> (MeshIdentity, AgentCapabilities) {
        let identity = MeshIdentity::generate();
        let caps = AgentCapabilities {
            name: "test-agent".to_string(),
            version: "1.0.0".to_string(),
            receipt_types: vec!["execution".to_string()],
            skills: vec!["reasoning".to_string()],
            actor_type: "agent".to_string(),
            trust_tier: "operator".to_string(),
        };
        (identity, caps)
    }

    #[tokio::test]
    async fn test_build_announce_payload() {
        let (identity, caps) = make_test_identity_and_caps();
        let payload = DiscoveryManager::build_announce_payload(&identity, &caps).unwrap();

        // Should be: 64 (key) + json + 64 (sig)
        assert!(payload.len() >= 129);

        // Combined key should be first 64 bytes
        assert_eq!(&payload[..64], &identity.combined_public_key());

        // Signature should verify
        let sig_start = payload.len() - 64;
        let sig: [u8; 64] = payload[sig_start..].try_into().unwrap();
        assert!(verify_announce_signature(
            &payload[..32],
            &payload[..sig_start],
            &sig
        ));
    }

    #[tokio::test]
    async fn test_announce_fans_out_to_all_backends() {
        let (identity, caps) = make_test_identity_and_caps();
        let manager = DiscoveryManager::default();

        manager
            .add_backend(Box::new(MockBackend::new("web", DiscoverySource::Web)))
            .await;
        manager
            .add_backend(Box::new(MockBackend::new(
                "reticulum",
                DiscoverySource::Reticulum,
            )))
            .await;

        manager.announce_all(&identity, &caps).await.unwrap();

        // Both backends should have received the announce
        let backends = manager.backends.read().await;
        assert_eq!(backends.len(), 2);
    }

    #[tokio::test]
    async fn test_poll_validates_and_deduplicates() {
        let manager = DiscoveryManager::default();

        // Create a "remote" peer
        let (peer_id, peer_caps) = make_test_identity_and_caps();
        let payload = DiscoveryManager::build_announce_payload(&peer_id, &peer_caps).unwrap();

        // Create a mock backend with the discovery pre-loaded
        let mgr_backend = MockBackend::new("web", DiscoverySource::Web);
        mgr_backend
            .pending_discoveries
            .write()
            .await
            .push(DiscoveredPeer {
                payload: payload.clone(),
                source: DiscoverySource::Web,
                discovered_at: Utc::now(),
                hops: 1,
            });
        manager.add_backend(Box::new(mgr_backend)).await;

        // First poll: should get one new peer
        let results = manager.poll_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_new);
        assert_eq!(results[0].capabilities.name, "test-agent");
        assert_eq!(results[0].source, DiscoverySource::Web);

        // Verify peer is now tracked
        assert_eq!(manager.peer_count().await, 1);
    }

    #[tokio::test]
    async fn test_invalid_signature_rejected() {
        let manager = DiscoveryManager::default();

        // Create payload with corrupted signature
        let (peer_id, peer_caps) = make_test_identity_and_caps();
        let mut payload = DiscoveryManager::build_announce_payload(&peer_id, &peer_caps).unwrap();

        // Corrupt the last byte of the signature
        let last = payload.len() - 1;
        payload[last] ^= 0xFF;

        let mgr_backend = MockBackend::new("web", DiscoverySource::Web);
        mgr_backend
            .pending_discoveries
            .write()
            .await
            .push(DiscoveredPeer {
                payload,
                source: DiscoverySource::Web,
                discovered_at: Utc::now(),
                hops: 1,
            });
        manager.add_backend(Box::new(mgr_backend)).await;

        // Should reject — invalid signature
        let results = manager.poll_all().await;
        assert_eq!(results.len(), 0);
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_payload_too_small_rejected() {
        let manager = DiscoveryManager::default();

        let mgr_backend = MockBackend::new("reticulum", DiscoverySource::Reticulum);
        mgr_backend
            .pending_discoveries
            .write()
            .await
            .push(DiscoveredPeer {
                payload: vec![0u8; 50], // Too small
                source: DiscoverySource::Reticulum,
                discovered_at: Utc::now(),
                hops: 1,
            });
        manager.add_backend(Box::new(mgr_backend)).await;

        let results = manager.poll_all().await;
        assert_eq!(results.len(), 0);
    }

    #[tokio::test]
    async fn test_multi_source_discovery() {
        let manager = DiscoveryManager::default();

        // Same peer discovered via both backends
        let (peer_id, peer_caps) = make_test_identity_and_caps();
        let payload = DiscoveryManager::build_announce_payload(&peer_id, &peer_caps).unwrap();

        // Web backend
        let web = MockBackend::new("web", DiscoverySource::Web);
        web.pending_discoveries.write().await.push(DiscoveredPeer {
            payload: payload.clone(),
            source: DiscoverySource::Web,
            discovered_at: Utc::now(),
            hops: 2,
        });
        manager.add_backend(Box::new(web)).await;

        // First poll — new peer via web
        let results = manager.poll_all().await;
        assert_eq!(results.len(), 1);
        assert!(results[0].is_new);

        // Now add reticulum backend with same peer at lower hops
        let ret = MockBackend::new("reticulum", DiscoverySource::Reticulum);
        ret.pending_discoveries.write().await.push(DiscoveredPeer {
            payload: payload.clone(),
            source: DiscoverySource::Reticulum,
            discovered_at: Utc::now(),
            hops: 1,
        });
        manager.add_backend(Box::new(ret)).await;

        // Second poll — same peer, but via reticulum now
        let results = manager.poll_all().await;
        assert_eq!(results.len(), 1);
        assert!(!results[0].is_new); // Known peer, updated source

        // Still only one peer in records
        assert_eq!(manager.peer_count().await, 1);

        // Records should show both sources
        let records = manager.peer_records.read().await;
        let dest_hash = PeerIdentity::from_combined_key(&peer_id.combined_public_key(), 1)
            .unwrap()
            .destination_hash;
        let record = records.get(&dest_hash).unwrap();
        assert_eq!(record.sources.len(), 2);
        assert!(record.sources.contains(&DiscoverySource::Web));
        assert!(record.sources.contains(&DiscoverySource::Reticulum));
        assert_eq!(record.best_hops, 1); // Reticulum had lower hops
    }

    #[tokio::test]
    async fn test_prune_expired() {
        let manager = DiscoveryManager::new(Duration::from_millis(100));

        let (peer_id, peer_caps) = make_test_identity_and_caps();
        let payload = DiscoveryManager::build_announce_payload(&peer_id, &peer_caps).unwrap();

        let backend = MockBackend::new("web", DiscoverySource::Web);
        backend
            .pending_discoveries
            .write()
            .await
            .push(DiscoveredPeer {
                payload,
                source: DiscoverySource::Web,
                discovered_at: Utc::now() - chrono::Duration::seconds(10), // Old
                hops: 1,
            });
        manager.add_backend(Box::new(backend)).await;

        manager.poll_all().await;
        assert_eq!(manager.peer_count().await, 1);

        // Prune — the peer's last_seen is 10 seconds ago, TTL is 100ms
        let pruned = manager.prune_expired().await;
        assert_eq!(pruned, 1);
        assert_eq!(manager.peer_count().await, 0);
    }

    #[tokio::test]
    async fn test_shutdown_deactivates_all() {
        let manager = DiscoveryManager::default();
        manager
            .add_backend(Box::new(MockBackend::new("web", DiscoverySource::Web)))
            .await;
        manager
            .add_backend(Box::new(MockBackend::new(
                "ret",
                DiscoverySource::Reticulum,
            )))
            .await;

        assert_eq!(manager.active_backends().await.len(), 2);

        manager.shutdown().await;

        assert_eq!(manager.active_backends().await.len(), 0);
    }

    #[tokio::test]
    async fn test_total_discoveries_counter() {
        let manager = DiscoveryManager::default();

        let (peer_id, peer_caps) = make_test_identity_and_caps();
        let payload = DiscoveryManager::build_announce_payload(&peer_id, &peer_caps).unwrap();

        let backend = MockBackend::new("web", DiscoverySource::Web);
        backend
            .pending_discoveries
            .write()
            .await
            .push(DiscoveredPeer {
                payload,
                source: DiscoverySource::Web,
                discovered_at: Utc::now(),
                hops: 1,
            });
        manager.add_backend(Box::new(backend)).await;

        assert_eq!(manager.total_discoveries().await, 0);
        manager.poll_all().await;
        assert_eq!(manager.total_discoveries().await, 1);
    }
}
