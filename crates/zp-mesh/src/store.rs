//! Persistent mesh state — SQLite-backed durable storage.
//!
//! The `MeshStore` persists critical mesh state across restarts:
//!
//! - **Peers**: known peer identities and capabilities
//! - **Reputations**: per-peer reputation signals
//! - **Delegations**: delegation chains received from peers
//! - **Attestations**: peer audit attestation records
//! - **Policy agreements**: negotiated policy agreements
//!
//! ## Design
//!
//! Follows the same `rusqlite` pattern as `zp-audit::AuditStore`.
//! All serialization uses JSON (via serde_json) for human-readable
//! inspection and debugging. Binary blobs (destination hashes) are
//! stored as hex strings.

use std::collections::HashMap;
use std::path::Path;

use rusqlite::{params, Connection};
use tracing::{debug, info, warn};

use crate::error::{MeshError, MeshResult};
use crate::identity::PeerIdentity;
use crate::policy_sync::PolicyAgreement;
use crate::reputation::{PeerReputation, ReputationSignal};
use crate::transport::AgentCapabilities;

/// Errors specific to the mesh store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

impl From<StoreError> for MeshError {
    fn from(e: StoreError) -> Self {
        MeshError::Other(format!("Store error: {}", e))
    }
}

/// Persistent mesh state backed by SQLite.
pub struct MeshStore {
    conn: Connection,
}

impl MeshStore {
    /// Open or create a mesh store at the given path.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    /// Open an in-memory store (useful for testing).
    pub fn open_memory() -> StoreResult<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    /// Initialize all tables.
    fn init(&self) -> StoreResult<()> {
        self.conn.execute_batch(
            "
            -- Known peers
            CREATE TABLE IF NOT EXISTS peers (
                dest_hash TEXT PRIMARY KEY,
                identity_json TEXT NOT NULL,
                capabilities_json TEXT,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Reputation signals (append-only per peer)
            CREATE TABLE IF NOT EXISTS reputation_signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_hash TEXT NOT NULL,
                signal_json TEXT NOT NULL,
                recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_rep_peer ON reputation_signals(peer_hash);

            -- Delegation chains
            CREATE TABLE IF NOT EXISTS delegation_chains (
                grant_id TEXT PRIMARY KEY,
                chain_json TEXT NOT NULL,
                stored_at TEXT NOT NULL DEFAULT (datetime('now'))
            );

            -- Audit attestations
            CREATE TABLE IF NOT EXISTS audit_attestations (
                id TEXT PRIMARY KEY,
                peer_hash TEXT NOT NULL,
                attestation_json TEXT NOT NULL,
                stored_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_att_peer ON audit_attestations(peer_hash);

            -- Policy agreements
            CREATE TABLE IF NOT EXISTS policy_agreements (
                peer_hash TEXT PRIMARY KEY,
                agreement_json TEXT NOT NULL,
                stored_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            ",
        )?;

        debug!("Mesh store initialized");
        Ok(())
    }

    // =========================================================================
    // Peers
    // =========================================================================

    /// Save or update a peer identity.
    pub fn save_peer(
        &self,
        peer: &PeerIdentity,
        capabilities: Option<&AgentCapabilities>,
    ) -> StoreResult<()> {
        let dest_hex = hex::encode(peer.destination_hash);
        let identity_json = serde_json::to_string(peer)?;
        let caps_json = capabilities.map(serde_json::to_string).transpose()?;

        self.conn.execute(
            "INSERT OR REPLACE INTO peers (dest_hash, identity_json, capabilities_json, updated_at)
             VALUES (?, ?, ?, datetime('now'))",
            params![dest_hex, identity_json, caps_json],
        )?;

        debug!(peer = %dest_hex, "Peer saved");
        Ok(())
    }

    /// Load all known peers.
    pub fn load_peers(&self) -> StoreResult<Vec<(PeerIdentity, Option<AgentCapabilities>)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT identity_json, capabilities_json FROM peers")?;

        let rows = stmt
            .query_map([], |row| {
                let identity_json: String = row.get(0)?;
                let caps_json: Option<String> = row.get(1)?;
                Ok((identity_json, caps_json))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut result = Vec::new();
        for (ident_json, caps_json) in rows {
            let peer: PeerIdentity = match serde_json::from_str(&ident_json) {
                Ok(p) => p,
                Err(e) => {
                    warn!("Skipping corrupt peer record: {}", e);
                    continue;
                }
            };
            let caps = caps_json
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .unwrap_or_else(|e| {
                    warn!("Skipping corrupt capabilities: {}", e);
                    None
                });
            result.push((peer, caps));
        }

        debug!(count = result.len(), "Peers loaded");
        Ok(result)
    }

    /// Count of stored peers.
    pub fn peer_count(&self) -> StoreResult<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM peers", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // =========================================================================
    // Reputation signals
    // =========================================================================

    /// Append a reputation signal for a peer.
    pub fn save_reputation_signal(
        &self,
        peer_hash: &[u8; 16],
        signal: &ReputationSignal,
    ) -> StoreResult<()> {
        let peer_hex = hex::encode(peer_hash);
        let signal_json = serde_json::to_string(signal)?;

        self.conn.execute(
            "INSERT INTO reputation_signals (peer_hash, signal_json, recorded_at)
             VALUES (?, ?, datetime('now'))",
            params![peer_hex, signal_json],
        )?;

        Ok(())
    }

    /// Save all reputation signals for a peer (bulk replace).
    pub fn save_peer_reputation(
        &self,
        peer_hash: &[u8; 16],
        reputation: &PeerReputation,
    ) -> StoreResult<()> {
        let peer_hex = hex::encode(peer_hash);

        // Delete existing signals for this peer
        self.conn.execute(
            "DELETE FROM reputation_signals WHERE peer_hash = ?",
            params![peer_hex],
        )?;

        // Insert all current signals
        for signal in reputation.signals() {
            let signal_json = serde_json::to_string(signal)?;
            self.conn.execute(
                "INSERT INTO reputation_signals (peer_hash, signal_json, recorded_at)
                 VALUES (?, ?, datetime('now'))",
                params![peer_hex, signal_json],
            )?;
        }

        debug!(peer = %peer_hex, signals = reputation.signal_count(), "Reputation saved");
        Ok(())
    }

    /// Load all reputation signals, grouped by peer.
    pub fn load_reputations(&self) -> StoreResult<HashMap<[u8; 16], PeerReputation>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_hash, signal_json FROM reputation_signals ORDER BY id ASC")?;

        let rows = stmt
            .query_map([], |row| {
                let peer_hex: String = row.get(0)?;
                let signal_json: String = row.get(1)?;
                Ok((peer_hex, signal_json))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut reputations: HashMap<[u8; 16], PeerReputation> = HashMap::new();

        for (peer_hex, signal_json) in rows {
            let peer_hash = match hex_to_hash16(&peer_hex) {
                Some(h) => h,
                None => {
                    warn!("Skipping signal with invalid peer hash: {}", peer_hex);
                    continue;
                }
            };

            let signal: ReputationSignal = match serde_json::from_str(&signal_json) {
                Ok(s) => s,
                Err(e) => {
                    warn!("Skipping corrupt reputation signal: {}", e);
                    continue;
                }
            };

            reputations.entry(peer_hash).or_default().record(signal);
        }

        debug!(peers = reputations.len(), "Reputations loaded");
        Ok(reputations)
    }

    /// Count total reputation signals stored.
    pub fn reputation_signal_count(&self) -> StoreResult<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM reputation_signals", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    // =========================================================================
    // Delegation chains
    // =========================================================================

    /// Save a delegation chain.
    pub fn save_delegation_chain(
        &self,
        grant_id: &str,
        chain: &[zp_core::CapabilityGrant],
    ) -> StoreResult<()> {
        let chain_json = serde_json::to_string(chain)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO delegation_chains (grant_id, chain_json, stored_at)
             VALUES (?, ?, datetime('now'))",
            params![grant_id, chain_json],
        )?;

        debug!(grant_id = %grant_id, links = chain.len(), "Delegation chain saved");
        Ok(())
    }

    /// Load all delegation chains.
    pub fn load_delegation_chains(
        &self,
    ) -> StoreResult<HashMap<String, Vec<zp_core::CapabilityGrant>>> {
        let mut stmt = self
            .conn
            .prepare("SELECT grant_id, chain_json FROM delegation_chains")?;

        let rows = stmt
            .query_map([], |row| {
                let grant_id: String = row.get(0)?;
                let chain_json: String = row.get(1)?;
                Ok((grant_id, chain_json))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut chains = HashMap::new();
        for (grant_id, chain_json) in rows {
            match serde_json::from_str(&chain_json) {
                Ok(chain) => {
                    chains.insert(grant_id, chain);
                }
                Err(e) => {
                    warn!(grant_id = %grant_id, "Skipping corrupt delegation chain: {}", e);
                }
            }
        }

        debug!(count = chains.len(), "Delegation chains loaded");
        Ok(chains)
    }

    /// Count of stored delegation chains.
    pub fn delegation_chain_count(&self) -> StoreResult<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM delegation_chains", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    // =========================================================================
    // Audit attestations
    // =========================================================================

    /// Save an audit attestation.
    pub fn save_attestation(
        &self,
        peer_hash: &[u8; 16],
        attestation: &zp_audit::PeerAuditAttestation,
    ) -> StoreResult<()> {
        let peer_hex = hex::encode(peer_hash);
        let att_json = serde_json::to_string(attestation)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO audit_attestations (id, peer_hash, attestation_json, stored_at)
             VALUES (?, ?, ?, datetime('now'))",
            params![attestation.id, peer_hex, att_json],
        )?;

        debug!(id = %attestation.id, peer = %peer_hex, "Attestation saved");
        Ok(())
    }

    /// Load all audit attestations, grouped by peer.
    pub fn load_attestations(
        &self,
    ) -> StoreResult<HashMap<[u8; 16], Vec<zp_audit::PeerAuditAttestation>>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_hash, attestation_json FROM audit_attestations ORDER BY stored_at ASC",
        )?;

        let rows = stmt
            .query_map([], |row| {
                let peer_hex: String = row.get(0)?;
                let att_json: String = row.get(1)?;
                Ok((peer_hex, att_json))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut attestations: HashMap<[u8; 16], Vec<zp_audit::PeerAuditAttestation>> =
            HashMap::new();

        for (peer_hex, att_json) in rows {
            let peer_hash = match hex_to_hash16(&peer_hex) {
                Some(h) => h,
                None => {
                    warn!("Skipping attestation with invalid peer hash: {}", peer_hex);
                    continue;
                }
            };

            match serde_json::from_str(&att_json) {
                Ok(att) => {
                    attestations.entry(peer_hash).or_default().push(att);
                }
                Err(e) => {
                    warn!("Skipping corrupt attestation: {}", e);
                }
            }
        }

        debug!(peers = attestations.len(), "Attestations loaded");
        Ok(attestations)
    }

    /// Count of stored attestations.
    pub fn attestation_count(&self) -> StoreResult<usize> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM audit_attestations", [], |row| {
                    row.get(0)
                })?;
        Ok(count as usize)
    }

    // =========================================================================
    // Policy agreements
    // =========================================================================

    /// Save a policy agreement for a peer.
    pub fn save_policy_agreement(
        &self,
        peer_hash: &[u8; 16],
        agreement: &PolicyAgreement,
    ) -> StoreResult<()> {
        let peer_hex = hex::encode(peer_hash);
        let agreement_json = serde_json::to_string(agreement)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO policy_agreements (peer_hash, agreement_json, stored_at)
             VALUES (?, ?, datetime('now'))",
            params![peer_hex, agreement_json],
        )?;

        debug!(peer = %peer_hex, "Policy agreement saved");
        Ok(())
    }

    /// Load all policy agreements.
    pub fn load_policy_agreements(&self) -> StoreResult<HashMap<[u8; 16], PolicyAgreement>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer_hash, agreement_json FROM policy_agreements")?;

        let rows = stmt
            .query_map([], |row| {
                let peer_hex: String = row.get(0)?;
                let agreement_json: String = row.get(1)?;
                Ok((peer_hex, agreement_json))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        let mut agreements = HashMap::new();
        for (peer_hex, agreement_json) in rows {
            let peer_hash = match hex_to_hash16(&peer_hex) {
                Some(h) => h,
                None => continue,
            };

            match serde_json::from_str(&agreement_json) {
                Ok(agreement) => {
                    agreements.insert(peer_hash, agreement);
                }
                Err(e) => {
                    warn!("Skipping corrupt policy agreement: {}", e);
                }
            }
        }

        debug!(count = agreements.len(), "Policy agreements loaded");
        Ok(agreements)
    }

    // =========================================================================
    // Bulk save/load (for MeshNode snapshot)
    // =========================================================================

    /// Save all mesh state from a MeshNode snapshot.
    ///
    /// This performs a transactional bulk write of all state tables.
    pub fn save_snapshot(
        &self,
        peers: &HashMap<[u8; 16], PeerIdentity>,
        capabilities: &HashMap<[u8; 16], AgentCapabilities>,
        reputations: &HashMap<[u8; 16], PeerReputation>,
        delegations: &HashMap<String, Vec<zp_core::CapabilityGrant>>,
        attestations: &HashMap<[u8; 16], Vec<zp_audit::PeerAuditAttestation>>,
        agreements: &HashMap<[u8; 16], PolicyAgreement>,
    ) -> StoreResult<()> {
        self.conn.execute_batch("BEGIN TRANSACTION")?;

        let result = (|| -> StoreResult<()> {
            // Peers
            for (hash, peer) in peers {
                let caps = capabilities.get(hash);
                self.save_peer(peer, caps)?;
            }

            // Reputations
            for (hash, rep) in reputations {
                self.save_peer_reputation(hash, rep)?;
            }

            // Delegations
            for (grant_id, chain) in delegations {
                self.save_delegation_chain(grant_id, chain)?;
            }

            // Attestations
            for (hash, atts) in attestations {
                for att in atts {
                    self.save_attestation(hash, att)?;
                }
            }

            // Agreements
            for (hash, agreement) in agreements {
                self.save_policy_agreement(hash, agreement)?;
            }

            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn.execute_batch("COMMIT")?;
                info!(
                    peers = peers.len(),
                    reputations = reputations.len(),
                    delegations = delegations.len(),
                    "Mesh state snapshot saved"
                );
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

/// Convert a hex string to a 16-byte hash.
fn hex_to_hash16(hex_str: &str) -> Option<[u8; 16]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes);
    Some(hash)
}

// ============================================================================
// MeshNode integration
// ============================================================================

impl crate::transport::MeshNode {
    /// Save all mesh state to persistent storage.
    pub async fn save_to_store(&self, store: &MeshStore) -> MeshResult<()> {
        let peers = self.peers.read().await.clone();
        let capabilities = self.peer_capabilities.read().await.clone();
        let reputations = self.peer_reputations.read().await.clone();
        let delegations = self.delegation_chains.read().await.clone();
        let attestations = self.peer_audit_attestations.read().await.clone();
        let agreements = self.policy_agreements.read().await.clone();

        store.save_snapshot(
            &peers,
            &capabilities,
            &reputations,
            &delegations,
            &attestations,
            &agreements,
        )?;

        Ok(())
    }

    /// Restore mesh state from persistent storage.
    pub async fn load_from_store(&self, store: &MeshStore) -> MeshResult<()> {
        // Peers
        let loaded_peers = store.load_peers()?;
        {
            let mut peers = self.peers.write().await;
            let mut caps = self.peer_capabilities.write().await;
            for (peer, capabilities) in loaded_peers {
                let hash = peer.destination_hash;
                peers.insert(hash, peer);
                if let Some(c) = capabilities {
                    caps.insert(hash, c);
                }
            }
        }

        // Reputations
        let loaded_reps = store.load_reputations()?;
        {
            let mut reps = self.peer_reputations.write().await;
            for (hash, rep) in loaded_reps {
                reps.insert(hash, rep);
            }
        }

        // Delegations
        let loaded_delegations = store.load_delegation_chains()?;
        {
            let mut delegs = self.delegation_chains.write().await;
            for (id, chain) in loaded_delegations {
                delegs.insert(id, chain);
            }
        }

        // Attestations
        let loaded_atts = store.load_attestations()?;
        {
            let mut atts = self.peer_audit_attestations.write().await;
            for (hash, att_list) in loaded_atts {
                atts.insert(hash, att_list);
            }
        }

        // Policy agreements
        let loaded_agreements = store.load_policy_agreements()?;
        {
            let mut agreements = self.policy_agreements.write().await;
            for (hash, agreement) in loaded_agreements {
                agreements.insert(hash, agreement);
            }
        }

        info!("Mesh state loaded from store");
        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_peer(seed: u8) -> PeerIdentity {
        let mut signing_key = [0u8; 32];
        signing_key[0] = seed;
        let mut encryption_key = [0u8; 32];
        encryption_key[0] = seed;
        encryption_key[1] = 0xFF;
        let mut dest_hash = [0u8; 16];
        dest_hash[0] = seed;

        PeerIdentity {
            signing_key,
            encryption_key,
            destination_hash: dest_hash,
            first_seen: Utc::now(),
            last_announced: Utc::now(),
            hops: 1,
        }
    }

    fn make_capabilities() -> AgentCapabilities {
        AgentCapabilities {
            name: "test-agent".to_string(),
            version: "1.0".to_string(),
            receipt_types: vec!["receipt_v1".to_string()],
            skills: vec!["code_review".to_string()],
            actor_type: "agent".to_string(),
            trust_tier: "tier1".to_string(),
        }
    }

    #[test]
    fn test_store_open_memory() {
        let store = MeshStore::open_memory().unwrap();
        assert_eq!(store.peer_count().unwrap(), 0);
    }

    #[test]
    fn test_store_open_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh.db");
        let store = MeshStore::open(&path).unwrap();
        assert_eq!(store.peer_count().unwrap(), 0);
    }

    #[test]
    fn test_save_and_load_peer() {
        let store = MeshStore::open_memory().unwrap();
        let peer = make_peer(1);
        let caps = make_capabilities();

        store.save_peer(&peer, Some(&caps)).unwrap();
        assert_eq!(store.peer_count().unwrap(), 1);

        let loaded = store.load_peers().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0.destination_hash, peer.destination_hash);
        assert!(loaded[0].1.is_some());
        assert_eq!(loaded[0].1.as_ref().unwrap().name, "test-agent");
    }

    #[test]
    fn test_save_peer_without_capabilities() {
        let store = MeshStore::open_memory().unwrap();
        let peer = make_peer(2);

        store.save_peer(&peer, None).unwrap();
        let loaded = store.load_peers().unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded[0].1.is_none());
    }

    #[test]
    fn test_save_peer_upsert() {
        let store = MeshStore::open_memory().unwrap();
        let peer = make_peer(3);

        store.save_peer(&peer, None).unwrap();
        store.save_peer(&peer, Some(&make_capabilities())).unwrap();

        assert_eq!(store.peer_count().unwrap(), 1);
        let loaded = store.load_peers().unwrap();
        assert!(loaded[0].1.is_some());
    }

    #[test]
    fn test_save_and_load_reputation_signals() {
        let store = MeshStore::open_memory().unwrap();
        let peer_hash = [1u8; 16];

        let signal = crate::reputation::signal_from_receipt("r1", true, Utc::now());
        store.save_reputation_signal(&peer_hash, &signal).unwrap();

        let signal2 = crate::reputation::signal_from_delegation("d1", false, Utc::now());
        store.save_reputation_signal(&peer_hash, &signal2).unwrap();

        assert_eq!(store.reputation_signal_count().unwrap(), 2);

        let loaded = store.load_reputations().unwrap();
        assert_eq!(loaded.len(), 1);
        let rep = loaded.get(&peer_hash).unwrap();
        assert_eq!(rep.signal_count(), 2);
    }

    #[test]
    fn test_save_peer_reputation_bulk() {
        let store = MeshStore::open_memory().unwrap();
        let peer_hash = [2u8; 16];
        let mut rep = PeerReputation::new();

        rep.record(crate::reputation::signal_from_receipt(
            "r1",
            true,
            Utc::now(),
        ));
        rep.record(crate::reputation::signal_from_receipt(
            "r2",
            true,
            Utc::now(),
        ));
        rep.record(crate::reputation::signal_from_delegation(
            "d1",
            false,
            Utc::now(),
        ));

        store.save_peer_reputation(&peer_hash, &rep).unwrap();
        assert_eq!(store.reputation_signal_count().unwrap(), 3);

        // Saving again should replace
        let mut rep2 = PeerReputation::new();
        rep2.record(crate::reputation::signal_from_receipt(
            "r3",
            true,
            Utc::now(),
        ));
        store.save_peer_reputation(&peer_hash, &rep2).unwrap();
        assert_eq!(store.reputation_signal_count().unwrap(), 1);
    }

    #[test]
    fn test_save_and_load_delegation_chain() {
        let store = MeshStore::open_memory().unwrap();

        let grant = zp_core::CapabilityGrant::new(
            "grantor-1".to_string(),
            "grantee-1".to_string(),
            zp_core::capability_grant::GrantedCapability::Read {
                scope: vec!["scope:/test".to_string()],
            },
            "receipt-1".to_string(),
        );
        let chain = vec![grant];

        store.save_delegation_chain("grant-001", &chain).unwrap();
        assert_eq!(store.delegation_chain_count().unwrap(), 1);

        let loaded = store.load_delegation_chains().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded["grant-001"].len(), 1);
        assert_eq!(loaded["grant-001"][0].grantor, "grantor-1");
    }

    #[test]
    fn test_save_and_load_attestation() {
        let store = MeshStore::open_memory().unwrap();
        let peer_hash = [3u8; 16];

        let att = zp_audit::PeerAuditAttestation {
            id: "att-1".to_string(),
            peer: hex::encode(peer_hash),
            oldest_hash: "aaa".to_string(),
            newest_hash: "bbb".to_string(),
            entries_verified: 10,
            chain_valid: true,
            signatures_valid: 5,
            timestamp: Utc::now(),
            signature: None,
        };

        store.save_attestation(&peer_hash, &att).unwrap();
        assert_eq!(store.attestation_count().unwrap(), 1);

        let loaded = store.load_attestations().unwrap();
        assert_eq!(loaded.len(), 1);
        let att_list = loaded.get(&peer_hash).unwrap();
        assert_eq!(att_list.len(), 1);
        assert_eq!(att_list[0].entries_verified, 10);
        assert!(att_list[0].chain_valid);
    }

    #[test]
    fn test_save_and_load_policy_agreement() {
        let store = MeshStore::open_memory().unwrap();
        let peer_hash = [4u8; 16];

        let agreement = PolicyAgreement {
            proposal_id: "prop-1".to_string(),
            enforced: vec!["module_a".to_string()],
            rejected: vec!["module_b".to_string()],
        };

        store.save_policy_agreement(&peer_hash, &agreement).unwrap();

        let loaded = store.load_policy_agreements().unwrap();
        assert_eq!(loaded.len(), 1);
        let loaded_agreement = loaded.get(&peer_hash).unwrap();
        assert_eq!(loaded_agreement.enforced, vec!["module_a"]);
        assert_eq!(loaded_agreement.rejected, vec!["module_b"]);
    }

    #[test]
    fn test_snapshot_roundtrip() {
        let store = MeshStore::open_memory().unwrap();

        // Build up state
        let mut peers = HashMap::new();
        let peer1 = make_peer(10);
        peers.insert(peer1.destination_hash, peer1.clone());

        let mut capabilities = HashMap::new();
        capabilities.insert(peer1.destination_hash, make_capabilities());

        let mut reputations = HashMap::new();
        let mut rep = PeerReputation::new();
        rep.record(crate::reputation::signal_from_receipt(
            "r1",
            true,
            Utc::now(),
        ));
        reputations.insert(peer1.destination_hash, rep);

        let mut delegations = HashMap::new();
        let grant = zp_core::CapabilityGrant::new(
            "g".to_string(),
            "e".to_string(),
            zp_core::capability_grant::GrantedCapability::Execute { languages: vec![] },
            "receipt-all".to_string(),
        );
        delegations.insert("del-1".to_string(), vec![grant]);

        let attestations: HashMap<[u8; 16], Vec<zp_audit::PeerAuditAttestation>> = HashMap::new();

        let mut agreements = HashMap::new();
        agreements.insert(
            peer1.destination_hash,
            PolicyAgreement {
                proposal_id: "p1".to_string(),
                enforced: vec!["mod_x".to_string()],
                rejected: vec![],
            },
        );

        store
            .save_snapshot(
                &peers,
                &capabilities,
                &reputations,
                &delegations,
                &attestations,
                &agreements,
            )
            .unwrap();

        // Verify everything was saved
        assert_eq!(store.peer_count().unwrap(), 1);
        assert_eq!(store.reputation_signal_count().unwrap(), 1);
        assert_eq!(store.delegation_chain_count().unwrap(), 1);
        assert_eq!(store.attestation_count().unwrap(), 0);

        // Load everything back
        let loaded_peers = store.load_peers().unwrap();
        assert_eq!(loaded_peers.len(), 1);

        let loaded_reps = store.load_reputations().unwrap();
        assert_eq!(loaded_reps.len(), 1);

        let loaded_delegations = store.load_delegation_chains().unwrap();
        assert_eq!(loaded_delegations.len(), 1);

        let loaded_agreements = store.load_policy_agreements().unwrap();
        assert_eq!(loaded_agreements.len(), 1);
    }

    #[test]
    fn test_multiple_peers_reputations() {
        let store = MeshStore::open_memory().unwrap();

        let peer1 = [1u8; 16];
        let peer2 = [2u8; 16];

        store
            .save_reputation_signal(
                &peer1,
                &crate::reputation::signal_from_receipt("r1", true, Utc::now()),
            )
            .unwrap();
        store
            .save_reputation_signal(
                &peer2,
                &crate::reputation::signal_from_receipt("r2", false, Utc::now()),
            )
            .unwrap();
        store
            .save_reputation_signal(
                &peer2,
                &crate::reputation::signal_from_delegation("d1", true, Utc::now()),
            )
            .unwrap();

        let loaded = store.load_reputations().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[&peer1].signal_count(), 1);
        assert_eq!(loaded[&peer2].signal_count(), 2);
    }

    #[test]
    fn test_file_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mesh_persist.db");

        // Write
        {
            let store = MeshStore::open(&path).unwrap();
            let peer = make_peer(5);
            store.save_peer(&peer, Some(&make_capabilities())).unwrap();
            store
                .save_reputation_signal(
                    &peer.destination_hash,
                    &crate::reputation::signal_from_receipt("r1", true, Utc::now()),
                )
                .unwrap();
        }

        // Read from new connection
        {
            let store = MeshStore::open(&path).unwrap();
            assert_eq!(store.peer_count().unwrap(), 1);
            assert_eq!(store.reputation_signal_count().unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn test_mesh_node_save_load_roundtrip() {
        use crate::identity::MeshIdentity;
        use crate::transport::{AgentTransport, MeshNode};

        let store = MeshStore::open_memory().unwrap();

        // Create a node and populate it
        let identity = MeshIdentity::generate();
        let node = MeshNode::new(identity);

        // Register a peer
        let peer_identity = MeshIdentity::generate();
        let peer_id = crate::identity::PeerIdentity::from_combined_key(
            &peer_identity.combined_public_key(),
            1,
        )
        .unwrap();
        let dest_hash = peer_id.destination_hash;
        node.register_peer(peer_id, Some(make_capabilities())).await;

        // Record a reputation signal
        node.record_reputation_signal(
            &dest_hash,
            crate::reputation::signal_from_receipt("r1", true, Utc::now()),
        )
        .await;

        // Save state
        node.save_to_store(&store).await.unwrap();

        // Create a fresh node and load state
        let identity2 = MeshIdentity::generate();
        let node2 = MeshNode::new(identity2);
        node2.load_from_store(&store).await.unwrap();

        // Verify loaded state
        let peers = node2.known_peers().await;
        assert_eq!(peers.len(), 1);

        let reps = node2.all_peer_reputations().await;
        assert_eq!(reps.len(), 1);
    }
}
