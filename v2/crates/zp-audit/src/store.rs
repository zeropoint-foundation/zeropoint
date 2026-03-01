use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;
use tracing::{debug, info, warn};

use zp_core::{AuditEntry, AuditId, ConversationId};

/// Errors that can occur in the audit store.
#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Chain verification failed: entry {id} has invalid hash chain")]
    ChainVerificationFailed { id: String },

    #[error("No entries found in audit log")]
    NoEntries,
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// The audit store manages an append-only SQLite database of audit entries
/// with hash-chained verification for integrity.
pub struct AuditStore {
    conn: Connection,
}

impl AuditStore {
    /// Opens or creates an audit store at the given path.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(StoreError::Database)?;

        let store = AuditStore { conn };
        store.init()?;
        Ok(store)
    }

    /// Initializes the audit_entries table if it doesn't exist.
    fn init(&self) -> Result<()> {
        self.conn
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS audit_entries (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    policy_decision TEXT NOT NULL,
                    policy_module TEXT NOT NULL,
                    receipt TEXT,
                    signature TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_conversation_id ON audit_entries(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_entries(timestamp);
                ",
            )
            .map_err(StoreError::Database)?;

        info!("Audit store initialized");
        Ok(())
    }

    /// Appends a new audit entry to the store.
    /// This is the only way to add entries — the table is append-only.
    pub fn append(&self, entry: AuditEntry) -> Result<()> {
        let timestamp = entry.timestamp.to_rfc3339();
        let conversation_id_str = format!("{:?}", entry.conversation_id.0);
        let actor = format!("{:?}", entry.actor);
        let action = serde_json::to_string(&entry.action)?;
        let policy_decision = serde_json::to_string(&entry.policy_decision)?;
        let receipt = entry
            .receipt
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        self.conn
            .execute(
                "INSERT INTO audit_entries 
                 (id, timestamp, prev_hash, entry_hash, actor, action, conversation_id, 
                  policy_decision, policy_module, receipt, signature)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    format!("{:?}", entry.id.0),
                    timestamp,
                    entry.prev_hash,
                    entry.entry_hash,
                    actor,
                    action,
                    conversation_id_str,
                    policy_decision,
                    entry.policy_module,
                    receipt,
                    entry.signature,
                ],
            )
            .map_err(StoreError::Database)?;

        debug!("Appended audit entry: {:?}", entry.id.0);
        Ok(())
    }

    /// Execute a raw SQL statement (for demo/simulation purposes only).
    pub fn execute_raw(&self, sql: &str) -> Result<()> {
        self.conn.execute_batch(sql).map_err(StoreError::Database)?;
        Ok(())
    }

    /// Returns the hash of the most recent entry, or a genesis hash if the log is empty.
    pub fn get_latest_hash(&self) -> Result<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry_hash FROM audit_entries ORDER BY timestamp DESC LIMIT 1")
            .map_err(StoreError::Database)?;

        let result = stmt
            .query_row([], |row| row.get::<_, String>(0))
            .optional()
            .map_err(StoreError::Database)?;

        match result {
            Some(hash) => Ok(hash),
            None => {
                // Genesis hash: blake3 of empty string
                let genesis = blake3::hash(b"").to_hex().to_string();
                debug!("Audit log is empty, returning genesis hash: {}", genesis);
                Ok(genesis)
            }
        }
    }

    /// Retrieves all entries for a given conversation ID, up to `limit` most recent entries.
    pub fn get_entries(
        &self,
        conversation_id: &ConversationId,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        let conversation_id_str = format!("{:?}", conversation_id.0);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, prev_hash, entry_hash, actor, action, 
                        conversation_id, policy_decision, policy_module, receipt, signature
                 FROM audit_entries
                 WHERE conversation_id = ?
                 ORDER BY timestamp DESC
                 LIMIT ?",
            )
            .map_err(StoreError::Database)?;

        let entries = stmt
            .query_map(params![conversation_id_str, limit], |row| {
                let id_str: String = row.get(0)?;
                let timestamp_str: String = row.get(1)?;
                let prev_hash: String = row.get(2)?;
                let entry_hash: String = row.get(3)?;
                let actor_json: String = row.get(4)?;
                let action_json: String = row.get(5)?;
                let conv_id_str: String = row.get(6)?;
                let policy_decision_json: String = row.get(7)?;
                let policy_module: String = row.get(8)?;
                let receipt_json: Option<String> = row.get(9)?;
                let signature: Option<String> = row.get(10)?;

                Ok((
                    id_str,
                    timestamp_str,
                    prev_hash,
                    entry_hash,
                    actor_json,
                    action_json,
                    conv_id_str,
                    policy_decision_json,
                    policy_module,
                    receipt_json,
                    signature,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        let mut result = Vec::new();
        for (
            id_str,
            timestamp_str,
            prev_hash,
            entry_hash,
            actor_json,
            action_json,
            _conv_id_str,
            policy_decision_json,
            policy_module,
            receipt_json,
            signature,
        ) in entries
        {
            let id = uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::nil());
            let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);
            let actor = serde_json::from_str(&actor_json)
                .unwrap_or_else(|_| zp_core::ActorId::System("unknown".to_string()));
            let action = serde_json::from_str(&action_json).unwrap_or_else(|_| {
                zp_core::AuditAction::SystemEvent {
                    event: "unknown".to_string(),
                }
            });
            let conversation_id = ConversationId(
                uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::nil()),
            );
            let policy_decision =
                serde_json::from_str(&policy_decision_json).unwrap_or_else(|_| {
                    zp_core::PolicyDecision::Block {
                        reason: "unknown".to_string(),
                        policy_module: "unknown".to_string(),
                    }
                });
            let receipt = receipt_json
                .as_ref()
                .and_then(|json| serde_json::from_str(json).ok());

            result.push(AuditEntry {
                id: AuditId(id),
                timestamp,
                prev_hash,
                entry_hash,
                actor,
                action,
                conversation_id,
                policy_decision,
                policy_module,
                receipt,
                signature,
            });
        }

        Ok(result)
    }

    /// Export a chain segment for peer verification.
    ///
    /// Returns entries in chronological order (oldest first), suitable for
    /// passing to `ChainVerifier::verify()`.
    pub fn export_chain(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                        conversation_id, policy_decision, policy_module, receipt, signature
                 FROM audit_entries
                 ORDER BY timestamp ASC
                 LIMIT ?",
            )
            .map_err(StoreError::Database)?;

        let entries = stmt
            .query_map(params![limit], |row| {
                let id_str: String = row.get(0)?;
                let timestamp_str: String = row.get(1)?;
                let prev_hash: String = row.get(2)?;
                let entry_hash: String = row.get(3)?;
                let actor_json: String = row.get(4)?;
                let action_json: String = row.get(5)?;
                let conv_id_str: String = row.get(6)?;
                let policy_decision_json: String = row.get(7)?;
                let policy_module: String = row.get(8)?;
                let receipt_json: Option<String> = row.get(9)?;
                let signature: Option<String> = row.get(10)?;

                Ok((
                    id_str,
                    timestamp_str,
                    prev_hash,
                    entry_hash,
                    actor_json,
                    action_json,
                    conv_id_str,
                    policy_decision_json,
                    policy_module,
                    receipt_json,
                    signature,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        let mut result = Vec::new();
        for (
            id_str,
            timestamp_str,
            prev_hash,
            entry_hash,
            actor_json,
            action_json,
            conv_id_str,
            policy_decision_json,
            policy_module,
            receipt_json,
            signature,
        ) in entries
        {
            let id = uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::nil());
            let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);
            let actor = serde_json::from_str(&actor_json)
                .unwrap_or_else(|_| zp_core::ActorId::System("unknown".to_string()));
            let action = serde_json::from_str(&action_json).unwrap_or_else(|_| {
                zp_core::AuditAction::SystemEvent {
                    event: "unknown".to_string(),
                }
            });
            let conversation_id = zp_core::ConversationId(
                uuid::Uuid::parse_str(&conv_id_str).unwrap_or_else(|_| uuid::Uuid::nil()),
            );
            let policy_decision =
                serde_json::from_str(&policy_decision_json).unwrap_or_else(|_| {
                    zp_core::PolicyDecision::Block {
                        reason: "unknown".to_string(),
                        policy_module: "unknown".to_string(),
                    }
                });
            let receipt = receipt_json
                .as_ref()
                .and_then(|json| serde_json::from_str(json).ok());

            result.push(AuditEntry {
                id: zp_core::AuditId(id),
                timestamp,
                prev_hash,
                entry_hash,
                actor,
                action,
                conversation_id,
                policy_decision,
                policy_module,
                receipt,
                signature,
            });
        }

        Ok(result)
    }

    /// Verify chain linkage integrity with a detailed report.
    ///
    /// Checks that stored entry hashes form a valid chain (each entry's
    /// `prev_hash` matches the previous entry's `entry_hash`). Does NOT
    /// recompute hashes — that requires the original in-memory `AuditEntry`
    /// objects (use `ChainVerifier::verify` for peer-provided entries).
    pub fn verify_with_report(&self) -> Result<crate::verifier::VerificationReport> {
        let chain = self.export_chain(i32::MAX as usize)?;
        Ok(crate::verifier::verify_linkage_report(&chain, None))
    }

    /// Verifies the integrity of the entire hash chain.
    /// Walks through all entries in chronological order and ensures each entry's
    /// entry_hash matches prev_hash of the next entry.
    pub fn verify_chain(&self) -> Result<bool> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, prev_hash, entry_hash FROM audit_entries ORDER BY timestamp ASC")
            .map_err(StoreError::Database)?;

        let entries: Vec<(String, String, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        if entries.is_empty() {
            debug!("Chain verification: empty log is valid");
            return Ok(true);
        }

        // Check genesis: first entry's prev_hash should match the genesis hash
        let genesis_hash = blake3::hash(b"").to_hex().to_string();
        if entries[0].1 != genesis_hash {
            warn!(
                "Chain verification failed: first entry {} has incorrect prev_hash",
                entries[0].0
            );
            return Err(StoreError::ChainVerificationFailed {
                id: entries[0].0.clone(),
            });
        }

        // Verify each link: entry[i].entry_hash == entry[i+1].prev_hash
        for i in 0..entries.len() - 1 {
            let current_hash = &entries[i].2;
            let next_prev_hash = &entries[i + 1].1;

            if current_hash != next_prev_hash {
                warn!(
                    "Chain verification failed: entry {} hash {} does not match next entry's prev_hash {}",
                    entries[i].0, current_hash, next_prev_hash
                );
                return Err(StoreError::ChainVerificationFailed {
                    id: entries[i].0.clone(),
                });
            }
        }

        info!("Chain verification succeeded for {} entries", entries.len());
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainBuilder;
    use zp_core::{ActorId, AuditAction, PolicyDecision};

    fn make_test_entry(prev_hash: &str, module: &str) -> AuditEntry {
        let actor = ActorId::System("test-agent".to_string());
        let action = AuditAction::SystemEvent {
            event: "test".to_string(),
        };
        let conv_id = ConversationId(uuid::Uuid::now_v7());
        let decision = PolicyDecision::Allow { conditions: vec![] };

        ChainBuilder::build_entry(
            prev_hash,
            actor,
            action,
            conv_id,
            decision,
            module.to_string(),
            None,
            None,
        )
    }

    #[test]
    fn test_genesis_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        let hash = store.get_latest_hash().unwrap();
        let expected = blake3::hash(b"").to_hex().to_string();
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_export_chain_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();

        let chain = store.export_chain(100).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_export_chain_with_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();

        let genesis = blake3::hash(b"").to_hex().to_string();
        let entry1 = make_test_entry(&genesis, "mod1");
        let entry2 = make_test_entry(&entry1.entry_hash, "mod2");

        store.append(entry1).unwrap();
        store.append(entry2).unwrap();

        let chain = store.export_chain(100).unwrap();
        assert_eq!(chain.len(), 2);
        // Should be in chronological order
        assert_eq!(chain[1].prev_hash, chain[0].entry_hash);
    }

    #[test]
    fn test_verify_with_report_on_valid_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();

        let genesis = blake3::hash(b"").to_hex().to_string();
        let entry1 = make_test_entry(&genesis, "mod1");
        let entry2 = make_test_entry(&entry1.entry_hash, "mod2");
        let entry3 = make_test_entry(&entry2.entry_hash, "mod3");

        store.append(entry1).unwrap();
        store.append(entry2).unwrap();
        store.append(entry3).unwrap();

        let report = store.verify_with_report().unwrap();

        assert!(report.chain_valid);
        assert!(report.is_clean());
        assert_eq!(report.entries_examined, 3);
        assert_eq!(report.hashes_valid, 3);
        assert_eq!(report.chain_links_valid, 3);
    }
}
