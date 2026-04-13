use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use thiserror::Error;
use tracing::{debug, info, warn};

use zp_core::{AuditEntry, AuditId, ConversationId};

use crate::chain::{genesis_hash, new_audit_id, seal_entry, UnsealedEntry};

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

    #[error(
        "audit DB schema version mismatch: found v{found}, expected v{expected} — \
         run `security/pentest-2026-04-06/forensic-dump-audit-03.sh` to preserve \
         forensic evidence, then delete `audit.db` and let the server recreate it"
    )]
    SchemaMismatch { found: i32, expected: i32 },
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

    /// Schema version of the canonical audit store. Stage 4 of the
    /// AUDIT-03 recanonicalization. A store with a different `user_version`
    /// is rejected at `open` time — callers must drop and recreate the DB
    /// (preserving forensic evidence separately; see
    /// `security/pentest-2026-04-06/forensic-dump-audit-03.sh`).
    const SCHEMA_VERSION: i32 = 2;

    /// Initializes the audit_entries table and enforces the canonical
    /// schema. This is the single place that defines the audit store's
    /// on-disk shape — everything else reads/writes via typed methods.
    ///
    /// # Stage 4 invariants
    ///
    /// * `journal_mode = WAL` and `synchronous = NORMAL` are set on every
    ///   open (not best-effort; a failure is surfaced).
    /// * `audit_entries` carries a `UNIQUE(prev_hash)` partial index that
    ///   excludes the genesis hash, so any second row claiming the same
    ///   parent is rejected at the storage layer — a belt-and-suspenders
    ///   complement to `BEGIN IMMEDIATE` in `append`.
    /// * `user_version` pragma is stamped with `SCHEMA_VERSION`. Opening
    ///   a DB with a mismatched version returns an error instead of
    ///   silently migrating.
    fn init(&self) -> Result<()> {
        // WAL + synchronous=NORMAL are part of the canonical schema: the
        // chain's durability/consistency story depends on them. We surface
        // any failure instead of silently falling back.
        self.conn
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(StoreError::Database)?;
        self.conn
            .pragma_update(None, "synchronous", "NORMAL")
            .map_err(StoreError::Database)?;

        // Read the current user_version (0 on a brand-new database).
        let version: i32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(StoreError::Database)?;

        if version != 0 && version != Self::SCHEMA_VERSION {
            return Err(StoreError::SchemaMismatch {
                found: version,
                expected: Self::SCHEMA_VERSION,
            });
        }

        // Canonical schema. Note the partial UNIQUE index on prev_hash:
        // every non-genesis entry must have a unique parent, which makes a
        // concurrent-append fork (AUDIT-03) a storage-layer constraint
        // violation, not just a chain-verifier finding.
        let genesis = genesis_hash();
        self.conn
            .execute_batch(&format!(
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
                CREATE INDEX IF NOT EXISTS idx_conversation_id
                    ON audit_entries(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_timestamp
                    ON audit_entries(timestamp);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_prev_hash
                    ON audit_entries(prev_hash)
                    WHERE prev_hash != '{genesis}';
                "
            ))
            .map_err(StoreError::Database)?;

        if version == 0 {
            self.conn
                .pragma_update(None, "user_version", Self::SCHEMA_VERSION)
                .map_err(StoreError::Database)?;
        }

        info!(
            "Audit store initialized (schema v{})",
            Self::SCHEMA_VERSION
        );
        Ok(())
    }

    /// Append a new audit entry to the store.
    ///
    /// This is the **only** way to add entries to the audit chain.
    /// Callers pass an [`UnsealedEntry`] containing the application-level
    /// fields (actor, action, etc.) and the store atomically:
    ///
    /// 1. Acquires a `BEGIN IMMEDIATE` transaction (SQLite RESERVED lock —
    ///    serializes writers across both in-process handles and OS processes).
    /// 2. Reads the current chain tip (`MAX(rowid)`).
    /// 3. Allocates a fresh `id` and `timestamp`.
    /// 4. Computes `entry_hash` via `chain::seal_entry`.
    /// 5. Inserts the row.
    /// 6. Commits.
    ///
    /// This closes both layers of AUDIT-03: callers can no longer compute a
    /// stale `prev_hash` (because they don't compute it at all), and concurrent
    /// `AuditStore` handles can no longer race (because the lock is at the
    /// SQLite file level, not the connection level).
    ///
    /// Returns the fully-sealed [`AuditEntry`] so callers that need to
    /// reference its `entry_hash` (e.g. to chain receipts) can do so.
    ///
    /// All identity and policy fields are serialized via `serde_json`, fixing
    /// AUDIT-02 (the silent Debug-format round-trip data loss).
    pub fn append(&mut self, unsealed: UnsealedEntry) -> Result<AuditEntry> {
        // AUDIT-04: redact bearer tokens, API keys, and other secret-shaped
        // substrings from free-text fields before the entry is sealed. The
        // scrubber is always on — there is no opt-out — because the audit
        // chain is the forensic record and must never hold a live credential.
        let unsealed = crate::scrub::scrub_unsealed(unsealed);

        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::Database)?;

        // Read the current chain tip from inside the transaction. Using rowid
        // (not timestamp) because the new transactional path inserts in chain
        // order, and rowid is monotonic with insertion. Sub-millisecond
        // timestamp ties were one of the symptoms of AUDIT-03.
        let prev_hash: String = tx
            .query_row(
                "SELECT entry_hash FROM audit_entries ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(StoreError::Database)?
            .unwrap_or_else(genesis_hash);

        let id = new_audit_id();
        let timestamp = chrono::Utc::now();

        let sealed = seal_entry(&unsealed, &prev_hash, id, timestamp);

        // Serialize fields with proper JSON (AUDIT-02 fix). conversation_id
        // and id use Display (Uuid hyphenated form) so the read path can
        // round-trip them with Uuid::parse_str.
        let id_str = sealed.id.0.to_string();
        let timestamp_str = sealed.timestamp.to_rfc3339();
        let conversation_id_str = sealed.conversation_id.0.to_string();
        let actor_json = serde_json::to_string(&sealed.actor)?;
        let action_json = serde_json::to_string(&sealed.action)?;
        let policy_decision_json = serde_json::to_string(&sealed.policy_decision)?;
        let receipt_json = sealed
            .receipt
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        tx.execute(
            "INSERT INTO audit_entries
             (id, timestamp, prev_hash, entry_hash, actor, action, conversation_id,
              policy_decision, policy_module, receipt, signature)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                id_str,
                timestamp_str,
                sealed.prev_hash,
                sealed.entry_hash,
                actor_json,
                action_json,
                conversation_id_str,
                policy_decision_json,
                sealed.policy_module,
                receipt_json,
                sealed.signature,
            ],
        )
        .map_err(StoreError::Database)?;

        tx.commit().map_err(StoreError::Database)?;

        debug!("Appended audit entry: {}", sealed.id.0);
        Ok(sealed)
    }

    /// Overwrite an entry's `entry_hash`. **Demo/pentest only.**
    ///
    /// This is the single, narrow back door that replaces the old
    /// `execute_raw` SQL-injection surface. It is only compiled when the
    /// `pentest-demo` feature is enabled, takes the entry id and new hash
    /// as parameterized values (no SQL string formatting), and exists
    /// solely so the integrity-demo endpoints can corrupt and then
    /// recover a single row. See docs/audit-invariant.md §Back doors.
    #[cfg(feature = "pentest-demo")]
    pub fn tamper_entry_hash(&self, id: &str, new_hash: &str) -> Result<()> {
        warn!(entry_id = id, "pentest-demo: tampering entry_hash");
        let affected = self
            .conn
            .execute(
                "UPDATE audit_entries SET entry_hash = ?1 WHERE id = ?2",
                params![new_hash, id],
            )
            .map_err(StoreError::Database)?;
        if affected == 0 {
            return Err(StoreError::NoEntries);
        }
        Ok(())
    }

    /// Restore an entry's `entry_hash` to a known-good value.
    /// Companion to [`Self::tamper_entry_hash`]; same demo-only contract.
    #[cfg(feature = "pentest-demo")]
    pub fn restore_entry_hash(&self, id: &str, original_hash: &str) -> Result<()> {
        warn!(entry_id = id, "pentest-demo: restoring entry_hash");
        let affected = self
            .conn
            .execute(
                "UPDATE audit_entries SET entry_hash = ?1 WHERE id = ?2",
                params![original_hash, id],
            )
            .map_err(StoreError::Database)?;
        if affected == 0 {
            return Err(StoreError::NoEntries);
        }
        Ok(())
    }

    /// Clear all audit entries (reset the chain). Returns the number of entries deleted.
    pub fn clear(&self) -> Result<usize> {
        let count = self
            .conn
            .execute("DELETE FROM audit_entries", [])
            .map_err(StoreError::Database)?;
        info!("Cleared {} audit entries", count);
        Ok(count)
    }

    /// Returns the hash of the most recent entry, or a genesis hash if the
    /// log is empty.
    ///
    /// **As of AUDIT-03, callers should not use this to compute their own
    /// `prev_hash` and then call `append`. Use [`Self::append`] directly —
    /// it reads the tip atomically inside the append transaction.** This
    /// method exists for read-only inspection paths only.
    pub fn get_latest_hash(&self) -> Result<String> {
        let mut stmt = self
            .conn
            .prepare("SELECT entry_hash FROM audit_entries ORDER BY rowid DESC LIMIT 1")
            .map_err(StoreError::Database)?;

        let result = stmt
            .query_row([], |row| row.get::<_, String>(0))
            .optional()
            .map_err(StoreError::Database)?;

        match result {
            Some(hash) => Ok(hash),
            None => {
                let g = genesis_hash();
                debug!("Audit log is empty, returning genesis hash: {}", g);
                Ok(g)
            }
        }
    }

    /// Retrieves all entries for a given conversation ID, up to `limit` most recent entries.
    pub fn get_entries(
        &self,
        conversation_id: &ConversationId,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        // AUDIT-02 fix: new entries store conversation_id as Display
        // (hyphenated UUID), not Debug. Use the same format here.
        let conversation_id_str = conversation_id.0.to_string();
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
            // AUDIT-02 fix: was parsing id_str (typo). Use the actual
            // conv_id column read from the row.
            let conversation_id = ConversationId(
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
                 ORDER BY rowid ASC
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
            .prepare("SELECT id, prev_hash, entry_hash FROM audit_entries ORDER BY rowid ASC")
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
    use zp_core::{ActorId, AuditAction, PolicyDecision};

    fn unsealed(module: &str) -> UnsealedEntry {
        UnsealedEntry::new(
            ActorId::System("test-agent".to_string()),
            AuditAction::SystemEvent {
                event: "test".to_string(),
            },
            ConversationId(uuid::Uuid::now_v7()),
            PolicyDecision::Allow { conditions: vec![] },
            module,
        )
    }

    #[test]
    fn test_genesis_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        let hash = store.get_latest_hash().unwrap();
        assert_eq!(hash, genesis_hash());
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
    fn test_append_links_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open(&path).unwrap();

        let e1 = store.append(unsealed("mod1")).unwrap();
        let e2 = store.append(unsealed("mod2")).unwrap();

        // Store assigns prev_hash atomically — caller never touches it.
        assert_eq!(e1.prev_hash, genesis_hash());
        assert_eq!(e2.prev_hash, e1.entry_hash);

        let chain = store.export_chain(100).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].prev_hash, chain[0].entry_hash);
    }

    #[test]
    fn test_verify_with_report_on_valid_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open(&path).unwrap();

        store.append(unsealed("mod1")).unwrap();
        store.append(unsealed("mod2")).unwrap();
        store.append(unsealed("mod3")).unwrap();

        let report = store.verify_with_report().unwrap();

        assert!(report.chain_valid);
        assert!(report.is_clean());
        assert_eq!(report.entries_examined, 3);
        assert_eq!(report.hashes_valid, 3);
        assert_eq!(report.chain_links_valid, 3);
    }

    /// AUDIT-03 regression: verify with the catalog grammar that a chain
    /// produced by sequential appends is well-formed.
    #[test]
    fn test_catalog_verify_after_sequential_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open(&path).unwrap();

        for i in 0..10 {
            store.append(unsealed(&format!("mod{i}"))).unwrap();
        }

        let report = store.verify_with_catalog().unwrap();
        assert!(
            report.violations().is_empty(),
            "expected ACCEPT but got {:?}",
            report.violations()
        );
        assert_eq!(report.receipts_checked, 10);
    }

    /// AUDIT-03 regression: the production race was caused by **two**
    /// `AuditStore` handles on the same DB file (AppState + Pipeline),
    /// each guarded by its own private `Mutex`, so in-process locking
    /// could not serialize them. The fix is `BEGIN IMMEDIATE`, which
    /// takes a SQLite RESERVED lock at the file level and therefore
    /// serializes writers across handles.
    ///
    /// This test mirrors that exact shape: two `AuditStore` instances
    /// on the same file, multiple writer threads per instance, then
    /// `verify_with_catalog` over the merged chain. With the
    /// transactional append, the result must be ACCEPT.
    #[test]
    fn test_concurrent_append_two_handles_same_file() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");

        let store_a = Arc::new(Mutex::new(AuditStore::open(&path).unwrap()));
        let store_b = Arc::new(Mutex::new(AuditStore::open(&path).unwrap()));

        const THREADS_PER_HANDLE: usize = 4;
        const APPENDS_PER_THREAD: usize = 25;

        let mut handles = vec![];
        for handle in [&store_a, &store_b] {
            for t in 0..THREADS_PER_HANDLE {
                let s = Arc::clone(handle);
                handles.push(thread::spawn(move || {
                    for i in 0..APPENDS_PER_THREAD {
                        let u = UnsealedEntry::new(
                            ActorId::System(format!("worker-{t}")),
                            AuditAction::SystemEvent {
                                event: format!("evt-{i}"),
                            },
                            ConversationId(uuid::Uuid::now_v7()),
                            PolicyDecision::Allow { conditions: vec![] },
                            "concurrent-test",
                        );
                        s.lock().unwrap().append(u).unwrap();
                    }
                }));
            }
        }
        for h in handles {
            h.join().unwrap();
        }

        let expected = 2 * THREADS_PER_HANDLE * APPENDS_PER_THREAD;
        let report = store_a.lock().unwrap().verify_with_catalog().unwrap();
        assert_eq!(report.receipts_checked, expected);
        assert!(
            report.violations().is_empty(),
            "expected ACCEPT but got {} violations: {:?}",
            report.violations().len(),
            report.violations()
        );
    }

    /// Round-trip property test (Stage 5 of AUDIT-03 recanonicalization).
    ///
    /// For every append, the sealed entry returned by `append` must be
    /// bit-exactly recoverable via `get_entries`, and the recovered
    /// entry's `entry_hash` must survive a recompute. This pins the
    /// single-entry-equality contract from docs/audit-invariant.md and
    /// guards against any future drift between the `seal_entry` preimage
    /// and the `get_entries` read path (the AUDIT-02 failure mode).
    #[test]
    fn test_append_get_roundtrip_preserves_hash() {
        use crate::chain::recompute_entry_hash;

        let dir = tempfile::tempdir().unwrap();
        let mut store = AuditStore::open(dir.path().join("audit.db")).unwrap();

        let mut sealed_ids = Vec::new();
        let mut sealed_hashes = Vec::new();
        let convo = ConversationId(uuid::Uuid::now_v7());

        for i in 0..10 {
            let u = UnsealedEntry::new(
                ActorId::User(format!("user-{i}")),
                AuditAction::SystemEvent {
                    event: format!("roundtrip-{i}"),
                },
                convo.clone(),
                PolicyDecision::Allow { conditions: vec![] },
                "roundtrip-test",
            );
            let sealed = store.append(u).unwrap();
            // The returned sealed entry must round-trip its own hash.
            assert_eq!(
                recompute_entry_hash(&sealed),
                sealed.entry_hash,
                "seal_entry / recompute_entry_hash drift at i={i}"
            );
            sealed_ids.push(sealed.id.0);
            sealed_hashes.push(sealed.entry_hash.clone());
        }

        // Now read them back via the public query path and confirm every
        // recovered row still re-hashes to the stored entry_hash. This is
        // exactly what the catalog verifier's strict P2 check asserts.
        let got = store.get_entries(&convo, 100).unwrap();
        assert_eq!(got.len(), 10);
        for entry in &got {
            assert_eq!(
                recompute_entry_hash(entry),
                entry.entry_hash,
                "DB round-trip altered the hash preimage for entry {}",
                entry.id.0
            );
            assert!(sealed_ids.contains(&entry.id.0));
            assert!(sealed_hashes.contains(&entry.entry_hash));
        }

        // And the catalog verifier — now in strict P2 mode — must ACCEPT.
        let report = store.verify_with_catalog().unwrap();
        assert!(
            report.violations().is_empty(),
            "strict P2 rejected a fresh chain: {:?}",
            report.violations()
        );
    }

    // ========================================================================
    // Sweep 5 — Tier 2 hardening tests
    // ========================================================================

    /// Sweep 5 — schema migration: opening a DB stamped with `user_version=1`
    /// must be rejected with `StoreError::SchemaMismatch`, not silently
    /// upgraded. This guards the contract documented in
    /// `docs/audit-architecture.md` §4 (no in-place migration; preserve as
    /// forensic evidence and recreate).
    #[test]
    fn test_sweep5_rejects_v1_schema() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");

        // Build a "v1" database the way one would have looked: any non-zero,
        // non-current user_version stamped, with some prior table shape.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE audit_entries (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL
                );",
            )
            .unwrap();
            conn.pragma_update(None, "user_version", 1i32).unwrap();
        }

        // Now AuditStore::open must refuse it.
        let err = match AuditStore::open(&path) {
            Ok(_) => panic!("expected SchemaMismatch, got Ok"),
            Err(e) => e,
        };
        match err {
            StoreError::SchemaMismatch { found, expected } => {
                assert_eq!(found, 1);
                assert_eq!(expected, 2);
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    /// Sweep 5 — schema migration: a v0 database (PRAGMA user_version = 0,
    /// the brand-new state) must be accepted and stamped to v2. This is the
    /// "fresh install" path and must remain frictionless.
    #[test]
    fn test_sweep5_accepts_v0_and_stamps_v2() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");

        // Create the file but leave user_version = 0 (the SQLite default).
        {
            let _conn = Connection::open(&path).unwrap();
        }

        let store = AuditStore::open(&path).unwrap();
        let v: i32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, 2, "fresh open must stamp user_version=2");
    }

    /// Sweep 5 — fork rejection at the storage layer.
    ///
    /// `BEGIN IMMEDIATE` serializes legitimate writers, so a fork can only
    /// be produced by code that bypasses the `append` path entirely (a bug,
    /// a malicious dump-and-restore, or a stale `tamper_entry_hash` follow-up).
    /// The partial UNIQUE index `idx_unique_prev_hash` is the belt-and-
    /// suspenders that catches such a fork at the storage layer.
    ///
    /// This test reaches around `append` with a raw `Connection` and
    /// confirms:
    ///
    ///   1. The duplicate-`prev_hash` insert is rejected.
    ///   2. The rejection surfaces as a SQLITE_CONSTRAINT_UNIQUE error
    ///      (extended code 2067), so callers that want to translate it to
    ///      a domain-level "fork detected" alert can do so reliably.
    ///   3. After the rejected insert, the legitimate `append` path still
    ///      works (the failed transaction did not poison the chain).
    #[test]
    fn test_sweep5_partial_unique_index_rejects_fork() {
        use rusqlite::ErrorCode;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open(&path).unwrap();

        // Lay down two legitimate entries so we have a real prev_hash to
        // collide with.
        let e1 = store.append(unsealed("mod1")).unwrap();
        let _e2 = store.append(unsealed("mod2")).unwrap();

        // Open a side connection (simulates the failure mode: any writer
        // that does NOT go through `append`'s BEGIN IMMEDIATE path).
        let side = Connection::open(&path).unwrap();
        let inject = side.execute(
            "INSERT INTO audit_entries
             (id, timestamp, prev_hash, entry_hash, actor, action, conversation_id,
              policy_decision, policy_module, receipt, signature)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                "fork-attempt-id",
                chrono::Utc::now().to_rfc3339(),
                e1.entry_hash,           // <-- duplicate prev_hash
                "deadbeef".repeat(8),
                "{\"System\":\"attacker\"}",
                "{\"SystemEvent\":{\"event\":\"fork\"}}",
                ConversationId(uuid::Uuid::now_v7()).0.to_string(),
                "{\"Allow\":{\"conditions\":[]}}",
                "fork-test",
                Option::<String>::None,
                Option::<String>::None,
            ],
        );

        let err = inject.expect_err("duplicate prev_hash must be rejected");
        let sqlite_err = match err {
            rusqlite::Error::SqliteFailure(e, _) => e,
            other => panic!("expected SqliteFailure, got {other:?}"),
        };
        assert_eq!(
            sqlite_err.code,
            ErrorCode::ConstraintViolation,
            "expected ConstraintViolation, got {:?}",
            sqlite_err.code
        );
        assert_eq!(
            sqlite_err.extended_code, 2067,
            "expected SQLITE_CONSTRAINT_UNIQUE (2067), got {}",
            sqlite_err.extended_code
        );
        drop(side);

        // The chain must still be appendable and verify clean.
        let _e3 = store.append(unsealed("mod3")).unwrap();
        let report = store.verify_with_catalog().unwrap();
        assert!(
            report.violations().is_empty(),
            "post-rejection chain must verify clean, got {:?}",
            report.violations()
        );
        assert_eq!(report.receipts_checked, 3);
    }

    /// Sweep 5 — recovery after a poisoned write attempt.
    ///
    /// Combines the fork-rejection path with `verify_with_catalog`: after
    /// a rejected duplicate-`prev_hash` insert AND after a forced
    /// `tamper_entry_hash` followed by `restore_entry_hash` (the demo back
    /// door), the chain must still verify ACCEPT. This pins the
    /// "rejection does not poison the WAL" claim from the canonical
    /// schema docstring.
    #[cfg(feature = "pentest-demo")]
    #[test]
    fn test_sweep5_tamper_and_restore_keeps_chain_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open(&path).unwrap();

        let e1 = store.append(unsealed("mod1")).unwrap();
        let _e2 = store.append(unsealed("mod2")).unwrap();

        // Tamper, verify the chain breaks, restore, verify it heals.
        let id = e1.id.0.to_string();
        store.tamper_entry_hash(&id, &"f".repeat(64)).unwrap();
        let bad = store.verify_with_catalog().unwrap();
        assert!(
            !bad.violations().is_empty(),
            "tampered chain must surface violations"
        );

        store.restore_entry_hash(&id, &e1.entry_hash).unwrap();
        let good = store.verify_with_catalog().unwrap();
        assert!(
            good.violations().is_empty(),
            "restored chain must verify clean, got {:?}",
            good.violations()
        );
    }
}
