//! The Officer trait and scoped read handles.
//!
//! Officers are read-only observers. The trait enforces this: read handles
//! to substrate state, one output path (returning findings), no mutable
//! references. If an officer needs something changed, it proposes. The
//! operator signs.

use crate::finding::Finding;
use zp_audit::store::AuditStore;
use zp_core::AuditEntry;

/// Read-only view of the audit chain.
///
/// Wraps `&AuditStore` behind a curated API so officers can read chain
/// entries but never append, modify, or access the underlying connection.
pub struct ChainReader<'a> {
    store: &'a AuditStore,
}

impl<'a> ChainReader<'a> {
    pub fn new(store: &'a AuditStore) -> Self {
        Self { store }
    }

    /// Get the most recent N entries from the chain, in chronological order
    /// (oldest of the N first, newest last). Reads the *tail* of the chain,
    /// not the head — so on a 5000-entry chain with limit=1000, you get
    /// entries 4001–5000 in ascending order.
    pub fn recent_entries(&self, limit: usize) -> Result<Vec<AuditEntry>, ChainReadError> {
        let mut entries = self
            .store
            .recent_entries(limit)
            .map_err(|e| ChainReadError::StoreError(e.to_string()))?;
        // AuditStore::recent_entries returns newest-first (DESC).
        // Callers expect chronological (oldest-first within the window),
        // matching the old export_chain contract but reading the tail.
        entries.reverse();
        Ok(entries)
    }

    /// Get the latest hash in the chain.
    pub fn latest_hash(&self) -> Result<String, ChainReadError> {
        self.store
            .get_latest_hash()
            .map_err(|e| ChainReadError::StoreError(e.to_string()))
    }

    /// Verify chain integrity and return the report.
    pub fn verify(&self) -> Result<zp_audit::verifier::VerificationReport, ChainReadError> {
        self.store
            .verify_with_report()
            .map_err(|e| ChainReadError::StoreError(e.to_string()))
    }

    /// Search chain entries by action keyword.
    pub fn search_by_keyword(
        &self,
        keyword: &str,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, ChainReadError> {
        self.store
            .search_chain_by_action_keyword(keyword, limit)
            .map_err(|e| ChainReadError::StoreError(e.to_string()))
    }

    /// Get entries after a specific rowid (for incremental scanning).
    pub fn entries_after_rowid(
        &self,
        after_rowid: i64,
        limit: usize,
    ) -> Result<Vec<(i64, AuditEntry)>, ChainReadError> {
        self.store
            .export_entries_after_rowid(after_rowid, limit)
            .map_err(|e| ChainReadError::StoreError(e.to_string()))
    }
}

/// Read-only view of vault key names.
///
/// Officers see key *names* but never values. This is the structural
/// enforcement of the read-only invariant for credential state: an
/// officer can detect orphaned namespaces, naming convention violations,
/// or missing expected keys without ever touching secrets.
pub struct VaultKeyLister {
    /// Cached list of key names from the vault.
    key_names: Vec<String>,
}

impl VaultKeyLister {
    /// Create from a pre-collected list of key names.
    ///
    /// The caller (sweep runner) reads `vault.list()` once per sweep
    /// while holding the vault key, then passes the names here. The
    /// officer never touches the vault directly.
    pub fn new(key_names: Vec<String>) -> Self {
        Self { key_names }
    }

    /// All key names in the vault.
    pub fn all_keys(&self) -> &[String] {
        &self.key_names
    }

    /// Key names under a given prefix (e.g., "tools/ironclaw/").
    pub fn keys_with_prefix(&self, prefix: &str) -> Vec<&str> {
        self.key_names
            .iter()
            .filter(|k| k.starts_with(prefix))
            .map(|k| k.as_str())
            .collect()
    }

    /// Count of keys.
    pub fn count(&self) -> usize {
        self.key_names.len()
    }

    /// Unique namespace prefixes (everything before the first `/`).
    pub fn namespaces(&self) -> Vec<String> {
        let mut ns: Vec<String> = self
            .key_names
            .iter()
            .filter_map(|k| k.split('/').next().map(|s| s.to_string()))
            .collect();
        ns.sort();
        ns.dedup();
        ns
    }
}

/// Errors from reading substrate state.
#[derive(Debug, thiserror::Error)]
pub enum ChainReadError {
    #[error("audit store error: {0}")]
    StoreError(String),
}

/// The Officer trait — the contract all officers implement.
///
/// Officers are stateless between sweeps: they receive read handles,
/// produce findings, and return them. The sweep runner manages
/// activation, finding emission, and loop prevention.
pub trait Officer: Send + Sync {
    /// Short name used in receipt events (e.g., "std", "sen", "forge").
    fn name(&self) -> &'static str;

    /// Domain this officer is responsible for.
    fn domain(&self) -> &'static str;

    /// Chain event prefixes this officer watches for real-time activation.
    /// E.g., Steward watches for hash discontinuity patterns.
    fn watch_patterns(&self) -> &[&'static str];

    /// Run the full diagnostic sweep.
    ///
    /// Called periodically (default: every 15 minutes) and on real-time
    /// trigger matches. Returns all findings from this sweep cycle.
    fn sweep(
        &self,
        chain: &ChainReader<'_>,
        vault_keys: &VaultKeyLister,
    ) -> Vec<Finding>;

    /// Evaluate a single chain entry for real-time activation.
    ///
    /// Called for each new chain entry that matches `watch_patterns()`.
    /// Returns findings if the entry warrants immediate attention.
    /// Default: delegates to sweep (suboptimal but correct).
    fn evaluate_entry(
        &self,
        _entry: &AuditEntry,
        chain: &ChainReader<'_>,
        vault_keys: &VaultKeyLister,
    ) -> Vec<Finding> {
        // Default: run full sweep. Officers can override for
        // targeted real-time checks that don't need the full suite.
        self.sweep(chain, vault_keys)
    }
}
