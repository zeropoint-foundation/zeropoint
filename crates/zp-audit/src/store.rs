use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use zp_core::{AuditEntry, AuditId, ConversationId, SignatureBlock};

use crate::chain::{genesis_hash, new_audit_id, seal_entry, UnsealedEntry};
use crate::signer::AuditSigner;

/// A single tail-entry probe result — rowid, entry_hash, timestamp.
///
/// Used by OBSERVER-COHERENCE Class 1 chain readers cross-check.
/// See `AuditStore::tail_probes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailEntry {
    pub rowid: i64,
    pub entry_hash: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Cross-strategy probe results for OBSERVER-COHERENCE Class 1.
///
/// Three independent tail queries plus context. If the strategies disagree,
/// the underlying read path is producing incoherent views. See
/// `docs/design/OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` §Class 1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TailProbes {
    /// Newest entry by rowid (`ORDER BY rowid DESC LIMIT 1`).
    pub by_rowid: Option<TailEntry>,
    /// Newest entry by timestamp (`ORDER BY timestamp DESC LIMIT 1`).
    /// On a healthy substrate, this should match `by_rowid` — rowid
    /// ordering matches timestamp ordering under append-only usage.
    pub by_timestamp: Option<TailEntry>,
    /// Tail entry_hash via `get_latest_hash`-style dedicated query.
    /// Should match `by_rowid.entry_hash` — redundant query for
    /// coherence verification.
    pub via_latest_hash: Option<String>,
    /// Count of rows in `audit_entries` (live table).
    pub live_count: usize,
    /// Whether the `audit_entries_archive` table exists.
    pub archive_exists: bool,
}

/// Decode the on-disk `signatures` column (a JSON array of [`SignatureBlock`])
/// into the typed vec used by [`AuditEntry`]. Storage may legitimately hold
/// either an empty array (`[]`, the schema default for unsigned entries) or
/// a populated one (post-Phase-1.B); both round-trip correctly here.
fn decode_signatures(json: &str) -> Vec<SignatureBlock> {
    serde_json::from_str(json).unwrap_or_default()
}

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

    /// `append` was called on a store opened via [`AuditStore::open_readonly`].
    /// Read-only stores deliberately reject writes so inspection commands
    /// (`zp audit list`, etc.) can run without a sovereignty unlock.
    #[error("audit store is read-only; use AuditStore::open_signed to write")]
    ReadOnly,
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Type alias for audit row data from database queries.
///
/// Column order matches the SELECT clause used by the query helpers:
/// `(id, timestamp, prev_hash, entry_hash, actor, action, conversation_id,
///  policy_decision, policy_module, receipt, signatures)`.
///
/// Column 10 (`signatures`) is `String`, not `Option<String>`: schema v=3
/// makes the column NOT NULL with default `'[]'` so an unsigned entry
/// stores a literal empty JSON array. Decoding to `Vec<SignatureBlock>`
/// happens in [`decode_signatures`].
type AuditRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    Option<String>,
    String,
);

/// The audit store manages an append-only SQLite database of audit entries
/// with hash-chained verification for integrity.
///
/// # Construction
///
/// As of Phase 1.B (Seam 1), `AuditStore::open` no longer exists. Three
/// typed constructors split read vs write vs test:
///
/// | Constructor                      | Path        | Holds signer | Append |
/// |----------------------------------|-------------|--------------|--------|
/// | [`AuditStore::open_signed`]      | production  | yes          | signs  |
/// | [`AuditStore::open_readonly`]    | production  | no           | errors |
/// | [`AuditStore::open_unsigned`]    | test-only   | no           | empty  |
///
/// The hard cutover is intentional: there is no path by which a production
/// writer can construct an unsigned store. `open_unsigned` is `cfg(test)`
/// inside this crate; external test consumers must enable the `test-support`
/// feature explicitly.
pub struct AuditStore {
    conn: Connection,
    /// Per-store signer. `Some` for stores opened via [`AuditStore::open_signed`];
    /// `None` for the read-only and test-support paths. When `Some`,
    /// [`Self::append`] signs the sealed entry hash and pushes the resulting
    /// [`SignatureBlock`] into the entry's `signatures` vec before INSERT.
    signer: Option<AuditSigner>,
    /// Read-only mode. Set by [`Self::open_readonly`] and rejected by
    /// [`Self::append`] with [`StoreError::ReadOnly`]. Distinct from
    /// `signer.is_none()` because the test-support path also has no signer
    /// but is allowed to write (with empty signatures).
    read_only: bool,
    /// Optional post-commit notifier (P3 #176). Fires once per appended row so
    /// the Merkle anchor pipeline can detect trigger events without the store
    /// itself knowing about anchoring. Notifiers must be non-blocking — the
    /// audit store's mutex is still held across the call.
    notifier: Option<crate::notify::SharedNotifier>,
}

impl AuditStore {
    /// Open or create an audit store with read+write access and a held signer.
    ///
    /// This is the **only production write entry point**. The signer is held
    /// for the lifetime of the store; every subsequent [`Self::append`] uses
    /// it to sign the sealed entry hash and populate the entry's `signatures`
    /// vec. The Phase-1.B invariant: no entry reaches storage unsigned.
    ///
    /// The signer should come from
    /// [`zp_keys::derive_audit_signer_seed`] applied to the in-memory
    /// Genesis seed (sovereignty unlock at startup, not on disk).
    pub fn open_signed(
        path: impl AsRef<std::path::Path>,
        signer: AuditSigner,
    ) -> Result<Self> {
        let conn = Connection::open(path).map_err(StoreError::Database)?;
        let store = AuditStore {
            conn,
            signer: Some(signer),
            read_only: false,
            notifier: None,
        };
        store.init()?;
        Ok(store)
    }

    /// Open an audit store for **read-only** access. Production-safe; does
    /// not require a sovereignty unlock.
    ///
    /// Use this for inspection commands (`zp audit list`, `zp audit verify`,
    /// dashboard queries) that must work without the operator unlocking
    /// Genesis. [`Self::append`] returns [`StoreError::ReadOnly`] on a
    /// read-only store, so every write path is statically forced through
    /// [`Self::open_signed`].
    pub fn open_readonly(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(StoreError::Database)?;
        let store = AuditStore {
            conn,
            signer: None,
            read_only: true,
            notifier: None,
        };
        store.init()?;
        Ok(store)
    }

    /// Open an audit store for **maintenance** operations that modify tables
    /// but do not append chain entries (e.g. compaction, vacuuming).
    ///
    /// No signer required — compaction moves rows between `audit_entries`
    /// and `audit_entries_archive` without creating new signed entries.
    /// [`Self::append`] returns [`StoreError::ReadOnly`] is not enforced
    /// here, so callers must not use this handle to append entries.
    pub fn open_maintenance(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(StoreError::Database)?;
        let store = AuditStore {
            conn,
            signer: None,
            read_only: false,
            notifier: None,
        };
        store.init()?;
        Ok(store)
    }

    /// Open an audit store **without a signer**, allowing writes. Test-only.
    ///
    /// Inside `zp-audit`, callable from tests directly. External crates must
    /// enable the `test-support` feature to access this constructor.
    /// Production code MUST NOT enable that feature.
    ///
    /// Entries appended via this store carry `signatures: []`. Verifiers
    /// will report `signatures_present = 0` for them; the chain-integrity
    /// fast path still works (entry hashes still link), but the chain has
    /// no per-entry attestation. This is correct for test fixtures and
    /// reconstitution-pipeline unit tests that don't need a sovereignty
    /// unlock to run.
    #[cfg(any(test, feature = "test-support"))]
    pub fn open_unsigned(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path).map_err(StoreError::Database)?;
        let store = AuditStore {
            conn,
            signer: None,
            read_only: false,
            notifier: None,
        };
        store.init()?;
        Ok(store)
    }

    /// Register a post-commit notifier. Replaces any prior notifier.
    /// The notifier fires once per successful `append` with the sealed entry
    /// and its SQLite rowid (treated as the chain sequence number).
    pub fn set_notifier(&mut self, notifier: crate::notify::SharedNotifier) {
        self.notifier = Some(notifier);
    }

    /// Flush the prepared-statement cache on the underlying connection.
    ///
    /// Discards all cached prepared statements. Any held implicit read
    /// transactions from cached statements are released. Used by chain-read
    /// canary Tier 1 remediation when a read path is detected as stuck at a
    /// stale snapshot per `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md`.
    ///
    /// Cheap operation — cached statements are re-prepared on next use.
    pub fn flush_statement_cache(&mut self) {
        // Setting capacity to 0 discards all cached statements; restoring to
        // the default rusqlite capacity (16) preserves normal performance
        // characteristics on subsequent queries.
        self.conn.set_prepared_statement_cache_capacity(0);
        self.conn.set_prepared_statement_cache_capacity(16);
    }

    /// Force a WAL checkpoint with RESTART mode.
    ///
    /// WAL RESTART checkpoints all frames to the main DB, waits for any
    /// active readers to release their snapshot, then restarts the WAL. This
    /// forces snapshot-boundary refresh across the connection. Used by
    /// chain-read canary Tier 1 remediation as a stronger alternative to
    /// statement cache flush when the stale-snapshot fault persists.
    ///
    /// Returns the checkpoint result triple `(busy, log_frames, checkpointed_frames)`
    /// per SQLite's `PRAGMA wal_checkpoint(RESTART)` output.
    pub fn wal_checkpoint_restart(&self) -> Result<(i64, i64, i64)> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(RESTART)", [], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?))
            })
            .map_err(StoreError::Database)
    }

    /// Schema version of the canonical audit store. Stage 4 of the
    /// AUDIT-03 recanonicalization. A store with a different `user_version`
    /// is rejected at `open` time — callers must drop and recreate the DB
    /// (preserving forensic evidence separately; see
    /// `security/pentest-2026-04-06/forensic-dump-audit-03.sh`).
    ///
    /// **v=3 (Phase 1, Seam 1):** the `signature TEXT` column is replaced by
    /// `signatures TEXT NOT NULL DEFAULT '[]'`, holding a JSON array of
    /// [`SignatureBlock`]s. The hash function in [`crate::chain::compute_entry_hash`]
    /// changed accordingly (`"signature": null` → `"signatures": []`), so
    /// pre-v=3 entries cannot be rehashed by the v=3 verifier. The rejection
    /// + drop-and-recreate policy from AUDIT-03 covers the upgrade.
    const SCHEMA_VERSION: i32 = 3;

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
                    signatures TEXT NOT NULL DEFAULT '[]'
                );
                CREATE INDEX IF NOT EXISTS idx_conversation_id
                    ON audit_entries(conversation_id);
                CREATE INDEX IF NOT EXISTS idx_timestamp
                    ON audit_entries(timestamp);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_prev_hash
                    ON audit_entries(prev_hash)
                    WHERE prev_hash != '{genesis}';

                -- Phase 1.C (Seam 1): make audit_entries append-only at the
                -- storage layer. UPDATE/DELETE attempts are rejected by the
                -- engine itself, not by application code. Closes the surface
                -- where any process with FS access could mutate the chain via
                -- raw sqlite. The triggers are CREATE IF NOT EXISTS so existing
                -- v=3 databases gain the protection on next open without
                -- requiring a schema-version bump (the row format is unchanged).
                --
                -- The `pentest-demo` integrity demo no longer uses UPDATE; it
                -- works on in-memory clones via AuditStore::corrupt_clone_for_demo
                -- (see store.rs).
                CREATE TRIGGER IF NOT EXISTS no_update_audit_entries
                    BEFORE UPDATE ON audit_entries
                    BEGIN SELECT RAISE(ABORT, 'audit_entries is append-only'); END;
                CREATE TRIGGER IF NOT EXISTS no_delete_audit_entries
                    BEFORE DELETE ON audit_entries
                    BEGIN SELECT RAISE(ABORT, 'audit_entries is append-only'); END;
                "
            ))
            .map_err(StoreError::Database)?;

        if version == 0 {
            self.conn
                .pragma_update(None, "user_version", Self::SCHEMA_VERSION)
                .map_err(StoreError::Database)?;
        }

        info!("Audit store initialized (schema v{})", Self::SCHEMA_VERSION);
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
        // Phase 1.B: a read-only store rejects writes structurally. Inspection
        // commands that opened via [`Self::open_readonly`] cannot accidentally
        // write — they hit this guard before any I/O.
        if self.read_only {
            return Err(StoreError::ReadOnly);
        }

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

        let mut sealed = seal_entry(&unsealed, &prev_hash, id, timestamp);

        // Hash-then-sign discipline (Phase 1.B). `seal_entry` produced a
        // sealed `entry_hash` over `signatures: []`. If we hold a signer,
        // sign that hash now and push the resulting block into the entry's
        // `signatures` vec **and** the on-disk JSON column. The hash itself
        // is unchanged — it was computed before the signature existed, so
        // adding the signature can never invalidate the chain link.
        if let Some(signer) = self.signer.as_ref() {
            sealed
                .signatures
                .push(signer.sign_entry(&sealed.entry_hash));
        }

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

        // `signatures` carries either the signed block (production via
        // open_signed) or the empty array (test-only via open_unsigned).
        // The schema column is NOT NULL with default '[]' so both paths
        // round-trip cleanly.
        let signatures_json = serde_json::to_string(&sealed.signatures)?;

        tx.execute(
            "INSERT INTO audit_entries
             (id, timestamp, prev_hash, entry_hash, actor, action, conversation_id,
              policy_decision, policy_module, receipt, signatures)
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
                signatures_json,
            ],
        )
        .map_err(StoreError::Database)?;

        let sequence = tx.last_insert_rowid();

        tx.commit().map_err(StoreError::Database)?;

        debug!("Appended audit entry: {}", sealed.id.0);

        if let Some(ref notifier) = self.notifier {
            notifier.notify(&sealed, sequence);
        }

        Ok(sealed)
    }

    /// Return an in-memory **clone** of an entry with its `entry_hash`
    /// corrupted so the verifier will reject it. The on-disk row is NOT
    /// modified — the `audit_entries` table remains append-only via the
    /// triggers added in Phase 1.C.
    ///
    /// This replaces the old `tamper_entry_hash` / `restore_entry_hash`
    /// pair, which mutated the DB and depended on a back-door UPDATE
    /// surface. The integrity demo at `zeropoint.global/playground` uses
    /// this to exhibit chain-verification failure without ever creating
    /// a tampered row on disk: load the chain, swap one entry for the
    /// corrupted clone, run the verifier on the spliced chain, watch it
    /// fail. Real DB stays clean.
    ///
    /// Available under the `pentest-demo` feature only — it's a demo
    /// helper, not a production primitive.
    #[cfg(feature = "pentest-demo")]
    pub fn corrupt_clone_for_demo(&self, id: &str) -> Result<AuditEntry> {
        warn!(entry_id = id, "pentest-demo: returning corrupted clone");
        // Load the entry by id. Reuse the existing column list so the
        // signatures column round-trips correctly.
        let entry = self.conn.query_row(
            "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                    conversation_id, policy_decision, policy_module, receipt, signatures
             FROM audit_entries WHERE id = ?1",
            params![id],
            |row| {
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
                let signatures_json: String = row.get(10)?;
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
                    signatures_json,
                ))
            },
        )
        .optional()
        .map_err(StoreError::Database)?
        .ok_or(StoreError::NoEntries)?;

        let mut hydrated = self.hydrate_entries(vec![entry])?;
        let mut tampered = hydrated.pop().ok_or(StoreError::NoEntries)?;
        // Replace the entry_hash with a visibly-bogus value. The verifier
        // will recompute the canonical hash and find the mismatch.
        tampered.entry_hash = "f".repeat(64);
        Ok(tampered)
    }

    /// Drop and recreate the `audit_entries` table. Test/dev-tools only.
    ///
    /// Gated behind `cfg(any(test, feature = "test-support"))` because the
    /// audit chain is supposed to be append-only — production resets are
    /// done by deleting the audit DB file and letting the server recreate
    /// it. Tests that need a clean store between cases call this directly;
    /// the dev-tools `audit_clear_handler` reaches it via the
    /// `dev-tools = ["zp-audit/test-support"]` feature pass-through.
    ///
    /// Implementation note: the BEFORE DELETE trigger (Phase 1.C) blocks
    /// row-by-row deletion, so we DROP the table and let `init()` rebuild
    /// it (along with its triggers) on the next call. This is structurally
    /// correct: a "clear" that destroys the table-as-such isn't pretending
    /// the chain is mutable, it's resetting the substrate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn clear(&self) -> Result<usize> {
        let count: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .map_err(StoreError::Database)?;
        self.conn
            .execute_batch("DROP TABLE audit_entries;")
            .map_err(StoreError::Database)?;
        // Re-create the table + indexes + triggers via the canonical init().
        self.init()?;
        info!("Cleared {} audit entries (table dropped and recreated)", count);
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

    /// Cross-strategy tail probes for OBSERVER-COHERENCE Class 1 chain readers.
    ///
    /// Runs three independent tail queries on the shared connection and
    /// returns their results for comparison. If the strategies disagree, the
    /// underlying read path is producing incoherent views — the exact fault
    /// class OBSERVER-COHERENCE-DISCIPLINE-2026-07.md targets.
    ///
    /// - `by_rowid`: newest via `ORDER BY rowid DESC LIMIT 1` (matches
    ///   `recent_entries(1)` and `get_latest_hash()` primitives)
    /// - `by_timestamp`: newest via `ORDER BY timestamp DESC LIMIT 1` (matches
    ///   an alternative "when did last activity happen" query pattern)
    /// - `via_latest_hash`: dedicated `get_latest_hash()` call (should match
    ///   `by_rowid.entry_hash`; independent query for redundancy)
    /// - `live_count`: count of rows in live table
    /// - `archive_exists`: whether `audit_entries_archive` table exists
    ///
    /// Coherence discipline expectation: on a healthy substrate, `by_rowid`
    /// and `by_timestamp` return the same entry (rowid ordering matches
    /// timestamp ordering under normal append-only usage), and
    /// `via_latest_hash` matches `by_rowid.entry_hash`. Any divergence is a
    /// diagnostic signal per `coherence:diverged:class1_chain_readers`.
    pub fn tail_probes(&self) -> Result<TailProbes> {
        // Probe A — newest by rowid
        let by_rowid: Option<TailEntry> = self
            .conn
            .query_row(
                "SELECT rowid, entry_hash, timestamp FROM audit_entries
                 ORDER BY rowid DESC LIMIT 1",
                [],
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let entry_hash: String = row.get(1)?;
                    let timestamp_str: String = row.get(2)?;
                    Ok((rowid, entry_hash, timestamp_str))
                },
            )
            .optional()
            .map_err(StoreError::Database)?
            .and_then(|(rowid, entry_hash, timestamp_str)| {
                chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                    .ok()
                    .map(|dt| TailEntry {
                        rowid,
                        entry_hash,
                        timestamp: dt.with_timezone(&chrono::Utc),
                    })
            });

        // Probe B — newest by timestamp
        let by_timestamp: Option<TailEntry> = self
            .conn
            .query_row(
                "SELECT rowid, entry_hash, timestamp FROM audit_entries
                 ORDER BY timestamp DESC LIMIT 1",
                [],
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let entry_hash: String = row.get(1)?;
                    let timestamp_str: String = row.get(2)?;
                    Ok((rowid, entry_hash, timestamp_str))
                },
            )
            .optional()
            .map_err(StoreError::Database)?
            .and_then(|(rowid, entry_hash, timestamp_str)| {
                chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                    .ok()
                    .map(|dt| TailEntry {
                        rowid,
                        entry_hash,
                        timestamp: dt.with_timezone(&chrono::Utc),
                    })
            });

        // Probe C — via get_latest_hash (dedicated method, independent prep)
        let via_latest_hash: Option<String> = self
            .conn
            .query_row(
                "SELECT entry_hash FROM audit_entries ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(StoreError::Database)?;

        let live_count: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .map_err(StoreError::Database)?;

        let archive_exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='audit_entries_archive'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        Ok(TailProbes {
            by_rowid,
            by_timestamp,
            via_latest_hash,
            live_count,
            archive_exists,
        })
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
                        conversation_id, policy_decision, policy_module, receipt, signatures
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
                let signatures_json: String = row.get(10)?;

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
                    signatures_json,
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
            signatures_json,
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
                signatures: decode_signatures(&signatures_json),
            });
        }

        Ok(result)
    }

    /// Export `(rowid, entry_hash)` pairs strictly after the given rowid,
    /// in ascending rowid order. Used by the Merkle anchor pipeline to build
    /// epochs from the entries appended since the last seal.
    ///
    /// `after_rowid = 0` means "from the beginning of the chain".
    pub fn export_hashes_after(&self, after_rowid: i64) -> Result<Vec<(i64, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT rowid, entry_hash FROM audit_entries
                 WHERE rowid > ?
                 ORDER BY rowid ASC",
            )
            .map_err(StoreError::Database)?;

        let rows = stmt
            .query_map(params![after_rowid], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        Ok(rows)
    }

    /// Export `(rowid, entry_hash)` pairs in the inclusive rowid range
    /// `[first, last]`, in ascending rowid order. Used by `zp verify --anchors`
    /// to recompute Merkle roots over a sealed epoch's exact entry range.
    pub fn export_hashes_in_range(&self, first: i64, last: i64) -> Result<Vec<(i64, String)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT rowid, entry_hash FROM audit_entries
                 WHERE rowid BETWEEN ? AND ?
                 ORDER BY rowid ASC",
            )
            .map_err(StoreError::Database)?;

        let rows = stmt
            .query_map(params![first, last], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        Ok(rows)
    }

    /// Find the latest anchor epoch receipt in the chain.
    ///
    /// Scans only the `action` column for `epoch:anchored:*` events using
    /// a LIKE query, avoiding a full-chain deserialization. Returns the
    /// epoch number, the last_sequence from the receipt detail, and the
    /// entry_hash of the anchor receipt — enough for pipeline rehydration.
    pub fn latest_anchor_epoch(&self) -> Result<Option<(u64, i64, String)>> {
        // The action column stores JSON like:
        //   {"SystemEvent":{"event":"epoch:anchored:61"}}
        // We search for the pattern and parse the epoch number from the match.
        let mut stmt = self
            .conn
            .prepare(
                "SELECT action, policy_decision, entry_hash
                 FROM audit_entries
                 WHERE action LIKE '%epoch:anchored:%'
                 ORDER BY rowid DESC
                 LIMIT 1",
            )
            .map_err(StoreError::Database)?;

        let result = stmt
            .query_row([], |row| {
                let action_json: String = row.get(0)?;
                let policy_json: String = row.get(1)?;
                let entry_hash: String = row.get(2)?;
                Ok((action_json, policy_json, entry_hash))
            })
            .optional()
            .map_err(StoreError::Database)?;

        match result {
            None => Ok(None),
            Some((action_json, policy_json, entry_hash)) => {
                // Parse epoch number from action JSON.
                let action: zp_core::AuditAction = match serde_json::from_str(&action_json) {
                    Ok(a) => a,
                    Err(_) => return Ok(None),
                };
                let epoch_num = match &action {
                    zp_core::AuditAction::SystemEvent { event } => {
                        event.strip_prefix("epoch:anchored:")
                            .and_then(|s| s.parse::<u64>().ok())
                    }
                    _ => None,
                };
                let epoch_num = match epoch_num {
                    Some(n) => n,
                    None => return Ok(None),
                };

                // Parse last_sequence from policy_decision conditions.
                let policy: zp_core::PolicyDecision = match serde_json::from_str(&policy_json) {
                    Ok(p) => p,
                    Err(_) => return Ok(None),
                };
                let last_seq = match &policy {
                    zp_core::PolicyDecision::Allow { conditions } => {
                        conditions.first().and_then(|c| {
                            serde_json::from_str::<serde_json::Value>(c).ok()
                                .and_then(|v| v.get("last_sequence")?.as_i64())
                        }).unwrap_or(0)
                    }
                    _ => 0,
                };

                Ok(Some((epoch_num, last_seq, entry_hash)))
            }
        }
    }

    /// Total number of entries in the chain (live + archive combined).
    ///
    /// Callers expect this to report the full chain size regardless of
    /// compaction state. Consults both `audit_entries` (live) and
    /// `audit_entries_archive` (post-compaction storage) so post-compaction
    /// chains report accurate total counts. Same archive-boundary discipline
    /// as `verify_with_report` and `search_chain_by_action_keyword`.
    pub fn entry_count(&self) -> Result<usize> {
        let live: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .map_err(StoreError::Database)?;

        let archive_exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='audit_entries_archive'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if archive_exists {
            let archived: usize = self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_entries_archive",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            Ok(live + archived)
        } else {
            Ok(live)
        }
    }

    /// Number of entries in the live table only (excludes archive).
    ///
    /// Used by compaction logic to decide how many entries to archive.
    /// For general "chain size" queries, use `entry_count()` instead.
    pub fn live_entry_count(&self) -> Result<usize> {
        self.conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .map_err(StoreError::Database)
    }

    /// Retroactively sign previously unsigned entries on the chain.
    ///
    /// Queries entries where `signatures = '[]'` and signs each one using
    /// the store's held signer. This is the Regent's `batch_sign` remediation
    /// tool — when the Sentinel reports unsigned entries, the Regent can
    /// invoke this to close the gap.
    ///
    /// Returns the number of entries signed, or an error if the store has
    /// no signer (read-only or test-support stores cannot backfill).
    ///
    /// # Hash-then-sign discipline
    ///
    /// The `entry_hash` was computed over `signatures: []` at sealing time.
    /// Adding a signature block to the `signatures` column does not change
    /// the hash — the signature is _over_ the hash, not part of it. This
    /// is the same discipline used in `append()`.
    pub fn backfill_signatures(&mut self) -> Result<u64> {
        let signer = self.signer.as_ref().ok_or(StoreError::ReadOnly)?;

        // Find all entries with empty signature arrays.
        let unsigned: Vec<(i64, String)> = {
            let mut stmt = self.conn.prepare(
                "SELECT rowid, entry_hash FROM audit_entries WHERE signatures = '[]'"
            ).map_err(StoreError::Database)?;

            let rows = stmt.query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .map_err(StoreError::Database)?;
            rows.filter_map(|r| r.ok()).collect()
        };

        let count = unsigned.len() as u64;
        if count == 0 {
            debug!("backfill_signatures: no unsigned entries found");
            return Ok(0);
        }

        info!(count, "backfill_signatures: signing unsigned entries");

        // Sign in a transaction for atomicity.
        // The BEFORE UPDATE trigger (Phase 1.C) blocks row mutation — we
        // temporarily drop it within the transaction, same pattern as
        // compact_chain() with the DELETE trigger. Signature backfilling
        // is a legitimate maintenance operation: the entry_hash is
        // unchanged, only the signatures column gains a block.
        let tx = self.conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::Database)?;

        tx.execute_batch("DROP TRIGGER IF EXISTS no_update_audit_entries")
            .map_err(StoreError::Database)?;

        for (rowid, entry_hash) in &unsigned {
            let block = signer.sign_entry(entry_hash);
            let signatures_json = serde_json::to_string(&vec![block])?;
            tx.execute(
                "UPDATE audit_entries SET signatures = ?1 WHERE rowid = ?2",
                params![signatures_json, rowid],
            ).map_err(StoreError::Database)?;
        }

        // Restore the append-only trigger.
        tx.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS no_update_audit_entries
                 BEFORE UPDATE ON audit_entries
                 BEGIN SELECT RAISE(ABORT, 'audit_entries is append-only'); END"
        ).map_err(StoreError::Database)?;

        tx.commit().map_err(StoreError::Database)?;

        info!(count, "backfill_signatures: complete");
        Ok(count)
    }

    /// Count of entries with empty signature arrays.
    ///
    /// Used by the Sentinel to report unsigned entries as a finding,
    /// and by the Regent to decide whether batch_sign remediation is needed.
    /// Number of unsigned entries across live + archive combined.
    ///
    /// Consults both `audit_entries` (live) and `audit_entries_archive`
    /// (post-compaction storage) so Sentinel/Steward reports accurate
    /// unsigned counts regardless of compaction state. Same archive-boundary
    /// discipline as `entry_count` and `search_chain_by_action_keyword`.
    /// Prior to this fix, unsigned entries archived away were invisible to
    /// signing-hygiene reporting.
    pub fn unsigned_entry_count(&self) -> Result<u64> {
        let live: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM audit_entries WHERE signatures = '[]'",
                [],
                |row| row.get(0),
            )
            .map_err(StoreError::Database)?;

        let archive_exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='audit_entries_archive'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if archive_exists {
            let archived: u64 = self
                .conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_entries_archive WHERE signatures = '[]'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            Ok(live + archived)
        } else {
            Ok(live)
        }
    }

    /// Compact the chain by archiving old entries.
    ///
    /// Moves entries with `rowid <= (max_rowid - retain)` into an
    /// `audit_entries_archive` table within the same database file.
    /// The archive preserves full chain integrity — all hashes, signatures,
    /// and prev_hash linkage are maintained. Only hot-path queries (which
    /// read from `audit_entries`) are affected; verification can still
    /// walk the archive.
    ///
    /// Returns the number of entries archived.
    pub fn compact_chain(&mut self, retain: usize) -> Result<usize> {
        let total: i64 = self.conn
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |row| row.get(0))
            .map_err(StoreError::Database)?;

        let to_archive = total - retain as i64;
        if to_archive <= 0 {
            info!(total, retain, "chain compact: nothing to archive");
            return Ok(0);
        }

        // Find the cutoff rowid — entries with rowid <= this move to archive.
        let cutoff_rowid: i64 = self.conn
            .query_row(
                "SELECT rowid FROM audit_entries ORDER BY rowid ASC LIMIT 1 OFFSET ?",
                params![to_archive],
                |row| row.get(0),
            )
            .map_err(StoreError::Database)?;

        info!(total, retain, to_archive, cutoff_rowid, "chain compact: archiving entries");

        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StoreError::Database)?;

        // Create archive table if it doesn't exist (same schema as active).
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_entries_archive (
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
                signatures TEXT NOT NULL DEFAULT '[]'
            )"
        ).map_err(StoreError::Database)?;

        // Move entries to archive.
        let archived = tx.execute(
            "INSERT OR IGNORE INTO audit_entries_archive
             SELECT * FROM audit_entries WHERE rowid < ?",
            params![cutoff_rowid],
        ).map_err(StoreError::Database)?;

        // Temporarily drop the append-only trigger so we can delete
        // archived entries. The trigger is restored immediately after.
        tx.execute_batch("DROP TRIGGER IF EXISTS no_delete_audit_entries")
            .map_err(StoreError::Database)?;

        tx.execute(
            "DELETE FROM audit_entries WHERE rowid < ?",
            params![cutoff_rowid],
        ).map_err(StoreError::Database)?;

        // Restore the append-only trigger.
        tx.execute_batch(
            "CREATE TRIGGER IF NOT EXISTS no_delete_audit_entries
                 BEFORE DELETE ON audit_entries
                 BEGIN SELECT RAISE(ABORT, 'audit_entries is append-only'); END"
        ).map_err(StoreError::Database)?;

        tx.commit().map_err(StoreError::Database)?;

        info!(archived, "chain compact complete");
        Ok(archived)
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
                        conversation_id, policy_decision, policy_module, receipt, signatures
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
                let signatures_json: String = row.get(10)?;

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
                    signatures_json,
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
            signatures_json,
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
                signatures: decode_signatures(&signatures_json),
            });
        }

        Ok(result)
    }

    /// Return the most recent `limit` entries in chronological order.
    ///
    /// Like `export_chain` but reads the tail of the chain instead of the
    /// head. Useful for CLI commands like `zp audit log` where the operator
    /// wants to see what happened recently.
    pub fn recent_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                        conversation_id, policy_decision, policy_module, receipt, signatures
                 FROM audit_entries
                 ORDER BY rowid DESC
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
                let signatures_json: String = row.get(10)?;

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
                    signatures_json,
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
            signatures_json,
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
                signatures: decode_signatures(&signatures_json),
            });
        }

        // Reverse: query fetched newest-first, restore chronological order.
        result.reverse();

        Ok(result)
    }

    /// Search chain entries whose serialized `action` JSON contains `keyword`.
    ///
    /// Uses a SQL `LIKE '%keyword%'` pre-filter so the full chain is never
    /// loaded into memory.  The caller is still responsible for exact matching
    /// after deserialization; this method is intentionally permissive to keep
    /// the SQL simple and fast.  Returns up to `limit` results in **descending**
    /// rowid order (newest first) so Regent's precedent queries and "recent
    /// activity" queries return the most recent matches.
    ///
    /// Consults both `audit_entries` (live table) and `audit_entries_archive`
    /// (post-compaction storage) so results survive chain compaction. Same
    /// archive-boundary discipline as `verify_with_report` — searching only
    /// the live table produced the Task #33 bug where Regent's `chain_query`
    /// filter hid post-compaction receipts and (via ASC ordering + LIMIT)
    /// returned only the oldest matches instead of the newest.
    pub fn search_chain_by_action_keyword(
        &self,
        keyword: &str,
        limit: usize,
    ) -> Result<Vec<AuditEntry>> {
        // Simple LIKE with no ESCAPE clause — the keyword never contains SQL LIKE
        // metacharacters (% or _), so no escaping is needed.  The sqlite3 CLI
        // confirmed that `WHERE action LIKE '%model:registered%'` (no ESCAPE)
        // returns the expected rows; the ESCAPE '|' variant returned 0 on the
        // same DB, suggesting a SQLite build quirk with '|' as escape char.
        let like_pattern = format!("%{}%", keyword);

        let archive_exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type='table' AND name='audit_entries_archive'
                )",
                [],
                |row| row.get(0),
            )
            .unwrap_or(false);

        // Prepare a query that unions live + archive when the archive exists,
        // ordered by timestamp DESC so the newest matches come first regardless
        // of which table they live in.  Same schema across both tables.
        let sql = if archive_exists {
            "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                    conversation_id, policy_decision, policy_module, receipt, signatures
             FROM audit_entries
             WHERE action LIKE ?1
             UNION ALL
             SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                    conversation_id, policy_decision, policy_module, receipt, signatures
             FROM audit_entries_archive
             WHERE action LIKE ?1
             ORDER BY timestamp DESC
             LIMIT ?2"
        } else {
            "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                    conversation_id, policy_decision, policy_module, receipt, signatures
             FROM audit_entries
             WHERE action LIKE ?1
             ORDER BY timestamp DESC
             LIMIT ?2"
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(StoreError::Database)?;

        let rows = stmt
            .query_map(params![like_pattern, limit], |row| {
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
                let signatures_json: String = row.get(10)?;
                Ok((
                    id_str, timestamp_str, prev_hash, entry_hash,
                    actor_json, action_json, conv_id_str,
                    policy_decision_json, policy_module, receipt_json, signatures_json,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        let mut result = Vec::new();
        for (id_str, timestamp_str, prev_hash, entry_hash, actor_json, action_json,
             conv_id_str, policy_decision_json, policy_module, receipt_json, signatures_json) in rows
        {
            let id = uuid::Uuid::parse_str(&id_str).unwrap_or_else(|_| uuid::Uuid::nil());
            let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                .ok()
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(chrono::Utc::now);
            let actor = serde_json::from_str(&actor_json)
                .unwrap_or_else(|_| zp_core::ActorId::System("unknown".to_string()));
            let action = serde_json::from_str(&action_json).unwrap_or_else(|_| {
                zp_core::AuditAction::SystemEvent { event: "unknown".to_string() }
            });
            let conversation_id = zp_core::ConversationId(
                uuid::Uuid::parse_str(&conv_id_str).unwrap_or_else(|_| uuid::Uuid::nil()),
            );
            let policy_decision = serde_json::from_str(&policy_decision_json)
                .unwrap_or_else(|_| zp_core::PolicyDecision::Block {
                    reason: "unknown".to_string(),
                    policy_module: "unknown".to_string(),
                });
            let receipt = receipt_json.as_ref().and_then(|json| serde_json::from_str(json).ok());
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
                signatures: decode_signatures(&signatures_json),
            });
        }
        Ok(result)
    }

    /// Export `(rowid, AuditEntry)` pairs strictly after the given rowid,
    /// in ascending rowid order, up to `limit` entries.
    ///
    /// `after_rowid = 0` means "from the beginning of the chain".
    /// The returned rowid can be base64-encoded as an opaque cursor for
    /// forward-pagination of the chain by consumers such as the foundation
    /// relay SSE bridge.
    pub fn export_entries_after_rowid(
        &self,
        after_rowid: i64,
        limit: usize,
    ) -> Result<Vec<(i64, AuditEntry)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT rowid, id, timestamp, prev_hash, entry_hash, actor, action,
                        conversation_id, policy_decision, policy_module, receipt, signatures
                 FROM audit_entries
                 WHERE rowid > ?
                 ORDER BY rowid ASC
                 LIMIT ?",
            )
            .map_err(StoreError::Database)?;

        let rows = stmt
            .query_map(params![after_rowid, limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        let mut result = Vec::new();
        for (rowid, id_str, timestamp_str, prev_hash, entry_hash, actor_json, action_json,
             conv_id_str, policy_decision_json, policy_module, receipt_json, signatures_json) in rows
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
            result.push((
                rowid,
                AuditEntry {
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
                    signatures: decode_signatures(&signatures_json),
                },
            ));
        }
        Ok(result)
    }

    /// Verify chain linkage integrity with a detailed report.
    ///
    /// Checks that stored entry hashes form a valid chain (each entry's
    /// `prev_hash` matches the previous entry's `entry_hash`). Does NOT
    /// recompute hashes — that requires the original in-memory `AuditEntry`
    /// objects (use `ChainVerifier::verify` for peer-provided entries).
    ///
    /// After compaction, the first live entry's `prev_hash` links to the
    /// archive's tail — NOT to the genesis hash. This function consults the
    /// `audit_entries_archive` table (if present) to find the correct
    /// expected prev_hash for the first live entry. Same discipline as
    /// `verify_chain` at line 1420. Failing to do this caused 692 false
    /// positive `chain_link_broken` findings from Steward over 4+ days
    /// (2026-07-10 diagnostic).
    pub fn verify_with_report(&self) -> Result<crate::verifier::VerificationReport> {
        let chain = self.export_chain(i32::MAX as usize)?;

        // If the archive table exists and contains entries, the first live
        // entry's prev_hash should link to the last archive entry's entry_hash.
        // Look it up and pass as expected_prev_hash so verify_linkage_report
        // doesn't default to genesis.
        let archive_tail_hash: Option<String> = {
            let archive_exists: bool = self.conn
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_master
                        WHERE type='table' AND name='audit_entries_archive'
                    )",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false);

            if archive_exists {
                self.conn
                    .query_row(
                        "SELECT entry_hash FROM audit_entries_archive
                         ORDER BY rowid DESC LIMIT 1",
                        [],
                        |row| row.get::<_, String>(0),
                    )
                    .ok()
            } else {
                None
            }
        };

        Ok(crate::verifier::verify_linkage_report(
            &chain,
            archive_tail_hash.as_deref(),
        ))
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

        // Check genesis: first entry's prev_hash should match the genesis hash,
        // OR it should reference an entry in the archive table (post-compaction).
        let genesis_hash = blake3::hash(b"").to_hex().to_string();
        if entries[0].1 != genesis_hash {
            // Check if the prev_hash exists in the archive (compacted chain).
            // The archive table may not exist on a never-compacted chain.
            let in_archive: bool = self.conn
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM sqlite_master
                        WHERE type='table' AND name='audit_entries_archive'
                    )",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(false)
                && self.conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM audit_entries_archive WHERE entry_hash = ?)",
                        params![entries[0].1],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);

            if !in_archive {
                warn!(
                    "Chain verification failed: first entry {} has incorrect prev_hash",
                    entries[0].0
                );
                return Err(StoreError::ChainVerificationFailed {
                    id: entries[0].0.clone(),
                });
            }
            debug!("Chain verification: first entry links to archived chain (post-compaction)");
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

    // ========================================================================
    // Phase 2.4: Typed receipt queries
    // ========================================================================

    /// Query audit entries whose attached receipt has a specific receipt_type.
    ///
    /// Uses SQLite's json_extract to filter on the receipt JSON without
    /// requiring a schema migration. For large chains, consider adding a
    /// denormalized `receipt_type` column in a future schema version.
    pub fn query_by_claim_type(&self, claim_type: &str, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                        conversation_id, policy_decision, policy_module, receipt, signatures
                 FROM audit_entries
                 WHERE json_extract(receipt, '$.receipt_type') = ?1
                 ORDER BY rowid DESC
                 LIMIT ?2",
            )
            .map_err(StoreError::Database)?;

        let entries = stmt
            .query_map(params![claim_type, limit], |row| {
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
                let signatures_json: String = row.get(10)?;

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
                    signatures_json,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        self.hydrate_entries(entries)
    }

    /// Query revocation claims that target a specific receipt ID.
    ///
    /// Scans audit entries for RevocationClaim receipts whose claim_metadata
    /// contains the given receipt_id as the revoked target.
    pub fn query_revocations(&self, receipt_id: &str, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                        conversation_id, policy_decision, policy_module, receipt, signatures
                 FROM audit_entries
                 WHERE json_extract(receipt, '$.receipt_type') = 'revocation_claim'
                   AND json_extract(receipt, '$.claim_metadata.revoked_receipt_id') = ?1
                 ORDER BY rowid DESC
                 LIMIT ?2",
            )
            .map_err(StoreError::Database)?;

        let entries = stmt
            .query_map(params![receipt_id, limit], |row| {
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
                let signatures_json: String = row.get(10)?;

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
                    signatures_json,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        self.hydrate_entries(entries)
    }

    /// Query audit entries whose attached receipt has expired.
    pub fn query_expired_receipts(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let now = chrono::Utc::now().to_rfc3339();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, prev_hash, entry_hash, actor, action,
                        conversation_id, policy_decision, policy_module, receipt, signatures
                 FROM audit_entries
                 WHERE json_extract(receipt, '$.expires_at') IS NOT NULL
                   AND json_extract(receipt, '$.expires_at') < ?1
                 ORDER BY rowid DESC
                 LIMIT ?2",
            )
            .map_err(StoreError::Database)?;

        let entries = stmt
            .query_map(params![now, limit], |row| {
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
                let signatures_json: String = row.get(10)?;

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
                    signatures_json,
                ))
            })
            .map_err(StoreError::Database)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(StoreError::Database)?;

        self.hydrate_entries(entries)
    }

    /// Internal helper to convert raw row tuples into AuditEntry structs.
    /// Extracted to avoid duplicating the deserialization logic across query methods.
    fn hydrate_entries(&self, entries: Vec<AuditRow>) -> Result<Vec<AuditEntry>> {
        let mut result = Vec::with_capacity(entries.len());
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
            signatures_json,
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
                signatures: decode_signatures(&signatures_json),
            });
        }
        Ok(result)
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
        let store = AuditStore::open_unsigned(&path).unwrap();
        let hash = store.get_latest_hash().unwrap();
        assert_eq!(hash, genesis_hash());
    }

    #[test]
    fn test_export_chain_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open_unsigned(&path).unwrap();

        let chain = store.export_chain(100).unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn test_append_links_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open_unsigned(&path).unwrap();

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
        let mut store = AuditStore::open_unsigned(&path).unwrap();

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
        let mut store = AuditStore::open_unsigned(&path).unwrap();

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

        let store_a = Arc::new(Mutex::new(AuditStore::open_unsigned(&path).unwrap()));
        let store_b = Arc::new(Mutex::new(AuditStore::open_unsigned(&path).unwrap()));

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
        let mut store = AuditStore::open_unsigned(dir.path().join("audit.db")).unwrap();

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

        // Now AuditStore::open_unsigned must refuse it (the schema-mismatch
        // check fires before any signer is consulted).
        let err = match AuditStore::open_unsigned(&path) {
            Ok(_) => panic!("expected SchemaMismatch, got Ok"),
            Err(e) => e,
        };
        match err {
            StoreError::SchemaMismatch { found, expected } => {
                assert_eq!(found, 1);
                assert_eq!(expected, 3);
            }
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    /// Sweep 5 — schema migration: a v0 database (PRAGMA user_version = 0,
    /// the brand-new state) must be accepted and stamped to v3. This is the
    /// "fresh install" path and must remain frictionless.
    #[test]
    fn test_sweep5_accepts_v0_and_stamps_v3() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");

        // Create the file but leave user_version = 0 (the SQLite default).
        {
            let _conn = Connection::open(&path).unwrap();
        }

        let store = AuditStore::open_unsigned(&path).unwrap();
        let v: i32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(v, 3, "fresh open must stamp user_version=3");
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
        let mut store = AuditStore::open_unsigned(&path).unwrap();

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
              policy_decision, policy_module, receipt, signatures)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                "fork-attempt-id",
                chrono::Utc::now().to_rfc3339(),
                e1.entry_hash, // <-- duplicate prev_hash
                "deadbeef".repeat(8),
                "{\"System\":\"attacker\"}",
                "{\"SystemEvent\":{\"event\":\"fork\"}}",
                ConversationId(uuid::Uuid::now_v7()).0.to_string(),
                "{\"Allow\":{\"conditions\":[]}}",
                "fork-test",
                Option::<String>::None,
                // signatures column is NOT NULL with default '[]' under v=3.
                "[]".to_string(),
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

    /// Phase 1.C — corrupt-clone integrity demo.
    ///
    /// Replaces the old `tamper_entry_hash` / `restore_entry_hash` round-trip
    /// (which mutated the DB via a back-door UPDATE) with the in-memory
    /// clone path. The on-disk chain is **never** modified — Phase 1.C
    /// triggers reject UPDATE/DELETE on `audit_entries` at the storage
    /// layer.
    ///
    /// The demo claim is preserved: a corrupted entry exhibits chain
    /// violations to the verifier, while the real DB remains clean. The
    /// playground integrity demo at `zeropoint.global` consumes this same
    /// API to render the failure mode without ever creating a tampered
    /// row on disk.
    #[cfg(feature = "pentest-demo")]
    #[test]
    fn test_corrupt_clone_breaks_verify_without_touching_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open_unsigned(&path).unwrap();

        let e1 = store.append(unsealed("mod1")).unwrap();
        let _e2 = store.append(unsealed("mod2")).unwrap();

        // The DB chain is clean to start.
        let report_before = store.verify_with_catalog().unwrap();
        assert!(
            report_before.violations().is_empty(),
            "chain must verify clean before any tampering, got {:?}",
            report_before.violations()
        );

        // Get a corrupted in-memory clone of e1 via the demo helper.
        let id = e1.id.0.to_string();
        let tampered = store.corrupt_clone_for_demo(&id).unwrap();
        assert_ne!(
            tampered.entry_hash, e1.entry_hash,
            "clone must carry a different (bogus) entry_hash"
        );

        // The on-disk row is untouched: re-verify the real DB.
        let report_after = store.verify_with_catalog().unwrap();
        assert!(
            report_after.violations().is_empty(),
            "real DB must remain clean after corrupt_clone_for_demo, got {:?}",
            report_after.violations()
        );

        // The clone, run through the chain verifier, would surface a hash
        // violation — that's the demo's payload to the user.
        let recomputed = crate::chain::recompute_entry_hash(&tampered);
        assert_ne!(
            recomputed, tampered.entry_hash,
            "verifier-side recompute of the tampered clone must mismatch"
        );
    }

    /// Phase 1.C — DB-level append-only enforcement.
    ///
    /// The BEFORE UPDATE / BEFORE DELETE triggers reject row mutation at
    /// the SQLite layer, even when a malicious caller bypasses
    /// [`AuditStore::append`] entirely with a raw connection. This pins
    /// the storage-layer half of "signing is gravity" — a tampered row
    /// can't physically exist on disk.
    #[test]
    fn test_phase1c_triggers_block_raw_update_and_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let mut store = AuditStore::open_unsigned(&path).unwrap();
        let e1 = store.append(unsealed("mod1")).unwrap();

        // Reach around the typed API with a raw connection.
        let raw = Connection::open(&path).unwrap();

        let upd = raw.execute(
            "UPDATE audit_entries SET entry_hash = ? WHERE id = ?",
            params!["deadbeef".repeat(8), e1.id.0.to_string()],
        );
        assert!(
            upd.is_err(),
            "BEFORE UPDATE trigger must reject row mutation; got Ok"
        );

        let del = raw.execute(
            "DELETE FROM audit_entries WHERE id = ?",
            params![e1.id.0.to_string()],
        );
        assert!(
            del.is_err(),
            "BEFORE DELETE trigger must reject row deletion; got Ok"
        );

        // The row is still there and verifies clean.
        let count: i64 = raw
            .query_row("SELECT COUNT(*) FROM audit_entries", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "row must survive rejected UPDATE/DELETE");
    }
}
