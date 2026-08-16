//! OntologyStore — writer-side handle for the derived ontology database.
//!
//! Per CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md §Section 5.
//!
//! Owned by the Cartographer background task. Serializes writes via internal
//! Mutex-guarded connection. Readers acquire separate connections via
//! `OntologyStore::open_reader`.
//!
//! P0 scope (this file): connection open, schema migration, meta table
//! read/write. Object CREATE / UPDATE and relationship materialization
//! land in P1.

use std::path::Path;
use std::sync::Mutex;

use chrono::Utc;
use rusqlite::{params, Connection};
use tracing::info;
use zp_core::AuditId;

use crate::error::{ReadError, StoreError};
use crate::id::{ObjectId, ObjectType};
use crate::objects::OntologyObject;
use crate::relationships::{ObjectRef, Relationship};

/// Compiled-in schema DDL for v1.
const SCHEMA_V1_SQL: &str = include_str!("../migrations/schema-v1.sql");

/// Current schema version compiled into this binary.
const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Meta-key names.
pub mod meta_keys {
    pub const SCHEMA_VERSION: &str = "schema_version";
    pub const CARTOGRAPHER_VERSION: &str = "cartographer_version";
    pub const LAST_PROCESSED_SEQUENCE: &str = "last_processed_sequence";
    pub const LAST_PROCESSED_AT: &str = "last_processed_at";
    pub const BOUNDARY_CONFIG: &str = "boundary_config";
    pub const REBUILD_IN_PROGRESS: &str = "rebuild_in_progress";
}

/// Writer-side handle to the ontology database.
///
/// One instance per process, owned by the Cartographer task. All mutations
/// go through this handle; readers get their own connections via
/// `open_reader`.
pub struct OntologyStore {
    /// Mutex-guarded write connection.
    /// WAL journal mode means readers do not block the writer.
    conn: Mutex<Connection>,
}

impl OntologyStore {
    /// Open (or create) the ontology database at `path`, applying schema
    /// migrations as needed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;

        // WAL journal mode for reader/writer concurrency.
        // busy_timeout to give writers a chance under mild contention.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let store = OntologyStore {
            conn: Mutex::new(conn),
        };
        store.apply_migrations()?;
        info!(
            path = %path.display(),
            schema_version = CURRENT_SCHEMA_VERSION,
            "OntologyStore opened"
        );
        Ok(store)
    }

    /// Apply schema migrations from the current on-disk version up to
    /// `CURRENT_SCHEMA_VERSION`. Idempotent.
    fn apply_migrations(&self) -> Result<(), StoreError> {
        let guard = self.conn.lock().map_err(|e| StoreError::Migration {
            found: 0,
            target: CURRENT_SCHEMA_VERSION,
            detail: format!("lock poisoned: {e}"),
        })?;

        // Apply v1 schema unconditionally — all CREATE TABLE / INDEX
        // statements are IF NOT EXISTS. This handles both first-open
        // and idempotent re-open.
        guard.execute_batch(SCHEMA_V1_SQL)?;
        drop(guard);

        // Read version from meta; write current if absent.
        let existing = self.get_meta(meta_keys::SCHEMA_VERSION)?;
        match existing {
            None => {
                self.set_meta(
                    meta_keys::SCHEMA_VERSION,
                    &CURRENT_SCHEMA_VERSION.to_string(),
                )?;
            }
            Some(v) => {
                let parsed: u32 = v.parse().map_err(|_| StoreError::MetaInvalid {
                    key: meta_keys::SCHEMA_VERSION.into(),
                    detail: format!("not a valid schema version: {v}"),
                })?;
                if parsed > CURRENT_SCHEMA_VERSION {
                    return Err(StoreError::Migration {
                        found: parsed,
                        target: CURRENT_SCHEMA_VERSION,
                        detail:
                            "on-disk schema is newer than this binary understands — refuse to open"
                                .into(),
                    });
                }
                // parsed < CURRENT would trigger forward migrations here;
                // only v1 exists at this time, so nothing to do.
            }
        }
        Ok(())
    }

    /// Get a meta key's value, if set.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: key.into(),
            detail: "lock poisoned".into(),
        })?;
        let mut stmt = guard.prepare("SELECT value FROM meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Set a meta key. Upsert semantics.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: key.into(),
            detail: "lock poisoned".into(),
        })?;
        let now = Utc::now().to_rfc3339();
        guard.execute(
            "INSERT INTO meta (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
            params![key, value, now],
        )?;
        Ok(())
    }

    /// Get the current last-processed audit sequence, if any.
    pub fn last_processed_sequence(&self) -> Result<Option<i64>, StoreError> {
        match self.get_meta(meta_keys::LAST_PROCESSED_SEQUENCE)? {
            None => Ok(None),
            Some(s) => {
                let n: i64 = s.parse().map_err(|_| StoreError::MetaInvalid {
                    key: meta_keys::LAST_PROCESSED_SEQUENCE.into(),
                    detail: format!("not a valid sequence number: {s}"),
                })?;
                Ok(Some(n))
            }
        }
    }

    /// Advance the last-processed audit sequence.
    pub fn set_last_processed_sequence(&self, seq: i64) -> Result<(), StoreError> {
        self.set_meta(meta_keys::LAST_PROCESSED_SEQUENCE, &seq.to_string())?;
        self.set_meta(meta_keys::LAST_PROCESSED_AT, &Utc::now().to_rfc3339())?;
        Ok(())
    }

    /// Count rows in the objects table. P0-utility for smoke tests.
    pub fn object_count(&self) -> Result<i64, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "objects".into(),
            detail: "lock poisoned".into(),
        })?;
        let count: i64 = guard.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
        Ok(count)
    }

    /// Count rows in the objects table for a specific type.
    pub fn object_count_by_type(&self, ty: ObjectType) -> Result<i64, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "objects".into(),
            detail: "lock poisoned".into(),
        })?;
        let count: i64 = guard.query_row(
            "SELECT COUNT(*) FROM objects WHERE object_type = ?1",
            params![ty.as_str()],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    // ── Object CRUD ────────────────────────────────────────────────────────

    /// Insert an ontology object.
    ///
    /// Fails if an object with the same ID already exists (use `update_object`
    /// for mutations). Foreign key check enforces trajectory_id validity for
    /// sub-objects.
    pub fn insert_object<T: OntologyObject>(&self, obj: &T) -> Result<(), StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "objects".into(),
            detail: "lock poisoned".into(),
        })?;

        let payload = serde_json::to_vec(obj)?;

        guard.execute(
            "INSERT INTO objects
             (id, object_type, trajectory_id, status, title, payload,
              boundary_confidence, created_at, last_active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                obj.id().as_bytes().as_slice(),
                T::OBJECT_TYPE.as_str(),
                obj.trajectory_id().map(|id| id.as_bytes().as_slice()),
                obj.status_str(),
                obj.title(),
                payload,
                obj.boundary_confidence(),
                obj.created_at().to_rfc3339(),
                obj.last_active().to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    /// Get an ontology object by ID. Returns None if not found; returns error
    /// if object exists but is of a different type than requested (type mismatch
    /// indicates a logic bug in the caller).
    pub fn get_object<T: OntologyObject>(&self, id: &ObjectId) -> Result<Option<T>, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "objects".into(),
            detail: "lock poisoned".into(),
        })?;

        let mut stmt = guard.prepare("SELECT object_type, payload FROM objects WHERE id = ?1")?;
        let mut rows = stmt.query(params![id.as_bytes().as_slice()])?;

        if let Some(row) = rows.next()? {
            let stored_type: String = row.get(0)?;
            if stored_type != T::OBJECT_TYPE.as_str() {
                // Type mismatch: caller asked for T but stored object is different.
                return Err(StoreError::MetaInvalid {
                    key: format!("object:{}", id.to_hex()),
                    detail: format!(
                        "type mismatch: requested {}, stored {}",
                        T::OBJECT_TYPE.as_str(),
                        stored_type
                    ),
                });
            }
            let payload: Vec<u8> = row.get(1)?;
            let obj: T = serde_json::from_slice(&payload)?;
            Ok(Some(obj))
        } else {
            Ok(None)
        }
    }

    /// Update an existing ontology object. Fails if the object does not exist.
    pub fn update_object<T: OntologyObject>(&self, obj: &T) -> Result<(), StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "objects".into(),
            detail: "lock poisoned".into(),
        })?;

        let payload = serde_json::to_vec(obj)?;

        let updated = guard.execute(
            "UPDATE objects
             SET status = ?2, title = ?3, payload = ?4,
                 boundary_confidence = ?5, last_active = ?6
             WHERE id = ?1 AND object_type = ?7",
            params![
                obj.id().as_bytes().as_slice(),
                obj.status_str(),
                obj.title(),
                payload,
                obj.boundary_confidence(),
                obj.last_active().to_rfc3339(),
                T::OBJECT_TYPE.as_str(),
            ],
        )?;

        if updated == 0 {
            return Err(StoreError::MetaInvalid {
                key: format!("object:{}", obj.id().to_hex()),
                detail: format!(
                    "no {} row with that id (call insert_object first)",
                    T::OBJECT_TYPE.as_str()
                ),
            });
        }
        Ok(())
    }

    // ── Object-receipt linkage ────────────────────────────────────────────

    /// Link an audit-chain receipt to an ontology object.
    /// Idempotent — the (object_id, audit_id) primary key prevents duplicates.
    pub fn link_receipt(
        &self,
        object_id: &ObjectId,
        audit_id: &AuditId,
        role: Option<&str>,
    ) -> Result<(), StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "object_receipts".into(),
            detail: "lock poisoned".into(),
        })?;

        guard.execute(
            "INSERT OR IGNORE INTO object_receipts (object_id, audit_id, role)
             VALUES (?1, ?2, ?3)",
            params![
                object_id.as_bytes().as_slice(),
                audit_id.0.as_bytes().as_slice(),
                role,
            ],
        )?;
        Ok(())
    }

    /// Get all audit-chain receipt IDs linked to an ontology object.
    pub fn receipts_for(&self, object_id: &ObjectId) -> Result<Vec<AuditId>, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "object_receipts".into(),
            detail: "lock poisoned".into(),
        })?;

        let mut stmt = guard.prepare(
            "SELECT audit_id FROM object_receipts WHERE object_id = ?1
             ORDER BY audit_id",
        )?;
        let rows = stmt.query_map(params![object_id.as_bytes().as_slice()], |row| {
            let bytes: Vec<u8> = row.get(0)?;
            Ok(bytes)
        })?;

        let mut out = Vec::new();
        for row in rows {
            let bytes = row?;
            if bytes.len() != 16 {
                return Err(StoreError::MetaInvalid {
                    key: format!("object_receipts:{}", object_id.to_hex()),
                    detail: format!("audit_id has wrong length: {}", bytes.len()),
                });
            }
            let uuid_bytes: [u8; 16] = bytes.try_into().expect("length checked above");
            out.push(AuditId(uuid::Uuid::from_bytes(uuid_bytes)));
        }
        Ok(out)
    }

    // ── Relationship CRUD ─────────────────────────────────────────────────

    /// Insert a relationship. Idempotent on (source, target, kind) via
    /// UNIQUE constraint — inserting the same relationship twice is a no-op.
    pub fn insert_relationship(&self, rel: &Relationship) -> Result<(), StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "relationships".into(),
            detail: "lock poisoned".into(),
        })?;

        let payload = serde_json::to_vec(rel)?;

        guard.execute(
            "INSERT OR IGNORE INTO relationships
             (id, source_type, source_id, target_type, target_id,
              kind, created_at, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                rel.id.as_bytes().as_slice(),
                rel.source.object_type.as_str(),
                rel.source.object_id.as_bytes().as_slice(),
                rel.target.object_type.as_str(),
                rel.target.object_id.as_bytes().as_slice(),
                rel.kind.as_str(),
                rel.created_at.to_rfc3339(),
                payload,
            ],
        )?;

        // Also link the relationship's receipt refs.
        for audit_id in &rel.receipt_refs {
            guard.execute(
                "INSERT OR IGNORE INTO relationship_receipts (relationship_id, audit_id)
                 VALUES (?1, ?2)",
                params![
                    rel.id.as_bytes().as_slice(),
                    audit_id.0.as_bytes().as_slice(),
                ],
            )?;
        }

        Ok(())
    }

    /// Get all relationships originating from a source object.
    pub fn relationships_from(&self, source: ObjectRef) -> Result<Vec<Relationship>, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "relationships".into(),
            detail: "lock poisoned".into(),
        })?;

        let mut stmt = guard.prepare(
            "SELECT payload FROM relationships
             WHERE source_type = ?1 AND source_id = ?2
             ORDER BY created_at",
        )?;
        let rows = stmt.query_map(
            params![
                source.object_type.as_str(),
                source.object_id.as_bytes().as_slice(),
            ],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            let bytes = row?;
            let rel: Relationship = serde_json::from_slice(&bytes)?;
            out.push(rel);
        }
        Ok(out)
    }

    /// Get all relationships targeting a specific object.
    pub fn relationships_to(&self, target: ObjectRef) -> Result<Vec<Relationship>, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "relationships".into(),
            detail: "lock poisoned".into(),
        })?;

        let mut stmt = guard.prepare(
            "SELECT payload FROM relationships
             WHERE target_type = ?1 AND target_id = ?2
             ORDER BY created_at",
        )?;
        let rows = stmt.query_map(
            params![
                target.object_type.as_str(),
                target.object_id.as_bytes().as_slice(),
            ],
            |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            },
        )?;

        let mut out = Vec::new();
        for row in rows {
            let bytes = row?;
            let rel: Relationship = serde_json::from_slice(&bytes)?;
            out.push(rel);
        }
        Ok(out)
    }

    /// Fetch the most-recently-active trajectory across all statuses.
    ///
    /// Returns None if no trajectory rows exist yet (fresh substrate). Used by
    /// Cartographer to determine the "current" trajectory for boundary
    /// evaluation on new receipts.
    pub fn most_recently_active_trajectory(
        &self,
    ) -> Result<Option<crate::objects::Trajectory>, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "objects".into(),
            detail: "lock poisoned".into(),
        })?;

        let mut stmt = guard.prepare(
            "SELECT payload FROM objects
             WHERE object_type = 'trajectory'
             ORDER BY last_active DESC
             LIMIT 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(0)?;
            let traj: crate::objects::Trajectory = serde_json::from_slice(&payload)?;
            Ok(Some(traj))
        } else {
            Ok(None)
        }
    }

    /// Count rows in the relationships table.
    pub fn relationship_count(&self) -> Result<i64, StoreError> {
        let guard = self.conn.lock().map_err(|_| StoreError::MetaInvalid {
            key: "relationships".into(),
            detail: "lock poisoned".into(),
        })?;
        let count: i64 = guard.query_row("SELECT COUNT(*) FROM relationships", [], |r| r.get(0))?;
        Ok(count)
    }
}

// Silence unused-import warning for ReadError; consumers will use it via
// `pub use` re-exports in lib.rs. Left in the import list to signal intent.
#[allow(dead_code)]
fn _read_error_placeholder(_: ReadError) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_store() -> (OntologyStore, TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("ontology.db");
        let store = OntologyStore::open(&path).expect("open store");
        (store, tmp)
    }

    #[test]
    fn open_creates_database_and_meta() {
        let (store, _tmp) = temp_store();
        let ver = store.get_meta(meta_keys::SCHEMA_VERSION).expect("get meta");
        assert_eq!(ver.as_deref(), Some("1"));
    }

    #[test]
    fn open_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("ontology.db");

        let s1 = OntologyStore::open(&path).expect("first open");
        s1.set_meta("test_key", "hello").expect("set");
        drop(s1);

        let s2 = OntologyStore::open(&path).expect("reopen");
        let v = s2.get_meta("test_key").expect("get");
        assert_eq!(v.as_deref(), Some("hello"));
    }

    #[test]
    fn empty_chain_produces_empty_ontology() {
        let (store, _tmp) = temp_store();
        assert_eq!(store.object_count().expect("count"), 0);
        assert_eq!(store.last_processed_sequence().expect("last seq"), None);
    }

    #[test]
    fn last_processed_sequence_roundtrip() {
        let (store, _tmp) = temp_store();
        assert_eq!(store.last_processed_sequence().unwrap(), None);
        store.set_last_processed_sequence(42).unwrap();
        assert_eq!(store.last_processed_sequence().unwrap(), Some(42));
        store.set_last_processed_sequence(100).unwrap();
        assert_eq!(store.last_processed_sequence().unwrap(), Some(100));
    }

    #[test]
    fn set_meta_updates_timestamp() {
        let (store, _tmp) = temp_store();
        store.set_meta("k", "v1").unwrap();
        let guard = store.conn.lock().unwrap();
        let ts1: String = guard
            .query_row("SELECT updated_at FROM meta WHERE key = 'k'", [], |r| {
                r.get(0)
            })
            .unwrap();
        drop(guard);

        std::thread::sleep(std::time::Duration::from_millis(10));
        store.set_meta("k", "v2").unwrap();
        let guard = store.conn.lock().unwrap();
        let ts2: String = guard
            .query_row("SELECT updated_at FROM meta WHERE key = 'k'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_ne!(ts1, ts2);
    }

    // ── P1 CRUD tests ──────────────────────────────────────────────────

    use crate::id::{derive_object_id, derive_trajectory_id};
    use crate::objects::{
        Decision, DecisionStatus, Friction, FrictionSeverity, FrictionStatus, Trajectory,
        TrajectoryStatus,
    };
    use crate::relationships::{ObjectRef, Relationship, RelationshipKind};
    use chrono::Utc;
    use zp_core::AuditId;

    fn sample_trajectory() -> Trajectory {
        let id = derive_trajectory_id("hash-alpha", r#"{"time_gap":0.6}"#);
        let now = Utc::now();
        Trajectory {
            id,
            title: "Sample".into(),
            status: TrajectoryStatus::Active,
            boundary_confidence: 0.75,
            parent_id: None,
            tags: vec![],
            created_at: now,
            last_active: now,
            receipt_refs: vec![],
            dominant_conversation_id: zp_core::ConversationId(uuid::Uuid::nil()),
            seen_conversation_ids: vec![],
            event_prefix_counts: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn insert_and_get_trajectory_roundtrip() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert");

        let fetched: Option<Trajectory> = store.get_object(&t.id).expect("get");
        assert_eq!(fetched.as_ref(), Some(&t));

        assert_eq!(store.object_count().unwrap(), 1);
        assert_eq!(
            store.object_count_by_type(ObjectType::Trajectory).unwrap(),
            1
        );
    }

    #[test]
    fn get_nonexistent_object_returns_none() {
        let (store, _tmp) = temp_store();
        let fake_id = derive_trajectory_id("nope", "{}");
        let fetched: Option<Trajectory> = store.get_object(&fake_id).expect("get");
        assert!(fetched.is_none());
    }

    #[test]
    fn insert_duplicate_id_fails() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("first insert ok");
        let result = store.insert_object(&t);
        assert!(
            result.is_err(),
            "second insert of same ID should fail (use update_object instead)"
        );
    }

    #[test]
    fn update_object_modifies_row() {
        let (store, _tmp) = temp_store();
        let mut t = sample_trajectory();
        store.insert_object(&t).expect("insert");

        t.status = TrajectoryStatus::Dormant;
        t.title = "Renamed".into();
        store.update_object(&t).expect("update");

        let fetched: Trajectory = store.get_object(&t.id).unwrap().expect("present");
        assert_eq!(fetched.status, TrajectoryStatus::Dormant);
        assert_eq!(fetched.title, "Renamed");
    }

    #[test]
    fn update_nonexistent_object_fails() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        // Never inserted; update should fail.
        let result = store.update_object(&t);
        assert!(result.is_err());
    }

    #[test]
    fn type_mismatch_on_get_returns_error() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert");

        // Asking for a Decision at the trajectory's ID: type mismatch.
        let result: Result<Option<Decision>, StoreError> = store.get_object(&t.id);
        assert!(result.is_err());
    }

    #[test]
    fn insert_decision_requires_valid_trajectory_fk() {
        let (store, _tmp) = temp_store();
        // Insert trajectory first.
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert traj");

        // Now a Decision referencing the trajectory: should succeed.
        let d = Decision {
            id: derive_object_id(ObjectType::Decision, "r1", "d1"),
            trajectory_id: t.id,
            title: "Approve".into(),
            description: "".into(),
            status: DecisionStatus::Active,
            superseded_by: None,
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        store.insert_object(&d).expect("insert decision");

        assert_eq!(store.object_count().unwrap(), 2);
        assert_eq!(store.object_count_by_type(ObjectType::Decision).unwrap(), 1);
    }

    #[test]
    fn insert_decision_with_invalid_trajectory_fk_fails() {
        let (store, _tmp) = temp_store();
        // Skip inserting the trajectory — the FK should fail.
        let bogus_traj_id = derive_trajectory_id("nonexistent", "{}");
        let d = Decision {
            id: derive_object_id(ObjectType::Decision, "r1", "d1"),
            trajectory_id: bogus_traj_id,
            title: "".into(),
            description: "".into(),
            status: DecisionStatus::Active,
            superseded_by: None,
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        let result = store.insert_object(&d);
        assert!(
            result.is_err(),
            "FK constraint should reject orphan decision"
        );
    }

    #[test]
    fn link_receipt_and_query_back() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert");

        let a1 = AuditId::new();
        let a2 = AuditId::new();
        store.link_receipt(&t.id, &a1, Some("origin")).unwrap();
        store.link_receipt(&t.id, &a2, Some("evidence")).unwrap();

        let receipts = store.receipts_for(&t.id).unwrap();
        assert_eq!(receipts.len(), 2);
        // Sorted by audit_id bytes; check both are present.
        assert!(receipts.contains(&a1));
        assert!(receipts.contains(&a2));
    }

    #[test]
    fn link_receipt_is_idempotent() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert");
        let a = AuditId::new();
        store.link_receipt(&t.id, &a, None).unwrap();
        // Second link with same pair is a no-op via INSERT OR IGNORE.
        store.link_receipt(&t.id, &a, None).unwrap();
        assert_eq!(store.receipts_for(&t.id).unwrap().len(), 1);
    }

    #[test]
    fn insert_relationship_and_query_from() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert traj");

        let d = Decision {
            id: derive_object_id(ObjectType::Decision, "r1", "d1"),
            trajectory_id: t.id,
            title: "Approve".into(),
            description: "".into(),
            status: DecisionStatus::Active,
            superseded_by: None,
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        store.insert_object(&d).expect("insert dec");

        let rel = Relationship::new(
            ObjectRef::new(ObjectType::Decision, d.id),
            ObjectRef::new(ObjectType::Trajectory, t.id),
            RelationshipKind::BelongsTo,
            vec![AuditId::new()],
        );
        store.insert_relationship(&rel).expect("insert rel");

        assert_eq!(store.relationship_count().unwrap(), 1);

        // Query from source.
        let from = store
            .relationships_from(ObjectRef::new(ObjectType::Decision, d.id))
            .unwrap();
        assert_eq!(from.len(), 1);
        assert_eq!(from[0].id, rel.id);

        // Query to target.
        let to = store
            .relationships_to(ObjectRef::new(ObjectType::Trajectory, t.id))
            .unwrap();
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].id, rel.id);
    }

    #[test]
    fn duplicate_relationship_insert_is_noop() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert traj");

        let d = Decision {
            id: derive_object_id(ObjectType::Decision, "r", "d"),
            trajectory_id: t.id,
            title: "".into(),
            description: "".into(),
            status: DecisionStatus::Active,
            superseded_by: None,
            created_at: Utc::now(),
            receipt_refs: vec![],
        };
        store.insert_object(&d).expect("insert dec");

        let rel = Relationship::new(
            ObjectRef::new(ObjectType::Decision, d.id),
            ObjectRef::new(ObjectType::Trajectory, t.id),
            RelationshipKind::BelongsTo,
            vec![],
        );
        store.insert_relationship(&rel).unwrap();
        store.insert_relationship(&rel).unwrap();
        assert_eq!(store.relationship_count().unwrap(), 1);
    }

    #[test]
    fn insert_friction_end_to_end() {
        let (store, _tmp) = temp_store();
        let t = sample_trajectory();
        store.insert_object(&t).expect("insert traj");

        let now = Utc::now();
        let f = Friction {
            id: derive_object_id(ObjectType::Friction, "r-fri", "recurring"),
            trajectory_id: t.id,
            title: "Third occurrence".into(),
            description: "".into(),
            severity: FrictionSeverity::High,
            status: FrictionStatus::Active,
            occurrences: 3,
            first_seen: now - chrono::Duration::days(2),
            last_seen: now,
            workaround: None,
            created_at: now,
            receipt_refs: vec![],
        };
        store.insert_object(&f).expect("insert friction");

        let fetched: Friction = store.get_object(&f.id).unwrap().expect("present");
        assert_eq!(fetched, f);
        // last_active should equal last_seen (per OntologyObject impl).
        assert_eq!(fetched.last_active(), f.last_seen);
    }

    #[test]
    fn refuses_to_open_newer_schema() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("ontology.db");

        let s = OntologyStore::open(&path).unwrap();
        s.set_meta(meta_keys::SCHEMA_VERSION, "999").unwrap();
        drop(s);

        // Can't use unwrap_err() — OntologyStore holds Mutex<Connection>
        // which doesn't impl Debug. Pattern-match on the Err arm instead.
        match OntologyStore::open(&path) {
            Ok(_) => panic!("expected Migration error for newer schema, got Ok"),
            Err(StoreError::Migration { found: 999, .. }) => {}
            Err(other) => panic!("expected Migration{{found:999,..}}, got {other:?}"),
        }
    }
}
