//! SQLite index for artifact lifecycle state and metadata queries.
//!
//! Tracks: artifact_id → (content_store_id, state, operator_id, kind, supersedes, created_at).
//! The content store holds the bytes; this index holds the mutable lifecycle facts.

use std::path::Path;

use rusqlite::{Connection, params};

use crate::artifact::{ArtifactKind, LibraryFilter};
use crate::LibraryError;

pub struct ArtifactIndex {
    conn: std::sync::Mutex<Connection>,
}

#[derive(Debug)]
pub struct IndexRow {
    pub artifact_id: String,
    pub content_store_id: String,
    pub operator_id: String,
    pub kind: String,
    pub state: String,
    pub supersedes: Option<String>,
    pub created_at_ms: i64,
}

impl ArtifactIndex {
    pub fn open(path: &Path) -> Result<Self, LibraryError> {
        let conn = Connection::open(path)
            .map_err(|e| LibraryError::Index(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id      TEXT PRIMARY KEY,
                content_store_id TEXT NOT NULL,
                operator_id      TEXT NOT NULL,
                kind             TEXT NOT NULL,
                state            TEXT NOT NULL,
                supersedes       TEXT,
                created_at       INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kind_state
                ON artifacts (kind, state, operator_id, created_at DESC);",
        )
        .map_err(|e| LibraryError::Index(e.to_string()))?;
        Ok(Self { conn: std::sync::Mutex::new(conn) })
    }

    /// Insert a new artifact row. No-op if artifact_id already exists.
    pub fn insert(&self, row: &IndexRow) -> Result<(), LibraryError> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO artifacts
             (artifact_id, content_store_id, operator_id, kind, state, supersedes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                row.artifact_id,
                row.content_store_id,
                row.operator_id,
                row.kind,
                row.state,
                row.supersedes,
                row.created_at_ms,
            ],
        )
        .map_err(|e| LibraryError::Index(e.to_string()))?;
        Ok(())
    }

    /// Update the content_store_id and state for an existing artifact.
    pub fn update_state(
        &self,
        artifact_id: &str,
        new_content_store_id: &str,
        new_state: &str,
    ) -> Result<(), LibraryError> {
        let conn = self.conn.lock().unwrap();
        let n = conn
            .execute(
                "UPDATE artifacts SET content_store_id = ?1, state = ?2 WHERE artifact_id = ?3",
                params![new_content_store_id, new_state, artifact_id],
            )
            .map_err(|e| LibraryError::Index(e.to_string()))?;
        if n == 0 {
            return Err(LibraryError::NotFound(artifact_id.to_string()));
        }
        Ok(())
    }

    /// Look up a row by artifact_id.
    pub fn get(&self, artifact_id: &str) -> Result<Option<IndexRow>, LibraryError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT artifact_id, content_store_id, operator_id, kind, state, supersedes, created_at
             FROM artifacts WHERE artifact_id = ?1",
            params![artifact_id],
            |r| {
                Ok(IndexRow {
                    artifact_id: r.get(0)?,
                    content_store_id: r.get(1)?,
                    operator_id: r.get(2)?,
                    kind: r.get(3)?,
                    state: r.get(4)?,
                    supersedes: r.get(5)?,
                    created_at_ms: r.get(6)?,
                })
            },
        );
        match result {
            Ok(row) => Ok(Some(row)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LibraryError::Index(e.to_string())),
        }
    }

    /// List artifact_ids matching the filter.
    pub fn list(
        &self,
        filter: &LibraryFilter,
    ) -> Result<Vec<(String, String)>, LibraryError> {
        // Returns (artifact_id, content_store_id) pairs
        let limit = if filter.limit == 0 { 100 } else { filter.limit };
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from(
            "SELECT artifact_id, content_store_id FROM artifacts WHERE 1=1",
        );
        let mut params_dyn: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(kind) = &filter.kind {
            sql.push_str(" AND kind = ?");
            params_dyn.push(Box::new(kind.as_str().to_string()));
        }
        if let Some(state) = &filter.state {
            sql.push_str(" AND state = ?");
            params_dyn.push(Box::new(state.as_str().to_string()));
        }
        if let Some(op) = &filter.operator_id {
            sql.push_str(" AND operator_id = ?");
            params_dyn.push(Box::new(op.clone()));
        }
        if let Some(since) = filter.since {
            sql.push_str(" AND created_at > ?");
            params_dyn.push(Box::new(since.timestamp_millis()));
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT ?");
        params_dyn.push(Box::new(limit as i64));

        let refs: Vec<&dyn rusqlite::ToSql> =
            params_dyn.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| LibraryError::Index(e.to_string()))?;
        let rows: Vec<(String, String)> = stmt
            .query_map(refs.as_slice(), |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| LibraryError::Index(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Latest signed artifact for a kind + operator.
    pub fn latest_signed(
        &self,
        kind: &ArtifactKind,
        operator_id: &str,
    ) -> Result<Option<(String, String)>, LibraryError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT artifact_id, content_store_id FROM artifacts
             WHERE kind = ?1 AND operator_id = ?2 AND state = 'signed'
             ORDER BY created_at DESC LIMIT 1",
            params![kind.as_str(), operator_id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
        );
        match result {
            Ok(pair) => Ok(Some(pair)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(LibraryError::Index(e.to_string())),
        }
    }
}
