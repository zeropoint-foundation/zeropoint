//! Local SQLite index for content metadata lookups.
//!
//! The index is a derived cache — it can be rebuilt by walking the backend.
//! It lives at `~/ZeroPoint/content-index.db` (or `$ZP_CONTENT_INDEX`),
//! separate from the audit chain's SQLite.

use std::path::Path;

use chrono::{TimeZone as _, Utc};
use rusqlite::{params, Connection};

use crate::{ContentError, ContentFilter, ContentId, ContentMeta};

/// SQLite-backed index for content metadata.
pub struct LocalIndex {
    conn: std::sync::Mutex<Connection>,
}

impl LocalIndex {
    /// Open (or create) the index at `path`.
    pub fn open(path: &Path) -> Result<Self, ContentError> {
        let conn = Connection::open(path).map_err(|e| ContentError::Index(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS content (
                content_id  BLOB NOT NULL PRIMARY KEY,
                kind        TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                size_bytes  INTEGER NOT NULL,
                extensions  TEXT
            );",
        )
        .map_err(|e| ContentError::Index(e.to_string()))?;
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Insert a content entry. No-op if the id already exists.
    pub fn insert(&self, id: &ContentId, meta: &ContentMeta) -> Result<(), ContentError> {
        let extensions = meta
            .extensions
            .as_ref()
            .map(|e| serde_json::to_string(e).unwrap_or_default());
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO content (content_id, kind, created_at, size_bytes, extensions)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                id.0.as_ref(),
                meta.kind,
                meta.created_at.timestamp_millis(),
                meta.size_bytes as i64,
                extensions,
            ],
        )
        .map_err(|e| ContentError::Index(e.to_string()))?;
        Ok(())
    }

    /// Return true if the id is present in the index.
    pub fn contains(&self, id: &ContentId) -> Result<bool, ContentError> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM content WHERE content_id = ?1",
                params![id.0.as_ref()],
                |r| r.get(0),
            )
            .map_err(|e| ContentError::Index(e.to_string()))?;
        Ok(count > 0)
    }

    /// Look up metadata for a content id.
    pub fn get_meta(&self, id: &ContentId) -> Result<Option<ContentMeta>, ContentError> {
        let conn = self.conn.lock().unwrap();
        let result = conn.query_row(
            "SELECT kind, created_at, size_bytes, extensions FROM content WHERE content_id = ?1",
            params![id.0.as_ref()],
            |r| {
                let kind: String = r.get(0)?;
                let ts: i64 = r.get(1)?;
                let size: i64 = r.get(2)?;
                let ext: Option<String> = r.get(3)?;
                Ok((kind, ts, size, ext))
            },
        );
        match result {
            Ok((kind, ts, size, ext)) => {
                let created_at = Utc
                    .timestamp_millis_opt(ts)
                    .single()
                    .unwrap_or_else(Utc::now);
                let extensions = ext.and_then(|s| serde_json::from_str(&s).ok());
                Ok(Some(ContentMeta {
                    kind,
                    created_at,
                    size_bytes: size as u64,
                    extensions,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ContentError::Index(e.to_string())),
        }
    }

    /// List content ids matching `filter`.
    pub fn list(&self, filter: &ContentFilter) -> Result<Vec<ContentId>, ContentError> {
        let limit = if filter.limit == 0 { 100 } else { filter.limit };
        let conn = self.conn.lock().unwrap();

        let mut sql = String::from("SELECT content_id FROM content WHERE 1=1");
        let mut param_values: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if let Some(kind) = &filter.kind {
            sql.push_str(" AND kind = ?");
            param_values.push(Box::new(kind.clone()));
        }
        if let Some(after) = filter.created_after {
            sql.push_str(" AND created_at > ?");
            param_values.push(Box::new(after.timestamp_millis()));
        }
        sql.push_str(" ORDER BY created_at DESC LIMIT ?");
        param_values.push(Box::new(limit as i64));

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            param_values.iter().map(|b| b.as_ref()).collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| ContentError::Index(e.to_string()))?;
        let ids = stmt
            .query_map(params_refs.as_slice(), |r| {
                let raw: Vec<u8> = r.get(0)?;
                Ok(raw)
            })
            .map_err(|e| ContentError::Index(e.to_string()))?
            .filter_map(|r| r.ok())
            .filter_map(|raw| {
                if raw.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&raw);
                    Some(ContentId(arr))
                } else {
                    None
                }
            })
            .collect();
        Ok(ids)
    }
}
