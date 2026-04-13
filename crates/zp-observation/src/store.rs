//! SQLite-backed observation store.
//!
//! Follows the same patterns as `zp-audit::AuditStore` and
//! `zp-learning::EpisodeStore` for consistency across the ZeroPoint ecosystem.

use std::path::Path;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use tracing::{debug, info};

use crate::{Observation, ObservationPriority, Reflection, SourceRange};

/// Errors from the observation store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("observation not found: {0}")]
    NotFound(String),
}

/// Persistent storage for observations and reflections.
///
/// Uses SQLite for consistency with ZeroPoint's existing store patterns.
/// The store manages the observation lifecycle: creation, querying,
/// superseding, and pruning.
///
/// **Thread Safety**: `ObservationStore` is NOT `Send` or `Sync` because
/// `rusqlite::Connection` requires single-threaded access. Wrap in
/// `Mutex<ObservationStore>` if multi-threaded access is needed.
pub struct ObservationStore {
    conn: Connection,
}

impl ObservationStore {
    /// Open or create an observation store at the given path.
    pub fn new(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory observation store (for testing).
    pub fn in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS observations (
                id              TEXT PRIMARY KEY,
                content         TEXT NOT NULL,
                priority        TEXT NOT NULL,
                category        TEXT NOT NULL,
                referenced_at   TEXT NOT NULL,
                observed_at     TEXT NOT NULL,
                relative_time   TEXT,
                source_range    TEXT NOT NULL,
                superseded      INTEGER NOT NULL DEFAULT 0,
                token_estimate  INTEGER NOT NULL,
                receipt_id      TEXT,
                content_hash    TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_observations_priority
                ON observations(priority);
            CREATE INDEX IF NOT EXISTS idx_observations_category
                ON observations(category);
            CREATE INDEX IF NOT EXISTS idx_observations_superseded
                ON observations(superseded);
            CREATE INDEX IF NOT EXISTS idx_observations_observed_at
                ON observations(observed_at);

            CREATE TABLE IF NOT EXISTS reflections (
                id              TEXT PRIMARY KEY,
                reflected_at    TEXT NOT NULL,
                consumed_ids    TEXT NOT NULL,
                produced_ids    TEXT NOT NULL,
                dropped_ids     TEXT NOT NULL,
                tokens_before   INTEGER NOT NULL,
                tokens_after    INTEGER NOT NULL,
                receipt_id      TEXT
            );

            CREATE TABLE IF NOT EXISTS observation_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ",
        )?;
        Ok(())
    }

    /// Append a new observation to the store.
    pub fn append(&self, obs: &Observation) -> Result<(), StoreError> {
        let source_range_json = serde_json::to_string(&obs.source_range)?;
        let content_hash = obs.content_hash();

        self.conn.execute(
            "INSERT INTO observations (
                id, content, priority, category, referenced_at, observed_at,
                relative_time, source_range, superseded, token_estimate,
                receipt_id, content_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                obs.id,
                obs.content,
                obs.priority.to_string(),
                obs.category,
                obs.referenced_at.to_rfc3339(),
                obs.observed_at.to_rfc3339(),
                obs.relative_time,
                source_range_json,
                obs.superseded as i32,
                obs.token_estimate as i64,
                obs.receipt_id,
                content_hash,
            ],
        )?;

        debug!(id = %obs.id, priority = %obs.priority, "observation appended");
        Ok(())
    }

    /// Get all active (non-superseded) observations, ordered by priority desc.
    pub fn get_active(&self) -> Result<Vec<Observation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, priority, category, referenced_at, observed_at,
                    relative_time, source_range, superseded, token_estimate, receipt_id
             FROM observations
             WHERE superseded = 0
             ORDER BY
                CASE priority
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    WHEN 'completed' THEN 1
                END DESC,
                observed_at DESC",
        )?;

        let mut observations = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            observations.push(self.row_to_observation(row)?);
        }

        Ok(observations)
    }

    /// Get active observations at or above a minimum priority.
    pub fn get_by_priority(
        &self,
        min_priority: ObservationPriority,
    ) -> Result<Vec<Observation>, StoreError> {
        let min_val = priority_to_int(min_priority);

        let mut stmt = self.conn.prepare(
            "SELECT id, content, priority, category, referenced_at, observed_at,
                    relative_time, source_range, superseded, token_estimate, receipt_id
             FROM observations
             WHERE superseded = 0
             AND CASE priority
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    WHEN 'completed' THEN 1
                 END >= ?1
             ORDER BY observed_at DESC",
        )?;

        let mut observations = Vec::new();
        let mut rows = stmt.query(params![min_val])?;
        while let Some(row) = rows.next()? {
            observations.push(self.row_to_observation(row)?);
        }

        Ok(observations)
    }

    /// Get active observations in a specific category.
    pub fn get_by_category(&self, category: &str) -> Result<Vec<Observation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, priority, category, referenced_at, observed_at,
                    relative_time, source_range, superseded, token_estimate, receipt_id
             FROM observations
             WHERE superseded = 0 AND category = ?1
             ORDER BY observed_at DESC",
        )?;

        let mut observations = Vec::new();
        let mut rows = stmt.query(params![category])?;
        while let Some(row) = rows.next()? {
            observations.push(self.row_to_observation(row)?);
        }

        Ok(observations)
    }

    /// Get a single observation by ID.
    pub fn get(&self, id: &str) -> Result<Option<Observation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, content, priority, category, referenced_at, observed_at,
                    relative_time, source_range, superseded, token_estimate, receipt_id
             FROM observations
             WHERE id = ?1",
        )?;

        let mut rows = stmt.query(params![id])?;
        let obs = match rows.next()? {
            Some(row) => Some(self.row_to_observation(row)?),
            None => None,
        };

        Ok(obs)
    }

    /// Mark observations as superseded (consumed by a reflection).
    pub fn mark_superseded(&self, observation_ids: &[String]) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        for id in observation_ids {
            tx.execute(
                "UPDATE observations SET superseded = 1 WHERE id = ?1",
                params![id],
            )?;
        }
        tx.commit()?;

        debug!(
            count = observation_ids.len(),
            "observations marked superseded"
        );
        Ok(())
    }

    /// Record a reflection and update the store accordingly.
    ///
    /// This:
    /// 1. Marks consumed observations as superseded
    /// 2. Marks dropped observations as superseded
    /// 3. Appends new produced observations
    /// 4. Records the reflection itself
    pub fn record_reflection(&self, reflection: &Reflection) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;

        // Mark consumed and dropped observations as superseded
        let all_superseded: Vec<&String> = reflection
            .consumed_observation_ids
            .iter()
            .chain(reflection.dropped_observation_ids.iter())
            .collect();

        for id in &all_superseded {
            tx.execute(
                "UPDATE observations SET superseded = 1 WHERE id = ?1",
                params![id],
            )?;
        }

        // Insert produced observations
        for obs in &reflection.produced_observations {
            let source_range_json = serde_json::to_string(&obs.source_range)?;
            let content_hash = obs.content_hash();

            tx.execute(
                "INSERT INTO observations (
                    id, content, priority, category, referenced_at, observed_at,
                    relative_time, source_range, superseded, token_estimate,
                    receipt_id, content_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    obs.id,
                    obs.content,
                    obs.priority.to_string(),
                    obs.category,
                    obs.referenced_at.to_rfc3339(),
                    obs.observed_at.to_rfc3339(),
                    obs.relative_time,
                    source_range_json,
                    obs.superseded as i32,
                    obs.token_estimate as i64,
                    obs.receipt_id,
                    content_hash,
                ],
            )?;
        }

        // Record the reflection itself
        let consumed_json = serde_json::to_string(&reflection.consumed_observation_ids)?;
        let produced_ids: Vec<&str> = reflection
            .produced_observations
            .iter()
            .map(|o| o.id.as_str())
            .collect();
        let produced_json = serde_json::to_string(&produced_ids)?;
        let dropped_json = serde_json::to_string(&reflection.dropped_observation_ids)?;

        tx.execute(
            "INSERT INTO reflections (
                id, reflected_at, consumed_ids, produced_ids, dropped_ids,
                tokens_before, tokens_after, receipt_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                reflection.id,
                reflection.reflected_at.to_rfc3339(),
                consumed_json,
                produced_json,
                dropped_json,
                reflection.tokens_before as i64,
                reflection.tokens_after as i64,
                reflection.receipt_id,
            ],
        )?;

        tx.commit()?;

        info!(
            reflection_id = %reflection.id,
            consumed = reflection.consumed_observation_ids.len(),
            produced = reflection.produced_observations.len(),
            dropped = reflection.dropped_observation_ids.len(),
            ratio = format!("{:.1}%", reflection.compression_ratio() * 100.0),
            "reflection recorded"
        );

        Ok(())
    }

    /// Get the total estimated token count for all active observations.
    pub fn total_token_estimate(&self) -> Result<usize, StoreError> {
        let total: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(token_estimate), 0) FROM observations WHERE superseded = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(total as usize)
    }

    /// Count of active (non-superseded) observations.
    pub fn active_count(&self) -> Result<usize, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM observations WHERE superseded = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(count as usize)
    }

    /// Prune superseded observations older than the given timestamp.
    /// Returns the number of rows deleted.
    pub fn prune_superseded(&self, older_than: DateTime<Utc>) -> Result<usize, StoreError> {
        let deleted = self.conn.execute(
            "DELETE FROM observations WHERE superseded = 1 AND observed_at < ?1",
            params![older_than.to_rfc3339()],
        )?;
        debug!(deleted, "pruned superseded observations");
        Ok(deleted)
    }

    /// Get or set a metadata value (for tracking last-processed sequence, etc.).
    pub fn get_meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        let val = self
            .conn
            .query_row(
                "SELECT value FROM observation_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(val)
    }

    /// Set a metadata value.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO observation_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Format all active observations into a summary string suitable for
    /// injection into a conversation context window.
    pub fn format_summary(&self) -> Result<String, StoreError> {
        let observations = self.get_active()?;
        if observations.is_empty() {
            return Ok(String::new());
        }

        let mut summary = String::from("<observations>\n");
        let mut current_priority = None;

        for obs in &observations {
            if current_priority != Some(obs.priority) {
                current_priority = Some(obs.priority);
                summary.push_str(&format!("\n## {} Priority\n", obs.priority.emoji()));
            }

            let time_str = obs.relative_time.as_deref().unwrap_or("unknown time");

            summary.push_str(&format!(
                "- [{}] {} ({})\n",
                obs.category, obs.content, time_str
            ));
        }

        summary.push_str("</observations>\n");
        Ok(summary)
    }

    // -- Internal helpers --

    fn row_to_observation(&self, row: &rusqlite::Row<'_>) -> Result<Observation, StoreError> {
        let id: String = row.get(0).map_err(StoreError::Database)?;
        let content: String = row.get(1).map_err(StoreError::Database)?;
        let priority_str: String = row.get(2).map_err(StoreError::Database)?;
        let category: String = row.get(3).map_err(StoreError::Database)?;
        let referenced_at_str: String = row.get(4).map_err(StoreError::Database)?;
        let observed_at_str: String = row.get(5).map_err(StoreError::Database)?;
        let relative_time: Option<String> = row.get(6).map_err(StoreError::Database)?;
        let source_range_json: String = row.get(7).map_err(StoreError::Database)?;
        let superseded: i32 = row.get(8).map_err(StoreError::Database)?;
        let token_estimate_raw: i64 = row.get(9).map_err(StoreError::Database)?;
        let receipt_id: Option<String> = row.get(10).map_err(StoreError::Database)?;

        let priority =
            ObservationPriority::from_str_loose(&priority_str).unwrap_or(ObservationPriority::Low);

        let referenced_at = DateTime::parse_from_rfc3339(&referenced_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let observed_at = DateTime::parse_from_rfc3339(&observed_at_str)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let source_range: SourceRange = serde_json::from_str(&source_range_json)?;

        let token_estimate = token_estimate_raw as usize;

        Ok(Observation {
            id,
            content,
            priority,
            category,
            referenced_at,
            observed_at,
            relative_time,
            source_range,
            superseded: superseded != 0,
            token_estimate,
            receipt_id,
        })
    }
}

fn priority_to_int(p: ObservationPriority) -> i32 {
    match p {
        ObservationPriority::Completed => 1,
        ObservationPriority::Low => 2,
        ObservationPriority::Medium => 3,
        ObservationPriority::High => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_observation(id: &str, content: &str, priority: ObservationPriority) -> Observation {
        Observation {
            id: id.to_string(),
            content: content.to_string(),
            priority,
            category: "test".to_string(),
            referenced_at: Utc::now(),
            observed_at: Utc::now(),
            relative_time: Some("just now".to_string()),
            source_range: SourceRange::new("chain-1", "aaa", "bbb", 0, 5),
            superseded: false,
            token_estimate: Observation::estimate_tokens(content),
            receipt_id: None,
        }
    }

    #[test]
    fn create_and_query() {
        let store = ObservationStore::in_memory().unwrap();
        let obs = make_observation("obs-1", "User prefers dark mode", ObservationPriority::Low);
        store.append(&obs).unwrap();

        let active = store.get_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, "obs-1");
        assert_eq!(active[0].content, "User prefers dark mode");
    }

    #[test]
    fn priority_filtering() {
        let store = ObservationStore::in_memory().unwrap();
        store
            .append(&make_observation(
                "o1",
                "low priority",
                ObservationPriority::Low,
            ))
            .unwrap();
        store
            .append(&make_observation(
                "o2",
                "high priority",
                ObservationPriority::High,
            ))
            .unwrap();
        store
            .append(&make_observation(
                "o3",
                "medium priority",
                ObservationPriority::Medium,
            ))
            .unwrap();

        let high_only = store.get_by_priority(ObservationPriority::High).unwrap();
        assert_eq!(high_only.len(), 1);
        assert_eq!(high_only[0].id, "o2");

        let medium_plus = store.get_by_priority(ObservationPriority::Medium).unwrap();
        assert_eq!(medium_plus.len(), 2);
    }

    #[test]
    fn category_filtering() {
        let store = ObservationStore::in_memory().unwrap();
        let mut obs1 = make_observation("o1", "project A detail", ObservationPriority::Medium);
        obs1.category = "project-a".to_string();
        let mut obs2 = make_observation("o2", "project B detail", ObservationPriority::Medium);
        obs2.category = "project-b".to_string();

        store.append(&obs1).unwrap();
        store.append(&obs2).unwrap();

        let results = store.get_by_category("project-a").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "o1");
    }

    #[test]
    fn superseding() {
        let store = ObservationStore::in_memory().unwrap();
        store
            .append(&make_observation("o1", "fact 1", ObservationPriority::Low))
            .unwrap();
        store
            .append(&make_observation("o2", "fact 2", ObservationPriority::Low))
            .unwrap();

        assert_eq!(store.active_count().unwrap(), 2);

        store.mark_superseded(&["o1".to_string()]).unwrap();

        assert_eq!(store.active_count().unwrap(), 1);
        let active = store.get_active().unwrap();
        assert_eq!(active[0].id, "o2");
    }

    #[test]
    fn token_estimate_tracking() {
        let store = ObservationStore::in_memory().unwrap();
        store
            .append(&make_observation(
                "o1",
                "a fairly long observation about something important",
                ObservationPriority::High,
            ))
            .unwrap();
        store
            .append(&make_observation(
                "o2",
                "short fact",
                ObservationPriority::Low,
            ))
            .unwrap();

        let total = store.total_token_estimate().unwrap();
        assert!(total > 0);
    }

    #[test]
    fn metadata() {
        let store = ObservationStore::in_memory().unwrap();
        assert_eq!(store.get_meta("last_sequence").unwrap(), None);

        store.set_meta("last_sequence", "42").unwrap();
        assert_eq!(
            store.get_meta("last_sequence").unwrap(),
            Some("42".to_string())
        );

        store.set_meta("last_sequence", "99").unwrap();
        assert_eq!(
            store.get_meta("last_sequence").unwrap(),
            Some("99".to_string())
        );
    }

    #[test]
    fn reflection_recording() {
        let store = ObservationStore::in_memory().unwrap();

        // Add initial observations
        store
            .append(&make_observation(
                "o1",
                "fact about X",
                ObservationPriority::Low,
            ))
            .unwrap();
        store
            .append(&make_observation(
                "o2",
                "fact about X updated",
                ObservationPriority::Medium,
            ))
            .unwrap();
        store
            .append(&make_observation(
                "o3",
                "stale fact",
                ObservationPriority::Completed,
            ))
            .unwrap();

        assert_eq!(store.active_count().unwrap(), 3);

        // Create a reflection that merges o1+o2 and drops o3
        let merged = make_observation(
            "o4",
            "comprehensive fact about X",
            ObservationPriority::Medium,
        );

        let reflection = Reflection {
            id: "r1".to_string(),
            reflected_at: Utc::now(),
            consumed_observation_ids: vec!["o1".to_string(), "o2".to_string()],
            produced_observations: vec![merged],
            dropped_observation_ids: vec!["o3".to_string()],
            tokens_before: 100,
            tokens_after: 40,
            receipt_id: None,
        };

        store.record_reflection(&reflection).unwrap();

        // After reflection: o1, o2, o3 superseded; o4 active
        assert_eq!(store.active_count().unwrap(), 1);
        let active = store.get_active().unwrap();
        assert_eq!(active[0].id, "o4");
        assert_eq!(active[0].content, "comprehensive fact about X");
    }

    #[test]
    fn format_summary_output() {
        let store = ObservationStore::in_memory().unwrap();
        store
            .append(&make_observation(
                "o1",
                "critical blocker",
                ObservationPriority::High,
            ))
            .unwrap();
        store
            .append(&make_observation(
                "o2",
                "user likes Rust",
                ObservationPriority::Low,
            ))
            .unwrap();

        let summary = store.format_summary().unwrap();
        assert!(summary.contains("<observations>"));
        assert!(summary.contains("critical blocker"));
        assert!(summary.contains("user likes Rust"));
        assert!(summary.contains("🔴"));
        assert!(summary.contains("🟢"));
    }

    #[test]
    fn empty_summary() {
        let store = ObservationStore::in_memory().unwrap();
        let summary = store.format_summary().unwrap();
        assert!(summary.is_empty());
    }
}
