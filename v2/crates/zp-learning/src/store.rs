//! Episode storage using SQLite for persistence and querying.

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};

use zp_core::episode::{Episode, EpisodeId};

/// Errors that can occur in the episode store.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("episode not found")]
    NotFound,

    #[error("invalid data: {0}")]
    InvalidData(String),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Stores and retrieves episodes from a SQLite database.
pub struct EpisodeStore {
    conn: Connection,
}

impl EpisodeStore {
    /// Opens or creates an episode store at the given path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrency
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;

        // Create the episodes table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS episodes (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                request_category TEXT NOT NULL,
                data TEXT NOT NULL
            ) STRICT",
            [],
        )?;

        // Create indexes for common queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_conversation_id ON episodes(conversation_id)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON episodes(timestamp DESC)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_request_category ON episodes(request_category)",
            [],
        )?;

        info!("opened episode store");

        Ok(Self { conn })
    }

    /// Records a new episode in the store.
    pub fn record(&self, episode: &Episode) -> Result<()> {
        let episode_data = serde_json::to_string(&episode)?;
        let episode_id = episode.id.0.to_string();
        let conversation_id = episode.conversation_id.0.to_string();
        let timestamp = episode.timestamp.to_rfc3339();

        self.conn.execute(
            "INSERT INTO episodes (id, conversation_id, timestamp, request_category, data)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &episode_id,
                &conversation_id,
                &timestamp,
                &episode.request_category,
                &episode_data
            ],
        )?;

        debug!(%episode_id, category = %episode.request_category, "recorded episode");

        Ok(())
    }

    /// Retrieves an episode by its ID.
    pub fn get(&self, id: &EpisodeId) -> Result<Option<Episode>> {
        let episode_id = id.0.to_string();

        let result = self
            .conn
            .query_row(
                "SELECT data FROM episodes WHERE id = ?1",
                params![&episode_id],
                |row| {
                    let data: String = row.get(0)?;
                    Ok(data)
                },
            )
            .optional()?;

        match result {
            Some(data) => {
                let episode = serde_json::from_str(&data)?;
                Ok(Some(episode))
            }
            None => Ok(None),
        }
    }

    /// Retrieves the N most recent episodes.
    pub fn recent(&self, limit: usize) -> Result<Vec<Episode>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM episodes
             ORDER BY timestamp DESC
             LIMIT ?1",
        )?;

        let episodes = stmt
            .query_map(params![limit as i64], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|data| serde_json::from_str(&data))
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;

        debug!(count = episodes.len(), "retrieved recent episodes");

        Ok(episodes)
    }

    /// Retrieves episodes with a specific request category.
    pub fn by_category(&self, category: &str, limit: usize) -> Result<Vec<Episode>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM episodes
             WHERE request_category = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let episodes = stmt
            .query_map(params![category, limit as i64], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|data| serde_json::from_str(&data))
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;

        debug!(
            category,
            count = episodes.len(),
            "retrieved episodes by category"
        );

        Ok(episodes)
    }

    /// Returns the total number of episodes in the store.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM episodes", [], |row| row.get(0))?;

        Ok(count as usize)
    }

    /// Retrieves episodes within a specific conversation.
    pub fn by_conversation(&self, conversation_id: &str, limit: usize) -> Result<Vec<Episode>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM episodes
             WHERE conversation_id = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let episodes = stmt
            .query_map(params![conversation_id, limit as i64], |row| {
                let data: String = row.get(0)?;
                Ok(data)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
            .into_iter()
            .map(|data| serde_json::from_str(&data))
            .collect::<std::result::Result<Vec<_>, serde_json::Error>>()?;

        debug!(
            conversation_id,
            count = episodes.len(),
            "retrieved episodes by conversation"
        );

        Ok(episodes)
    }

    /// Deletes episodes older than N days (for cleanup).
    pub fn delete_older_than_days(&self, days: i64) -> Result<usize> {
        let cutoff_time = Utc::now()
            .checked_sub_signed(chrono::Duration::days(days))
            .unwrap()
            .to_rfc3339();

        let changes = self.conn.execute(
            "DELETE FROM episodes WHERE timestamp < ?1",
            params![&cutoff_time],
        )?;

        info!(days, deleted_count = changes, "cleaned up old episodes");

        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use zp_core::episode::{EpisodeId, Outcome};
    use zp_core::types::ConversationId;

    #[test]
    fn test_store_and_retrieve() {
        let store = EpisodeStore::open(":memory:").unwrap();

        let episode = Episode {
            id: EpisodeId::new(),
            conversation_id: ConversationId::new(),
            timestamp: Utc::now(),
            request_hash: "test_hash".to_string(),
            request_category: "test_category".to_string(),
            tools_used: vec![],
            active_skills: vec![],
            model_used: "test_model".to_string(),
            outcome: Outcome::Success,
            feedback: None,
            duration_ms: 100,
            policy_decisions: vec![],
        };

        store.record(&episode).unwrap();

        let retrieved = store.get(&episode.id).unwrap();
        assert!(retrieved.is_some());

        let retrieved_episode = retrieved.unwrap();
        assert_eq!(retrieved_episode.id, episode.id);
        assert_eq!(retrieved_episode.request_category, episode.request_category);
    }

    #[test]
    fn test_recent() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let conversation_id = ConversationId::new();

        for i in 0..5 {
            let episode = Episode {
                id: EpisodeId::new(),
                conversation_id: conversation_id.clone(),
                timestamp: Utc::now(),
                request_hash: format!("hash_{}", i),
                request_category: "test".to_string(),
                tools_used: vec![],
                active_skills: vec![],
                model_used: "test".to_string(),
                outcome: Outcome::Success,
                feedback: None,
                duration_ms: 100,
                policy_decisions: vec![],
            };
            store.record(&episode).unwrap();
        }

        let recent = store.recent(3).unwrap();
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn test_by_category() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let conversation_id = ConversationId::new();

        for i in 0..3 {
            let episode = Episode {
                id: EpisodeId::new(),
                conversation_id: conversation_id.clone(),
                timestamp: Utc::now(),
                request_hash: format!("hash_{}", i),
                request_category: "analysis".to_string(),
                tools_used: vec![],
                active_skills: vec![],
                model_used: "test".to_string(),
                outcome: Outcome::Success,
                feedback: None,
                duration_ms: 100,
                policy_decisions: vec![],
            };
            store.record(&episode).unwrap();
        }

        for i in 0..2 {
            let episode = Episode {
                id: EpisodeId::new(),
                conversation_id: conversation_id.clone(),
                timestamp: Utc::now(),
                request_hash: format!("hash_other_{}", i),
                request_category: "other".to_string(),
                tools_used: vec![],
                active_skills: vec![],
                model_used: "test".to_string(),
                outcome: Outcome::Success,
                feedback: None,
                duration_ms: 100,
                policy_decisions: vec![],
            };
            store.record(&episode).unwrap();
        }

        let analysis = store.by_category("analysis", 10).unwrap();
        assert_eq!(analysis.len(), 3);

        let other = store.by_category("other", 10).unwrap();
        assert_eq!(other.len(), 2);
    }

    #[test]
    fn test_count() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let conversation_id = ConversationId::new();

        for i in 0..5 {
            let episode = Episode {
                id: EpisodeId::new(),
                conversation_id: conversation_id.clone(),
                timestamp: Utc::now(),
                request_hash: format!("hash_{}", i),
                request_category: "test".to_string(),
                tools_used: vec![],
                active_skills: vec![],
                model_used: "test".to_string(),
                outcome: Outcome::Success,
                feedback: None,
                duration_ms: 100,
                policy_decisions: vec![],
            };
            store.record(&episode).unwrap();
        }

        assert_eq!(store.count().unwrap(), 5);
    }
}
