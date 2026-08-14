//! Regent memory — persistent knowledge across cognitive cycles.
//!
//! The Regent's memory is distinct from the chain. The chain records
//! what happened (immutable, append-only, cryptographically sealed).
//! Memory records what the Regent learned (mutable, searchable, lossy).
//!
//! Memory fragments are the Regent's retained understanding — compressed
//! versions of chain events, operator preferences, learned patterns,
//! and contextual knowledge. They serve the same role as human episodic
//! and semantic memory: not a transcript, but understanding derived
//! from experience.
//!
//! Storage backend: initially file-based (JSON in the ZP data directory).
//! Future: vector-indexed for semantic retrieval.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A unit of persistent memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Unique key for this memory (namespaced, e.g., "operator:preferences:tone").
    pub key: String,

    /// The remembered content.
    pub content: String,

    /// When this was first stored.
    pub created_at: DateTime<Utc>,

    /// When this was last updated.
    pub updated_at: DateTime<Utc>,

    /// How many times this memory has been retrieved (relevance signal).
    pub access_count: u64,

    /// Source chain entry IDs that contributed to this memory, if any.
    pub source_receipts: Vec<String>,

    /// Tags for categorical retrieval.
    pub tags: Vec<String>,
}

/// The Regent's memory store.
///
/// MVP: in-memory HashMap backed by periodic JSON serialization.
/// This is deliberately simple — the memory system's value is in
/// what the Regent chooses to remember, not in the storage engine.
pub struct MemoryStore {
    entries: std::collections::HashMap<String, MemoryEntry>,
    data_path: std::path::PathBuf,
    dirty: bool,
}

impl MemoryStore {
    /// Create a new memory store, loading from disk if available.
    pub fn new(data_dir: &std::path::Path) -> Self {
        let data_path = data_dir.join("regent-memory.json");
        let entries = if data_path.exists() {
            match std::fs::read_to_string(&data_path) {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => std::collections::HashMap::new(),
            }
        } else {
            std::collections::HashMap::new()
        };

        Self {
            entries,
            data_path,
            dirty: false,
        }
    }

    /// Store or update a memory entry.
    pub fn remember(&mut self, key: String, content: String, tags: Vec<String>) {
        let now = Utc::now();
        let entry = self.entries.entry(key.clone()).or_insert_with(|| MemoryEntry {
            key: key.clone(),
            content: String::new(),
            created_at: now,
            updated_at: now,
            access_count: 0,
            source_receipts: Vec::new(),
            tags: Vec::new(),
        });
        entry.content = content;
        entry.updated_at = now;
        entry.tags = tags;
        self.dirty = true;
    }

    /// Retrieve a memory by exact key.
    pub fn recall(&mut self, key: &str) -> Option<&MemoryEntry> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.access_count += 1;
            self.dirty = true;
        }
        self.entries.get(key)
    }

    /// Search memories by tag.
    pub fn search_by_tag(&self, tag: &str) -> Vec<&MemoryEntry> {
        self.entries
            .values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .collect()
    }

    /// Search memories by keyword in content.
    pub fn search_by_keyword(&self, keyword: &str) -> Vec<&MemoryEntry> {
        let kw = keyword.to_lowercase();
        self.entries
            .values()
            .filter(|e| e.content.to_lowercase().contains(&kw) || e.key.to_lowercase().contains(&kw))
            .collect()
    }

    /// Get the N most recently updated memories.
    pub fn recent(&self, limit: usize) -> Vec<&MemoryEntry> {
        let mut entries: Vec<&MemoryEntry> = self.entries.values().collect();
        entries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        entries.truncate(limit);
        entries
    }

    /// Persist to disk if dirty.
    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        if !self.dirty {
            return Ok(());
        }
        if let Some(parent) = self.data_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(std::io::Error::other)?;
        std::fs::write(&self.data_path, json)?;
        self.dirty = false;
        Ok(())
    }

    /// Number of stored memories.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
