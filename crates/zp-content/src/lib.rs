//! Content-addressed storage for ZeroPoint signed artifacts.
//!
//! The `ContentStore` trait is the singular substrate primitive for storing
//! signed, content-addressed artifacts. Multiple backends (local filesystem,
//! in-memory for tests, Cloudflare R2/D1 via `zp-cloudflare`) implement the
//! same trait; consumers use the trait, not specific backends.
//!
//! ## Key invariants
//!
//! - Identity is BLAKE3(content_bytes). Same bytes → same `ContentId` everywhere.
//! - The store is append-only in spirit: no delete, no update, no rename.
//! - Supersession (artifact A replaced by artifact B) lives in the audit chain,
//!   not in this store.
//! - The store is plaintext-only. Encryption is the vault's concern.

pub mod backends;
pub mod index;

use std::collections::HashMap;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Content-addressed identity: BLAKE3 hash of the stored bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    /// Hash `content` with BLAKE3 and return the resulting `ContentId`.
    pub fn from_bytes(content: &[u8]) -> Self {
        Self(*blake3::hash(content).as_bytes())
    }

    /// Hex-encode the content id (64 lowercase hex characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decode a hex-encoded content id.
    pub fn from_hex(s: &str) -> Result<Self, ContentError> {
        let bytes = hex::decode(s).map_err(|e| ContentError::IdParse(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(ContentError::IdParse(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Metadata stored alongside content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMeta {
    /// Reverse-DNS kind string, e.g. `"artifact.calendar.v1"`.
    pub kind: String,
    /// When the content was first stored.
    pub created_at: DateTime<Utc>,
    /// Size of the stored bytes.
    pub size_bytes: u64,
    /// Caller-defined extensions (e.g. operator pubkey, source receipt ids).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

/// Filter for `ContentStore::list`.
#[derive(Debug, Clone, Default)]
pub struct ContentFilter {
    /// If set, only return content of this kind.
    pub kind: Option<String>,
    /// If set, only return content created after this timestamp.
    pub created_after: Option<DateTime<Utc>>,
    /// Maximum number of results to return. Callers must always set this.
    /// Backends treat `0` as "use backend default" (typically 100).
    pub limit: usize,
}

/// Errors returned by `ContentStore` operations.
#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("backend I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("index error: {0}")]
    Index(String),
    #[error("content id parse error: {0}")]
    IdParse(String),
    #[error("backend error: {0}")]
    Backend(String),
}

/// The singular substrate primitive for content-addressed signed artifact storage.
///
/// Implementors: `LocalFsBackend`, `MemoryBackend` (this crate);
/// `R2Backend`, `D1Backend` (in `zp-cloudflare`).
///
/// No `delete`, `update`, or `encrypt`. See design rationale in
/// `docs/handoffs/storage-abstraction-design-2026-05.md`.
#[async_trait]
pub trait ContentStore: Send + Sync {
    /// Store `content` with the given `meta`; return its content-addressed id.
    ///
    /// Idempotent: storing the same bytes returns the same `ContentId` without
    /// writing twice.
    async fn put(&self, content: &[u8], meta: ContentMeta) -> Result<ContentId, ContentError>;

    /// Fetch content by id. Returns `None` if not present.
    async fn get(&self, id: &ContentId) -> Result<Option<Bytes>, ContentError>;

    /// Return `true` if the content is present without fetching it.
    async fn has(&self, id: &ContentId) -> Result<bool, ContentError>;

    /// List content ids matching `filter`. Always bounded by `filter.limit`.
    async fn list(&self, filter: &ContentFilter) -> Result<Vec<ContentId>, ContentError>;

    /// Return metadata for a content id. Returns `None` if not present.
    async fn meta(&self, id: &ContentId) -> Result<Option<ContentMeta>, ContentError>;
}
