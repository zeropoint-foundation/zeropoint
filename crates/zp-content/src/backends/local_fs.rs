//! Local filesystem backend for `ContentStore`.
//!
//! Content is stored in a two-level sharded layout under `$ZP_CONTENT_DIR`
//! (default: `~/ZeroPoint/content/`):
//!
//! ```text
//! content/
//!   aa/
//!     bb/
//!       aabb<remaining 60 hex chars>
//! ```
//!
//! Metadata is kept in a `LocalIndex` SQLite at `$ZP_CONTENT_INDEX`
//! (default: `~/ZeroPoint/content-index.db`).

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::{ContentError, ContentFilter, ContentId, ContentMeta, ContentStore, index::LocalIndex};

/// Filesystem-backed `ContentStore` with two-level hash-prefix sharding.
pub struct LocalFsBackend {
    root: PathBuf,
    index: LocalIndex,
}

impl LocalFsBackend {
    /// Create a new backend rooted at `content_dir`.
    ///
    /// `index_path` is the path to the SQLite index file.
    /// Both paths are created if they don't exist.
    pub async fn new(content_dir: &Path, index_path: &Path) -> Result<Self, ContentError> {
        tokio::fs::create_dir_all(content_dir).await?;
        if let Some(parent) = index_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let index = LocalIndex::open(index_path)?;
        Ok(Self {
            root: content_dir.to_owned(),
            index,
        })
    }

    /// Derive the shard path for a content id.
    ///
    /// `aa/bb/aabb<60 remaining hex chars>`
    fn shard_path(&self, id: &ContentId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join(&hex[..2]).join(&hex[2..4]).join(&hex)
    }

    /// Rebuild the index from existing content on disk. Called once on startup
    /// when the index is empty but the content dir is not.
    async fn maybe_rebuild_index(&self) -> Result<(), ContentError> {
        let root = self.root.clone();
        if !root.exists() {
            return Ok(());
        }
        // Walk two directory levels deep
        let mut level1 = match tokio::fs::read_dir(&root).await {
            Ok(d) => d,
            Err(_) => return Ok(()),
        };
        while let Ok(Some(e1)) = level1.next_entry().await {
            if !e1.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let mut level2 = match tokio::fs::read_dir(e1.path()).await {
                Ok(d) => d,
                Err(_) => continue,
            };
            while let Ok(Some(e2)) = level2.next_entry().await {
                if !e2.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let mut files = match tokio::fs::read_dir(e2.path()).await {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                while let Ok(Some(file)) = files.next_entry().await {
                    let name = file.file_name().to_string_lossy().to_string();
                    if name.len() != 64 {
                        continue;
                    }
                    let id = match ContentId::from_hex(&name) {
                        Ok(id) => id,
                        Err(_) => continue,
                    };
                    if self.index.contains(&id)? {
                        continue;
                    }
                    let size = file.metadata().await.map(|m| m.len()).unwrap_or(0);
                    let meta = ContentMeta {
                        kind: "unknown".to_string(),
                        created_at: Utc::now(),
                        size_bytes: size,
                        extensions: None,
                    };
                    self.index.insert(&id, &meta)?;
                    debug!("index rebuilt entry: {}", id);
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl ContentStore for LocalFsBackend {
    async fn put(&self, content: &[u8], meta: ContentMeta) -> Result<ContentId, ContentError> {
        let id = ContentId::from_bytes(content);
        let path = self.shard_path(&id);

        if !path.exists() {
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::write(&path, content).await?;
            debug!("content stored: {}", id);
        }

        self.index.insert(&id, &meta)?;
        Ok(id)
    }

    async fn get(&self, id: &ContentId) -> Result<Option<Bytes>, ContentError> {
        let path = self.shard_path(id);
        if !path.exists() {
            return Ok(None);
        }
        let mut file = tokio::fs::File::open(&path).await?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).await?;
        Ok(Some(Bytes::from(buf)))
    }

    async fn has(&self, id: &ContentId) -> Result<bool, ContentError> {
        Ok(self.shard_path(id).exists())
    }

    async fn list(&self, filter: &ContentFilter) -> Result<Vec<ContentId>, ContentError> {
        self.index.list(filter)
    }

    async fn meta(&self, id: &ContentId) -> Result<Option<ContentMeta>, ContentError> {
        self.index.get_meta(id)
    }
}

/// Convenience constructor that reads paths from environment variables with
/// sensible defaults under `~/ZeroPoint/`.
pub async fn default_local_fs_backend() -> Result<LocalFsBackend, ContentError> {
    let home = dirs_from_env();
    let content_dir = std::env::var("ZP_CONTENT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join("content"));
    let index_path = std::env::var("ZP_CONTENT_INDEX")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join("content-index.db"));
    let backend = LocalFsBackend::new(&content_dir, &index_path).await?;
    backend.maybe_rebuild_index().await?;
    Ok(backend)
}

fn dirs_from_env() -> PathBuf {
    std::env::var("ZP_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/ZeroPoint"))
}
