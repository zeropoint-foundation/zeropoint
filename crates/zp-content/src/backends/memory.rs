//! In-memory `ContentStore` for tests.

use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use tokio::sync::RwLock;

use crate::{ContentError, ContentFilter, ContentId, ContentMeta, ContentStore};

type Store = BTreeMap<ContentId, (Bytes, ContentMeta)>;

/// In-memory `ContentStore`. Thread-safe; suitable for unit and integration tests.
#[derive(Clone, Default)]
pub struct MemoryBackend {
    inner: Arc<RwLock<Store>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ContentStore for MemoryBackend {
    async fn put(&self, content: &[u8], meta: ContentMeta) -> Result<ContentId, ContentError> {
        let id = ContentId::from_bytes(content);
        let mut store = self.inner.write().await;
        store
            .entry(id.clone())
            .or_insert_with(|| (Bytes::copy_from_slice(content), meta));
        Ok(id)
    }

    async fn get(&self, id: &ContentId) -> Result<Option<Bytes>, ContentError> {
        let store = self.inner.read().await;
        Ok(store.get(id).map(|(b, _)| b.clone()))
    }

    async fn has(&self, id: &ContentId) -> Result<bool, ContentError> {
        let store = self.inner.read().await;
        Ok(store.contains_key(id))
    }

    async fn list(&self, filter: &ContentFilter) -> Result<Vec<ContentId>, ContentError> {
        let limit = if filter.limit == 0 { 100 } else { filter.limit };
        let store = self.inner.read().await;
        let now = Utc::now();
        let ids: Vec<ContentId> = store
            .iter()
            .filter(|(_, (_, m))| {
                if let Some(k) = &filter.kind {
                    if &m.kind != k {
                        return false;
                    }
                }
                if let Some(after) = filter.created_after {
                    if m.created_at <= after {
                        return false;
                    }
                }
                let _ = now;
                true
            })
            .take(limit)
            .map(|(id, _)| id.clone())
            .collect();
        Ok(ids)
    }

    async fn meta(&self, id: &ContentId) -> Result<Option<ContentMeta>, ContentError> {
        let store = self.inner.read().await;
        Ok(store.get(id).map(|(_, m)| m.clone()))
    }
}
