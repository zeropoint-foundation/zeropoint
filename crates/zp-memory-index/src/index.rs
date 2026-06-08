//! Concrete `TurboVecIndex` — wraps `turbovec::IdMapIndex` behind `MemoryIndex`.

use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use turbovec::IdMapIndex;

use crate::{MemoryIndex, MemoryIndexError};

/// Configuration for constructing a [`TurboVecIndex`].
///
/// Serializable so it can be persisted alongside the `.tvim` file and used to
/// reconstruct or validate the index on load.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    /// Embedding dimension. 0 = lazy (inferred from first add).
    pub dim: usize,
    /// TurboQuant compression bit width. Must be 2 or 4.
    pub bit_width: usize,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self { dim: 0, bit_width: 4 }
    }
}

/// A single search result returned by [`MemoryIndex::search`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Canonical memory ID supplied at index time.
    pub id: u64,
    /// Approximate inner-product score from TurboQuant. Higher = more similar.
    pub score: f32,
}

/// Substrate-shaped wrapper around `turbovec::IdMapIndex`.
///
/// Uses `IdMapIndex` (not `TurboQuantIndex`) because memory IDs must survive
/// deletes — the gate's allowlist contains canonical memory IDs, not positional
/// slot indices, so stable external ID mapping is required.
pub struct TurboVecIndex {
    inner: IdMapIndex,
    config: IndexConfig,
}

impl TurboVecIndex {
    /// Create a new index with the given config.
    ///
    /// When `config.dim == 0`, uses `IdMapIndex::new_lazy` — the dimension
    /// is locked on the first `add`/`add_batch` call.
    pub fn new(config: &IndexConfig) -> Result<Self, MemoryIndexError> {
        if config.bit_width != 2 && config.bit_width != 4 {
            return Err(MemoryIndexError::TurboVec(format!(
                "bit_width must be 2 or 4, got {}",
                config.bit_width
            )));
        }
        let inner = if config.dim == 0 {
            IdMapIndex::new_lazy(config.bit_width)
                .map_err(|e| MemoryIndexError::TurboVec(e.to_string()))?
        } else {
            IdMapIndex::new(config.dim, config.bit_width)
                .map_err(|e| MemoryIndexError::TurboVec(e.to_string()))?
        };
        Ok(Self { inner, config: config.clone() })
    }

    /// Load an existing `.tvim` index from disk.
    pub fn load(path: &Path, config: &IndexConfig) -> Result<Self, MemoryIndexError> {
        let inner = IdMapIndex::load(path)?;
        Ok(Self { inner, config: config.clone() })
    }

    /// The config used at construction time.
    pub fn config(&self) -> &IndexConfig {
        &self.config
    }

    /// Compute a stable `u64` memory ID from a chain receipt id string.
    ///
    /// Takes the first 8 bytes of the blake3 hash — deterministic and
    /// collision-resistant for the corpus sizes ZeroPoint targets.
    pub fn id_from_receipt(receipt_id: &str) -> u64 {
        let hash = blake3::hash(receipt_id.as_bytes());
        let bytes = hash.as_bytes();
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    }
}

impl MemoryIndex for TurboVecIndex {
    fn add(&mut self, id: u64, embedding: &[f32]) -> Result<(), MemoryIndexError> {
        // Use add_with_ids_2d so this works on both lazy-dim and committed
        // indices. For a committed index, dim must match the locked dimension.
        let dim = embedding.len();
        self.inner
            .add_with_ids_2d(embedding, dim, &[id])
            .map_err(|e| MemoryIndexError::TurboVec(e.to_string()))
    }

    fn add_batch(&mut self, ids: &[u64], embeddings: &[f32]) -> Result<(), MemoryIndexError> {
        if ids.is_empty() {
            return Ok(());
        }
        let dim = embeddings.len() / ids.len();
        self.inner
            .add_with_ids_2d(embeddings, dim, ids)
            .map_err(|e| MemoryIndexError::TurboVec(e.to_string()))
    }

    fn search(
        &self,
        query: &[f32],
        k: usize,
        allowlist: Option<&[u64]>,
    ) -> Result<Vec<SearchResult>, MemoryIndexError> {
        if let Some(al) = allowlist {
            if al.is_empty() {
                return Err(MemoryIndexError::EmptyAllowlist);
            }
        }

        // `search_with_allowlist` handles both the filtered and unfiltered
        // cases. Returns (scores, ids) directly — not a Result.
        let (scores, ids) = self.inner.search_with_allowlist(query, k, allowlist);

        // Defense-in-depth: verify no result escaped the allowlist.
        // TurboVec enforces this at the kernel level; we enforce it again at
        // the output boundary per the integration brief's defense-in-depth req.
        if let Some(al) = allowlist {
            let allowed: HashSet<u64> = al.iter().copied().collect();
            for &id in &ids {
                if !allowed.contains(&id) {
                    return Err(MemoryIndexError::AllowlistViolation { id });
                }
            }
        }

        Ok(scores
            .into_iter()
            .zip(ids)
            .map(|(score, id)| SearchResult { id, score })
            .collect())
    }

    fn remove(&mut self, id: u64) -> bool {
        self.inner.remove(id)
    }

    fn contains(&self, id: u64) -> bool {
        self.inner.contains(id)
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn dim(&self) -> Option<usize> {
        self.inner.dim_opt()
    }

    fn bit_width(&self) -> u8 {
        self.inner.bit_width() as u8
    }

    fn save(&self, path: &Path) -> Result<(), MemoryIndexError> {
        self.inner.write(path).map_err(MemoryIndexError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // TurboVec requires dim to be a positive multiple of 8.
    const DIM: usize = 8;

    fn zero_vec() -> Vec<f32> {
        vec![0.0f32; DIM]
    }

    fn ones_vec() -> Vec<f32> {
        vec![1.0f32; DIM]
    }

    #[test]
    fn add_and_search_basic() {
        let config = IndexConfig { dim: DIM, bit_width: 4 };
        let mut idx = TurboVecIndex::new(&config).unwrap();

        idx.add(1001, &ones_vec()).unwrap();
        idx.add(1002, &zero_vec()).unwrap();

        assert_eq!(idx.len(), 2);
        assert_eq!(idx.dim(), Some(DIM));
        assert!(idx.contains(1001));
        assert!(idx.contains(1002));
        assert!(!idx.contains(9999));

        let results = idx.search(&ones_vec(), 2, None).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn allowlist_filters_results() {
        let config = IndexConfig { dim: DIM, bit_width: 4 };
        let mut idx = TurboVecIndex::new(&config).unwrap();

        idx.add(1001, &ones_vec()).unwrap();
        idx.add(1002, &ones_vec()).unwrap();
        idx.add(1003, &ones_vec()).unwrap();

        // Only 1001 is in the allowlist.
        let results = idx.search(&ones_vec(), 10, Some(&[1001])).unwrap();
        assert!(results.iter().all(|r| r.id == 1001));
    }

    #[test]
    fn empty_allowlist_errors() {
        let config = IndexConfig { dim: DIM, bit_width: 4 };
        let mut idx = TurboVecIndex::new(&config).unwrap();
        idx.add(1001, &ones_vec()).unwrap();

        let err = idx.search(&ones_vec(), 5, Some(&[])).unwrap_err();
        assert!(matches!(err, MemoryIndexError::EmptyAllowlist));
    }

    #[test]
    fn remove_and_contains() {
        let config = IndexConfig { dim: DIM, bit_width: 4 };
        let mut idx = TurboVecIndex::new(&config).unwrap();

        idx.add(42, &ones_vec()).unwrap();
        assert!(idx.contains(42));
        assert!(idx.remove(42));
        assert!(!idx.contains(42));
        assert!(!idx.remove(42)); // already removed
    }

    #[test]
    fn save_and_load_roundtrip() {
        let config = IndexConfig { dim: DIM, bit_width: 4 };
        let mut idx = TurboVecIndex::new(&config).unwrap();
        idx.add(100, &ones_vec()).unwrap();
        idx.add(200, &zero_vec()).unwrap();

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.tvim");
        idx.save(&path).unwrap();

        let loaded = TurboVecIndex::load(&path, &config).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(100));
        assert!(loaded.contains(200));
    }

    #[test]
    fn id_from_receipt_is_deterministic() {
        let a = TurboVecIndex::id_from_receipt("rcpt-abc123");
        let b = TurboVecIndex::id_from_receipt("rcpt-abc123");
        let c = TurboVecIndex::id_from_receipt("rcpt-xyz999");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn lazy_dim_locks_on_first_add() {
        let config = IndexConfig { dim: 0, bit_width: 4 };
        let mut idx = TurboVecIndex::new(&config).unwrap();
        assert_eq!(idx.dim(), None);

        idx.add(1, &ones_vec()).unwrap();
        assert_eq!(idx.dim(), Some(DIM));
    }
}
