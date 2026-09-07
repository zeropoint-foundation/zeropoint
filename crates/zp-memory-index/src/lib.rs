//! `zp-memory-index` — vector index wrapper for substrate-governed memory retrieval.
//!
//! This crate wraps TurboVec's `IdMapIndex` behind a substrate-shaped
//! interface. The [`MemoryIndex`] trait is the single contract that the
//! `memory:retrieve` gated tool depends on; the concrete [`TurboVecIndex`]
//! implementation is swappable without rewriting any consumer.
//!
//! # Architecture
//!
//! Per the TurboVec integration brief (`docs/design/TURBOVEC-INTEGRATION-2026-06.md`):
//!
//! - **Cache-not-canon**: this index is derived state. The canonical audit
//!   chain is the source of truth; the index is a projection. Any result
//!   returned by [`MemoryIndex::search`] is a *candidate* — it must be
//!   verified against the canonical chain entry before acting on it.
//!
//! - **Gate-mediated access only**: the index is never called directly by
//!   agents. The gate produces an allowlist of authorized memory IDs; the
//!   `memory:retrieve` tool passes that allowlist to [`MemoryIndex::search`].
//!   Unauthorized memory IDs never enter the result space.
//!
//! - **Receipt emission is the caller's responsibility**: this crate emits
//!   no chain receipts. `zp-server` owns receipt emission via `tool_chain::*`
//!   so the audit store dependency stays in one place.

pub mod error;
pub mod index;

pub use error::MemoryIndexError;
pub use index::{IndexConfig, SearchResult, TurboVecIndex};

use std::path::Path;

/// Trait contract for substrate-governed vector memory retrieval.
///
/// Implementations must be `Send + Sync` so the index can live in an
/// `Arc<Mutex<dyn MemoryIndex>>` inside `AppState`.
///
/// # Forbidden
///
/// Implementations must NOT bypass the allowlist. If an allowlist is
/// provided, every returned [`SearchResult::id`] must be a member of it.
/// The `TurboVecIndex` implementation enforces this at the kernel level;
/// alternative implementations must enforce it in output validation too
/// (defense-in-depth per the integration brief).
pub trait MemoryIndex: Send + Sync {
    /// Add a single memory entry.
    ///
    /// `id` is the substrate's canonical memory ID (a `u64` derived from
    /// the chain entry's receipt id). `embedding` length must match the
    /// index dimension once committed; on the first call to a lazy-dim
    /// index the length locks the dimension.
    fn add(&mut self, id: u64, embedding: &[f32]) -> Result<(), MemoryIndexError>;

    /// Add a batch of memory entries.
    ///
    /// `ids.len()` must equal `embeddings.len() / dim`. More efficient than
    /// repeated [`add`](Self::add) calls because TurboVec encodes the batch
    /// in one pass.
    fn add_batch(&mut self, ids: &[u64], embeddings: &[f32]) -> Result<(), MemoryIndexError>;

    /// Search for the top-`k` nearest neighbors of `query`.
    ///
    /// When `allowlist` is `Some`, results are restricted to those IDs at
    /// the SIMD kernel level — no over-fetching. The effective k is
    /// `min(k, allowlist.len())`.
    ///
    /// # Errors
    ///
    /// - [`MemoryIndexError::EmptyAllowlist`] — `allowlist` is `Some(&[])`
    ///   (the gate produced no authorized IDs; almost certainly a caller bug)
    /// - [`MemoryIndexError::DimMismatch`] — `query.len() != self.dim()`
    fn search(
        &self,
        query: &[f32],
        k: usize,
        allowlist: Option<&[u64]>,
    ) -> Result<Vec<SearchResult>, MemoryIndexError>;

    /// Remove a memory entry by ID. Returns `true` if the ID was present.
    fn remove(&mut self, id: u64) -> bool;

    /// Check whether `id` is in the index.
    fn contains(&self, id: u64) -> bool;

    /// Number of vectors currently indexed.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Embedding dimension if committed, `None` on a fresh lazy-dim index.
    fn dim(&self) -> Option<usize>;

    /// TurboQuant bit width (2 or 4).
    fn bit_width(&self) -> u8;

    /// Persist to disk. Path should use the `.tvim` extension.
    fn save(&self, path: &Path) -> Result<(), MemoryIndexError>;
}
