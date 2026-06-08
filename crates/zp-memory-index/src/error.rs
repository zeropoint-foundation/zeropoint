use thiserror::Error;

#[derive(Error, Debug)]
pub enum MemoryIndexError {
    #[error("empty allowlist: gate produced no authorized IDs for this query")]
    EmptyAllowlist,

    #[error("dimension mismatch: query has {query} dims, index expects {index}")]
    DimMismatch { query: usize, index: usize },

    #[error("id {0} already exists in the index")]
    DuplicateId(u64),

    #[error("index not yet committed: add at least one vector before searching")]
    NotCommitted,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("turbovec error: {0}")]
    TurboVec(String),

    /// A search result fell outside the allowlist — indicates a bug in the
    /// index implementation or a corrupt allowlist. Surfaced as an error
    /// rather than silently dropped so the caller can log and alert.
    #[error(
        "allowlist violation: result id {id} was not in the allowlist \
         (implementation bug — this must never happen in production)"
    )]
    AllowlistViolation { id: u64 },
}
