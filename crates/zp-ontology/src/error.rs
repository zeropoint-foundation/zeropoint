//! Ontology error types.

use thiserror::Error;

/// Errors from OntologyStore operations (writer side, Cartographer-only).
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("schema migration failed: version {found} -> {target}: {detail}")]
    Migration {
        found: u32,
        target: u32,
        detail: String,
    },

    #[error("meta key '{0}' missing")]
    MetaMissing(String),

    #[error("meta key '{key}' has invalid value: {detail}")]
    MetaInvalid { key: String, detail: String },
}

/// Errors from OntologyReader operations (read side, many concurrent).
#[derive(Debug, Error)]
pub enum ReadError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("deserialization error: {0}")]
    Deserialization(#[from] serde_json::Error),

    #[error("object not found: {0}")]
    ObjectNotFound(String),
}
