//! Configuration errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    FileNotFound(String),

    #[error("config parse error in {path}: {detail}")]
    ParseError { path: String, detail: String },

    #[error("invalid value for '{key}': {reason}")]
    InvalidValue { key: String, reason: String },

    #[error("consistency error: {0}")]
    Consistency(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
