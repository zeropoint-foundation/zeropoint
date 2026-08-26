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

    /// W6 (HARNESS-SEAM S5): the key resolves from a layer strictly
    /// higher-precedence than `target_layer`, so writing `target_layer`
    /// would succeed on disk but not change the resolved value. The
    /// `#[error]` text here is a plain-text fallback; `zp-cli` special-
    /// cases this variant to print the full multi-line diagnostic.
    #[error("refusing to write '{key}' to {target_layer}: shadowed by {shadow_layer} (currently: {shadow_value})")]
    Shadowed {
        key: String,
        target_layer: String,
        target_value: String,
        shadow_layer: String,
        shadow_value: String,
    },

    #[error("consistency error: {0}")]
    Consistency(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
