//! Configuration validation — internal consistency checks.
//!
//! Called by `zp config validate` and during server startup.

use crate::error::ConfigError;
use crate::schema::ZpConfig;

/// Validate internal consistency. Returns a list of errors (empty = valid).
pub fn validate(config: &ZpConfig) -> Vec<ConfigError> {
    let mut errors = Vec::new();

    // ── Port range ──
    if config.port.value == 0 {
        errors.push(ConfigError::InvalidValue {
            key: "port".into(),
            reason: "port cannot be 0".into(),
        });
    }

    // ── Data dir writability ──
    if config.data_dir.value.exists()
        && config
            .data_dir
            .value
            .metadata()
            .map(|m| m.permissions().readonly())
            .unwrap_or(false)
    {
        errors.push(ConfigError::InvalidValue {
            key: "data.dir".into(),
            reason: format!(
                "{} exists but is read-only",
                config.data_dir.value.display()
            ),
        });
    }

    errors
}
