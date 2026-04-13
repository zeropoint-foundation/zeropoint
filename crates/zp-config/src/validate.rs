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

    // ── Posture values ──
    let valid_postures = ["permissive", "balanced", "strict"];
    if !valid_postures.contains(&config.posture.value.as_str()) {
        errors.push(ConfigError::InvalidValue {
            key: "posture".into(),
            reason: format!(
                "'{}' is not valid — must be one of: {}",
                config.posture.value,
                valid_postures.join(", ")
            ),
        });
    }
    if !valid_postures.contains(&config.shell_posture.value.as_str()) {
        errors.push(ConfigError::InvalidValue {
            key: "shell.posture".into(),
            reason: format!(
                "'{}' is not valid — must be one of: {}",
                config.shell_posture.value,
                valid_postures.join(", ")
            ),
        });
    }

    // ── Log level ──
    let valid_levels = ["trace", "debug", "info", "warn", "error"];
    if !valid_levels.contains(&config.log_level.value.as_str()) {
        errors.push(ConfigError::InvalidValue {
            key: "log_level".into(),
            reason: format!(
                "'{}' is not valid — must be one of: {}",
                config.log_level.value,
                valid_levels.join(", ")
            ),
        });
    }

    // ── Mesh consistency ──
    if config.mesh_enabled.value && config.mesh_listen.value.is_none() {
        errors.push(ConfigError::Consistency(
            "mesh.enabled is true but mesh.listen is not set — mesh nodes need a listen address"
                .into(),
        ));
    }

    // ── DLT network ──
    if config.dlt_enabled.value {
        let valid_networks = ["mainnet", "testnet", "previewnet"];
        if !valid_networks.contains(&config.dlt_network.value.as_str()) {
            errors.push(ConfigError::InvalidValue {
                key: "dlt.network".into(),
                reason: format!(
                    "'{}' is not valid — must be one of: {}",
                    config.dlt_network.value,
                    valid_networks.join(", ")
                ),
            });
        }
    }

    // ── Session max age ──
    if config.session_max_age_s.value == 0 {
        errors.push(ConfigError::InvalidValue {
            key: "session.max_age_s".into(),
            reason: "session max age cannot be 0".into(),
        });
    }
    if config.session_max_age_s.value > 604800 {
        // > 7 days
        errors.push(ConfigError::InvalidValue {
            key: "session.max_age_s".into(),
            reason: format!(
                "{}s is over 7 days — long session lifetimes are a security risk",
                config.session_max_age_s.value
            ),
        });
    }

    // ── Rate limit ──
    if config.auth_rate_limit_per_min.value == 0 {
        errors.push(ConfigError::InvalidValue {
            key: "session.auth_rate_limit_per_min".into(),
            reason: "rate limit cannot be 0 — this would block all authentication".into(),
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
