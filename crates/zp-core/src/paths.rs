//! Centralized path resolution for ZeroPoint.
//!
//! All ZeroPoint data lives under `~/ZeroPoint/` — visible, obvious,
//! no hidden dotfiles, no platform-specific conventions. One tree,
//! one place to back up, one place to audit.
//!
//! The `ZP_HOME` environment variable overrides the default location
//! for development, testing, and non-standard deployments.
//!
//! # Directory layout
//!
//! ```text
//! ~/ZeroPoint/
//! ├── keys/               # Cryptographic identity (genesis, operator)
//! ├── vault.json          # Encrypted credential vault
//! ├── data/
//! │   ├── audit.db        # Receipt/audit chain
//! │   ├── attestations.db # Attestation store
//! │   └── observations.db # Cognition pipeline
//! ├── policies/           # WASM policy modules
//! ├── config.toml         # Operator configuration
//! ├── guard-receipts/     # Guard execution receipts
//! ├── session.json        # Runtime session token (ephemeral)
//! └── assets/             # Dashboard override assets
//! ```
//!
//! # No legacy support
//!
//! ZeroPoint v3 uses `~/ZeroPoint/` exclusively. There is no
//! backward-compatibility layer for `~/.zeropoint`.

use std::path::PathBuf;

/// Error resolving ZeroPoint paths.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("Cannot determine home directory: HOME environment variable not set")]
    NoHome,
}

/// Return the ZeroPoint home directory.
///
/// Resolution order:
/// 1. `ZP_HOME` environment variable (highest priority)
/// 2. `~/ZeroPoint/` (the canonical location)
///
/// This is the single source of truth for all path construction
/// in the ZeroPoint codebase.
pub fn home() -> Result<PathBuf, PathError> {
    // 1. Explicit override
    if let Ok(zp_home) = std::env::var("ZP_HOME") {
        return Ok(PathBuf::from(zp_home));
    }

    // 2. ~/ZeroPoint/
    let user_home = std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| PathError::NoHome)?;

    Ok(user_home.join("ZeroPoint"))
}

/// Keys directory — cryptographic identity material.
/// `~/ZeroPoint/keys/`
pub fn keys_dir() -> Result<PathBuf, PathError> {
    Ok(home()?.join("keys"))
}

/// Data directory — audit chain, attestations, observations.
/// `~/ZeroPoint/data/`
pub fn data_dir() -> Result<PathBuf, PathError> {
    // ZP_DATA_DIR override for the data subdirectory specifically
    if let Ok(d) = std::env::var("ZP_DATA_DIR") {
        return Ok(PathBuf::from(d));
    }
    Ok(home()?.join("data"))
}

/// Vault file — encrypted credential store.
/// `~/ZeroPoint/vault.json`
pub fn vault_path() -> Result<PathBuf, PathError> {
    Ok(home()?.join("vault.json"))
}

/// Session file — ephemeral runtime auth token.
/// `~/ZeroPoint/session.json`
pub fn session_path() -> Result<PathBuf, PathError> {
    Ok(home()?.join("session.json"))
}

/// Policies directory — WASM modules, policy rules.
/// `~/ZeroPoint/policies/`
pub fn policies_dir() -> Result<PathBuf, PathError> {
    Ok(home()?.join("policies"))
}

/// Config file path.
/// `~/ZeroPoint/config.toml`
pub fn config_path() -> Result<PathBuf, PathError> {
    Ok(home()?.join("config.toml"))
}

/// Guard receipts directory.
/// `~/ZeroPoint/guard-receipts/`
pub fn guard_receipts_dir() -> Result<PathBuf, PathError> {
    Ok(home()?.join("guard-receipts"))
}

/// Assets override directory (dashboard customizations).
/// `~/ZeroPoint/assets/`
pub fn assets_dir() -> Result<PathBuf, PathError> {
    Ok(home()?.join("assets"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zp_home_override() {
        // ZP_HOME takes precedence
        std::env::set_var("ZP_HOME", "/tmp/zp-test-home");
        let h = home().unwrap();
        assert_eq!(h, PathBuf::from("/tmp/zp-test-home"));
        std::env::remove_var("ZP_HOME");
    }

    #[test]
    fn test_default_home_is_under_user_home() {
        std::env::remove_var("ZP_HOME");
        let h = home().unwrap();
        assert!(h.ends_with("ZeroPoint"));
    }

    #[test]
    fn test_subdirectories() {
        std::env::set_var("ZP_HOME", "/tmp/zp-paths-test");
        assert_eq!(keys_dir().unwrap(), PathBuf::from("/tmp/zp-paths-test/keys"));
        assert_eq!(data_dir().unwrap(), PathBuf::from("/tmp/zp-paths-test/data"));
        assert_eq!(vault_path().unwrap(), PathBuf::from("/tmp/zp-paths-test/vault.json"));
        assert_eq!(session_path().unwrap(), PathBuf::from("/tmp/zp-paths-test/session.json"));
        assert_eq!(policies_dir().unwrap(), PathBuf::from("/tmp/zp-paths-test/policies"));
        std::env::remove_var("ZP_HOME");
    }

    #[test]
    fn test_data_dir_override() {
        std::env::set_var("ZP_HOME", "/tmp/zp-paths-test");
        std::env::set_var("ZP_DATA_DIR", "/custom/data");
        assert_eq!(data_dir().unwrap(), PathBuf::from("/custom/data"));
        std::env::remove_var("ZP_DATA_DIR");
        std::env::remove_var("ZP_HOME");
    }
}
