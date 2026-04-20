//! Vault convenience layer over `zp_trust::CredentialVault`.
//!
//! Provides common operations: open vault, store credential, bulk import.
//! Used by both server and CLI to avoid duplicating vault access patterns.

use std::path::PathBuf;

/// Default vault file path: `~/ZeroPoint/vault.json`
pub fn default_vault_path() -> PathBuf {
    zp_core::paths::vault_path().unwrap_or_else(|_| {
        PathBuf::from(".").join("vault.json")
    })
}

/// Result of a bulk vault import operation.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// Number of credentials successfully stored
    pub stored: usize,
    /// Number of credentials that failed to store
    pub failed: usize,
    /// Details per credential
    pub details: Vec<ImportDetail>,
}

/// Detail for one credential in a bulk import.
#[derive(Debug, Clone)]
pub struct ImportDetail {
    pub vault_ref: String,
    pub success: bool,
    pub error: Option<String>,
}

/// Bulk-import credentials into the vault.
///
/// Each credential is a (vault_ref, value) pair.
/// Returns import results with per-credential detail.
pub fn bulk_import(
    vault: &mut zp_trust::CredentialVault,
    vault_path: &std::path::Path,
    credentials: &[(&str, &str)],
) -> ImportResult {
    let mut result = ImportResult {
        stored: 0,
        failed: 0,
        details: Vec::new(),
    };

    for (vault_ref, value) in credentials {
        match vault.store(vault_ref, value.as_bytes()) {
            Ok(_) => {
                result.stored += 1;
                result.details.push(ImportDetail {
                    vault_ref: vault_ref.to_string(),
                    success: true,
                    error: None,
                });
            }
            Err(e) => {
                result.failed += 1;
                result.details.push(ImportDetail {
                    vault_ref: vault_ref.to_string(),
                    success: false,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // Persist to disk
    if result.stored > 0 {
        if let Err(e) = vault.save(vault_path) {
            tracing::error!("Failed to save vault after bulk import: {}", e);
        }
    }

    result
}
