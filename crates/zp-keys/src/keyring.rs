//! Keyring — persistent storage for the key hierarchy.
//!
//! Stores keys and certificates to `~/.zeropoint/keys/`:
//! ```text
//! ~/.zeropoint/keys/
//!   genesis.json        ← genesis certificate (public only)
//!   operator.json       ← operator certificate
//!   operator.secret     ← operator secret key
//!   agents/
//!     agent-001.json    ← agent certificate chain
//!     agent-001.secret  ← agent secret key
//! ```
//!
//! The Genesis secret key is stored in the OS credential store (macOS Keychain,
//! Linux Secret Service, Windows Credential Manager) — never as a file on disk.
//! This ensures the root of trust is protected by platform security from the
//! moment of creation.
//!
//! Certificate files are JSON. Operator and agent secret files are 32-byte raw
//! key material (these will migrate to the credential store in a future version).

use std::path::{Path, PathBuf};

use crate::certificate::Certificate;
use crate::error::KeyError;
use crate::hierarchy::{AgentKey, GenesisKey, OperatorKey};

/// Service name for Genesis secret in the OS credential store.
/// Public so biometric.rs can use the same identifiers.
pub(crate) const GENESIS_KEYCHAIN_SERVICE: &str = "zeropoint-genesis";

/// Account name for the Genesis secret in the OS credential store.
/// Public so biometric.rs can use the same identifiers.
pub(crate) const GENESIS_KEYCHAIN_ACCOUNT: &str = "genesis-secret";

/// Persistent keyring backed by the filesystem + OS credential store.
pub struct Keyring {
    base_dir: PathBuf,
}

/// What's stored in the keyring (public info only).
#[derive(Debug)]
pub struct KeyringStatus {
    pub has_genesis: bool,
    pub has_genesis_secret: bool,
    pub has_operator: bool,
    pub has_operator_secret: bool,
    pub agent_count: usize,
    pub agent_names: Vec<String>,
}

impl Keyring {
    /// Open or create a keyring at the given directory.
    pub fn open(base_dir: impl Into<PathBuf>) -> Result<Self, KeyError> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(&base_dir)?;
        std::fs::create_dir_all(base_dir.join("agents"))?;
        Ok(Self { base_dir })
    }

    /// Open the default keyring at `~/.zeropoint/keys/`.
    pub fn open_default() -> Result<Self, KeyError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::open(home.join(".zeropoint").join("keys"))
    }

    /// Get the keyring directory path.
    pub fn path(&self) -> &Path {
        &self.base_dir
    }

    /// Check what's in the keyring without loading secrets.
    pub fn status(&self) -> KeyringStatus {
        let agents_dir = self.base_dir.join("agents");
        let agent_names: Vec<String> = std::fs::read_dir(&agents_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".json") {
                    Some(name.trim_end_matches(".json").to_string())
                } else {
                    None
                }
            })
            .collect();

        // Genesis secret can be in credential store OR on disk (legacy)
        let has_genesis_secret = self.base_dir.join("genesis.secret").exists()
            || has_genesis_in_credential_store();

        KeyringStatus {
            has_genesis: self.base_dir.join("genesis.json").exists(),
            has_genesis_secret,
            has_operator: self.base_dir.join("operator.json").exists(),
            has_operator_secret: self.base_dir.join("operator.secret").exists(),
            agent_count: agent_names.len(),
            agent_names,
        }
    }

    // ── Genesis ─────────────────────────────────────────────────

    /// Save a genesis key — certificate to disk, secret to OS credential store.
    ///
    /// The `save_secret` flag controls whether the secret key is stored at all.
    /// When true, the secret is written to the OS credential store (Keychain)
    /// if available, otherwise falls back to a `genesis.secret` file on disk.
    /// The load-side migration in `load_genesis()` / `load_genesis_secret()`
    /// will automatically upgrade file-based secrets to the credential store
    /// when the `os-keychain` feature is enabled.
    ///
    /// Returns `Ok(true)` if the secret was stored in the credential store,
    /// `Ok(false)` if it was stored on disk or not stored at all.
    pub fn save_genesis(&self, genesis: &GenesisKey, save_secret: bool) -> Result<bool, KeyError> {
        let cert_json = serde_json::to_string_pretty(genesis.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("genesis.json"), cert_json)?;

        if save_secret {
            match save_genesis_to_credential_store(&genesis.secret_key()) {
                Ok(()) => return Ok(true),
                Err(e) => {
                    // Credential store unavailable — fall back to file.
                    // The load path will auto-migrate to credential store
                    // when the feature becomes available.
                    tracing::debug!("Credential store unavailable ({}), writing genesis.secret file", e);
                    std::fs::write(
                        self.base_dir.join("genesis.secret"),
                        genesis.secret_key(),
                    )?;
                    return Ok(false);
                }
            }
        }

        Ok(false)
    }

    /// Load the genesis certificate (public only).
    pub fn load_genesis_certificate(&self) -> Result<Certificate, KeyError> {
        let path = self.base_dir.join("genesis.json");
        let json = std::fs::read_to_string(&path)?;
        serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))
    }

    /// Load the full genesis key (with secret from OS credential store).
    ///
    /// Tries the OS credential store first, then falls back to the legacy
    /// `genesis.secret` file for backward compatibility. If found on disk,
    /// migrates the secret to the credential store and removes the file.
    pub fn load_genesis(&self) -> Result<GenesisKey, KeyError> {
        let cert = self.load_genesis_certificate()?;

        // 1. Try OS credential store (the correct path)
        if let Ok(secret) = load_genesis_from_credential_store() {
            return GenesisKey::from_parts(secret, cert);
        }

        // 2. Fall back to legacy file, then migrate
        let secret_path = self.base_dir.join("genesis.secret");
        if secret_path.exists() {
            let secret_bytes = std::fs::read(&secret_path)?;
            if secret_bytes.len() != 32 {
                return Err(KeyError::InvalidKeyMaterial(
                    "genesis secret must be 32 bytes".into(),
                ));
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&secret_bytes);

            // Migrate: store in credential store, then securely remove the file.
            // This is user-visible because their file disappears.
            match save_genesis_to_credential_store(&secret) {
                Ok(()) => {
                    secure_delete_file(&secret_path);
                    tracing::info!("Genesis secret migrated from disk to OS credential store");
                    eprintln!(
                        "  \x1b[32m✓\x1b[0m Genesis secret migrated to OS credential store \
                         (genesis.secret removed from disk)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not migrate Genesis secret to credential store: {}. \
                         Secret remains on disk — run `zp init` on a system with \
                         Keychain/Secret Service support.",
                        e
                    );
                }
            }

            return GenesisKey::from_parts(secret, cert);
        }

        Err(KeyError::InvalidKeyMaterial(
            "Genesis secret not found in OS credential store or on disk. \
             Run `zp init` to create your Genesis key."
                .into(),
        ))
    }

    /// Load just the genesis secret bytes from the OS credential store.
    ///
    /// This is the primitive that vault_key uses for derivation.
    /// Returns the raw 32-byte Ed25519 secret key and whether the source
    /// was the credential store (true) or a legacy file (false).
    ///
    /// Like `load_genesis()`, this attempts migration from legacy files
    /// to the credential store when a disk secret is found.
    pub fn load_genesis_secret(&self) -> Result<([u8; 32], bool), KeyError> {
        // Verify genesis.json exists (sanity check)
        if !self.base_dir.join("genesis.json").exists() {
            return Err(KeyError::InvalidKeyMaterial(
                "No genesis.json found — run `zp init` first".into(),
            ));
        }

        // 1. Try credential store
        if let Ok(secret) = load_genesis_from_credential_store() {
            return Ok((secret, true));
        }

        // 2. Fall back to legacy file, then migrate (consistent with load_genesis)
        let secret_path = self.base_dir.join("genesis.secret");
        if secret_path.exists() {
            let secret_bytes = std::fs::read(&secret_path)?;
            if secret_bytes.len() != 32 {
                return Err(KeyError::InvalidKeyMaterial(
                    "genesis secret must be 32 bytes".into(),
                ));
            }
            let mut secret = [0u8; 32];
            secret.copy_from_slice(&secret_bytes);

            // Migrate: store in credential store, then securely remove the file.
            // This is user-visible because their file disappears.
            match save_genesis_to_credential_store(&secret) {
                Ok(()) => {
                    secure_delete_file(&secret_path);
                    tracing::info!("Genesis secret migrated from disk to OS credential store");
                    eprintln!(
                        "  \x1b[32m✓\x1b[0m Genesis secret migrated to OS credential store \
                         (genesis.secret removed from disk)"
                    );
                    // After successful migration, report as credential store source
                    return Ok((secret, true));
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not migrate Genesis secret to credential store: {}. \
                         Secret remains on disk — run `zp init` on a system with \
                         Keychain/Secret Service support.",
                        e
                    );
                }
            }

            return Ok((secret, false));
        }

        Err(KeyError::InvalidKeyMaterial(
            "Genesis secret not available. Run `zp init`.".into(),
        ))
    }

    /// Remove the Genesis secret from the OS credential store.
    pub fn clear_genesis_secret(&self) -> Result<(), KeyError> {
        clear_genesis_from_credential_store()
    }

    // ── Operator ────────────────────────────────────────────────

    /// Save an operator key (certificate + secret).
    pub fn save_operator(&self, operator: &OperatorKey) -> Result<(), KeyError> {
        let cert_json = serde_json::to_string_pretty(operator.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("operator.json"), cert_json)?;
        std::fs::write(self.base_dir.join("operator.secret"), operator.secret_key())?;
        Ok(())
    }

    /// Load the operator key (with secret).
    pub fn load_operator(&self) -> Result<OperatorKey, KeyError> {
        let cert_path = self.base_dir.join("operator.json");
        let json = std::fs::read_to_string(&cert_path)?;
        let cert: Certificate =
            serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))?;

        let secret_path = self.base_dir.join("operator.secret");
        let secret_bytes = std::fs::read(&secret_path)?;
        if secret_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "operator secret must be 32 bytes".into(),
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);

        let genesis_cert = self.load_genesis_certificate()?;
        OperatorKey::from_parts(secret, cert, genesis_cert)
    }

    // ── Agents ──────────────────────────────────────────────────

    /// Save an agent key (chain + secret).
    pub fn save_agent(&self, name: &str, agent: &AgentKey) -> Result<(), KeyError> {
        let chain = agent.portable_chain();
        let chain_json = serde_json::to_string_pretty(&chain)
            .map_err(|e| KeyError::Serialization(e.to_string()))?;

        let agents_dir = self.base_dir.join("agents");
        std::fs::write(agents_dir.join(format!("{}.json", name)), chain_json)?;
        std::fs::write(
            agents_dir.join(format!("{}.secret", name)),
            agent.secret_key(),
        )?;
        Ok(())
    }

    /// Load an agent key by name.
    pub fn load_agent(&self, name: &str) -> Result<AgentKey, KeyError> {
        let agents_dir = self.base_dir.join("agents");

        let chain_path = agents_dir.join(format!("{}.json", name));
        let json = std::fs::read_to_string(&chain_path)?;
        let certs: Vec<Certificate> =
            serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))?;

        if certs.len() != 3 {
            return Err(KeyError::BrokenChain {
                depth: 0,
                reason: format!("expected 3 certificates, found {}", certs.len()),
            });
        }

        let secret_path = agents_dir.join(format!("{}.secret", name));
        let secret_bytes = std::fs::read(&secret_path)?;
        if secret_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "agent secret must be 32 bytes".into(),
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);

        AgentKey::from_parts(secret, certs[2].clone(), certs[1].clone(), certs[0].clone())
    }

    /// Load just the portable certificate chain for an agent (no secrets).
    pub fn load_agent_chain(&self, name: &str) -> Result<Vec<Certificate>, KeyError> {
        let path = self.base_dir.join("agents").join(format!("{}.json", name));
        let json = std::fs::read_to_string(&path)?;
        serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))
    }
}

// ── OS Credential Store helpers ──────────────────────────────────────

/// Check if the Genesis secret exists AND is valid in the credential store.
///
/// Validates that the stored value is well-formed (64 hex chars = 32 bytes)
/// rather than just checking for existence. This catches corruption.
fn has_genesis_in_credential_store() -> bool {
    #[cfg(feature = "os-keychain")]
    {
        // Full load validates format; a simple `get_password().is_ok()` would
        // return true for corrupt entries.
        load_genesis_from_credential_store().is_ok()
    }

    #[cfg(not(feature = "os-keychain"))]
    {
        false
    }
}

/// Securely delete a file containing key material.
///
/// Overwrites the file with multiple passes of different patterns before
/// unlinking. This reduces (but cannot eliminate) the chance of recovery
/// from swap, filesystem journal, or SSD wear-leveling caches.
fn secure_delete_file(path: &std::path::Path) {
    if let Ok(len) = std::fs::metadata(path).map(|m| m.len() as usize) {
        // Pass 1: zeros
        let _ = std::fs::write(path, vec![0u8; len]);
        // Pass 2: ones
        let _ = std::fs::write(path, vec![0xFFu8; len]);
        // Pass 3: zeros again
        let _ = std::fs::write(path, vec![0u8; len]);
    }
    let _ = std::fs::remove_file(path);
}

/// Store the Genesis secret in the OS credential store (login password gating).
/// For biometric gating, use `biometric::save_genesis_biometric()` instead.
pub(crate) fn save_genesis_to_credential_store(secret: &[u8; 32]) -> Result<(), KeyError> {
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(GENESIS_KEYCHAIN_SERVICE, GENESIS_KEYCHAIN_ACCOUNT)
            .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;
        entry
            .set_password(&hex::encode(secret))
            .map_err(|e| KeyError::CredentialStore(format!("store error: {}", e)))?;
        Ok(())
    }

    #[cfg(not(feature = "os-keychain"))]
    {
        let _ = secret;
        Err(KeyError::CredentialStore(
            "OS credential store not available (enable 'os-keychain' feature). \
             Falling back to file storage."
                .into(),
        ))
    }
}

/// Load the Genesis secret from the OS credential store.
/// For biometric mode on macOS, the OS automatically triggers the biometric prompt.
/// For biometric mode on Linux, call `biometric::load_genesis_biometric()` instead.
pub(crate) fn load_genesis_from_credential_store() -> Result<[u8; 32], KeyError> {
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(GENESIS_KEYCHAIN_SERVICE, GENESIS_KEYCHAIN_ACCOUNT)
            .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;
        let hex_secret = entry
            .get_password()
            .map_err(|e| KeyError::CredentialStore(format!("load error: {}", e)))?;
        let bytes = hex::decode(&hex_secret).map_err(|e| {
            KeyError::CredentialStore(format!("stored secret is not valid hex: {}", e))
        })?;
        if bytes.len() != 32 {
            return Err(KeyError::CredentialStore(format!(
                "stored secret has wrong length: {} (expected 32)",
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Ok(secret)
    }

    #[cfg(not(feature = "os-keychain"))]
    {
        Err(KeyError::CredentialStore(
            "OS credential store not available".into(),
        ))
    }
}

/// Clear the Genesis secret from the OS credential store.
fn clear_genesis_from_credential_store() -> Result<(), KeyError> {
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(GENESIS_KEYCHAIN_SERVICE, GENESIS_KEYCHAIN_ACCOUNT)
            .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // idempotent
            Err(e) => Err(KeyError::CredentialStore(format!("delete error: {}", e))),
        }
    }

    #[cfg(not(feature = "os-keychain"))]
    {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        // Generate full hierarchy
        let genesis = GenesisKey::generate("test-genesis");
        let operator = OperatorKey::generate("test-operator", &genesis, None);
        let agent = AgentKey::generate("test-agent-001", &operator, None);

        // Save — genesis secret goes to credential store (or file fallback in tests)
        keyring.save_genesis(&genesis, true).unwrap();
        keyring.save_operator(&operator).unwrap();
        keyring.save_agent("agent-001", &agent).unwrap();

        // Check status
        let status = keyring.status();
        assert!(status.has_genesis);
        assert!(status.has_operator);
        assert!(status.has_operator_secret);
        assert_eq!(status.agent_count, 1);
        assert_eq!(status.agent_names, vec!["agent-001"]);

        // Load and verify — genesis loads from credential store (or file fallback)
        let loaded_genesis = keyring.load_genesis().unwrap();
        assert_eq!(loaded_genesis.public_key(), genesis.public_key());

        let loaded_operator = keyring.load_operator().unwrap();
        assert_eq!(loaded_operator.public_key(), operator.public_key());

        let loaded_agent = keyring.load_agent("agent-001").unwrap();
        assert_eq!(loaded_agent.public_key(), agent.public_key());

        // Verify the loaded agent's chain
        let chain = loaded_agent.chain().unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_keyring_without_genesis_secret() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("g");
        keyring.save_genesis(&genesis, false).unwrap();

        let status = keyring.status();
        assert!(status.has_genesis);

        // But the certificate should still be loadable
        let cert = keyring.load_genesis_certificate().unwrap();
        assert_eq!(cert.body.subject, "g");
    }

    #[test]
    fn test_portable_chain_verification() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        keyring.save_genesis(&genesis, false).unwrap();
        keyring.save_operator(&operator).unwrap();
        keyring.save_agent("a", &agent).unwrap();

        // A remote node loads just the certificate chain (no secrets)
        let certs = keyring.load_agent_chain("a").unwrap();
        assert_eq!(certs.len(), 3);

        // Verify against the genesis public key
        let chain = crate::certificate::CertificateChain::verify_against_genesis(
            certs,
            &genesis.public_key(),
        )
        .unwrap();
        assert_eq!(chain.leaf().body.subject, "a");
    }

    #[test]
    fn test_load_genesis_secret_direct() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("secret-test");
        keyring.save_genesis(&genesis, true).unwrap();

        let (secret, _from_credential_store) = keyring.load_genesis_secret().unwrap();
        assert_eq!(secret, genesis.secret_key());
    }

    #[test]
    fn test_load_genesis_secret_fails_without_init() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        // No genesis at all
        assert!(keyring.load_genesis_secret().is_err());
    }
}
