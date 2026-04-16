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
///
/// In test builds (`#[cfg(test)]`), these resolve to a test-scoped suffix
/// so `cargo test` never wipes the production keychain entry.
#[allow(dead_code)]
pub(crate) const GENESIS_KEYCHAIN_SERVICE: &str = if cfg!(test) {
    "zeropoint-genesis-test"
} else {
    "zeropoint-genesis"
};

/// Account name for the Genesis secret in the OS credential store.
/// Public so biometric.rs can use the same identifiers.
#[allow(dead_code)]
pub(crate) const GENESIS_KEYCHAIN_ACCOUNT: &str = if cfg!(test) {
    "genesis-secret-test"
} else {
    "genesis-secret"
};

/// Service name for the Operator secret in the OS credential store.
#[allow(dead_code)]
const OPERATOR_KEYCHAIN_SERVICE: &str = if cfg!(test) {
    "zeropoint-operator-test"
} else {
    "zeropoint-operator"
};

/// Account name for the Operator secret in the OS credential store.
#[allow(dead_code)]
const OPERATOR_KEYCHAIN_ACCOUNT: &str = if cfg!(test) {
    "operator-secret-test"
} else {
    "operator-secret"
};

/// Version byte for the on-disk encrypted operator secret blob.
/// Format: [0x01][12-byte nonce][ChaCha20-Poly1305 ciphertext+tag].
const OPERATOR_BLOB_VERSION: u8 = 0x01;

/// Set restrictive permissions on a directory (owner-only).
#[cfg(unix)]
fn chmod_700(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}
#[cfg(not(unix))]
fn chmod_700(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Set restrictive permissions on a secret file (owner read/write only).
#[cfg(unix)]
fn chmod_600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn chmod_600(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Write a file and immediately chmod 600. Fails loudly if either step fails.
fn write_secret_file(path: &Path, data: &[u8]) -> Result<(), KeyError> {
    std::fs::write(path, data)?;
    chmod_600(path)?;
    Ok(())
}

/// Encrypt an operator-class secret under a vault key derived from Genesis.
/// Output: [version || 12-byte random nonce || ciphertext+tag].
fn encrypt_with_vault_key(secret: &[u8; 32], vault_key: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
    use rand::RngCore;

    let cipher = ChaCha20Poly1305::new(vault_key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, secret.as_ref())
        .map_err(|e| KeyError::CredentialStore(format!("operator encrypt failed: {}", e)))?;

    let mut blob = Vec::with_capacity(1 + 12 + ciphertext.len());
    blob.push(OPERATOR_BLOB_VERSION);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

/// Decrypt an operator-class secret blob produced by `encrypt_with_vault_key`.
fn decrypt_with_vault_key(blob: &[u8], vault_key: &[u8; 32]) -> Result<[u8; 32], KeyError> {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};

    if blob.len() < 1 + 12 + 16 {
        return Err(KeyError::InvalidKeyMaterial(
            "operator blob too short".into(),
        ));
    }
    if blob[0] != OPERATOR_BLOB_VERSION {
        return Err(KeyError::InvalidKeyMaterial(format!(
            "unknown operator blob version: 0x{:02x}",
            blob[0]
        )));
    }
    let nonce_bytes: [u8; 12] = blob[1..13].try_into().unwrap();
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = &blob[13..];
    let cipher = ChaCha20Poly1305::new(vault_key.into());
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|_| KeyError::CredentialStore("operator decrypt failed".into()))?;
    if plaintext.len() != 32 {
        return Err(KeyError::InvalidKeyMaterial(format!(
            "decrypted operator secret has wrong length: {}",
            plaintext.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(out)
}

/// BLAKE3-keyed vault key derivation (inlined to avoid circular dep with vault_key.rs).
fn derive_vault_key_local(genesis_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(b"zp-credential-vault-v1");
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

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
        // Lock down directory perms so other local accounts can't even list
        // the keyring. Also tighten the parent (~/.zeropoint) so audit.db
        // and sibling state aren't cross-user readable (CROSS-USER-01).
        let _ = chmod_700(&base_dir);
        let _ = chmod_700(&base_dir.join("agents"));
        if let Some(parent) = base_dir.parent() {
            let _ = chmod_700(parent);
        }
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

        // Canon: Genesis lives in the OS credential store, full stop.
        let has_genesis_secret = has_genesis_in_credential_store();

        KeyringStatus {
            has_genesis: self.base_dir.join("genesis.json").exists(),
            has_genesis_secret,
            has_operator: self.base_dir.join("operator.json").exists(),
            // Canon: credential store preferred; encrypted-at-rest fallback
            // only when the caller explicitly opted into a file mode.
            has_operator_secret: has_operator_in_credential_store()
                || self.base_dir.join("operator.secret.enc").exists(),
            agent_count: agent_names.len(),
            agent_names,
        }
    }

    // ── Genesis ─────────────────────────────────────────────────

    /// Save a genesis key — certificate to disk, secret to OS credential store.
    ///
    /// The `save_secret` flag controls whether the secret key is stored at all.
    /// When true, the secret MUST go into the OS credential store. There is
    /// no file fallback. If the credential store is unavailable, this returns
    /// an error and the caller must surface it to the user. Writing a root
    /// key to disk silently is exactly the failure mode that produced
    /// SECRETS-FS-01 and is forbidden in canon.
    ///
    /// Returns `Ok(true)` if the secret was stored, `Ok(false)` if the caller
    /// requested cert-only (`save_secret = false`).
    pub fn save_genesis(&self, genesis: &GenesisKey, save_secret: bool) -> Result<bool, KeyError> {
        let cert_json = serde_json::to_string_pretty(genesis.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("genesis.json"), cert_json)?;

        if save_secret {
            save_genesis_to_credential_store(&genesis.secret_key()).map_err(|e| {
                KeyError::CredentialStore(format!(
                    "Refusing to store Genesis secret: OS credential store unavailable ({}). \
                     ZeroPoint does not write root keys to disk. Enable Keychain/Secret Service \
                     and re-run `zp init`.",
                    e
                ))
            })?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Load the genesis certificate (public only).
    pub fn load_genesis_certificate(&self) -> Result<Certificate, KeyError> {
        let path = self.base_dir.join("genesis.json");
        let json = std::fs::read_to_string(&path)?;
        serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))
    }

    /// Load the full genesis key (secret from OS credential store).
    ///
    /// Canon: the Genesis secret lives in the OS credential store only.
    /// There is no disk fallback and no migration path — that was the bug.
    pub fn load_genesis(&self) -> Result<GenesisKey, KeyError> {
        let cert = self.load_genesis_certificate()?;
        let secret = load_genesis_from_credential_store().map_err(|e| {
            KeyError::InvalidKeyMaterial(format!(
                "Genesis secret not in OS credential store ({}). \
                 Run `zp recover` with your 24-word mnemonic, or `zp init` to start fresh.",
                e
            ))
        })?;
        GenesisKey::from_parts(secret, cert)
    }

    /// Load just the genesis secret bytes from the OS credential store.
    ///
    /// This is the primitive that `vault_key` and operator-secret encryption
    /// use for derivation. The `bool` in the return is retained for API
    /// compatibility with `vault_key::resolve_vault_key`; in canon it is
    /// always `true` because the credential store is the only supported
    /// source.
    pub fn load_genesis_secret(&self) -> Result<([u8; 32], bool), KeyError> {
        if !self.base_dir.join("genesis.json").exists() {
            return Err(KeyError::InvalidKeyMaterial(
                "No genesis.json found — run `zp init` first".into(),
            ));
        }
        let secret = load_genesis_from_credential_store().map_err(|e| {
            KeyError::InvalidKeyMaterial(format!(
                "Genesis secret not in OS credential store ({}). Run `zp init`.",
                e
            ))
        })?;
        Ok((secret, true))
    }

    /// Remove the Genesis secret from the OS credential store.
    pub fn clear_genesis_secret(&self) -> Result<(), KeyError> {
        clear_genesis_from_credential_store()
    }

    // ── Operator ────────────────────────────────────────────────

    /// Save an operator key (certificate + secret) with the Genesis secret
    /// supplied by the caller.
    ///
    /// This is the canonical save path. Every sovereignty mode (Keychain,
    /// Touch ID, Windows Hello, Linux biometrics, Trezor, FileBased) has a
    /// point during `zp init` / onboarding where the Genesis secret is
    /// briefly in memory after being unwrapped by its provider. Pass it here
    /// so the operator secret can be vaulted without this keyring having to
    /// know which provider owns the root.
    ///
    /// This writes strictly to `operator.secret.enc` (ChaCha20-Poly1305 under
    /// `BLAKE3-keyed(genesis_secret, "zp-credential-vault-v1")`). It never
    /// touches the OS credential store — if the caller has explicit custody
    /// of the Genesis secret, they own the encrypted-at-rest path. Callers
    /// that want the credential-store path should call
    /// [`Keyring::save_operator`] instead. A plaintext `operator.secret` is
    /// never written.
    pub fn save_operator_with_genesis_secret(
        &self,
        operator: &OperatorKey,
        genesis_secret: &[u8; 32],
    ) -> Result<(), KeyError> {
        let cert_json = serde_json::to_string_pretty(operator.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("operator.json"), cert_json)?;

        let secret = operator.secret_key();
        let vault_key = derive_vault_key_local(genesis_secret);
        let blob = encrypt_with_vault_key(&secret, &vault_key)?;
        write_secret_file(&self.base_dir.join("operator.secret.enc"), &blob)?;
        Ok(())
    }

    /// Save an operator key via the OS credential store path.
    ///
    /// Storage order:
    /// 1. OS credential store (`zeropoint-operator`) when available.
    /// 2. `operator.secret.enc` — ChaCha20-Poly1305 under a vault key
    ///    derived from the Genesis secret pulled from the credential store.
    ///
    /// This is the convenience wrapper for the Keychain / Touch ID /
    /// Windows Hello / Secret Service path. Other sovereignty modes (Trezor,
    /// Linux biometrics, FileBased) that own the Genesis secret themselves
    /// should call [`Keyring::save_operator_with_genesis_secret`] directly.
    pub fn save_operator(&self, operator: &OperatorKey) -> Result<(), KeyError> {
        let cert_json = serde_json::to_string_pretty(operator.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("operator.json"), cert_json)?;

        let secret = operator.secret_key();

        // 1. Credential store fast path.
        if save_operator_to_credential_store(&secret).is_ok() {
            let enc = self.base_dir.join("operator.secret.enc");
            if enc.exists() {
                let _ = std::fs::remove_file(&enc);
            }
            return Ok(());
        }

        // 2. Encrypted-at-rest fallback — needs the Genesis secret from
        //    the credential store (only reachable if Genesis is there).
        let (genesis_secret, _) = self.load_genesis_secret()?;
        let vault_key = derive_vault_key_local(&genesis_secret);
        let blob = encrypt_with_vault_key(&secret, &vault_key)?;
        write_secret_file(&self.base_dir.join("operator.secret.enc"), &blob)?;
        Ok(())
    }

    /// Load the operator key with the Genesis secret supplied by the caller.
    ///
    /// Strictly disk-only: decrypts `operator.secret.enc` with a vault key
    /// derived from the caller-supplied Genesis secret. Does not consult the
    /// OS credential store. Use [`Keyring::load_operator`] if you want the
    /// credential-store path.
    pub fn load_operator_with_genesis_secret(
        &self,
        genesis_secret: &[u8; 32],
    ) -> Result<OperatorKey, KeyError> {
        let cert_path = self.base_dir.join("operator.json");
        let json = std::fs::read_to_string(&cert_path)?;
        let cert: Certificate =
            serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))?;
        let genesis_cert = self.load_genesis_certificate()?;

        let enc_path = self.base_dir.join("operator.secret.enc");
        if !enc_path.exists() {
            return Err(KeyError::InvalidKeyMaterial(
                "No encrypted operator blob on disk (operator.secret.enc). \
                 Run `zp init`."
                    .into(),
            ));
        }
        let blob = std::fs::read(&enc_path)?;
        let vault_key = derive_vault_key_local(genesis_secret);
        let secret = decrypt_with_vault_key(&blob, &vault_key)?;
        OperatorKey::from_parts(secret, cert, genesis_cert)
    }

    /// Load the operator key via the OS credential store path.
    ///
    /// Resolution order:
    /// 1. OS credential store (`zeropoint-operator`).
    /// 2. `operator.secret.enc`, using a vault key derived from the Genesis
    ///    secret pulled from the credential store.
    ///
    /// Convenience wrapper for the Keychain / Touch ID / Windows Hello /
    /// Secret Service path.
    pub fn load_operator(&self) -> Result<OperatorKey, KeyError> {
        let cert_path = self.base_dir.join("operator.json");
        let json = std::fs::read_to_string(&cert_path)?;
        let cert: Certificate =
            serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))?;
        let genesis_cert = self.load_genesis_certificate()?;

        if let Ok(secret) = load_operator_from_credential_store() {
            return OperatorKey::from_parts(secret, cert, genesis_cert);
        }

        let (genesis_secret, _) = self.load_genesis_secret()?;
        let enc_path = self.base_dir.join("operator.secret.enc");
        if !enc_path.exists() {
            return Err(KeyError::InvalidKeyMaterial(
                "Operator secret not found in credential store or encrypted-at-rest file. \
                 Run `zp init`."
                    .into(),
            ));
        }
        let blob = std::fs::read(&enc_path)?;
        let vault_key = derive_vault_key_local(&genesis_secret);
        let secret = decrypt_with_vault_key(&blob, &vault_key)?;
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

/// Check if the Operator secret exists and is well-formed in the credential store.
fn has_operator_in_credential_store() -> bool {
    #[cfg(feature = "os-keychain")]
    {
        load_operator_from_credential_store().is_ok()
    }
    #[cfg(not(feature = "os-keychain"))]
    {
        false
    }
}

/// Store the Operator secret in the OS credential store.
fn save_operator_to_credential_store(secret: &[u8; 32]) -> Result<(), KeyError> {
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(OPERATOR_KEYCHAIN_SERVICE, OPERATOR_KEYCHAIN_ACCOUNT)
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
            "OS credential store not available (enable 'os-keychain' feature)".into(),
        ))
    }
}

/// Load the Operator secret from the OS credential store.
fn load_operator_from_credential_store() -> Result<[u8; 32], KeyError> {
    #[cfg(feature = "os-keychain")]
    {
        let entry = keyring::Entry::new(OPERATOR_KEYCHAIN_SERVICE, OPERATOR_KEYCHAIN_ACCOUNT)
            .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;
        let hex_secret = entry
            .get_password()
            .map_err(|e| KeyError::CredentialStore(format!("load error: {}", e)))?;
        let bytes = hex::decode(&hex_secret).map_err(|e| {
            KeyError::CredentialStore(format!("stored operator secret is not valid hex: {}", e))
        })?;
        if bytes.len() != 32 {
            return Err(KeyError::CredentialStore(format!(
                "stored operator secret has wrong length: {} (expected 32)",
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
    fn test_keyring_roundtrip_encrypted_at_rest() {
        // Exercises the canon fallback path that every non-Keychain
        // sovereignty provider (Trezor, Linux biometrics, FileBased) uses:
        // caller supplies the Genesis secret, operator is encrypted at rest
        // under a vault key derived from it.
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("test-genesis");
        let operator = OperatorKey::generate("test-operator", &genesis, None);
        let agent = AgentKey::generate("test-agent-001", &operator, None);

        keyring.save_genesis(&genesis, false).unwrap();
        keyring
            .save_operator_with_genesis_secret(&operator, &genesis.secret_key())
            .unwrap();
        keyring.save_agent("agent-001", &agent).unwrap();

        assert!(keyring.base_dir.join("operator.secret.enc").exists());
        assert!(!keyring.base_dir.join("operator.secret").exists());

        let loaded_operator = keyring
            .load_operator_with_genesis_secret(&genesis.secret_key())
            .unwrap();
        assert_eq!(loaded_operator.public_key(), operator.public_key());
        assert_eq!(loaded_operator.secret_key(), operator.secret_key());

        let loaded_agent = keyring.load_agent("agent-001").unwrap();
        assert_eq!(loaded_agent.public_key(), agent.public_key());
        assert_eq!(loaded_agent.chain().unwrap().len(), 3);
    }

    #[test]
    fn test_operator_encrypted_blob_wrong_vault_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis_a = GenesisKey::generate("a");
        let genesis_b = GenesisKey::generate("b");
        let operator = OperatorKey::generate("op", &genesis_a, None);

        keyring.save_genesis(&genesis_a, false).unwrap();
        keyring
            .save_operator_with_genesis_secret(&operator, &genesis_a.secret_key())
            .unwrap();

        // Decrypting with the wrong Genesis must fail authentication.
        let wrong = keyring.load_operator_with_genesis_secret(&genesis_b.secret_key());
        assert!(wrong.is_err(), "wrong vault key must not decrypt operator");
    }

    #[cfg(feature = "os-keychain")]
    #[test]
    fn test_keyring_roundtrip_credential_store() {
        // Only meaningful with a real credential store backend.
        // Serialized with other Keychain-touching tests because the macOS
        // credential store uses process-global `zeropoint-genesis` /
        // `zeropoint-operator` entries that parallel tests would clobber.
        let _serial = crate::test_sync::serial_guard();
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        let genesis = GenesisKey::generate("test-cs-genesis");
        let operator = OperatorKey::generate("test-cs-op", &genesis, None);
        keyring.save_genesis(&genesis, true).unwrap();
        keyring.save_operator(&operator).unwrap();
        let loaded = keyring.load_operator().unwrap();
        assert_eq!(loaded.public_key(), operator.public_key());
        let _ = keyring.clear_genesis_secret();
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
        keyring
            .save_operator_with_genesis_secret(&operator, &genesis.secret_key())
            .unwrap();
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

    #[cfg(feature = "os-keychain")]
    #[test]
    fn test_load_genesis_secret_direct() {
        let _serial = crate::test_sync::serial_guard();
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("secret-test");
        keyring.save_genesis(&genesis, true).unwrap();

        let (secret, from_credential_store) = keyring.load_genesis_secret().unwrap();
        assert_eq!(secret, genesis.secret_key());
        assert!(
            from_credential_store,
            "canon: genesis secret must come from credential store"
        );
        let _ = keyring.clear_genesis_secret();
    }

    #[test]
    fn test_load_genesis_secret_fails_without_init() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        // No genesis at all
        assert!(keyring.load_genesis_secret().is_err());
    }
}
