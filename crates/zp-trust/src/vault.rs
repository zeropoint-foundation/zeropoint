//! Credential vault for secure storage and encryption at rest.
//!
//! Stores credentials encrypted using ChaCha20-Poly1305 with a master key derived from the initial key material.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};
use zeroize::Zeroize;

/// Errors that can occur during vault operations.
#[derive(Error, Debug)]
pub enum VaultError {
    /// Encryption of credential data failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption of credential data failed.
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// The requested credential was not found in the vault.
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),

    /// The provided key material is invalid.
    #[error("Invalid key material")]
    InvalidKeyMaterial,

    /// File I/O error during vault persistence.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for vault operations.
pub type VaultResult<T> = Result<T, VaultError>;

/// An encrypted credential stored in the vault.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct EncryptedCredential {
    /// 12-byte nonce for ChaCha20-Poly1305
    pub nonce: [u8; 12],
    /// Encrypted credential data (includes authentication tag)
    pub ciphertext: Vec<u8>,
}

/// Secure credential vault that encrypts credentials at rest.
///
/// Credentials are stored encrypted using ChaCha20-Poly1305 with a master key.
/// All sensitive data is zeroized on drop.
#[derive(Debug)]
pub struct CredentialVault {
    /// Master encryption key (32 bytes for ChaCha20-Poly1305)
    master_key: [u8; 32],
    /// In-memory storage of encrypted credentials
    credentials: HashMap<String, EncryptedCredential>,
}

impl Drop for CredentialVault {
    fn drop(&mut self) {
        self.master_key.zeroize();
        // Encrypted credentials are ciphertext, not sensitive.
        // The master_key is the critical secret to zeroize.
    }
}

impl CredentialVault {
    /// Create a new credential vault with the given master key.
    ///
    /// # Arguments
    /// * `master_key` - A 32-byte master key for ChaCha20-Poly1305 encryption
    ///
    /// # Returns
    /// A new CredentialVault instance
    pub fn new(master_key: &[u8; 32]) -> Self {
        Self {
            master_key: *master_key,
            credentials: HashMap::new(),
        }
    }

    /// Store a credential in the vault with encryption.
    ///
    /// # Arguments
    /// * `name` - The name/identifier for the credential
    /// * `value` - The raw credential data to encrypt and store
    ///
    /// # Returns
    /// Ok(()) on success, or a VaultError if encryption fails
    pub fn store(&mut self, name: &str, value: &[u8]) -> VaultResult<()> {
        // Generate a random nonce for this credential
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Create the cipher with the master key
        let cipher = ChaCha20Poly1305::new_from_slice(&self.master_key)
            .map_err(|_| VaultError::InvalidKeyMaterial)?;

        // Encrypt the credential
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, value)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        // Store the encrypted credential
        let encrypted = EncryptedCredential {
            nonce: nonce_bytes,
            ciphertext,
        };

        self.credentials.insert(name.to_string(), encrypted);
        Ok(())
    }

    /// Retrieve and decrypt a credential from the vault.
    ///
    /// # Arguments
    /// * `name` - The name/identifier of the credential to retrieve
    ///
    /// # Returns
    /// Ok(decrypted_value) on success, or a VaultError if not found or decryption fails
    pub fn retrieve(&self, name: &str) -> VaultResult<Vec<u8>> {
        // Find the credential — try exact match first, then fallback aliases.
        //
        // Onboarding stores refs as "{provider}/{env_var_lowercase}" (e.g. "openai/openai_api_key")
        // while configure patterns use the normalized form "{provider}/{field}" (e.g. "openai/api_key").
        // This fallback bridges the two conventions so credentials resolve either way.
        let encrypted = self
            .credentials
            .get(name)
            .or_else(|| {
                // Fallback: if ref is "provider/field", also try "provider/provider_field"
                if let Some((provider, field)) = name.split_once('/') {
                    let expanded = format!("{}/{}_{}", provider, provider, field);
                    self.credentials.get(&expanded)
                } else {
                    None
                }
            })
            .or_else(|| {
                // Reverse fallback: if ref is "provider/provider_field", try "provider/field"
                if let Some((provider, field)) = name.split_once('/') {
                    let prefix = format!("{}_", provider);
                    if field.starts_with(&prefix) {
                        let stripped = format!("{}/{}", provider, &field[prefix.len()..]);
                        self.credentials.get(&stripped)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .ok_or_else(|| VaultError::CredentialNotFound(name.to_string()))?;

        // Create the cipher with the master key
        let cipher = ChaCha20Poly1305::new_from_slice(&self.master_key)
            .map_err(|_| VaultError::InvalidKeyMaterial)?;

        // Decrypt the credential
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let plaintext = cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }

    /// Remove a credential from the vault.
    ///
    /// # Arguments
    /// * `name` - The name/identifier of the credential to remove
    ///
    /// # Returns
    /// Ok(()) on success, or VaultError::CredentialNotFound if the credential doesn't exist
    pub fn remove(&mut self, name: &str) -> VaultResult<()> {
        self.credentials
            .remove(name)
            .ok_or_else(|| VaultError::CredentialNotFound(name.to_string()))?;
        Ok(())
    }

    /// List all credential names (not their values).
    ///
    /// # Returns
    /// A vector of credential names
    pub fn list(&self) -> Vec<String> {
        self.credentials.keys().cloned().collect()
    }

    /// Get the number of credentials stored in the vault.
    pub fn count(&self) -> usize {
        self.credentials.len()
    }

    // ========================================================================
    // Persistence — save/load encrypted credentials to/from disk
    // ========================================================================

    /// Save the vault's encrypted credentials to a JSON file.
    ///
    /// Only the encrypted ciphertexts and nonces are written — the master key
    /// never touches disk. The file is safe to store in version control
    /// (credentials are ChaCha20-Poly1305 encrypted), though this is not
    /// recommended for production deployments.
    pub fn save(&self, path: &Path) -> VaultResult<()> {
        let json = serde_json::to_string_pretty(&self.credentials)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        // Write atomically: write to .tmp, then rename
        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json.as_bytes())?;
        std::fs::rename(&tmp_path, path)?;

        info!(
            path = %path.display(),
            count = self.credentials.len(),
            "Vault saved to disk"
        );
        Ok(())
    }

    /// Load encrypted credentials from a JSON file into this vault.
    ///
    /// Existing credentials in memory are replaced. The master key remains
    /// unchanged — it must match the key used when the credentials were
    /// originally stored, or subsequent `retrieve()` calls will fail with
    /// `DecryptionFailed`.
    pub fn load(&mut self, path: &Path) -> VaultResult<()> {
        let json = std::fs::read_to_string(path)?;
        let credentials: HashMap<String, EncryptedCredential> = serde_json::from_str(&json)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        info!(
            path = %path.display(),
            count = credentials.len(),
            "Vault loaded from disk"
        );

        self.credentials = credentials;
        Ok(())
    }

    /// Create a vault and load existing credentials if the file exists.
    ///
    /// This is the primary constructor for production use:
    /// - If `path` exists, loads encrypted credentials from it.
    /// - If `path` does not exist, starts with an empty vault.
    ///
    /// In either case, the master key is used for all subsequent
    /// encrypt/decrypt operations.
    pub fn load_or_create(master_key: &[u8; 32], path: &Path) -> VaultResult<Self> {
        let mut vault = Self::new(master_key);

        if path.exists() {
            vault.load(path)?;
            debug!(
                path = %path.display(),
                count = vault.credentials.len(),
                "Loaded existing vault"
            );
        } else {
            debug!(
                path = %path.display(),
                "No existing vault file — starting fresh"
            );
        }

        Ok(vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_store_and_retrieve() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        let credential_name = "test-db-password";
        let credential_value = b"super-secret-password";

        // Store the credential
        assert!(vault.store(credential_name, credential_value).is_ok());

        // Retrieve the credential
        let retrieved = vault.retrieve(credential_name).unwrap();
        assert_eq!(retrieved, credential_value);
    }

    #[test]
    fn test_vault_list() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("cred1", b"value1").unwrap();
        vault.store("cred2", b"value2").unwrap();
        vault.store("cred3", b"value3").unwrap();

        let list = vault.list();
        assert_eq!(list.len(), 3);
        assert!(list.contains(&"cred1".to_string()));
        assert!(list.contains(&"cred2".to_string()));
        assert!(list.contains(&"cred3".to_string()));
    }

    #[test]
    fn test_vault_remove() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("test-cred", b"test-value").unwrap();
        assert_eq!(vault.count(), 1);

        assert!(vault.remove("test-cred").is_ok());
        assert_eq!(vault.count(), 0);

        // Trying to remove a non-existent credential should fail
        let result = vault.remove("non-existent");
        assert!(result.is_err());
    }

    #[test]
    fn test_vault_not_found() {
        let master_key = [0x42u8; 32];
        let vault = CredentialVault::new(&master_key);

        let result = vault.retrieve("non-existent");
        assert!(matches!(result, Err(VaultError::CredentialNotFound(_))));
    }

    #[test]
    fn test_vault_encryption_isolation() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("secret1", b"value1").unwrap();
        vault.store("secret2", b"value2").unwrap();

        // Verify each credential is encrypted separately
        let list = vault.list();
        assert_eq!(list.len(), 2);

        // Each encrypted credential should have different nonces
        let cred1 = vault.credentials.get("secret1").unwrap();
        let cred2 = vault.credentials.get("secret2").unwrap();
        assert_ne!(cred1.nonce, cred2.nonce);
    }

    // ========================================================================
    // Persistence tests
    // ========================================================================

    #[test]
    fn test_vault_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("zp-vault-test-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault.json");

        // Clean up from previous runs
        let _ = std::fs::remove_file(&vault_path);

        let master_key = [0xABu8; 32];

        // Store credentials and save to disk
        {
            let mut vault = CredentialVault::new(&master_key);
            vault.store("anthropic/api_key", b"sk-ant-test-key-123").unwrap();
            vault.store("openai/api_key", b"sk-openai-test-456").unwrap();
            vault.store("postgres/password", b"hunter2").unwrap();
            vault.save(&vault_path).unwrap();
        }

        // Load into a fresh vault and verify decryption
        {
            let mut vault = CredentialVault::new(&master_key);
            vault.load(&vault_path).unwrap();

            assert_eq!(vault.count(), 3);
            assert_eq!(vault.retrieve("anthropic/api_key").unwrap(), b"sk-ant-test-key-123");
            assert_eq!(vault.retrieve("openai/api_key").unwrap(), b"sk-openai-test-456");
            assert_eq!(vault.retrieve("postgres/password").unwrap(), b"hunter2");
        }

        // Cleanup
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_vault_load_or_create_new() {
        let dir = std::env::temp_dir().join("zp-vault-test-loadcreate");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-new.json");

        // Ensure file doesn't exist
        let _ = std::fs::remove_file(&vault_path);

        let master_key = [0xCDu8; 32];
        let vault = CredentialVault::load_or_create(&master_key, &vault_path).unwrap();

        // Should start empty
        assert_eq!(vault.count(), 0);

        // Cleanup
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_vault_load_or_create_existing() {
        let dir = std::env::temp_dir().join("zp-vault-test-existing");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-existing.json");

        let master_key = [0xEFu8; 32];

        // Create and persist a vault
        {
            let mut vault = CredentialVault::new(&master_key);
            vault.store("tavily/api_key", b"tvly-test-789").unwrap();
            vault.save(&vault_path).unwrap();
        }

        // load_or_create should pick up the existing file
        let vault = CredentialVault::load_or_create(&master_key, &vault_path).unwrap();
        assert_eq!(vault.count(), 1);
        assert_eq!(vault.retrieve("tavily/api_key").unwrap(), b"tvly-test-789");

        // Cleanup
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_vault_wrong_key_fails_decrypt() {
        let dir = std::env::temp_dir().join("zp-vault-test-wrongkey");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-wrongkey.json");

        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        // Store with key A
        {
            let mut vault = CredentialVault::new(&key_a);
            vault.store("secret/token", b"classified").unwrap();
            vault.save(&vault_path).unwrap();
        }

        // Load with key B — load succeeds (it's just JSON) but decrypt must fail
        {
            let vault = CredentialVault::load_or_create(&key_b, &vault_path).unwrap();
            assert_eq!(vault.count(), 1); // ciphertext is there
            let result = vault.retrieve("secret/token");
            assert!(matches!(result, Err(VaultError::DecryptionFailed(_))));
        }

        // Cleanup
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_vault_atomic_save_no_partial() {
        let dir = std::env::temp_dir().join("zp-vault-test-atomic");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-atomic.json");
        let tmp_path = vault_path.with_extension("json.tmp");

        let master_key = [0x33u8; 32];

        let mut vault = CredentialVault::new(&master_key);
        vault.store("test/cred", b"atomicity-check").unwrap();
        vault.save(&vault_path).unwrap();

        // After a successful save, the .tmp file should NOT exist
        assert!(!tmp_path.exists(), "Temporary file should be cleaned up after save");
        assert!(vault_path.exists(), "Final vault file should exist");

        // Cleanup
        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }
}
