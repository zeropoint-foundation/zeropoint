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
use thiserror::Error;
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
        // Find the credential
        let encrypted = self
            .credentials
            .get(name)
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
}
