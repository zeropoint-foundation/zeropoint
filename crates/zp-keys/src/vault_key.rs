//! Vault key derivation — derives the CredentialVault master key from the Genesis secret.
//!
//! The vault key is a 32-byte symmetric key used for ChaCha20-Poly1305 encryption
//! of stored credentials. It is derived deterministically from the Genesis secret
//! key using BLAKE3 keyed hashing, so the same Genesis key always produces the
//! same vault key.
//!
//! # Architecture
//!
//! The Genesis secret lives in the OS credential store (macOS Keychain, Linux
//! Secret Service) — never as a file on disk. The vault key is derived on-demand
//! in memory and zeroized after use. There is no separate "vault key cache."
//!
//! ```text
//! OS Credential Store (Keychain)
//!     │
//!     └── Genesis secret (32 bytes, hex-encoded)
//!             │
//!             ▼
//!         BLAKE3-keyed(genesis_secret, "zp-credential-vault-v1")
//!             │
//!             ▼
//!         Vault master key (32 bytes, Zeroizing, ephemeral)
//!             │
//!             ▼
//!         ChaCha20-Poly1305 → encrypted credentials
//! ```
//!
//! # Derivation
//!
//! ```text
//! vault_key = BLAKE3-keyed(genesis_secret, context="zp-credential-vault-v1")
//! ```
//!
//! The context string is versioned so we can rotate derivation if needed.

use crate::error::KeyError;
use crate::keyring::Keyring;
use zeroize::Zeroizing;

/// Context string for vault key derivation. Versioned for future rotation.
const VAULT_KEY_CONTEXT: &[u8] = b"zp-credential-vault-v1";

/// Indicates how the vault key was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultKeySource {
    /// Derived from Genesis secret in OS credential store.
    CredentialStore,
    /// Derived from Genesis secret found on disk (legacy, migrated).
    LegacyFileMigrated,
    /// Read from SECRETS_MASTER_KEY environment variable (deprecated).
    LegacyEnvVar,
}

/// The result of resolving a vault key: the key material + how it was obtained.
pub struct ResolvedVaultKey {
    /// The 32-byte vault master key (zeroized on drop).
    pub key: Zeroizing<[u8; 32]>,
    /// How the key was resolved — for audit trail and caller awareness.
    pub source: VaultKeySource,
}

/// Derive the vault master key from a Genesis secret key.
///
/// This is a pure, deterministic function: same genesis secret → same vault key.
/// Uses BLAKE3 keyed hashing with a domain-separation context.
///
/// The returned key is wrapped in `Zeroizing` for automatic cleanup.
pub fn derive_vault_key(genesis_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_keyed(genesis_secret);
    hasher.update(VAULT_KEY_CONTEXT);
    let hash = hasher.finalize();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Minimum length for raw-string SECRETS_MASTER_KEY values.
/// Anything shorter than 16 bytes is rejected as too weak.
const MIN_ENV_KEY_LENGTH: usize = 16;

/// Resolve the vault master key from the keyring.
///
/// Reads the Genesis secret from the OS credential store (or legacy file),
/// derives the vault key via BLAKE3, and returns it with source metadata.
///
/// Source attribution is determined at **runtime** by `load_genesis_secret()`,
/// which reports whether the secret came from the credential store or a legacy
/// file on disk. This is more accurate than the compile-time `cfg!` check.
///
/// Priority:
/// 1. Genesis secret from OS credential store (Keychain) → derive vault key
/// 2. Genesis secret from legacy file → derive vault key, migrate to credential store
/// 3. `SECRETS_MASTER_KEY` env var → deprecated fallback (hex only, ≥16 bytes)
/// 4. Error — no silent degradation
pub fn resolve_vault_key(keyring: &Keyring) -> Result<ResolvedVaultKey, KeyError> {
    // 1. Try loading Genesis secret from keyring (credential store → file fallback)
    match keyring.load_genesis_secret() {
        Ok((secret, from_credential_store)) => {
            let key = derive_vault_key(&secret);
            // Runtime source tracking — the keyring tells us where it actually came from
            let source = if from_credential_store {
                VaultKeySource::CredentialStore
            } else {
                VaultKeySource::LegacyFileMigrated
            };
            return Ok(ResolvedVaultKey { key, source });
        }
        Err(e) => {
            tracing::debug!("Could not load Genesis secret from keyring: {}", e);
        }
    }

    // 2. Legacy fallback: SECRETS_MASTER_KEY env var (deprecated)
    //    Only accepts 64 hex chars (= 32 bytes). Raw string padding is removed
    //    because it silently produces weak keys from short inputs.
    if let Ok(env_key) = std::env::var("SECRETS_MASTER_KEY") {
        tracing::warn!("Using SECRETS_MASTER_KEY env var — deprecated, run `zp init`");
        eprintln!("Warning: SECRETS_MASTER_KEY is deprecated. Run `zp init` instead.");
        match hex::decode(&env_key) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&bytes);
                return Ok(ResolvedVaultKey {
                    key,
                    source: VaultKeySource::LegacyEnvVar,
                });
            }
            Ok(bytes) => {
                return Err(KeyError::InvalidKeyMaterial(format!(
                    "SECRETS_MASTER_KEY must be 64 hex chars (32 bytes), got {} bytes. \
                     Run `zp init` for proper key generation.",
                    bytes.len()
                )));
            }
            Err(_) => {
                // Not valid hex — accept raw bytes only if long enough
                let raw = env_key.as_bytes();
                if raw.len() < MIN_ENV_KEY_LENGTH {
                    return Err(KeyError::InvalidKeyMaterial(format!(
                        "SECRETS_MASTER_KEY is too short ({} bytes, minimum {}). \
                         Use a 64-char hex string or run `zp init`.",
                        raw.len(),
                        MIN_ENV_KEY_LENGTH,
                    )));
                }
                // BLAKE3-hash the raw string to get a proper 32-byte key
                // This is safer than zero-padding.
                let hash = blake3::hash(raw);
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(hash.as_bytes());
                eprintln!(
                    "Warning: SECRETS_MASTER_KEY is not hex — hashed to derive vault key. \
                     Run `zp init` for a proper Genesis key."
                );
                return Ok(ResolvedVaultKey {
                    key,
                    source: VaultKeySource::LegacyEnvVar,
                });
            }
        }
    }

    // 3. No valid key source — hard error
    Err(KeyError::InvalidKeyMaterial(
        "No vault key available. Run `zp init` to create your Genesis key.".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hierarchy::GenesisKey;

    // ── Core derivation tests ────────────────────────────────────────

    #[test]
    fn test_derive_vault_key_deterministic() {
        let secret = [42u8; 32];
        let key1 = derive_vault_key(&secret);
        let key2 = derive_vault_key(&secret);
        assert_eq!(*key1, *key2, "same genesis secret must produce same vault key");
    }

    #[test]
    fn test_derive_vault_key_different_secrets() {
        let secret_a = [1u8; 32];
        let secret_b = [2u8; 32];
        let key_a = derive_vault_key(&secret_a);
        let key_b = derive_vault_key(&secret_b);
        assert_ne!(*key_a, *key_b, "different secrets must produce different vault keys");
    }

    #[test]
    fn test_derive_vault_key_not_identity() {
        let secret = [42u8; 32];
        let key = derive_vault_key(&secret);
        assert_ne!(*key, secret, "vault key must not be the genesis secret itself");
    }

    #[test]
    fn test_derive_vault_key_all_zeros() {
        let secret = [0u8; 32];
        let key = derive_vault_key(&secret);
        assert_ne!(*key, [0u8; 32], "vault key must not be zero even with zero input");
        let key2 = derive_vault_key(&secret);
        assert_eq!(*key, *key2, "still deterministic");
    }

    #[test]
    fn test_derive_vault_key_avalanche() {
        let secret_a = [0x42u8; 32];
        let mut secret_b = [0x42u8; 32];
        secret_b[16] ^= 1; // flip one bit

        let key_a = derive_vault_key(&secret_a);
        let key_b = derive_vault_key(&secret_b);

        assert_ne!(*key_a, *key_b, "single bit flip must produce different key");
        let mut diff_bits = 0u32;
        for i in 0..32 {
            diff_bits += (key_a[i] ^ key_b[i]).count_ones();
        }
        assert!(diff_bits > 64, "avalanche: only {} bits differ (expect ~128)", diff_bits);
    }

    // ── Keyring integration tests ────────────────────────────────────

    #[test]
    fn test_resolve_vault_key_from_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("resolve-test");
        keyring.save_genesis(&genesis, true).unwrap();

        let resolved = resolve_vault_key(&keyring).unwrap();
        let expected = derive_vault_key(&genesis.secret_key());
        assert_eq!(*resolved.key, *expected);
    }

    #[test]
    fn test_resolve_vault_key_errors_without_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        std::env::remove_var("SECRETS_MASTER_KEY");
        assert!(resolve_vault_key(&keyring).is_err());
    }

    #[test]
    fn test_resolve_vault_key_env_var_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        let test_key = [0xAB_u8; 32];
        std::env::set_var("SECRETS_MASTER_KEY", hex::encode(test_key));
        let resolved = resolve_vault_key(&keyring).unwrap();
        std::env::remove_var("SECRETS_MASTER_KEY");
        assert_eq!(*resolved.key, test_key);
        assert_eq!(resolved.source, VaultKeySource::LegacyEnvVar);
    }

    #[test]
    fn test_resolve_vault_key_rejects_short_env_var() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        // Too short (< 16 bytes) and not valid hex for 32 bytes
        std::env::set_var("SECRETS_MASTER_KEY", "tooshort");
        let result = resolve_vault_key(&keyring);
        std::env::remove_var("SECRETS_MASTER_KEY");
        assert!(result.is_err(), "short env var keys must be rejected");
    }

    #[test]
    fn test_resolve_vault_key_rejects_wrong_length_hex() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        // Valid hex but only 16 bytes (32 hex chars) — not 32 bytes
        std::env::set_var("SECRETS_MASTER_KEY", hex::encode([0xABu8; 16]));
        let result = resolve_vault_key(&keyring);
        std::env::remove_var("SECRETS_MASTER_KEY");
        assert!(result.is_err(), "non-32-byte hex keys must be rejected");
    }

    #[test]
    fn test_resolve_vault_key_hashes_long_raw_string() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();
        // Long enough raw string (>= 16 bytes), not valid hex
        let raw = "this-is-a-legacy-passphrase-from-old-setup";
        std::env::set_var("SECRETS_MASTER_KEY", raw);
        let resolved = resolve_vault_key(&keyring).unwrap();
        std::env::remove_var("SECRETS_MASTER_KEY");
        assert_eq!(resolved.source, VaultKeySource::LegacyEnvVar);
        // Key should be BLAKE3 hash of the raw string, not zero-padded
        let expected = blake3::hash(raw.as_bytes());
        assert_eq!(&resolved.key[..], expected.as_bytes());
    }

    #[test]
    fn test_derive_and_resolve_consistency() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("consistency-test");
        keyring.save_genesis(&genesis, true).unwrap();

        let resolved = resolve_vault_key(&keyring).unwrap();
        let direct = derive_vault_key(&genesis.secret_key());
        assert_eq!(*resolved.key, *direct, "resolve and derive must match");
    }
}
