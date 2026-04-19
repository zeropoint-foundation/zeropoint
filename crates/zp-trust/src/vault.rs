//! Credential vault — tiered, encrypted, reference-aware credential store.
//!
//! ## Ontology
//!
//! The vault organizes secrets into four tiers, each with its own derived
//! encryption key:
//!
//! - **Providers** (`providers/`): Shared credential pool — API keys, tokens,
//!   connection strings. Human-owned, long-lived.  One entry per provider/field
//!   pair (e.g. `providers/openai/api_key`).
//!
//! - **Tools** (`tools/`): Per-tool configuration. A mix of **references** to
//!   provider credentials and **local values** (model names, ports, toggles).
//!   System-managed, lifecycle-bound to tool registration.
//!
//! - **System** (`system/`): Internal ZP operational secrets — relay signing
//!   keys, receipt chain seeds, vault metadata.
//!
//! - **Ephemeral** (`ephemeral/`): Short-lived secrets — OAuth refresh tokens,
//!   session material.
//!
//! ## Entry Types
//!
//! Each vault entry is either:
//! - A **Value**: encrypted bytes (ChaCha20-Poly1305, per-tier derived key).
//! - A **Ref**: a pointer to another vault path. Resolved transparently at
//!   read time by chasing the reference to its target Value.
//!
//! ## Scoped Access
//!
//! Consumers interact with the vault through `VaultScope`, a zero-cost lens
//! restricted to a key prefix. A scope can read/write within its prefix and
//! resolve its own Ref edges to provider entries, but cannot enumerate or
//! write to other scopes.
//!
//! ## Key Derivation
//!
//! ```text
//! Genesis secret
//!   └─ master_key = BLAKE3-keyed(genesis, "zp-credential-vault-v1")
//!        ├─ providers_key = BLAKE3-keyed(master, "vault-tier:providers")
//!        ├─ tools_key     = BLAKE3-keyed(master, "vault-tier:tools")
//!        ├─ system_key    = BLAKE3-keyed(master, "vault-tier:system")
//!        └─ ephemeral_key = BLAKE3-keyed(master, "vault-tier:ephemeral")
//! ```
//!
//! Legacy entries (from pre-tiered vaults) are encrypted with the master key
//! directly and remain decryptable — no migration required.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info, warn};
use zeroize::Zeroize;

// ============================================================================
// Errors
// ============================================================================

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

    /// A reference target does not exist in the vault.
    #[error("Broken reference: {from} -> {to}")]
    BrokenRef {
        /// The entry that contains the reference.
        from: String,
        /// The target path that doesn't exist.
        to: String,
    },

    /// A reference chain exceeded the maximum depth (cycle or excessive nesting).
    #[error("Reference cycle detected at: {0}")]
    RefCycle(String),

    /// Scope violation — attempted access outside the scope prefix.
    #[error("Scope violation: '{attempted}' is outside scope '{scope}'")]
    ScopeViolation {
        /// The path the caller tried to access.
        attempted: String,
        /// The scope prefix that was violated.
        scope: String,
    },

    /// File I/O error during vault persistence.
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for vault operations.
pub type VaultResult<T> = Result<T, VaultError>;

// ============================================================================
// Tiers
// ============================================================================

/// The trust tier a vault entry belongs to.
///
/// Each tier derives its own encryption sub-key from the master key,
/// providing cryptographic isolation between tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultTier {
    /// Shared credential pool — API keys, tokens, connection strings.
    Providers,
    /// Per-tool configuration — references to providers + local values.
    Tools,
    /// Internal ZP operational secrets.
    System,
    /// Short-lived secrets — OAuth tokens, session material.
    Ephemeral,
    /// Legacy entries from pre-tiered vaults (encrypted with master key).
    Legacy,
}

impl VaultTier {
    /// The well-known key prefix for this tier.
    pub fn prefix(&self) -> &'static str {
        match self {
            VaultTier::Providers => "providers/",
            VaultTier::Tools => "tools/",
            VaultTier::System => "system/",
            VaultTier::Ephemeral => "ephemeral/",
            VaultTier::Legacy => "",
        }
    }

    /// Derive the tier-specific encryption key from the master key.
    ///
    /// Uses BLAKE3 in keyed mode: `BLAKE3-keyed(master, "vault-tier:{tier}")`.
    /// Legacy tier returns the master key unchanged for backward compatibility.
    pub fn derive_key(&self, master_key: &[u8; 32]) -> [u8; 32] {
        match self {
            VaultTier::Legacy => *master_key,
            tier => {
                let context = format!("vault-tier:{}", tier.as_str());
                let key = blake3::keyed_hash(master_key, context.as_bytes());
                *key.as_bytes()
            }
        }
    }

    /// String representation used in key derivation.
    fn as_str(&self) -> &'static str {
        match self {
            VaultTier::Providers => "providers",
            VaultTier::Tools => "tools",
            VaultTier::System => "system",
            VaultTier::Ephemeral => "ephemeral",
            VaultTier::Legacy => "legacy",
        }
    }

    /// Infer tier from a vault key path.
    pub fn from_path(path: &str) -> Self {
        if path.starts_with("providers/") {
            VaultTier::Providers
        } else if path.starts_with("tools/") {
            VaultTier::Tools
        } else if path.starts_with("system/") {
            VaultTier::System
        } else if path.starts_with("ephemeral/") {
            VaultTier::Ephemeral
        } else {
            VaultTier::Legacy
        }
    }
}

// ============================================================================
// Vault Entries
// ============================================================================

/// A single entry in the vault — either an encrypted value or a reference.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VaultEntry {
    /// An encrypted credential value.
    Value {
        /// The encrypted credential data.
        #[serde(flatten)]
        encrypted: EncryptedCredential,
        /// Which tier's key was used to encrypt this entry.
        /// `None` means legacy (master key).
        #[serde(skip_serializing_if = "Option::is_none")]
        tier: Option<VaultTier>,
    },
    /// A reference to another vault path.
    ///
    /// When retrieved, the vault transparently chases the reference
    /// and returns the target's decrypted value.
    Ref {
        /// The full vault path of the target entry.
        target: String,
    },
}

/// An encrypted credential stored in the vault.
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct EncryptedCredential {
    /// 12-byte nonce for ChaCha20-Poly1305
    pub nonce: [u8; 12],
    /// Encrypted credential data (includes authentication tag)
    pub ciphertext: Vec<u8>,
}

// ============================================================================
// Max ref-chase depth (prevents cycles)
// ============================================================================

const MAX_REF_DEPTH: usize = 8;

// ============================================================================
// The Vault
// ============================================================================

/// Secure credential vault with tiered encryption and reference resolution.
///
/// Credentials are organized by tier (providers, tools, system, ephemeral),
/// each with its own derived encryption key. Entries can be direct values
/// or references to other vault paths.
///
/// All sensitive data is zeroized on drop.
#[derive(Debug)]
pub struct CredentialVault {
    /// Master encryption key (32 bytes) — root of the key hierarchy.
    master_key: [u8; 32],
    /// In-memory storage of vault entries.
    entries: HashMap<String, VaultEntry>,
}

impl Drop for CredentialVault {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}

impl CredentialVault {
    /// Create a new credential vault with the given master key.
    pub fn new(master_key: &[u8; 32]) -> Self {
        Self {
            master_key: *master_key,
            entries: HashMap::new(),
        }
    }

    // ====================================================================
    // Low-level store/retrieve (backward-compatible, uses master key)
    // ====================================================================

    /// Store a credential in the vault with encryption.
    ///
    /// Uses the **master key** directly (Legacy tier) for backward
    /// compatibility. For tier-aware storage, use [`store_tiered`] or
    /// a [`VaultScope`].
    pub fn store(&mut self, name: &str, value: &[u8]) -> VaultResult<()> {
        let tier = VaultTier::from_path(name);
        self.store_with_tier(name, value, tier)
    }

    /// Store a credential encrypted with a specific tier's derived key.
    pub fn store_tiered(
        &mut self,
        name: &str,
        value: &[u8],
        tier: VaultTier,
    ) -> VaultResult<()> {
        self.store_with_tier(name, value, tier)
    }

    /// Internal: encrypt and store with the given tier's key.
    fn store_with_tier(
        &mut self,
        name: &str,
        value: &[u8],
        tier: VaultTier,
    ) -> VaultResult<()> {
        let key = tier.derive_key(&self.master_key);
        let encrypted = Self::encrypt_value(&key, value)?;

        let entry = VaultEntry::Value {
            encrypted,
            tier: if tier == VaultTier::Legacy {
                None
            } else {
                Some(tier)
            },
        };

        self.entries.insert(name.to_string(), entry);
        Ok(())
    }

    /// Store a reference entry in the vault.
    ///
    /// When the source path is retrieved, the vault transparently
    /// follows the reference and returns the target's decrypted value.
    pub fn store_ref(&mut self, source: &str, target: &str) -> VaultResult<()> {
        self.entries.insert(
            source.to_string(),
            VaultEntry::Ref {
                target: target.to_string(),
            },
        );
        Ok(())
    }

    /// Retrieve and decrypt a credential from the vault.
    ///
    /// Follows references transparently. Falls back to alias conventions
    /// for backward compatibility with pre-tiered naming.
    pub fn retrieve(&self, name: &str) -> VaultResult<Vec<u8>> {
        self.retrieve_resolved(name, 0)
    }

    /// Internal: retrieve with ref-depth tracking.
    fn retrieve_resolved(&self, name: &str, depth: usize) -> VaultResult<Vec<u8>> {
        if depth > MAX_REF_DEPTH {
            return Err(VaultError::RefCycle(name.to_string()));
        }

        let entry = self
            .find_entry(name)
            .ok_or_else(|| VaultError::CredentialNotFound(name.to_string()))?;

        match entry {
            VaultEntry::Value { encrypted, tier } => {
                let effective_tier = tier.unwrap_or(VaultTier::Legacy);
                let key = effective_tier.derive_key(&self.master_key);
                Self::decrypt_value(&key, encrypted)
            }
            VaultEntry::Ref { target } => {
                // Chase the reference
                self.retrieve_resolved(target, depth + 1).map_err(|e| {
                    match e {
                        VaultError::CredentialNotFound(_) => VaultError::BrokenRef {
                            from: name.to_string(),
                            to: target.clone(),
                        },
                        other => other,
                    }
                })
            }
        }
    }

    /// Look up an entry with alias fallback for backward compatibility.
    fn find_entry(&self, name: &str) -> Option<&VaultEntry> {
        self.entries
            .get(name)
            .or_else(|| {
                // Fallback: "provider/field" → "provider/provider_field"
                if let Some((provider, field)) = name.split_once('/') {
                    let expanded = format!("{}/{}_{}", provider, provider, field);
                    self.entries.get(&expanded)
                } else {
                    None
                }
            })
            .or_else(|| {
                // Reverse: "provider/provider_field" → "provider/field"
                if let Some((provider, field)) = name.split_once('/') {
                    let prefix = format!("{}_", provider);
                    if field.starts_with(&prefix) {
                        let stripped = format!("{}/{}", provider, &field[prefix.len()..]);
                        self.entries.get(&stripped)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
    }

    /// Check if an entry exists (Value or Ref).
    pub fn contains(&self, name: &str) -> bool {
        self.find_entry(name).is_some()
    }

    /// Check if an entry is a Ref.
    pub fn is_ref(&self, name: &str) -> bool {
        matches!(self.find_entry(name), Some(VaultEntry::Ref { .. }))
    }

    /// Remove a credential from the vault.
    pub fn remove(&mut self, name: &str) -> VaultResult<()> {
        self.entries
            .remove(name)
            .ok_or_else(|| VaultError::CredentialNotFound(name.to_string()))?;
        Ok(())
    }

    /// List all entry names (not their values).
    pub fn list(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// List entries under a given prefix.
    pub fn list_prefix(&self, prefix: &str) -> Vec<String> {
        self.entries
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect()
    }

    /// Get the number of entries stored in the vault.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    // ====================================================================
    // Scoped access
    // ====================================================================

    /// Create a scoped view of this vault, restricted to a key prefix.
    ///
    /// The scope uses the appropriate tier-derived encryption key and
    /// can only read/write entries under its prefix. Ref resolution
    /// follows edges outside the scope (e.g. to providers) but cannot
    /// enumerate or write outside the prefix.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let scope = vault.scope("tools/ember");
    /// scope.store("OPENAI_API_KEY", b"sk-...")?;  // stores at tools/ember/OPENAI_API_KEY
    /// scope.store_ref("MODEL_KEY", "providers/openai/api_key")?;
    /// let env = scope.resolve_all()?;  // follows refs, returns flat map
    /// ```
    pub fn scope(&mut self, prefix: &str) -> VaultScope<'_> {
        let normalized = if prefix.ends_with('/') {
            prefix.to_string()
        } else {
            format!("{}/", prefix)
        };
        let tier = VaultTier::from_path(&normalized);
        let derived_key = tier.derive_key(&self.master_key);

        VaultScope {
            vault: self,
            prefix: normalized,
            tier,
            derived_key,
        }
    }

    /// Create an immutable scoped view for read-only access.
    pub fn scope_ref(&self, prefix: &str) -> VaultScopeRef<'_> {
        let normalized = if prefix.ends_with('/') {
            prefix.to_string()
        } else {
            format!("{}/", prefix)
        };
        let tier = VaultTier::from_path(&normalized);
        let derived_key = tier.derive_key(&self.master_key);

        VaultScopeRef {
            vault: self,
            prefix: normalized,
            _tier: tier,
            derived_key,
        }
    }

    // ====================================================================
    // Provider convenience methods
    // ====================================================================

    /// Store a provider credential.
    ///
    /// Stores at `providers/{provider}/{field}` with the Providers tier key.
    pub fn store_provider(
        &mut self,
        provider: &str,
        field: &str,
        value: &[u8],
    ) -> VaultResult<()> {
        let path = format!("providers/{}/{}", provider, field);
        self.store_tiered(&path, value, VaultTier::Providers)
    }

    /// Retrieve a provider credential.
    pub fn retrieve_provider(&self, provider: &str, field: &str) -> VaultResult<Vec<u8>> {
        let path = format!("providers/{}/{}", provider, field);
        self.retrieve(&path)
    }

    // ====================================================================
    // Tool convenience methods
    // ====================================================================

    /// Store a tool environment variable (direct value).
    ///
    /// Stores at `tools/{tool}/{var}` with the Tools tier key.
    pub fn store_tool_env(
        &mut self,
        tool: &str,
        var: &str,
        value: &[u8],
    ) -> VaultResult<()> {
        let path = format!("tools/{}/{}", tool, var);
        self.store_tiered(&path, value, VaultTier::Tools)
    }

    /// Store a tool environment variable as a reference to a provider credential.
    ///
    /// The tool entry becomes a Ref that points to `providers/{provider}/{field}`.
    /// At resolve time, the vault chases the reference and returns the provider's
    /// decrypted value.
    pub fn store_tool_ref(
        &mut self,
        tool: &str,
        var: &str,
        provider: &str,
        field: &str,
    ) -> VaultResult<()> {
        let source = format!("tools/{}/{}", tool, var);
        let target = format!("providers/{}/{}", provider, field);
        self.store_ref(&source, &target)
    }

    /// Resolve all environment variables for a tool.
    ///
    /// Returns a flat `HashMap<var_name, decrypted_bytes>` where:
    /// - Value entries are decrypted directly
    /// - Ref entries are chased to their provider target and decrypted
    ///
    /// The returned keys are the bare variable names (without the `tools/{tool}/` prefix).
    pub fn resolve_tool_env(&self, tool: &str) -> VaultResult<HashMap<String, Vec<u8>>> {
        let prefix = format!("tools/{}/", tool);
        let mut result = HashMap::new();

        for (key, _entry) in &self.entries {
            if let Some(var) = key.strip_prefix(&prefix) {
                let value = self.retrieve(key)?;
                result.insert(var.to_string(), value);
            }
        }

        Ok(result)
    }

    /// Remove all configuration for a tool.
    pub fn remove_tool(&mut self, tool: &str) -> usize {
        let prefix = format!("tools/{}/", tool);
        let keys: Vec<String> = self
            .entries
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        let count = keys.len();
        for key in keys {
            self.entries.remove(&key);
        }
        count
    }

    // ====================================================================
    // Encryption primitives
    // ====================================================================

    fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> VaultResult<EncryptedCredential> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| VaultError::InvalidKeyMaterial)?;

        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedCredential {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    fn decrypt_value(key: &[u8; 32], encrypted: &EncryptedCredential) -> VaultResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| VaultError::InvalidKeyMaterial)?;

        let nonce = Nonce::from_slice(&encrypted.nonce);
        cipher
            .decrypt(nonce, encrypted.ciphertext.as_ref())
            .map_err(|e| VaultError::DecryptionFailed(e.to_string()))
    }

    // ====================================================================
    // Persistence — save/load with format auto-detection
    // ====================================================================

    /// Save the vault to a JSON file.
    ///
    /// Only encrypted ciphertexts, nonces, refs, and tier tags are written —
    /// the master key never touches disk. Atomic write via tmp+rename.
    pub fn save(&self, path: &Path) -> VaultResult<()> {
        let json = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        let tmp_path = path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json.as_bytes())?;
        std::fs::rename(&tmp_path, path)?;

        info!(
            path = %path.display(),
            count = self.entries.len(),
            "Vault saved to disk"
        );
        Ok(())
    }

    /// Load entries from a JSON file.
    ///
    /// Auto-detects format:
    /// - **New format**: `HashMap<String, VaultEntry>` (tagged with type/tier)
    /// - **Legacy format**: `HashMap<String, EncryptedCredential>` (flat, no tiers)
    ///
    /// Legacy entries are wrapped as `VaultEntry::Value { tier: None }`.
    pub fn load(&mut self, path: &Path) -> VaultResult<()> {
        let json = std::fs::read_to_string(path)?;

        // Try new format first
        if let Ok(entries) = serde_json::from_str::<HashMap<String, VaultEntry>>(&json) {
            info!(
                path = %path.display(),
                count = entries.len(),
                "Vault loaded (tiered format)"
            );
            self.entries = entries;
            return Ok(());
        }

        // Fall back to legacy format
        let legacy: HashMap<String, EncryptedCredential> = serde_json::from_str(&json)
            .map_err(|e| VaultError::SerializationError(e.to_string()))?;

        info!(
            path = %path.display(),
            count = legacy.len(),
            "Vault loaded (legacy format — auto-upgrading)"
        );

        self.entries = legacy
            .into_iter()
            .map(|(name, encrypted)| {
                (
                    name,
                    VaultEntry::Value {
                        encrypted,
                        tier: None, // Legacy: uses master key
                    },
                )
            })
            .collect();

        Ok(())
    }

    /// Create a vault and load existing credentials if the file exists.
    pub fn load_or_create(master_key: &[u8; 32], path: &Path) -> VaultResult<Self> {
        let mut vault = Self::new(master_key);

        if path.exists() {
            vault.load(path)?;
            debug!(
                path = %path.display(),
                count = vault.entries.len(),
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

    // ====================================================================
    // Internal: direct access to entries (for VaultScope)
    // ====================================================================

    /// Access the raw entries map (used by VaultScope for batch ops).
    #[doc(hidden)]
    pub fn entries(&self) -> &HashMap<String, VaultEntry> {
        &self.entries
    }

    /// Mutable access to entries (used by VaultScope for writes).
    #[doc(hidden)]
    pub fn entries_mut(&mut self) -> &mut HashMap<String, VaultEntry> {
        &mut self.entries
    }

}

// ============================================================================
// VaultScope — mutable scoped access
// ============================================================================

/// A mutable scoped view into the vault, restricted to a key prefix.
///
/// All reads/writes are constrained to `{prefix}*`. The scope uses a
/// tier-derived encryption key, providing cryptographic isolation from
/// other tiers.
///
/// Ref resolution can follow edges outside the scope (e.g. a tool scope
/// can resolve a ref pointing to `providers/openai/api_key`), but direct
/// reads of out-of-scope entries are denied.
pub struct VaultScope<'a> {
    vault: &'a mut CredentialVault,
    prefix: String,
    tier: VaultTier,
    derived_key: [u8; 32],
}

impl<'a> Drop for VaultScope<'a> {
    fn drop(&mut self) {
        self.derived_key.zeroize();
    }
}

impl<'a> VaultScope<'a> {
    /// The prefix this scope is restricted to.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The tier this scope belongs to.
    pub fn tier(&self) -> VaultTier {
        self.tier
    }

    /// Store an encrypted value within this scope.
    ///
    /// The `key` is relative to the scope prefix.
    /// E.g. on a `tools/ember/` scope, `store("MODEL", ...)` stores at
    /// `tools/ember/MODEL`.
    pub fn store(&mut self, key: &str, value: &[u8]) -> VaultResult<()> {
        let full_path = format!("{}{}", self.prefix, key);
        let encrypted = CredentialVault::encrypt_value(&self.derived_key, value)?;

        self.vault.entries_mut().insert(
            full_path,
            VaultEntry::Value {
                encrypted,
                tier: Some(self.tier),
            },
        );
        Ok(())
    }

    /// Store a batch of key-value pairs within this scope.
    ///
    /// More efficient than individual `store` calls — creates the cipher
    /// once and encrypts all values.
    pub fn store_batch(&mut self, pairs: &[(&str, &[u8])]) -> VaultResult<()> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.derived_key)
            .map_err(|_| VaultError::InvalidKeyMaterial)?;

        for (key, value) in pairs {
            let full_path = format!("{}{}", self.prefix, key);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher
                .encrypt(nonce, *value)
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;

            self.vault.entries_mut().insert(
                full_path,
                VaultEntry::Value {
                    encrypted: EncryptedCredential {
                        nonce: nonce_bytes,
                        ciphertext,
                    },
                    tier: Some(self.tier),
                },
            );
        }

        Ok(())
    }

    /// Store a reference within this scope.
    ///
    /// `key` is relative to scope prefix, `target` is an absolute vault path.
    pub fn store_ref(&mut self, key: &str, target: &str) -> VaultResult<()> {
        let full_path = format!("{}{}", self.prefix, key);
        self.vault.entries_mut().insert(
            full_path,
            VaultEntry::Ref {
                target: target.to_string(),
            },
        );
        Ok(())
    }

    /// Retrieve a value within this scope.
    ///
    /// `key` is relative to the scope prefix. Refs are resolved
    /// transparently (and may follow edges outside the scope).
    pub fn retrieve(&self, key: &str) -> VaultResult<Vec<u8>> {
        let full_path = format!("{}{}", self.prefix, key);
        self.vault.retrieve(&full_path)
    }

    /// List all keys in this scope (relative names, without prefix).
    pub fn list(&self) -> Vec<String> {
        self.vault
            .entries()
            .keys()
            .filter_map(|k| k.strip_prefix(&self.prefix).map(|s| s.to_string()))
            .collect()
    }

    /// Resolve all entries in this scope to a flat key→value map.
    ///
    /// Keys are relative (without the scope prefix). Refs are chased
    /// and resolved to their target values.
    pub fn resolve_all(&self) -> VaultResult<HashMap<String, Vec<u8>>> {
        let keys: Vec<(String, String)> = self
            .vault
            .entries()
            .keys()
            .filter_map(|k| {
                k.strip_prefix(&self.prefix)
                    .map(|rel| (k.clone(), rel.to_string()))
            })
            .collect();

        let mut result = HashMap::new();
        for (full_key, rel_key) in keys {
            match self.vault.retrieve(&full_key) {
                Ok(value) => {
                    result.insert(rel_key, value);
                }
                Err(VaultError::BrokenRef { from, to }) => {
                    warn!(
                        from = from,
                        to = to,
                        "Skipping broken reference during resolve_all"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        Ok(result)
    }

    /// Remove an entry within this scope.
    pub fn remove(&mut self, key: &str) -> VaultResult<()> {
        let full_path = format!("{}{}", self.prefix, key);
        self.vault.remove(&full_path)
    }

    /// Count entries in this scope.
    pub fn count(&self) -> usize {
        self.vault
            .entries()
            .keys()
            .filter(|k| k.starts_with(&self.prefix))
            .count()
    }
}

// ============================================================================
// VaultScopeRef — immutable scoped access (for read-only consumers)
// ============================================================================

/// An immutable scoped view into the vault.
///
/// Same semantics as [`VaultScope`] but read-only — no store or remove.
pub struct VaultScopeRef<'a> {
    vault: &'a CredentialVault,
    prefix: String,
    _tier: VaultTier,
    derived_key: [u8; 32],
}

impl<'a> Drop for VaultScopeRef<'a> {
    fn drop(&mut self) {
        self.derived_key.zeroize();
    }
}

impl<'a> VaultScopeRef<'a> {
    /// The prefix this scope is restricted to.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Retrieve a value within this scope.
    pub fn retrieve(&self, key: &str) -> VaultResult<Vec<u8>> {
        let full_path = format!("{}{}", self.prefix, key);
        self.vault.retrieve(&full_path)
    }

    /// List all keys in this scope (relative names).
    pub fn list(&self) -> Vec<String> {
        self.vault
            .entries()
            .keys()
            .filter_map(|k| k.strip_prefix(&self.prefix).map(|s| s.to_string()))
            .collect()
    }

    /// Resolve all entries in this scope to a flat key→value map.
    pub fn resolve_all(&self) -> VaultResult<HashMap<String, Vec<u8>>> {
        let keys: Vec<(String, String)> = self
            .vault
            .entries()
            .keys()
            .filter_map(|k| {
                k.strip_prefix(&self.prefix)
                    .map(|rel| (k.clone(), rel.to_string()))
            })
            .collect();

        let mut result = HashMap::new();
        for (full_key, rel_key) in keys {
            match self.vault.retrieve(&full_key) {
                Ok(value) => {
                    result.insert(rel_key, value);
                }
                Err(VaultError::BrokenRef { from, to }) => {
                    warn!(
                        from = from,
                        to = to,
                        "Skipping broken reference during resolve_all"
                    );
                }
                Err(e) => return Err(e),
            }
        }

        Ok(result)
    }

    /// Count entries in this scope.
    pub fn count(&self) -> usize {
        self.vault
            .entries()
            .keys()
            .filter(|k| k.starts_with(&self.prefix))
            .count()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Original backward-compatibility tests (all must still pass)
    // ====================================================================

    #[test]
    fn test_vault_store_and_retrieve() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        let credential_name = "test-db-password";
        let credential_value = b"super-secret-password";

        assert!(vault.store(credential_name, credential_value).is_ok());

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

        let list = vault.list();
        assert_eq!(list.len(), 2);

        // Each encrypted credential should have different nonces
        let cred1 = match vault.entries.get("secret1").unwrap() {
            VaultEntry::Value { encrypted, .. } => encrypted,
            _ => panic!("expected Value"),
        };
        let cred2 = match vault.entries.get("secret2").unwrap() {
            VaultEntry::Value { encrypted, .. } => encrypted,
            _ => panic!("expected Value"),
        };
        assert_ne!(cred1.nonce, cred2.nonce);
    }

    // ====================================================================
    // Persistence tests
    // ====================================================================

    #[test]
    fn test_vault_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("zp-vault-test-roundtrip");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault.json");
        let _ = std::fs::remove_file(&vault_path);

        let master_key = [0xABu8; 32];

        {
            let mut vault = CredentialVault::new(&master_key);
            vault
                .store("anthropic/api_key", b"sk-ant-test-key-123")
                .unwrap();
            vault
                .store("openai/api_key", b"sk-openai-test-456")
                .unwrap();
            vault.store("postgres/password", b"hunter2").unwrap();
            vault.save(&vault_path).unwrap();
        }

        {
            let mut vault = CredentialVault::new(&master_key);
            vault.load(&vault_path).unwrap();

            assert_eq!(vault.count(), 3);
            assert_eq!(
                vault.retrieve("anthropic/api_key").unwrap(),
                b"sk-ant-test-key-123"
            );
            assert_eq!(
                vault.retrieve("openai/api_key").unwrap(),
                b"sk-openai-test-456"
            );
            assert_eq!(vault.retrieve("postgres/password").unwrap(), b"hunter2");
        }

        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_vault_load_or_create_new() {
        let dir = std::env::temp_dir().join("zp-vault-test-loadcreate");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-new.json");
        let _ = std::fs::remove_file(&vault_path);

        let master_key = [0xCDu8; 32];
        let vault = CredentialVault::load_or_create(&master_key, &vault_path).unwrap();
        assert_eq!(vault.count(), 0);

        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_vault_load_or_create_existing() {
        let dir = std::env::temp_dir().join("zp-vault-test-existing");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-existing.json");

        let master_key = [0xEFu8; 32];

        {
            let mut vault = CredentialVault::new(&master_key);
            vault.store("tavily/api_key", b"tvly-test-789").unwrap();
            vault.save(&vault_path).unwrap();
        }

        let vault = CredentialVault::load_or_create(&master_key, &vault_path).unwrap();
        assert_eq!(vault.count(), 1);
        assert_eq!(vault.retrieve("tavily/api_key").unwrap(), b"tvly-test-789");

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

        {
            let mut vault = CredentialVault::new(&key_a);
            vault.store("secret/token", b"classified").unwrap();
            vault.save(&vault_path).unwrap();
        }

        {
            let vault = CredentialVault::load_or_create(&key_b, &vault_path).unwrap();
            assert_eq!(vault.count(), 1);
            let result = vault.retrieve("secret/token");
            assert!(matches!(result, Err(VaultError::DecryptionFailed(_))));
        }

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

        assert!(
            !tmp_path.exists(),
            "Temporary file should be cleaned up after save"
        );
        assert!(vault_path.exists(), "Final vault file should exist");

        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // ====================================================================
    // Tier key derivation tests
    // ====================================================================

    #[test]
    fn test_tier_derives_distinct_keys() {
        let master = [0x42u8; 32];
        let k_prov = VaultTier::Providers.derive_key(&master);
        let k_tool = VaultTier::Tools.derive_key(&master);
        let k_sys = VaultTier::System.derive_key(&master);
        let k_eph = VaultTier::Ephemeral.derive_key(&master);
        let k_leg = VaultTier::Legacy.derive_key(&master);

        // All tier keys must be distinct
        assert_ne!(k_prov, k_tool);
        assert_ne!(k_prov, k_sys);
        assert_ne!(k_prov, k_eph);
        assert_ne!(k_tool, k_sys);
        assert_ne!(k_tool, k_eph);
        assert_ne!(k_sys, k_eph);

        // Legacy returns master key unchanged
        assert_eq!(k_leg, master);
    }

    #[test]
    fn test_tier_key_isolation_prevents_cross_decrypt() {
        let master = [0x42u8; 32];
        let plaintext = b"cross-tier-test";

        // Encrypt with Providers key
        let prov_key = VaultTier::Providers.derive_key(&master);
        let encrypted = CredentialVault::encrypt_value(&prov_key, plaintext).unwrap();

        // Decrypt with Providers key — should succeed
        let decrypted = CredentialVault::decrypt_value(&prov_key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);

        // Decrypt with Tools key — must fail
        let tool_key = VaultTier::Tools.derive_key(&master);
        let result = CredentialVault::decrypt_value(&tool_key, &encrypted);
        assert!(matches!(result, Err(VaultError::DecryptionFailed(_))));
    }

    #[test]
    fn test_tier_from_path() {
        assert_eq!(VaultTier::from_path("providers/openai/api_key"), VaultTier::Providers);
        assert_eq!(VaultTier::from_path("tools/ember/MODEL"), VaultTier::Tools);
        assert_eq!(VaultTier::from_path("system/relay/key"), VaultTier::System);
        assert_eq!(VaultTier::from_path("ephemeral/oauth/token"), VaultTier::Ephemeral);
        assert_eq!(VaultTier::from_path("openai/api_key"), VaultTier::Legacy);
        assert_eq!(VaultTier::from_path("flat-key"), VaultTier::Legacy);
    }

    // ====================================================================
    // Tiered store/retrieve tests
    // ====================================================================

    #[test]
    fn test_store_tiered_and_retrieve() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault
            .store_tiered("providers/openai/api_key", b"sk-tiered", VaultTier::Providers)
            .unwrap();

        let retrieved = vault.retrieve("providers/openai/api_key").unwrap();
        assert_eq!(retrieved, b"sk-tiered");
    }

    #[test]
    fn test_auto_tier_detection_on_store() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        // store() auto-detects tier from path
        vault.store("providers/anthropic/api_key", b"sk-auto").unwrap();

        let entry = vault.entries.get("providers/anthropic/api_key").unwrap();
        match entry {
            VaultEntry::Value { tier, .. } => {
                assert_eq!(*tier, Some(VaultTier::Providers));
            }
            _ => panic!("expected Value"),
        }

        // Legacy path gets Legacy tier (None)
        vault.store("flat-key", b"legacy").unwrap();
        let entry = vault.entries.get("flat-key").unwrap();
        match entry {
            VaultEntry::Value { tier, .. } => {
                assert_eq!(*tier, None);
            }
            _ => panic!("expected Value"),
        }
    }

    // ====================================================================
    // Reference tests
    // ====================================================================

    #[test]
    fn test_ref_resolution() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        // Store a provider credential
        vault
            .store_provider("openai", "api_key", b"sk-ref-test")
            .unwrap();

        // Store a tool ref pointing to it
        vault
            .store_tool_ref("ember", "OPENAI_API_KEY", "openai", "api_key")
            .unwrap();

        // Retrieving the tool entry should chase the ref
        let value = vault.retrieve("tools/ember/OPENAI_API_KEY").unwrap();
        assert_eq!(value, b"sk-ref-test");
    }

    #[test]
    fn test_broken_ref() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_ref("tools/ember/MISSING", "providers/nonexistent/key").unwrap();

        let result = vault.retrieve("tools/ember/MISSING");
        assert!(matches!(result, Err(VaultError::BrokenRef { .. })));
    }

    #[test]
    fn test_ref_cycle_detection() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_ref("a", "b").unwrap();
        vault.store_ref("b", "c").unwrap();
        vault.store_ref("c", "a").unwrap(); // cycle

        let result = vault.retrieve("a");
        assert!(matches!(result, Err(VaultError::RefCycle(_))));
    }

    #[test]
    fn test_ref_chain() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        // Chain: a → b → c → actual value
        vault.store("c", b"end-of-chain").unwrap();
        vault.store_ref("b", "c").unwrap();
        vault.store_ref("a", "b").unwrap();

        assert_eq!(vault.retrieve("a").unwrap(), b"end-of-chain");
    }

    #[test]
    fn test_is_ref() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store("value-entry", b"data").unwrap();
        vault.store_ref("ref-entry", "value-entry").unwrap();

        assert!(!vault.is_ref("value-entry"));
        assert!(vault.is_ref("ref-entry"));
    }

    // ====================================================================
    // Provider convenience method tests
    // ====================================================================

    #[test]
    fn test_store_and_retrieve_provider() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_provider("anthropic", "api_key", b"sk-ant-test").unwrap();
        vault.store_provider("openai", "api_key", b"sk-oai-test").unwrap();

        assert_eq!(
            vault.retrieve_provider("anthropic", "api_key").unwrap(),
            b"sk-ant-test"
        );
        assert_eq!(
            vault.retrieve_provider("openai", "api_key").unwrap(),
            b"sk-oai-test"
        );
    }

    // ====================================================================
    // Tool convenience method tests
    // ====================================================================

    #[test]
    fn test_store_and_resolve_tool_env() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        // Provider credentials
        vault.store_provider("openai", "api_key", b"sk-tool-test").unwrap();

        // Tool config: mix of refs and local values
        vault.store_tool_ref("ember", "OPENAI_API_KEY", "openai", "api_key").unwrap();
        vault.store_tool_env("ember", "MODEL", b"gpt-4o").unwrap();
        vault.store_tool_env("ember", "PORT", b"3000").unwrap();

        // Resolve all
        let env = vault.resolve_tool_env("ember").unwrap();
        assert_eq!(env.len(), 3);
        assert_eq!(env.get("OPENAI_API_KEY").unwrap(), b"sk-tool-test");
        assert_eq!(env.get("MODEL").unwrap(), b"gpt-4o");
        assert_eq!(env.get("PORT").unwrap(), b"3000");
    }

    #[test]
    fn test_remove_tool() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_tool_env("ember", "A", b"1").unwrap();
        vault.store_tool_env("ember", "B", b"2").unwrap();
        vault.store_tool_env("shannon", "C", b"3").unwrap();

        let removed = vault.remove_tool("ember");
        assert_eq!(removed, 2);
        assert_eq!(vault.count(), 1); // only shannon/C remains
    }

    #[test]
    fn test_resolve_tool_env_with_broken_ref_in_other_tool() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        // Ember has good config
        vault.store_provider("openai", "api_key", b"sk-good").unwrap();
        vault.store_tool_ref("ember", "KEY", "openai", "api_key").unwrap();

        // Shannon has a broken ref — should NOT affect Ember
        vault.store_ref("tools/shannon/KEY", "providers/missing/key").unwrap();

        let env = vault.resolve_tool_env("ember").unwrap();
        assert_eq!(env.get("KEY").unwrap(), b"sk-good");
    }

    // ====================================================================
    // VaultScope tests
    // ====================================================================

    #[test]
    fn test_scope_store_and_retrieve() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        {
            let mut scope = vault.scope("tools/ember");
            scope.store("MODEL", b"gpt-4o").unwrap();
            scope.store("PORT", b"9100").unwrap();
        }

        // Verify stored at full paths
        assert!(vault.contains("tools/ember/MODEL"));
        assert!(vault.contains("tools/ember/PORT"));

        // Verify retrievable through scope
        let scope = vault.scope_ref("tools/ember");
        assert_eq!(scope.retrieve("MODEL").unwrap(), b"gpt-4o");
        assert_eq!(scope.retrieve("PORT").unwrap(), b"9100");
    }

    #[test]
    fn test_scope_list_is_relative() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_tool_env("ember", "A", b"1").unwrap();
        vault.store_tool_env("ember", "B", b"2").unwrap();
        vault.store_tool_env("shannon", "C", b"3").unwrap();

        let scope = vault.scope_ref("tools/ember/");
        let keys = scope.list();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"A".to_string()));
        assert!(keys.contains(&"B".to_string()));
        // Shannon's entry must NOT appear
        assert!(!keys.contains(&"C".to_string()));
    }

    #[test]
    fn test_scope_resolve_all_follows_refs() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_provider("openai", "api_key", b"sk-scope-test").unwrap();
        vault.store_tool_ref("ember", "OPENAI_API_KEY", "openai", "api_key").unwrap();
        vault.store_tool_env("ember", "MODEL", b"gpt-4o").unwrap();

        let scope = vault.scope_ref("tools/ember/");
        let env = scope.resolve_all().unwrap();
        assert_eq!(env.len(), 2);
        assert_eq!(env.get("OPENAI_API_KEY").unwrap(), b"sk-scope-test");
        assert_eq!(env.get("MODEL").unwrap(), b"gpt-4o");
    }

    #[test]
    fn test_scope_batch_store() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        {
            let mut scope = vault.scope("tools/ember");
            scope
                .store_batch(&[
                    ("MODEL", b"gpt-4o" as &[u8]),
                    ("PORT", b"9100"),
                    ("TEMPERATURE", b"0.7"),
                ])
                .unwrap();
        }

        assert_eq!(vault.list_prefix("tools/ember/").len(), 3);

        let scope = vault.scope_ref("tools/ember/");
        assert_eq!(scope.retrieve("MODEL").unwrap(), b"gpt-4o");
        assert_eq!(scope.retrieve("PORT").unwrap(), b"9100");
        assert_eq!(scope.retrieve("TEMPERATURE").unwrap(), b"0.7");
    }

    #[test]
    fn test_scope_remove() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_tool_env("ember", "A", b"1").unwrap();
        vault.store_tool_env("ember", "B", b"2").unwrap();

        {
            let mut scope = vault.scope("tools/ember");
            scope.remove("A").unwrap();
        }

        assert_eq!(vault.count(), 1);
        assert!(!vault.contains("tools/ember/A"));
        assert!(vault.contains("tools/ember/B"));
    }

    #[test]
    fn test_scope_count() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_tool_env("ember", "A", b"1").unwrap();
        vault.store_tool_env("ember", "B", b"2").unwrap();
        vault.store_tool_env("shannon", "C", b"3").unwrap();

        let scope = vault.scope_ref("tools/ember/");
        assert_eq!(scope.count(), 2);
    }

    #[test]
    fn test_scope_ref_to_provider() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_provider("anthropic", "api_key", b"sk-scope-ref").unwrap();

        {
            let mut scope = vault.scope("tools/shannon");
            scope.store_ref("ANTHROPIC_API_KEY", "providers/anthropic/api_key").unwrap();
            scope.store("MODEL", b"claude-sonnet-4-20250514").unwrap();
        }

        let scope = vault.scope_ref("tools/shannon/");
        assert_eq!(scope.retrieve("ANTHROPIC_API_KEY").unwrap(), b"sk-scope-ref");
        assert_eq!(scope.retrieve("MODEL").unwrap(), b"claude-sonnet-4-20250514");
    }

    // ====================================================================
    // Persistence with tiered entries and refs
    // ====================================================================

    #[test]
    fn test_tiered_save_and_load_roundtrip() {
        let dir = std::env::temp_dir().join("zp-vault-test-tiered-rt");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-tiered.json");
        let _ = std::fs::remove_file(&vault_path);

        let master_key = [0x55u8; 32];

        {
            let mut vault = CredentialVault::new(&master_key);
            vault.store_provider("openai", "api_key", b"sk-persist").unwrap();
            vault.store_tool_ref("ember", "KEY", "openai", "api_key").unwrap();
            vault.store_tool_env("ember", "MODEL", b"gpt-4o").unwrap();
            vault.save(&vault_path).unwrap();
        }

        {
            let vault = CredentialVault::load_or_create(&master_key, &vault_path).unwrap();
            assert_eq!(vault.count(), 3);

            // Provider value
            assert_eq!(
                vault.retrieve("providers/openai/api_key").unwrap(),
                b"sk-persist"
            );

            // Ref chases to provider
            assert_eq!(
                vault.retrieve("tools/ember/KEY").unwrap(),
                b"sk-persist"
            );

            // Tool local value
            assert_eq!(
                vault.retrieve("tools/ember/MODEL").unwrap(),
                b"gpt-4o"
            );
        }

        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_legacy_format_auto_upgrade() {
        let dir = std::env::temp_dir().join("zp-vault-test-legacy-upgrade");
        let _ = std::fs::create_dir_all(&dir);
        let vault_path = dir.join("vault-legacy.json");

        let master_key = [0x66u8; 32];

        // Write a legacy-format vault (flat EncryptedCredential, no VaultEntry wrapper)
        {
            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);

            let cipher = ChaCha20Poly1305::new_from_slice(&master_key).unwrap();
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, b"legacy-value" as &[u8]).unwrap();

            let mut legacy_map: HashMap<String, EncryptedCredential> = HashMap::new();
            legacy_map.insert(
                "openai/api_key".to_string(),
                EncryptedCredential {
                    nonce: nonce_bytes,
                    ciphertext,
                },
            );

            let json = serde_json::to_string_pretty(&legacy_map).unwrap();
            std::fs::write(&vault_path, json).unwrap();
        }

        // Load should auto-detect legacy format
        let vault = CredentialVault::load_or_create(&master_key, &vault_path).unwrap();
        assert_eq!(vault.count(), 1);
        assert_eq!(
            vault.retrieve("openai/api_key").unwrap(),
            b"legacy-value"
        );

        // Verify the entry was wrapped as Value with tier: None
        match vault.entries.get("openai/api_key").unwrap() {
            VaultEntry::Value { tier, .. } => assert_eq!(*tier, None),
            _ => panic!("expected Value"),
        }

        let _ = std::fs::remove_file(&vault_path);
        let _ = std::fs::remove_dir(&dir);
    }

    // ====================================================================
    // Provider rotation propagation test
    // ====================================================================

    #[test]
    fn test_provider_rotation_propagates_to_tools() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        // Initial provider credential
        vault.store_provider("openai", "api_key", b"sk-old-key").unwrap();

        // Two tools reference the same provider
        vault.store_tool_ref("ember", "OPENAI_API_KEY", "openai", "api_key").unwrap();
        vault.store_tool_ref("shannon", "OPENAI_API_KEY", "openai", "api_key").unwrap();

        // Both tools see old key
        assert_eq!(
            vault.resolve_tool_env("ember").unwrap().get("OPENAI_API_KEY").unwrap(),
            b"sk-old-key"
        );
        assert_eq!(
            vault.resolve_tool_env("shannon").unwrap().get("OPENAI_API_KEY").unwrap(),
            b"sk-old-key"
        );

        // Rotate the provider credential
        vault.store_provider("openai", "api_key", b"sk-new-key").unwrap();

        // Both tools now see new key — zero manual intervention
        assert_eq!(
            vault.resolve_tool_env("ember").unwrap().get("OPENAI_API_KEY").unwrap(),
            b"sk-new-key"
        );
        assert_eq!(
            vault.resolve_tool_env("shannon").unwrap().get("OPENAI_API_KEY").unwrap(),
            b"sk-new-key"
        );
    }

    // ====================================================================
    // list_prefix test
    // ====================================================================

    #[test]
    fn test_list_prefix() {
        let master_key = [0x42u8; 32];
        let mut vault = CredentialVault::new(&master_key);

        vault.store_provider("openai", "api_key", b"sk").unwrap();
        vault.store_provider("anthropic", "api_key", b"sk").unwrap();
        vault.store_tool_env("ember", "PORT", b"9100").unwrap();

        let providers = vault.list_prefix("providers/");
        assert_eq!(providers.len(), 2);

        let tools = vault.list_prefix("tools/");
        assert_eq!(tools.len(), 1);
    }
}
