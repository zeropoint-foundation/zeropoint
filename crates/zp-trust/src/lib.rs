//! ZeroPoint Trust Infrastructure (zp-trust)
//!
//! This crate provides the trust and credential management infrastructure for ZeroPoint v2,
//! including:
//!
//! - **Vault**: Secure encrypted storage for credentials at rest using ChaCha20-Poly1305
//! - **Injector**: Policy-based credential injection for skills with fine-grained access control
//! - **Signer**: Cryptographic signing infrastructure for trust tiers using Ed25519
//!
//! All sensitive data is automatically zeroized on drop to prevent information leakage.

#![warn(missing_docs)]

pub mod injector;
pub mod signer;
pub mod vault;

// Re-exports
pub use injector::{
    CredentialInjector, InjectorError, InjectorResult, PolicyCheckFn, PolicyContext,
};
pub use signer::{Signer, SignerError, SignerResult};
pub use vault::{
    CredentialVault, EncryptedCredential, VaultEntry, VaultError, VaultResult, VaultScope,
    VaultScopeRef, VaultTier,
};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
