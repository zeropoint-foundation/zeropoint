//! ZeroPoint Key Hierarchy — cryptographic foundation for trust distribution.
//!
//! This crate defines the three-level key hierarchy that underpins all trust
//! relationships in ZeroPoint:
//!
//! ```text
//! GenesisKey          ← self-signed root of trust (one per deployment)
//!   └─ OperatorKey    ← signed by genesis (one per node operator)
//!       └─ AgentKey   ← signed by operator (one per agent instance)
//! ```
//!
//! The hierarchy is a cryptographic primitive — it exists below the policy
//! engine and does not depend on it. Verification is deterministic: given
//! a chain of certificates, you can verify it offline with no network or
//! policy state required.
//!
//! The policy engine can *govern* when delegation happens (via ActionType::KeyDelegation),
//! but the mechanism itself is unconditional. This prevents circular dependencies
//! between key distribution and policy evaluation.

pub mod biometric;
pub mod certificate;
pub mod error;
pub mod hierarchy;
pub mod keyring;
pub mod recovery;
pub mod sovereignty;
pub mod vault_key;

// ── Sovereignty system (new) ──
pub use sovereignty::{
    SovereigntyMode, SovereigntyProvider, SovereigntyCategory,
    ProviderCapability, ProviderCapabilities, EnrollmentResult,
    detect_all_providers, provider_for,
};

// ── Hardware wallet infrastructure (quorum-ready) ──
pub use sovereignty::hardware::{
    EnrollmentMetadata, QuorumThreshold, DerivationSalt,
    rewrap_secret,
};

// ── Backward-compatible re-exports ──
// These delegate to sovereignty::detection, which wraps the new provider system.
pub use sovereignty::detection::{
    detect_biometric, BiometricCapability, BiometricType, Platform,
};

pub use certificate::{Certificate, CertificateChain, KeyRole};
pub use error::KeyError;
pub use hierarchy::{AgentKey, GenesisKey, OperatorKey};
pub use keyring::Keyring;
pub use recovery::{decode_mnemonic, encode_mnemonic, verify_recovery};
pub use vault_key::{derive_vault_key, resolve_vault_key, ResolvedVaultKey, VaultKeySource};
