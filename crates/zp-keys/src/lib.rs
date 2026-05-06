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

pub mod audit_signer;
pub mod biometric;
pub mod blast_radius;
pub mod certificate;
pub mod error;
pub mod genesis_v2;
pub mod hierarchy;
pub mod keyring;
pub mod recovery;
pub mod revocation;
pub mod rotation;
pub mod secret_file;
pub mod sovereignty;
#[cfg(any(test, feature = "test-support"))]
pub mod test_helpers;
pub mod vault_key;

#[cfg(test)]
pub(crate) mod test_sync {
    //! Shared lock to serialize tests that touch process-global state —
    //! the OS credential store entries and the `ZP_VAULT_KEY` env var.
    //!
    //! # Auto-installs the mock keyring backend
    //!
    //! `serial_guard()` calls
    //! [`crate::test_helpers::install_mock_keyring`] on first invocation
    //! (idempotent via `Once`). The hand-rolled in-memory builder lives
    //! in this crate, gives deterministic round-trip semantics, and
    //! removes the OS-Keychain-ACL-on-rebuilt-binary fragility that
    //! caused the May 2026 test-flake debugging session. Tests that
    //! touch `keyring::Entry` always go through the mock; the real OS
    //! Keychain is not touched during `cargo test -p zp-keys`.
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    pub fn serial_guard() -> MutexGuard<'static, ()> {
        // Install the in-memory mock keyring before any test reaches
        // `keyring::Entry`. Idempotent. The mock is shared across all
        // entries the builder creates, so set/get round-trips work
        // deterministically across `Entry::new(...)` calls with the
        // same identity triple.
        crate::test_helpers::install_mock_keyring();

        match LOCK.lock() {
            Ok(g) => g,
            // If a previous test panicked while holding the lock,
            // reset and continue — we still want serialization.
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

// ── Blast radius (Phase 3 R6-1) ──
pub use blast_radius::{BlastRadius, BlastRadiusTracker, CompromiseResponse, DelegationEdge};

// ── Sovereignty system (new) ──
pub use sovereignty::{
    detect_all_providers, provider_for, BiometricEvidence, EnrollmentResult, ProviderCapabilities,
    ProviderCapability, SovereigntyCategory, SovereigntyMode, SovereigntyProvider,
};

// ── Hardware wallet infrastructure (quorum-ready) ──
pub use sovereignty::hardware::{
    rewrap_secret, DerivationSalt, EnrollmentMetadata, QuorumThreshold,
};

// ── Backward-compatible re-exports ──
// These delegate to sovereignty::detection, which wraps the new provider system.
pub use sovereignty::detection::{detect_biometric, BiometricCapability, BiometricType, Platform};

pub use certificate::{Certificate, CertificateChain, KeyRole};
pub use error::KeyError;
pub use hierarchy::{AgentKey, GenesisKey, OperatorKey};
pub use keyring::Keyring;
pub use recovery::{decode_mnemonic, encode_mnemonic, verify_recovery};
pub use revocation::{
    verify_chain_with_revocation, RevocationCertificate, RevocationReason, RevocationStatus,
    RevocationStore,
};
pub use rotation::{RotationCertificate, RotationChain};
pub use audit_signer::derive_audit_signer_seed;
pub use secret_file::write_atomic as write_secret_file;
pub use vault_key::{derive_vault_key, resolve_vault_key, ResolvedVaultKey, VaultKeySource};
