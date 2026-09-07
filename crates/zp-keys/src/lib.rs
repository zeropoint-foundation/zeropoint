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
pub mod foundation_edge_signer;
pub mod gate_signer;
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

// ── Blast radius (Phase 3 R6-1) ──
pub use blast_radius::{BlastRadius, BlastRadiusTracker, CompromiseResponse, DelegationEdge};

// ── Sovereignty system (new) ──
pub use sovereignty::{
    detect_all_providers, load_sovereign_root, provider_for, provider_for_genesis_record,
    BiometricEvidence, EnrollmentResult, ProviderCapabilities, ProviderCapability,
    SovereigntyCategory, SovereigntyMode, SovereigntyProvider,
};

// ── Hardware wallet infrastructure (quorum-ready) ──
pub use sovereignty::hardware::{
    rewrap_secret, DerivationSalt, EnrollmentMetadata, QuorumThreshold,
};

// ── Backward-compatible re-exports ──
// These delegate to sovereignty::detection, which wraps the new provider system.
pub use sovereignty::detection::{detect_biometric, BiometricCapability, BiometricType, Platform};

pub use audit_signer::derive_audit_signer_seed;
pub use certificate::{Certificate, CertificateChain, KeyRole};
pub use error::KeyError;
pub use foundation_edge_signer::{
    derive_foundation_edge_signer_seed, FOUNDATION_EDGE_SIGNER_CONTEXT,
};
pub use gate_signer::{derive_gate_signer_seed, GATE_SIGNER_CONTEXT};
pub use hierarchy::{AgentKey, GenesisKey, OperatorKey};
pub use keyring::{
    delete_keychain_entry, find_orphan_keychain_entries, harden_key_home, Keyring, OrphanEntry,
};
pub use recovery::{decode_mnemonic, encode_mnemonic, verify_recovery};
pub use revocation::{
    verify_chain_with_revocation, RevocationCertificate, RevocationReason, RevocationStatus,
    RevocationStore,
};
pub use rotation::{RotationCertificate, RotationChain};
pub use secret_file::write_atomic as write_secret_file;
pub use vault_key::{derive_vault_key, resolve_vault_key, ResolvedVaultKey, VaultKeySource};

// ───────────────────────────────────────────────────────────────────────
// Test-only. Kept last in the file: clippy's `items_after_test_module`
// exists because anything declared below a test module reads, to someone
// scanning the file, as test scaffolding rather than public surface — and
// this crate's entire public API was sitting down there.
// ───────────────────────────────────────────────────────────────────────
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
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    static LOCK: Mutex<()> = Mutex::new(());

    /// A serialized test scope with `ZP_HOME` pointed at a fresh temp dir.
    ///
    /// # Why this exists
    ///
    /// [`serial_guard`] installs the mock credential store, which is enough
    /// for anything that reaches `keyring::Entry`. It is **not** enough for
    /// code that resolves ZP-home by path. `vault_key::resolve_vault_key`
    /// consults `zp_core::paths::genesis_record_path()` — `$ZP_HOME/genesis.json`,
    /// defaulting to `~/ZeroPoint/genesis.json` — *before* it looks at the
    /// `Keyring` it was handed. A test that builds a keyring in a temp dir has
    /// therefore isolated the wrong half: the fixture controls the directory,
    /// the code reads the operator's real home.
    ///
    /// The result is a suite that passes on a machine with no provisioned
    /// ZeroPoint install — CI, a fresh checkout — and fails on an operator's,
    /// which is the inverse of what a test should do. Observed 2026-08-12:
    /// eight tests in this crate resolving the operator's live vault key and
    /// asserting against a fixture's.
    ///
    /// # Why the lock is inside the guard
    ///
    /// Mutating `ZP_HOME` is process-global, so it is only safe while holding
    /// `LOCK`. Handing back a separate lock guard and a separate env guard
    /// would let a caller take one without the other. Binding them into one
    /// value makes that unrepresentable — the env var cannot be set except by
    /// constructing this, and it is restored when this drops.
    pub struct IsolatedZpHome {
        // Field order is drop order: release the env var, then the lock.
        prior: Option<OsString>,
        dir: tempfile::TempDir,
        _lock: MutexGuard<'static, ()>,
    }

    impl IsolatedZpHome {
        /// The isolated ZP home root — the value of `ZP_HOME` for this scope.
        pub fn path(&self) -> &Path {
            self.dir.path()
        }

        /// `$ZP_HOME/keys`, the directory a [`crate::Keyring`] opens.
        pub fn keys_dir(&self) -> PathBuf {
            self.dir.path().join("keys")
        }
    }

    impl Drop for IsolatedZpHome {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(prior) => std::env::set_var("ZP_HOME", prior),
                None => std::env::remove_var("ZP_HOME"),
            }
        }
    }

    /// Enter a serialized scope with the mock credential store installed and
    /// `ZP_HOME` isolated to a temp dir. Restores the prior `ZP_HOME` on drop.
    ///
    /// Use this instead of [`serial_guard`] for any test whose subject resolves
    /// paths through `zp_core::paths`. Use `serial_guard` when the test only
    /// touches the credential store or an env var it manages itself.
    pub fn isolated_zp_home() -> IsolatedZpHome {
        let lock = serial_guard();
        let dir = tempfile::tempdir().expect("tempdir for isolated ZP_HOME");
        let prior = std::env::var_os("ZP_HOME");
        std::env::set_var("ZP_HOME", dir.path());
        IsolatedZpHome {
            prior,
            dir,
            _lock: lock,
        }
    }

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
