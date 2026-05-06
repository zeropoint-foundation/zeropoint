//! Test-only helpers for `zp-keys`. **Never enable in production.**
//!
//! Gated behind `cfg(any(test, feature = "test-support"))` so production
//! builds can't reach this module. External test crates that need the
//! helpers (e.g. `zp-hardening-tests`) opt in by enabling the
//! `test-support` feature on their `zp-keys` dev-dependency.
//!
//! # Why a hand-rolled mock instead of `keyring::mock`
//!
//! `keyring` v3.6.3's `mock` module is opaque — its credential-builder
//! exhibited behavior where `set_password` followed by `get_password` on
//! a different `Entry::new(...)` instance with the same `(service, user)`
//! pair didn't round-trip in our test harness. Rather than diagnose a
//! third-party module's internals, this file implements the
//! `CredentialBuilderApi` and `CredentialApi` traits directly with an
//! `Arc<Mutex<HashMap>>` shared across every credential the builder
//! produces. Round-trip semantics are deterministic and obvious.
//!
//! # Why this earns its place in the codebase
//!
//! macOS Keychain (and Linux Secret Service, Windows Credential Manager)
//! bind ACLs to the calling binary's code-signature hash. When `cargo
//! test` rebuilds a test binary, the new signature differs from any
//! prior signature that wrote to the keychain entry. Behavior under
//! that mismatch is hostile: the kernel may prompt, may silently drop
//! a `set_password` write while returning Ok at the API level, or may
//! return cached pre-rebuild data on `get_password`. The substrate's
//! tests can't reliably round-trip credentials through the OS Keychain
//! across rebuilds. The mock backend turns the credential store into
//! a deterministic in-process map for tests, eliminating both the
//! prompt churn and the silent-replacement-failure pattern.
//!
//! Pairs with the Seam 11 namespace guard (`ZP_KEYCHAIN_TEST_NAMESPACE`)
//! as defense in depth: even on a code path that bypasses the mock for
//! some reason, the test-suffixed namespace is still used.

#[cfg(feature = "os-keychain")]
mod inner {
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, Once, OnceLock};

    use keyring::credential::{Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence};
    use keyring::Result as KeyringResult;

    /// Storage key: `(target, service, user)`. `target` is rarely used
    /// on macOS but the keyring API includes it; we track it for parity.
    type StorageKey = (Option<String>, String, String);
    type Storage = Arc<Mutex<HashMap<StorageKey, String>>>;

    /// In-memory `CredentialBuilderApi` implementation.
    ///
    /// All credentials produced by one builder share the same backing
    /// `HashMap`, so an `Entry::new(...).set_password(x)` followed by
    /// a fresh `Entry::new(...).get_password()` with the same identity
    /// triple round-trips deterministically.
    pub(super) struct InMemoryBuilder {
        storage: Storage,
    }

    impl InMemoryBuilder {
        fn new() -> Self {
            Self {
                storage: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl CredentialBuilderApi for InMemoryBuilder {
        fn build(
            &self,
            target: Option<&str>,
            service: &str,
            user: &str,
        ) -> KeyringResult<Box<Credential>> {
            Ok(Box::new(InMemoryCredential {
                storage: Arc::clone(&self.storage),
                key: (
                    target.map(String::from),
                    service.to_string(),
                    user.to_string(),
                ),
            }))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn persistence(&self) -> CredentialPersistence {
            // The map dies with the process. That's the point — tests
            // shouldn't leave persistent state behind.
            CredentialPersistence::ProcessOnly
        }
    }

    struct InMemoryCredential {
        storage: Storage,
        key: StorageKey,
    }

    impl CredentialApi for InMemoryCredential {
        fn set_password(&self, password: &str) -> KeyringResult<()> {
            self.storage
                .lock()
                .expect("InMemoryBuilder mutex poisoned")
                .insert(self.key.clone(), password.to_string());
            Ok(())
        }

        fn set_secret(&self, secret: &[u8]) -> KeyringResult<()> {
            // Many callers in zp-keys use `set_password` (hex-encoded
            // strings); some may call `set_secret` with raw bytes.
            // Store as UTF-8 if possible, otherwise hex — and read
            // back symmetrically in `get_secret`. Hex is already a
            // direct dep of `zp-keys`, so we don't need to pull in
            // base64 just for this fallback. For zp-keys' actual
            // usage (hex strings of Ed25519 secrets), the UTF-8 path
            // is always taken.
            match std::str::from_utf8(secret) {
                Ok(s) => self.set_password(s),
                Err(_) => {
                    let encoded = hex::encode(secret);
                    self.set_password(&format!("__hex__{}", encoded))
                }
            }
        }

        fn get_password(&self) -> KeyringResult<String> {
            self.storage
                .lock()
                .expect("InMemoryBuilder mutex poisoned")
                .get(&self.key)
                .cloned()
                .ok_or(keyring::Error::NoEntry)
        }

        fn get_secret(&self) -> KeyringResult<Vec<u8>> {
            let p = self.get_password()?;
            if let Some(rest) = p.strip_prefix("__hex__") {
                hex::decode(rest).map_err(|_| keyring::Error::BadEncoding(p.into_bytes()))
            } else {
                Ok(p.into_bytes())
            }
        }

        fn delete_credential(&self) -> KeyringResult<()> {
            let removed = self
                .storage
                .lock()
                .expect("InMemoryBuilder mutex poisoned")
                .remove(&self.key);
            if removed.is_some() {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    /// Process-global guard so the mock builder is installed at most once.
    static INSTALLED: OnceLock<()> = OnceLock::new();
    static INSTALL_ONCE: Once = Once::new();

    pub(super) fn install() {
        INSTALL_ONCE.call_once(|| {
            // Always set the namespace var as defense in depth, even if
            // the credential builder install below somehow no-ops.
            std::env::set_var("ZP_KEYCHAIN_TEST_NAMESPACE", "1");

            let builder = InMemoryBuilder::new();
            keyring::set_default_credential_builder(Box::new(builder));

            // Mark that we've successfully installed.
            let _ = INSTALLED.set(());
        });
    }

    #[allow(dead_code)]
    pub(super) fn is_installed() -> bool {
        INSTALLED.get().is_some()
    }
}

/// Install the in-memory mock credential backend as the keyring default.
///
/// Idempotent and concurrency-safe. Once installed, any
/// `keyring::Entry::new(...)` in this process returns an in-memory
/// credential whose `set_password` / `get_password` / `delete_credential`
/// operate on a shared `HashMap`. The OS Keychain is not touched.
///
/// Call this from test harness setup before any code path that may
/// reach `keyring::Entry`. The first call installs; subsequent calls
/// are no-ops.
///
/// Sets `ZP_KEYCHAIN_TEST_NAMESPACE=1` even when the install is a no-op,
/// so the Seam 11 namespace guard kicks in either way.
#[cfg(feature = "os-keychain")]
pub fn install_mock_keyring() {
    inner::install();
}

/// No-op variant for builds without the `os-keychain` feature.
#[cfg(not(feature = "os-keychain"))]
pub fn install_mock_keyring() {
    // No keyring dep means no OS Keychain interaction means nothing to mock.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// install_mock_keyring is idempotent — calling it many times is safe.
    #[test]
    fn install_is_idempotent() {
        install_mock_keyring();
        install_mock_keyring();
        install_mock_keyring();
    }

    /// install_mock_keyring sets the namespace env var on first call.
    #[cfg(feature = "os-keychain")]
    #[test]
    fn install_sets_namespace_env_var() {
        install_mock_keyring();
        assert_eq!(
            std::env::var("ZP_KEYCHAIN_TEST_NAMESPACE").unwrap(),
            "1",
            "install_mock_keyring must set the namespace guard"
        );
    }

    /// Round-trip: a fresh `Entry::new` with the same identity triple
    /// reads back what a prior `Entry::new` wrote. This is the property
    /// that the third-party mock module didn't satisfy in our harness.
    #[cfg(feature = "os-keychain")]
    #[test]
    fn mock_round_trips_across_entry_instances() {
        install_mock_keyring();
        let svc = "zp-test-mock-rt-service";
        let acct = "zp-test-mock-rt-account";

        // Two distinct Entry instances with the same identity.
        let writer = keyring::Entry::new(svc, acct).expect("Entry::new write");
        writer.set_password("secret-bytes").expect("set_password");

        let reader = keyring::Entry::new(svc, acct).expect("Entry::new read");
        let read = reader.get_password().expect("get_password");
        assert_eq!(read, "secret-bytes");

        // Cleanup so the in-process map doesn't pollute later tests in
        // this binary that use the same identity.
        let _ = reader.delete_credential();
    }

    /// Distinct identities don't see each other's data.
    #[cfg(feature = "os-keychain")]
    #[test]
    fn mock_isolates_distinct_identities() {
        install_mock_keyring();
        let a = keyring::Entry::new("zp-test-iso-svc-a", "user-a").unwrap();
        let b = keyring::Entry::new("zp-test-iso-svc-b", "user-b").unwrap();

        a.set_password("alpha").unwrap();
        b.set_password("beta").unwrap();

        assert_eq!(a.get_password().unwrap(), "alpha");
        assert_eq!(b.get_password().unwrap(), "beta");

        let _ = a.delete_credential();
        let _ = b.delete_credential();
    }

    /// delete_credential removes the entry; subsequent get returns NoEntry.
    #[cfg(feature = "os-keychain")]
    #[test]
    fn mock_delete_then_get_returns_no_entry() {
        install_mock_keyring();
        let e = keyring::Entry::new("zp-test-del-svc", "user").unwrap();
        e.set_password("doomed").unwrap();
        e.delete_credential().unwrap();

        match e.get_password() {
            Err(keyring::Error::NoEntry) => {}
            other => panic!("expected NoEntry after delete, got {:?}", other),
        }
    }
}
