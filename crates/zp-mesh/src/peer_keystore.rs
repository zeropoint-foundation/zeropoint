//! Peer verifying-key registry.
//!
//! Sweep 6 (docs/rfc-mesh-inbound-auth-v1.md §3.1). A trait the mesh bridge
//! consults to resolve an ed25519 verifying key for a sender peer hash.
//! Callers register keys as peer links come up; the bridge reads them when
//! verifying inbound payload signatures.
//!
//! This is intentionally minimal. The production wiring (trust-on-first-use,
//! persistence, revocation) is Sweep 7+ work. This trait exists so
//! `MeshBridge` can depend on the *interface*, not on any particular
//! keystore implementation.

use std::collections::HashMap;
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;

/// Resolver for peer verifying keys, keyed by the 16-byte peer hash used
/// throughout `zp-mesh` (see `identity.rs`).
pub trait PeerKeyStore: Send + Sync {
    /// Returns the verifying key registered for `peer_hash`, if any.
    fn verifying_key(&self, peer_hash: &[u8; 16]) -> Option<VerifyingKey>;
}

/// Trivial in-memory keystore. Not persisted. Useful for tests and for the
/// first Sweep 6 integration pass where keys are registered at link-up time
/// and live only in the running process.
#[derive(Default)]
pub struct InMemoryPeerKeyStore {
    inner: RwLock<HashMap<[u8; 16], VerifyingKey>>,
}

impl InMemoryPeerKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the verifying key for `peer_hash`.
    pub fn insert(&self, peer_hash: [u8; 16], key: VerifyingKey) {
        self.inner
            .write()
            .expect("keystore rwlock poisoned")
            .insert(peer_hash, key);
    }

    /// Remove a peer's registered key.
    pub fn remove(&self, peer_hash: &[u8; 16]) {
        self.inner
            .write()
            .expect("keystore rwlock poisoned")
            .remove(peer_hash);
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("keystore rwlock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl PeerKeyStore for InMemoryPeerKeyStore {
    fn verifying_key(&self, peer_hash: &[u8; 16]) -> Option<VerifyingKey> {
        self.inner
            .read()
            .expect("keystore rwlock poisoned")
            .get(peer_hash)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn insert_and_lookup_roundtrip() {
        let store = InMemoryPeerKeyStore::new();
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let peer = [7u8; 16];

        assert!(store.verifying_key(&peer).is_none());
        store.insert(peer, verifying);
        let got = store.verifying_key(&peer).unwrap();
        assert_eq!(got.to_bytes(), verifying.to_bytes());
        assert_eq!(store.len(), 1);

        store.remove(&peer);
        assert!(store.verifying_key(&peer).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn missing_peer_returns_none() {
        let store = InMemoryPeerKeyStore::new();
        assert!(store.verifying_key(&[0u8; 16]).is_none());
    }
}
