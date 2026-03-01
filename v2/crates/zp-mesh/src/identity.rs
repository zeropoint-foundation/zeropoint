//! Mesh identity — Ed25519 + X25519 keypair.
//!
//! Every agent on the mesh has an identity consisting of:
//! - An **Ed25519 signing keypair** (256-bit) for authentication and receipts
//! - An **X25519 encryption keypair** (256-bit) for key exchange
//!
//! The combined 512-bit public key uniquely identifies the agent.
//! Destination addresses derive from SHA-256 of this public key (truncated to 128 bits).
//!
//! This mirrors the Reticulum identity model exactly, enabling interop
//! with Reticulum nodes running MeshChat, Sideband, or NomadNet.

use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::error::{MeshError, MeshResult};

/// Combined public key: 32 bytes Ed25519 + 32 bytes X25519 = 64 bytes.
pub const PUBLIC_KEY_SIZE: usize = 64;

/// A mesh agent identity — the cryptographic root of trust.
///
/// Contains both signing (Ed25519) and encryption (X25519) keypairs.
/// The signing key is shared with `zp-trust::Signer` for receipt signing.
/// The encryption key enables forward-secret key exchange over the mesh.
pub struct MeshIdentity {
    /// Ed25519 signing key (for authentication, receipts, announces)
    signing_key: SigningKey,
    /// X25519 static secret (for ECDH key exchange)
    encryption_secret: StaticSecret,
    /// Cached X25519 public key
    encryption_public: X25519PublicKey,
}

impl MeshIdentity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let encryption_secret = StaticSecret::random_from_rng(OsRng);
        let encryption_public = X25519PublicKey::from(&encryption_secret);
        Self {
            signing_key,
            encryption_secret,
            encryption_public,
        }
    }

    /// Create from existing Ed25519 secret key bytes.
    ///
    /// Derives the X25519 key deterministically from the Ed25519 secret
    /// using HKDF, so that `zp-trust::Signer` keys can be promoted to
    /// mesh identities without managing two separate secrets.
    pub fn from_ed25519_secret(secret: &[u8; 32]) -> MeshResult<Self> {
        let signing_key = SigningKey::from_bytes(secret);

        // Derive X25519 secret deterministically from Ed25519 secret via HKDF.
        // This lets an agent's zp-trust signing key and mesh encryption key
        // share a single secret seed.
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"zp-mesh-x25519-derive-v1"), secret);
        let mut x_secret_bytes = [0u8; 32];
        hk.expand(b"x25519-static-secret", &mut x_secret_bytes)
            .map_err(|e| MeshError::InvalidKeyMaterial(e.to_string()))?;

        let encryption_secret = StaticSecret::from(x_secret_bytes);
        let encryption_public = X25519PublicKey::from(&encryption_secret);

        Ok(Self {
            signing_key,
            encryption_secret,
            encryption_public,
        })
    }

    /// Create from a `zp-trust::Signer` — promotes a trust-layer identity to mesh.
    pub fn from_signer(signer: &zp_trust::Signer) -> MeshResult<Self> {
        Self::from_ed25519_secret(&signer.secret_key())
    }

    // ── Public keys ──────────────────────────────────────────────

    /// The Ed25519 verifying (public) key — 32 bytes.
    pub fn signing_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// The X25519 public key — 32 bytes.
    pub fn encryption_public_key(&self) -> [u8; 32] {
        self.encryption_public.to_bytes()
    }

    /// Combined 64-byte public key (Ed25519 ‖ X25519).
    ///
    /// This is the canonical identity representation on the mesh —
    /// the same format Reticulum uses for announce packets.
    pub fn combined_public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let mut combined = [0u8; PUBLIC_KEY_SIZE];
        combined[..32].copy_from_slice(&self.signing_public_key());
        combined[32..].copy_from_slice(&self.encryption_public_key());
        combined
    }

    /// Compute the 128-bit destination hash for this identity.
    ///
    /// This is the address used in packet routing — SHA-256 of the
    /// combined public key, truncated to 16 bytes.
    pub fn destination_hash(&self) -> [u8; 16] {
        let mut hasher = Sha256::new();
        hasher.update(self.combined_public_key());
        let full_hash = hasher.finalize();
        let mut truncated = [0u8; 16];
        truncated.copy_from_slice(&full_hash[..16]);
        truncated
    }

    /// Human-readable hex representation of the destination hash.
    pub fn address(&self) -> String {
        hex::encode(self.destination_hash())
    }

    // ── Signing ──────────────────────────────────────────────────

    /// Sign data with the Ed25519 key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        let sig = self.signing_key.sign(data);
        sig.to_bytes()
    }

    /// Verify a signature against this identity's public key.
    pub fn verify(&self, data: &[u8], signature: &[u8; 64]) -> bool {
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.signing_key
            .verifying_key()
            .verify_strict(data, &sig)
            .is_ok()
    }

    /// Verify a signature against an arbitrary Ed25519 public key.
    pub fn verify_with_key(
        public_key: &[u8; 32],
        data: &[u8],
        signature: &[u8; 64],
    ) -> MeshResult<bool> {
        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| MeshError::InvalidKeyMaterial("invalid Ed25519 public key".into()))?;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        Ok(verifying_key.verify_strict(data, &sig).is_ok())
    }

    // ── Key exchange ─────────────────────────────────────────────

    /// Perform X25519 Diffie-Hellman key exchange with a peer's public key.
    ///
    /// Returns the 32-byte shared secret. Both sides compute the same value.
    pub fn key_exchange(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer = X25519PublicKey::from(*peer_public);
        self.encryption_secret.diffie_hellman(&peer).to_bytes()
    }

    /// Derive symmetric session keys from a shared secret using HKDF.
    ///
    /// Returns (encrypt_key, decrypt_key, hmac_key) — each 32 bytes.
    /// The `initiator` flag ensures each side uses opposite encrypt/decrypt keys.
    pub fn derive_session_keys(
        shared_secret: &[u8; 32],
        initiator: bool,
    ) -> MeshResult<([u8; 32], [u8; 32], [u8; 32])> {
        let hk = hkdf::Hkdf::<Sha256>::new(Some(b"zp-mesh-link-keys-v1"), shared_secret);

        let mut key_a = [0u8; 32];
        let mut key_b = [0u8; 32];
        let mut hmac_key = [0u8; 32];

        hk.expand(b"link-key-a", &mut key_a)
            .map_err(|e| MeshError::KeyExchangeFailed(e.to_string()))?;
        hk.expand(b"link-key-b", &mut key_b)
            .map_err(|e| MeshError::KeyExchangeFailed(e.to_string()))?;
        hk.expand(b"link-hmac-key", &mut hmac_key)
            .map_err(|e| MeshError::KeyExchangeFailed(e.to_string()))?;

        if initiator {
            Ok((key_a, key_b, hmac_key))
        } else {
            Ok((key_b, key_a, hmac_key))
        }
    }

    // ── Secret access (for persistence) ──────────────────────────

    /// Export the Ed25519 secret key bytes. Handle with care.
    pub fn signing_secret(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }
}

impl std::fmt::Debug for MeshIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeshIdentity")
            .field("address", &self.address())
            .field("signing_pub", &hex::encode(self.signing_public_key()))
            .field("encryption_pub", &hex::encode(self.encryption_public_key()))
            .finish()
    }
}

impl std::fmt::Display for MeshIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<{}>", self.address())
    }
}

/// A verified peer identity — public keys only (no secrets).
///
/// Learned from announce packets or link establishment.
/// Stored in the mesh routing table for destination resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerIdentity {
    /// Ed25519 public key — 32 bytes
    pub signing_key: [u8; 32],
    /// X25519 public key — 32 bytes
    pub encryption_key: [u8; 32],
    /// Cached 128-bit destination hash
    pub destination_hash: [u8; 16],
    /// When this identity was first seen
    pub first_seen: chrono::DateTime<chrono::Utc>,
    /// When this identity was last announced
    pub last_announced: chrono::DateTime<chrono::Utc>,
    /// Number of hops in the last announce
    pub hops: u8,
}

impl PeerIdentity {
    /// Reconstruct from combined 64-byte public key (from announce packet).
    pub fn from_combined_key(combined: &[u8; PUBLIC_KEY_SIZE], hops: u8) -> MeshResult<Self> {
        let mut signing_key = [0u8; 32];
        let mut encryption_key = [0u8; 32];
        signing_key.copy_from_slice(&combined[..32]);
        encryption_key.copy_from_slice(&combined[32..]);

        // Verify the destination hash matches
        let mut hasher = Sha256::new();
        hasher.update(combined);
        let full_hash = hasher.finalize();
        let mut destination_hash = [0u8; 16];
        destination_hash.copy_from_slice(&full_hash[..16]);

        let now = chrono::Utc::now();
        Ok(Self {
            signing_key,
            encryption_key,
            destination_hash,
            first_seen: now,
            last_announced: now,
            hops,
        })
    }

    /// Hex address string.
    pub fn address(&self) -> String {
        hex::encode(self.destination_hash)
    }

    /// Verify a signature from this peer.
    pub fn verify(&self, data: &[u8], signature: &[u8; 64]) -> MeshResult<bool> {
        MeshIdentity::verify_with_key(&self.signing_key, data, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = MeshIdentity::generate();
        assert_eq!(id.signing_public_key().len(), 32);
        assert_eq!(id.encryption_public_key().len(), 32);
        assert_eq!(id.combined_public_key().len(), 64);
        assert_eq!(id.destination_hash().len(), 16);
        assert_eq!(id.address().len(), 32); // 16 bytes = 32 hex chars
    }

    #[test]
    fn test_deterministic_from_secret() {
        let secret = [0x42u8; 32];
        let id1 = MeshIdentity::from_ed25519_secret(&secret).unwrap();
        let id2 = MeshIdentity::from_ed25519_secret(&secret).unwrap();

        assert_eq!(id1.signing_public_key(), id2.signing_public_key());
        assert_eq!(id1.encryption_public_key(), id2.encryption_public_key());
        assert_eq!(id1.destination_hash(), id2.destination_hash());
    }

    #[test]
    fn test_sign_and_verify() {
        let id = MeshIdentity::generate();
        let data = b"test message for mesh transport";
        let sig = id.sign(data);

        assert!(id.verify(data, &sig));
        assert!(!id.verify(b"tampered", &sig));
    }

    #[test]
    fn test_key_exchange_symmetric() {
        let alice = MeshIdentity::generate();
        let bob = MeshIdentity::generate();

        let shared_a = alice.key_exchange(&bob.encryption_public_key());
        let shared_b = bob.key_exchange(&alice.encryption_public_key());

        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_session_key_derivation() {
        let shared_secret = [0xAB; 32];

        let (enc_i, dec_i, hmac_i) =
            MeshIdentity::derive_session_keys(&shared_secret, true).unwrap();
        let (enc_r, dec_r, hmac_r) =
            MeshIdentity::derive_session_keys(&shared_secret, false).unwrap();

        // Initiator's encrypt key = Responder's decrypt key (and vice versa)
        assert_eq!(enc_i, dec_r);
        assert_eq!(dec_i, enc_r);
        // HMAC key is the same for both sides
        assert_eq!(hmac_i, hmac_r);
    }

    #[test]
    fn test_from_signer_compatibility() {
        let signer = zp_trust::Signer::generate();
        let mesh_id = MeshIdentity::from_signer(&signer).unwrap();

        // The Ed25519 signing key should produce the same public key
        assert_eq!(mesh_id.signing_public_key(), signer.public_key());
    }

    #[test]
    fn test_peer_identity_from_combined() {
        let id = MeshIdentity::generate();
        let combined = id.combined_public_key();
        let peer = PeerIdentity::from_combined_key(&combined, 3).unwrap();

        assert_eq!(peer.destination_hash, id.destination_hash());
        assert_eq!(peer.signing_key, id.signing_public_key());
        assert_eq!(peer.encryption_key, id.encryption_public_key());
        assert_eq!(peer.hops, 3);
    }

    #[test]
    fn test_peer_verify_signature() {
        let id = MeshIdentity::generate();
        let data = b"peer verification test";
        let sig = id.sign(data);

        let peer = PeerIdentity::from_combined_key(&id.combined_public_key(), 0).unwrap();
        assert!(peer.verify(data, &sig).unwrap());
    }

    #[test]
    fn test_display_format() {
        let id = MeshIdentity::generate();
        let display = format!("{}", id);
        assert!(display.starts_with('<'));
        assert!(display.ends_with('>'));
        assert_eq!(display.len(), 34); // <32 hex chars>
    }
}
