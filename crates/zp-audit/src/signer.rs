//! Audit-chain signer — owns Ed25519 signing for [`crate::AuditStore::append`].
//!
//! # Where the seed comes from
//!
//! The signer wraps an Ed25519 [`SigningKey`] derived from the Genesis seed
//! by [`zp_keys::derive_audit_signer_seed`]. This crate does not depend on
//! `zp-keys` (to avoid a dep cycle and to keep `AuditStore` testable without
//! a sovereignty unlock); callers in `zp-cli` / `zp-server` are responsible
//! for performing the derivation at startup and constructing an `AuditSigner`
//! via [`AuditSigner::from_seed`].
//!
//! # What it produces
//!
//! [`AuditSigner::sign_entry`] takes a sealed entry hash (the hex string from
//! [`crate::chain::seal_entry`]) and returns a [`SignatureBlock`] ready to be
//! pushed into [`zp_core::AuditEntry::signatures`]:
//!
//! - `algorithm = SignatureAlgorithm::Ed25519`
//! - `key_id    = hex(public_key_bytes)`
//! - `signature_b64 = base64(ed25519_signature)`
//!
//! The signed material is the entry-hash hex string's bytes — same convention
//! the chain verifier reads in [`crate::verifier::ChainVerifier::verify_block`].
//!
//! # Hash-then-sign discipline
//!
//! Sealing computes the entry hash with `signatures: []` (see
//! [`crate::chain::compute_entry_hash`]). Signing happens after sealing,
//! over the resulting hash. The hash is therefore well-defined before
//! any signature exists, and the signature column never feeds back into
//! the hash. This is the standard hash-then-sign pattern; see whitepaper §
//! "signing is gravity."

use ed25519_dalek::{Signer as _, SigningKey};
use zp_core::SignatureBlock;

/// The audit-chain signer.
///
/// Holds an Ed25519 signing key for the lifetime of an [`crate::AuditStore`].
/// `Clone` is intentionally not implemented — exactly one signer should live
/// per store, and duplicating signing keys via Clone is a smell.
pub struct AuditSigner {
    signing_key: SigningKey,
    /// Cached hex-encoded public key, populated lazily for `key_id`.
    public_key_hex: String,
}

impl AuditSigner {
    /// Construct an `AuditSigner` from a 32-byte Ed25519 seed.
    ///
    /// Production callers obtain this seed via
    /// [`zp_keys::derive_audit_signer_seed`] applied to the in-memory Genesis
    /// secret. Tests can pass any 32 bytes; an `AuditSigner::generate()`
    /// helper exists for that purpose.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let public_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        Self {
            signing_key,
            public_key_hex,
        }
    }

    /// Generate a fresh random signer. Test-only — production signers must
    /// be derived from Genesis so chain verification is reproducible from
    /// the sovereignty seed alone.
    #[cfg(test)]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// The hex-encoded 32-byte Ed25519 public key. This is the `key_id`
    /// that appears in every [`SignatureBlock`] this signer produces, and
    /// what the verifier matches against its known-keys list.
    pub fn public_key_hex(&self) -> &str {
        &self.public_key_hex
    }

    /// Sign an entry hash, returning a populated Ed25519 [`SignatureBlock`].
    ///
    /// `entry_hash` is the hex string returned by
    /// [`crate::chain::seal_entry`] — the bytes of that string (not the
    /// hex-decoded raw hash) are what get signed. This matches the
    /// verifier's `entry.entry_hash.as_bytes()` convention.
    pub fn sign_entry(&self, entry_hash: &str) -> SignatureBlock {
        use base64::Engine;
        let signature = self.signing_key.sign(entry_hash.as_bytes());
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
        SignatureBlock::ed25519(&self.public_key_hex, &signature_b64)
    }
}

impl std::fmt::Debug for AuditSigner {
    /// Redact the signing key in debug output. The public key is fine to
    /// print; the secret material never appears in logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSigner")
            .field("public_key_hex", &self.public_key_hex)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::SignatureAlgorithm;

    #[test]
    fn sign_then_verify_roundtrips() {
        use base64::Engine;

        let seed = [0x55u8; 32];
        let signer = AuditSigner::from_seed(&seed);
        let entry_hash = "deadbeef".repeat(8); // 64-char hex

        let block = signer.sign_entry(&entry_hash);
        assert!(matches!(block.algorithm, SignatureAlgorithm::Ed25519));
        assert_eq!(block.key_id, signer.public_key_hex);

        // Verify the produced signature via the canonical primitive (Seam 5).
        let pk_bytes = hex::decode(&block.key_id).expect("key_id is hex");
        let pk_array: [u8; 32] = pk_bytes.try_into().unwrap();

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&block.signature_b64)
            .expect("signature_b64 is base64");
        let sig_array: [u8; 64] = sig_bytes.try_into().unwrap();

        // Same primitive the chain verifier uses.
        zp_receipt::verify::verify_signature(&pk_array, entry_hash.as_bytes(), &sig_array)
            .expect("signature must verify under the signer's own pk");

        // Sanity: a malformed entry_hash must NOT verify under the same sig.
        let wrong_hash = "ff".repeat(32);
        assert!(zp_receipt::verify::verify_signature(
            &pk_array,
            wrong_hash.as_bytes(),
            &sig_array
        )
        .is_err());
    }

    #[test]
    fn deterministic_from_seed() {
        let seed = [7u8; 32];
        let a = AuditSigner::from_seed(&seed);
        let b = AuditSigner::from_seed(&seed);
        assert_eq!(a.public_key_hex(), b.public_key_hex());

        let entry_hash = "aabbccdd".repeat(8);
        let block_a = a.sign_entry(&entry_hash);
        let block_b = b.sign_entry(&entry_hash);
        // Ed25519 is deterministic per RFC 8032 — same key + same message →
        // same signature.
        assert_eq!(block_a.signature_b64, block_b.signature_b64);
    }

    #[test]
    fn debug_redacts_signing_key() {
        let signer = AuditSigner::from_seed(&[0xAAu8; 32]);
        let s = format!("{:?}", signer);
        assert!(s.contains("<redacted>"));
        assert!(!s.contains("AAAAAAAA")); // no raw seed bytes
    }
}
