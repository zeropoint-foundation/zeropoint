//! ML-DSA-65 (FIPS 204 / Dilithium) post-quantum signing for receipts.
//!
//! Gated behind the `pq-signing` feature flag. This module provides a
//! standalone PQ signer that produces `SignatureBlock` entries using the
//! `Experimental("ML-DSA-65")` algorithm tag — ensuring older verifiers
//! that lack PQ support skip the block gracefully instead of failing.
//!
//! ## Key sizes (ML-DSA-65)
//!
//! | Item           | Seed  | Expanded | Verifying key | Signature |
//! |----------------|-------|----------|---------------|-----------|
//! | Bytes          | 32    | ~4032    | 1952          | 3309      |
//!
//! The 32-byte seed is the canonical storage form for signing keys.
//! The expanded key is derived deterministically from the seed.

use crate::Receipt;
use base64::Engine;
use ml_dsa::{ExpandedSigningKey, MlDsa65, VerifyingKey};
use ml_dsa::signature::SignatureEncoding;

/// ML-DSA-65 post-quantum signer for receipts.
///
/// Produces `SignatureBlock` entries with algorithm `Experimental("ML-DSA-65")`.
/// Designed to be used alongside [`crate::Signer`] (Ed25519) for hybrid
/// signing during the classical→PQ transition.
///
/// Internally stores a 32-byte seed from which the expanded signing key
/// is derived. This keeps serialization compact (same size as Ed25519)
/// while the expanded key handles the actual lattice-based operations.
pub struct PqSigner {
    /// The 32-byte seed — canonical serialization form.
    seed: [u8; 32],
    /// Expanded signing key derived from seed (not Clone/Copy by design —
    /// zeroized on drop for side-channel resistance).
    expanded: ExpandedSigningKey<MlDsa65>,
    /// Public verifying key.
    verifying_key: VerifyingKey<MlDsa65>,
}

impl PqSigner {
    /// Generate a new random ML-DSA-65 keypair from a random 32-byte seed.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        Self::from_seed_bytes(&raw)
    }

    /// Construct from a 32-byte seed.
    ///
    /// The expanded signing key and verifying key are derived deterministically.
    pub fn from_seed_bytes(seed_bytes: &[u8; 32]) -> Self {
        let seed = ml_dsa::Seed::from(*seed_bytes);
        let expanded = ExpandedSigningKey::<MlDsa65>::from_seed(&seed);
        let verifying_key = expanded.verifying_key();
        Self {
            seed: *seed_bytes,
            expanded,
            verifying_key,
        }
    }

    /// Get the 32-byte seed for storage.
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get the verifying key as a hex string.
    pub fn verifying_key_hex(&self) -> String {
        let encoded = self.verifying_key.encode();
        hex_encode(encoded.as_ref())
    }

    /// Sign a receipt, appending an ML-DSA-65 `SignatureBlock`.
    ///
    /// Uses deterministic signing (FIPS 204 §5.2) over the receipt's
    /// `content_hash`. The block is added to [`Receipt::signatures`]
    /// which is re-sorted to maintain canonical ordering.
    ///
    /// This does NOT clear legacy Ed25519 fields — it is designed to
    /// be called *after* [`crate::Signer::sign`] for hybrid receipts.
    pub fn sign(&self, receipt: &mut Receipt) {
        use ml_dsa::signature::Signer as MlDsaSigner;

        // Ensure content_hash is computed.
        if receipt.content_hash.is_empty() {
            receipt.content_hash = crate::canonical_hash(receipt);
        }

        let sig = self.expanded.sign(receipt.content_hash.as_bytes());
        let sig_bytes = sig.to_bytes();
        let sig_b64 =
            base64::engine::general_purpose::STANDARD.encode::<&[u8]>(sig_bytes.as_ref());
        let vk_hex = self.verifying_key_hex();

        receipt
            .signatures
            .push(crate::SignatureBlock::ml_dsa_65(&vk_hex, &sig_b64));
        receipt
            .signatures
            .sort_by(|a, b| a.canonical_sort_key().cmp(&b.canonical_sort_key()));
    }

    /// Verify a receipt's ML-DSA-65 signature against a known verifying key.
    ///
    /// Searches [`Receipt::signatures`] for an `Experimental("ML-DSA-65")`
    /// block and verifies it. Returns `Err` if no ML-DSA-65 signature is
    /// present; returns `Ok(false)` if the signature doesn't match.
    pub fn verify_receipt(
        receipt: &Receipt,
        verifying_key_hex: &str,
    ) -> Result<bool, String> {
        use ml_dsa::signature::Verifier;

        let sig_b64 = receipt
            .signatures
            .iter()
            .find(|b| b.algorithm.is_ml_dsa_65())
            .map(|b| b.signature_b64.clone())
            .ok_or("Receipt has no ML-DSA-65 signature")?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .map_err(|e| format!("Invalid ML-DSA-65 signature encoding: {}", e))?;

        // Reconstruct signature from bytes
        let signature = ml_dsa::Signature::<MlDsa65>::try_from(sig_bytes.as_slice())
            .map_err(|e| format!("Invalid ML-DSA-65 signature: {}", e))?;

        // Reconstruct verifying key from hex
        let vk_bytes = hex_decode(verifying_key_hex)?;
        let encoded_vk = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(
            vk_bytes.as_slice(),
        )
        .map_err(|_| {
            format!(
                "Invalid ML-DSA-65 verifying key length: expected 1952, got {}",
                vk_bytes.len()
            )
        })?;
        let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_vk);

        Ok(verifying_key
            .verify(receipt.content_hash.as_bytes(), &signature)
            .is_ok())
    }
}

impl Clone for PqSigner {
    fn clone(&self) -> Self {
        // ExpandedSigningKey doesn't implement Clone (zeroize-on-drop),
        // so we reconstruct from the seed.
        Self::from_seed_bytes(&self.seed)
    }
}

impl std::fmt::Debug for PqSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let vk_hex = self.verifying_key_hex();
        f.debug_struct("PqSigner")
            .field("algorithm", &"ML-DSA-65")
            .field(
                "verifying_key",
                &format!("{}…", &vk_hex[..32.min(vk_hex.len())]),
            )
            .finish()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err("Hex string has odd length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    #[test]
    fn test_pq_sign_and_verify() {
        let signer = PqSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        assert!(receipt.is_signed());
        assert_eq!(receipt.signatures.len(), 1);
        assert!(receipt.signatures[0].algorithm.is_ml_dsa_65());

        let vk_hex = signer.verifying_key_hex();
        assert!(PqSigner::verify_receipt(&receipt, &vk_hex).unwrap());
    }

    #[test]
    fn test_pq_tampered_receipt_fails() {
        let signer = PqSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);
        receipt.content_hash = "tampered".to_string();

        let vk_hex = signer.verifying_key_hex();
        assert!(!PqSigner::verify_receipt(&receipt, &vk_hex).unwrap());
    }

    #[test]
    fn test_pq_wrong_key_fails() {
        let signer1 = PqSigner::generate();
        let signer2 = PqSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer1.sign(&mut receipt);

        let wrong_vk = signer2.verifying_key_hex();
        assert!(!PqSigner::verify_receipt(&receipt, &wrong_vk).unwrap());
    }

    #[test]
    fn test_pq_seed_roundtrip() {
        let signer1 = PqSigner::generate();
        let seed = *signer1.seed_bytes();
        let signer2 = PqSigner::from_seed_bytes(&seed);

        assert_eq!(signer1.verifying_key_hex(), signer2.verifying_key_hex());
    }

    #[test]
    fn test_pq_clone_produces_same_key() {
        let signer1 = PqSigner::generate();
        let signer2 = signer1.clone();

        assert_eq!(signer1.verifying_key_hex(), signer2.verifying_key_hex());
    }
}
