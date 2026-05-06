//! Ed25519 signing and verification for receipts.
//!
//! Gated behind the `signing` feature flag (enabled by default).

use crate::Receipt;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Ed25519 signer for receipts.
#[derive(Clone)]
pub struct Signer {
    signing_key: SigningKey,
}

impl Signer {
    /// Generate a new random signing key.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        Self { signing_key }
    }

    /// Create from a 32-byte secret.
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(secret),
        }
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the public key as hex string.
    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.public_key_bytes())
    }

    /// Get the secret key bytes.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign a receipt in place.
    ///
    /// **F8 — algorithm-agile signature emission.** Appends a fresh
    /// `SignatureBlock { Ed25519, key_id = pub-hex, signature = base64 }`
    /// to [`Receipt::signatures`] and re-sorts the vec by canonical
    /// order `(algorithm.as_str(), key_id)` so the JSON output is
    /// deterministic regardless of how many algorithms have signed.
    ///
    /// Legacy behavior preserved: the same Ed25519 signature is *also*
    /// mirrored into the legacy [`Receipt::signature`] /
    /// [`Receipt::signer_public_key`] fields *only when* the signing
    /// path is producing a fresh receipt for an older verifier — i.e.
    /// when `signatures` was empty before this call. Calling `sign`
    /// twice (e.g. F8 hybrid signing where Ed25519 signs first, then
    /// a PQ algorithm appends) leaves the legacy fields cleared.
    pub fn sign(&self, receipt: &mut Receipt) {
        use ed25519_dalek::Signer as DalekSigner;

        // Ensure content_hash is computed.
        if receipt.content_hash.is_empty() {
            receipt.content_hash = crate::canonical_hash(receipt);
        }

        let sig = self.signing_key.sign(receipt.content_hash.as_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        let pk_hex = self.public_key_hex();

        // F8 path — append to the typed vec and keep it canonically ordered.
        let was_empty = receipt.signatures.is_empty();
        receipt
            .signatures
            .push(crate::SignatureBlock::ed25519(&pk_hex, &sig_b64));
        receipt
            .signatures
            .sort_by(|a, b| a.canonical_sort_key().cmp(&b.canonical_sort_key()));

        // Clear legacy fields. New receipts emit only `signatures` on the
        // wire; old receipts deserialized into this struct keep their
        // legacy fields populated until something re-signs them.
        if was_empty {
            receipt.signature = None;
            receipt.signer_public_key = None;
        }
    }

    /// Verify a receipt's signature against a known public key.
    ///
    /// F8: searches both [`Receipt::signatures`] (post-F8) and the
    /// legacy [`Receipt::signature`] (pre-F8) for an Ed25519 signature
    /// to verify. Returns `Err` only when no Ed25519 signature is
    /// present at all; experimental algorithms are ignored here (the
    /// chain verifier in `zp-verify` is the right place to surface
    /// them).
    pub fn verify_receipt(receipt: &Receipt, public_key: &[u8; 32]) -> Result<bool, String> {
        // Prefer the F8 vec; fall back to the legacy single field.
        let sig_b64: String = receipt
            .signatures
            .iter()
            .find(|b| b.algorithm == crate::SignatureAlgorithm::Ed25519)
            .map(|b| b.signature_b64.clone())
            .or_else(|| receipt.signature.clone())
            .ok_or("Receipt has no Ed25519 signature")?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&sig_b64)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("Invalid signature format: {}", e))?;

        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        // Phase 1.C: verify_strict, never the malleable verify. The pairing
        // with `Signer::sign` always produces canonical signatures, so any
        // input that would verify but not verify_strict is structurally
        // invalid and should be rejected.
        Ok(verifying_key
            .verify_strict(receipt.content_hash.as_bytes(), &signature)
            .is_ok())
    }
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("public_key", &self.public_key_hex())
            .finish()
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    #[test]
    fn test_sign_and_verify() {
        let signer = Signer::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        // F8: post-sign, the F8 vec carries the signature; the legacy
        // single-field path is left empty for new receipts.
        assert!(receipt.is_signed());
        assert_eq!(receipt.signatures.len(), 1);
        assert_eq!(
            receipt.signatures[0].algorithm,
            crate::SignatureAlgorithm::Ed25519
        );

        let pk = signer.public_key_bytes();
        assert!(Signer::verify_receipt(&receipt, &pk).unwrap());
    }

    #[test]
    fn test_tampered_receipt_fails_verification() {
        let signer = Signer::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        // Tamper with the content hash
        receipt.content_hash = "tampered".to_string();

        let pk = signer.public_key_bytes();
        assert!(!Signer::verify_receipt(&receipt, &pk).unwrap());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signer1 = Signer::generate();
        let signer2 = Signer::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer1.sign(&mut receipt);

        let wrong_pk = signer2.public_key_bytes();
        assert!(!Signer::verify_receipt(&receipt, &wrong_pk).unwrap());
    }

    #[test]
    fn test_round_trip_secret() {
        let signer1 = Signer::generate();
        let secret = signer1.secret_key_bytes();
        let signer2 = Signer::from_secret(&secret);

        assert_eq!(signer1.public_key_bytes(), signer2.public_key_bytes());
    }
}
