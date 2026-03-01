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

    /// Sign a receipt in place: sets `signature` and `signer_public_key`.
    pub fn sign(&self, receipt: &mut Receipt) {
        use ed25519_dalek::Signer as DalekSigner;

        // Ensure content_hash is computed
        if receipt.content_hash.is_empty() {
            receipt.content_hash = crate::canonical_hash(receipt);
        }

        let sig = self.signing_key.sign(receipt.content_hash.as_bytes());
        receipt.signature = Some(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()));
        receipt.signer_public_key = Some(self.public_key_hex());
    }

    /// Verify a receipt's signature against a known public key.
    pub fn verify_receipt(receipt: &Receipt, public_key: &[u8; 32]) -> Result<bool, String> {
        let sig_b64 = receipt
            .signature
            .as_ref()
            .ok_or("Receipt has no signature")?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .map_err(|e| format!("Invalid signature encoding: {}", e))?;

        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes)
            .map_err(|e| format!("Invalid signature format: {}", e))?;

        let verifying_key = VerifyingKey::from_bytes(public_key)
            .map_err(|e| format!("Invalid public key: {}", e))?;

        use ed25519_dalek::Verifier;
        Ok(verifying_key
            .verify(receipt.content_hash.as_bytes(), &signature)
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

        assert!(receipt.signature.is_some());
        assert!(receipt.signer_public_key.is_some());

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
