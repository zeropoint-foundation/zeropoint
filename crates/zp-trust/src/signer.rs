//! Cryptographic signing infrastructure for trust tiers.
//!
//! Uses Ed25519 for signing and signature verification.

use ed25519_dalek::{Signer as _, SigningKey};
use rand::rngs::OsRng;
use thiserror::Error;

/// Errors that can occur during signing operations.
#[derive(Error, Debug)]
pub enum SignerError {
    /// The signature did not match the data and public key.
    #[error("Signature verification failed")]
    VerificationFailed,

    /// The signature bytes could not be parsed.
    #[error("Invalid signature format")]
    InvalidSignatureFormat(String),

    /// The provided key material is invalid or malformed.
    #[error("Invalid key material")]
    InvalidKeyMaterial,

    /// The signing operation failed unexpectedly.
    #[error("Signing operation failed: {0}")]
    SigningFailed(String),
}

/// Result type for signing operations.
pub type SignerResult<T> = Result<T, SignerError>;

/// Cryptographic signer for trust tier operations.
///
/// Uses Ed25519 for deterministic signing and verification.
#[derive(Debug)]
pub struct Signer {
    /// Ed25519 signing key
    signing_key: SigningKey,
}

impl Drop for Signer {
    fn drop(&mut self) {
        // SigningKey implements Zeroize when the feature is enabled;
        // we manually zeroize the bytes as a safety measure.
        self.signing_key = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl Signer {
    /// Generate a new random keypair using the OS random number generator.
    ///
    /// # Returns
    /// A new Signer with a randomly generated keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create a signer from an existing 32-byte secret key.
    ///
    /// # Arguments
    /// * `secret` - A 32-byte Ed25519 secret key
    ///
    /// # Returns
    /// Ok(Signer) on success, or SignerError if the key material is invalid
    pub fn from_secret(secret: &[u8; 32]) -> SignerResult<Self> {
        let signing_key = SigningKey::from_bytes(secret);
        Ok(Self { signing_key })
    }

    /// Sign data with the signing key.
    ///
    /// # Arguments
    /// * `data` - The data to sign
    ///
    /// # Returns
    /// A hex-encoded Ed25519 signature
    pub fn sign(&self, data: &[u8]) -> String {
        let signature = self.signing_key.sign(data);
        hex::encode(signature.to_bytes())
    }

    /// Verify a signature against data using a public key.
    ///
    /// # Arguments
    /// * `public_key` - A 32-byte Ed25519 public key
    /// * `data` - The data that was signed
    /// * `signature` - A hex-encoded signature
    ///
    /// # Returns
    /// Ok(true) if signature is valid, Ok(false) if invalid, or SignerError on other issues
    pub fn verify(public_key: &[u8; 32], data: &[u8], signature: &str) -> SignerResult<bool> {
        // Decode the hex signature
        let signature_bytes = hex::decode(signature)
            .map_err(|e| SignerError::InvalidSignatureFormat(e.to_string()))?;

        if signature_bytes.len() != 64 {
            return Err(SignerError::InvalidSignatureFormat(
                "signature must be 64 bytes".to_string(),
            ));
        }

        // Convert to fixed-size array
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&signature_bytes);

        // Routes through the single canonical verify primitive (Seam 5).
        // `InvalidPublicKey` propagates as `SignerError::InvalidKeyMaterial`;
        // a Mismatch (good key, wrong sig) returns `Ok(false)`.
        use zp_core::{verify_signature, VerifyError};
        match verify_signature(public_key, data, &sig_array) {
            Ok(()) => Ok(true),
            Err(VerifyError::InvalidPublicKey) => Err(SignerError::InvalidKeyMaterial),
            Err(VerifyError::Mismatch | VerifyError::InvalidSignature) => Ok(false),
        }
    }

    /// Get the public key associated with this signer.
    ///
    /// # Returns
    /// The 32-byte Ed25519 public key
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the secret key associated with this signer.
    ///
    /// # Returns
    /// The 32-byte Ed25519 secret key
    pub fn secret_key(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signer_generate() {
        let signer = Signer::generate();
        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 32);
    }

    #[test]
    fn test_signer_sign_and_verify() {
        let signer = Signer::generate();
        let public_key = signer.public_key();

        let data = b"test data to sign";
        let signature = signer.sign(data);

        let is_valid = Signer::verify(&public_key, data, &signature).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_signer_verify_invalid_signature() {
        let signer = Signer::generate();
        let public_key = signer.public_key();

        let data = b"test data to sign";
        let signature = signer.sign(data);

        // Try to verify with different data
        let is_valid = Signer::verify(&public_key, b"different data", &signature).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_signer_from_secret() {
        let secret = [0x42u8; 32];
        let signer1 = Signer::from_secret(&secret).unwrap();
        let signer2 = Signer::from_secret(&secret).unwrap();

        // Same secret should produce same public key
        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn test_signer_deterministic_signatures() {
        let secret = [0x42u8; 32];
        let signer = Signer::from_secret(&secret).unwrap();

        let data = b"deterministic test data";
        let sig1 = signer.sign(data);
        let sig2 = signer.sign(data);

        // Ed25519 signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signer_cross_verification() {
        let signer = Signer::generate();
        let public_key = signer.public_key();

        let data = b"cross-verify test";
        let signature = signer.sign(data);

        // Verify with static method
        let is_valid = Signer::verify(&public_key, data, &signature).unwrap();
        assert!(is_valid);
    }
}
