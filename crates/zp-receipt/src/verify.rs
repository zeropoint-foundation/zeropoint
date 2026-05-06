//! The single Ed25519 signature-verification primitive.
//!
//! # The wire (Seam 5)
//!
//! Every Ed25519 signature check in ZeroPoint goes through
//! [`verify_signature`] (raw bytes) or [`verify_signed`] (any
//! [`crate::Signable`]). The architectural commitment: there is **one**
//! verify primitive in the workspace. Direct calls to
//! `ed25519_dalek::VerifyingKey::verify` and `verify_strict` are
//! forbidden outside this module — Phase-1.C swept the workspace from
//! the malleable `verify` to `verify_strict` at five call sites, and
//! follow-up sweeps consolidate the ~138 sites doing
//! `verify_strict(...).is_ok()` into calls to the helper.
//!
//! # Why a single primitive
//!
//! Every divergence between verify call sites is a footgun. Some sites
//! used `verify` (malleable); some used `verify_strict`. Some
//! base64-decoded signatures; some hex-decoded. Some validated key/sig
//! length; some panicked. Routing every check through one function
//! means there's one place to fix bugs, one place to add observability,
//! and one place to enforce the verify-strict discipline.
//!
//! # Composition with [`crate::Signable`] (Seam 20)
//!
//! The `verify_signed` overload pairs this primitive with the canonical
//! preimage trait: callers pass an object, and verification re-derives
//! the preimage via `Signable::canonical_hash` — the same bytes the
//! signer signed. There is no path by which a verifier could re-derive
//! a *different* preimage from the same value.
//!
//! # Errors
//!
//! [`VerifyError`] surfaces the specific failure mode (bad key bytes,
//! bad signature bytes, signature didn't verify) so callers can log
//! diagnostically without leaking secret material. The verifier never
//! returns the secret bytes in any error.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::Signable;

/// Errors from signature verification. Each variant is a distinct
/// failure mode — callers can log them without leaking secret bytes.
///
/// `Display` and `std::error::Error` are hand-rolled rather than derived
/// via `thiserror` to keep `zp-receipt`'s "minimal dependencies by
/// design" invariant (see Cargo.toml header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The 32-byte slice is not a valid Ed25519 public key
    /// (e.g. compressed point that doesn't decompress).
    InvalidPublicKey,

    /// The signature bytes are malformed (currently
    /// `Signature::from_bytes` cannot fail, but this variant is
    /// reserved for future signature shapes that can).
    InvalidSignature,

    /// The signature is well-formed but does not verify against the
    /// (`public_key`, `message`) pair under `verify_strict`.
    Mismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::InvalidPublicKey => write!(f, "invalid Ed25519 public key bytes"),
            VerifyError::InvalidSignature => write!(f, "invalid Ed25519 signature bytes"),
            VerifyError::Mismatch => {
                write!(f, "signature does not verify against the supplied public key")
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify an Ed25519 signature using `verify_strict` (non-malleable).
///
/// This is the **only** sanctioned verification primitive. Direct calls
/// to `VerifyingKey::verify` (malleable) or `verify_strict` outside this
/// module are forbidden — the discipline turns a convention into an
/// invariant.
pub fn verify_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), VerifyError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| VerifyError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| VerifyError::Mismatch)
}

/// Verify an Ed25519 signature against a [`Signable`] value's canonical
/// hash.
///
/// Re-derives the preimage via `value.canonical_hash()` and passes it to
/// [`verify_signature`]. Use this whenever you have the original signed
/// object — it removes the temptation to recompute the preimage by hand.
pub fn verify_signed<T: Signable>(
    value: &T,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), VerifyError> {
    let hash = value.canonical_hash();
    verify_signature(public_key, &hash, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixture_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42u8; 32])
    }

    #[test]
    fn valid_signature_verifies() {
        let sk = fixture_key();
        let msg = b"the quick brown fox";
        let sig = sk.sign(msg);
        let pk = sk.verifying_key().to_bytes();
        verify_signature(&pk, msg, &sig.to_bytes()).expect("valid sig must verify");
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = fixture_key();
        let other_sk = SigningKey::from_bytes(&[0x99u8; 32]);
        let msg = b"hello";
        let sig = sk.sign(msg);
        let result = verify_signature(&other_sk.verifying_key().to_bytes(), msg, &sig.to_bytes());
        assert_eq!(result, Err(VerifyError::Mismatch));
    }

    #[test]
    fn tampered_message_rejected() {
        let sk = fixture_key();
        let msg = b"hello";
        let tampered = b"helloX";
        let sig = sk.sign(msg);
        let result = verify_signature(&sk.verifying_key().to_bytes(), tampered, &sig.to_bytes());
        assert_eq!(result, Err(VerifyError::Mismatch));
    }

    #[test]
    fn invalid_public_key_rejected() {
        // All-zeros is not a valid Ed25519 public key (it's a torsion point
        // that fails the small-subgroup check in `from_bytes` on some
        // implementations; here we just confirm the error surfaces).
        let bad_pk = [0u8; 32];
        let sig = [0u8; 64];
        let msg = b"x";
        let result = verify_signature(&bad_pk, msg, &sig);
        // The exact error type depends on the curve check — accept either
        // InvalidPublicKey or Mismatch, but never silently succeed.
        assert!(matches!(
            result,
            Err(VerifyError::InvalidPublicKey | VerifyError::Mismatch)
        ));
    }

    /// Test that [`verify_signed`] composes with [`crate::Signable`].
    ///
    /// We define a local Signable type, sign its canonical_hash, and
    /// confirm the helper accepts the same signature.
    #[test]
    fn verify_signed_round_trips_through_signable() {
        use serde::Serialize;

        #[derive(Serialize)]
        struct Doc {
            id: String,
            payload: u64,
        }
        impl Signable for Doc {
            fn canonical_preimage(&self) -> Vec<u8> {
                crate::canonical::canonical_bytes_of(self).expect("Doc serializes cleanly")
            }
        }

        let sk = fixture_key();
        let pk = sk.verifying_key().to_bytes();
        let doc = Doc {
            id: "x".into(),
            payload: 7,
        };

        let sig = sk.sign(&doc.canonical_hash());
        verify_signed(&doc, &pk, &sig.to_bytes()).expect("signed doc must verify");

        // Tampering with the doc invalidates the sig.
        let tampered = Doc {
            id: "x".into(),
            payload: 8,
        };
        assert_eq!(
            verify_signed(&tampered, &pk, &sig.to_bytes()),
            Err(VerifyError::Mismatch)
        );
    }
}
