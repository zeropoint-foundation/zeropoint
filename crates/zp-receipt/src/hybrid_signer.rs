//! Hybrid Ed25519 + ML-DSA-65 signer for quantum-resistant receipts.
//!
//! Gated behind the `pq-signing` feature flag. Signs every receipt with
//! both algorithms, producing two `SignatureBlock` entries. During the
//! classical→PQ transition:
//!
//! - **Old verifiers** check Ed25519, skip the ML-DSA-65 block (treated
//!   as an unknown experimental algorithm).
//! - **New verifiers** check both — Ed25519 for backwards compatibility,
//!   ML-DSA-65 for quantum resistance.
//! - **Future verifiers** (Phase 4) gate on ML-DSA-65 and treat Ed25519
//!   as legacy-only.
//!
//! This is the recommended signer for new deployments starting Phase 1
//! of the post-quantum migration.

use crate::{PqSigner, Receipt, Signer};

/// Dual-algorithm signer: Ed25519 (classical) + ML-DSA-65 (post-quantum).
///
/// Every receipt signed with `HybridSigner` carries two signature blocks
/// in its `signatures` vec, both over the same `content_hash`. The
/// canonical sort order places Ed25519 before ML-DSA-65, ensuring
/// deterministic JSON serialization.
#[derive(Clone)]
pub struct HybridSigner {
    /// Classical Ed25519 signer (the current trust anchor).
    ed25519: Signer,
    /// Post-quantum ML-DSA-65 signer (the future trust anchor).
    pq: PqSigner,
}

impl HybridSigner {
    /// Generate fresh keypairs for both algorithms.
    pub fn generate() -> Self {
        Self {
            ed25519: Signer::generate(),
            pq: PqSigner::generate(),
        }
    }

    /// Construct from existing signers.
    pub fn from_signers(ed25519: Signer, pq: PqSigner) -> Self {
        Self { ed25519, pq }
    }

    /// Get the Ed25519 public key as hex (64 chars).
    pub fn ed25519_public_key_hex(&self) -> String {
        self.ed25519.public_key_hex()
    }

    /// Get the ML-DSA-65 verifying key as hex (3904 chars).
    pub fn pq_verifying_key_hex(&self) -> String {
        self.pq.verifying_key_hex()
    }

    /// Get the Ed25519 public key bytes.
    pub fn ed25519_public_key_bytes(&self) -> [u8; 32] {
        self.ed25519.public_key_bytes()
    }

    /// Access the inner Ed25519 signer.
    pub fn ed25519_signer(&self) -> &Signer {
        &self.ed25519
    }

    /// Access the inner PQ signer.
    pub fn pq_signer(&self) -> &PqSigner {
        &self.pq
    }

    /// Sign a receipt with both Ed25519 and ML-DSA-65.
    ///
    /// Produces two `SignatureBlock` entries in [`Receipt::signatures`],
    /// canonically sorted. The Ed25519 block uses algorithm `Ed25519`;
    /// the ML-DSA-65 block uses `Experimental("ML-DSA-65")`.
    ///
    /// Legacy fields (`signature`, `signer_public_key`) are cleared —
    /// hybrid receipts always use the F8 `signatures` vec.
    pub fn sign(&self, receipt: &mut Receipt) {
        // Ed25519 first (sets content_hash if empty, clears legacy fields).
        self.ed25519.sign(receipt);
        // ML-DSA-65 second (appends to signatures vec, re-sorts).
        self.pq.sign(receipt);
    }

    /// Verify both signatures on a receipt.
    ///
    /// Returns `Ok(true)` only if BOTH Ed25519 and ML-DSA-65 signatures
    /// are present and valid. Returns `Err` if either signature is missing.
    pub fn verify_receipt(&self, receipt: &Receipt) -> Result<bool, String> {
        let ed_ok = Signer::verify_receipt(receipt, &self.ed25519.public_key_bytes())?;
        let pq_ok = PqSigner::verify_receipt(receipt, &self.pq.verifying_key_hex())?;
        Ok(ed_ok && pq_ok)
    }
}

impl std::fmt::Debug for HybridSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSigner")
            .field("ed25519", &self.ed25519_public_key_hex())
            .field("ml_dsa_65", &format!("{}…", &self.pq_verifying_key_hex()[..32]))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    #[test]
    fn test_hybrid_sign_produces_two_blocks() {
        let signer = HybridSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        assert!(receipt.is_signed());
        assert_eq!(receipt.signatures.len(), 2);

        // Canonical sort by as_str(): "ML-DSA-65" < "ed25519" (ASCII uppercase first)
        assert!(receipt.signatures[0].algorithm.is_ml_dsa_65());
        assert_eq!(
            receipt.signatures[1].algorithm,
            crate::SignatureAlgorithm::Ed25519
        );
    }

    #[test]
    fn test_hybrid_verify_both() {
        let signer = HybridSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        assert!(signer.verify_receipt(&receipt).unwrap());
    }

    #[test]
    fn test_hybrid_tampered_fails() {
        let signer = HybridSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);
        receipt.content_hash = "tampered".to_string();

        assert!(!signer.verify_receipt(&receipt).unwrap());
    }

    #[test]
    fn test_hybrid_old_verifier_sees_ed25519() {
        // Simulate an old verifier that only knows Ed25519.
        let signer = HybridSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        // Old verifier path: only check Ed25519 — should pass.
        let ed_ok = Signer::verify_receipt(
            &receipt,
            &signer.ed25519_public_key_bytes(),
        )
        .unwrap();
        assert!(ed_ok);
    }

    #[test]
    fn test_hybrid_receipt_json_roundtrip() {
        let signer = HybridSigner::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        // Serialize → deserialize → verify
        let json = serde_json::to_string(&receipt).unwrap();
        let deserialized: Receipt = serde_json::from_str(&json).unwrap();

        assert!(signer.verify_receipt(&deserialized).unwrap());
        assert_eq!(deserialized.signatures.len(), 2);
    }
}
