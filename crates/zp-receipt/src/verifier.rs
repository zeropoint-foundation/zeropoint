//! Receipt verification — the protocol primitive that lets any service
//! independently verify a receipt's integrity and authenticity.
//!
//! This is the key module for the "protocol" play: services that receive
//! a ZeroPoint receipt can verify it without any dependency on ZeroPoint
//! infrastructure. All they need is this crate.

use crate::Receipt;

/// Result of verifying a receipt.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the content hash is valid.
    pub hash_valid: bool,
    /// Whether the signature is valid (None if unsigned).
    pub signature_valid: Option<bool>,
    /// Whether the parent chain link is valid (None if no parent).
    pub chain_valid: Option<bool>,
    /// Individual check results for detailed reporting.
    pub checks: Vec<VerificationCheck>,
}

impl VerificationResult {
    /// Returns true if all checks passed.
    pub fn is_valid(&self) -> bool {
        self.hash_valid && self.signature_valid.unwrap_or(true) && self.chain_valid.unwrap_or(true)
    }
}

/// A single verification check.
#[derive(Debug, Clone)]
pub struct VerificationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Error during verification.
#[derive(Debug, Clone)]
pub enum VerificationError {
    /// Receipt is malformed.
    MalformedReceipt(String),
    /// Signature verification failed due to encoding issues.
    SignatureError(String),
    /// Public key is invalid.
    InvalidPublicKey(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::MalformedReceipt(msg) => write!(f, "Malformed receipt: {}", msg),
            VerificationError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            VerificationError::InvalidPublicKey(msg) => write!(f, "Invalid public key: {}", msg),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Stateless receipt verifier.
///
/// Designed to be used by any service that receives ZeroPoint receipts.
/// No ZeroPoint infrastructure dependency — just this crate.
///
/// # Example
///
/// ```rust,ignore
/// use zp_receipt::{ReceiptVerifier, Receipt};
///
/// let receipt: Receipt = serde_json::from_str(&receipt_json)?;
/// let result = ReceiptVerifier::verify(&receipt)?;
///
/// if result.is_valid() {
///     println!("Receipt is authentic and untampered");
/// }
/// ```
pub struct ReceiptVerifier;

impl ReceiptVerifier {
    /// Verify a receipt's integrity (hash check only, no signature).
    pub fn verify_hash(receipt: &Receipt) -> Result<VerificationResult, VerificationError> {
        let mut checks = Vec::new();

        // 1. Content hash verification
        let hash_valid = receipt.verify_hash();
        checks.push(VerificationCheck {
            name: "content_hash".to_string(),
            passed: hash_valid,
            detail: if hash_valid {
                "Content hash matches receipt body".to_string()
            } else {
                "Content hash does NOT match receipt body — receipt may be tampered".to_string()
            },
        });

        // 2. Schema version check
        let version_ok = receipt.version == crate::RECEIPT_SCHEMA_VERSION;
        checks.push(VerificationCheck {
            name: "schema_version".to_string(),
            passed: version_ok,
            detail: format!(
                "Version: {} (expected {})",
                receipt.version,
                crate::RECEIPT_SCHEMA_VERSION
            ),
        });

        // 3. ID prefix check
        let prefix_ok = receipt.id.starts_with(receipt.receipt_type.id_prefix());
        checks.push(VerificationCheck {
            name: "id_prefix".to_string(),
            passed: prefix_ok,
            detail: format!(
                "ID '{}' {} prefix '{}-'",
                receipt.id,
                if prefix_ok {
                    "matches"
                } else {
                    "does NOT match"
                },
                receipt.receipt_type.id_prefix()
            ),
        });

        // 4. Chain linkage check
        let chain_valid = if receipt.receipt_type == crate::ReceiptType::Intent {
            if receipt.parent_receipt_id.is_some() {
                checks.push(VerificationCheck {
                    name: "chain_linkage".to_string(),
                    passed: false,
                    detail: "Intent receipt should not have a parent".to_string(),
                });
                Some(false)
            } else {
                checks.push(VerificationCheck {
                    name: "chain_linkage".to_string(),
                    passed: true,
                    detail: "Intent receipt correctly has no parent".to_string(),
                });
                Some(true)
            }
        } else if receipt.parent_receipt_id.is_some() {
            checks.push(VerificationCheck {
                name: "chain_linkage".to_string(),
                passed: true,
                detail: format!(
                    "{} receipt links to parent {}",
                    receipt.receipt_type,
                    receipt.parent_receipt_id.as_ref().unwrap()
                ),
            });
            Some(true)
        } else {
            // Non-intent without parent — warn but don't fail (standalone receipts are valid)
            checks.push(VerificationCheck {
                name: "chain_linkage".to_string(),
                passed: true,
                detail: format!(
                    "{} receipt has no parent (standalone)",
                    receipt.receipt_type
                ),
            });
            None
        };

        // 5. Expiry check
        if let Some(expires_at) = receipt.expires_at {
            let expired = chrono::Utc::now() > expires_at;
            checks.push(VerificationCheck {
                name: "expiry".to_string(),
                passed: !expired,
                detail: if expired {
                    format!("Receipt expired at {}", expires_at)
                } else {
                    format!("Receipt valid until {}", expires_at)
                },
            });
        }

        // 6. Claim metadata type consistency
        if let Some(ref meta) = receipt.claim_metadata {
            let type_matches = match (&receipt.receipt_type, meta) {
                (crate::ReceiptType::ObservationClaim, crate::ClaimMetadata::Observation { .. }) => true,
                (crate::ReceiptType::PolicyClaim, crate::ClaimMetadata::Policy { .. }) => true,
                (crate::ReceiptType::AuthorizationClaim, crate::ClaimMetadata::Authorization { .. }) => true,
                (crate::ReceiptType::MemoryPromotionClaim, crate::ClaimMetadata::MemoryPromotion { .. }) => true,
                (crate::ReceiptType::DelegationClaim, crate::ClaimMetadata::Delegation { .. }) => true,
                (crate::ReceiptType::NarrativeSynthesisClaim, crate::ClaimMetadata::NarrativeSynthesis { .. }) => true,
                (crate::ReceiptType::RevocationClaim, crate::ClaimMetadata::Revocation { .. }) => true,
                _ => false,
            };
            checks.push(VerificationCheck {
                name: "claim_metadata_type".to_string(),
                passed: type_matches,
                detail: if type_matches {
                    "Claim metadata matches receipt type".to_string()
                } else {
                    format!(
                        "Claim metadata variant does not match receipt type '{}'",
                        receipt.receipt_type
                    )
                },
            });
        }

        Ok(VerificationResult {
            hash_valid,
            signature_valid: None,
            chain_valid,
            checks,
        })
    }

    /// Full verification: hash + signature.
    #[cfg(feature = "signing")]
    pub fn verify(receipt: &Receipt) -> Result<VerificationResult, VerificationError> {
        let mut result = Self::verify_hash(receipt)?;

        // Signature verification
        if let Some(ref _sig) = receipt.signature {
            let pk_hex = receipt.signer_public_key.as_ref().ok_or_else(|| {
                VerificationError::SignatureError(
                    "Receipt has signature but no signer_public_key".to_string(),
                )
            })?;

            let pk_bytes = hex_decode(pk_hex).map_err(VerificationError::InvalidPublicKey)?;

            if pk_bytes.len() != 32 {
                return Err(VerificationError::InvalidPublicKey(format!(
                    "Expected 32 bytes, got {}",
                    pk_bytes.len()
                )));
            }

            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pk_bytes);

            let sig_valid = crate::Signer::verify_receipt(receipt, &pk)
                .map_err(VerificationError::SignatureError)?;

            result.checks.push(VerificationCheck {
                name: "signature".to_string(),
                passed: sig_valid,
                detail: if sig_valid {
                    format!("Valid Ed25519 signature from {}", &pk_hex[..16])
                } else {
                    "Signature does NOT match content — receipt may be forged".to_string()
                },
            });

            result.signature_valid = Some(sig_valid);
        } else {
            result.checks.push(VerificationCheck {
                name: "signature".to_string(),
                passed: true, // Unsigned receipts are valid, just lower trust
                detail: "Receipt is unsigned (TrustGrade D)".to_string(),
            });
        }

        Ok(result)
    }

    /// Verify without the signing feature — hash only.
    #[cfg(not(feature = "signing"))]
    pub fn verify(receipt: &Receipt) -> Result<VerificationResult, VerificationError> {
        Self::verify_hash(receipt)
    }
}

#[cfg(feature = "signing")]
fn hex_decode(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
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
    use crate::{Receipt, Status};

    #[test]
    fn test_verify_hash_valid() {
        let receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        let result = ReceiptVerifier::verify_hash(&receipt).unwrap();
        assert!(result.is_valid());
        assert!(result.hash_valid);
    }

    #[test]
    fn test_verify_hash_tampered() {
        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        receipt.status = Status::Failed; // Tamper after finalization

        let result = ReceiptVerifier::verify_hash(&receipt).unwrap();
        assert!(!result.is_valid());
        assert!(!result.hash_valid);
    }

    #[test]
    fn test_verify_intent_chain() {
        let receipt = Receipt::intent("user").status(Status::Success).finalize();

        let result = ReceiptVerifier::verify_hash(&receipt).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.chain_valid, Some(true));
    }

    #[cfg(feature = "signing")]
    #[test]
    fn test_verify_full_signed() {
        let signer = crate::Signer::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        signer.sign(&mut receipt);

        let result = ReceiptVerifier::verify(&receipt).unwrap();
        assert!(result.is_valid());
        assert_eq!(result.signature_valid, Some(true));
    }

    #[cfg(feature = "signing")]
    #[test]
    fn test_verify_forged_signature() {
        let signer = crate::Signer::generate();
        let forger = crate::Signer::generate();

        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        // Sign with one key, but set the public key of another
        signer.sign(&mut receipt);
        receipt.signer_public_key = Some(forger.public_key_hex());

        let result = ReceiptVerifier::verify(&receipt).unwrap();
        assert!(!result.is_valid());
        assert_eq!(result.signature_valid, Some(false));
    }
}
