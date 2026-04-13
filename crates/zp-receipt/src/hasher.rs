//! Canonical hashing for receipt integrity verification.
//!
//! The canonical hash is computed over a deterministic JSON representation
//! of the receipt body (all fields except `content_hash`, `signature`, and
//! `signer_public_key`). This ensures that the hash is stable regardless of
//! field ordering or whitespace.

use crate::Receipt;

/// Compute the Blake3 canonical hash of a receipt.
///
/// Excludes `content_hash`, `signature`, and `signer_public_key` from the
/// hash input (these are computed/set after the body is finalized).
pub fn canonical_hash(receipt: &Receipt) -> String {
    let hash_input = serde_json::json!({
        "id": receipt.id,
        "version": receipt.version,
        "receipt_type": receipt.receipt_type,
        "parent_receipt_id": receipt.parent_receipt_id,
        "status": receipt.status,
        "trust_grade": receipt.trust_grade,
        "created_at": receipt.created_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "executor": receipt.executor,
        "action": receipt.action,
        "timing": receipt.timing,
        "resources": receipt.resources,
        "outputs": receipt.outputs,
        "io_hashes": receipt.io_hashes,
        "policy": receipt.policy,
        "error": receipt.error,
        "redactions": receipt.redactions,
        "chain": receipt.chain,
        "extensions": receipt.extensions,
        "expires_at": receipt.expires_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        "claim_metadata": receipt.claim_metadata,
        "superseded_by": receipt.superseded_by,
        "revoked_at": receipt.revoked_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
    });

    let canonical = serde_json::to_string(&hash_input).unwrap_or_default();
    blake3::hash(canonical.as_bytes()).to_hex().to_string()
}

/// Hash arbitrary bytes with Blake3.
#[allow(dead_code)] // Public utility — used by consumers (zp-mesh, zp-trust)
pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReceiptType, Status, TrustGrade};
    use chrono::Utc;

    fn minimal_receipt() -> Receipt {
        Receipt {
            id: "rcpt-00000001".to_string(),
            version: crate::RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_type: ReceiptType::Execution,
            parent_receipt_id: None,
            status: Status::Success,
            content_hash: String::new(),
            signature: None,
            signer_public_key: None,
            trust_grade: TrustGrade::D,
            created_at: Utc::now(),
            executor: None,
            action: None,
            timing: None,
            resources: None,
            outputs: None,
            io_hashes: None,
            policy: None,
            error: None,
            redactions: None,
            chain: None,
            extensions: None,
            expires_at: None,
            claim_metadata: None,
            superseded_by: None,
            revoked_at: None,
        }
    }

    #[test]
    fn test_canonical_hash_is_deterministic() {
        let receipt = minimal_receipt();
        let hash1 = canonical_hash(&receipt);
        let hash2 = canonical_hash(&receipt);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_excludes_signature_fields() {
        let mut r1 = minimal_receipt();
        let mut r2 = minimal_receipt();
        r2.created_at = r1.created_at; // Ensure same timestamp

        r1.signature = None;
        r2.signature = Some("different-signature".to_string());

        // Signatures should not affect the hash
        let hash1 = canonical_hash(&r1);
        let hash2 = canonical_hash(&r2);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_changes_with_content() {
        let r1 = minimal_receipt();
        let mut r2 = minimal_receipt();
        r2.created_at = r1.created_at;
        r2.status = Status::Failed;

        let hash1 = canonical_hash(&r1);
        let hash2 = canonical_hash(&r2);
        assert_ne!(hash1, hash2);
    }
}
