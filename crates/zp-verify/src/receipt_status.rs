//! Revocation-aware receipt status verification (C3-2 wiring).
//!
//! Before accepting any receipt as evidence for memory promotion,
//! delegation, or capability grants, callers must check the receipt
//! against the `RevocationIndex` to ensure it hasn't been revoked
//! or superseded.
//!
//! This module provides the bridge between `zp-audit::RevocationIndex`
//! and `zp-receipt::Receipt`, giving callers a single function to
//! determine whether a receipt is still valid.

use zp_receipt::{Receipt, RevocationIndex};

/// The status of a receipt after checking revocation and supersession.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptStatus {
    /// The receipt is active — neither revoked nor superseded.
    Active,
    /// The receipt has been explicitly revoked.
    Revoked {
        /// The ID of the receipt that revoked this one.
        revoking_receipt_id: String,
    },
    /// The receipt has been superseded by a newer version.
    Superseded {
        /// The ID of the receipt that supersedes this one.
        superseding_receipt_id: String,
    },
    /// The receipt has expired (past its `expires_at` timestamp).
    Expired,
}

impl ReceiptStatus {
    /// Whether this receipt is still valid for use as evidence.
    pub fn is_valid(&self) -> bool {
        matches!(self, ReceiptStatus::Active)
    }
}

/// Summary report from batch receipt status verification.
#[derive(Debug, Default)]
pub struct ReceiptStatusReport {
    /// Total receipts checked.
    pub total: usize,
    /// Receipts that are still active.
    pub active: usize,
    /// Receipts that were revoked.
    pub revoked: usize,
    /// Receipts that were superseded.
    pub superseded: usize,
    /// Receipts that have expired.
    pub expired: usize,
    /// Individual results (receipt_id → status).
    pub results: Vec<(String, ReceiptStatus)>,
}

/// Check whether a single receipt is still valid.
///
/// This is the primary verification entry point for C3-2. All code paths
/// that accept a receipt as evidence (memory promotion, delegation
/// verification, capability grant validation) should call this before
/// trusting the receipt.
///
/// Checks in order:
/// 1. Revocation (hard void — receipt is completely invalid)
/// 2. Supersession (soft replacement — receipt is outdated)
/// 3. Expiry (time-based invalidation)
pub fn verify_receipt_status(
    receipt: &Receipt,
    revocation_index: &RevocationIndex,
) -> ReceiptStatus {
    // 1. Check revocation (strongest invalidation).
    if let Some(revoking_id) = revocation_index.revoking_receipt(receipt.id.as_str()) {
        tracing::debug!(
            receipt_id = %receipt.id,
            revoking_id = %revoking_id,
            "Receipt is revoked"
        );
        return ReceiptStatus::Revoked {
            revoking_receipt_id: revoking_id.to_string(),
        };
    }

    // 2. Check supersession (soft replacement).
    if let Some(superseding_id) = revocation_index.superseding_receipt(receipt.id.as_str()) {
        tracing::debug!(
            receipt_id = %receipt.id,
            superseding_id = %superseding_id,
            "Receipt is superseded"
        );
        return ReceiptStatus::Superseded {
            superseding_receipt_id: superseding_id.to_string(),
        };
    }

    // 3. Check expiry.
    if let Some(expires_at) = receipt.expires_at {
        if chrono::Utc::now() > expires_at {
            tracing::debug!(
                receipt_id = %receipt.id,
                expires_at = %expires_at,
                "Receipt has expired"
            );
            return ReceiptStatus::Expired;
        }
    }

    ReceiptStatus::Active
}

/// Batch-check a set of receipts against the revocation index.
///
/// Returns a summary report with counts and per-receipt status.
pub fn verify_receipts_status(
    receipts: &[Receipt],
    revocation_index: &RevocationIndex,
) -> ReceiptStatusReport {
    let mut report = ReceiptStatusReport {
        total: receipts.len(),
        ..Default::default()
    };

    for receipt in receipts {
        let status = verify_receipt_status(receipt, revocation_index);
        match &status {
            ReceiptStatus::Active => report.active += 1,
            ReceiptStatus::Revoked { .. } => report.revoked += 1,
            ReceiptStatus::Superseded { .. } => report.superseded += 1,
            ReceiptStatus::Expired => report.expired += 1,
        }
        report.results.push((receipt.id.clone(), status));
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_receipt::{ReceiptBuilder, ReceiptType, Status};

    fn make_receipt(id: &str) -> Receipt {
        let mut r = ReceiptBuilder::new(ReceiptType::Execution, "test")
            .status(Status::Success)
            .finalize();
        r.id = id.to_string();
        r
    }

    fn make_receipt_with_expiry(id: &str, expires_at: chrono::DateTime<chrono::Utc>) -> Receipt {
        let mut r = make_receipt(id);
        r.expires_at = Some(expires_at);
        r
    }

    #[test]
    fn active_receipt_passes() {
        let index = RevocationIndex::new();
        let receipt = make_receipt("rcpt-001");
        let status = verify_receipt_status(&receipt, &index);
        assert_eq!(status, ReceiptStatus::Active);
        assert!(status.is_valid());
    }

    #[test]
    fn revoked_receipt_rejected() {
        let revoker = {
            let mut r = ReceiptBuilder::new(ReceiptType::Execution, "test")
                .status(Status::Success)
                .revokes_receipt("rcpt-001")
                .finalize();
            r.id = "rcpt-002".to_string();
            r
        };
        let index = RevocationIndex::rebuild_from_receipts(&[revoker]);

        let receipt = make_receipt("rcpt-001");
        let status = verify_receipt_status(&receipt, &index);
        assert_eq!(
            status,
            ReceiptStatus::Revoked {
                revoking_receipt_id: "rcpt-002".to_string()
            }
        );
        assert!(!status.is_valid());
    }

    #[test]
    fn superseded_receipt_rejected() {
        let superseder = {
            let mut r = ReceiptBuilder::new(ReceiptType::Execution, "test")
                .status(Status::Success)
                .supersedes("rcpt-001")
                .finalize();
            r.id = "rcpt-002".to_string();
            r
        };
        let index = RevocationIndex::rebuild_from_receipts(&[superseder]);

        let receipt = make_receipt("rcpt-001");
        let status = verify_receipt_status(&receipt, &index);
        assert_eq!(
            status,
            ReceiptStatus::Superseded {
                superseding_receipt_id: "rcpt-002".to_string()
            }
        );
        assert!(!status.is_valid());
    }

    #[test]
    fn expired_receipt_rejected() {
        let index = RevocationIndex::new();
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let receipt = make_receipt_with_expiry("rcpt-001", past);
        let status = verify_receipt_status(&receipt, &index);
        assert_eq!(status, ReceiptStatus::Expired);
        assert!(!status.is_valid());
    }

    #[test]
    fn future_expiry_still_active() {
        let index = RevocationIndex::new();
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        let receipt = make_receipt_with_expiry("rcpt-001", future);
        let status = verify_receipt_status(&receipt, &index);
        assert_eq!(status, ReceiptStatus::Active);
    }

    #[test]
    fn revocation_takes_precedence_over_supersession() {
        // Receipt is both revoked and superseded — revocation wins.
        let revoker = {
            let mut r = ReceiptBuilder::new(ReceiptType::Execution, "test")
                .status(Status::Success)
                .revokes_receipt("rcpt-001")
                .finalize();
            r.id = "rcpt-revoker".to_string();
            r
        };
        let superseder = {
            let mut r = ReceiptBuilder::new(ReceiptType::Execution, "test")
                .status(Status::Success)
                .supersedes("rcpt-001")
                .finalize();
            r.id = "rcpt-superseder".to_string();
            r
        };
        let index = RevocationIndex::rebuild_from_receipts(&[revoker, superseder]);

        let receipt = make_receipt("rcpt-001");
        let status = verify_receipt_status(&receipt, &index);
        // Revocation is checked first and takes precedence.
        assert!(matches!(status, ReceiptStatus::Revoked { .. }));
    }

    #[test]
    fn batch_verification_report() {
        let revoker = {
            let mut r = ReceiptBuilder::new(ReceiptType::Execution, "test")
                .status(Status::Success)
                .revokes_receipt("rcpt-001")
                .finalize();
            r.id = "rcpt-revoker".to_string();
            r
        };
        let index = RevocationIndex::rebuild_from_receipts(&[revoker]);

        let receipts = vec![
            make_receipt("rcpt-001"), // revoked
            make_receipt("rcpt-002"), // active
            make_receipt("rcpt-003"), // active
        ];

        let report = verify_receipts_status(&receipts, &index);
        assert_eq!(report.total, 3);
        assert_eq!(report.active, 2);
        assert_eq!(report.revoked, 1);
        assert_eq!(report.superseded, 0);
        assert_eq!(report.expired, 0);
    }
}
