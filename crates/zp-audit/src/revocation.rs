//! Revocation index for receipt chain integrity (C3-2).
//!
//! Maintains an in-memory index of revoked receipt IDs, rebuilt from
//! the chain on startup. Used by `zp-verify` and the reconstitution
//! engine to skip revoked receipts before accepting them as evidence.
//!
//! The index is bidirectional:
//! - Forward: revoking_receipt_id → vec[revoked_receipt_ids]
//! - Reverse: revoked_receipt_id → revoking_receipt_id
//!
//! It also tracks supersession (soft replacement) separately.

use std::collections::HashMap;

/// In-memory index of revoked and superseded receipts.
///
/// Built from the receipt chain at startup and updated incrementally
/// as new receipts arrive.
#[derive(Debug, Default)]
pub struct RevocationIndex {
    /// revoked_receipt_id → revoking_receipt_id
    revoked: HashMap<String, String>,
    /// superseded_receipt_id → superseding_receipt_id
    superseded: HashMap<String, String>,
}

impl RevocationIndex {
    /// Create an empty revocation index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the index from a sequence of receipts.
    ///
    /// Scans each receipt's `revokes` and `supersedes` fields to
    /// populate the index. Call this at startup with the full chain.
    pub fn rebuild_from_receipts<'a>(
        receipts: impl IntoIterator<Item = &'a zp_receipt::Receipt>,
    ) -> Self {
        let mut index = Self::new();
        for receipt in receipts {
            index.index_receipt(receipt);
        }
        index
    }

    /// Index a single receipt's revocation and supersession references.
    ///
    /// Called incrementally when a new receipt is appended to the chain.
    pub fn index_receipt(&mut self, receipt: &zp_receipt::Receipt) {
        for revoked_id in &receipt.revokes {
            self.revoked
                .insert(revoked_id.clone(), receipt.id.clone());
        }
        for superseded_id in &receipt.supersedes {
            self.superseded
                .insert(superseded_id.clone(), receipt.id.clone());
        }
    }

    /// Check if a receipt has been revoked.
    pub fn is_revoked(&self, receipt_id: &str) -> bool {
        self.revoked.contains_key(receipt_id)
    }

    /// Get the ID of the receipt that revoked the given receipt, if any.
    pub fn revoking_receipt(&self, receipt_id: &str) -> Option<&str> {
        self.revoked.get(receipt_id).map(|s| s.as_str())
    }

    /// Check if a receipt has been superseded.
    pub fn is_superseded(&self, receipt_id: &str) -> bool {
        self.superseded.contains_key(receipt_id)
    }

    /// Get the ID of the receipt that supersedes the given receipt, if any.
    pub fn superseding_receipt(&self, receipt_id: &str) -> Option<&str> {
        self.superseded.get(receipt_id).map(|s| s.as_str())
    }

    /// Check if a receipt is still valid (neither revoked nor superseded).
    pub fn is_active(&self, receipt_id: &str) -> bool {
        !self.is_revoked(receipt_id) && !self.is_superseded(receipt_id)
    }

    /// Number of revoked receipts tracked.
    pub fn revoked_count(&self) -> usize {
        self.revoked.len()
    }

    /// Number of superseded receipts tracked.
    pub fn superseded_count(&self) -> usize {
        self.superseded.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_receipt::{Receipt, ReceiptBuilder, ReceiptType, Status};

    fn make_receipt(id: &str, revokes: Vec<&str>, supersedes: Vec<&str>) -> Receipt {
        let mut builder = ReceiptBuilder::new(ReceiptType::Execution, "test")
            .status(Status::Success);

        for r in &revokes {
            builder = builder.revokes_receipt(r);
        }
        for s in &supersedes {
            builder = builder.supersedes(s);
        }

        let mut receipt = builder.finalize();
        receipt.id = id.to_string(); // Override generated ID for test determinism
        receipt
    }

    #[test]
    fn test_empty_index() {
        let index = RevocationIndex::new();
        assert!(!index.is_revoked("rcpt-001"));
        assert!(!index.is_superseded("rcpt-001"));
        assert!(index.is_active("rcpt-001"));
        assert_eq!(index.revoked_count(), 0);
        assert_eq!(index.superseded_count(), 0);
    }

    #[test]
    fn test_revocation_tracking() {
        let r1 = make_receipt("rcpt-001", vec![], vec![]);
        let r2 = make_receipt("rcpt-002", vec!["rcpt-001"], vec![]);

        let index = RevocationIndex::rebuild_from_receipts(&[r1, r2]);

        assert!(index.is_revoked("rcpt-001"));
        assert_eq!(index.revoking_receipt("rcpt-001"), Some("rcpt-002"));
        assert!(!index.is_active("rcpt-001"));
        assert!(index.is_active("rcpt-002"));
        assert_eq!(index.revoked_count(), 1);
    }

    #[test]
    fn test_supersession_tracking() {
        let r1 = make_receipt("rcpt-001", vec![], vec![]);
        let r2 = make_receipt("rcpt-002", vec![], vec!["rcpt-001"]);

        let index = RevocationIndex::rebuild_from_receipts(&[r1, r2]);

        assert!(index.is_superseded("rcpt-001"));
        assert_eq!(index.superseding_receipt("rcpt-001"), Some("rcpt-002"));
        assert!(!index.is_active("rcpt-001"));
        assert!(index.is_active("rcpt-002"));
        assert_eq!(index.superseded_count(), 1);
    }

    #[test]
    fn test_multiple_revocations() {
        let r1 = make_receipt("rcpt-001", vec![], vec![]);
        let r2 = make_receipt("rcpt-002", vec![], vec![]);
        let r3 = make_receipt("rcpt-003", vec!["rcpt-001", "rcpt-002"], vec![]);

        let index = RevocationIndex::rebuild_from_receipts(&[r1, r2, r3]);

        assert!(index.is_revoked("rcpt-001"));
        assert!(index.is_revoked("rcpt-002"));
        assert!(!index.is_revoked("rcpt-003"));
        assert_eq!(index.revoking_receipt("rcpt-001"), Some("rcpt-003"));
        assert_eq!(index.revoking_receipt("rcpt-002"), Some("rcpt-003"));
        assert_eq!(index.revoked_count(), 2);
    }

    #[test]
    fn test_incremental_indexing() {
        let mut index = RevocationIndex::new();

        let r1 = make_receipt("rcpt-001", vec![], vec![]);
        index.index_receipt(&r1);
        assert!(index.is_active("rcpt-001"));

        let r2 = make_receipt("rcpt-002", vec!["rcpt-001"], vec![]);
        index.index_receipt(&r2);
        assert!(!index.is_active("rcpt-001"));
        assert!(index.is_active("rcpt-002"));
    }

    #[test]
    fn test_mixed_revocation_and_supersession() {
        let r1 = make_receipt("rcpt-001", vec![], vec![]);
        let r2 = make_receipt("rcpt-002", vec![], vec![]);
        let r3 = make_receipt("rcpt-003", vec!["rcpt-001"], vec!["rcpt-002"]);

        let index = RevocationIndex::rebuild_from_receipts(&[r1, r2, r3]);

        assert!(index.is_revoked("rcpt-001"));
        assert!(index.is_superseded("rcpt-002"));
        assert!(!index.is_active("rcpt-001"));
        assert!(!index.is_active("rcpt-002"));
        assert!(index.is_active("rcpt-003"));
    }
}
