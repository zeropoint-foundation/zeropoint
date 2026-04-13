//! Receipt chain — ordered, hash-linked sequence of receipts.
//!
//! The chain provides an immutable audit trail where each entry's hash
//! incorporates the previous entry's hash, making tampering detectable.
//!
//! # ⚠️ Pedagogical use only
//!
//! This `ReceiptChain` is an in-memory, single-writer teaching abstraction
//! used by the `course-examples` crate (labs 07, 14, 16) to illustrate
//! hash-linked chains. **It is not the canonical ZeroPoint audit chain.**
//!
//! The canonical production chain is [`zp_audit::AuditStore`], which:
//!
//! - persists to SQLite with `user_version = 2`,
//! - serializes writers via `BEGIN IMMEDIATE`,
//! - enforces `prev_hash` uniqueness at the storage layer,
//! - is verified under strict P1–P4 by the catalog verifier, and
//! - has a single owner per process (`Arc<Mutex<AuditStore>>`).
//!
//! Do NOT use `ReceiptChain` in production code paths. If you need a
//! persistent, multi-writer receipt chain, use `zp_audit::AuditStore`.
//! A ripple audit tracked this as finding **R3** (see
//! `docs/audit-architecture.md` §7 and
//! `security/pentest-2026-04-06/RIPPLE-AUDIT.md`). Sweep 2 of the
//! 2026-04-07 remediation confirmed that `ReceiptChain` has zero
//! non-test consumers outside `course-examples`, and retained it as a
//! pedagogical artifact under this visibility constraint.

use crate::Receipt;
use serde::{Deserialize, Serialize};

/// Error type for chain operations.
#[derive(Debug, Clone)]
pub enum ChainError {
    /// The receipt's prev_hash doesn't match the chain's head.
    HashMismatch { expected: String, actual: String },
    /// The receipt's sequence number is wrong.
    SequenceMismatch { expected: u64, actual: u64 },
    /// The chain is empty when it shouldn't be.
    EmptyChain,
    /// Receipt is missing chain metadata.
    MissingChainMetadata,
    /// Chain integrity violation detected at the given index.
    IntegrityViolation { index: usize, detail: String },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::HashMismatch { expected, actual } => {
                write!(f, "Hash mismatch: expected {}, got {}", expected, actual)
            }
            ChainError::SequenceMismatch { expected, actual } => write!(
                f,
                "Sequence mismatch: expected {}, got {}",
                expected, actual
            ),
            ChainError::EmptyChain => write!(f, "Chain is empty"),
            ChainError::MissingChainMetadata => write!(f, "Receipt is missing chain metadata"),
            ChainError::IntegrityViolation { index, detail } => {
                write!(f, "Integrity violation at index {}: {}", index, detail)
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// A lightweight entry in the chain (for validation without full receipts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainEntry {
    pub sequence: u64,
    pub content_hash: String,
    pub prev_hash: String,
    pub receipt_id: String,
}

/// An append-only chain of receipts with hash linking.
#[derive(Debug, Clone)]
pub struct ReceiptChain {
    chain_id: String,
    entries: Vec<ChainEntry>,
    head_hash: String,
}

impl ReceiptChain {
    /// Create a new empty chain.
    pub fn new(chain_id: &str) -> Self {
        Self {
            chain_id: chain_id.to_string(),
            entries: Vec::new(),
            head_hash: "genesis".to_string(),
        }
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Get the current head hash.
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries.
    pub fn entries(&self) -> &[ChainEntry] {
        &self.entries
    }

    /// Append a receipt to the chain.
    ///
    /// Sets the receipt's chain metadata (prev_hash, sequence, chain_id)
    /// and appends it to the chain.
    pub fn append(&mut self, receipt: &mut Receipt) -> Result<(), ChainError> {
        let sequence = self.entries.len() as u64;
        let prev_hash = self.head_hash.clone();

        // Set chain metadata on the receipt
        receipt.chain = Some(crate::ChainMetadata {
            prev_hash: Some(prev_hash.clone()),
            sequence: Some(sequence),
            chain_id: Some(self.chain_id.clone()),
        });

        // Recompute content hash (chain metadata is now part of the body)
        receipt.content_hash = crate::canonical_hash(receipt);

        // Compute the chain entry hash: blake3(prev_hash + content_hash)
        let entry_hash = compute_entry_hash(&prev_hash, &receipt.content_hash);

        let entry = ChainEntry {
            sequence,
            content_hash: receipt.content_hash.clone(),
            prev_hash,
            receipt_id: receipt.id.clone(),
        };

        self.entries.push(entry);
        self.head_hash = entry_hash;

        Ok(())
    }

    /// Verify the integrity of the entire chain.
    ///
    /// Checks that each entry's prev_hash matches the previous entry's
    /// chain hash, and that sequences are monotonically increasing.
    pub fn verify_integrity(&self) -> Result<(), ChainError> {
        let mut expected_prev = "genesis".to_string();

        for (i, entry) in self.entries.iter().enumerate() {
            // Check sequence
            if entry.sequence != i as u64 {
                return Err(ChainError::SequenceMismatch {
                    expected: i as u64,
                    actual: entry.sequence,
                });
            }

            // Check prev_hash linkage
            if entry.prev_hash != expected_prev {
                return Err(ChainError::IntegrityViolation {
                    index: i,
                    detail: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        expected_prev, entry.prev_hash
                    ),
                });
            }

            // Advance: this entry's chain hash becomes next entry's expected prev
            expected_prev = compute_entry_hash(&entry.prev_hash, &entry.content_hash);
        }

        Ok(())
    }
}

/// Compute the chain entry hash from prev_hash and content_hash.
fn compute_entry_hash(prev_hash: &str, content_hash: &str) -> String {
    let input = format!("{}:{}", prev_hash, content_hash);
    blake3::hash(input.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Receipt, Status};

    #[test]
    fn test_empty_chain() {
        let chain = ReceiptChain::new("test-chain");
        assert!(chain.is_empty());
        assert_eq!(chain.head_hash(), "genesis");
        assert!(chain.verify_integrity().is_ok());
    }

    #[test]
    fn test_append_single() {
        let mut chain = ReceiptChain::new("test-chain");
        let mut receipt = Receipt::execution("test")
            .status(Status::Success)
            .finalize();

        chain.append(&mut receipt).unwrap();

        assert_eq!(chain.len(), 1);
        assert_ne!(chain.head_hash(), "genesis");
        assert!(receipt.chain.is_some());
        assert_eq!(receipt.chain.as_ref().unwrap().sequence, Some(0));
        assert!(chain.verify_integrity().is_ok());
    }

    #[test]
    fn test_append_multiple() {
        let mut chain = ReceiptChain::new("test-chain");

        for i in 0..5 {
            let mut receipt = Receipt::execution(&format!("executor-{}", i))
                .status(Status::Success)
                .finalize();
            chain.append(&mut receipt).unwrap();
        }

        assert_eq!(chain.len(), 5);
        assert!(chain.verify_integrity().is_ok());

        // Each entry should have increasing sequence numbers
        for (i, entry) in chain.entries().iter().enumerate() {
            assert_eq!(entry.sequence, i as u64);
        }
    }

    #[test]
    fn test_tampered_chain_detected() {
        let mut chain = ReceiptChain::new("test-chain");

        for _ in 0..3 {
            let mut receipt = Receipt::execution("test")
                .status(Status::Success)
                .finalize();
            chain.append(&mut receipt).unwrap();
        }

        // Tamper with middle entry
        chain.entries[1].content_hash = "tampered".to_string();

        assert!(chain.verify_integrity().is_err());
    }

    #[test]
    fn test_chain_hash_determinism() {
        let h1 = compute_entry_hash("prev", "content");
        let h2 = compute_entry_hash("prev", "content");
        assert_eq!(h1, h2);

        let h3 = compute_entry_hash("different", "content");
        assert_ne!(h1, h3);
    }
}
