//! Receipt and chain verification utilities for ZeroPoint.
//!
//! Provides the catalog grammar abstraction for verifying hash-chained
//! audit entries. The `ChainEntry` trait abstracts over concrete entry types,
//! and `Verifier` runs a set of verification rules (P1 chain extension,
//! M3 hash-chain continuity, M4 trajectory monotonicity).
//!
//! Also provides revocation-aware receipt verification (C3-2): before
//! accepting any receipt as valid evidence, callers should check it
//! against the `RevocationIndex` via `verify_receipt_status()`.

pub mod receipt_status;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Re-export revocation-aware verification
pub use receipt_status::{
    verify_receipt_status, verify_receipts_status, ReceiptStatus, ReceiptStatusReport,
};

/// Trait for entries in a hash-linked chain.
///
/// Implementations provide the links (self hash, parent hash) and
/// content integrity check. The verifier walks these to check
/// chain continuity and ordering.
pub trait ChainEntry {
    /// Human-readable identifier for this entry.
    fn entry_id(&self) -> &str;

    /// This entry's hash (the "self link" in the chain).
    fn self_link(&self) -> &str;

    /// The parent entry's hash (None for the genesis/root entry).
    fn parent_link(&self) -> Option<&str>;

    /// Whether this entry's content hash matches its stored hash.
    fn content_hash_valid(&self) -> bool;

    /// When this entry was created.
    fn timestamp(&self) -> DateTime<Utc>;
}

/// A single finding from the verification process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyFinding {
    /// The rule that was violated.
    pub rule: String,
    /// The entry where the violation was found.
    pub entry_id: String,
    /// Description of the violation.
    pub description: String,
    /// Severity level.
    pub severity: FindingSeverity,
}

/// Severity of a verification finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

/// Report from running the verification rules.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Total entries checked.
    pub entries_checked: usize,
    /// Backward-compatible alias for entries_checked.
    pub receipts_checked: usize,
    /// Findings from the rules.
    pub findings: Vec<VerifyFinding>,
    /// Whether the chain passed all rules.
    pub passed: bool,
}

impl VerifyReport {
    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Error)
            .count()
    }

    /// Get all error-level findings (backward-compatible with old API).
    pub fn violations(&self) -> Vec<&VerifyFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Error)
            .collect()
    }
}

/// The chain verifier — runs catalog rules against a sequence of chain entries.
pub struct Verifier {
    // Future: configurable rule sets
}

impl Verifier {
    pub fn new() -> Self {
        Self {}
    }

    /// Verify a chain of entries, checking:
    /// - P1: Chain extension (each entry's parent_link matches previous self_link)
    /// - M3: Hash-chain continuity (no gaps)
    /// - M4: Trajectory monotonicity (timestamps non-decreasing)
    pub fn verify<E: ChainEntry>(&self, entries: &[E]) -> VerifyReport {
        let mut report = VerifyReport {
            entries_checked: entries.len(),
            receipts_checked: entries.len(),
            findings: Vec::new(),
            passed: true,
        };

        if entries.is_empty() {
            return report;
        }

        // Check genesis.
        if entries[0].parent_link().is_some() {
            report.findings.push(VerifyFinding {
                rule: "P1".to_string(),
                entry_id: entries[0].entry_id().to_string(),
                description: "First entry should have no parent".to_string(),
                severity: FindingSeverity::Error,
            });
            report.passed = false;
        }

        // Walk the chain.
        for i in 1..entries.len() {
            let prev = &entries[i - 1];
            let curr = &entries[i];

            // P1 + M3: Parent link continuity.
            if let Some(parent) = curr.parent_link() {
                if parent != prev.self_link() {
                    report.findings.push(VerifyFinding {
                        rule: "M3".to_string(),
                        entry_id: curr.entry_id().to_string(),
                        description: format!(
                            "Parent link {} does not match previous self link {}",
                            parent,
                            prev.self_link()
                        ),
                        severity: FindingSeverity::Error,
                    });
                    report.passed = false;
                }
            }

            // M4: Timestamp monotonicity.
            if curr.timestamp() < prev.timestamp() {
                report.findings.push(VerifyFinding {
                    rule: "M4".to_string(),
                    entry_id: curr.entry_id().to_string(),
                    description: "Timestamp regression detected".to_string(),
                    severity: FindingSeverity::Warning,
                });
            }

            // Content hash integrity.
            if !curr.content_hash_valid() {
                report.findings.push(VerifyFinding {
                    rule: "P2".to_string(),
                    entry_id: curr.entry_id().to_string(),
                    description: "Content hash mismatch — possible tampering".to_string(),
                    severity: FindingSeverity::Error,
                });
                report.passed = false;
            }
        }

        report
    }
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEntry {
        id: String,
        self_hash: String,
        parent_hash: Option<String>,
        ts: DateTime<Utc>,
        valid: bool,
    }

    impl ChainEntry for TestEntry {
        fn entry_id(&self) -> &str {
            &self.id
        }
        fn self_link(&self) -> &str {
            &self.self_hash
        }
        fn parent_link(&self) -> Option<&str> {
            self.parent_hash.as_deref()
        }
        fn content_hash_valid(&self) -> bool {
            self.valid
        }
        fn timestamp(&self) -> DateTime<Utc> {
            self.ts
        }
    }

    #[test]
    fn valid_chain() {
        let now = Utc::now();
        let entries = vec![
            TestEntry {
                id: "0".into(),
                self_hash: "h0".into(),
                parent_hash: None,
                ts: now,
                valid: true,
            },
            TestEntry {
                id: "1".into(),
                self_hash: "h1".into(),
                parent_hash: Some("h0".into()),
                ts: now,
                valid: true,
            },
            TestEntry {
                id: "2".into(),
                self_hash: "h2".into(),
                parent_hash: Some("h1".into()),
                ts: now,
                valid: true,
            },
        ];

        let report = Verifier::new().verify(&entries);
        assert!(report.passed);
        assert_eq!(report.error_count(), 0);
    }

    #[test]
    fn broken_chain() {
        let now = Utc::now();
        let entries = vec![
            TestEntry {
                id: "0".into(),
                self_hash: "h0".into(),
                parent_hash: None,
                ts: now,
                valid: true,
            },
            TestEntry {
                id: "1".into(),
                self_hash: "h1".into(),
                parent_hash: Some("wrong".into()),
                ts: now,
                valid: true,
            },
        ];

        let report = Verifier::new().verify(&entries);
        assert!(!report.passed);
        assert_eq!(report.error_count(), 1);
    }
}
