//! Receipt and chain verification utilities for ZeroPoint.
//!
//! Provides the catalog grammar abstraction for verifying hash-chained
//! audit entries. The `VerifiableEntry` trait abstracts over concrete entry types,
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
///
/// The signature accessors are optional — entries that don't carry an
/// Ed25519 signature simply opt out by returning None and rule S1
/// skips them.
pub trait VerifiableEntry {
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

    /// Base64-encoded Ed25519 signature, if this entry is signed.
    ///
    /// Pre-F8 / single-signature path. Returning a value here makes
    /// rule S1 verify exactly that one Ed25519 signature against
    /// [`Self::signer_public_key_hex`]. Implementations that expose
    /// the F8 [`Self::signature_blocks`] vec should return `None` from
    /// these legacy accessors — S1 prefers the vec when both are
    /// non-empty.
    fn signature_b64(&self) -> Option<&str> {
        None
    }

    /// Hex-encoded Ed25519 public key of the signer, if available.
    fn signer_public_key_hex(&self) -> Option<&str> {
        None
    }

    /// The bytes that were signed (e.g., the receipt's content_hash bytes).
    /// Required for S1 to verify a signature.
    fn signed_payload(&self) -> Option<&[u8]> {
        None
    }

    /// **F8 algorithm-agile signatures.** Borrow the entry's
    /// `Vec<SignatureBlock>` view for rule S1.
    ///
    /// Default impl returns an empty slice so existing test fixtures
    /// stay on the legacy single-signature path. Production
    /// implementations (`AuditVerifiableEntry` in `zp-audit`) override
    /// this to expose every block on the receipt.
    fn signature_blocks(&self) -> Vec<SignatureBlockView<'_>> {
        Vec::new()
    }
}

/// Borrowing view of one [`zp_receipt::SignatureBlock`].
///
/// `zp-verify` needs to inspect blocks without depending on
/// `zp-receipt` directly — keeps the trait crate-light. The
/// `AuditVerifiableEntry` adapter constructs these from the underlying
/// receipt; the verifier only ever reads them.
#[derive(Debug, Clone, Copy)]
pub struct SignatureBlockView<'a> {
    /// Algorithm identifier as a stable string. `"ed25519"` is
    /// recognized natively; anything else is treated as experimental
    /// (warned + skipped, never failed).
    pub algorithm: &'a str,
    /// Stable identifier for the signing key. For Ed25519 this is the
    /// hex-encoded 32-byte public key.
    pub key_id: &'a str,
    /// Base64-encoded signature bytes.
    pub signature_b64: &'a str,
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
    /// Timestamp of the first entry — the "well-formed since" date.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_timestamp: Option<DateTime<Utc>>,
    /// Hash of the last entry in the chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_head: Option<String>,
    /// Number of S1 signature checks attempted (entries with a signature + key).
    #[serde(default)]
    pub signature_checks: usize,
    /// Number of signature checks that failed.
    #[serde(default)]
    pub signature_failures: usize,
    /// **F8.** Number of signature blocks the verifier encountered
    /// whose algorithm it didn't recognize. These are skipped (with a
    /// `Warning` finding under rule S1) rather than failed — older
    /// verifiers must keep accepting hybrid-signed receipts produced
    /// by future ZP versions, as long as at least one signature on
    /// the entry is verifiable.
    #[serde(default)]
    pub signatures_skipped_unsupported: usize,
    /// IDs of all rules that were evaluated.
    #[serde(default)]
    pub rules_checked: Vec<String>,
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
    /// - P1: Chain extension (first entry has no parent)
    /// - P2: Content hash integrity (each entry's recomputed hash matches stored)
    /// - M3: Hash-chain continuity (each entry's parent_link matches previous self_link)
    /// - M4: Trajectory monotonicity (timestamps non-decreasing)
    /// - S1: Ed25519 signature validity (for entries that expose signature data)
    pub fn verify<E: VerifiableEntry>(&self, entries: &[E]) -> VerifyReport {
        let mut report = VerifyReport {
            entries_checked: entries.len(),
            receipts_checked: entries.len(),
            findings: Vec::new(),
            passed: true,
            genesis_timestamp: None,
            chain_head: None,
            signature_checks: 0,
            signature_failures: 0,
            signatures_skipped_unsupported: 0,
            rules_checked: vec![
                "P1".to_string(),
                "P2".to_string(),
                "M3".to_string(),
                "M4".to_string(),
                "S1".to_string(),
            ],
        };

        if entries.is_empty() {
            return report;
        }

        report.genesis_timestamp = Some(entries[0].timestamp());
        report.chain_head = Some(entries[entries.len() - 1].self_link().to_string());

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

        // S1 on genesis too — sign-everything-or-nothing, the genesis is no exception.
        check_signature(&entries[0], &mut report);

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

            // P2: Content hash integrity.
            if !curr.content_hash_valid() {
                report.findings.push(VerifyFinding {
                    rule: "P2".to_string(),
                    entry_id: curr.entry_id().to_string(),
                    description: "Content hash mismatch — possible tampering".to_string(),
                    severity: FindingSeverity::Error,
                });
                report.passed = false;
            }

            // S1: Ed25519 signature validity.
            check_signature(curr, &mut report);
        }

        report
    }
}

/// Run rule S1 on a single entry.
///
/// **F8 — algorithm-agile signature checking.** Entries that expose
/// the new [`VerifiableEntry::signature_blocks`] vec take the
/// algorithm-aware path:
///
/// * Each `Ed25519` block is verified individually. Each successful
///   verification increments `signature_checks`; each failure also
///   increments `signature_failures` and adds an Error finding.
/// * Each `Experimental` block is *skipped*: the verifier doesn't
///   know how to verify it, so it logs a Warning finding and
///   increments `signatures_skipped_unsupported`. **Skipping is not a
///   failure** — older verifiers must keep accepting hybrid-signed
///   receipts produced by future ZP versions.
/// * If the vec is non-empty but contains zero `Ed25519` blocks, the
///   entry is rejected (Error). At least one verifiable signature is
///   required; pure-experimental signing isn't a thing yet.
///
/// Entries that don't expose `signature_blocks` (legacy fixtures, the
/// in-tree `TestEntry`) fall back to the single-signature accessors —
/// identical to the pre-F8 behavior.
fn check_signature<E: VerifiableEntry>(entry: &E, report: &mut VerifyReport) {
    let blocks = entry.signature_blocks();
    let payload = match entry.signed_payload() {
        Some(p) => p,
        None => {
            // No payload to verify against — nothing to check, regardless
            // of which signature accessor is in use.
            return;
        }
    };

    if blocks.is_empty() {
        // Legacy single-signature path. Identical to pre-F8 behavior.
        if let (Some(sig_b64), Some(pk_hex)) =
            (entry.signature_b64(), entry.signer_public_key_hex())
        {
            verify_one_ed25519(entry, sig_b64, pk_hex, payload, report);
        }
        return;
    }

    // F8 path. Iterate every block; require ≥ 1 Ed25519.
    let mut ed25519_seen = 0usize;
    for block in &blocks {
        if block.algorithm == "ed25519" {
            ed25519_seen += 1;
            verify_one_ed25519(
                entry,
                block.signature_b64,
                block.key_id,
                payload,
                report,
            );
        } else {
            // Experimental algorithm — warn and skip.
            report.signatures_skipped_unsupported += 1;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: entry.entry_id().to_string(),
                description: format!(
                    "Skipping signature: algorithm '{}' not recognized by this verifier (key_id={})",
                    block.algorithm, block.key_id
                ),
                severity: FindingSeverity::Warning,
            });
            tracing::warn!(
                entry = entry.entry_id(),
                algorithm = block.algorithm,
                key_id = block.key_id,
                "F8: skipping signature block — unsupported algorithm",
            );
        }
    }

    if ed25519_seen == 0 {
        report.signature_failures += 1;
        report.findings.push(VerifyFinding {
            rule: "S1".to_string(),
            entry_id: entry.entry_id().to_string(),
            description:
                "Receipt has signature blocks but none are Ed25519 — at least one Ed25519 signature is required"
                    .to_string(),
            severity: FindingSeverity::Error,
        });
        report.passed = false;
    }
}

/// Verify a single Ed25519 signature, recording the outcome on `report`.
///
/// Extracted so the legacy single-sig path and the F8 vec path share
/// exactly the same crypto-error handling — same finding strings, same
/// counter updates, same fail-the-chain semantics.
fn verify_one_ed25519<E: VerifiableEntry>(
    entry: &E,
    sig_b64: &str,
    pk_hex: &str,
    payload: &[u8],
    report: &mut VerifyReport,
) {
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    report.signature_checks += 1;

    let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(sig_b64) {
        Ok(b) => b,
        Err(e) => {
            report.signature_failures += 1;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: entry.entry_id().to_string(),
                description: format!("Invalid signature encoding: {}", e),
                severity: FindingSeverity::Error,
            });
            report.passed = false;
            return;
        }
    };

    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            report.signature_failures += 1;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: entry.entry_id().to_string(),
                description: format!("Invalid signature format: {}", e),
                severity: FindingSeverity::Error,
            });
            report.passed = false;
            return;
        }
    };

    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(e) => {
            report.signature_failures += 1;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: entry.entry_id().to_string(),
                description: format!("Invalid public key hex: {}", e),
                severity: FindingSeverity::Error,
            });
            report.passed = false;
            return;
        }
    };

    let pk_array: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            report.signature_failures += 1;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: entry.entry_id().to_string(),
                description: format!(
                    "Public key wrong length: expected 32 bytes, got {}",
                    pk_bytes.len()
                ),
                severity: FindingSeverity::Error,
            });
            report.passed = false;
            return;
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(e) => {
            report.signature_failures += 1;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: entry.entry_id().to_string(),
                description: format!("Invalid public key: {}", e),
                severity: FindingSeverity::Error,
            });
            report.passed = false;
            return;
        }
    };

    if verifying_key.verify(payload, &signature).is_err() {
        report.signature_failures += 1;
        report.findings.push(VerifyFinding {
            rule: "S1".to_string(),
            entry_id: entry.entry_id().to_string(),
            description: "Signature does not verify against signer_public_key".to_string(),
            severity: FindingSeverity::Error,
        });
        report.passed = false;
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

    impl VerifiableEntry for TestEntry {
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
