//! Verifier for the foundation chain (Cloudflare Workers + D1).
//!
//! The foundation chain uses the same hash-chain discipline as the local
//! `zp-audit::AuditStore`, with two differences:
//!
//! 1. The canonical preimage schema is "foundation-canonical-v1" (not
//!    "ZP-canonical-v1") — it includes a `chain` sub-object carrying
//!    `chain_id`, `prev_hash`, and `sequence`.
//!
//! 2. Signatures are verified against the foundation worker's public key
//!    (fetched from `/api/v1/foundation/pubkey`), not the local operator key.
//!
//! Both sides use BLAKE3 over key-sorted, no-whitespace UTF-8 JSON, so the
//! same `zp_receipt::canonical` helpers are used here.
//!
//! # Cross-language conformance
//!
//! The TypeScript implementation lives in
//! `zeropointfoundation.org/src/chain/canonical.js`. Both must produce
//! identical bytes for the same logical preimage. The shared fixture at
//! `crates/zp-verify/tests/foundation-canonical-fixtures.json` pins expected
//! hashes; the Rust test suite and the TS test suite both assert against it.

use serde::{Deserialize, Serialize};

use crate::{FindingSeverity, VerifyFinding, VerifyReport};

/// BLAKE3 hash of the empty byte string — `blake3(b"")`.
/// Sentinel `prev_hash` for the genesis entry of any chain.
/// Byte-identical to `zp_audit::chain::genesis_hash()`.
pub const GENESIS_HASH: &str =
    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

// ── Wire types (match the JSON shape returned by /api/v1/foundation/chain) ──

/// One signature block on a chain entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationSignature {
    pub alg: String,
    pub kid: String,
    /// Base64-encoded (standard, padded) Ed25519 signature over the canonical
    /// preimage bytes (not over entry_hash — see preimage_bytes()).
    pub value: String,
}

/// A single entry in the foundation chain as returned by the worker API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationEntry {
    pub id: String,
    pub operator_id: String,
    pub claim: String,
    pub subject: String,
    pub capability_used: String,
    pub metadata: serde_json::Value,
    pub created_at: String,
    pub sequence: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub signatures: Vec<FoundationSignature>,
}

/// Response shape from `GET /api/v1/foundation/pubkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationPubkeyResponse {
    pub alg: String,
    pub kid: String,
    pub pubkey_hex: String,
    pub chain_id: String,
    pub schema_version: String,
}

/// Response shape from `GET /api/v1/foundation/chain`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundationChainResponse {
    pub chain_id: String,
    pub head_sequence: u64,
    pub entries: Vec<FoundationEntry>,
    pub next_from: Option<u64>,
}

// ── Preimage ──────────────────────────────────────────────────────────────────

/// Build the canonical preimage `serde_json::Value` for a foundation entry.
///
/// This must byte-match the TypeScript `canonicalString(preimage)` in
/// `src/chain/canonical.js`. Both sides: deep-sort keys, no whitespace,
/// UTF-8. The `entry_hash` and `signatures` fields are excluded — the
/// preimage defines what is *hashed*, not what is *stored*.
pub fn build_preimage(entry: &FoundationEntry, chain_id: &str) -> serde_json::Value {
    serde_json::json!({
        "capability_used": entry.capability_used,
        "chain": {
            "chain_id": chain_id,
            "prev_hash": entry.prev_hash,
            "sequence": entry.sequence,
        },
        "claim": entry.claim,
        "created_at": entry.created_at,
        "id": entry.id,
        "metadata": entry.metadata,
        "operator_id": entry.operator_id,
        "subject": entry.subject,
    })
}

/// Compute the canonical bytes of a foundation entry's preimage.
///
/// These bytes are:
/// - hashed (BLAKE3) to produce `entry_hash`
/// - signed (Ed25519) to produce the signature in `signatures[*].value`
pub fn preimage_bytes(entry: &FoundationEntry, chain_id: &str) -> Vec<u8> {
    zp_receipt::canonical::canonical_bytes(&build_preimage(entry, chain_id))
}

/// Recompute `entry_hash` from an entry's fields and return it as hex.
pub fn recompute_entry_hash(entry: &FoundationEntry, chain_id: &str) -> String {
    zp_receipt::canonical::canonical_hash(&build_preimage(entry, chain_id))
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Walk a slice of foundation chain entries and return a `VerifyReport`.
///
/// Checks (in order per entry):
/// - Sequence is exactly `expected_sequence` (monotonic from 0)
/// - `prev_hash` links correctly to the previous entry's `entry_hash`
///   (or to `genesis_hash()` for entry 0)
/// - Recomputed `entry_hash` matches stored value
/// - Each Ed25519 signature in `signatures` verifies against `pubkey_hex`
///
/// Entries are processed in the order supplied; caller is responsible for
/// providing them in ascending sequence order.
pub fn verify_foundation_chain(
    entries: &[FoundationEntry],
    chain_id: &str,
    pubkey_hex: &str,
) -> VerifyReport {
    use base64::Engine;
    // genesis_hash is the GENESIS_HASH constant defined in this module.

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
            "S1".to_string(),
        ],
    };

    if entries.is_empty() {
        return report;
    }

    let pk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            report.passed = false;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: "setup".to_string(),
                description: format!("Invalid pubkey_hex: {}", e),
                severity: FindingSeverity::Error,
            });
            return report;
        }
    };
    let pk_array: [u8; 32] = match pk_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            report.passed = false;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: "setup".to_string(),
                description: format!(
                    "pubkey_hex wrong length: expected 32 bytes, got {}",
                    pk_bytes.len()
                ),
                severity: FindingSeverity::Error,
            });
            return report;
        }
    };

    let genesis_sentinel = GENESIS_HASH.to_string();
    let mut expected_prev = genesis_sentinel.clone();

    for (i, entry) in entries.iter().enumerate() {
        let eid = entry.id.as_str();

        // Record genesis timestamp from the first entry.
        if i == 0 {
            report.genesis_timestamp = entry
                .created_at
                .parse::<chrono::DateTime<chrono::Utc>>()
                .ok();
        }

        // M3 — sequence monotonicity.
        if entry.sequence != i as u64 {
            report.passed = false;
            report.findings.push(VerifyFinding {
                rule: "M3".to_string(),
                entry_id: eid.to_string(),
                description: format!(
                    "Expected sequence {}, got {}",
                    i, entry.sequence
                ),
                severity: FindingSeverity::Error,
            });
        }

        // M3 — prev_hash linkage.
        if entry.prev_hash != expected_prev {
            report.passed = false;
            report.findings.push(VerifyFinding {
                rule: "M3".to_string(),
                entry_id: eid.to_string(),
                description: format!(
                    "prev_hash mismatch at sequence {}: expected {}, got {}",
                    entry.sequence, expected_prev, entry.prev_hash
                ),
                severity: FindingSeverity::Error,
            });
        }

        // P2 — content hash integrity.
        let computed_hash = recompute_entry_hash(entry, chain_id);
        if computed_hash != entry.entry_hash {
            report.passed = false;
            report.findings.push(VerifyFinding {
                rule: "P2".to_string(),
                entry_id: eid.to_string(),
                description: format!(
                    "entry_hash mismatch at sequence {}: computed {}, stored {}",
                    entry.sequence, computed_hash, entry.entry_hash
                ),
                severity: FindingSeverity::Error,
            });
        }

        // S1 — Ed25519 signature(s).
        let payload = preimage_bytes(entry, chain_id);
        let mut foundation_sigs = 0usize;
        for sig in &entry.signatures {
            if sig.alg != "Ed25519" {
                report.signatures_skipped_unsupported += 1;
                report.findings.push(VerifyFinding {
                    rule: "S1".to_string(),
                    entry_id: eid.to_string(),
                    description: format!(
                        "Skipping signature: algorithm '{}' not recognized (kid={})",
                        sig.alg, sig.kid
                    ),
                    severity: FindingSeverity::Warning,
                });
                continue;
            }
            foundation_sigs += 1;
            report.signature_checks += 1;

            let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(&sig.value) {
                Ok(b) => b,
                Err(e) => {
                    report.signature_failures += 1;
                    report.passed = false;
                    report.findings.push(VerifyFinding {
                        rule: "S1".to_string(),
                        entry_id: eid.to_string(),
                        description: format!("Invalid base64 signature: {}", e),
                        severity: FindingSeverity::Error,
                    });
                    continue;
                }
            };

            let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    report.signature_failures += 1;
                    report.passed = false;
                    report.findings.push(VerifyFinding {
                        rule: "S1".to_string(),
                        entry_id: eid.to_string(),
                        description: format!(
                            "Signature wrong length: expected 64 bytes, got {}",
                            sig_bytes.len()
                        ),
                        severity: FindingSeverity::Error,
                    });
                    continue;
                }
            };

            match zp_receipt::verify::verify_signature(&pk_array, &payload, &sig_arr) {
                Ok(()) => {}
                Err(_) => {
                    report.signature_failures += 1;
                    report.passed = false;
                    report.findings.push(VerifyFinding {
                        rule: "S1".to_string(),
                        entry_id: eid.to_string(),
                        description: format!(
                            "Signature verification failed at sequence {} (kid={})",
                            entry.sequence, sig.kid
                        ),
                        severity: FindingSeverity::Error,
                    });
                }
            }
        }

        // Require at least one Ed25519 signature on every entry.
        if foundation_sigs == 0 && entry.signatures.iter().any(|s| s.alg == "Ed25519") {
            // All Ed25519 sigs failed — already reported above.
        } else if foundation_sigs == 0 {
            report.passed = false;
            report.findings.push(VerifyFinding {
                rule: "S1".to_string(),
                entry_id: eid.to_string(),
                description: format!(
                    "No Ed25519 signature on entry at sequence {}",
                    entry.sequence
                ),
                severity: FindingSeverity::Error,
            });
        }

        expected_prev = entry.entry_hash.clone();
    }

    report.chain_head = entries.last().map(|e| e.entry_hash.clone());
    report
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// Build a minimal signed entry for test chains.
    fn make_entry(
        sequence: u64,
        prev_hash: &str,
        chain_id: &str,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> FoundationEntry {
        let id = format!("test-entry-{}", sequence);
        let created_at = "2026-05-20T00:00:00.000Z".to_string();
        let mut entry = FoundationEntry {
            id: id.clone(),
            operator_id: "test-op".to_string(),
            claim: "test:claim".to_string(),
            subject: "".to_string(),
            capability_used: "".to_string(),
            metadata: serde_json::json!({}),
            created_at,
            sequence,
            prev_hash: prev_hash.to_string(),
            entry_hash: String::new(), // filled below
            signatures: vec![],
        };

        let payload = preimage_bytes(&entry, chain_id);
        entry.entry_hash = zp_receipt::canonical::canonical_hash(&build_preimage(&entry, chain_id));

        use ed25519_dalek::Signer;
        let raw_sig = signing_key.sign(&payload);
        entry.signatures = vec![FoundationSignature {
            alg: "Ed25519".to_string(),
            kid: "foundation-root-v1".to_string(),
            value: base64::engine::general_purpose::STANDARD
                .encode(raw_sig.to_bytes()),
        }];

        entry
    }

    #[test]
    fn preimage_is_deterministic() {
        let entry = FoundationEntry {
            id: "test-id".to_string(),
            operator_id: "ken".to_string(),
            claim: "onboard:progress".to_string(),
            subject: "".to_string(),
            capability_used: "".to_string(),
            metadata: serde_json::json!({"step": 4, "status": "completed"}),
            created_at: "2026-05-20T17:42:11.123Z".to_string(),
            sequence: 1,
            prev_hash: "abc123".to_string(),
            entry_hash: "".to_string(),
            signatures: vec![],
        };
        let chain_id = "foundation:test01";
        let a = preimage_bytes(&entry, chain_id);
        let b = preimage_bytes(&entry, chain_id);
        assert_eq!(a, b);
    }

    #[test]
    fn preimage_hash_is_64_hex_chars() {
        let entry = FoundationEntry {
            id: "test-id".to_string(),
            operator_id: "ken".to_string(),
            claim: "test:claim".to_string(),
            subject: "".to_string(),
            capability_used: "".to_string(),
            metadata: serde_json::json!({}),
            created_at: "2026-05-20T00:00:00.000Z".to_string(),
            sequence: 0,
            prev_hash: GENESIS_HASH.to_string(),
            entry_hash: "".to_string(),
            signatures: vec![],
        };
        let hash = recompute_entry_hash(&entry, "foundation:test01");
        assert_eq!(hash.len(), 64, "entry_hash must be 64 hex chars");
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn verify_valid_chain() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let chain_id = "foundation:testchain01";

        let genesis_prev = GENESIS_HASH.to_string();
        let e0 = make_entry(0, &genesis_prev, chain_id, &sk);
        let e1 = make_entry(1, &e0.entry_hash, chain_id, &sk);
        let e2 = make_entry(2, &e1.entry_hash, chain_id, &sk);

        let report = verify_foundation_chain(&[e0, e1, e2], chain_id, &pk_hex);
        assert!(report.passed, "findings: {:?}", report.findings);
        assert_eq!(report.entries_checked, 3);
        assert_eq!(report.signature_checks, 3);
        assert_eq!(report.signature_failures, 0);
    }

    #[test]
    fn verify_tampered_metadata_fails() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let chain_id = "foundation:testchain02";

        let genesis_prev = GENESIS_HASH.to_string();
        let e0 = make_entry(0, &genesis_prev, chain_id, &sk);
        let mut e1 = make_entry(1, &e0.entry_hash, chain_id, &sk);
        e1.metadata = serde_json::json!({"tampered": true});

        let report = verify_foundation_chain(&[e0, e1], chain_id, &pk_hex);
        assert!(!report.passed);
        let errors: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == crate::FindingSeverity::Error)
            .collect();
        assert!(!errors.is_empty(), "expected error findings after tamper");
    }

    #[test]
    fn verify_broken_prev_hash_fails() {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let sk = SigningKey::generate(&mut OsRng);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        let chain_id = "foundation:testchain03";

        let genesis_prev = GENESIS_HASH.to_string();
        let e0 = make_entry(0, &genesis_prev, chain_id, &sk);
        // e1 points to wrong prev_hash — breaks chain linkage.
        let e1 = make_entry(1, "deadbeef0000", chain_id, &sk);

        let report = verify_foundation_chain(&[e0, e1], chain_id, &pk_hex);
        assert!(!report.passed);
    }
}
