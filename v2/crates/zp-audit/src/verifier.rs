//! Peer-to-peer audit chain verification.
//!
//! When two agents exchange audit chains, the receiving agent needs to verify
//! that the chain is intact and trustworthy. This module provides the tools
//! to do that:
//!
//! ```text
//! Peer A                              Peer B
//!   │                                    │
//!   │── "Show me your audit chain" ────▶│
//!   │                                    │
//!   │◀──── [AuditEntry, AuditEntry, ...] │
//!   │                                    │
//!   │  verify_chain()                    │
//!   │  verify_entry_hashes()             │
//!   │  verify_signatures()               │
//!   │                                    │
//!   │  VerificationReport {              │
//!   │    chain_valid: true/false,        │
//!   │    entries_verified: N,            │
//!   │    signature_results: [...],       │
//!   │  }                                 │
//! ```
//!
//! Design:
//! - Stateless verification: operates on a slice of entries, no DB needed
//! - Recomputes hashes deterministically using the same algorithm as ChainBuilder
//! - Signature verification uses ed25519 public keys from peer identity
//! - Returns a detailed report, not just pass/fail

use serde::{Deserialize, Serialize};
use serde_json::json;
use zp_core::AuditEntry;

/// Result of verifying a single audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryVerification {
    /// The entry ID that was verified.
    pub entry_id: String,
    /// Whether the entry_hash matches a recomputed hash.
    pub hash_valid: bool,
    /// Whether the prev_hash links correctly to the prior entry.
    pub chain_link_valid: bool,
    /// Signature verification result (None if no signature present).
    pub signature_valid: Option<bool>,
    /// Human-readable issue, if any.
    pub issue: Option<String>,
}

/// Summary report of verifying an audit chain segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Total number of entries examined.
    pub entries_examined: usize,
    /// Number of entries with valid hashes.
    pub hashes_valid: usize,
    /// Number of entries with valid chain links.
    pub chain_links_valid: usize,
    /// Number of entries with valid signatures (out of those that have signatures).
    pub signatures_valid: usize,
    /// Number of entries that have signatures.
    pub signatures_present: usize,
    /// Whether the entire chain is considered valid.
    pub chain_valid: bool,
    /// Per-entry verification details.
    pub entries: Vec<EntryVerification>,
    /// Overall issues found.
    pub issues: Vec<String>,
}

impl VerificationReport {
    /// Whether the chain is fully verified with no issues.
    pub fn is_clean(&self) -> bool {
        self.chain_valid && self.issues.is_empty()
    }

    /// Percentage of entries with valid hashes (0.0 - 1.0).
    pub fn hash_validity_ratio(&self) -> f64 {
        if self.entries_examined == 0 {
            return 1.0;
        }
        self.hashes_valid as f64 / self.entries_examined as f64
    }
}

/// Verifier for peer-provided audit chain segments.
///
/// Operates statelessly on a slice of `AuditEntry` values.
/// Does not require database access — the entries come from the peer.
pub struct ChainVerifier {
    /// Known signing keys for signature verification.
    /// Maps hex-encoded public key to a human-readable label.
    known_keys: Vec<([u8; 32], String)>,
}

impl ChainVerifier {
    /// Create a new verifier with no known signing keys.
    pub fn new() -> Self {
        Self {
            known_keys: Vec::new(),
        }
    }

    /// Add a known signing key for signature verification.
    pub fn with_signing_key(mut self, key: [u8; 32], label: String) -> Self {
        self.known_keys.push((key, label));
        self
    }

    /// Verify a chain segment.
    ///
    /// The entries should be in chronological order (oldest first).
    /// If `expected_prev_hash` is provided, the first entry's `prev_hash`
    /// must match it. If None, genesis hash is assumed.
    pub fn verify(
        &self,
        entries: &[AuditEntry],
        expected_prev_hash: Option<&str>,
    ) -> VerificationReport {
        let mut report = VerificationReport {
            entries_examined: entries.len(),
            hashes_valid: 0,
            chain_links_valid: 0,
            signatures_valid: 0,
            signatures_present: 0,
            chain_valid: true,
            entries: Vec::with_capacity(entries.len()),
            issues: Vec::new(),
        };

        if entries.is_empty() {
            return report;
        }

        // Determine the expected prev_hash for the first entry
        let genesis = blake3::hash(b"").to_hex().to_string();
        let first_expected = expected_prev_hash.unwrap_or(&genesis);

        for (i, entry) in entries.iter().enumerate() {
            let mut ev = EntryVerification {
                entry_id: format!("{:?}", entry.id.0),
                hash_valid: false,
                chain_link_valid: false,
                signature_valid: None,
                issue: None,
            };

            // 1. Verify chain linkage
            let expected_prev = if i == 0 {
                first_expected.to_string()
            } else {
                entries[i - 1].entry_hash.clone()
            };

            if entry.prev_hash == expected_prev {
                ev.chain_link_valid = true;
                report.chain_links_valid += 1;
            } else {
                ev.chain_link_valid = false;
                ev.issue = Some(format!(
                    "Chain break: prev_hash {} does not match expected {}",
                    &entry.prev_hash[..8.min(entry.prev_hash.len())],
                    &expected_prev[..8.min(expected_prev.len())],
                ));
                report.chain_valid = false;
                report
                    .issues
                    .push(format!("Entry {} has broken chain link", ev.entry_id));
            }

            // 2. Verify entry hash (recompute)
            let recomputed = recompute_entry_hash(entry);
            if entry.entry_hash == recomputed {
                ev.hash_valid = true;
                report.hashes_valid += 1;
            } else {
                ev.hash_valid = false;
                if ev.issue.is_none() {
                    ev.issue = Some(format!(
                        "Hash mismatch: stored {} vs computed {}",
                        &entry.entry_hash[..8.min(entry.entry_hash.len())],
                        &recomputed[..8.min(recomputed.len())],
                    ));
                }
                report.chain_valid = false;
                report
                    .issues
                    .push(format!("Entry {} has invalid entry_hash", ev.entry_id));
            }

            // 3. Verify signature (if present)
            if let Some(sig_hex) = &entry.signature {
                report.signatures_present += 1;
                let sig_valid = self.verify_signature(entry, sig_hex);
                ev.signature_valid = Some(sig_valid);
                if sig_valid {
                    report.signatures_valid += 1;
                } else {
                    report
                        .issues
                        .push(format!("Entry {} has invalid signature", ev.entry_id));
                }
            }

            report.entries.push(ev);
        }

        report
    }

    /// Verify a signature on an entry against known keys.
    fn verify_signature(&self, entry: &AuditEntry, sig_hex: &str) -> bool {
        use ed25519_dalek::VerifyingKey;

        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        // The signed material is the entry_hash
        let message = entry.entry_hash.as_bytes();

        // Try each known key
        for (key_bytes, _label) in &self.known_keys {
            if let Ok(verifying_key) = VerifyingKey::from_bytes(key_bytes) {
                if verifying_key.verify_strict(message, &signature).is_ok() {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for ChainVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Recompute the entry hash for verification.
///
/// Uses the exact same algorithm as `ChainBuilder::build_entry` —
/// a deterministic JSON serialization hashed with blake3.
///
/// Note: the signature field is always hashed as `null` because the entry_hash
/// is computed before the signature exists. The signature covers the entry_hash,
/// not the other way around.
fn recompute_entry_hash(entry: &AuditEntry) -> String {
    let entry_data = json!({
        "id": format!("{:?}", entry.id.0),
        "timestamp": entry.timestamp.to_rfc3339(),
        "prev_hash": entry.prev_hash,
        "actor": format!("{:?}", entry.actor),
        "action": serde_json::to_value(&entry.action).unwrap_or(json!(null)),
        "conversation_id": format!("{:?}", entry.conversation_id.0),
        "policy_decision": serde_json::to_value(&entry.policy_decision).unwrap_or(json!(null)),
        "policy_module": entry.policy_module,
        "receipt": entry.receipt.as_ref().map(|r| serde_json::to_value(r).unwrap_or(json!(null))),
        "signature": Option::<String>::None,
    });

    let entry_bytes = serde_json::to_vec(&entry_data).unwrap_or_default();
    blake3::hash(&entry_bytes).to_hex().to_string()
}

/// Verify chain linkage and produce a report (no hash recomputation).
///
/// This is the right choice for DB-exported entries where the stored hashes
/// are trusted but the in-memory fields may not round-trip perfectly.
pub fn verify_linkage_report(
    entries: &[AuditEntry],
    expected_prev_hash: Option<&str>,
) -> VerificationReport {
    let mut report = VerificationReport {
        entries_examined: entries.len(),
        hashes_valid: entries.len(), // trust stored hashes
        chain_links_valid: 0,
        signatures_valid: 0,
        signatures_present: 0,
        chain_valid: true,
        entries: Vec::with_capacity(entries.len()),
        issues: Vec::new(),
    };

    if entries.is_empty() {
        return report;
    }

    let genesis = blake3::hash(b"").to_hex().to_string();
    let first_expected = expected_prev_hash.unwrap_or(&genesis);

    for (i, entry) in entries.iter().enumerate() {
        let expected_prev = if i == 0 {
            first_expected.to_string()
        } else {
            entries[i - 1].entry_hash.clone()
        };

        let chain_link_valid = entry.prev_hash == expected_prev;
        if chain_link_valid {
            report.chain_links_valid += 1;
        } else {
            report.chain_valid = false;
            report
                .issues
                .push(format!("Entry {:?} has broken chain link", entry.id.0));
        }

        report.entries.push(EntryVerification {
            entry_id: format!("{:?}", entry.id.0),
            hash_valid: true, // trust stored hash
            chain_link_valid,
            signature_valid: None,
            issue: if chain_link_valid {
                None
            } else {
                Some("Chain link broken".to_string())
            },
        });
    }

    report
}

/// Convenience: verify just the hash chain linkage (no hash recomputation or signatures).
/// This is the fast path — O(n) with no crypto operations.
pub fn verify_linkage(entries: &[AuditEntry]) -> bool {
    if entries.is_empty() {
        return true;
    }

    let genesis = blake3::hash(b"").to_hex().to_string();
    if entries[0].prev_hash != genesis {
        return false;
    }

    for i in 1..entries.len() {
        if entries[i].prev_hash != entries[i - 1].entry_hash {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainBuilder;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use uuid::Uuid;
    use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

    fn make_chain(n: usize) -> Vec<AuditEntry> {
        let actor = ActorId::System("test-agent".to_string());
        let action = AuditAction::SystemEvent {
            event: "test".to_string(),
        };
        let conv_id = ConversationId(Uuid::now_v7());
        let decision = PolicyDecision::Allow { conditions: vec![] };

        let mut chain: Vec<AuditEntry> = Vec::new();
        for i in 0..n {
            let prev_hash = if i == 0 {
                blake3::hash(b"").to_hex().to_string()
            } else {
                chain[i - 1].entry_hash.clone()
            };

            let entry = ChainBuilder::build_entry(
                &prev_hash,
                actor.clone(),
                action.clone(),
                conv_id.clone(),
                decision.clone(),
                format!("module-{}", i),
                None,
                None,
            );
            chain.push(entry);
        }
        chain
    }

    #[test]
    fn test_verify_valid_chain() {
        let chain = make_chain(5);
        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);

        assert!(report.chain_valid);
        assert!(report.is_clean());
        assert_eq!(report.entries_examined, 5);
        assert_eq!(report.hashes_valid, 5);
        assert_eq!(report.chain_links_valid, 5);
        assert_eq!(report.signatures_present, 0);
    }

    #[test]
    fn test_verify_empty_chain() {
        let verifier = ChainVerifier::new();
        let report = verifier.verify(&[], None);

        assert!(report.chain_valid);
        assert!(report.is_clean());
        assert_eq!(report.entries_examined, 0);
    }

    #[test]
    fn test_verify_single_entry() {
        let chain = make_chain(1);
        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);

        assert!(report.chain_valid);
        assert_eq!(report.hashes_valid, 1);
        assert_eq!(report.chain_links_valid, 1);
    }

    #[test]
    fn test_verify_detects_tampered_hash() {
        let mut chain = make_chain(3);
        // Tamper with middle entry's hash
        chain[1].entry_hash = "0000deadbeef".to_string();

        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);

        assert!(!report.chain_valid);
        // Entry 1 has bad hash, entry 2 has broken chain link
        assert!(report.hashes_valid < 3);
        assert!(!report.issues.is_empty());
    }

    #[test]
    fn test_verify_detects_broken_chain_link() {
        let mut chain = make_chain(3);
        // Break the chain link: entry 2's prev_hash doesn't match entry 1's hash
        chain[2].prev_hash = "aaaa".to_string();

        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);

        assert!(!report.chain_valid);
        assert_eq!(report.entries[2].chain_link_valid, false);
    }

    #[test]
    fn test_verify_detects_wrong_genesis() {
        let mut chain = make_chain(2);
        // Corrupt the genesis link
        chain[0].prev_hash = "not-the-genesis-hash".to_string();

        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);

        assert!(!report.chain_valid);
        assert_eq!(report.entries[0].chain_link_valid, false);
    }

    #[test]
    fn test_verify_with_expected_prev_hash() {
        // Build a chain segment that starts from a known anchor
        let anchor_hash = "abcdef1234567890".to_string();
        let actor = ActorId::System("test".to_string());
        let action = AuditAction::SystemEvent {
            event: "test".to_string(),
        };
        let conv_id = ConversationId(Uuid::now_v7());
        let decision = PolicyDecision::Allow { conditions: vec![] };

        let entry = ChainBuilder::build_entry(
            &anchor_hash,
            actor,
            action,
            conv_id,
            decision,
            "mod".to_string(),
            None,
            None,
        );

        let verifier = ChainVerifier::new();

        // With correct anchor — valid
        let report = verifier.verify(&[entry.clone()], Some(&anchor_hash));
        assert!(report.chain_valid);
        assert_eq!(report.chain_links_valid, 1);

        // With wrong anchor — invalid
        let report = verifier.verify(&[entry], Some("wrong-anchor"));
        assert!(!report.chain_valid);
    }

    #[test]
    fn test_verify_signed_entries() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        let mut chain = make_chain(2);

        // Sign each entry: signature = sign(entry_hash)
        for entry in &mut chain {
            let sig = signing_key.sign(entry.entry_hash.as_bytes());
            entry.signature = Some(hex::encode(sig.to_bytes()));
        }

        let verifier = ChainVerifier::new()
            .with_signing_key(verifying_key.to_bytes(), "test-signer".to_string());

        let report = verifier.verify(&chain, None);

        assert!(report.chain_valid);
        assert_eq!(report.signatures_present, 2);
        assert_eq!(report.signatures_valid, 2);
    }

    #[test]
    fn test_verify_rejects_wrong_signature() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let wrong_key = SigningKey::generate(&mut rand::thread_rng());

        let mut chain = make_chain(1);
        // Sign with one key
        let sig = signing_key.sign(chain[0].entry_hash.as_bytes());
        chain[0].signature = Some(hex::encode(sig.to_bytes()));

        // Verify with different key
        let verifier = ChainVerifier::new()
            .with_signing_key(wrong_key.verifying_key().to_bytes(), "wrong".to_string());

        let report = verifier.verify(&chain, None);

        assert!(report.chain_valid); // Chain is still valid, just sig fails
        assert_eq!(report.signatures_present, 1);
        assert_eq!(report.signatures_valid, 0);
        assert_eq!(report.entries[0].signature_valid, Some(false));
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());

        let mut chain = make_chain(1);
        let sig = signing_key.sign(chain[0].entry_hash.as_bytes());
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[0] ^= 0xFF; // Tamper
        chain[0].signature = Some(hex::encode(sig_bytes));

        let verifier = ChainVerifier::new()
            .with_signing_key(signing_key.verifying_key().to_bytes(), "signer".to_string());

        let report = verifier.verify(&chain, None);
        assert_eq!(report.signatures_valid, 0);
    }

    #[test]
    fn test_verify_linkage_fast_path() {
        let chain = make_chain(10);
        assert!(verify_linkage(&chain));

        let mut broken = make_chain(10);
        broken[5].prev_hash = "broken".to_string();
        assert!(!verify_linkage(&broken));

        assert!(verify_linkage(&[]));
    }

    #[test]
    fn test_hash_validity_ratio() {
        let chain = make_chain(4);
        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);
        assert!((report.hash_validity_ratio() - 1.0).abs() < f64::EPSILON);

        let empty_report = verifier.verify(&[], None);
        assert!((empty_report.hash_validity_ratio() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_report_details_per_entry() {
        let chain = make_chain(3);
        let verifier = ChainVerifier::new();
        let report = verifier.verify(&chain, None);

        assert_eq!(report.entries.len(), 3);
        for ev in &report.entries {
            assert!(ev.hash_valid);
            assert!(ev.chain_link_valid);
            assert!(ev.issue.is_none());
            assert!(ev.signature_valid.is_none()); // no signatures
        }
    }

    #[test]
    fn test_mixed_signed_and_unsigned() {
        let signing_key = SigningKey::generate(&mut rand::thread_rng());
        let mut chain = make_chain(3);

        // Only sign the middle entry
        let sig = signing_key.sign(chain[1].entry_hash.as_bytes());
        chain[1].signature = Some(hex::encode(sig.to_bytes()));

        let verifier = ChainVerifier::new().with_signing_key(
            signing_key.verifying_key().to_bytes(),
            "partial".to_string(),
        );

        let report = verifier.verify(&chain, None);

        assert!(report.chain_valid);
        assert_eq!(report.signatures_present, 1);
        assert_eq!(report.signatures_valid, 1);
        assert!(report.entries[0].signature_valid.is_none());
        assert_eq!(report.entries[1].signature_valid, Some(true));
        assert!(report.entries[2].signature_valid.is_none());
    }
}
