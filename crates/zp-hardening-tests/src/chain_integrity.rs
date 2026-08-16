//! Claim 1 hardening tests: chain integrity via `verify_with_catalog()`.
//!
//! These tests prove that the catalog verifier's S1 rule actually checks
//! the per-entry Ed25519 signatures written by `AuditSigner` — not the
//! receipt-level signatures that lived in `receipt.signatures` before the
//! Claim 1 gap was closed.
//!
//! Run with:
//! ```bash
//! cargo test -p zp-hardening-tests chain_integrity
//! ```

#[cfg(test)]
use tempfile::tempdir;
#[cfg(test)]
use uuid::Uuid;
#[cfg(test)]
use zp_audit::{AuditSigner, AuditStore, UnsealedEntry};
#[cfg(test)]
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

/// Construct a minimal `UnsealedEntry` for chain testing.
#[cfg(test)]
fn test_entry(label: &str) -> UnsealedEntry {
    UnsealedEntry::new(
        ActorId::System("chain-integrity-test".to_string()),
        AuditAction::SystemEvent {
            event: format!("hardening:{label}"),
        },
        ConversationId(Uuid::now_v7()),
        PolicyDecision::Allow { conditions: vec![] },
        "test",
    )
}

/// A signed store with N entries must pass all catalog rules, and S1 must
/// have been exercised exactly N times (one per entry, including genesis).
///
/// This is the acceptance test for Claim 1 (chain integrity). If S1 were
/// still inspecting receipt-level signatures (the pre-fix gap), it would
/// find zero Ed25519 blocks on entries that have no receipt, and fail or
/// skip — not accumulate `signature_checks == N`.
#[test]
fn chain_integrity_signed_entries_verify_clean() {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");

    // Deterministic seed — production derives this from Genesis; tests can
    // use any 32 bytes. Same seed → same public key → reproducible key_id.
    let seed = [0x5Au8; 32];
    let signer = AuditSigner::from_seed(&seed);
    let mut store = AuditStore::open_signed(&db, signer).expect("open_signed");

    const N: usize = 3;
    for i in 0..N {
        let entry = test_entry(&format!("evt-{i}"));
        store.append(entry).expect("append");
    }

    let report = store.verify_with_catalog().expect("verify_with_catalog");

    assert!(
        report.passed,
        "Chain should pass all catalog rules; findings: {:#?}",
        report.findings
    );
    assert_eq!(
        report.entries_checked, N,
        "All {N} entries should have been checked"
    );
    assert_eq!(
        report.signature_checks, N,
        "S1 must have verified exactly {N} Ed25519 signatures (one per entry, including genesis). \
         Got {} — S1 may still be inspecting the wrong signature layer.",
        report.signature_checks
    );
    assert_eq!(
        report.signature_failures, 0,
        "No signature should have failed"
    );
    assert_eq!(report.error_count(), 0, "No error-level findings expected");
}

/// An unsigned store (entries have no `entry.signatures`) must still pass
/// P1, P2, M3, M4 — S1 simply skips entries that carry no signature blocks
/// rather than treating the absence as a failure.
///
/// This validates the open_unsigned path used in unit tests and read-only
/// CLI commands that have no Genesis-derived signer available.
#[test]
fn chain_integrity_unsigned_store_passes_structural_rules() {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");

    let mut store = AuditStore::open_unsigned(&db).expect("open_unsigned");

    for i in 0..3 {
        store
            .append(test_entry(&format!("unsigned-{i}")))
            .expect("append");
    }

    let report = store.verify_with_catalog().expect("verify_with_catalog");

    assert!(
        report.passed,
        "Unsigned chain should pass structural rules (P1/P2/M3/M4); findings: {:#?}",
        report.findings
    );
    assert_eq!(
        report.signature_checks, 0,
        "Unsigned entries carry no signature blocks — S1 should skip, not check"
    );
    assert_eq!(report.signature_failures, 0);
}
