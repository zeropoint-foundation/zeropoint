//! Claim 2 hardening tests: collective audit / present-state compression.
//!
//! Claim 2 states: "Present state compresses full history." The mechanism
//! is the `AuditChallenge → AuditResponse → PeerAuditAttestation` protocol.
//! The falsifier is a peer that claims a `chain_tip` that does not match
//! its actual chain.
//!
//! These tests exercise `verify_response` (which composes tip consistency
//! with P1 chain-link continuity) against adversarial response shapes. They
//! use real `AuditStore` entries so the test chain matches production shapes.
//!
//! Run with:
//! ```bash
//! cargo test -p zp-hardening-tests claim2
//! ```

// Gated to match the items below, and to match `uuid::Uuid` immediately
// after — an ungated `use tempfile::tempdir;` here read as unused in the lib
// target and was deleted by `cargo clippy --fix` on 2026-08-12. See the note
// in `receipt_chain_stress.rs`.
#[cfg(test)]
use tempfile::tempdir;
#[cfg(test)]
use uuid::Uuid;
#[cfg(test)]
use zp_audit::{
    response_tip_consistent, verify_response, AuditResponse, AuditStore, CompactAuditEntry,
    UnsealedEntry,
};
#[cfg(test)]
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

/// Build a small chain in an unsigned store and return the entries.
#[cfg(test)]
fn build_chain(n: usize) -> Vec<zp_core::AuditEntry> {
    let dir = tempdir().expect("tempdir");
    let db = dir.path().join("audit.db");
    let mut store = AuditStore::open_unsigned(&db).expect("open");
    for i in 0..n {
        store
            .append(UnsealedEntry::new(
                ActorId::System("claim2-test".to_string()),
                AuditAction::SystemEvent {
                    event: format!("claim2:evt:{i}"),
                },
                ConversationId(Uuid::now_v7()),
                PolicyDecision::Allow { conditions: vec![] },
                "claim2-test",
            ))
            .expect("append");
    }
    store.export_chain(n + 1).expect("export")
}

/// Construct an honest `AuditResponse` from a chain slice.
#[cfg(test)]
fn honest_response(entries: &[zp_core::AuditEntry]) -> AuditResponse {
    let compact: Vec<CompactAuditEntry> =
        entries.iter().map(CompactAuditEntry::from_entry).collect();
    let chain_tip = compact.last().map(|e| e.eh.clone()).unwrap_or_default();
    AuditResponse {
        challenge_id: "chal-test".to_string(),
        entries: compact,
        chain_tip,
        total_available: entries.len(),
        has_more: false,
    }
}

// ─── Happy path ──────────────────────────────────────────────────────────────

/// An honest response from a well-behaved peer must verify cleanly.
#[test]
fn claim2_honest_response_verifies_clean() {
    let chain = build_chain(5);
    let response = honest_response(&chain);

    assert!(
        response_tip_consistent(&response),
        "honest response must have consistent chain_tip"
    );

    let att = verify_response("honest-peer", &response);
    assert!(att.chain_valid, "honest chain must be valid: {:?}", att);
    assert_eq!(att.entries_verified, 5);
    assert_eq!(att.peer, "honest-peer");
}

// ─── Adversarial: chain_tip tampering ────────────────────────────────────────

/// A peer that claims a fabricated chain_tip (doesn't match last entry) must
/// be detected. This is the primary Claim 2 falsifier.
#[test]
fn claim2_fabricated_chain_tip_detected() {
    let chain = build_chain(4);
    let mut response = honest_response(&chain);

    // Adversary overwrites chain_tip with an arbitrary hash.
    response.chain_tip = "adversary_fabricated_tip".to_string();

    assert!(
        !response_tip_consistent(&response),
        "fabricated tip must fail consistency check"
    );

    let att = verify_response("adversarial-peer", &response);
    assert!(
        !att.chain_valid,
        "attestation must reject fabricated chain_tip"
    );
}

/// Empty entries with a non-empty claimed tip must be rejected.
/// An adversary cannot assert a chain state without providing the entries
/// that anchor it.
#[test]
fn claim2_empty_entries_nonempty_tip_detected() {
    let response = AuditResponse {
        challenge_id: "chal-empty".to_string(),
        entries: vec![],
        chain_tip: "some_fabricated_tip".to_string(),
        total_available: 0,
        has_more: false,
    };

    assert!(
        !response_tip_consistent(&response),
        "non-empty tip with no entries must be rejected"
    );

    let att = verify_response("adversarial-peer", &response);
    assert!(
        !att.chain_valid,
        "zero-entry response with claimed tip must fail"
    );
}

/// Empty entries with an empty tip is the legitimate "no chain yet" shape.
#[test]
fn claim2_empty_entries_empty_tip_is_valid() {
    let response = AuditResponse {
        challenge_id: "chal-fresh".to_string(),
        entries: vec![],
        chain_tip: String::new(),
        total_available: 0,
        has_more: false,
    };

    assert!(
        response_tip_consistent(&response),
        "empty entries with empty tip is the honest zero-state"
    );

    let att = verify_response("fresh-peer", &response);
    assert!(att.chain_valid, "empty chain with empty tip must be valid");
}

// ─── Adversarial: prev_hash link tampering ───────────────────────────────────

/// A peer that tampers with a prev_hash link (internal chain break) must
/// be detected even when the claimed chain_tip is self-consistent.
#[test]
fn claim2_tampered_prev_hash_detected() {
    let chain = build_chain(4);
    let mut response = honest_response(&chain);

    // Adversary breaks an internal link but updates chain_tip to match
    // the (now-inconsistent) final entry — tip is consistent with the
    // last entry, but the internal link is broken.
    response.entries[2].ph = "tampered_prev_hash".to_string();

    // chain_tip still matches last entry — tip check passes.
    // But link check must fail.
    let att = verify_response("adversarial-peer", &response);
    assert!(
        !att.chain_valid,
        "broken prev_hash link must be detected even with consistent tip"
    );
}

/// A peer that both breaks a link AND fabricates the tip must also be caught.
#[test]
fn claim2_both_attacks_simultaneously_detected() {
    let chain = build_chain(3);
    let mut response = honest_response(&chain);

    response.entries[1].ph = "broken".to_string();
    response.chain_tip = "also_fabricated".to_string();

    assert!(!response_tip_consistent(&response));
    let att = verify_response("adversarial-peer", &response);
    assert!(!att.chain_valid);
}

// ─── Single-entry edge cases ──────────────────────────────────────────────────

/// Single honest entry — no windows(2) to check, tip must still match.
#[test]
fn claim2_single_entry_verifies() {
    let chain = build_chain(1);
    let response = honest_response(&chain);

    assert!(response_tip_consistent(&response));
    let att = verify_response("peer-single", &response);
    assert!(att.chain_valid);
    assert_eq!(att.entries_verified, 1);
}

/// Single entry with a fabricated tip must be detected.
#[test]
fn claim2_single_entry_fabricated_tip_detected() {
    let chain = build_chain(1);
    let mut response = honest_response(&chain);
    response.chain_tip = "fabricated".to_string();

    assert!(!response_tip_consistent(&response));
    let att = verify_response("peer-single-adversary", &response);
    assert!(!att.chain_valid);
}
