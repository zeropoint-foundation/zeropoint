//! Unit tests: one accept case + one reject case per rule clause.
//!
//! Each test corresponds directly to a falsifiability claim from the
//! invariant catalog. The test names mirror the catalog rule ids so the
//! correspondence is searchable from either direction.

use zp_receipt::{canonical_hash, Receipt, Status};

use crate::{p1_chain_extension, m3_hash_chain_continuity, m4_trajectory_monotonicity, RuleId, Verifier};

// ---------------------------------------------------------------------------
// Helpers — build a chain of N receipts where each properly references the
// previous one. Returns receipts with valid hashes and ids.
// ---------------------------------------------------------------------------

fn build_chain(n: usize) -> Vec<Receipt> {
    let mut chain = Vec::with_capacity(n);
    let root = Receipt::intent("test-executor")
        .status(Status::Success)
        .finalize();
    chain.push(root);
    for _ in 1..n {
        let parent_id = chain.last().unwrap().id.clone();
        let next = Receipt::execution("test-executor")
            .parent(&parent_id)
            .status(Status::Success)
            .finalize();
        chain.push(next);
    }
    chain
}

/// Re-hash a receipt after we've mutated something. Without this, mutating
/// a receipt directly leaves the stored content_hash stale and would be
/// caught by P1 clause 1 instead of the clause we're trying to test.
fn rehash(r: &mut Receipt) {
    r.content_hash = canonical_hash(r);
}

// ---------------------------------------------------------------------------
// P1 — Chain extension
// ---------------------------------------------------------------------------

#[test]
fn p1_accepts_well_formed_chain() {
    let chain = build_chain(5);
    let v = p1_chain_extension(&chain);
    assert!(v.is_empty(), "expected no P1 violations, got {:?}", v);
}

#[test]
fn p1_rejects_tampered_content_hash() {
    let mut chain = build_chain(3);
    // Corrupt the content_hash on the middle receipt without re-hashing.
    chain[1].content_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();

    let v = p1_chain_extension(&chain);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, RuleId::P1);
    assert_eq!(v[0].index, 1);
    assert!(v[0].message.contains("content_hash"));
}

#[test]
fn p1_rejects_missing_parent_on_non_root() {
    let mut chain = build_chain(2);
    chain[1].parent_receipt_id = None;
    rehash(&mut chain[1]);

    let v = p1_chain_extension(&chain);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, RuleId::P1);
    assert_eq!(v[0].index, 1);
    assert!(v[0].message.contains("no parent_link"));
}

#[test]
fn p1_rejects_wrong_parent_id() {
    let mut chain = build_chain(3);
    chain[2].parent_receipt_id = Some("intn-deadbeef".into());
    rehash(&mut chain[2]);

    let v = p1_chain_extension(&chain);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, RuleId::P1);
    assert_eq!(v[0].index, 2);
    assert!(v[0].message.contains("does not match predecessor"));
}

// ---------------------------------------------------------------------------
// M3 — Hash-chain continuity
// ---------------------------------------------------------------------------

#[test]
fn m3_accepts_well_formed_chain() {
    let chain = build_chain(5);
    let v = m3_hash_chain_continuity(&chain);
    assert!(v.is_empty(), "expected no M3 violations, got {:?}", v);
}

#[test]
fn m3_accepts_empty_slice() {
    let v = m3_hash_chain_continuity::<Receipt>(&[]);
    assert!(v.is_empty());
}

#[test]
fn m3_rejects_duplicate_id() {
    let mut chain = build_chain(3);
    let dup_id = chain[0].id.clone();
    chain[2].id = dup_id;
    rehash(&mut chain[2]);

    let v = m3_hash_chain_continuity(&chain);
    assert!(v.iter().any(|x| x.rule == RuleId::M3 && x.message.contains("duplicate receipt id")));
}

#[test]
fn m3_rejects_two_roots() {
    let mut chain = build_chain(3);
    chain[2].parent_receipt_id = None; // second root
    rehash(&mut chain[2]);

    let v = m3_hash_chain_continuity(&chain);
    assert!(v.iter().any(|x| x.rule == RuleId::M3 && x.message.contains("more than one root")));
}

#[test]
fn m3_rejects_dangling_parent_reference() {
    let mut chain = build_chain(2);
    chain[1].parent_receipt_id = Some("intn-doesnotexist".into());
    rehash(&mut chain[1]);

    let v = m3_hash_chain_continuity(&chain);
    assert!(v.iter().any(|x| x.rule == RuleId::M3 && x.message.contains("does not resolve")));
}

#[test]
fn m3_rejects_chain_with_no_root() {
    let mut chain = build_chain(2);
    chain[0].parent_receipt_id = Some(chain[1].id.clone());
    rehash(&mut chain[0]);

    let v = m3_hash_chain_continuity(&chain);
    assert!(v.iter().any(|x| x.rule == RuleId::M3 && x.message.contains("no root")));
}

// ---------------------------------------------------------------------------
// M4 — Trajectory monotonicity
// ---------------------------------------------------------------------------

#[test]
fn m4_accepts_monotone_chain() {
    let chain = build_chain(4);
    let v = m4_trajectory_monotonicity(&chain);
    assert!(v.is_empty(), "expected no M4 violations, got {:?}", v);
}

#[test]
fn m4_rejects_clock_rollback() {
    let mut chain = build_chain(3);
    // Pull the middle receipt's timestamp back by an hour.
    chain[1].created_at = chain[0].created_at - chrono::Duration::hours(1);
    rehash(&mut chain[1]);

    let v = m4_trajectory_monotonicity(&chain);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule, RuleId::M4);
    assert_eq!(v[0].index, 1);
    assert!(v[0].message.contains("precedes predecessor"));
}

// ---------------------------------------------------------------------------
// Verifier — composition
// ---------------------------------------------------------------------------

#[test]
fn verifier_default_accepts_well_formed_chain() {
    let chain = build_chain(5);
    let report = Verifier::new().verify(&chain);
    assert!(report.is_well_formed(), "{:?}", report.violations());
    assert_eq!(report.receipts_checked, 5);
}

#[test]
fn verifier_reports_audit_01_style_failure() {
    // Reproduce the AUDIT-01 shape: a chain whose hash links break partway
    // through. This is the test that proves zp-verify v0 catches the
    // pentest finding it was scoped against.
    let mut chain = build_chain(6);
    // Break the link at index 3 the same way the running server's chain did:
    // valid receipt, but pr field doesn't match its predecessor.
    chain[3].parent_receipt_id = Some("intn-spurious".into());
    rehash(&mut chain[3]);

    let report = Verifier::new().verify(&chain);
    assert!(!report.is_well_formed());
    // P1 catches the local mismatch.
    assert!(report.count(RuleId::P1) >= 1);
    // M3 catches the dangling reference globally.
    assert!(report.count(RuleId::M3) >= 1);
}
