//! Catalog rules implemented in v0, generic over [`ChainEntry`].
//!
//! Each rule is a free function from `&[T]` to `Vec<Violation>` for any
//! `T: ChainEntry`. This shape keeps the rules independently testable,
//! lets the [`crate::Verifier`] compose them without internal state,
//! and lets the same rule logic verify both `zp_receipt::Receipt` chains
//! and `zp_core::AuditEntry` chains without duplication.

use std::collections::HashMap;

use crate::chain_entry::ChainEntry;
use crate::report::{RuleId, Violation};

// ---------------------------------------------------------------------------
// P1 — Chain extension
// ---------------------------------------------------------------------------

/// **P1 — Chain extension.**
///
/// > `Chain(Γ) ::= Chain(Γ′) · R`
/// > where `R.pr = id(last(Γ′))`
/// >    ∧ `R.ch = Blake3(content(R))`
///
/// v0 checks the two locally-verifiable clauses:
///
/// 1. The content hash on every entry matches its serialized body
///    (delegated to [`ChainEntry::content_hash_valid`]).
/// 2. Every non-root entry's `parent_link` equals the `self_link` of
///    the entry immediately before it in the slice.
///
/// The signature clause and the constitutional-allow clause are deferred
/// to v1 (they require `zp-keys` and `zp-policy` respectively).
pub fn p1_chain_extension<T: ChainEntry>(entries: &[T]) -> Vec<Violation> {
    let mut out = Vec::new();

    for (i, r) in entries.iter().enumerate() {
        // Clause 1: content hash matches body.
        if !r.content_hash_valid() {
            out.push(Violation {
                rule: RuleId::P1,
                index: i,
                receipt_id: Some(r.entry_id().to_string()),
                message: format!(
                    "content_hash does not match canonical body (tamper detected at index {})",
                    i
                ),
            });
        }

        // Clause 2: pr linkage. The root (index 0) is allowed to have no
        // parent; every other entry must point at its predecessor.
        if i == 0 {
            continue;
        }
        let prev = &entries[i - 1];
        match r.parent_link() {
            None => {
                out.push(Violation {
                    rule: RuleId::P1,
                    index: i,
                    receipt_id: Some(r.entry_id().to_string()),
                    message: format!(
                        "non-root entry at index {} has no parent_link (gap detection)",
                        i
                    ),
                });
            }
            Some(pr) if pr != prev.self_link() => {
                out.push(Violation {
                    rule: RuleId::P1,
                    index: i,
                    receipt_id: Some(r.entry_id().to_string()),
                    message: format!(
                        "parent_link={} does not match predecessor self_link={} at index {}",
                        pr,
                        prev.self_link(),
                        i
                    ),
                });
            }
            Some(_) => { /* well-formed extension */ }
        }
    }

    out
}

// ---------------------------------------------------------------------------
// M3 — Hash-chain continuity
// ---------------------------------------------------------------------------

/// **M3 — Hash-chain continuity.**
///
/// > ☐ For every R in Γ where R is not the Genesis entry,
/// > `R.pr = self_link(predecessor(R))` and the predecessor exists in Γ.
///
/// Where P1 is the local check ("does this entry extend the chain
/// correctly given the slice order?"), M3 is the global check ("does
/// the entire collection form one connected sequence?"). The two
/// catch overlapping but not identical failure modes:
///
/// - Duplicate ids in the chain → M3 reject.
/// - A `parent_link` that points to *some* entry in the collection but
///   not the immediate predecessor → P1 catches the ordering bug; M3
///   confirms the collection is at least a connected set.
/// - More than one root → M3 reject.
/// - A `parent_link` that points to nothing in the collection at all →
///   M3 reject (dangling reference).
pub fn m3_hash_chain_continuity<T: ChainEntry>(entries: &[T]) -> Vec<Violation> {
    let mut out = Vec::new();

    if entries.is_empty() {
        return out;
    }

    // Build a self_link → index map. Duplicate self_links are themselves
    // a violation: the catalog requires the link to be a function.
    let mut link_to_index: HashMap<&str, usize> = HashMap::new();
    for (i, r) in entries.iter().enumerate() {
        if let Some(prior) = link_to_index.insert(r.self_link(), i) {
            out.push(Violation {
                rule: RuleId::M3,
                index: i,
                receipt_id: Some(r.entry_id().to_string()),
                message: format!(
                    "duplicate receipt id {} (also at index {}); chain is not a function",
                    r.entry_id(),
                    prior
                ),
            });
        }
    }

    // Count roots and verify every parent reference resolves.
    let mut root_count = 0usize;
    for (i, r) in entries.iter().enumerate() {
        match r.parent_link() {
            None => {
                root_count += 1;
                if root_count > 1 {
                    out.push(Violation {
                        rule: RuleId::M3,
                        index: i,
                        receipt_id: Some(r.entry_id().to_string()),
                        message: format!(
                            "more than one root receipt in chain (second root at index {})",
                            i
                        ),
                    });
                }
            }
            Some(pr) => {
                if !link_to_index.contains_key(pr) {
                    out.push(Violation {
                        rule: RuleId::M3,
                        index: i,
                        receipt_id: Some(r.entry_id().to_string()),
                        message: format!(
                            "parent_link={} at index {} does not resolve to any entry in the chain (dangling reference)",
                            pr, i
                        ),
                    });
                }
            }
        }
    }

    if root_count == 0 {
        out.push(Violation {
            rule: RuleId::M3,
            index: 0,
            receipt_id: entries.first().map(|r| r.entry_id().to_string()),
            message: "chain has no root receipt (no entry with parent_link = None)"
                .to_string(),
        });
    }

    out
}

// ---------------------------------------------------------------------------
// M4 — Trajectory monotonicity
// ---------------------------------------------------------------------------

/// **M4 — Trajectory monotonicity.**
///
/// > ☐ Timestamps in Γ are non-decreasing.
///
/// v0 checks `timestamp()` along the slice in order. Two entries with
/// the same timestamp are allowed. An entry whose timestamp precedes
/// its predecessor's is a clock-rollback violation.
pub fn m4_trajectory_monotonicity<T: ChainEntry>(entries: &[T]) -> Vec<Violation> {
    let mut out = Vec::new();

    for (i, r) in entries.iter().enumerate().skip(1) {
        let prev = &entries[i - 1];
        if r.timestamp() < prev.timestamp() {
            out.push(Violation {
                rule: RuleId::M4,
                index: i,
                receipt_id: Some(r.entry_id().to_string()),
                message: format!(
                    "created_at={} precedes predecessor created_at={} at index {} (temporal monotonicity violation / clock rollback)",
                    r.timestamp(),
                    prev.timestamp(),
                    i
                ),
            });
        }
    }

    out
}
