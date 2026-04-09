//! The [`ChainEntry`] trait — the minimal shape the catalog rules need
//! to verify *any* hash-linked, signed, replayable derivation.
//!
//! ZeroPoint has (at least) two concrete chain shapes in production:
//!
//! - `zp_receipt::Receipt`, where each receipt references its predecessor
//!   by **id** (`parent_receipt_id`) — a git-blob-style chain.
//! - `zp_core::AuditEntry`, where each entry references its predecessor by
//!   the **hash** of the previous entry (`prev_hash`) — a Bitcoin-style
//!   chain.
//!
//! Both are valid expressions of P1 (chain extension) and M3 (hash-chain
//! continuity); the catalog grammar does not care which link discipline
//! you pick, only that the link is well-defined and resolvable.
//!
//! The trait reflects this: every entry has a *self link* (the string
//! the next entry will quote), a *parent link* (what this entry quotes
//! to identify its predecessor), a content-hash self-check, and a
//! monotone timestamp. The rules in [`crate::rules`] are written
//! generically against this trait.

use chrono::{DateTime, Utc};

/// One node in a hash-linked derivation chain.
///
/// Implementors choose what `self_link` and `parent_link` mean — id,
/// content hash, or anything else — as long as they agree with each
/// other: `child.parent_link() == Some(parent.self_link())` for every
/// non-root pair.
pub trait ChainEntry {
    /// Stable identifier for this entry, used in violation messages and
    /// for duplicate detection in M3.
    fn entry_id(&self) -> &str;

    /// What the next entry will quote to point at this one.
    fn self_link(&self) -> &str;

    /// What this entry quotes to point at its predecessor, or `None`
    /// if this entry is a root.
    fn parent_link(&self) -> Option<&str>;

    /// `true` iff this entry's stored content hash matches a fresh
    /// canonical hash of its body. Implementors delegate to whatever
    /// hash check the underlying type already provides.
    fn content_hash_valid(&self) -> bool;

    /// The entry's timestamp, used by M4 (trajectory monotonicity).
    fn timestamp(&self) -> DateTime<Utc>;
}

// ---------------------------------------------------------------------------
// Implementation for zp_receipt::Receipt — id-based linking.
// ---------------------------------------------------------------------------

impl ChainEntry for zp_receipt::Receipt {
    fn entry_id(&self) -> &str {
        &self.id
    }

    fn self_link(&self) -> &str {
        // Receipts link by id: the child's parent_receipt_id quotes
        // the parent's id.
        &self.id
    }

    fn parent_link(&self) -> Option<&str> {
        self.parent_receipt_id.as_deref()
    }

    fn content_hash_valid(&self) -> bool {
        self.verify_hash()
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.created_at
    }
}
