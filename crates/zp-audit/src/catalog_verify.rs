//! Catalog-grammar verification for `AuditEntry` chains.
//!
//! This module bridges `zp_core::AuditEntry` (Bitcoin-style chain — each
//! entry references the *hash* of its predecessor) into the catalog
//! grammar via the [`zp_verify::VerifiableEntry`] trait, then exposes a
//! convenience method on [`AuditStore`] that loads the chain and runs
//! every v0 catalog rule against it.
//!
//! The earlier [`crate::verifier`] module checks linkage by re-hashing
//! entries and comparing `prev_hash` byte-for-byte. The catalog
//! verifier is *additive*: it covers the same ground from a higher
//! abstraction level (P1 + M3 + M4) and is the rule path the rest of
//! the platform should grow into.

use chrono::{DateTime, Utc};
use zp_core::AuditEntry;
use zp_verify::{VerifiableEntry, Verifier, VerifyReport};

use crate::store::{AuditStore, Result};

/// Wrapper around an [`AuditEntry`] that implements [`VerifiableEntry`] using
/// the entry's `entry_hash` as the self link and `prev_hash` as the
/// parent link.
///
/// We wrap rather than impl on the foreign type directly so the orphan
/// rules don't bite us if `zp_core` later moves and so the link
/// semantics are obvious to anyone tracing the rule output.
#[derive(Debug, Clone)]
pub struct AuditVerifiableEntry<'a>(pub &'a AuditEntry);

/// The blake3 hash of the empty byte string — the sentinel that
/// `ChainBuilder::build_entry_from_genesis` writes into `prev_hash` to
/// mark an entry as the chain root. We compute it lazily at first use
/// and compare string-wise.
fn genesis_sentinel() -> &'static str {
    use std::sync::OnceLock;
    static SENTINEL: OnceLock<String> = OnceLock::new();
    SENTINEL.get_or_init(|| blake3::hash(b"").to_hex().to_string())
}

impl<'a> VerifiableEntry for AuditVerifiableEntry<'a> {
    fn entry_id(&self) -> &str {
        // AuditId stringifies via Display in core; we use the entry_hash
        // as the public id since it's also what other entries quote.
        &self.0.entry_hash
    }

    fn self_link(&self) -> &str {
        &self.0.entry_hash
    }

    fn parent_link(&self) -> Option<&str> {
        // Two forms of "no parent" to handle:
        //  1. Empty string — defensive, in case any path ever stores
        //     the literal empty prev_hash.
        //  2. blake3(b"") — what ChainBuilder actually writes for the
        //     genesis entry via `build_entry_from_genesis`.
        // Both collapse to None so M3's root detection fires correctly.
        let p = self.0.prev_hash.as_str();
        if p.is_empty() || p == genesis_sentinel() {
            None
        } else {
            Some(p)
        }
    }

    fn content_hash_valid(&self) -> bool {
        // Stage 5 (AUDIT-03): strict P2 content-hash check. Every entry
        // in a canonical (schema v2) database was written by the
        // transactional `AuditStore::append` path, which seals the entry
        // via `seal_entry` using proper JSON serialization for every
        // identity/policy field. `recompute_entry_hash` is the exact
        // inverse of that sealing, so any mismatch here means the row
        // has been tampered with (or the hash function has drifted).
        //
        // The schema version is stamped in `PRAGMA user_version` by
        // `AuditStore::init`; opening a pre-v2 DB returns
        // `StoreError::SchemaMismatch`, so this check can never be run
        // against the old Debug-format layout. See docs/audit-invariant.md.
        crate::chain::recompute_entry_hash(self.0) == self.0.entry_hash
    }

    fn timestamp(&self) -> DateTime<Utc> {
        self.0.timestamp
    }

    fn signed_payload(&self) -> Option<&[u8]> {
        // Entry-level signing (Claim 1): AuditSigner::sign_entry signs the
        // raw 32-byte blake3 hash of entry_hash (preimage_version=2). The
        // verifier's F8 path hex-decodes these ASCII bytes to get the raw
        // preimage before verifying. entry_hash is always present on a
        // sealed entry — None is structurally impossible here.
        Some(self.0.entry_hash.as_bytes())
    }

    fn signature_blocks(&self) -> Vec<zp_verify::SignatureBlockView<'_>> {
        // Entry-level signatures: AuditSigner writes one Ed25519 block into
        // entry.signatures on every AuditStore::append. These are the
        // per-row chain attestations that S1 must verify for Claim 1
        // (chain integrity). Receipt-level signatures (receipt.signatures)
        // are a separate concern verified by verify_receipt_status — they
        // are NOT the signatures S1 should be checking here.
        //
        // Note: the legacy signature_b64 / signer_public_key_hex accessors
        // are intentionally not overridden — they default to None from the
        // trait, so S1 takes the F8 vec path whenever entry.signatures is
        // non-empty (signed store) and skips cleanly when it is empty
        // (read-only / test store opened via open_unsigned).
        self.0
            .signatures
            .iter()
            .map(|b| zp_verify::SignatureBlockView {
                algorithm: b.algorithm.as_str(),
                key_id: b.key_id.as_str(),
                signature_b64: b.signature_b64.as_str(),
                preimage_version: b.preimage_version,
            })
            .collect()
    }
}

impl AuditStore {
    /// Load the full chain from storage and run the catalog v0 rules
    /// against it (P1 chain extension, M3 hash-chain continuity, M4
    /// trajectory monotonicity).
    ///
    /// Returns a [`VerifyReport`] for downstream tools (CLI, dashboards,
    /// the adversarial test stack) to consume.
    pub fn verify_with_catalog(&self) -> Result<VerifyReport> {
        // rusqlite binds the LIMIT parameter as i64; usize::MAX overflows on
        // 64-bit targets. i64::MAX rows is effectively "no limit" for any
        // real audit chain.
        let entries = self.export_chain(i64::MAX as usize)?;
        let wrapped: Vec<AuditVerifiableEntry<'_>> = entries.iter().map(AuditVerifiableEntry).collect();
        Ok(Verifier::new().verify(&wrapped))
    }
}
