//! zp-audit: Hash-chained, always-on audit trail for ZeroPoint v2.
//!
//! This crate provides an append-only, integrity-verified audit system using SQLite
//! and blake3 for cryptographic hashing. All audit entries form a hash chain where
//! each entry includes the hash of the previous entry, preventing tampering.

pub mod catalog_verify;
pub mod chain;
pub mod collective_audit;
pub mod scrub;
pub mod store;
pub mod verifier;

pub use chain::{genesis_hash, recompute_entry_hash, seal_entry, UnsealedEntry};
pub use collective_audit::{
    verify_peer_chain, AuditChallenge, AuditRange, AuditResponse, CompactAuditEntry,
    PeerAuditAttestation, MAX_ENTRIES_PER_RESPONSE,
};
pub use store::{AuditStore, Result, StoreError};
pub use verifier::{verify_linkage, verify_linkage_report, ChainVerifier, VerificationReport};
