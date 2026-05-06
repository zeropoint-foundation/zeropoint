//! Chain construction for audit entries.
//!
//! # Architecture (post-AUDIT-03)
//!
//! As of the AUDIT-03 fix (see `security/pentest-2026-04-06/REMEDIATION-NOTES.md`),
//! the audit chain is **owned by `AuditStore::append`**, not by callers. Callers
//! construct an [`UnsealedEntry`] containing only the application-level fields
//! (actor, action, conversation_id, policy_decision, policy_module, receipt,
//! signature) and hand it to `AuditStore::append`. The store then, inside a
//! `BEGIN IMMEDIATE` transaction:
//!
//! 1. Reads the current chain tip from SQLite by `MAX(rowid)`.
//! 2. Assigns `id` and `timestamp`.
//! 3. Computes `entry_hash` via [`seal_entry`].
//! 4. Inserts the row.
//! 5. Commits.
//!
//! `BEGIN IMMEDIATE` acquires SQLite's RESERVED lock, which serializes writers
//! at the *file* level — not the connection level — so this is correct across
//! both concurrent in-process handles and concurrent OS processes.
//!
//! # Hashing
//!
//! [`seal_entry`] hashes a JSON representation of the entry. Unlike the
//! pre-AUDIT-03 layout (which used `format!("{:?}", actor)` and hit AUDIT-02),
//! this layout uses proper [`serde_json`] serialization for `actor`,
//! `action`, `conversation_id`, and `policy_decision`. New entries written
//! through `AuditStore::append` round-trip bit-exactly through the database.
//!
//! Historical entries (written by the legacy `ChainBuilder::build_entry`
//! path) used the Debug-format layout and will not match this hash function.
//! The catalog verifier (`crate::catalog_verify`) currently leaves the
//! content-hash check disabled because of this; re-enabling it requires
//! either a fresh database or a one-time hash-rebuild migration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use zp_core::{ActorId, AuditAction, AuditEntry, AuditId, ConversationId, PolicyDecision, Receipt};
// SignatureBlock is unused in this module after the chain-signing refactor —
// hash-time `signatures` is always `[]` (signing happens in AuditStore::append),
// and read-side construction is via Vec::<SignatureBlock>::new() inferred from
// the AuditEntry field type.

/// An audit entry that has not yet been linked into the chain.
///
/// Construct one of these and pass it to [`crate::AuditStore::append`]. The
/// store assigns `id`, `timestamp`, `prev_hash`, `entry_hash`, **and the
/// signature(s)** atomically inside a transaction; callers must NOT compute
/// or supply any of these themselves.
///
/// # Why no signature field
///
/// Pre-Phase-1, this struct carried `signature: Option<String>` and a
/// `with_signature(...)` builder. Both are gone. The store owns signing —
/// callers describe *intent* (actor, action, policy decision, optional
/// receipt) and the store crystallizes it into a sealed, signed record.
/// This closes Seam 1 of the principle "signing is gravity": there is no
/// path by which an entry reaches storage unsigned, because callers no
/// longer have a knob to leave it off.
///
/// This is the only sanctioned way to add entries to the audit chain. The
/// pre-AUDIT-03 `ChainBuilder::build_entry` API is gone because it allowed
/// callers to read the chain tip outside of any serialization, which produced
/// the concurrent-append race documented in REMEDIATION-NOTES.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsealedEntry {
    pub actor: ActorId,
    pub action: AuditAction,
    pub conversation_id: ConversationId,
    pub policy_decision: PolicyDecision,
    pub policy_module: String,
    pub receipt: Option<Receipt>,
}

impl UnsealedEntry {
    /// Convenience constructor for the common case (no receipt).
    pub fn new(
        actor: ActorId,
        action: AuditAction,
        conversation_id: ConversationId,
        policy_decision: PolicyDecision,
        policy_module: impl Into<String>,
    ) -> Self {
        Self {
            actor,
            action,
            conversation_id,
            policy_decision,
            policy_module: policy_module.into(),
            receipt: None,
        }
    }

    /// Attach a receipt to this unsealed entry.
    pub fn with_receipt(mut self, receipt: Receipt) -> Self {
        self.receipt = Some(receipt);
        self
    }
}

/// The blake3 hash of the empty byte string. Used as `prev_hash` for the
/// genesis entry of any chain.
pub fn genesis_hash() -> String {
    blake3::hash(b"").to_hex().to_string()
}

/// Seal an [`UnsealedEntry`] into a fully-linked [`AuditEntry`] using the
/// supplied `prev_hash`, `id`, and `timestamp`.
///
/// **This is an internal helper for [`crate::AuditStore::append`].** Callers
/// outside of `zp-audit` should not invoke it directly — doing so is exactly
/// the failure mode AUDIT-03 was about. It's `pub` only because the catalog
/// verifier needs to be able to recompute hashes for the content-hash check.
pub fn seal_entry(
    unsealed: &UnsealedEntry,
    prev_hash: &str,
    id: AuditId,
    timestamp: DateTime<Utc>,
) -> AuditEntry {
    let entry_hash = compute_entry_hash(unsealed, prev_hash, &id, &timestamp);
    AuditEntry {
        id,
        timestamp,
        prev_hash: prev_hash.to_string(),
        entry_hash,
        actor: unsealed.actor.clone(),
        action: unsealed.action.clone(),
        conversation_id: unsealed.conversation_id.clone(),
        policy_decision: unsealed.policy_decision.clone(),
        policy_module: unsealed.policy_module.clone(),
        receipt: unsealed.receipt.clone(),
        // Always empty at seal time. AuditStore::append signs the sealed
        // entry_hash and populates this vec before INSERT. Hash-then-sign
        // discipline: the hash must be defined before any signature exists.
        signatures: Vec::new(),
    }
}

/// Compute the `entry_hash` for an unsealed entry given its `prev_hash`,
/// `id`, and `timestamp`. Pure function — does not touch the database.
///
/// The hash is blake3 over a JSON object with all entry fields in a stable
/// key order. All identity and policy fields are serialized via
/// `serde_json::to_value` so the same bytes are reproducible from a database
/// round-trip — the AUDIT-02 fix.
///
/// **The `signatures` field is hashed as `[]`**, never as the actual
/// signature blocks. Signatures are computed *over* the entry_hash, so the
/// hash must be well-defined before any signature exists. The pre-AUDIT-03
/// ChainBuilder included `signature` in the hash, which was inconsistent
/// with the verifier (verifier always set it to null). The Phase-1 form
/// makes the convention explicit: hash always sees the empty array, so
/// `compute_entry_hash` is a pure function of the entry's *intent*, not
/// of its attestation.
fn compute_entry_hash(
    unsealed: &UnsealedEntry,
    prev_hash: &str,
    id: &AuditId,
    timestamp: &DateTime<Utc>,
) -> String {
    let entry_data = json!({
        "id": id.0.to_string(),
        "timestamp": timestamp.to_rfc3339(),
        "prev_hash": prev_hash,
        "actor": serde_json::to_value(&unsealed.actor).unwrap_or(json!(null)),
        "action": serde_json::to_value(&unsealed.action).unwrap_or(json!(null)),
        "conversation_id": unsealed.conversation_id.0.to_string(),
        "policy_decision": serde_json::to_value(&unsealed.policy_decision).unwrap_or(json!(null)),
        "policy_module": unsealed.policy_module,
        "receipt": unsealed.receipt.as_ref().map(|r| serde_json::to_value(r).unwrap_or(json!(null))),
        "signatures": json!([]),
    });
    // Seam 17: every preimage that produces a hash for signing routes
    // through the canonical helper. Pre-Seam-17 this site was open-coded
    // (`to_vec(...).unwrap_or_default()` + `blake3::hash`) — byte-equivalent
    // by accident of serde_json's BTreeMap-backed Map, but not by design.
    zp_core::canonical_hash(&entry_data)
}

/// Recompute the `entry_hash` for an existing [`AuditEntry`].
///
/// Used by the catalog verifier (`crate::catalog_verify`) for the P1
/// content-hash check: a stored entry is well-formed iff
/// `recompute_entry_hash(&entry) == entry.entry_hash`.
///
/// **Only valid for entries written by the post-AUDIT-03 `AuditStore::append`
/// path.** Pre-AUDIT-03 entries used a different (Debug-formatted) layout
/// and will not round-trip through this function. See the module docs.
pub fn recompute_entry_hash(entry: &AuditEntry) -> String {
    let unsealed = UnsealedEntry {
        actor: entry.actor.clone(),
        action: entry.action.clone(),
        conversation_id: entry.conversation_id.clone(),
        policy_decision: entry.policy_decision.clone(),
        policy_module: entry.policy_module.clone(),
        receipt: entry.receipt.clone(),
        // `signatures` is intentionally not part of the hashed payload —
        // see compute_entry_hash. We don't reconstruct it on this path.
    };
    compute_entry_hash(&unsealed, &entry.prev_hash, &entry.id, &entry.timestamp)
}

/// Allocate a fresh `AuditId` (v7 UUID, monotonic with wall clock).
pub(crate) fn new_audit_id() -> AuditId {
    AuditId(Uuid::now_v7())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_unsealed(module: &str) -> UnsealedEntry {
        UnsealedEntry::new(
            ActorId::System("test-actor".to_string()),
            AuditAction::SystemEvent {
                event: "test".to_string(),
            },
            ConversationId(Uuid::now_v7()),
            PolicyDecision::Allow { conditions: vec![] },
            module,
        )
    }

    #[test]
    fn seal_is_deterministic() {
        let unsealed = sample_unsealed("m1");
        let id = AuditId(Uuid::now_v7());
        let ts = Utc::now();
        let prev = genesis_hash();
        let a = seal_entry(&unsealed, &prev, id.clone(), ts);
        let b = seal_entry(&unsealed, &prev, id, ts);
        assert_eq!(a.entry_hash, b.entry_hash);
    }

    #[test]
    fn recompute_matches_seal() {
        let unsealed = sample_unsealed("m1");
        let sealed = seal_entry(&unsealed, &genesis_hash(), new_audit_id(), Utc::now());
        assert_eq!(recompute_entry_hash(&sealed), sealed.entry_hash);
    }

    #[test]
    fn different_prev_hash_produces_different_entry_hash() {
        let unsealed = sample_unsealed("m1");
        let id = AuditId(Uuid::now_v7());
        let ts = Utc::now();
        let a = seal_entry(&unsealed, &genesis_hash(), id.clone(), ts);
        let b = seal_entry(&unsealed, "deadbeef", id, ts);
        assert_ne!(a.entry_hash, b.entry_hash);
    }
}
