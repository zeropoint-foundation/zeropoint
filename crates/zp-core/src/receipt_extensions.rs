//! Canonical names for the `zp.*` receipt extension keys.
//!
//! These strings are a **contract between two crates that never reference each
//! other**: a producer in `zp-server` writes them onto a receipt, and
//! `zp_audit::RecoveryEngine` reads them back to rebuild operational state after
//! a restart. Until 2026-08-09 both sides spelled them as bare literals, so the
//! contract was "two people typed the same string correctly", enforced by
//! nothing.
//!
//! It was not being met. Measured against the live chain that day: of 285,071
//! entries, **zero** carried a receipt, so all seventeen keys `RecoveryEngine`
//! reads had never once been present. Recovery replayed the whole chain, found
//! nothing, and reported `success: true` — indistinguishable from a clean
//! recovery of a quiet chain. That is the failure this module exists to prevent
//! recurring: not a typo, but a pairing nobody could see was broken.
//!
//! **Scope.** Two consumers: `zp_audit::recovery` (operational state) and
//! `zp_audit::reconstitute` (trust/security state). Both sets are below, and
//! each key records whether a producer actually writes it — a constant with no
//! writer is centralised, not fixed.
//!
//! # Rules
//!
//! - **Never inline one of these strings.** Reference the constant. A literal
//!   that drifts by a character produces no error on either side — the writer
//!   writes to a key nobody reads, the reader reads a key nobody writes, and
//!   both report success.
//! - **Adding a key here is not enough.** A key with a reader and no writer is
//!   an alarm that cannot fire; a key with a writer and no reader is a fact
//!   nobody uses. Add both ends, and add a round-trip test that asserts the
//!   producer's output reaches the consumer — see
//!   `zp_audit::recovery` tests.
//! - See `docs/design/CHANNEL-BOUNDARY-2026-08.md` for *which* claims belong on
//!   the receipt channel at all. Telemetry belongs in the event string; only
//!   state that must survive a restart or be independently verified belongs
//!   here.

/// Capability grant identity — read by `RecoveryEngine` to rebuild in-flight
/// grants. Written by the Regent startup delegation in `zp-server`.
pub const CAPABILITY_GRANT_ID: &str = "zp.capability.grant_id";

/// Human-readable scope of a capability grant.
pub const CAPABILITY_SCOPE: &str = "zp.capability.scope";

/// The actor a capability was granted to.
pub const CAPABILITY_GRANTEE: &str = "zp.capability.grantee";

/// Grant id being revoked. Removes the matching in-flight grant on replay.
pub const CAPABILITY_REVOKED_GRANT_ID: &str = "zp.capability.revoked_grant_id";

/// Tool name for an invocation. Opens a pending tool execution on replay.
pub const TOOL_NAME: &str = "zp.tool.name";

/// Conversation a tool invocation belongs to.
pub const TOOL_CONVERSATION_ID: &str = "zp.tool.conversation_id";

/// Entry id of the invocation a completion closes. Clears the pending entry.
pub const TOOL_COMPLETED_INVOCATION_ID: &str = "zp.tool.completed_invocation_id";

/// Conversation identity, tracked as active on replay.
pub const CONVERSATION_ID: &str = "zp.conversation.id";

/// Marks a conversation as ended, so replay does not treat it as active.
pub const CONVERSATION_ENDED: &str = "zp.conversation.ended";

/// Observation identity — opens an active observation on replay.
pub const OBSERVATION_ID: &str = "zp.observation.id";

/// Category of an observation, carried alongside its id.
pub const OBSERVATION_CATEGORY: &str = "zp.observation.category";

/// Observation ids consumed by a reflection, closing them on replay.
pub const REFLECTION_CONSUMED_IDS: &str = "zp.reflection.consumed_ids";

// ── Reconstitution keys ─────────────────────────────────────────────────────
//
// Read by `zp_audit::reconstitute` to rebuild trust state for compromise
// analysis.
//
// CORRECTION, 2026-08-09. An earlier version of this comment claimed that of the
// six memory/quarantine keys, "exactly ONE has a writer", and told a confident
// story about `zp.quarantine.memory_ids` (plural) and `zp.quarantine.memory_id`
// (singular) being one key split by a typo. That was wrong, and it was wrong
// because of how it was measured: the survey grepped for `.extension("key"` on a
// single line, and `zp-memory` writes its keys like this —
//
//     .extension(
//         "zp.memory.memory_id",
//         serde_json::Value::String(entry.id.clone()),
//     )
//
// — with the key on its own line. Every multi-line call was invisible. Three of
// those six keys are in fact written (`promotion.rs:284`, `quarantine.rs:389`,
// `quarantine.rs:451`), and singular and plural are two deliberate keys: one per
// memory, one for bulk quarantine.
//
// The correction is left in place rather than quietly edited out, because the
// original error is the exact hazard this module documents — a confident claim
// derived from an instrument nobody had checked. Status below is now taken from
// `tools/false_assurance.py`, which resolves constants and multi-line calls, and
// which cross-checks `KNOWN_ORPHAN_READS` against what it measures.

/// Certificate public key, read during key-lifecycle reconstitution to add the
/// rotated-to key to `valid_operator_keys` / `valid_agent_keys`.
/// **Producer:** `zp_core::certificate_rotation_receipts`, called by
/// `zp-keys/src/rotation.rs`. Round-tripped by
/// `round_trip_key_rotation_producer_to_reconstituted_state`.
pub const CERTIFICATE_PUBLIC_KEY: &str = "zp.certificate.public_key";

/// Certificate role — one of the `ROLE_*` constants below, never a serialised
/// enum. **Producer:** see [`CERTIFICATE_PUBLIC_KEY`].
pub const CERTIFICATE_ROLE: &str = "zp.certificate.role";

/// Revoked key identity. Removes the key from both valid-key sets on replay.
/// **Producer:** [`crate::certificate_rotation_receipts`]'s revocation half.
pub const REVOCATION_REVOKED_KEY: &str = "zp.revocation.revoked_key";

/// Policy version in force. **No producer.** `reconstitute` raises
/// `PolicyDowngradeDetected` on this key, so that alarm cannot fire. The only
/// writers anywhere are that file's own tests.
pub const POLICY_VERSION: &str = "zp.policy.version";

/// Memory identity for promotion tracking.
/// **Producer:** `zp-memory/src/promotion.rs`.
pub const MEMORY_ID: &str = "zp.memory.memory_id";

/// Promotion stage. **No producer.**
pub const MEMORY_STAGE: &str = "zp.memory.stage";

/// Agent a memory originated from. **No producer.**
pub const MEMORY_SOURCE_AGENT: &str = "zp.memory.source_agent";

/// Quarantined memory ids, plural — the bulk-quarantine form.
/// **Producer:** `zp-memory/src/quarantine.rs`.
pub const QUARANTINE_MEMORY_IDS: &str = "zp.quarantine.memory_ids";

/// A single quarantined memory. Distinct from [`QUARANTINE_MEMORY_IDS`] by
/// design — one memory versus a bulk set, not a typo.
/// **Producer:** `zp-memory/src/quarantine.rs:389`.
pub const QUARANTINE_MEMORY_ID: &str = "zp.quarantine.memory_id";

/// Reinstated memory id.
/// **Producer:** `zp-memory/src/quarantine.rs:451`.
pub const REINSTATEMENT_MEMORY_ID: &str = "zp.reinstatement.memory_id";

// ── Value vocabularies ──────────────────────────────────────────────────────
//
// Key names are only half the contract. `reconstitute` matches the *value* of
// `zp.certificate.role` against literal strings, so the writer and reader must
// agree on spelling and case too.
//
// This nearly went wrong on 2026-08-09. `zp_keys::KeyRole` derives `Serialize`
// with no `rename_all`, so serde emits `"Operator"` and `"Agent"` — capitalised.
// `reconstitute` matches `"operator"` and `"agent"`, falling through to `_ => {}`
// otherwise. Writing the serialised role straight onto the receipt would have
// produced a valid receipt that the consumer reads, matches nothing on, and
// discards without error: emitted, consumed, and ignored.
//
// Producers must map their own enum onto these constants explicitly rather than
// serialising it, so the mapping is a visible decision rather than an accident
// of derive order.

/// Node operator key. Recognised by `reconstitute` as a valid operator key.
pub const ROLE_OPERATOR: &str = "operator";

/// Agent instance key. Recognised by `reconstitute` as a valid agent key.
pub const ROLE_AGENT: &str = "agent";

/// Root of trust. **Currently ignored by `reconstitute`** — its `match` handles
/// operator and agent and drops everything else. Named here so the omission is
/// visible; whether genesis rotation should update reconstituted trust state is
/// an open question, not a settled one.
pub const ROLE_GENESIS: &str = "genesis";

/// Keys `zp_audit::reconstitute` consumes.
pub const RECONSTITUTION_KEYS: &[&str] = &[
    CAPABILITY_GRANT_ID,
    CAPABILITY_SCOPE,
    CAPABILITY_GRANTEE,
    CAPABILITY_REVOKED_GRANT_ID,
    CERTIFICATE_PUBLIC_KEY,
    CERTIFICATE_ROLE,
    REVOCATION_REVOKED_KEY,
    POLICY_VERSION,
    MEMORY_ID,
    MEMORY_STAGE,
    MEMORY_SOURCE_AGENT,
    QUARANTINE_MEMORY_IDS,
    QUARANTINE_MEMORY_ID,
    REINSTATEMENT_MEMORY_ID,
];

/// Keys with a reader and, as of 2026-08-09, **no producer anywhere**.
///
/// Every entry is an alarm that cannot fire or a state rebuild that will always
/// come back empty. Listed explicitly so the count is visible and shrinking is
/// measurable — `tools/false_assurance.py` regenerates the underlying survey.
/// Remove an entry only when a producer lands *and* a round-trip test covers it.
///
/// Cross-checked against measured reality by `tools/false_assurance.py`, which
/// parses this list and fails if it disagrees with what the code actually does.
/// That guard exists because this list rotted within the hour it was written:
/// the three certificate keys were wired the same afternoon and left here,
/// still documented as having no producer — drift in the file whose whole
/// purpose is preventing drift. A list of known problems is itself a claim, and
/// claims need falsifying.
pub const KNOWN_ORPHAN_READS: &[&str] = &[
    POLICY_VERSION,
    MEMORY_STAGE,
    MEMORY_SOURCE_AGENT,
    CAPABILITY_REVOKED_GRANT_ID,
    CONVERSATION_ID,
    CONVERSATION_ENDED,
    OBSERVATION_ID,
    REFLECTION_CONSUMED_IDS,
    TOOL_NAME,
    TOOL_CONVERSATION_ID,
    TOOL_COMPLETED_INVOCATION_ID,
];

/// Every key `zp_audit::RecoveryEngine` consumes.
///
/// Exists so a test can assert the producing side covers the consuming side
/// rather than leaving that to inspection. A key present here with no writer
/// anywhere is a reader with no producer — the dangerous direction, because it
/// presents as a safety net rather than as a gap.
pub const RECOVERY_KEYS: &[&str] = &[
    CAPABILITY_GRANT_ID,
    CAPABILITY_SCOPE,
    CAPABILITY_GRANTEE,
    CAPABILITY_REVOKED_GRANT_ID,
    TOOL_NAME,
    TOOL_CONVERSATION_ID,
    TOOL_COMPLETED_INVOCATION_ID,
    CONVERSATION_ID,
    CONVERSATION_ENDED,
    OBSERVATION_ID,
    OBSERVATION_CATEGORY,
    REFLECTION_CONSUMED_IDS,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_reads_are_declared_members_of_the_read_sets() {
        // A key cannot be a known orphan unless something actually reads it.
        // Guards against the list rotting into a graveyard of deleted keys.
        for k in KNOWN_ORPHAN_READS {
            assert!(
                RECONSTITUTION_KEYS.contains(k) || RECOVERY_KEYS.contains(k),
                "{k} is listed as an orphan read but is in neither read set"
            );
        }
    }

    #[test]
    fn reconstitution_keys_are_namespaced_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for k in RECONSTITUTION_KEYS {
            assert!(k.starts_with("zp."), "{k} must use the `zp.` namespace");
            assert!(seen.insert(*k), "duplicate extension key: {k}");
        }
    }

    #[test]
    fn keys_are_namespaced_and_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for k in RECOVERY_KEYS {
            assert!(
                k.starts_with("zp."),
                "{k} must use the reverse-domain `zp.` namespace"
            );
            assert!(seen.insert(*k), "duplicate extension key: {k}");
        }
    }
}
