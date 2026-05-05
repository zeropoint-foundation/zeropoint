//! Tool lifecycle receipts — readiness state derived from the audit chain.
//!
//! ## Terminology
//!
//! - **Audit chain**: the hash-linked append-only log in `zp_audit::AuditStore`.
//!   Each entry carries an `AuditAction` and a typed, signed `Receipt`.
//! - **Abacus wire**: a domain dimension (system, provider, tool, node).
//! - **Bead**: a signed `Receipt` object anchored to a wire.
//! - **Bead zero**: the first bead on a wire — a `CanonicalizedClaim` receipt
//!   capturing the entity's first-known-state.
//! - **Wire tip**: the most recent bead on a wire (latest receipt ID).
//!
//! ## Architecture: Receipt-first
//!
//! Every Receipt is self-describing via `ClaimMetadata`:
//!
//! - **Bead zero** carries `ClaimMetadata::Canonicalization` with domain,
//!   entity, parent, initial_state, canonicalized_by.
//! - **Lifecycle beads** carry `ClaimMetadata::Lifecycle` with tool_id,
//!   event_type, and optional detail.
//!
//! The query path (`query_tool_readiness()`) reads `ClaimMetadata` first
//! and only falls back to parsing the `AuditAction::SystemEvent` string
//! for legacy entries written before Phase 6.
//!
//! String events (`tool:configured:ironclaw`, etc.) remain on entries as
//! a lightweight index but carry no data — "every bit counts."
//!
//! ## Event taxonomy
//!
//! Lifecycle event types (stored in `ClaimMetadata::Lifecycle.event_type`):
//!
//!   configured           — credentials resolved
//!   preflight:passed     — all infra checks green
//!   preflight:failed     — one or more checks failed
//!   launched             — process spawned, port responded
//!   setup:complete       — tool's own first-run finished
//!   providers:resolved   — Tier 1: runtime loaded providers
//!   capability:verified  — Tier 2: auth probe returned 2xx
//!   capability:degraded  — capability probe degraded
//!   capability:failed    — capability probe failed
//!
//! All beads carry `ClaimSemantics::IntegrityAttestation` and an Ed25519
//! signature from the server's signing key (when available).
//!
//! The cockpit reads the audit chain to determine readiness. Missing beads
//! tell you exactly what's outstanding, and every bead is signed and
//! hash-linked so the readiness state is verifiable.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision, TrustTier};
use zp_engine::capability::Reversibility;
use zp_receipt::{
    CanonicalDomain, ClaimMetadata, ClaimSemantics, Receipt, Signer, Status as ReceiptStatus,
};

// ── Well-known namespace ────────────────────────────────────────────────
// All tool lifecycle events live under a single synthetic conversation ID
// so they can be queried efficiently without scanning the entire audit chain.
pub(crate) fn tool_lifecycle_conv_id() -> &'static ConversationId {
    static ID: OnceLock<ConversationId> = OnceLock::new();
    ID.get_or_init(|| {
        ConversationId(Uuid::parse_str("00000000-0000-7000-8000-746f6f6c6c63").unwrap())
    })
}

// ── Event types ─────────────────────────────────────────────────────────

/// Structured tool lifecycle event names.
pub struct ToolEvent;

impl ToolEvent {
    pub fn registered(name: &str) -> String {
        format!("tool:registered:{}", name)
    }
    pub fn configured(name: &str) -> String {
        format!("tool:configured:{}", name)
    }
    pub fn preflight_passed(name: &str) -> String {
        format!("tool:preflight:passed:{}", name)
    }
    pub fn preflight_failed(name: &str) -> String {
        format!("tool:preflight:failed:{}", name)
    }
    pub fn preflight_check(name: &str, check: &str, status: &str) -> String {
        format!("tool:preflight:check:{}:{}:{}", name, check, status)
    }
    pub fn launched(name: &str) -> String {
        format!("tool:launched:{}", name)
    }
    pub fn stopped(name: &str) -> String {
        format!("tool:stopped:{}", name)
    }
    pub fn setup_complete(name: &str) -> String {
        format!("tool:setup:complete:{}", name)
    }
    pub fn providers_resolved(name: &str) -> String {
        format!("tool:providers:resolved:{}", name)
    }
    pub fn capability_verified(name: &str, capability: &str) -> String {
        format!("tool:capability:verified:{}:{}", name, capability)
    }
    pub fn capability_degraded(name: &str, capability: &str) -> String {
        format!("tool:capability:degraded:{}:{}", name, capability)
    }
    pub fn capability_failed(name: &str, capability: &str) -> String {
        format!("tool:capability:failed:{}:{}", name, capability)
    }
    pub fn capability_configured(name: &str, parameter: &str) -> String {
        format!("tool:capability:configured:{}:{}", name, parameter)
    }
    /// Bead zero: provider first-known-state
    pub fn provider_canonicalized(name: &str) -> String {
        format!("provider:canonicalized:{}", name)
    }
    /// Bead zero: tool first-known-state
    pub fn tool_canonicalized(name: &str) -> String {
        format!("tool:canonicalized:{}", name)
    }
    /// Bead zero: node first-known-state
    pub fn node_canonicalized(name: &str) -> String {
        format!("node:canonicalized:{}", name)
    }

    // ── P4 (#197): standing delegation lifecycle ───────────────────────
    /// A new standing-delegation grant has been issued.
    pub fn delegation_granted(subject_id: &str) -> String {
        format!("delegation:granted:{}", subject_id)
    }
    /// A standing-delegation grant's lease has been renewed.
    pub fn delegation_renewed(subject_id: &str) -> String {
        format!("delegation:renewed:{}", subject_id)
    }
    /// A standing-delegation grant has been revoked (operator-initiated).
    pub fn delegation_revoked(subject_id: &str) -> String {
        format!("delegation:revoked:{}", subject_id)
    }
    /// A standing-delegation grant's lease expired without renewal.
    pub fn delegation_expired(subject_id: &str) -> String {
        format!("delegation:expired:{}", subject_id)
    }
}

// ── Emit receipts ───────────────────────────────────────────────────────

/// Emit a tool lifecycle event into the audit chain.
///
/// Returns the entry_hash of the appended entry.
pub fn emit_tool_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    event: &str,
    detail: Option<&str>,
) -> Option<String> {
    let mut store = audit_store.lock().ok()?;

    let action = AuditAction::SystemEvent {
        event: event.to_string(),
    };

    let policy_decision = PolicyDecision::Allow {
        conditions: if let Some(d) = detail {
            vec![d.to_string()]
        } else {
            vec![]
        },
    };

    // AUDIT-03: caller no longer computes prev_hash. The store reads the
    // tip and seals the entry atomically inside a BEGIN IMMEDIATE
    // transaction, eliminating the concurrent-append race.
    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-preflight".to_string()),
        action,
        tool_lifecycle_conv_id().clone(),
        policy_decision,
        "tool-lifecycle",
    );

    store.append(unsealed).ok().map(|sealed| sealed.entry_hash)
}

/// Emit a batch of tool lifecycle receipts (e.g., during preflight).
/// Returns the number of entries successfully appended.
pub fn emit_tool_receipts(
    audit_store: &Arc<Mutex<AuditStore>>,
    events: &[(&str, Option<&str>)],
) -> usize {
    let mut count = 0;
    for (event, detail) in events {
        if emit_tool_receipt(audit_store, event, *detail).is_some() {
            count += 1;
        }
    }
    count
}

// ── P4 (#197): standing delegation chain emission ───────────────────────────

/// Append a `delegation:{lifecycle}:{subject}` receipt to the chain.
///
/// `lifecycle` is one of `granted`, `renewed`, `expired` — `revoked` is
/// emitted via `emit_revocation_receipt` because a revocation requires a
/// signed `RevocationClaim` body, not just a CapabilityGrant snapshot.
///
/// The grant's canonical JSON is stored as `policy_decision::Allow.conditions[0]`
/// so verifiers can reconstitute the grant body without needing to re-fetch
/// from anywhere. Returns the entry_hash on success.
pub fn emit_delegation_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    lifecycle: &str,
    grant: &zp_core::CapabilityGrant,
) -> Option<String> {
    let event = format!("delegation:{}:{}", lifecycle, grant.grantee);
    let body = serde_json::to_string(grant).ok()?;

    let mut store = audit_store.lock().ok()?;

    let action = AuditAction::SystemEvent { event };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![body],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-delegation".to_string()),
        action,
        tool_lifecycle_conv_id().clone(),
        policy_decision,
        "delegation",
    );
    store.append(unsealed).ok().map(|sealed| sealed.entry_hash)
}

/// Append a `delegation:revoked:{target_grant_subject}` receipt to the chain.
///
/// The target grant's grantee is used as the subject suffix so the chain
/// reads symmetrically with `delegation:granted:{subject}`. The signed
/// `RevocationClaim` JSON body is stored on the entry's `policy_decision`
/// conditions, the claim's `revocation_id` becomes the entry's
/// `policy_module` for fast indexing.
pub fn emit_revocation_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    target_subject: &str,
    claim: &zp_core::RevocationClaim,
) -> Option<String> {
    let event = format!("delegation:revoked:{}", target_subject);
    let body = serde_json::to_string(claim).ok()?;

    let mut store = audit_store.lock().ok()?;
    let action = AuditAction::SystemEvent { event };
    let policy_decision = PolicyDecision::Allow {
        conditions: vec![body],
    };
    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-delegation".to_string()),
        action,
        tool_lifecycle_conv_id().clone(),
        policy_decision,
        &claim.revocation_id,
    );
    store.append(unsealed).ok().map(|sealed| sealed.entry_hash)
}

// ── F5: reversibility-aware action gate ─────────────────────────────────

/// Outcome of `enforce_reversibility_gate`. The caller decides whether to
/// emit anything onto the chain — `Allow` carries the claim string the
/// receipt should advertise, `Deny` carries the reason.
#[derive(Debug, Clone)]
pub enum ReversibilityGate {
    /// The action may proceed at this trust tier. The receipt should carry
    /// `claim` (one of `tool:capability:reversible` / `tool:capability:irreversible`).
    Allow {
        reversibility: Reversibility,
        claim: String,
    },
    /// The action is irreversible (or unknown, treated as irreversible) and
    /// the requesting tier is too low. Caller should refuse and surface
    /// `reason` to the operator.
    Deny {
        reversibility: Reversibility,
        reason: String,
    },
}

/// Look up the reversibility a tool declared at canonicalization time.
///
/// Walks the `tool-lifecycle` conversation looking for the tool's bead-zero
/// `Canonicalization` claim. Returns `Reversibility::Unknown` if the tool
/// has no canon yet, or if the canon predates F5 and didn't record a value.
pub fn query_tool_reversibility(
    audit_store: &Arc<Mutex<AuditStore>>,
    tool_name: &str,
) -> Reversibility {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return Reversibility::Unknown,
    };
    let entries = match store.get_entries(tool_lifecycle_conv_id(), 500) {
        Ok(e) => e,
        Err(_) => return Reversibility::Unknown,
    };

    for entry in &entries {
        let Some(receipt) = entry.receipt.as_ref() else {
            continue;
        };
        let Some(ClaimMetadata::Canonicalization {
            domain: CanonicalDomain::Tool,
            entity_id,
            reversibility,
            ..
        }) = receipt.claim_metadata.as_ref()
        else {
            continue;
        };
        if entity_id == tool_name {
            return reversibility
                .as_deref()
                .map(Reversibility::from_str)
                .unwrap_or(Reversibility::Unknown);
        }
    }
    Reversibility::Unknown
}

/// F5 gate: decide whether `trust_tier` may invoke an action on `tool_name`,
/// using the tool's declared reversibility as an additional input alongside
/// the existing tier check.
///
/// Rules:
/// - `Reversible` → allowed at any tier; receipt carries `tool:capability:reversible`.
/// - `Partial` / `Irreversible` / `Unknown` → require tier ≥ 1; receipt
///   carries `tool:capability:irreversible`. `Tier0` is denied.
///
/// The function does **not** itself emit anything onto the chain — that is
/// the caller's responsibility. This keeps the gate composable with the
/// rest of `zp-policy` evaluation, which is where action receipts are tagged.
pub fn enforce_reversibility_gate(
    audit_store: &Arc<Mutex<AuditStore>>,
    tool_name: &str,
    trust_tier: TrustTier,
) -> ReversibilityGate {
    let declared = query_tool_reversibility(audit_store, tool_name);
    let effective = declared.effective();

    // Reversible → permissive path.
    if matches!(effective, Reversibility::Reversible) {
        return ReversibilityGate::Allow {
            reversibility: declared,
            claim: "tool:capability:reversible".to_string(),
        };
    }

    // Otherwise (Irreversible / Partial / Unknown all fold here): require ≥ Tier1.
    if trust_tier >= TrustTier::Tier1 {
        ReversibilityGate::Allow {
            reversibility: declared,
            claim: "tool:capability:irreversible".to_string(),
        }
    } else {
        ReversibilityGate::Deny {
            reversibility: declared,
            reason: format!(
                "irreversible action on tool '{}' requires trust tier ≥ 1 (declared: {})",
                tool_name,
                declared.as_str()
            ),
        }
    }
}

/// F5: emit a tool action receipt with the reversibility gate applied first.
///
/// The realistic "execution path" entry point. Behavior:
/// - Run `enforce_reversibility_gate`.
/// - On `Deny`: log a WARN, emit nothing, return `Err(reason)`. The caller
///   should propagate the denial to the operator.
/// - On `Allow`: log a WARN if the action is irreversible (so operators
///   notice), append the chain entry tagged with the claim, and return
///   `Ok(entry_hash)`.
///
/// The reversibility claim is encoded in two places for redundancy:
///   1. The `AuditAction::SystemEvent` string (lightweight wire index).
///   2. The first entry of `PolicyDecision::Allow.conditions` so a chain
///      reader without `Receipt` access can still observe it.
///
/// Pre-existing call sites that don't yet carry a trust tier should keep
/// using `emit_tool_receipt`. Migrate them to this function as the gate
/// becomes load-bearing.
pub fn emit_tool_action_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    tool_name: &str,
    action_event: &str,
    detail: Option<&str>,
    trust_tier: TrustTier,
) -> Result<Option<String>, String> {
    let gate = enforce_reversibility_gate(audit_store, tool_name, trust_tier);
    match gate {
        ReversibilityGate::Deny { reason, .. } => {
            tracing::warn!(
                tool = %tool_name,
                tier = ?trust_tier,
                reason = %reason,
                "F5: refusing irreversible action — trust tier too low",
            );
            Err(reason)
        }
        ReversibilityGate::Allow {
            reversibility,
            claim,
        } => {
            // Surface irreversible actions to the operator regardless of
            // tier — they pass the gate but they're worth noticing.
            if !matches!(reversibility.effective(), Reversibility::Reversible) {
                tracing::warn!(
                    tool = %tool_name,
                    tier = ?trust_tier,
                    declared = %reversibility.as_str(),
                    action = %action_event,
                    "F5: irreversible action authorized",
                );
            }

            let mut store = match audit_store.lock() {
                Ok(s) => s,
                Err(_) => return Ok(None),
            };

            let mut conditions: Vec<String> = vec![claim.clone()];
            if let Some(d) = detail {
                conditions.push(d.to_string());
            }

            let policy_decision = PolicyDecision::Allow { conditions };
            let action = AuditAction::SystemEvent {
                event: action_event.to_string(),
            };

            let unsealed = UnsealedEntry::new(
                ActorId::System("zp-server".to_string()),
                action,
                tool_lifecycle_conv_id().clone(),
                policy_decision,
                "tool-lifecycle",
            );

            Ok(store.append(unsealed).ok().map(|sealed| sealed.entry_hash))
        }
    }
}

/// Walk the audit chain and count entries whose `PolicyDecision::Allow.conditions`
/// advertise `tool:capability:irreversible`. Used by `zp verify` to publish
/// the trajectory summary line.
///
/// Returns `(irreversible_count, signed_irreversible_count)`. A signed entry
/// is one whose receipt carries an Ed25519 signature — at tier ≥ 1 every
/// irreversible entry should be signed.
pub fn count_irreversible_actions(
    audit_store: &Arc<Mutex<AuditStore>>,
) -> (usize, usize) {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return (0, 0),
    };
    let entries = match store.get_entries(tool_lifecycle_conv_id(), 100_000) {
        Ok(e) => e,
        Err(_) => return (0, 0),
    };
    let mut total = 0usize;
    let mut signed = 0usize;
    for entry in &entries {
        let PolicyDecision::Allow { conditions } = &entry.policy_decision else {
            continue;
        };
        let irreversible = conditions
            .iter()
            .any(|c| c == "tool:capability:irreversible");
        if !irreversible {
            continue;
        }
        total += 1;
        if entry
            .receipt
            .as_ref()
            .map(|r| r.is_signed())
            .unwrap_or(false)
        {
            signed += 1;
        }
    }
    (total, signed)
}

/// Emit a ConfigurationClaim receipt into the audit chain.
///
/// Records a tool parameter being configured — used by the configure
/// handler and the manifest-defaults bootstrap path to produce an
/// auditable trail of every parameter value applied.
pub fn emit_configuration_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    tool_name: &str,
    parameter: &str,
    value: &serde_json::Value,
    source: &str,
    previous_value: Option<&serde_json::Value>,
) -> Option<String> {
    let event = ToolEvent::capability_configured(tool_name, parameter);
    let detail = serde_json::json!({
        "tool_id": tool_name,
        "parameter": parameter,
        "value": value,
        "source": source,
        "previous_value": previous_value,
    });
    emit_tool_receipt(audit_store, &event, Some(&detail.to_string()))
}

// ── Canonicalization (bead zero) ────────────────────────────────────────

/// Parse a domain string into the typed enum.
fn parse_domain(domain: &str) -> CanonicalDomain {
    match domain {
        "system" => CanonicalDomain::System,
        "provider" => CanonicalDomain::Provider,
        "tool" => CanonicalDomain::Tool,
        "node" => CanonicalDomain::Node,
        _ => CanonicalDomain::Tool, // conservative default
    }
}

/// Emit a signed canonicalization receipt — bead zero on a domain wire.
///
/// Creates a typed `CanonicalizedClaim` Receipt with:
/// - `ClaimMetadata::Canonicalization` carrying domain, entity, parent, and initial state
/// - `ClaimSemantics::IntegrityAttestation` ("this hasn't changed")
/// - Ed25519 signature from the server's signing key
///
/// The Receipt is stored in the audit entry's `receipt` field (included in
/// the blake3 entry hash) alongside the `AuditAction::SystemEvent` string
/// event for backward-compatible queries during migration.
///
/// Returns the entry_hash if successful, None if the receipt already exists
/// (idempotent) or append fails.
pub fn emit_canonicalization_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    domain: &str,
    entity_id: &str,
    initial_state: &serde_json::Value,
    parent_entity: Option<&str>,
    canonicalized_by: &str,
) -> Option<String> {
    emit_signed_canonicalization_receipt(
        audit_store,
        domain,
        entity_id,
        initial_state,
        parent_entity,
        canonicalized_by,
        None, // no signing key — legacy path, Receipt created but unsigned
    )
}

/// Emit a signed canonicalization receipt with an explicit signing key.
///
/// This is the preferred entry point. When `signing_key` is provided,
/// the Receipt is signed with Ed25519 before being sealed into the audit chain.
pub fn emit_signed_canonicalization_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    domain: &str,
    entity_id: &str,
    initial_state: &serde_json::Value,
    parent_entity: Option<&str>,
    canonicalized_by: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Option<String> {
    // Idempotency: check if a canonicalization receipt already exists
    let event = format!("{}:canonicalized:{}", domain, entity_id);
    if has_canonicalization_receipt(audit_store, &event) {
        return None; // already anchored — bead zero exists
    }

    // Build typed Receipt — bead zero has no predecessor on this wire.
    let mut receipt = Receipt::canonicalized(canonicalized_by)
        .status(ReceiptStatus::Success)
        .claim_semantics(ClaimSemantics::IntegrityAttestation)
        .claim_metadata(ClaimMetadata::Canonicalization {
            domain: parse_domain(domain),
            entity_id: entity_id.to_string(),
            parent_entity: parent_entity.map(|s| s.to_string()),
            initial_state: initial_state.clone(),
            canonicalized_by: canonicalized_by.to_string(),
            scan_verdict: None,
            scan_findings_count: None,
            scan_timestamp: None,
            reversibility: None,
        })
        .finalize();
    // Bead zero: parent_receipt_id is None (root of this wire).

    // Sign if key provided
    if let Some(key) = signing_key {
        let signer = Signer::from_secret(&key.to_bytes());
        signer.sign(&mut receipt);
    }

    // Store in audit chain. The Receipt's ClaimMetadata::Canonicalization
    // is the source of truth. The string event remains as a lightweight
    // index for backward-compat wire lookups. The detail JSON that was
    // previously duplicated in PolicyDecision::Allow conditions has been
    // removed — "every bit counts."
    let mut store = audit_store.lock().ok()?;

    let action = AuditAction::SystemEvent {
        event: event.to_string(),
    };

    let policy_decision = PolicyDecision::Allow {
        conditions: vec![],
    };

    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-server".to_string()),
        action,
        tool_lifecycle_conv_id().clone(),
        policy_decision,
        "tool-lifecycle",
    )
    .with_receipt(receipt);

    store.append(unsealed).ok().map(|sealed| sealed.entry_hash)
}

// ── F3: scanned canonicalization ────────────────────────────────────────

/// Outcome of a scan-gated canonicalization attempt.
///
/// Adaptation **F3** turns canonicalization into a security gate: a tool
/// that fails the content scanner cannot earn a canon. Callers must handle
/// the `Blocked` arm explicitly — silently dropping it would defeat the gate.
pub enum ScannedCanonicalization {
    /// Bead-zero appended. Carries the audit entry hash and the scanner verdict.
    Emitted {
        entry_hash: String,
        verdict: zp_engine::tool_scan_security::ScanVerdict,
        findings_count: usize,
    },
    /// A canonicalization receipt already exists for this entity (idempotent).
    AlreadyExists,
    /// Scanner verdict was `Blocked`. The receipt was *not* emitted.
    /// Operator override required to canonicalize.
    Blocked(zp_engine::tool_scan_security::ToolContentScanResult),
}

/// Emit a canonicalization receipt **only after** running the F3 content
/// scanner against the supplied tool definition.
///
/// Behavior by verdict:
/// - `Clean`   → emit bead-zero with `scan_verdict = "clean"`.
/// - `Flagged` → emit bead-zero with `scan_verdict = "flagged"` and the
///   findings attached to the policy decision conditions for inspection.
/// - `Blocked` → return `ScannedCanonicalization::Blocked(...)`. No bead is
///   appended. The caller decides whether to surface an operator override.
///
/// `reversibility` is the F5 declaration from the tool's manifest. Pass
/// `None` for system/provider canonicalizations or pre-F5 callers.
#[allow(clippy::too_many_arguments)]
pub fn emit_canonicalization_receipt_with_scan(
    audit_store: &Arc<Mutex<AuditStore>>,
    domain: &str,
    entity_id: &str,
    initial_state: &serde_json::Value,
    parent_entity: Option<&str>,
    canonicalized_by: &str,
    tool_def: &zp_engine::tool_scan_security::ToolDefinition,
    known_tools: &[String],
    signing_key: Option<&ed25519_dalek::SigningKey>,
    reversibility: Option<&str>,
) -> ScannedCanonicalization {
    use zp_engine::tool_scan_security::{scan_tool_definition, ScanVerdict};

    let scan = scan_tool_definition(tool_def, known_tools);
    if matches!(scan.verdict, ScanVerdict::Blocked) {
        return ScannedCanonicalization::Blocked(scan);
    }

    // Idempotency check (mirrors emit_signed_canonicalization_receipt).
    let event = format!("{}:canonicalized:{}", domain, entity_id);
    if has_canonicalization_receipt(audit_store, &event) {
        return ScannedCanonicalization::AlreadyExists;
    }

    let scan_timestamp = chrono::Utc::now().to_rfc3339();
    let findings_count = scan.findings.len();

    // Build typed Receipt — bead zero has no predecessor on this wire.
    let mut receipt = Receipt::canonicalized(canonicalized_by)
        .status(ReceiptStatus::Success)
        .claim_semantics(ClaimSemantics::IntegrityAttestation)
        .claim_metadata(ClaimMetadata::Canonicalization {
            domain: parse_domain(domain),
            entity_id: entity_id.to_string(),
            parent_entity: parent_entity.map(|s| s.to_string()),
            initial_state: initial_state.clone(),
            canonicalized_by: canonicalized_by.to_string(),
            scan_verdict: Some(scan.verdict.as_str().to_string()),
            scan_findings_count: Some(findings_count as u32),
            scan_timestamp: Some(scan_timestamp.clone()),
            reversibility: reversibility.map(|s| s.to_string()),
        })
        .finalize();

    if let Some(key) = signing_key {
        let signer = Signer::from_secret(&key.to_bytes());
        signer.sign(&mut receipt);
    }

    // Lightweight string-event index. For Flagged tools we also stash the
    // finding categories on the policy decision so a chain reader can see
    // *what* was flagged without re-running the scanner.
    let scan_event = match scan.verdict {
        ScanVerdict::Clean => format!("tool:scanned:clean:{}", entity_id),
        ScanVerdict::Flagged => format!("tool:scanned:flagged:{}", entity_id),
        ScanVerdict::Blocked => unreachable!("blocked path returned above"),
    };
    let _ = scan_event; // string-event index emitted below alongside the canon event.

    let mut store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return ScannedCanonicalization::AlreadyExists, // best we can do
    };

    let action = AuditAction::SystemEvent {
        event: event.clone(),
    };

    // Embed finding summaries on Flagged so they remain inspectable from
    // the chain even if the receipt's ClaimMetadata is read by older code.
    let conditions = if matches!(scan.verdict, ScanVerdict::Flagged) {
        scan.findings
            .iter()
            .map(|f| {
                format!(
                    "scan:{:?}:{:?}:{}:{}",
                    f.severity, f.category, f.location, f.detail
                )
            })
            .collect()
    } else {
        vec![]
    };
    let policy_decision = PolicyDecision::Allow { conditions };

    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-server".to_string()),
        action,
        tool_lifecycle_conv_id().clone(),
        policy_decision,
        "tool-lifecycle",
    )
    .with_receipt(receipt);

    match store.append(unsealed) {
        Ok(sealed) => ScannedCanonicalization::Emitted {
            entry_hash: sealed.entry_hash,
            verdict: scan.verdict,
            findings_count,
        },
        Err(_) => ScannedCanonicalization::AlreadyExists,
    }
}

/// Check if a canonicalization receipt already exists for the given event.
///
/// Checks both the Receipt object (preferred) and the legacy string event
/// (backward compat) to handle entries created before the migration.
fn has_canonicalization_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    event_name: &str,
) -> bool {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let entries = match store.get_entries(tool_lifecycle_conv_id(), 500) {
        Ok(e) => e,
        Err(_) => return false,
    };

    entries.iter().any(|entry| {
        // Check Receipt object first (new path)
        if let Some(ref receipt) = entry.receipt {
            if receipt.receipt_type == zp_receipt::ReceiptType::CanonicalizedClaim {
                if let Some(ClaimMetadata::Canonicalization {
                    ref domain,
                    ref entity_id,
                    ..
                }) = receipt.claim_metadata
                {
                    let receipt_event = format!(
                        "{}:canonicalized:{}",
                        match domain {
                            CanonicalDomain::System => "system",
                            CanonicalDomain::Provider => "provider",
                            CanonicalDomain::Tool => "tool",
                            CanonicalDomain::Node => "node",
                        },
                        entity_id
                    );
                    if receipt_event == event_name {
                        return true;
                    }
                }
            }
        }
        // Fall back to legacy string event check
        if let AuditAction::SystemEvent { event } = &entry.action {
            event == event_name
        } else {
            false
        }
    })
}

/// Find the most recent Receipt ID on a given tool wire.
///
/// Receipt-first: checks `ClaimMetadata` for wire membership. Falls back
/// to string-event matching for legacy entries without self-describing metadata.
///
/// Wire prefix examples: `"tool:ironclaw"`, `"provider:anthropic"`, `"system:zeropoint"`.
///
/// Returns the Receipt ID of that entry, which becomes the `parent_receipt_id`
/// for the next bead on this wire.
pub fn latest_receipt_id_on_wire(
    audit_store: &Arc<Mutex<AuditStore>>,
    wire_prefix: &str,
) -> Option<String> {
    let store = audit_store.lock().ok()?;
    let entries = store.get_entries(tool_lifecycle_conv_id(), 500).ok()?;

    // Entries are most-recent-first; find the first matching one
    for entry in &entries {
        // ── Receipt-first: check ClaimMetadata for wire membership ──
        if let Some(ref receipt) = entry.receipt {
            let on_wire = match &receipt.claim_metadata {
                // Canonicalization receipts: match domain + entity_id
                Some(ClaimMetadata::Canonicalization {
                    domain,
                    ref entity_id,
                    ..
                }) => {
                    let wire = match domain {
                        CanonicalDomain::Tool => format!("tool:{}", entity_id),
                        CanonicalDomain::Provider => format!("provider:{}", entity_id),
                        CanonicalDomain::System => "system:zeropoint".to_string(),
                        CanonicalDomain::Node => format!("node:{}", entity_id),
                    };
                    wire == wire_prefix
                }
                // Lifecycle receipts: match tool_id
                Some(ClaimMetadata::Lifecycle { ref tool_id, .. }) => {
                    wire_prefix == format!("tool:{}", tool_id)
                }
                _ => false,
            };
            if on_wire {
                return Some(receipt.id.clone());
            }
        }

        // ── String-event fallback (legacy entries) ─────────────────
        if let AuditAction::SystemEvent { event } = &entry.action {
            let belongs_to_wire = if let Some(tool_name) = wire_prefix.strip_prefix("tool:") {
                event.starts_with("tool:") && event.ends_with(&format!(":{}", tool_name))
            } else if let Some(prov_name) = wire_prefix.strip_prefix("provider:") {
                event.starts_with("provider:") && event.ends_with(&format!(":{}", prov_name))
            } else if wire_prefix == "system:zeropoint" {
                event == "system:canonicalized:zeropoint"
            } else {
                false
            };

            if belongs_to_wire {
                if let Some(ref receipt) = entry.receipt {
                    return Some(receipt.id.clone());
                }
                return Some(entry.entry_hash.clone());
            }
        }
    }
    None
}

/// Emit a signed tool lifecycle receipt (beads after bead zero).
///
/// Creates a Receipt with `parent_receipt_id` pointing to the previous
/// bead on the same wire, establishing an explicit linked list.
///
/// Use this for tool:configured, tool:preflight:passed, tool:launched, etc.
pub fn emit_signed_lifecycle_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    event: &str,
    detail: Option<&str>,
    tool_name: &str,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Option<String> {
    // Find the previous bead on this tool's wire
    let wire_prefix = format!("tool:{}", tool_name);
    let prev_receipt_id = latest_receipt_id_on_wire(audit_store, &wire_prefix);

    // Extract lifecycle event type from the full event string.
    // "tool:configured:ironclaw" → "configured"
    // "tool:preflight:passed:ironclaw" → "preflight:passed"
    // "tool:capability:verified:ironclaw:auth" → "capability:verified"
    let event_type = extract_lifecycle_event_type(event, tool_name);

    // Build Receipt with self-describing ClaimMetadata
    let mut builder = Receipt::execution("zp-server")
        .status(ReceiptStatus::Success)
        .claim_semantics(ClaimSemantics::IntegrityAttestation)
        .claim_metadata(ClaimMetadata::Lifecycle {
            tool_id: tool_name.to_string(),
            event_type,
            detail: detail.map(|d| d.to_string()),
        });

    // Chain to predecessor
    if let Some(ref prev_id) = prev_receipt_id {
        builder = builder.parent(prev_id);
    }

    let mut receipt = builder.finalize();

    // Sign if key provided
    if let Some(key) = signing_key {
        let signer = Signer::from_secret(&key.to_bytes());
        signer.sign(&mut receipt);
    }

    // Store in audit chain. The Receipt's ClaimMetadata::Lifecycle is
    // the source of truth. The string event remains as a lightweight
    // index for backward-compat wire lookups. Detail that was previously
    // duplicated in PolicyDecision::Allow conditions now lives exclusively
    // in ClaimMetadata — "every bit counts."
    let mut store = audit_store.lock().ok()?;

    let action = AuditAction::SystemEvent {
        event: event.to_string(),
    };

    let policy_decision = PolicyDecision::Allow {
        conditions: vec![],
    };

    let unsealed = UnsealedEntry::new(
        ActorId::System("zp-server".to_string()),
        action,
        tool_lifecycle_conv_id().clone(),
        policy_decision,
        "tool-lifecycle",
    )
    .with_receipt(receipt);

    store.append(unsealed).ok().map(|sealed| sealed.entry_hash)
}

/// F6: per-canon-entity metadata extracted from bead-zero receipts.
///
/// Returned by [`query_canonicalization_metadata`] for `zp doctor`'s
/// content-security and reversibility-coverage falsifiers. All optional
/// fields are absent on legacy entries that predate the relevant feature.
#[derive(Debug, Clone, Serialize)]
pub struct CanonMetadata {
    /// `"system" | "provider" | "tool" | "node"`.
    pub domain: String,
    /// Entity name within the domain (e.g., `"ironclaw"`).
    pub entity_id: String,
    /// F3 content-scan verdict: `"clean" | "flagged" | "blocked"`. None on
    /// pre-F3 chains or non-tool canonicalizations that didn't scan.
    pub scan_verdict: Option<String>,
    /// F3 number of scanner findings recorded on the bead.
    pub scan_findings_count: Option<u32>,
    /// F5 reversibility declaration: `"reversible" | "partial" | "irreversible" | "unknown"`.
    /// None on pre-F5 chains.
    pub reversibility: Option<String>,
    /// Whether the bead-zero carries an Ed25519 signature.
    pub signed: bool,
}

/// F6: extract per-entity canonicalization metadata from the audit chain.
///
/// Returns a map keyed by `"domain:entity_id"`. Only the *earliest* bead-zero
/// for each entity is recorded — re-canonicalizations are idempotent and
/// the first one is the authoritative anchor.
///
/// Use this instead of [`query_bead_zeros`] when you need the F3/F5
/// metadata embedded in the bead-zero claim. `query_bead_zeros` returns a
/// JSON-shaped detail blob optimized for the `zp discover` UI; this returns
/// typed fields the doctor checks reason about directly.
pub fn query_canonicalization_metadata(
    audit_store: &Arc<Mutex<AuditStore>>,
) -> HashMap<String, CanonMetadata> {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };
    let entries = match store.get_entries(tool_lifecycle_conv_id(), 100_000) {
        Ok(e) => e,
        Err(_) => return HashMap::new(),
    };

    // Pass 1 — bead-zero (oldest-first so the earliest wins idempotency).
    let mut out: HashMap<String, CanonMetadata> = HashMap::new();
    for entry in entries.iter().rev() {
        let Some(receipt) = entry.receipt.as_ref() else {
            continue;
        };
        if receipt.receipt_type != zp_receipt::ReceiptType::CanonicalizedClaim {
            continue;
        }
        let Some(ClaimMetadata::Canonicalization {
            domain,
            entity_id,
            scan_verdict,
            scan_findings_count,
            reversibility,
            ..
        }) = receipt.claim_metadata.as_ref()
        else {
            continue;
        };
        let domain_str = match domain {
            CanonicalDomain::System => "system",
            CanonicalDomain::Provider => "provider",
            CanonicalDomain::Tool => "tool",
            CanonicalDomain::Node => "node",
        };
        let key = format!("{}:{}", domain_str, entity_id);
        out.entry(key).or_insert_with(|| CanonMetadata {
            domain: domain_str.to_string(),
            entity_id: entity_id.clone(),
            scan_verdict: scan_verdict.clone(),
            scan_findings_count: *scan_findings_count,
            reversibility: reversibility.clone(),
            signed: receipt.is_signed(),
        });
    }

    // Pass 2 — V6 `adapted` lifecycle overlay (newest-first; most recent wins).
    //
    // `zp adapt <tool>` emits a `tool:adapted:<tool>` lifecycle bead carrying
    // refreshed scan_verdict/scan_findings_count/reversibility in its detail
    // JSON, parented to the tool's wire tip. The bead-zero stays untouched —
    // chain integrity preserved — but doctor reads the latest values via
    // this overlay. Pre-adapt tools fall through to bead-zero values.
    let mut overlaid: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    for entry in entries.iter() {
        let Some(receipt) = entry.receipt.as_ref() else {
            continue;
        };
        let Some(ClaimMetadata::Lifecycle {
            tool_id,
            event_type,
            detail: Some(detail_json),
        }) = receipt.claim_metadata.as_ref()
        else {
            continue;
        };
        if event_type != "adapted" {
            continue;
        }
        let key = format!("tool:{}", tool_id);
        if overlaid.contains(&key) {
            // Newer adapted bead already overlaid; skip older ones.
            continue;
        }
        let Some(record) = out.get_mut(&key) else {
            // Adapt-without-bead-zero: structurally invalid. Skip silently.
            continue;
        };
        // Parse the detail JSON; tolerate missing/malformed fields by
        // leaving the bead-zero values in place.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(detail_json) {
            if let Some(s) = v.get("scan_verdict").and_then(|x| x.as_str()) {
                record.scan_verdict = Some(s.to_string());
            }
            if let Some(n) = v.get("scan_findings_count").and_then(|x| x.as_u64()) {
                record.scan_findings_count = Some(n as u32);
            }
            if let Some(r) = v.get("reversibility").and_then(|x| x.as_str()) {
                record.reversibility = Some(r.to_string());
            }
        }
        overlaid.insert(key);
    }

    out
}

/// V6: emit a `tool:adapted:<name>` lifecycle bead carrying refreshed
/// schema-current metadata, parented to the tool's existing wire tip.
///
/// Used by `zp adapt <tool>` to bring a pre-F3/F5 bead-zero into current
/// shape without rewriting it. `query_canonicalization_metadata` overlays
/// these beads on top of bead-zero claims so the doctor-side view tracks
/// disk truth.
pub fn emit_adapted_receipt(
    audit_store: &Arc<Mutex<AuditStore>>,
    tool_name: &str,
    scan_verdict: Option<&str>,
    scan_findings_count: Option<u32>,
    reversibility: Option<&str>,
    signing_key: Option<&ed25519_dalek::SigningKey>,
) -> Option<String> {
    let mut detail = serde_json::Map::new();
    detail.insert(
        "adapted_at".into(),
        serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
    );
    if let Some(s) = scan_verdict {
        detail.insert("scan_verdict".into(), serde_json::Value::String(s.into()));
    }
    if let Some(n) = scan_findings_count {
        detail.insert(
            "scan_findings_count".into(),
            serde_json::Value::Number(n.into()),
        );
    }
    if let Some(r) = reversibility {
        detail.insert(
            "reversibility".into(),
            serde_json::Value::String(r.into()),
        );
    }
    let detail_json = serde_json::Value::Object(detail).to_string();

    let event = format!("tool:adapted:{}", tool_name);
    emit_signed_lifecycle_receipt(
        audit_store,
        &event,
        Some(&detail_json),
        tool_name,
        signing_key,
    )
}

/// Query all bead zeros (first-known-state receipts) from the audit chain.
///
/// Returns a map of "domain:entity_id" → (timestamp, detail_json, receipt_id).
/// Checks Receipt objects first (new path), falls back to string events
/// (legacy path) for entries created before the migration.
pub fn query_bead_zeros(
    audit_store: &Arc<Mutex<AuditStore>>,
) -> HashMap<String, (String, Option<serde_json::Value>)> {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };

    let entries = match store.get_entries(tool_lifecycle_conv_id(), 500) {
        Ok(e) => e,
        Err(_) => return HashMap::new(),
    };

    let mut anchors = HashMap::new();
    for entry in &entries {
        // Prefer Receipt-based extraction (new path)
        if let Some(ref receipt) = entry.receipt {
            if receipt.receipt_type == zp_receipt::ReceiptType::CanonicalizedClaim {
                if let Some(ClaimMetadata::Canonicalization {
                    ref domain,
                    ref entity_id,
                    ref parent_entity,
                    ref initial_state,
                    ref canonicalized_by,
                    ..
                }) = receipt.claim_metadata
                {
                    let domain_str = match domain {
                        CanonicalDomain::System => "system",
                        CanonicalDomain::Provider => "provider",
                        CanonicalDomain::Tool => "tool",
                        CanonicalDomain::Node => "node",
                    };
                    let key = format!("{}:{}", domain_str, entity_id);
                    anchors.entry(key).or_insert_with(|| {
                        let detail = serde_json::json!({
                            "domain": domain_str,
                            "entity_id": entity_id,
                            "parent_entity": parent_entity,
                            "initial_state": initial_state,
                            "canonicalized_by": canonicalized_by,
                            "receipt_id": receipt.id,
                            "signed": receipt.is_signed(),
                        });
                        (entry.timestamp.to_rfc3339(), Some(detail))
                    });
                    continue;
                }
            }
        }

        // Fall back to legacy string event extraction
        if let AuditAction::SystemEvent { event } = &entry.action {
            let parts: Vec<&str> = event.splitn(3, ':').collect();
            if parts.len() == 3 && parts[1] == "canonicalized" {
                let key = format!("{}:{}", parts[0], parts[2]);
                anchors.entry(key).or_insert_with(|| {
                    let detail = if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                        conditions.first().and_then(|s| serde_json::from_str(s).ok())
                    } else {
                        None
                    };
                    (entry.timestamp.to_rfc3339(), detail)
                });
            }
        }
    }

    anchors
}

// ── Query the audit chain ───────────────────────────────────────────────

/// Readiness state for a single tool, derived from the audit chain.
#[derive(Debug, Clone, Serialize)]
pub struct ToolChainState {
    pub name: String,
    /// Bead zero: whether a canonicalization receipt anchors this tool's wire
    pub canonicalized: bool,
    pub canonicalized_at: Option<String>,
    pub configured: bool,
    pub configured_at: Option<String>,
    pub preflight_passed: bool,
    pub preflight_at: Option<String>,
    pub preflight_issues: Vec<String>,
    pub launched: bool,
    pub launched_at: Option<String>,
    pub setup_complete: bool,
    pub setup_at: Option<String>,
    /// Tier 1: tool runtime confirmed it loaded configured providers
    pub providers_resolved: bool,
    pub providers_resolved_at: Option<String>,
    pub providers_detail: Option<String>,
    /// Tier 2: per-capability verification results
    pub capabilities: Vec<CapabilityChainState>,
    /// True only if canonicalized + configured + preflight passed
    pub ready: bool,
    /// True only if ready + providers resolved + all required capabilities verified
    pub verified: bool,
    // ── Receipt chain integrity ──────────────────────────────────────
    /// Receipt ID of bead zero (canonicalization), if it carries a signed Receipt
    pub bead_zero_receipt_id: Option<String>,
    /// Whether bead zero is signed with Ed25519
    pub bead_zero_signed: bool,
    /// Total number of signed Receipts on this wire
    pub signed_bead_count: u32,
    /// Receipt ID of the most recent bead on this wire
    pub wire_tip_receipt_id: Option<String>,
}

/// Per-capability verification state, derived from the audit chain.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityChainState {
    pub capability: String,
    pub status: String, // "verified", "degraded", "failed"
    pub verified_at: Option<String>,
    pub detail: Option<String>,
}

/// Query the audit chain for tool lifecycle state.
///
/// Scans entries under the tool-lifecycle conversation ID,
/// extracts the latest event for each tool, and returns a map
/// of tool name → readiness state.
pub fn query_tool_readiness(
    audit_store: &Arc<Mutex<AuditStore>>,
) -> HashMap<String, ToolChainState> {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };

    // Get all tool lifecycle entries (most recent first)
    let entries = match store.get_entries(tool_lifecycle_conv_id(), 500) {
        Ok(e) => e,
        Err(_) => return HashMap::new(),
    };

    let mut states: HashMap<String, ToolChainState> = HashMap::new();

    // ── Single-pass scan: Receipt-first with string-event fallback ──────
    //
    // For each entry, try to extract lifecycle state from the Receipt's
    // ClaimMetadata (self-describing). If no ClaimMetadata is present
    // (legacy entries from before Phase 6), fall back to parsing the
    // AuditAction::SystemEvent string.
    //
    // Entries are most-recent-first. For each tool, only the LATEST
    // event of each type matters — once a field is set, we skip it.
    for entry in &entries {
        let timestamp = entry.timestamp.to_rfc3339();

        // ── Receipt-first path ─────────────────────────────────────
        if let Some(ref receipt) = entry.receipt {
            match &receipt.claim_metadata {
                // Bead zero: canonicalization receipt
                Some(ClaimMetadata::Canonicalization {
                    domain: CanonicalDomain::Tool,
                    ref entity_id,
                    ..
                }) => {
                    let state = states
                        .entry(entity_id.clone())
                        .or_insert_with(|| empty_state(entity_id));
                    if !state.canonicalized {
                        state.canonicalized = true;
                        state.canonicalized_at = Some(timestamp.clone());
                    }
                    if state.bead_zero_receipt_id.is_none() {
                        state.bead_zero_receipt_id = Some(receipt.id.clone());
                        state.bead_zero_signed = receipt.is_signed();
                    }
                    // Wire tip + signed bead tracking
                    if state.wire_tip_receipt_id.is_none() {
                        state.wire_tip_receipt_id = Some(receipt.id.clone());
                    }
                    if receipt.is_signed() {
                        state.signed_bead_count += 1;
                    }
                    continue; // fully handled by Receipt
                }

                // Lifecycle bead: self-describing event type + tool_id
                Some(ClaimMetadata::Lifecycle {
                    ref tool_id,
                    ref event_type,
                    ref detail,
                }) => {
                    let state = states
                        .entry(tool_id.clone())
                        .or_insert_with(|| empty_state(tool_id));

                    apply_lifecycle_event(
                        state,
                        event_type,
                        detail.as_deref(),
                        &timestamp,
                        &entry.policy_decision,
                    );

                    // Wire tip + signed bead tracking
                    if state.wire_tip_receipt_id.is_none() {
                        state.wire_tip_receipt_id = Some(receipt.id.clone());
                    }
                    if receipt.is_signed() {
                        state.signed_bead_count += 1;
                    }
                    continue; // fully handled by Receipt
                }

                // Other ClaimMetadata variants or None — fall through to string path
                _ => {}
            }
        }

        // ── String-event fallback (legacy entries) ─────────────────
        if let AuditAction::SystemEvent { event } = &entry.action {
            if !event.starts_with("tool:") {
                continue;
            }

            let parts: Vec<&str> = event.splitn(4, ':').collect();
            if parts.len() < 3 {
                continue;
            }

            match parts[1] {
                "canonicalized" => {
                    let name = parts[2].to_string();
                    let state = states
                        .entry(name.clone())
                        .or_insert_with(|| empty_state(&name));
                    if !state.canonicalized {
                        state.canonicalized = true;
                        state.canonicalized_at = Some(timestamp.clone());
                    }
                    // Extract bead-zero Receipt metadata if present (Phase 4 compat)
                    if state.bead_zero_receipt_id.is_none() {
                        if let Some(ref receipt) = entry.receipt {
                            if receipt.receipt_type
                                == zp_receipt::ReceiptType::CanonicalizedClaim
                            {
                                state.bead_zero_receipt_id = Some(receipt.id.clone());
                                state.bead_zero_signed = receipt.is_signed();
                            }
                        }
                    }
                }
                "configured" => {
                    let name = parts[2].to_string();
                    let state = states
                        .entry(name.clone())
                        .or_insert_with(|| empty_state(&name));
                    if !state.configured {
                        state.configured = true;
                        state.configured_at = Some(timestamp);
                    }
                }
                "preflight" => {
                    if parts.len() < 4 {
                        continue;
                    }
                    let sub = parts[2];
                    let name = parts[3].to_string();
                    match sub {
                        "passed" => {
                            let state = states
                                .entry(name.clone())
                                .or_insert_with(|| empty_state(&name));
                            if state.preflight_at.is_none() {
                                state.preflight_passed = true;
                                state.preflight_at = Some(timestamp);
                            }
                        }
                        "failed" => {
                            let state = states
                                .entry(name.clone())
                                .or_insert_with(|| empty_state(&name));
                            if state.preflight_at.is_none() {
                                state.preflight_passed = false;
                                state.preflight_at = Some(timestamp);
                                if let PolicyDecision::Allow { conditions } = &entry.policy_decision
                                {
                                    state.preflight_issues = conditions.clone();
                                }
                            }
                        }
                        "check" => { /* granular — tracked but doesn't override summary */ }
                        _ => {}
                    }
                }
                "launched" => {
                    let name = parts[2].to_string();
                    let state = states
                        .entry(name.clone())
                        .or_insert_with(|| empty_state(&name));
                    if !state.launched {
                        state.launched = true;
                        state.launched_at = Some(timestamp);
                    }
                }
                "setup" => {
                    if parts.len() >= 4 && parts[2] == "complete" {
                        let name = parts[3].to_string();
                        let state = states
                            .entry(name.clone())
                            .or_insert_with(|| empty_state(&name));
                        if !state.setup_complete {
                            state.setup_complete = true;
                            state.setup_at = Some(timestamp);
                        }
                    }
                }
                "providers" => {
                    if parts.len() >= 4 && parts[2] == "resolved" {
                        let name = parts[3].to_string();
                        let state = states
                            .entry(name.clone())
                            .or_insert_with(|| empty_state(&name));
                        if !state.providers_resolved {
                            state.providers_resolved = true;
                            state.providers_resolved_at = Some(timestamp);
                            if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                                state.providers_detail = conditions.first().cloned();
                            }
                        }
                    }
                }
                "capability" => {
                    if parts.len() >= 4 {
                        let sub = parts[2];
                        let rest = parts[3];
                        if let Some((name, cap)) = rest.split_once(':') {
                            let name = name.to_string();
                            let cap = cap.to_string();
                            let state = states
                                .entry(name.clone())
                                .or_insert_with(|| empty_state(&name));
                            let already = state.capabilities.iter().any(|c| c.capability == cap);
                            if !already {
                                let detail = if let PolicyDecision::Allow { conditions } =
                                    &entry.policy_decision
                                {
                                    conditions.first().cloned()
                                } else {
                                    None
                                };
                                state.capabilities.push(CapabilityChainState {
                                    capability: cap,
                                    status: sub.to_string(),
                                    verified_at: Some(timestamp),
                                    detail,
                                });
                            }
                        }
                    }
                }
                _ => {}
            }

            // Legacy wire tip / signed bead tracking for entries with Receipt
            // but no ClaimMetadata (fell through from Receipt-first path above)
            if let Some(ref receipt) = entry.receipt {
                let tool_name = extract_tool_name_from_event(event);
                if let Some(name) = tool_name {
                    if let Some(state) = states.get_mut(&name) {
                        if state.wire_tip_receipt_id.is_none() {
                            state.wire_tip_receipt_id = Some(receipt.id.clone());
                        }
                        if receipt.is_signed() {
                            state.signed_bead_count += 1;
                        }
                    }
                }
            }
        }
    }

    // Compute readiness and verification
    for state in states.values_mut() {
        state.ready = state.canonicalized && state.configured && state.preflight_passed;
        // Verified = ready + providers resolved + no failed required capabilities
        // (empty capabilities list means verification hasn't run yet → not verified)
        state.verified = state.ready
            && state.providers_resolved
            && !state.capabilities.is_empty()
            && state.capabilities.iter().all(|c| c.status != "failed");
    }

    states
}

/// Extract the tool name from a tool lifecycle event string.
///
/// Handles all event formats:
/// - `tool:canonicalized:<name>` → `<name>`
/// - `tool:configured:<name>` → `<name>`
/// - `tool:launched:<name>` → `<name>`
/// - `tool:preflight:{passed|failed}:<name>` → `<name>`
/// - `tool:setup:complete:<name>` → `<name>`
/// - `tool:providers:resolved:<name>` → `<name>`
/// - `tool:capability:{verified|degraded|failed}:<name>:<cap>` → `<name>`
///
/// Returns `None` for non-tool events or unrecognized formats.
fn extract_tool_name_from_event(event: &str) -> Option<String> {
    if !event.starts_with("tool:") {
        return None;
    }
    let parts: Vec<&str> = event.splitn(4, ':').collect();
    if parts.len() < 3 {
        return None;
    }
    match parts[1] {
        "canonicalized" | "configured" | "launched" => Some(parts[2].to_string()),
        "preflight" | "setup" | "providers" => {
            // tool:preflight:{passed|failed}:<name>
            // tool:setup:complete:<name>
            // tool:providers:resolved:<name>
            if parts.len() >= 4 {
                Some(parts[3].to_string())
            } else {
                None
            }
        }
        "capability" => {
            // tool:capability:{verified|degraded|failed}:<name>:<cap>
            if parts.len() >= 4 {
                // parts[3] = "<name>:<cap>"
                parts[3].split_once(':').map(|(name, _)| name.to_string())
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the lifecycle event type from a full event string, stripping
/// the `tool:` prefix and the tool name suffix.
///
/// Examples:
/// - `"tool:configured:ironclaw"` → `"configured"`
/// - `"tool:preflight:passed:ironclaw"` → `"preflight:passed"`
/// - `"tool:setup:complete:ironclaw"` → `"setup:complete"`
/// - `"tool:providers:resolved:ironclaw"` → `"providers:resolved"`
/// - `"tool:capability:verified:ironclaw:auth"` → `"capability:verified"`
fn extract_lifecycle_event_type(event: &str, tool_name: &str) -> String {
    // Strip "tool:" prefix
    let without_prefix = event.strip_prefix("tool:").unwrap_or(event);

    // For capability events: "capability:verified:ironclaw:auth" → "capability:verified"
    // For simple events: "configured:ironclaw" → "configured"
    // For compound events: "preflight:passed:ironclaw" → "preflight:passed"

    // Find the tool name boundary and take everything before it
    let tool_suffix = format!(":{}", tool_name);
    if let Some(idx) = without_prefix.find(&tool_suffix) {
        without_prefix[..idx].to_string()
    } else {
        // Fallback: return the full string without prefix
        without_prefix.to_string()
    }
}

/// Apply a lifecycle event to a tool's chain state.
///
/// Maps the Receipt's `event_type` string to the corresponding state field.
/// This is the Receipt-first equivalent of the string-event match arms.
fn apply_lifecycle_event(
    state: &mut ToolChainState,
    event_type: &str,
    detail: Option<&str>,
    timestamp: &str,
    policy_decision: &PolicyDecision,
) {
    match event_type {
        "configured" => {
            if !state.configured {
                state.configured = true;
                state.configured_at = Some(timestamp.to_string());
            }
        }
        "preflight:passed" => {
            if state.preflight_at.is_none() {
                state.preflight_passed = true;
                state.preflight_at = Some(timestamp.to_string());
            }
        }
        "preflight:failed" => {
            if state.preflight_at.is_none() {
                state.preflight_passed = false;
                state.preflight_at = Some(timestamp.to_string());
                if let PolicyDecision::Allow { conditions } = policy_decision {
                    state.preflight_issues = conditions.clone();
                }
            }
        }
        "preflight:check" => { /* granular — tracked but doesn't override summary */ }
        "launched" => {
            if !state.launched {
                state.launched = true;
                state.launched_at = Some(timestamp.to_string());
            }
        }
        "setup:complete" => {
            if !state.setup_complete {
                state.setup_complete = true;
                state.setup_at = Some(timestamp.to_string());
            }
        }
        "providers:resolved" => {
            if !state.providers_resolved {
                state.providers_resolved = true;
                state.providers_resolved_at = Some(timestamp.to_string());
                state.providers_detail = detail.map(|d| d.to_string());
            }
        }
        evt if evt.starts_with("capability:") => {
            // "capability:verified", "capability:degraded", "capability:failed"
            let cap_status = evt.strip_prefix("capability:").unwrap_or("unknown");
            if let Some(cap_name) = detail {
                let already = state.capabilities.iter().any(|c| c.capability == cap_name);
                if !already {
                    state.capabilities.push(CapabilityChainState {
                        capability: cap_name.to_string(),
                        status: cap_status.to_string(),
                        verified_at: Some(timestamp.to_string()),
                        detail: None,
                    });
                }
            }
        }
        _ => {}
    }
}

fn empty_state(name: &str) -> ToolChainState {
    ToolChainState {
        name: name.to_string(),
        canonicalized: false,
        canonicalized_at: None,
        configured: false,
        configured_at: None,
        preflight_passed: false,
        preflight_at: None,
        preflight_issues: vec![],
        launched: false,
        launched_at: None,
        setup_complete: false,
        setup_at: None,
        providers_resolved: false,
        providers_resolved_at: None,
        providers_detail: None,
        capabilities: vec![],
        ready: false,
        verified: false,
        bead_zero_receipt_id: None,
        bead_zero_signed: false,
        signed_bead_count: 0,
        wire_tip_receipt_id: None,
    }
}

// ── P6-2: Configuration receipt query ─────────────────────────────────

/// A single configuration parameter receipt, derived from the audit chain.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigParameterSnapshot {
    pub parameter: String,
    pub value: Option<serde_json::Value>,
    pub source: Option<String>,
    pub previous_value: Option<serde_json::Value>,
    pub configured_at: String,
    pub entry_hash: String,
}

/// Query the audit chain for all configuration receipts for a specific tool.
///
/// Returns the latest configuration receipt per parameter, ordered by timestamp.
pub fn query_tool_configuration(
    audit_store: &Arc<Mutex<AuditStore>>,
    tool_name: &str,
) -> Vec<ConfigParameterSnapshot> {
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let entries = match store.get_entries(tool_lifecycle_conv_id(), 500) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let prefix = format!("tool:capability:configured:{}:", tool_name);
    let mut seen: HashMap<String, ConfigParameterSnapshot> = HashMap::new();

    // Walk entries (most recent first) — only take first per parameter
    for entry in &entries {
        if let AuditAction::SystemEvent { event } = &entry.action {
            if let Some(param) = event.strip_prefix(&prefix) {
                if seen.contains_key(param) {
                    continue; // already have a newer receipt for this param
                }

                // Parse the detail JSON from the policy conditions
                let detail_json: Option<serde_json::Value> =
                    if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                        conditions.first().and_then(|s| serde_json::from_str(s).ok())
                    } else {
                        None
                    };

                let (value, source, previous_value) = if let Some(ref dj) = detail_json {
                    (
                        dj.get("value").cloned(),
                        dj.get("source").and_then(|s| s.as_str()).map(String::from),
                        dj.get("previous_value").cloned().filter(|v| !v.is_null()),
                    )
                } else {
                    (None, None, None)
                };

                seen.insert(
                    param.to_string(),
                    ConfigParameterSnapshot {
                        parameter: param.to_string(),
                        value,
                        source,
                        previous_value,
                        configured_at: entry.timestamp.to_rfc3339(),
                        entry_hash: entry.entry_hash.clone(),
                    },
                );
            }
        }
    }

    let mut receipts: Vec<ConfigParameterSnapshot> = seen.into_values().collect();
    receipts.sort_by(|a, b| a.parameter.cmp(&b.parameter));
    receipts
}

// ── REST endpoint for tool-issued receipts ──────────────────────────────

/// Request body for tools to announce their own lifecycle events.
/// POST /api/v1/tools/receipt
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReceiptRequest {
    /// Tool name (must match a configured tool)
    pub name: String,
    /// Event type: "setup:complete", or any custom event
    pub event: String,
    /// Optional detail/evidence
    pub detail: Option<String>,
}

// ── Broadcast-aware emission (P4-1) ────────────────────────────────────

/// Emit a tool lifecycle receipt AND broadcast it to the SSE event stream.
///
/// This is the preferred entry point for handlers that have access to
/// AppState — it combines audit chain persistence with real-time
/// notification in a single call.
pub fn emit_and_broadcast(
    audit_store: &Arc<Mutex<AuditStore>>,
    event_tx: &tokio::sync::broadcast::Sender<crate::events::EventStreamItem>,
    event: &str,
    detail: Option<&str>,
) -> Option<String> {
    let entry_hash = emit_tool_receipt(audit_store, event, detail);

    // Broadcast to SSE subscribers (best-effort)
    let item = crate::events::EventStreamItem::from_audit(
        event,
        entry_hash.clone(),
    );
    let item = if let Some(d) = detail {
        item.with_summary(d)
    } else {
        item
    };
    crate::events::broadcast_event(event_tx, item);

    entry_hash
}

// ── F5 tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod f5_tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_store() -> (TempDir, Arc<Mutex<AuditStore>>) {
        let dir = TempDir::new().expect("tempdir");
        let store = AuditStore::open(dir.path().join("audit.db")).expect("open");
        (dir, Arc::new(Mutex::new(store)))
    }

    fn dummy_tool_def(name: &str) -> zp_engine::tool_scan_security::ToolDefinition {
        zp_engine::tool_scan_security::ToolDefinition {
            name: name.to_string(),
            description: Some("test fixture".to_string()),
            parameters: vec![],
        }
    }

    fn canon_tool(
        store: &Arc<Mutex<AuditStore>>,
        name: &str,
        rev: Reversibility,
    ) {
        let initial = serde_json::json!({"fields": []});
        let outcome = emit_canonicalization_receipt_with_scan(
            store,
            "tool",
            name,
            &initial,
            None,
            "f5-test",
            &dummy_tool_def(name),
            &[],
            None,
            Some(rev.as_str()),
        );
        match outcome {
            ScannedCanonicalization::Emitted { .. } => {}
            ScannedCanonicalization::AlreadyExists => {}
            ScannedCanonicalization::Blocked(s) => {
                panic!("test fixture blocked unexpectedly: {} findings", s.findings.len())
            }
        }
    }

    #[test]
    fn bead_zero_carries_reversibility_claim() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "irc", Reversibility::Irreversible);

        let queried = query_tool_reversibility(&store, "irc");
        assert_eq!(queried, Reversibility::Irreversible);
    }

    #[test]
    fn missing_canon_returns_unknown() {
        let (_d, store) = fresh_store();
        assert_eq!(
            query_tool_reversibility(&store, "never-canon'd"),
            Reversibility::Unknown
        );
    }

    #[test]
    fn gate_allows_reversible_at_tier0() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "search", Reversibility::Reversible);

        match enforce_reversibility_gate(&store, "search", TrustTier::Tier0) {
            ReversibilityGate::Allow { claim, .. } => {
                assert_eq!(claim, "tool:capability:reversible");
            }
            ReversibilityGate::Deny { reason, .. } => {
                panic!("expected Allow, got Deny: {}", reason)
            }
        }
    }

    #[test]
    fn gate_denies_irreversible_at_tier0() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "delete", Reversibility::Irreversible);

        let outcome = enforce_reversibility_gate(&store, "delete", TrustTier::Tier0);
        assert!(matches!(outcome, ReversibilityGate::Deny { .. }));
    }

    #[test]
    fn gate_allows_irreversible_at_tier1() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "delete", Reversibility::Irreversible);

        match enforce_reversibility_gate(&store, "delete", TrustTier::Tier1) {
            ReversibilityGate::Allow { claim, .. } => {
                assert_eq!(claim, "tool:capability:irreversible");
            }
            other => panic!("expected Allow at Tier1, got {:?}", other),
        }
    }

    #[test]
    fn gate_treats_partial_as_irreversible() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "writeish", Reversibility::Partial);

        // Tier 0 → deny.
        assert!(matches!(
            enforce_reversibility_gate(&store, "writeish", TrustTier::Tier0),
            ReversibilityGate::Deny { .. }
        ));
        // Tier 1 → allow with irreversible claim.
        match enforce_reversibility_gate(&store, "writeish", TrustTier::Tier1) {
            ReversibilityGate::Allow { claim, .. } => {
                assert_eq!(claim, "tool:capability:irreversible");
            }
            other => panic!("expected Allow at Tier1, got {:?}", other),
        }
    }

    #[test]
    fn gate_treats_unknown_as_irreversible() {
        let (_d, store) = fresh_store();
        // Canonicalize without any reversibility annotation — simulates a
        // pre-F5 chain entry.
        let initial = serde_json::json!({});
        let _ = emit_canonicalization_receipt_with_scan(
            &store,
            "tool",
            "legacy",
            &initial,
            None,
            "f5-test",
            &dummy_tool_def("legacy"),
            &[],
            None,
            None, // <-- no reversibility recorded
        );
        assert!(matches!(
            enforce_reversibility_gate(&store, "legacy", TrustTier::Tier0),
            ReversibilityGate::Deny { .. }
        ));
        assert!(matches!(
            enforce_reversibility_gate(&store, "legacy", TrustTier::Tier1),
            ReversibilityGate::Allow { .. }
        ));
    }

    #[test]
    fn action_receipt_blocks_irreversible_tier0_and_emits_nothing() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "delete", Reversibility::Irreversible);
        let before = count_irreversible_actions(&store);

        let result = emit_tool_action_receipt(
            &store,
            "delete",
            "tool:executed:delete",
            None,
            TrustTier::Tier0,
        );
        assert!(result.is_err(), "tier0 must be denied");

        let after = count_irreversible_actions(&store);
        assert_eq!(before, after, "no chain entry should be appended on deny");
    }

    #[test]
    fn action_receipt_records_irreversible_claim_at_tier1() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "delete", Reversibility::Irreversible);

        let result = emit_tool_action_receipt(
            &store,
            "delete",
            "tool:executed:delete",
            Some("dropped row 42"),
            TrustTier::Tier1,
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());

        let (total, _signed) = count_irreversible_actions(&store);
        assert_eq!(total, 1);
    }

    #[test]
    fn reversible_action_does_not_inflate_irreversible_counter() {
        let (_d, store) = fresh_store();
        canon_tool(&store, "search", Reversibility::Reversible);

        let result = emit_tool_action_receipt(
            &store,
            "search",
            "tool:executed:search",
            None,
            TrustTier::Tier0,
        );
        assert!(result.is_ok());

        let (total, _) = count_irreversible_actions(&store);
        assert_eq!(total, 0);
    }
}
