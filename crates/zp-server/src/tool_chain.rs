//! Tool lifecycle receipts — readiness state derived from the audit chain.
//!
//! Instead of caching tool readiness in a JSON file, every meaningful
//! state transition for a tool produces a hash-linked audit entry:
//!
//!   tool:registered:<name>                — added to governance via Add Tool flow
//!   tool:configured:<name>                — .env written, credentials resolved
//!   tool:preflight:passed:<name>          — all infra checks green
//!   tool:preflight:failed:<name>          — one or more checks failed
//!   tool:preflight:check:<name>:<check>   — individual check result
//!   tool:launched:<name>                  — process spawned, port responded
//!   tool:setup:complete:<name>            — tool's own first-run finished
//!   tool:providers:resolved:<name>        — Tier 1: runtime loaded configured providers
//!   tool:capability:verified:<name>:<cap> — Tier 2: capability auth probe returned 2xx
//!   tool:capability:degraded:<name>:<cap> — Tier 2: optional capability probe failed
//!   tool:capability:failed:<name>:<cap>   — Tier 2: required capability probe failed
//!
//! The cockpit reads the chain to determine readiness. Missing receipts
//! tell you exactly what's outstanding, and every receipt is signed and
//! hash-linked so the readiness state is verifiable.
//!
//! The `preflight.json` file is kept as a **read cache** for fast cockpit
//! rendering, but the chain is canonical.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use uuid::Uuid;

use zp_audit::{AuditStore, UnsealedEntry};
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};

// ── Well-known namespace ────────────────────────────────────────────────
// All tool lifecycle events live under a single synthetic conversation ID
// so they can be queried efficiently without scanning the entire chain.
pub(crate) fn tool_lifecycle_conv_id() -> &'static ConversationId {
    static ID: OnceLock<ConversationId> = OnceLock::new();
    ID.get_or_init(|| {
        ConversationId(
            Uuid::parse_str("00000000-0000-7000-8000-746f6f6c6c63").unwrap()
        )
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

// ── Query the chain ─────────────────────────────────────────────────────

/// Readiness state for a single tool, derived from the chain.
#[derive(Debug, Clone, Serialize)]
pub struct ToolChainState {
    pub name: String,
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
    /// True only if configured + preflight passed
    pub ready: bool,
    /// True only if ready + providers resolved + all required capabilities verified
    pub verified: bool,
}

/// Per-capability verification state, derived from the chain.
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

    // Walk entries from most recent to oldest.
    // For each tool, only the LATEST event of each type matters.
    for entry in &entries {
        if let AuditAction::SystemEvent { event } = &entry.action {
            if !event.starts_with("tool:") {
                continue;
            }

            let parts: Vec<&str> = event.splitn(4, ':').collect();
            // parts[0] = "tool", parts[1] = event_type, parts[2] = tool_name or sub-type
            if parts.len() < 3 {
                continue;
            }

            let timestamp = entry.timestamp.to_rfc3339();

            match parts[1] {
                "configured" => {
                    let name = parts[2].to_string();
                    let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));
                    if !state.configured {
                        state.configured = true;
                        state.configured_at = Some(timestamp);
                    }
                }
                "preflight" => {
                    if parts.len() < 4 {
                        continue;
                    }
                    let sub = parts[2]; // "passed", "failed", or "check"
                    let name = parts[3].to_string();

                    match sub {
                        "passed" => {
                            let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));
                            if state.preflight_at.is_none() {
                                // Only take the most recent
                                state.preflight_passed = true;
                                state.preflight_at = Some(timestamp);
                            }
                        }
                        "failed" => {
                            let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));
                            if state.preflight_at.is_none() {
                                state.preflight_passed = false;
                                state.preflight_at = Some(timestamp);
                                // Extract failure details from policy conditions
                                if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                                    state.preflight_issues = conditions.clone();
                                }
                            }
                        }
                        "check" => {
                            // tool:preflight:check:<name>:<check_name>:<status>
                            // Granular — we track these but don't override the summary
                        }
                        _ => {}
                    }
                }
                "launched" => {
                    let name = parts[2].to_string();
                    let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));
                    if !state.launched {
                        state.launched = true;
                        state.launched_at = Some(timestamp);
                    }
                }
                "setup" => {
                    // tool:setup:complete:<name>
                    if parts.len() >= 4 && parts[2] == "complete" {
                        let name = parts[3].to_string();
                        let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));
                        if !state.setup_complete {
                            state.setup_complete = true;
                            state.setup_at = Some(timestamp);
                        }
                    }
                }
                "providers" => {
                    // tool:providers:resolved:<name>
                    if parts.len() >= 4 && parts[2] == "resolved" {
                        let name = parts[3].to_string();
                        let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));
                        if !state.providers_resolved {
                            state.providers_resolved = true;
                            state.providers_resolved_at = Some(timestamp);
                            // Extract detail from policy conditions
                            if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
                                state.providers_detail = conditions.first().cloned();
                            }
                        }
                    }
                }
                "capability" => {
                    // tool:capability:{verified|degraded|failed}:<name>:<capability>
                    if parts.len() >= 4 {
                        let sub = parts[2]; // "verified", "degraded", or "failed"
                        // parts[3] = "<name>:<capability>" — need to split further
                        let rest = parts[3];
                        if let Some((name, cap)) = rest.split_once(':') {
                            let name = name.to_string();
                            let cap = cap.to_string();
                            let state = states.entry(name.clone()).or_insert_with(|| empty_state(&name));

                            // Only take the most recent receipt per capability
                            let already = state.capabilities.iter().any(|c| c.capability == cap);
                            if !already {
                                let detail = if let PolicyDecision::Allow { conditions } = &entry.policy_decision {
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
        }
    }

    // Compute readiness and verification
    for state in states.values_mut() {
        state.ready = state.configured && state.preflight_passed;
        // Verified = ready + providers resolved + no failed required capabilities
        // (empty capabilities list means verification hasn't run yet → not verified)
        state.verified = state.ready
            && state.providers_resolved
            && !state.capabilities.is_empty()
            && state.capabilities.iter()
                .all(|c| c.status != "failed");
    }

    states
}

fn empty_state(name: &str) -> ToolChainState {
    ToolChainState {
        name: name.to_string(),
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
    }
}

// ── REST endpoint for tool-issued receipts ──────────────────────────────

/// Request body for tools to announce their own lifecycle events.
/// POST /api/v1/tools/receipt
#[derive(serde::Deserialize)]
pub struct ToolReceiptRequest {
    /// Tool name (must match a configured tool)
    pub name: String,
    /// Event type: "setup:complete", or any custom event
    pub event: String,
    /// Optional detail/evidence
    pub detail: Option<String>,
}
