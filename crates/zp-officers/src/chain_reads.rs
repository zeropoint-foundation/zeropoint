//! Officer chain-read containment helper (S3 discipline).
//!
//! Per `SUBSTRATE-LOOP-CLOSURE-2026-07.md` §S3 — *Contain E4's coupling* —
//! this module centralizes every officer chain read that depends on
//! receipt-format strings. Before this module, officer files across the
//! crate did `event.strip_prefix("tool:launched:")` and
//! `chain.search_by_keyword("delegation:granted:", ...)` inline, coupling
//! each officer to the exact substrate receipt vocabulary. A receipt
//! rename could break an officer silently.
//!
//! After this module, officers call typed helpers (`tool_lifecycle_events`,
//! `delegation_events`, `gate_events`, `officer_attestations`,
//! `system_lifecycle_events`) that return **extracted typed fields**
//! — `ToolLifecycleEvent { tool_name, kind, .. }` — never the raw event
//! string. The coupling is now enumerable in one file (see
//! `OFFICER_READ_PREFIXES` below).
//!
//! **Seam for Cartographer.** Per `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`,
//! Cartographer will materialize the substrate's ontology from the chain
//! (Trajectories, Decisions, Insights, Artifacts, Frictions, Waypoints).
//! When it lands, each function in this module becomes the seam that
//! queries the ontology projection instead of raw chain search — call
//! sites in officers stay unchanged, and the coupling to receipt-format
//! strings moves from officer files into Cartographer's projection code
//! (which is precisely where it belongs, because Cartographer's job is
//! translating chain shapes into ontology shapes).
//!
//! **Preserving semantics on refactor.** Each helper wraps exactly one
//! `ChainReader::search_by_keyword` call and applies exactly the same
//! extraction logic the callers used before. Per-prefix limits are
//! preserved (each helper takes a `limit` parameter that applies to its
//! single underlying query). Callers that previously did two queries
//! (e.g., `tool:launched:` and `tool:started:` for the same semantic
//! event class) continue to do two calls after refactor — this module
//! deliberately keeps the receipt-name duality visible rather than
//! papering over it.

use crate::officer::{ChainReadError, ChainReader};
use zp_core::{AuditAction, AuditEntry};

// ═══════════════════════════════════════════════════════════════════════
// Enumerated receipt-string dependencies
// ═══════════════════════════════════════════════════════════════════════

/// Every receipt prefix or event name officers depend on for parsing.
///
/// When this list changes, the officer chain-read surface changed —
/// Cartographer's projection (or, pre-Cartographer, any receipt-name
/// migration ceremony) needs matching updates. `SUBSTRATE-LOOP-CLOSURE`
/// §S3's whole purpose is making this list **exist and be one place**.
///
/// Not exposed as strings for callers to concat into `search_by_keyword`
/// — that would reintroduce the coupling this module contains. Provided
/// as a public constant so tooling can audit it, so migration ceremonies
/// can reference it, and so Cartographer's future projection code can
/// verify it covers every officer-read shape.
pub const OFFICER_READ_PREFIXES: &[&str] = &[
    // Tool lifecycle
    "tool:configured:",
    "tool:port:assigned:",
    "tool:preflight:passed:",
    "tool:preflight:failed:",
    "tool:launched:",
    "tool:started:",
    "tool:restarted:",
    "tool:stopped:",
    "tool:failed:",
    "tool:launch_failed:",
    "tool:health:up:",
    "tool:health:down:",
    // Delegation lifecycle
    "delegation:granted:",
    "delegation:renewed:",
    "delegation:revoked:",
    "delegation:expired:",
    // Gate outcomes
    "gate:allowed:",
    "gate:denied:",
    // Officer attestation — `officer:<name>:attested:<tool>`
    "attested:",
    // System lifecycle (bare event names, not prefixes)
    "server:started",
    "server:stopped",
    "system:startup",
    "system:shutdown",
];

// ═══════════════════════════════════════════════════════════════════════
// Tool lifecycle
// ═══════════════════════════════════════════════════════════════════════

/// Which stage of a tool's lifecycle an event marks.
///
/// Each variant maps 1:1 to a receipt prefix in `OFFICER_READ_PREFIXES`.
/// Callers that treat some variants as semantically equivalent (e.g.,
/// `Launched` and `Started` are both "the tool came up") do that in
/// their own code — this enum stays faithful to the underlying receipt
/// vocabulary so the coupling remains visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolLifecycleKind {
    Configured,
    PortAssigned,
    PreflightPassed,
    PreflightFailed,
    Launched,
    Started,
    Restarted,
    Stopped,
    Failed,
    LaunchFailed,
    HealthUp,
    HealthDown,
}

impl ToolLifecycleKind {
    /// The receipt prefix this kind reads. Contained here so callers
    /// never quote the string themselves.
    fn receipt_prefix(self) -> &'static str {
        match self {
            Self::Configured => "tool:configured:",
            Self::PortAssigned => "tool:port:assigned:",
            Self::PreflightPassed => "tool:preflight:passed:",
            Self::PreflightFailed => "tool:preflight:failed:",
            Self::Launched => "tool:launched:",
            Self::Started => "tool:started:",
            Self::Restarted => "tool:restarted:",
            Self::Stopped => "tool:stopped:",
            Self::Failed => "tool:failed:",
            Self::LaunchFailed => "tool:launch_failed:",
            Self::HealthUp => "tool:health:up:",
            Self::HealthDown => "tool:health:down:",
        }
    }
}

/// A tool lifecycle event with the tool name and stage already
/// extracted. The raw entry is retained so callers that need timestamps,
/// actor, or policy decision can still reach them.
#[derive(Debug, Clone)]
pub struct ToolLifecycleEvent {
    pub tool_name: String,
    pub kind: ToolLifecycleKind,
    pub entry: AuditEntry,
}

/// Query the chain for tool-lifecycle events of one specific kind.
///
/// Returns entries in the order the underlying store returned them
/// (same as `ChainReader::search_by_keyword`). Each entry's tool_name
/// is extracted from the receipt string; entries whose action isn't a
/// `SystemEvent` or whose event doesn't strip cleanly are silently
/// skipped — this preserves the current officer behavior of ignoring
/// unparseable entries.
///
/// For `PortAssigned`, extracts the tool name from
/// `tool:port:assigned:<name>:<port>` — the segment before the first
/// colon after the prefix.
pub fn tool_lifecycle_events(
    chain: &ChainReader<'_>,
    kind: ToolLifecycleKind,
    limit: usize,
) -> Result<Vec<ToolLifecycleEvent>, ChainReadError> {
    let prefix = kind.receipt_prefix();
    let raw = chain.search_by_keyword(prefix, limit)?;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let Some(rest) = event.strip_prefix(prefix) else {
            continue;
        };
        // PortAssigned encodes as tool:port:assigned:<name>:<port>;
        // extract the segment before the first colon after the prefix.
        // All other kinds have the tool name as the entire suffix.
        let tool_name = match kind {
            ToolLifecycleKind::PortAssigned => match rest.split(':').next() {
                Some(name) if !name.is_empty() => name.to_string(),
                _ => continue,
            },
            _ => {
                if rest.is_empty() {
                    continue;
                }
                rest.to_string()
            }
        };
        out.push(ToolLifecycleEvent {
            tool_name,
            kind,
            entry,
        });
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════
// Delegation
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationKind {
    Granted,
    Renewed,
    Revoked,
    Expired,
}

impl DelegationKind {
    fn receipt_prefix(self) -> &'static str {
        match self {
            Self::Granted => "delegation:granted:",
            Self::Renewed => "delegation:renewed:",
            Self::Revoked => "delegation:revoked:",
            Self::Expired => "delegation:expired:",
        }
    }
}

/// A delegation-lifecycle event with the target extracted from the
/// receipt string.
///
/// The target may be a tool name, an officer name (`officer:<name>`),
/// or a raw grant hash (64 hex chars). Callers filter as they need —
/// governance-posture, for instance, keeps only tool-shaped targets.
/// `is_tool_target()` / `is_officer_target()` / `is_hash_target()`
/// helpers below classify without further string surgery.
#[derive(Debug, Clone)]
pub struct DelegationEvent {
    pub target: String,
    pub kind: DelegationKind,
    pub entry: AuditEntry,
}

impl DelegationEvent {
    /// True if the target looks like a tool name (not officer-prefixed
    /// and not a 64-char hex hash). Matches the historical filter in
    /// `governance_posture::scan_chain_evidence`.
    pub fn is_tool_target(&self) -> bool {
        is_delegation_target_tool_shaped(&self.target)
    }

    /// True if the target is officer-shaped (`officer:<name>` prefix).
    pub fn is_officer_target(&self) -> bool {
        is_delegation_target_officer_shaped(&self.target)
    }

    /// True if the target is a raw 64-char hex hash.
    pub fn is_hash_target(&self) -> bool {
        is_delegation_target_hash_shaped(&self.target)
    }
}

/// Free-function classifier: tool-shaped delegation target.
/// Available separately so callers that already have a string (no full
/// `DelegationEvent`) can classify without constructing one, and so
/// tests can exercise the classifier without needing a real chain
/// entry.
pub fn is_delegation_target_tool_shaped(target: &str) -> bool {
    !target.is_empty()
        && !target.starts_with("officer:")
        && !is_delegation_target_hash_shaped(target)
}

/// Free-function classifier: officer-shaped delegation target.
pub fn is_delegation_target_officer_shaped(target: &str) -> bool {
    target.starts_with("officer:")
}

/// Free-function classifier: raw 64-char hex hash.
pub fn is_delegation_target_hash_shaped(target: &str) -> bool {
    target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit())
}

/// Query the chain for delegation events of one specific kind.
pub fn delegation_events(
    chain: &ChainReader<'_>,
    kind: DelegationKind,
    limit: usize,
) -> Result<Vec<DelegationEvent>, ChainReadError> {
    let prefix = kind.receipt_prefix();
    let raw = chain.search_by_keyword(prefix, limit)?;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let Some(target) = event.strip_prefix(prefix) else {
            continue;
        };
        out.push(DelegationEvent {
            target: target.to_string(),
            kind,
            entry,
        });
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════
// Officer attestation
// ═══════════════════════════════════════════════════════════════════════

/// An `officer:<name>:attested:<tool>` event with both parts extracted.
#[derive(Debug, Clone)]
pub struct OfficerAttestation {
    pub officer_name: String,
    pub tool_name: String,
    pub entry: AuditEntry,
}

/// Query the chain for officer attestations.
///
/// Searches by the `:attested:` substring (per the pre-refactor
/// behavior) and parses matches whose event begins with `officer:` and
/// contains `:attested:` — extracting `officer_name` and `tool_name`
/// from either side of the separator. Entries not matching this exact
/// shape are silently skipped.
pub fn officer_attestations(
    chain: &ChainReader<'_>,
    limit: usize,
) -> Result<Vec<OfficerAttestation>, ChainReadError> {
    // "attested:" is the substring the pre-refactor code searched;
    // matches are then filtered to those starting with "officer:".
    let raw = chain.search_by_keyword("attested:", limit)?;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let Some(rest) = event.strip_prefix("officer:") else {
            continue;
        };
        let Some(pos) = rest.find(":attested:") else {
            continue;
        };
        let officer_name = &rest[..pos];
        let tool_name = &rest[pos + ":attested:".len()..];
        if tool_name.is_empty() {
            continue;
        }
        out.push(OfficerAttestation {
            officer_name: officer_name.to_string(),
            tool_name: tool_name.to_string(),
            entry,
        });
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════
// Officer operations (findings with tool references in policy conditions)
// ═══════════════════════════════════════════════════════════════════════

/// An `officer:*:operations:*` event carrying a `tool=<name>` policy
/// condition, indicating an officer flagged concerns about that tool.
///
/// Historical use in `governance_posture::scan_chain_evidence`: any
/// such event contributes to the tool's `has_officer_warnings` facet.
/// Recency filtering is the caller's responsibility (the pre-refactor
/// code took the most recent 2000 and let ordering shape recency).
#[derive(Debug, Clone)]
pub struct OfficerOperationsWithTool {
    pub tool_name: String,
    pub entry: AuditEntry,
}

/// Query the chain for `officer:*:operations:*` events whose policy
/// decision carries a `tool=<name>` condition. Extracts one event per
/// matching condition.
pub fn officer_operations_with_tool(
    chain: &ChainReader<'_>,
    limit: usize,
) -> Result<Vec<OfficerOperationsWithTool>, ChainReadError> {
    let raw = chain.search_by_keyword(":operations:", limit)?;
    let mut out = Vec::new();
    for entry in raw {
        let AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        if !event.starts_with("officer:") {
            continue;
        }
        let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
            continue;
        };
        for condition in conditions {
            if let Some(tool_ref) = condition.strip_prefix("tool=") {
                out.push(OfficerOperationsWithTool {
                    tool_name: tool_ref.to_string(),
                    entry: entry.clone(),
                });
            }
        }
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════
// Gate outcomes (used by Sentinel today; declared here for
// future call sites)
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    Allowed,
    Denied,
}

impl GateOutcome {
    fn receipt_prefix(self) -> &'static str {
        match self {
            Self::Allowed => "gate:allowed:",
            Self::Denied => "gate:denied:",
        }
    }
}

/// A gate decision event with the subject (typically a tool name)
/// extracted from the receipt suffix.
#[derive(Debug, Clone)]
pub struct GateEvent {
    pub subject: String,
    pub outcome: GateOutcome,
    pub entry: AuditEntry,
}

/// Query the chain for gate decisions of one specific outcome kind.
pub fn gate_events(
    chain: &ChainReader<'_>,
    outcome: GateOutcome,
    limit: usize,
) -> Result<Vec<GateEvent>, ChainReadError> {
    let prefix = outcome.receipt_prefix();
    let raw = chain.search_by_keyword(prefix, limit)?;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let Some(subject) = event.strip_prefix(prefix) else {
            continue;
        };
        if subject.is_empty() {
            continue;
        }
        out.push(GateEvent {
            subject: subject.to_string(),
            outcome,
            entry,
        });
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════
// System lifecycle (bare event names, not prefixes)
// ═══════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemLifecycleKind {
    ServerStarted,
    ServerStopped,
    SystemStartup,
    SystemShutdown,
}

impl SystemLifecycleKind {
    fn event_name(self) -> &'static str {
        match self {
            Self::ServerStarted => "server:started",
            Self::ServerStopped => "server:stopped",
            Self::SystemStartup => "system:startup",
            Self::SystemShutdown => "system:shutdown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SystemLifecycleEvent {
    pub kind: SystemLifecycleKind,
    pub entry: AuditEntry,
}

/// Query the chain for system-lifecycle events of one specific kind.
/// These are bare event names (no colon suffix), so an exact match on
/// the event string filters after the substring search.
pub fn system_lifecycle_events(
    chain: &ChainReader<'_>,
    kind: SystemLifecycleKind,
    limit: usize,
) -> Result<Vec<SystemLifecycleEvent>, ChainReadError> {
    let name = kind.event_name();
    let raw = chain.search_by_keyword(name, limit)?;
    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        if event != name {
            continue;
        }
        out.push(SystemLifecycleEvent { kind, entry });
    }
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use zp_audit::store::AuditStore;
    use zp_audit::UnsealedEntry;
    use zp_core::{ActorId, ConversationId, PolicyDecision};

    fn appending_store() -> AuditStore {
        // open_maintenance is the test/non-signed write-capable path;
        // open_signed requires an AuditSigner, open_readonly errors on
        // append. Per crates/zp-audit/src/store.rs.
        AuditStore::open_maintenance(":memory:").expect("open store")
    }

    fn append_event(store: &mut AuditStore, event: &str) {
        let entry = UnsealedEntry {
            actor: ActorId::System("test".to_string()),
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: ConversationId::new(),
            policy_decision: PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            policy_module: "test".to_string(),
            receipt: None,
        };
        store.append(entry).expect("append");
    }

    fn append_event_with_conditions(
        store: &mut AuditStore,
        event: &str,
        conditions: Vec<String>,
    ) {
        let entry = UnsealedEntry {
            actor: ActorId::System("test".to_string()),
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: ConversationId::new(),
            policy_decision: PolicyDecision::Allow { conditions },
            policy_module: "test".to_string(),
            receipt: None,
        };
        store.append(entry).expect("append");
    }

    #[test]
    fn tool_lifecycle_configured_extracts_tool_name() {
        let mut store = appending_store();
        append_event(&mut store, "tool:configured:alpha");
        append_event(&mut store, "tool:configured:beta");
        append_event(&mut store, "unrelated:event");

        let chain = ChainReader::new(&store);
        let events =
            tool_lifecycle_events(&chain, ToolLifecycleKind::Configured, 100).unwrap();
        let names: Vec<_> = events.iter().map(|e| e.tool_name.clone()).collect();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn tool_lifecycle_port_assigned_extracts_only_tool_name() {
        // Verifies the port suffix is stripped from
        // `tool:port:assigned:<name>:<port>`. Order-agnostic because
        // `ChainReader::search_by_keyword` returns newest-first and
        // this helper doesn't reorder.
        let mut store = appending_store();
        append_event(&mut store, "tool:port:assigned:alpha:8080");
        append_event(&mut store, "tool:port:assigned:beta:9090");

        let chain = ChainReader::new(&store);
        let events =
            tool_lifecycle_events(&chain, ToolLifecycleKind::PortAssigned, 100).unwrap();
        let names: Vec<_> = events.iter().map(|e| e.tool_name.clone()).collect();
        assert!(names.contains(&"alpha".to_string()));
        assert!(names.contains(&"beta".to_string()));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn tool_lifecycle_launched_and_started_are_separate_kinds() {
        // Fidelity check: the helper does NOT merge launched and
        // started. Callers that want both must issue two queries.
        let mut store = appending_store();
        append_event(&mut store, "tool:launched:alpha");
        append_event(&mut store, "tool:started:beta");

        let chain = ChainReader::new(&store);
        let launched =
            tool_lifecycle_events(&chain, ToolLifecycleKind::Launched, 100).unwrap();
        let started =
            tool_lifecycle_events(&chain, ToolLifecycleKind::Started, 100).unwrap();
        assert_eq!(launched.len(), 1);
        assert_eq!(launched[0].tool_name, "alpha");
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].tool_name, "beta");
    }

    #[test]
    fn tool_lifecycle_empty_suffix_is_skipped() {
        let mut store = appending_store();
        append_event(&mut store, "tool:configured:");
        append_event(&mut store, "tool:configured:real");

        let chain = ChainReader::new(&store);
        let events =
            tool_lifecycle_events(&chain, ToolLifecycleKind::Configured, 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].tool_name, "real");
    }

    #[test]
    fn delegation_events_extract_target() {
        let mut store = appending_store();
        append_event(&mut store, "delegation:granted:mytool");
        append_event(&mut store, "delegation:granted:othertool");

        let chain = ChainReader::new(&store);
        let events = delegation_events(&chain, DelegationKind::Granted, 100).unwrap();
        let targets: Vec<_> = events.iter().map(|e| e.target.clone()).collect();
        assert!(targets.contains(&"mytool".to_string()));
        assert!(targets.contains(&"othertool".to_string()));
    }

    #[test]
    fn delegation_target_classifier_distinguishes_tool_officer_hash() {
        // Test the free-function classifiers directly; no need to
        // construct DelegationEvent (which would require a full
        // AuditEntry with hash-linkage fields).
        assert!(is_delegation_target_tool_shaped("mytool"));
        assert!(!is_delegation_target_officer_shaped("mytool"));
        assert!(!is_delegation_target_hash_shaped("mytool"));

        assert!(!is_delegation_target_tool_shaped("officer:cleo"));
        assert!(is_delegation_target_officer_shaped("officer:cleo"));

        let hash = "a".repeat(64);
        assert!(!is_delegation_target_tool_shaped(&hash));
        assert!(is_delegation_target_hash_shaped(&hash));

        // Empty target is not tool-shaped.
        assert!(!is_delegation_target_tool_shaped(""));
    }

    #[test]
    fn delegation_events_filter_composes_with_classifier() {
        // End-to-end: query the chain, then filter by classifier.
        // This is the pattern governance_posture.rs uses after refactor.
        let mut store = appending_store();
        append_event(&mut store, "delegation:granted:mytool");
        append_event(&mut store, "delegation:granted:officer:cleo");
        append_event(&mut store, &format!("delegation:granted:{}", "a".repeat(64)));

        let chain = ChainReader::new(&store);
        let all = delegation_events(&chain, DelegationKind::Granted, 100).unwrap();
        assert_eq!(all.len(), 3);
        let tool_only: Vec<_> = all
            .iter()
            .filter(|d| d.is_tool_target())
            .map(|d| d.target.clone())
            .collect();
        assert_eq!(tool_only, vec!["mytool"]);
    }

    #[test]
    fn officer_attestations_extract_officer_and_tool() {
        let mut store = appending_store();
        append_event(&mut store, "officer:steward:attested:mytool");
        append_event(&mut store, "officer:sentinel:attested:othertool");
        append_event(&mut store, "officer:cleo:attested:"); // empty tool: skipped
        append_event(&mut store, "notofficer:attested:x"); // wrong prefix: skipped

        let chain = ChainReader::new(&store);
        let attestations = officer_attestations(&chain, 100).unwrap();
        assert_eq!(attestations.len(), 2);
        let pairs: Vec<_> = attestations
            .iter()
            .map(|a| (a.officer_name.clone(), a.tool_name.clone()))
            .collect();
        assert!(pairs.contains(&("steward".to_string(), "mytool".to_string())));
        assert!(pairs.contains(&("sentinel".to_string(), "othertool".to_string())));
    }

    #[test]
    fn officer_operations_with_tool_extracts_from_conditions() {
        let mut store = appending_store();
        append_event_with_conditions(
            &mut store,
            "officer:sentinel:operations:sweep",
            vec!["tool=mytool".to_string(), "unrelated=x".to_string()],
        );
        append_event_with_conditions(
            &mut store,
            "officer:cleo:operations:report",
            vec!["tool=othertool".to_string()],
        );
        append_event_with_conditions(
            &mut store,
            "notofficer:operations:x",
            vec!["tool=skipped".to_string()],
        );

        let chain = ChainReader::new(&store);
        let ops = officer_operations_with_tool(&chain, 100).unwrap();
        let tools: Vec<_> = ops.iter().map(|o| o.tool_name.clone()).collect();
        assert!(tools.contains(&"mytool".to_string()));
        assert!(tools.contains(&"othertool".to_string()));
        assert!(!tools.contains(&"skipped".to_string()));
    }

    #[test]
    fn gate_events_extract_subject() {
        let mut store = appending_store();
        append_event(&mut store, "gate:allowed:mytool");
        append_event(&mut store, "gate:denied:badtool");

        let chain = ChainReader::new(&store);
        let allowed = gate_events(&chain, GateOutcome::Allowed, 100).unwrap();
        let denied = gate_events(&chain, GateOutcome::Denied, 100).unwrap();
        assert_eq!(allowed.len(), 1);
        assert_eq!(allowed[0].subject, "mytool");
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].subject, "badtool");
    }

    #[test]
    fn system_lifecycle_exact_match_only() {
        // `server:started` is a bare event name, not a prefix. Events
        // beginning with `server:started:something` must not match.
        let mut store = appending_store();
        append_event(&mut store, "server:started");
        append_event(&mut store, "server:started:extra");
        append_event(&mut store, "server:stopped");

        let chain = ChainReader::new(&store);
        let started =
            system_lifecycle_events(&chain, SystemLifecycleKind::ServerStarted, 100)
                .unwrap();
        assert_eq!(started.len(), 1);
        let stopped =
            system_lifecycle_events(&chain, SystemLifecycleKind::ServerStopped, 100)
                .unwrap();
        assert_eq!(stopped.len(), 1);
    }

    #[test]
    fn officer_read_prefixes_list_is_stable() {
        // Guardrail: if the list changes size, whoever adds/removes an
        // entry should update Cartographer's projection (or the S3
        // migration ceremony) accordingly. This test locks the count
        // to catch drift; update the number when the intentional
        // change lands.
        assert_eq!(OFFICER_READ_PREFIXES.len(), 23);
    }
}
