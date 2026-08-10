//! Chain narration primitives — deterministic, template-driven storytelling.
//!
//! The chain is the source of truth; narration is a derived, ephemeral
//! projection of chain state into human-readable text. Same chain →
//! same story, always. No LLM.
//!
//! Two tiers consume these primitives:
//! - **Substrate** (`zp chain story`): renders `ChainStory::render_text()`.
//! - **Cockpit** (Regent, future agents): reads `ChainStory` as JSON, adds
//!   interpretation, wraps in visualization.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::chain_reads::{
    classify_delegation, classify_gate, is_officer_event, is_system_shutdown_event,
    is_system_startup_event, DelegationKind, GateOutcome,
};
use crate::officer::ChainReader;
use zp_core::{AuditAction, AuditEntry, AuditId, PolicyDecision};

// ── StorySegment ─────────────────────────────────────────────────────────────

/// Structural classification for story segments.
///
/// Determines how cockpits render the segment and how CLI filters work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    // Governance (Cleo's domain)
    DelegationGranted,
    DelegationRevoked,
    DelegationExpired,
    DelegationRenewed,
    GateAllowed,
    GateDenied,
    AuthorityChainTrace,
    PolicyViolation,

    // Integrity (Steward's domain)
    IntegrityVerified,
    ChainSilence,
    ChainBurst,
    SignatureCoverage,

    // System events
    SystemStartup,
    SystemShutdown,
    OfficerHeartbeat,
    PostureChange,

    // Tool lifecycle
    ToolInvoked,
    ToolCompleted,
    ToolFailed,

    // Cognition
    MessageReceived,
    ResponseGenerated,
    ApiProxied,

    // Officer findings (domain-aware)
    OfficerFindingGovernance,
    OfficerFindingIntegrity,
    OfficerFindingOperations,

    // Fallback
    GenericEvent,
}

impl SegmentKind {
    /// The posture domain this segment kind relates to.
    pub fn domain(&self) -> &'static str {
        match self {
            Self::DelegationGranted
            | Self::DelegationRevoked
            | Self::DelegationExpired
            | Self::DelegationRenewed
            | Self::GateAllowed
            | Self::GateDenied
            | Self::AuthorityChainTrace
            | Self::PolicyViolation => "governance",

            Self::IntegrityVerified
            | Self::ChainSilence
            | Self::ChainBurst
            | Self::SignatureCoverage => "integrity",

            Self::ToolInvoked | Self::ToolCompleted | Self::ToolFailed
            | Self::OfficerFindingOperations => "operations",

            Self::OfficerFindingGovernance => "governance",
            Self::OfficerFindingIntegrity => "integrity",

            _ => "system",
        }
    }
}

/// A single narrated element of a chain story.
///
/// Grounds one or more chain entries into a human-readable sentence
/// with structural classification for filtering and rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorySegment {
    /// Chain entry IDs this segment narrates.
    pub entry_ids: Vec<AuditId>,
    /// Human-readable narrative sentence.
    pub text: String,
    /// Structural classification.
    pub kind: SegmentKind,
    /// Time span covered by the referenced entries.
    pub span: (DateTime<Utc>, DateTime<Utc>),
    /// Which officer produced this segment (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_officer: Option<String>,
}

// ── ChainStory ───────────────────────────────────────────────────────────────

/// A complete narration over a range of chain entries.
///
/// Deterministic: same entries in → same story out. The narration engine
/// matches `AuditAction` variants to templates and extracts fields from
/// `PolicyDecision` conditions and `SystemEvent` event strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStory {
    /// Ordered segments (chronological).
    pub segments: Vec<StorySegment>,
    /// Total chain entries in range.
    pub entry_count: usize,
    /// Time range covered.
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
}

impl ChainStory {
    /// Generate a deterministic story from chain entries.
    ///
    /// Each `AuditAction` variant maps to a narration template.
    /// Entries are processed in chronological order.
    pub fn from_entries(entries: &[AuditEntry]) -> Self {
        let segments: Vec<StorySegment> = entries
            .iter()
            .filter_map(|entry| narrate_entry(entry))
            .collect();

        let time_range = if let (Some(first), Some(last)) = (entries.first(), entries.last()) {
            Some((first.timestamp, last.timestamp))
        } else {
            None
        };

        Self {
            segments,
            entry_count: entries.len(),
            time_range,
        }
    }

    /// Filter to segments matching the given domain.
    pub fn filter_domain(&self, domain: &str) -> Self {
        let segments: Vec<StorySegment> = self
            .segments
            .iter()
            .filter(|s| s.kind.domain() == domain)
            .cloned()
            .collect();
        Self {
            segments,
            entry_count: self.entry_count,
            time_range: self.time_range,
        }
    }

    /// Filter to specific segment kinds.
    pub fn filter_kinds(&self, kinds: &[SegmentKind]) -> Self {
        let segments: Vec<StorySegment> = self
            .segments
            .iter()
            .filter(|s| kinds.contains(&s.kind))
            .cloned()
            .collect();
        Self {
            segments,
            entry_count: self.entry_count,
            time_range: self.time_range,
        }
    }

    /// Compressed summary: group related segments into arcs.
    ///
    /// Collapses repeated same-kind segments into counts.
    /// "IronClaw was delegated chain_render access and used it 3 times."
    pub fn summarize(&self) -> Vec<StorySegment> {
        if self.segments.is_empty() {
            return Vec::new();
        }

        let mut summary: Vec<StorySegment> = Vec::new();
        let mut i = 0;

        while i < self.segments.len() {
            let current = &self.segments[i];

            // Count consecutive segments of the same kind
            let mut run_end = i + 1;
            while run_end < self.segments.len()
                && self.segments[run_end].kind == current.kind
            {
                run_end += 1;
            }

            let run_len = run_end - i;
            if run_len > 1 {
                // Collapse the run
                let last = &self.segments[run_end - 1];
                let mut all_ids: Vec<AuditId> = Vec::new();
                for seg in &self.segments[i..run_end] {
                    all_ids.extend(seg.entry_ids.clone());
                }
                summary.push(StorySegment {
                    entry_ids: all_ids,
                    text: format!("{} (×{})", summarize_kind(current.kind), run_len),
                    kind: current.kind,
                    span: (current.span.0, last.span.1),
                    source_officer: current.source_officer.clone(),
                });
            } else {
                summary.push(current.clone());
            }

            i = run_end;
        }

        summary
    }

    /// Render as plain text for CLI output.
    pub fn render_text(&self) -> String {
        let mut out = String::new();

        if let Some((start, end)) = self.time_range {
            out.push_str(&format!(
                "  Chain Story — {} entries, {} → {}\n\n",
                self.entry_count,
                start.format("%Y-%m-%d %H:%M"),
                end.format("%H:%M"),
            ));
        } else {
            out.push_str("  Chain Story — empty chain\n\n");
            return out;
        }

        for segment in &self.segments {
            let time = segment.span.0.format("%H:%M");
            out.push_str(&format!("  {}  {}\n", time, segment.text));
        }

        out
    }
}

// ── Narration engine ─────────────────────────────────────────────────────────

/// Narrate a single chain entry into a story segment.
///
/// Returns `None` for entries that don't produce meaningful narrative
/// (e.g., internal bookkeeping).
fn narrate_entry(entry: &AuditEntry) -> Option<StorySegment> {
    let ts = entry.timestamp;
    let id = entry.id.clone();

    match &entry.action {
        AuditAction::SystemEvent { event } => narrate_system_event(event, entry),

        AuditAction::ToolInvoked {
            tool_name,
            arguments_hash,
        } => Some(StorySegment {
            entry_ids: vec![id],
            text: format!(
                "Tool invoked: **{}** (args {}…)",
                tool_name,
                &arguments_hash[..8.min(arguments_hash.len())]
            ),
            kind: SegmentKind::ToolInvoked,
            span: (ts, ts),
            source_officer: None,
        }),

        AuditAction::ToolCompleted {
            tool_name, success, ..
        } => {
            let (kind, status) = if *success {
                (SegmentKind::ToolCompleted, "completed successfully")
            } else {
                (SegmentKind::ToolFailed, "failed")
            };
            Some(StorySegment {
                entry_ids: vec![id],
                text: format!("Tool **{}** {}.", tool_name, status),
                kind,
                span: (ts, ts),
                source_officer: None,
            })
        }

        AuditAction::MessageReceived { .. } => Some(StorySegment {
            entry_ids: vec![id],
            text: "Message received.".into(),
            kind: SegmentKind::MessageReceived,
            span: (ts, ts),
            source_officer: None,
        }),

        AuditAction::ResponseGenerated { model, .. } => Some(StorySegment {
            entry_ids: vec![id],
            text: format!("Response generated (model: {}).", model),
            kind: SegmentKind::ResponseGenerated,
            span: (ts, ts),
            source_officer: None,
        }),

        AuditAction::ApiCallProxied {
            provider,
            endpoint,
            tokens_input,
            tokens_output,
            cost_usd,
        } => Some(StorySegment {
            entry_ids: vec![id],
            text: format!(
                "API call proxied: {}:{} ({} in / {} out, ${:.4}).",
                provider, endpoint, tokens_input, tokens_output, cost_usd
            ),
            kind: SegmentKind::ApiProxied,
            span: (ts, ts),
            source_officer: None,
        }),

        // These action types don't produce top-level story segments.
        // They may be referenced by officer findings that narrate them.
        AuditAction::CredentialInjected { .. }
        | AuditAction::PolicyInteraction { .. }
        | AuditAction::OutputSanitized { .. }
        | AuditAction::SkillActivated { .. }
        | AuditAction::SkillProposed { .. }
        | AuditAction::SkillApproved { .. } => None,
    }
}

/// Narrate a `SystemEvent` by parsing the event string.
///
/// Event strings follow ZP conventions:
/// - `delegation:granted:{subject}` / `delegation:revoked:{subject}`
/// - `gate:allowed:{tool}` / `gate:denied:{tool}`
/// - `officer:{name}:heartbeat` / `officer:{name}:{domain}:{finding_type}`
/// - `posture:computed`
/// - `system:startup` / `system:shutdown`
fn narrate_system_event(event: &str, entry: &AuditEntry) -> Option<StorySegment> {
    let ts = entry.timestamp;
    let id = entry.id.clone();
    let conditions = extract_conditions(&entry.policy_decision);

    // Delegation events — one classifier call, four-way match on kind.
    if let Some(ev) = classify_delegation(entry) {
        let subject = ev.target;
        let (text, kind) = match ev.kind {
            DelegationKind::Granted => {
                let capabilities = conditions
                    .get("capabilities")
                    .cloned()
                    .unwrap_or_default();
                let expiry = conditions.get("expires").cloned().unwrap_or_default();
                let text = if !capabilities.is_empty() && !expiry.is_empty() {
                    format!(
                        "Delegation granted to **{}** for {}, valid until {}.",
                        subject, capabilities, expiry
                    )
                } else if !capabilities.is_empty() {
                    format!(
                        "Delegation granted to **{}** for {}.",
                        subject, capabilities
                    )
                } else {
                    format!("Delegation granted to **{}**.", subject)
                };
                (text, SegmentKind::DelegationGranted)
            }
            DelegationKind::Revoked => {
                let actor = format!("{:?}", entry.actor);
                (
                    format!("Delegation to **{}** revoked by {}.", subject, actor),
                    SegmentKind::DelegationRevoked,
                )
            }
            DelegationKind::Expired => (
                format!("Delegation to **{}** expired without renewal.", subject),
                SegmentKind::DelegationExpired,
            ),
            DelegationKind::Renewed => {
                let renews = conditions.get("renews").cloned().unwrap_or_default();
                let text = if !renews.is_empty() {
                    format!(
                        "Delegation to **{}** renewed (prior: {}…).",
                        subject,
                        &renews[..12.min(renews.len())]
                    )
                } else {
                    format!("Delegation to **{}** renewed.", subject)
                };
                (text, SegmentKind::DelegationRenewed)
            }
        };
        return Some(StorySegment {
            entry_ids: vec![id],
            text,
            kind,
            span: (ts, ts),
            source_officer: None,
        });
    }

    // Gate decisions
    if let Some(ev) = classify_gate(entry) {
        let tool = ev.subject;
        let (text, kind) = match ev.outcome {
            GateOutcome::Allowed => {
                let grant_id = conditions.get("grant_id").cloned().unwrap_or_default();
                let text = if !grant_id.is_empty() {
                    format!(
                        "Gate allowed **{}**, citing delegation {}….",
                        tool,
                        &grant_id[..12.min(grant_id.len())]
                    )
                } else {
                    format!("Gate allowed **{}**.", tool)
                };
                (text, SegmentKind::GateAllowed)
            }
            GateOutcome::Denied => {
                let reason = match &entry.policy_decision {
                    PolicyDecision::Block { reason, .. } => reason.clone(),
                    _ => conditions
                        .get("reason")
                        .cloned()
                        .unwrap_or_else(|| "no reason given".into()),
                };
                (
                    format!("Gate denied **{}**: {}.", tool, reason),
                    SegmentKind::GateDenied,
                )
            }
        };
        return Some(StorySegment {
            entry_ids: vec![id],
            text,
            kind,
            span: (ts, ts),
            source_officer: None,
        });
    }

    // Officer heartbeats
    if event.contains(":heartbeat") {
        let parts: Vec<&str> = event.split(':').collect();
        let officer_name = parts.get(1).unwrap_or(&"?");
        let finding_count = conditions
            .get("finding_count")
            .cloned()
            .unwrap_or_else(|| "?".into());
        let max_sev = conditions
            .get("max_severity")
            .cloned()
            .unwrap_or_else(|| "Ok".into());
        return Some(StorySegment {
            entry_ids: vec![id],
            text: format!(
                "Officer **{}** swept: {} findings, max severity {}.",
                officer_name, finding_count, max_sev
            ),
            kind: SegmentKind::OfficerHeartbeat,
            span: (ts, ts),
            source_officer: Some(officer_name.to_string()),
        });
    }

    // Officer findings (officer:{name}:{domain}:{type})
    // Broad-match via chain_reads helper. The `officer:*` shape is a
    // multi-segment identifier; parsing into (name, domain, finding_type)
    // is narration-specific and stays here rather than in the classifier.
    if is_officer_event(entry) {
        let parts: Vec<&str> = event.split(':').collect();
        if parts.len() >= 4 {
            let officer_name = parts[1];
            let domain = parts[2];
            let finding_type = parts[3..].join(":");
            let summary = match &entry.policy_decision {
                PolicyDecision::Allow { conditions } => {
                    conditions.first().cloned().unwrap_or_default()
                }
                _ => String::new(),
            };
            let text = if !summary.is_empty() {
                format!(
                    "Officer **{}** ({}/{}): {}",
                    officer_name, domain, finding_type, summary
                )
            } else {
                format!(
                    "Officer **{}** finding: {}/{}.",
                    officer_name, domain, finding_type
                )
            };
            // Derive segment kind from the finding's domain so
            // `--domain governance` catches governance findings.
            let kind = match domain {
                "governance" => SegmentKind::OfficerFindingGovernance,
                "integrity" => SegmentKind::OfficerFindingIntegrity,
                "operations" => SegmentKind::OfficerFindingOperations,
                _ => SegmentKind::GenericEvent,
            };
            return Some(StorySegment {
                entry_ids: vec![id],
                text,
                kind,
                span: (ts, ts),
                source_officer: Some(officer_name.to_string()),
            });
        }
    }

    // Posture
    if event == "posture:computed" {
        let composite = conditions.get("composite").cloned().unwrap_or_default();
        let trend = conditions.get("trend").cloned().unwrap_or_default();
        let integrity = conditions.get("integrity").cloned().unwrap_or_default();
        let security = conditions.get("security").cloned().unwrap_or_default();
        let operations = conditions.get("operations").cloned().unwrap_or_default();
        let governance = conditions.get("governance").cloned().unwrap_or_default();

        let mut domain_parts = Vec::new();
        if !integrity.is_empty() {
            domain_parts.push(format!("integrity {}", integrity));
        }
        if !security.is_empty() {
            domain_parts.push(format!("security {}", security));
        }
        if !operations.is_empty() {
            domain_parts.push(format!("operations {}", operations));
        }
        if !governance.is_empty() {
            domain_parts.push(format!("governance {}", governance));
        }

        let text = format!(
            "System posture: {} ({}). {}.",
            composite,
            trend,
            domain_parts.join(", ")
        );
        return Some(StorySegment {
            entry_ids: vec![id],
            text,
            kind: SegmentKind::PostureChange,
            span: (ts, ts),
            source_officer: None,
        });
    }

    // Sweep all-clear
    if event == "system:sweep:officers:all_clear" {
        let posture = conditions.get("posture").cloned().unwrap_or_default();
        return Some(StorySegment {
            entry_ids: vec![id],
            text: format!("Officers all clear (posture {}).", posture),
            kind: SegmentKind::OfficerHeartbeat,
            span: (ts, ts),
            source_officer: None,
        });
    }

    // System lifecycle — broad matchers preserve pre-refactor behavior
    // (they include longer variants like `system:startup:extra_context`).
    if is_system_startup_event(entry) {
        return Some(StorySegment {
            entry_ids: vec![id],
            text: format!("System started ({}).", event),
            kind: SegmentKind::SystemStartup,
            span: (ts, ts),
            source_officer: None,
        });
    }

    if is_system_shutdown_event(entry) {
        return Some(StorySegment {
            entry_ids: vec![id],
            text: format!("System stopped ({}).", event),
            kind: SegmentKind::SystemShutdown,
            span: (ts, ts),
            source_officer: None,
        });
    }

    // Generic system event — narrate but don't classify
    Some(StorySegment {
        entry_ids: vec![id],
        text: format!("{}.", event),
        kind: SegmentKind::GenericEvent,
        span: (ts, ts),
        source_officer: None,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Extract key=value conditions from a PolicyDecision.
fn extract_conditions(decision: &PolicyDecision) -> std::collections::HashMap<String, String> {
    let conditions = match decision {
        PolicyDecision::Allow { conditions } => conditions,
        _ => return std::collections::HashMap::new(),
    };

    let mut map = std::collections::HashMap::new();
    for cond in conditions {
        if let Some((key, value)) = cond.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

/// Human-readable label for a segment kind (used in summaries).
fn summarize_kind(kind: SegmentKind) -> &'static str {
    match kind {
        SegmentKind::DelegationGranted => "Delegation granted",
        SegmentKind::DelegationRevoked => "Delegation revoked",
        SegmentKind::DelegationExpired => "Delegation expired",
        SegmentKind::DelegationRenewed => "Delegation renewed",
        SegmentKind::GateAllowed => "Gate allowed",
        SegmentKind::GateDenied => "Gate denied",
        SegmentKind::AuthorityChainTrace => "Authority chain trace",
        SegmentKind::PolicyViolation => "Policy violation",
        SegmentKind::IntegrityVerified => "Integrity verified",
        SegmentKind::ChainSilence => "Chain silence",
        SegmentKind::ChainBurst => "Chain burst",
        SegmentKind::SignatureCoverage => "Signature coverage",
        SegmentKind::SystemStartup => "System started",
        SegmentKind::SystemShutdown => "System stopped",
        SegmentKind::OfficerHeartbeat => "Officer heartbeat",
        SegmentKind::PostureChange => "Posture update",
        SegmentKind::ToolInvoked => "Tool invoked",
        SegmentKind::ToolCompleted => "Tool completed",
        SegmentKind::ToolFailed => "Tool failed",
        SegmentKind::MessageReceived => "Message received",
        SegmentKind::ResponseGenerated => "Response generated",
        SegmentKind::ApiProxied => "API call proxied",
        SegmentKind::OfficerFindingGovernance => "Officer finding (governance)",
        SegmentKind::OfficerFindingIntegrity => "Officer finding (integrity)",
        SegmentKind::OfficerFindingOperations => "Officer finding (operations)",
        SegmentKind::GenericEvent => "Event",
    }
}

// ── ChainNarrator trait ──────────────────────────────────────────────────────

/// Officers that can narrate chain state.
///
/// Not all officers narrate. Steward reports structural health via findings.
/// Cleo reports governance findings AND produces human-readable narration
/// of authority flow. The trait is separate from `Officer` because narration
/// is a distinct concern from sweep-based observation.
pub trait ChainNarrator: crate::officer::Officer {
    /// Generate story segments from chain entries.
    ///
    /// Deterministic, template-driven. No LLM.
    fn narrate(&self, chain: &ChainReader<'_>) -> Vec<StorySegment>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::{ActorId, ConversationId};

    fn make_system_event(event: &str, conditions: Vec<String>) -> AuditEntry {
        AuditEntry {
            id: AuditId::new(),
            timestamp: Utc::now(),
            prev_hash: "0".repeat(64),
            entry_hash: "f".repeat(64),
            actor: ActorId::Operator,
            action: AuditAction::SystemEvent {
                event: event.to_string(),
            },
            conversation_id: ConversationId::new(),
            policy_decision: PolicyDecision::Allow { conditions },
            policy_module: "test".into(),
            receipt: None,
            signatures: vec![],
        }
    }

    #[test]
    fn narrates_delegation_granted() {
        let entry = make_system_event(
            "delegation:granted:example-tool",
            vec![
                "capabilities=chain_render".into(),
                "expires=2026-07-01T00:00:00Z".into(),
            ],
        );
        let seg = narrate_entry(&entry).expect("should produce segment");
        assert_eq!(seg.kind, SegmentKind::DelegationGranted);
        assert!(seg.text.contains("example-tool"));
        assert!(seg.text.contains("chain_render"));
    }

    #[test]
    fn narrates_gate_denied() {
        let entry = AuditEntry {
            id: AuditId::new(),
            timestamp: Utc::now(),
            prev_hash: "0".repeat(64),
            entry_hash: "f".repeat(64),
            actor: ActorId::System("agent:unknown".into()),
            action: AuditAction::SystemEvent {
                event: "gate:denied:chain_render".into(),
            },
            conversation_id: ConversationId::new(),
            policy_decision: PolicyDecision::Block {
                reason: "no delegation exists".into(),
                policy_module: "gate".into(),
            },
            policy_module: "gate".into(),
            receipt: None,
            signatures: vec![],
        };
        let seg = narrate_entry(&entry).expect("should produce segment");
        assert_eq!(seg.kind, SegmentKind::GateDenied);
        assert!(seg.text.contains("no delegation exists"));
    }

    #[test]
    fn narrates_posture() {
        let entry = make_system_event(
            "posture:computed",
            vec![
                "composite=0.90".into(),
                "integrity=0.90".into(),
                "security=1.00".into(),
                "operations=1.00".into(),
                "trend=Stable".into(),
            ],
        );
        let seg = narrate_entry(&entry).expect("should produce segment");
        assert_eq!(seg.kind, SegmentKind::PostureChange);
        assert!(seg.text.contains("0.90"));
        assert!(seg.text.contains("Stable"));
    }

    #[test]
    fn narrates_tool_invoked() {
        let entry = AuditEntry {
            id: AuditId::new(),
            timestamp: Utc::now(),
            prev_hash: "0".repeat(64),
            entry_hash: "f".repeat(64),
            actor: ActorId::System("agent:example-tool".into()),
            action: AuditAction::ToolInvoked {
                tool_name: "memory_write".into(),
                arguments_hash: "abcdef1234567890".into(),
            },
            conversation_id: ConversationId::new(),
            policy_decision: PolicyDecision::Allow {
                conditions: vec![],
            },
            policy_module: "gate".into(),
            receipt: None,
            signatures: vec![],
        };
        let seg = narrate_entry(&entry).expect("should produce segment");
        assert_eq!(seg.kind, SegmentKind::ToolInvoked);
        assert!(seg.text.contains("memory_write"));
    }

    #[test]
    fn story_from_entries_produces_text() {
        let entries = vec![
            make_system_event("delegation:granted:example-tool", vec![]),
            make_system_event("gate:allowed:chain_render", vec![]),
        ];
        let story = ChainStory::from_entries(&entries);
        assert_eq!(story.segments.len(), 2);
        assert_eq!(story.entry_count, 2);

        let text = story.render_text();
        assert!(text.contains("Chain Story"));
        assert!(text.contains("example-tool"));
    }

    #[test]
    fn summary_collapses_runs() {
        let entries = vec![
            make_system_event("gate:allowed:tool_a", vec![]),
            make_system_event("gate:allowed:tool_b", vec![]),
            make_system_event("gate:allowed:tool_c", vec![]),
        ];
        let story = ChainStory::from_entries(&entries);
        let summary = story.summarize();
        assert_eq!(summary.len(), 1);
        assert!(summary[0].text.contains("×3"));
    }

    #[test]
    fn filter_domain_works() {
        let entries = vec![
            make_system_event("delegation:granted:example-tool", vec![]),
            make_system_event(
                "officer:std:heartbeat",
                vec![
                    "finding_count=0".into(),
                    "max_severity=Ok".into(),
                ],
            ),
        ];
        let story = ChainStory::from_entries(&entries);
        let governance = story.filter_domain("governance");
        assert_eq!(governance.segments.len(), 1);
        assert_eq!(
            governance.segments[0].kind,
            SegmentKind::DelegationGranted
        );
    }
}
