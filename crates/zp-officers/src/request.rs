//! Governance requests — consolidated operator-facing decision points.
//!
//! Officers write independently to the chain (audit trail). The cockpit
//! reads consolidated (GovernanceRequest). Officers are internal; the
//! system speaks with one voice.
//!
//! A GovernanceRequest merges findings from all officers about the same
//! subject into one decision point. The operator makes one decision per
//! request. The resulting receipt references all underlying finding IDs
//! for audit linkage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::finding::{Finding, Severity};
use crate::proposal::{Proposal, ProposedMutation};

/// What the governance request is about.
///
/// For known tools, the subject is the tool name. For unknown processes
/// discovered by sensors, the subject carries enriched process context
/// so the operator can identify what they're approving or dismissing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Subject {
    /// A tool already registered in the governance system.
    KnownTool { tool_name: String },
    /// An unregistered process discovered by sensors.
    UnknownProcess {
        pid: u32,
        process_name: String,
        /// Enriched context — binary path, command line, user, parent.
        /// Stored as JSON value so zp-officers doesn't depend on zp-sensors.
        context: serde_json::Value,
    },
}

impl Subject {
    /// Short display label for cockpit rendering.
    pub fn display_label(&self) -> String {
        match self {
            Self::KnownTool { tool_name } => tool_name.clone(),
            Self::UnknownProcess {
                process_name, pid, ..
            } => {
                format!("{process_name} (pid {pid})")
            }
        }
    }

    /// Machine-readable key for grouping — findings about the same
    /// subject produce the same key.
    pub fn group_key(&self) -> String {
        match self {
            Self::KnownTool { tool_name } => format!("tool:{tool_name}"),
            Self::UnknownProcess { pid, .. } => format!("pid:{pid}"),
        }
    }
}

/// A consolidated governance request presented to the operator.
///
/// One request per subject. Merges concerns from all officers (Steward,
/// Sentinel, Forge, Cleo) into a single decision point. The operator
/// approves, dismisses, or defers — one action covers all perspectives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceRequest {
    /// What this request is about.
    pub subject: Subject,
    /// Merged concerns from all officers, highest severity first.
    pub concerns: Vec<Concern>,
    /// Recommended actions from officer proposals (deduplicated).
    pub recommended_actions: Vec<ProposedMutation>,
    /// Maximum severity across all contributing findings.
    pub severity: Severity,
    /// Event keys of all contributing findings — audit linkage.
    pub finding_refs: Vec<String>,
    /// When this request was consolidated.
    pub consolidated_at: DateTime<Utc>,
}

/// A single concern within a governance request.
///
/// Preserves the officer attribution so the operator can see which
/// perspective each concern comes from, while the request itself is
/// the unified decision surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Concern {
    /// Which officer raised this concern.
    pub officer: String,
    /// The officer's domain (integrity, security, operations, governance).
    pub domain: String,
    /// Human-readable description.
    pub summary: String,
    /// Severity of this specific concern.
    pub severity: Severity,
}

impl GovernanceRequest {
    /// Chain event key for the consolidated request receipt.
    pub fn event_key(&self) -> String {
        format!(
            "governance_request:{}:{}",
            self.severity_label(),
            self.subject.group_key(),
        )
    }

    /// Human-readable one-line summary for cockpit display.
    pub fn display_summary(&self) -> String {
        let n = self.concerns.len();
        let officers: Vec<&str> = self
            .concerns
            .iter()
            .map(|c| c.officer.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        format!(
            "[{}] {} — {} concern{} from {}",
            self.severity_label(),
            self.subject.display_label(),
            n,
            if n == 1 { "" } else { "s" },
            officers.join(", "),
        )
    }

    fn severity_label(&self) -> &'static str {
        match self.severity {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }
}

/// One subject's accumulating request, before it becomes a `GovernanceRequest`.
///
/// In order: the subject itself, the concerns merged onto it, the deduplicated
/// mutations proposed for it, the ids of the findings backing it, and the
/// running maximum severity. Named because the tuple appears in a nested
/// generic position where writing it inline obscures what is being grouped.
type RequestGroup = (
    Subject,
    Vec<Concern>,
    Vec<ProposedMutation>,
    Vec<String>,
    Severity,
);

/// Consolidate findings and proposals into governance requests.
///
/// Groups by subject (tool name or PID), merges concerns, deduplicates
/// recommended actions, takes max severity. Returns one `GovernanceRequest`
/// per unique subject.
pub fn consolidate(findings: &[Finding], proposals: &[Proposal]) -> Vec<GovernanceRequest> {
    use std::collections::BTreeMap;

    // Group key → the accumulating request for that subject.
    let mut groups: BTreeMap<String, RequestGroup> = BTreeMap::new();

    // Process findings.
    for f in findings {
        let (key, subject) = subject_from_finding(f);
        let entry = groups
            .entry(key)
            .or_insert_with(|| (subject, Vec::new(), Vec::new(), Vec::new(), Severity::Ok));

        entry.1.push(Concern {
            officer: f.officer.to_string(),
            domain: f.domain.to_string(),
            summary: f.summary.clone(),
            severity: f.severity,
        });
        entry.3.push(f.event_key());
        if f.severity > entry.4 {
            entry.4 = f.severity;
        }
    }

    // Process proposals — attach to existing groups or create new ones.
    for p in proposals {
        let key = format!("tool:{}", p.mutation.tool_name());
        let subject = Subject::KnownTool {
            tool_name: p.mutation.tool_name().to_string(),
        };
        let entry = groups
            .entry(key)
            .or_insert_with(|| (subject, Vec::new(), Vec::new(), Vec::new(), Severity::Ok));

        // Add the finding as a concern if not already present.
        let finding_key = p.finding.event_key();
        if !entry.3.contains(&finding_key) {
            entry.1.push(Concern {
                officer: p.finding.officer.to_string(),
                domain: p.finding.domain.to_string(),
                summary: p.finding.summary.clone(),
                severity: p.finding.severity,
            });
            entry.3.push(finding_key);
            if p.finding.severity > entry.4 {
                entry.4 = p.finding.severity;
            }
        }

        // Deduplicate mutations by kind + tool.
        let dominated = entry.2.iter().any(|existing| {
            existing.kind_label() == p.mutation.kind_label()
                && existing.tool_name() == p.mutation.tool_name()
        });
        if !dominated {
            entry.2.push(p.mutation.clone());
        }
    }

    let now = Utc::now();
    groups
        .into_values()
        .map(|(subject, mut concerns, actions, refs, severity)| {
            // Sort concerns by severity (highest first).
            concerns.sort_by(|a, b| b.severity.cmp(&a.severity));

            GovernanceRequest {
                subject,
                concerns,
                recommended_actions: actions,
                severity,
                finding_refs: refs,
                consolidated_at: now,
            }
        })
        .collect()
}

/// Extract subject from a finding's detail field.
///
/// Convention: findings about known tools have `detail.tool_name`.
/// Findings about unknown processes have `detail.pid` + `detail.process_name`
/// + optionally `detail.context`.
fn subject_from_finding(f: &Finding) -> (String, Subject) {
    // Check for tool_name first (known tool).
    if let Some(tool) = f.detail.get("tool_name").and_then(|v| v.as_str()) {
        let key = format!("tool:{tool}");
        let subject = Subject::KnownTool {
            tool_name: tool.to_string(),
        };
        return (key, subject);
    }

    // Check for pid (unknown process).
    if let Some(pid) = f.detail.get("pid").and_then(|v| v.as_u64()) {
        let pid = pid as u32;
        let name = f
            .detail
            .get("process_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        let context = f
            .detail
            .get("context")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        let key = format!("pid:{pid}");
        let subject = Subject::UnknownProcess {
            pid,
            process_name: name,
            context,
        };
        return (key, subject);
    }

    // Fallback: use the finding type as the group key.
    let key = format!("finding:{}", f.finding_type);
    let subject = Subject::KnownTool {
        tool_name: f.finding_type.clone(),
    };
    (key, subject)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn forge_finding(tool: &str) -> Finding {
        Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "port_mismatch".into(),
            severity: Severity::Warning,
            summary: format!("{tool} port mismatch"),
            detail: json!({"tool_name": tool, "expected": 9101, "actual": 8090}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }
    }

    fn sentinel_finding(tool: &str) -> Finding {
        Finding {
            officer: "sentinel",
            domain: "security",
            finding_type: "credential_drift".into(),
            severity: Severity::Error,
            summary: format!("{tool} credential rotated without governance"),
            detail: json!({"tool_name": tool}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }
    }

    fn process_finding(pid: u32, name: &str) -> Finding {
        Finding {
            officer: "sentinel",
            domain: "security",
            finding_type: "unauthorized_listener".into(),
            severity: Severity::Warning,
            summary: format!("Unregistered process {name} listening on port"),
            detail: json!({
                "pid": pid,
                "process_name": name,
                "context": {
                    "pid": pid,
                    "name": name,
                    "binary_path": "/usr/local/bin/mystery",
                    "user": "ken"
                }
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }
    }

    #[test]
    fn consolidate_merges_same_tool() {
        let findings = vec![
            forge_finding("example-tool"),
            sentinel_finding("example-tool"),
        ];
        let requests = consolidate(&findings, &[]);

        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.subject.display_label(), "example-tool");
        assert_eq!(req.concerns.len(), 2);
        // Max severity is Error (from sentinel).
        assert_eq!(req.severity, Severity::Error);
        // Both findings referenced.
        assert_eq!(req.finding_refs.len(), 2);
    }

    #[test]
    fn consolidate_separates_different_tools() {
        let findings = vec![forge_finding("example-tool"), forge_finding("other-tool")];
        let requests = consolidate(&findings, &[]);

        assert_eq!(requests.len(), 2);
    }

    #[test]
    fn consolidate_unknown_process() {
        let findings = vec![process_finding(12345, "mystery-daemon")];
        let requests = consolidate(&findings, &[]);

        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.subject.display_label(), "mystery-daemon (pid 12345)");
        assert_eq!(req.subject.group_key(), "pid:12345");
        assert!(req.recommended_actions.is_empty());
    }

    #[test]
    fn consolidate_with_proposals() {
        let findings = vec![forge_finding("example-tool")];
        let proposals = vec![Proposal::new(
            forge_finding("example-tool"),
            ProposedMutation::SetPortBinding {
                tool: "example-tool".into(),
                port: 8090,
                rationale: "observed".into(),
            },
            "forge",
        )];
        let requests = consolidate(&findings, &proposals);

        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(req.recommended_actions.len(), 1);
        assert_eq!(req.recommended_actions[0].kind_label(), "set_port");
    }

    #[test]
    fn consolidate_deduplicates_mutations() {
        let proposals = vec![
            Proposal::new(
                forge_finding("example-tool"),
                ProposedMutation::SetPortBinding {
                    tool: "example-tool".into(),
                    port: 8090,
                    rationale: "first".into(),
                },
                "forge",
            ),
            Proposal::new(
                forge_finding("example-tool"),
                ProposedMutation::SetPortBinding {
                    tool: "example-tool".into(),
                    port: 8090,
                    rationale: "second".into(),
                },
                "forge",
            ),
        ];
        let requests = consolidate(&[], &proposals);

        assert_eq!(requests.len(), 1);
        // Only one SetPortBinding survives dedup.
        assert_eq!(requests[0].recommended_actions.len(), 1);
    }

    #[test]
    fn consolidate_mixed_tool_and_process() {
        let findings = vec![
            forge_finding("example-tool"),
            process_finding(99999, "rogue"),
        ];
        let requests = consolidate(&findings, &[]);

        assert_eq!(requests.len(), 2);
        let labels: Vec<String> = requests.iter().map(|r| r.subject.group_key()).collect();
        assert!(labels.contains(&"pid:99999".to_string()));
        assert!(labels.contains(&"tool:example-tool".to_string()));
    }

    #[test]
    fn display_summary_format() {
        let findings = vec![
            forge_finding("example-tool"),
            sentinel_finding("example-tool"),
        ];
        let requests = consolidate(&findings, &[]);
        let summary = requests[0].display_summary();

        assert!(summary.contains("example-tool"));
        assert!(summary.contains("2 concerns"));
        assert!(summary.contains("forge"));
        assert!(summary.contains("sentinel"));
        assert!(summary.contains("[error]"));
    }

    #[test]
    fn concerns_sorted_by_severity() {
        let findings = vec![
            forge_finding("example-tool"),
            sentinel_finding("example-tool"),
        ];
        let requests = consolidate(&findings, &[]);
        let req = &requests[0];

        // Error (sentinel) should come before Warning (forge).
        assert_eq!(req.concerns[0].severity, Severity::Error);
        assert_eq!(req.concerns[1].severity, Severity::Warning);
    }

    #[test]
    fn event_key_format() {
        let findings = vec![sentinel_finding("example-tool")];
        let requests = consolidate(&findings, &[]);
        assert_eq!(
            requests[0].event_key(),
            "governance_request:error:tool:example-tool"
        );
    }

    #[test]
    fn subject_serde_roundtrip() {
        let subject = Subject::UnknownProcess {
            pid: 42,
            process_name: "test".into(),
            context: json!({"binary_path": "/bin/test"}),
        };
        let json = serde_json::to_string(&subject).unwrap();
        let restored: Subject = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.group_key(), "pid:42");
    }

    #[test]
    fn empty_inputs() {
        let requests = consolidate(&[], &[]);
        assert!(requests.is_empty());
    }
}
