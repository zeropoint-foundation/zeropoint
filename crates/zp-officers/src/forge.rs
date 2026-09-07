//! Forge — Operations officer.
//!
//! Domain: Process lifecycle, resource health, operational coherence.
//! Surfaces findings and proposes actions. Never kills processes or
//! allocates ports directly.
//!
//! Watches the chain for tool launch/health patterns, crash loops,
//! and operational anomalies. Reports operational facts. Doesn't make
//! integrity judgments (Steward) or security judgments (Sentinel).

use std::collections::HashMap;

use chrono::Utc;
use serde_json::json;
use tracing::debug;

use crate::chain_reads::{classify_tool_lifecycle, ToolLifecycleKind};
use crate::finding::{Finding, Severity};
use crate::officer::{ChainReader, Officer, VaultKeyLister};

/// The Forge officer — watches process lifecycle, resource health,
/// and operational coherence.
pub struct Forge;

impl Default for Forge {
    fn default() -> Self {
        Self::new()
    }
}

impl Forge {
    pub fn new() -> Self {
        Self
    }

    /// Detect crash loops: tools that restart repeatedly in a short window.
    ///
    /// Looks for tools with 3+ launches in the recent chain without
    /// corresponding healthy intervals between them.
    fn check_crash_loops(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Count tool launches per tool name
        let mut launches_per_tool: HashMap<String, Vec<chrono::DateTime<chrono::Utc>>> =
            HashMap::new();

        for entry in &entries {
            // Match any launch-shaped lifecycle event; all three
            // (launched / started / restarted) contribute to the
            // crash-loop count for a tool.
            if let Some(ev) = classify_tool_lifecycle(entry) {
                if matches!(
                    ev.kind,
                    ToolLifecycleKind::Launched
                        | ToolLifecycleKind::Started
                        | ToolLifecycleKind::Restarted
                ) {
                    launches_per_tool
                        .entry(ev.tool_name)
                        .or_default()
                        .push(entry.timestamp);
                }
            }
        }

        for (tool, mut timestamps) in launches_per_tool {
            timestamps.sort();

            if timestamps.len() < 3 {
                continue;
            }

            // Check for 3+ launches within 30 minutes
            for i in 2..timestamps.len() {
                let window = timestamps[i] - timestamps[i - 2];
                if window.num_minutes() <= 30 {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "crash_loop_detected".into(),
                        severity: Severity::Warning,
                        summary: format!(
                            "Tool '{}' launched {} times in {} minutes — possible crash loop",
                            tool,
                            timestamps.len(),
                            window.num_minutes()
                        ),
                        detail: json!({
                            "tool": tool,
                            "launch_count": timestamps.len(),
                            "window_minutes": window.num_minutes(),
                            "timestamps": timestamps.iter().map(|t| t.to_rfc3339()).collect::<Vec<_>>(),
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                    break; // One crash loop finding per tool
                }
            }
        }

        findings
    }

    /// Check tool health status transitions.
    ///
    /// Looks for:
    /// - Tools that went down and haven't come back
    /// - Health check flip-flops (up/down/up/down)
    fn check_tool_health_patterns(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Track last known state per tool
        let mut tool_states: HashMap<String, Vec<(&str, chrono::DateTime<chrono::Utc>)>> =
            HashMap::new();

        for entry in &entries {
            if let Some(ev) = classify_tool_lifecycle(entry) {
                let state = match ev.kind {
                    ToolLifecycleKind::HealthUp => "up",
                    ToolLifecycleKind::HealthDown => "down",
                    ToolLifecycleKind::Stopped => "stopped",
                    ToolLifecycleKind::Failed => "failed",
                    _ => continue,
                };
                tool_states
                    .entry(ev.tool_name)
                    .or_default()
                    .push((state, entry.timestamp));
            }
        }

        let now = Utc::now();

        for (tool, states) in &tool_states {
            if states.is_empty() {
                continue;
            }

            // Check if last known state is "down" or "failed"
            if let Some((last_state, last_time)) = states.last() {
                if *last_state == "down" || *last_state == "failed" {
                    let age = now - *last_time;
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "tool_down".into(),
                        severity: if age.num_minutes() > 30 {
                            Severity::Error
                        } else {
                            Severity::Warning
                        },
                        summary: format!(
                            "Tool '{}' has been {} for {} minutes",
                            tool,
                            last_state,
                            age.num_minutes()
                        ),
                        detail: json!({
                            "tool": tool,
                            "state": last_state,
                            "since": last_time.to_rfc3339(),
                            "duration_minutes": age.num_minutes(),
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }

            // Check for flip-flops: alternating up/down states
            if states.len() >= 4 {
                let mut transitions = 0usize;
                for i in 1..states.len() {
                    if states[i].0 != states[i - 1].0 {
                        transitions += 1;
                    }
                }
                if transitions >= 4 {
                    findings.push(Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "health_flipflop".into(),
                        severity: Severity::Warning,
                        summary: format!(
                            "Tool '{}' health state changed {} times — possible instability",
                            tool, transitions
                        ),
                        detail: json!({
                            "tool": tool,
                            "transitions": transitions,
                            "states": states.len(),
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    });
                }
            }
        }

        findings
    }

    /// Check tool launch success patterns.
    ///
    /// Looks for tools that consistently fail to launch (preflight failures,
    /// configuration errors).
    fn check_launch_patterns(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut launch_success: HashMap<String, usize> = HashMap::new();
        let mut launch_failure: HashMap<String, usize> = HashMap::new();

        for entry in &entries {
            if let Some(ev) = classify_tool_lifecycle(entry) {
                match ev.kind {
                    ToolLifecycleKind::Launched | ToolLifecycleKind::Started => {
                        *launch_success.entry(ev.tool_name).or_insert(0) += 1;
                    }
                    ToolLifecycleKind::LaunchFailed | ToolLifecycleKind::PreflightFailed => {
                        *launch_failure.entry(ev.tool_name).or_insert(0) += 1;
                    }
                    _ => {}
                }
            }
        }

        // Report tools with high failure rates
        for (tool, failures) in &launch_failure {
            let successes = launch_success.get(tool).copied().unwrap_or(0);
            let total = successes + failures;
            if total >= 2 && *failures > successes {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "launch_failure_rate".into(),
                    severity: Severity::Warning,
                    summary: format!(
                        "Tool '{}': {} of {} launch attempts failed",
                        tool, failures, total
                    ),
                    detail: json!({
                        "tool": tool,
                        "successes": successes,
                        "failures": failures,
                        "total": total,
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }

    /// Check for operational silence — tools that should be producing
    /// health/activity receipts but aren't.
    fn check_operational_silence(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Collect tools that have been launched but have no recent activity
        let mut last_activity: HashMap<String, chrono::DateTime<chrono::Utc>> = HashMap::new();
        let mut known_tools: std::collections::HashSet<String> = std::collections::HashSet::new();

        for entry in &entries {
            // Only activity events (launched / started / restarted /
            // stopped / failed / health / launch_failed / preflight_failed).
            // `configured` and `port_assigned` are setup ceremony, not
            // ongoing activity — a tool that was configured six hours ago
            // and never launched isn't "silent" in the activity-tracking
            // sense that this check is looking for.
            if let Some(ev) =
                classify_tool_lifecycle(entry).filter(|ev| ev.kind.is_activity_event())
            {
                known_tools.insert(ev.tool_name.clone());
                let ts = last_activity.entry(ev.tool_name).or_insert(entry.timestamp);
                if entry.timestamp > *ts {
                    *ts = entry.timestamp;
                }
            }
        }

        let now = Utc::now();
        for (tool, last) in &last_activity {
            let age = now - *last;
            // Only flag if last activity was more than 2 hours ago
            if age.num_hours() >= 2 {
                findings.push(Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "operational_silence".into(),
                    severity: Severity::Info,
                    summary: format!(
                        "No chain activity from tool '{}' in {} hours",
                        tool,
                        age.num_hours()
                    ),
                    detail: json!({
                        "tool": tool,
                        "last_activity": last.to_rfc3339(),
                        "silence_hours": age.num_hours(),
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                });
            }
        }

        findings
    }
}

impl Forge {
    /// Assess an unregistered listening process from an operations perspective.
    ///
    /// Forge evaluates: should this process be brought under governance?
    /// Surfaces operational facts — what it is, what ports it holds, how
    /// long it's been running — without making security judgments (that's
    /// Sentinel's job). Proposes governance integration if the process
    /// looks like a tool that should be registered.
    pub fn assess_unregistered_listener(
        &self,
        pid: u32,
        process_name: &str,
        ports: &[serde_json::Value],
        context: &serde_json::Value,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        let binary_path = context
            .get("binary_path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let user = context
            .get("user")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let port_list: Vec<u64> = ports
            .iter()
            .filter_map(|p| p.get("port").and_then(|v| v.as_u64()))
            .collect();

        // Operational assessment: this process is using resources (ports)
        // that could conflict with governed tools.
        findings.push(Finding {
            officer: self.name(),
            domain: self.domain(),
            finding_type: "unregistered_listener".into(),
            severity: Severity::Info,
            summary: format!(
                "Process '{}' (pid {}, user {}) listening on port(s) {} — not under governance",
                process_name,
                pid,
                user,
                port_list
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            detail: json!({
                "pid": pid,
                "process_name": process_name,
                "binary_path": binary_path,
                "ports": port_list,
                "context": context,
                "tool_name": process_name,
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        });

        findings
    }

    /// Generate proposals from sweep findings (Band 2).
    ///
    /// Translates diagnostic findings into actionable mutations. Unlike
    /// `propose()` which scans the chain directly, this method converts
    /// findings that were already produced by `sweep()` or sensor-driven
    /// assessment into structured proposals.
    ///
    /// Supported conversions:
    /// - `port_mismatch` → `SetPortBinding` (correct the registry)
    /// - `unregistered_listener` → `SetPortBinding` (register the process)
    /// - `launch_failure_rate` → `RestartTool` (clean restart)
    pub fn propose_from_findings(&self, findings: &[Finding]) -> Vec<crate::proposal::Proposal> {
        use crate::proposal::{Proposal, ProposedMutation};

        let mut proposals = Vec::new();

        for f in findings {
            match f.finding_type.as_str() {
                "port_mismatch" => {
                    let tool = match f
                        .detail
                        .get("tool_name")
                        .or(f.detail.get("tool"))
                        .and_then(|v| v.as_str())
                    {
                        Some(t) => t.to_string(),
                        None => continue,
                    };
                    let actual_ports: Vec<u16> = f
                        .detail
                        .get("actual_ports")
                        .or(f.detail.get("actual"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|p| p as u16))
                                .collect()
                        })
                        .unwrap_or_default();

                    if let Some(&port) = actual_ports.first() {
                        proposals.push(Proposal::new(
                            f.clone(),
                            ProposedMutation::SetPortBinding {
                                tool: tool.clone(),
                                port,
                                rationale: format!(
                                    "observed on port {} (registry disagrees)",
                                    port
                                ),
                            },
                            self.name(),
                        ));
                    }
                }
                "unregistered_listener" => {
                    let tool = match f.detail.get("process_name").and_then(|v| v.as_str()) {
                        Some(t) => t.to_string(),
                        None => continue,
                    };
                    let ports: Vec<u16> = f
                        .detail
                        .get("ports")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_u64().map(|p| p as u16))
                                .collect()
                        })
                        .unwrap_or_default();

                    if let Some(&port) = ports.first() {
                        proposals.push(Proposal::new(
                            f.clone(),
                            ProposedMutation::SetPortBinding {
                                tool: tool.clone(),
                                port,
                                rationale: format!(
                                    "discovered on port {} — register under governance",
                                    port
                                ),
                            },
                            self.name(),
                        ));
                    }
                }
                "launch_failure_rate" => {
                    let tool = match f.detail.get("tool").and_then(|v| v.as_str()) {
                        Some(t) => t.to_string(),
                        None => continue,
                    };
                    let failures = f
                        .detail
                        .get("failures")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    proposals.push(Proposal::new(
                        f.clone(),
                        ProposedMutation::RestartTool {
                            tool: tool.clone(),
                            rationale: format!(
                                "{} launch failures — clean restart may resolve",
                                failures
                            ),
                        },
                        self.name(),
                    ));
                }
                _ => {} // Other finding types don't have well-defined automated fixes yet.
            }
        }

        proposals
    }
}

// (former `extract_tool_from_event` helper deleted 2026-08-04; use
// `crate::chain_reads::classify_tool_lifecycle` and read the
// `tool_name` field on the returned event. Its coverage of receipt
// prefixes is a superset of what this helper had.)

impl Forge {
    /// Generate structured proposals from chain evidence (Band 2).
    ///
    /// Proposals are derived from the same patterns as findings, but carry
    /// actionable mutations the operator can review and sign. Only emitted
    /// for conditions where an automated fix is well-defined.
    pub fn propose(&self, chain: &ChainReader<'_>) -> Vec<crate::proposal::Proposal> {
        use crate::proposal::{Proposal, ProposedMutation};

        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut proposals = Vec::new();

        // ── Crash loops → RestartTool ─────────────────────────────────
        // If a tool has been crash-looping, propose a governed restart
        // (clean stop + relaunch through `zp configure exec`).
        let mut launches_per_tool: std::collections::HashMap<
            String,
            Vec<chrono::DateTime<chrono::Utc>>,
        > = std::collections::HashMap::new();

        for entry in &entries {
            if let Some(ev) = classify_tool_lifecycle(entry) {
                if matches!(
                    ev.kind,
                    ToolLifecycleKind::Launched
                        | ToolLifecycleKind::Started
                        | ToolLifecycleKind::Restarted
                ) {
                    launches_per_tool
                        .entry(ev.tool_name)
                        .or_default()
                        .push(entry.timestamp);
                }
            }
        }

        for (tool, mut timestamps) in launches_per_tool {
            timestamps.sort();
            if timestamps.len() < 3 {
                continue;
            }
            for i in 2..timestamps.len() {
                let window = timestamps[i] - timestamps[i - 2];
                if window.num_minutes() <= 30 {
                    let finding = Finding {
                        officer: self.name(),
                        domain: self.domain(),
                        finding_type: "crash_loop_detected".into(),
                        severity: Severity::Warning,
                        summary: format!(
                            "Tool '{}' launched {} times in {} min",
                            tool,
                            timestamps.len(),
                            window.num_minutes()
                        ),
                        detail: json!({
                            "tool": tool,
                            "launch_count": timestamps.len(),
                            "window_minutes": window.num_minutes(),
                        }),
                        timestamp: Utc::now(),
                        cross_domain_depth: 0,
                    };
                    proposals.push(Proposal::new(
                        finding,
                        ProposedMutation::RestartTool {
                            tool: tool.clone(),
                            rationale: format!(
                                "crash loop: {} launches in {} min",
                                timestamps.len(),
                                window.num_minutes()
                            ),
                        },
                        self.name(),
                    ));
                    break;
                }
            }
        }

        // ── Tool down → RestartTool ───────────────────────────────────
        // If a tool has been down for >30 min, propose restart.
        let mut last_states: std::collections::HashMap<
            String,
            (&str, chrono::DateTime<chrono::Utc>),
        > = std::collections::HashMap::new();

        for entry in &entries {
            if let Some(ev) = classify_tool_lifecycle(entry) {
                let state = match ev.kind {
                    ToolLifecycleKind::HealthDown => "down",
                    ToolLifecycleKind::Failed => "failed",
                    ToolLifecycleKind::HealthUp => "up",
                    ToolLifecycleKind::Launched | ToolLifecycleKind::Started => "up",
                    _ => continue,
                };
                last_states.insert(ev.tool_name, (state, entry.timestamp));
            }
        }

        let now = Utc::now();
        for (tool, (state, since)) in &last_states {
            if (*state == "down" || *state == "failed") && (now - *since).num_minutes() > 30 {
                let finding = Finding {
                    officer: self.name(),
                    domain: self.domain(),
                    finding_type: "tool_down".into(),
                    severity: Severity::Error,
                    summary: format!(
                        "Tool '{}' has been {} for {} min",
                        tool,
                        state,
                        (now - *since).num_minutes()
                    ),
                    detail: json!({
                        "tool": tool,
                        "state": state,
                        "since": since.to_rfc3339(),
                    }),
                    timestamp: Utc::now(),
                    cross_domain_depth: 0,
                };
                proposals.push(Proposal::new(
                    finding,
                    ProposedMutation::RestartTool {
                        tool: tool.clone(),
                        rationale: format!("{} for {} min", state, (now - *since).num_minutes()),
                    },
                    self.name(),
                ));
            }
        }

        proposals
    }
}

impl Officer for Forge {
    fn name(&self) -> &'static str {
        "forge"
    }

    fn domain(&self) -> &'static str {
        "operations"
    }

    fn watch_patterns(&self) -> &[&'static str] {
        &[
            "tool:health:down:",
            "tool:failed:",
            "tool:launch_failed:",
            "tool:restarted:",
        ]
    }

    fn sweep(&self, chain: &ChainReader<'_>, _vault_keys: &VaultKeyLister) -> Vec<Finding> {
        debug!("Forge sweep starting");

        let mut findings = Vec::new();

        findings.extend(self.check_crash_loops(chain));
        findings.extend(self.check_tool_health_patterns(chain));
        findings.extend(self.check_launch_patterns(chain));
        findings.extend(self.check_operational_silence(chain));

        debug!(findings = findings.len(), "Forge sweep complete");

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::officer::{ChainReader, VaultKeyLister};
    use zp_audit::store::AuditStore;

    fn test_store() -> AuditStore {
        AuditStore::open_readonly(":memory:").expect("open in-memory store")
    }

    #[test]
    fn forge_trait_impl() {
        let forge = Forge::new();
        assert_eq!(forge.name(), "forge");
        assert_eq!(forge.domain(), "operations");
        assert!(!forge.watch_patterns().is_empty());
        assert!(forge.watch_patterns().contains(&"tool:health:down:"));
    }

    #[test]
    fn forge_sweep_empty_chain() {
        let store = test_store();
        let chain = ChainReader::new(&store);
        let vault = VaultKeyLister::new(vec![]);
        let forge = Forge::new();

        let findings = forge.sweep(&chain, &vault);
        // Empty chain = no findings
        assert!(findings.is_empty());
    }

    // (extract_tool_from_events test removed 2026-08-04 with the helper.
    // Equivalent coverage now lives in `chain_reads::tests::
    // classify_tool_lifecycle_identifies_each_kind` and
    // `classify_tool_lifecycle_returns_none_for_non_matching_events`.)

    #[test]
    fn finding_event_key_format() {
        let f = Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "crash_loop_detected".into(),
            severity: Severity::Warning,
            summary: "test".into(),
            detail: json!({}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        };

        assert_eq!(
            f.event_key(),
            "officer:forge:operations:crash_loop_detected"
        );
    }

    #[test]
    fn forge_assesses_unregistered_listener() {
        let forge = Forge::new();
        let context = json!({
            "pid": 12345,
            "name": "node",
            "binary_path": "/usr/local/bin/node",
            "user": "ken",
            "parent_name": "zsh"
        });
        let ports = vec![
            json!({"port": 3000, "protocol": "TCP", "socket": "127.0.0.1:3000"}),
            json!({"port": 3001, "protocol": "TCP", "socket": "127.0.0.1:3001"}),
        ];

        let findings = forge.assess_unregistered_listener(12345, "node", &ports, &context);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].finding_type, "unregistered_listener");
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].summary.contains("node"));
        assert!(findings[0].summary.contains("3000"));
        assert!(findings[0].detail.get("tool_name").is_some());
    }

    #[test]
    fn propose_empty_chain() {
        let store = test_store();
        let chain = ChainReader::new(&store);
        let forge = Forge::new();

        let proposals = forge.propose(&chain);
        assert!(proposals.is_empty());
    }

    #[test]
    fn proposal_event_key_format() {
        use crate::proposal::{Proposal, ProposedMutation};

        let finding = Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "crash_loop_detected".into(),
            severity: Severity::Warning,
            summary: "test".into(),
            detail: json!({}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        };
        let p = Proposal::new(
            finding,
            ProposedMutation::RestartTool {
                tool: "example-tool".into(),
                rationale: "crash loop".into(),
            },
            "forge",
        );
        assert_eq!(p.event_key(), "proposal:forge:restart_tool:example-tool");
    }

    #[test]
    fn propose_from_port_mismatch_finding() {
        let forge = Forge::new();
        let findings = vec![Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "port_mismatch".into(),
            severity: Severity::Warning,
            summary: "example-tool port mismatch".into(),
            detail: json!({
                "tool_name": "example-tool",
                "actual_ports": [8090],
                "expected": 9101,
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }];

        let proposals = forge.propose_from_findings(&findings);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].mutation.kind_label(), "set_port");
        assert_eq!(proposals[0].mutation.tool_name(), "example-tool");
    }

    #[test]
    fn propose_from_unregistered_listener() {
        let forge = Forge::new();
        let findings = vec![Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "unregistered_listener".into(),
            severity: Severity::Info,
            summary: "node listening".into(),
            detail: json!({
                "pid": 12345,
                "process_name": "node",
                "ports": [3000],
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }];

        let proposals = forge.propose_from_findings(&findings);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].mutation.kind_label(), "set_port");
        assert_eq!(proposals[0].mutation.tool_name(), "node");
    }

    #[test]
    fn propose_from_launch_failure() {
        let forge = Forge::new();
        let findings = vec![Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "launch_failure_rate".into(),
            severity: Severity::Warning,
            summary: "example-tool launch failures".into(),
            detail: json!({
                "tool": "example-tool",
                "failures": 5,
                "successes": 1,
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }];

        let proposals = forge.propose_from_findings(&findings);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].mutation.kind_label(), "restart_tool");
        assert_eq!(proposals[0].mutation.tool_name(), "example-tool");
    }

    #[test]
    fn propose_from_findings_skips_unknown_types() {
        let forge = Forge::new();
        let findings = vec![Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "operational_silence".into(),
            severity: Severity::Info,
            summary: "no activity".into(),
            detail: json!({"tool": "example-tool"}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }];

        let proposals = forge.propose_from_findings(&findings);
        assert!(proposals.is_empty());
    }
}
