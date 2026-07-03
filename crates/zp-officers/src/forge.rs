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

use crate::finding::{Finding, Severity};
use crate::officer::{ChainReader, Officer, VaultKeyLister};
use zp_core::AuditAction;

/// The Forge officer — watches process lifecycle, resource health,
/// and operational coherence.
pub struct Forge;

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
            if let AuditAction::SystemEvent { event } = &entry.action {
                // Match tool lifecycle events
                if let Some(tool) = event.strip_prefix("tool:launched:") {
                    launches_per_tool
                        .entry(tool.to_string())
                        .or_default()
                        .push(entry.timestamp);
                } else if let Some(tool) = event.strip_prefix("tool:started:") {
                    launches_per_tool
                        .entry(tool.to_string())
                        .or_default()
                        .push(entry.timestamp);
                } else if let Some(tool) = event.strip_prefix("tool:restarted:") {
                    launches_per_tool
                        .entry(tool.to_string())
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
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(tool) = event.strip_prefix("tool:health:up:") {
                    tool_states
                        .entry(tool.to_string())
                        .or_default()
                        .push(("up", entry.timestamp));
                } else if let Some(tool) = event.strip_prefix("tool:health:down:") {
                    tool_states
                        .entry(tool.to_string())
                        .or_default()
                        .push(("down", entry.timestamp));
                } else if let Some(tool) = event.strip_prefix("tool:stopped:") {
                    tool_states
                        .entry(tool.to_string())
                        .or_default()
                        .push(("stopped", entry.timestamp));
                } else if let Some(tool) = event.strip_prefix("tool:failed:") {
                    tool_states
                        .entry(tool.to_string())
                        .or_default()
                        .push(("failed", entry.timestamp));
                }
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
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(tool) = event.strip_prefix("tool:launched:")
                    .or_else(|| event.strip_prefix("tool:started:"))
                {
                    *launch_success.entry(tool.to_string()).or_insert(0) += 1;
                } else if let Some(tool) = event.strip_prefix("tool:launch_failed:")
                    .or_else(|| event.strip_prefix("tool:preflight:failed:"))
                {
                    *launch_failure.entry(tool.to_string()).or_insert(0) += 1;
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
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(tool) = extract_tool_from_event(event) {
                    known_tools.insert(tool.to_string());
                    let ts = last_activity.entry(tool.to_string()).or_insert(entry.timestamp);
                    if entry.timestamp > *ts {
                        *ts = entry.timestamp;
                    }
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

/// Extract tool name from a tool-related chain event, if present.
fn extract_tool_from_event(event: &str) -> Option<&str> {
    let prefixes = [
        "tool:launched:",
        "tool:started:",
        "tool:restarted:",
        "tool:stopped:",
        "tool:failed:",
        "tool:health:up:",
        "tool:health:down:",
        "tool:launch_failed:",
        "tool:preflight:failed:",
        "tool:preflight:passed:",
    ];

    for prefix in &prefixes {
        if let Some(rest) = event.strip_prefix(prefix) {
            return Some(rest);
        }
    }

    None
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

    fn sweep(
        &self,
        chain: &ChainReader<'_>,
        _vault_keys: &VaultKeyLister,
    ) -> Vec<Finding> {
        debug!("Forge sweep starting");

        let mut findings = Vec::new();

        findings.extend(self.check_crash_loops(chain));
        findings.extend(self.check_tool_health_patterns(chain));
        findings.extend(self.check_launch_patterns(chain));
        findings.extend(self.check_operational_silence(chain));

        debug!(
            findings = findings.len(),
            "Forge sweep complete"
        );

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

    #[test]
    fn extract_tool_from_events() {
        assert_eq!(extract_tool_from_event("tool:launched:ironclaw"), Some("ironclaw"));
        assert_eq!(extract_tool_from_event("tool:health:up:ironclaw"), Some("ironclaw"));
        assert_eq!(extract_tool_from_event("tool:health:down:ironclaw"), Some("ironclaw"));
        assert_eq!(extract_tool_from_event("tool:launch_failed:ironclaw"), Some("ironclaw"));
        assert_eq!(extract_tool_from_event("gate:denied:foo"), None);
        assert_eq!(extract_tool_from_event("delegation:granted:bar"), None);
    }

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

        assert_eq!(f.event_key(), "officer:forge:operations:crash_loop_detected");
    }
}
