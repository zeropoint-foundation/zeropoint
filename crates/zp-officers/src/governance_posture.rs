//! Per-tool governance posture — which facets are currently true.
//!
//! Posture is derived purely from chain evidence + port registry state.
//! Not a state machine — no required sequence. A tool can be Registered
//! + Governed but not Provisioned (vault entries missing). Facets gain/drop
//! as evidence appears or degrades.
//!
//! See `docs/design/TOOL-GOVERNANCE-LIFECYCLE-2026-07.md` §4.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::officer::ChainReader;
use zp_core::AuditAction;

// ── Facets ──────────────────────────────────────────────────────────────

/// A single governance facet that may be true for a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceFacet {
    /// Running process with no chain presence.
    /// Only knowable via sensor discovery — set externally.
    Unregistered,
    /// Manifest hash + port allocation on chain.
    Registered,
    /// Vault entries validate against manifest schema.
    Provisioned,
    /// Launched via governed path, delegation exists, gate evaluating.
    Governed,
    /// All four officers report clean. Forge deactivates.
    Hardened,
}

impl GovernanceFacet {
    /// Display label for CLI/dashboard.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unregistered => "unregistered",
            Self::Registered => "registered",
            Self::Provisioned => "provisioned",
            Self::Governed => "governed",
            Self::Hardened => "hardened",
        }
    }

    /// Short description for operator context.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Unregistered => "Running but no chain presence",
            Self::Registered => "Port allocated, manifest known",
            Self::Provisioned => "Vault schema validated",
            Self::Governed => "Launched via ZP, delegation active",
            Self::Hardened => "All officers clean",
        }
    }
}

/// The governance posture of a single tool.
#[derive(Debug, Clone, Serialize)]
pub struct ToolGovernancePosture {
    pub tool_name: String,
    /// Set of currently-true facets.
    pub facets: HashSet<GovernanceFacet>,
    /// When the posture was last computed.
    pub computed_at: DateTime<Utc>,
}

impl ToolGovernancePosture {
    pub fn has(&self, facet: GovernanceFacet) -> bool {
        self.facets.contains(&facet)
    }

    /// Highest governance level reached (for sorting/display).
    pub fn level(&self) -> u8 {
        if self.has(GovernanceFacet::Hardened) {
            5
        } else if self.has(GovernanceFacet::Governed) {
            4
        } else if self.has(GovernanceFacet::Provisioned) {
            3
        } else if self.has(GovernanceFacet::Registered) {
            2
        } else if self.has(GovernanceFacet::Unregistered) {
            1
        } else {
            0
        }
    }

    /// Human-readable summary: "registered, governed" or "unregistered".
    pub fn summary(&self) -> String {
        if self.facets.is_empty() {
            return "unknown".to_string();
        }
        // Sort by level for consistent display.
        let mut labels: Vec<_> = self.facets.iter().map(|f| f.label()).collect();
        labels.sort();
        labels.join(", ")
    }
}

// ── External context (non-chain data) ───────────────────────────────────

/// Port registry snapshot for posture computation.
/// Avoids coupling zp-officers to zp-server's PortRegistry type.
#[derive(Debug, Clone, Default)]
pub struct ToolRegistrySnapshot {
    /// Tools with port allocations. Key = tool name (lowercase).
    pub registered_tools: HashMap<String, RegisteredToolInfo>,
}

/// Minimal info from the port registry needed for posture assessment.
#[derive(Debug, Clone)]
pub struct RegisteredToolInfo {
    pub port: u16,
    pub pid: Option<u32>,
    pub has_launch_command: bool,
}

/// Names of tools discovered by the sensor layer that have no chain presence.
/// Passed in externally since the sensor layer lives in a different crate.
pub type UnregisteredTools = HashSet<String>;

// ── Computation ─────────────────────────────────────────────────────────

/// Compute governance posture for all known tools.
///
/// Merges chain evidence, port registry state, and sensor discoveries
/// into a per-tool set of true facets. Pure function — same inputs,
/// same output.
pub fn compute_postures(
    chain: &ChainReader<'_>,
    registry: &ToolRegistrySnapshot,
    unregistered: &UnregisteredTools,
) -> Vec<ToolGovernancePosture> {
    let now = Utc::now();

    // Scan chain for tool evidence.
    let chain_evidence = scan_chain_evidence(chain);

    // Collect all tool names from all sources.
    let mut all_tools: HashSet<String> = HashSet::new();
    all_tools.extend(chain_evidence.keys().cloned());
    all_tools.extend(registry.registered_tools.keys().cloned());
    all_tools.extend(unregistered.iter().cloned());

    let mut postures = Vec::new();

    for tool in &all_tools {
        let mut facets = HashSet::new();
        let evidence = chain_evidence.get(tool);

        // Unregistered: sensor discovered, no chain presence.
        if unregistered.contains(tool) && evidence.is_none() && !registry.registered_tools.contains_key(tool) {
            facets.insert(GovernanceFacet::Unregistered);
        }

        // Registered: port allocated OR configured receipt exists.
        if registry.registered_tools.contains_key(tool)
            || evidence.map_or(false, |e| e.has_configured || e.has_port_assigned)
        {
            facets.insert(GovernanceFacet::Registered);
        }

        // Provisioned: preflight passed (vault schema validated).
        if evidence.map_or(false, |e| e.has_preflight_passed) {
            facets.insert(GovernanceFacet::Provisioned);
        }

        // Governed: launched via ZP AND delegation exists.
        let has_launch_command = registry
            .registered_tools
            .get(tool)
            .map_or(false, |r| r.has_launch_command);
        if evidence.map_or(false, |e| e.has_launched) && has_launch_command
            && evidence.map_or(false, |e| e.has_delegation)
        {
            facets.insert(GovernanceFacet::Governed);
        }

        // Hardened: governed AND no Warning+ officer findings for this tool.
        if facets.contains(&GovernanceFacet::Governed)
            && evidence.map_or(true, |e| !e.has_officer_warnings)
        {
            facets.insert(GovernanceFacet::Hardened);
        }

        postures.push(ToolGovernancePosture {
            tool_name: tool.clone(),
            facets,
            computed_at: now,
        });
    }

    // Sort by name for stable output.
    postures.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
    postures
}

// ── Chain evidence scanner ──────────────────────────────────────────────

/// Evidence extracted from the chain for a single tool.
#[derive(Debug, Default)]
struct ToolChainEvidence {
    has_configured: bool,
    has_port_assigned: bool,
    has_preflight_passed: bool,
    has_launched: bool,
    has_delegation: bool,
    has_officer_warnings: bool,
}

/// Scan recent chain entries and extract per-tool evidence.
fn scan_chain_evidence(chain: &ChainReader<'_>) -> HashMap<String, ToolChainEvidence> {
    let entries = match chain.recent_entries(2000) {
        Ok(e) => e,
        Err(_) => return HashMap::new(),
    };

    let mut evidence: HashMap<String, ToolChainEvidence> = HashMap::new();

    for entry in &entries {
        match &entry.action {
            AuditAction::SystemEvent { event } => {
                // Tool lifecycle events.
                if let Some(tool) = event.strip_prefix("tool:configured:") {
                    evidence.entry(tool.to_string()).or_default().has_configured = true;
                } else if let Some(tool) = event.strip_prefix("tool:port:assigned:") {
                    // Format: tool:port:assigned:name:port — extract name.
                    if let Some(name) = tool.split(':').next() {
                        evidence.entry(name.to_string()).or_default().has_port_assigned = true;
                    }
                } else if let Some(tool) = event.strip_prefix("tool:preflight:passed:") {
                    evidence.entry(tool.to_string()).or_default().has_preflight_passed = true;
                } else if let Some(tool) = event.strip_prefix("tool:launched:") {
                    evidence.entry(tool.to_string()).or_default().has_launched = true;
                } else if let Some(tool) = event.strip_prefix("tool:started:") {
                    evidence.entry(tool.to_string()).or_default().has_launched = true;
                }

                // Delegation events.
                if let Some(rest) = event.strip_prefix("delegation:granted:") {
                    evidence.entry(rest.to_string()).or_default().has_delegation = true;
                }

                // Officer findings that reference a tool (Warning+).
                // Format: officer:forge:operations:crash_loop_detected
                // The finding's detail JSON contains the tool name, but we can't
                // parse JSON from the chain event string. Instead, check for
                // officer findings at Warning+ severity by looking at the
                // policy_decision conditions.
                if event.starts_with("officer:") && event.contains(":operations:") {
                    // Check conditions for tool references.
                    if let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision {
                        for condition in conditions {
                            if let Some(tool_ref) = condition.strip_prefix("tool=") {
                                evidence
                                    .entry(tool_ref.to_string())
                                    .or_default()
                                    .has_officer_warnings = true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    evidence
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inputs_produce_no_postures() {
        let store = zp_audit::store::AuditStore::open_readonly(":memory:")
            .expect("open in-memory store");
        let chain = ChainReader::new(&store);
        let registry = ToolRegistrySnapshot::default();
        let unregistered = UnregisteredTools::new();

        let postures = compute_postures(&chain, &registry, &unregistered);
        assert!(postures.is_empty());
    }

    #[test]
    fn unregistered_tool_from_sensor() {
        let store = zp_audit::store::AuditStore::open_readonly(":memory:")
            .expect("open in-memory store");
        let chain = ChainReader::new(&store);
        let registry = ToolRegistrySnapshot::default();
        let mut unregistered = UnregisteredTools::new();
        unregistered.insert("mystery-process".to_string());

        let postures = compute_postures(&chain, &registry, &unregistered);
        assert_eq!(postures.len(), 1);
        assert_eq!(postures[0].tool_name, "mystery-process");
        assert!(postures[0].has(GovernanceFacet::Unregistered));
        assert!(!postures[0].has(GovernanceFacet::Registered));
    }

    #[test]
    fn registered_tool_from_port_registry() {
        let store = zp_audit::store::AuditStore::open_readonly(":memory:")
            .expect("open in-memory store");
        let chain = ChainReader::new(&store);
        let mut registry = ToolRegistrySnapshot::default();
        registry.registered_tools.insert(
            "ironclaw".to_string(),
            RegisteredToolInfo {
                port: 9101,
                pid: Some(12345),
                has_launch_command: true,
            },
        );
        let unregistered = UnregisteredTools::new();

        let postures = compute_postures(&chain, &registry, &unregistered);
        assert_eq!(postures.len(), 1);
        assert!(postures[0].has(GovernanceFacet::Registered));
        assert!(!postures[0].has(GovernanceFacet::Unregistered));
    }

    #[test]
    fn facet_summary_format() {
        let posture = ToolGovernancePosture {
            tool_name: "test".into(),
            facets: [GovernanceFacet::Registered, GovernanceFacet::Provisioned]
                .into_iter()
                .collect(),
            computed_at: Utc::now(),
        };
        assert_eq!(posture.summary(), "provisioned, registered");
        assert_eq!(posture.level(), 3);
    }

    #[test]
    fn empty_facets_summary() {
        let posture = ToolGovernancePosture {
            tool_name: "test".into(),
            facets: HashSet::new(),
            computed_at: Utc::now(),
        };
        assert_eq!(posture.summary(), "unknown");
        assert_eq!(posture.level(), 0);
    }
}
