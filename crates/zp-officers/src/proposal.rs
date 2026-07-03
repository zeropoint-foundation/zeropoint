//! Structured proposals — Band 2 officer output.
//!
//! A proposal wraps a finding with an actionable mutation: a machine-readable
//! description of what the officer thinks should change. The operator reviews
//! proposals and signs the ones they approve. Execution happens downstream —
//! proposals are data, not function calls.
//!
//! See `docs/design/TOOL-GOVERNANCE-LIFECYCLE-2026-07.md` §2 (Band 2).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::finding::Finding;

/// A structured proposal emitted by an officer.
///
/// Combines the diagnostic (finding) with the prescription (mutation).
/// The operator sees both: "here's what's wrong" + "here's the fix."
/// Signing the proposal authorizes the mutation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// The underlying finding that motivated this proposal.
    pub finding: Finding,
    /// The mutation the officer proposes.
    pub mutation: ProposedMutation,
    /// Which officer proposed this.
    pub proposed_by: &'static str,
    /// When the proposal was created.
    pub proposed_at: DateTime<Utc>,
    /// Proposal status — starts as Pending.
    pub status: ProposalStatus,
}

impl Proposal {
    /// Create a new pending proposal from a finding and mutation.
    pub fn new(finding: Finding, mutation: ProposedMutation, officer: &'static str) -> Self {
        Self {
            finding,
            mutation,
            proposed_by: officer,
            proposed_at: Utc::now(),
            status: ProposalStatus::Pending,
        }
    }

    /// Chain event string for the proposal receipt.
    /// Format: `proposal:{officer}:{mutation_kind}:{tool}`
    pub fn event_key(&self) -> String {
        format!(
            "proposal:{}:{}:{}",
            self.proposed_by,
            self.mutation.kind_label(),
            self.mutation.tool_name(),
        )
    }
}

/// What the officer thinks should change.
///
/// Each variant is a complete, self-contained mutation description.
/// The operator can read it, understand the change, and sign or dismiss.
/// No variant performs side effects — they're pure data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProposedMutation {
    /// Set or correct a tool's port binding in the registry.
    SetPortBinding {
        tool: String,
        port: u16,
        /// Why this port (e.g., "observed on process 12345").
        rationale: String,
    },

    /// Fill a missing vault entry for a tool.
    FillVaultEntry {
        tool: String,
        /// Vault key path (e.g., "tools/ironclaw/API_KEY").
        key_path: String,
        /// What the entry is for (from manifest schema).
        description: String,
    },

    /// Grant a minimal delegation to a tool.
    GrantDelegation {
        tool: String,
        /// Proposed capability scopes (e.g., ["tool:exec:ironclaw"]).
        scopes: Vec<String>,
        /// Why this delegation is needed.
        rationale: String,
    },

    /// Update a tool's manifest to match observed behavior.
    UpdateManifest {
        tool: String,
        /// Which field to update (e.g., "port_env_var").
        field: String,
        /// Proposed new value.
        value: String,
        /// What was observed that motivated the change.
        observed: String,
    },

    /// Restart a tool (clean stop + governed relaunch).
    RestartTool {
        tool: String,
        /// Why a restart is proposed (e.g., "crash loop: 5 launches in 10 min").
        rationale: String,
    },
}

impl ProposedMutation {
    /// Machine-readable kind label for chain receipts.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::SetPortBinding { .. } => "set_port",
            Self::FillVaultEntry { .. } => "fill_vault",
            Self::GrantDelegation { .. } => "grant_delegation",
            Self::UpdateManifest { .. } => "update_manifest",
            Self::RestartTool { .. } => "restart_tool",
        }
    }

    /// Which tool this mutation targets.
    pub fn tool_name(&self) -> &str {
        match self {
            Self::SetPortBinding { tool, .. }
            | Self::FillVaultEntry { tool, .. }
            | Self::GrantDelegation { tool, .. }
            | Self::UpdateManifest { tool, .. }
            | Self::RestartTool { tool, .. } => tool,
        }
    }

    /// Human-readable summary for operator review.
    pub fn summary(&self) -> String {
        match self {
            Self::SetPortBinding { tool, port, rationale } => {
                format!("Set {}'s port binding to {} ({})", tool, port, rationale)
            }
            Self::FillVaultEntry { tool, key_path, description } => {
                format!("Add vault entry {} for {} ({})", key_path, tool, description)
            }
            Self::GrantDelegation { tool, scopes, .. } => {
                format!("Grant delegation to {}: [{}]", tool, scopes.join(", "))
            }
            Self::UpdateManifest { tool, field, value, .. } => {
                format!("Update {}'s manifest: {} = {}", tool, field, value)
            }
            Self::RestartTool { tool, rationale } => {
                format!("Restart {} ({})", tool, rationale)
            }
        }
    }
}

/// Lifecycle status of a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalStatus {
    /// Awaiting operator review.
    Pending,
    /// Operator approved and signed.
    Approved,
    /// Operator dismissed.
    Dismissed,
    /// Superseded by a newer proposal for the same target.
    Superseded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use serde_json::json;

    fn test_finding() -> Finding {
        Finding {
            officer: "forge",
            domain: "operations",
            finding_type: "port_mismatch".into(),
            severity: Severity::Warning,
            summary: "IronClaw port mismatch".into(),
            detail: json!({"expected": 9101, "actual": 8090}),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        }
    }

    #[test]
    fn proposal_event_key() {
        let p = Proposal::new(
            test_finding(),
            ProposedMutation::SetPortBinding {
                tool: "ironclaw".into(),
                port: 8090,
                rationale: "observed on PID 12345".into(),
            },
            "forge",
        );
        assert_eq!(p.event_key(), "proposal:forge:set_port:ironclaw");
        assert_eq!(p.status, ProposalStatus::Pending);
    }

    #[test]
    fn mutation_summary() {
        let m = ProposedMutation::RestartTool {
            tool: "ironclaw".into(),
            rationale: "crash loop: 5 launches in 10 min".into(),
        };
        assert_eq!(m.kind_label(), "restart_tool");
        assert_eq!(m.tool_name(), "ironclaw");
        assert!(m.summary().contains("Restart ironclaw"));
    }

    #[test]
    fn mutation_serde_round_trip() {
        let m = ProposedMutation::GrantDelegation {
            tool: "ironclaw".into(),
            scopes: vec!["tool:exec:ironclaw".into()],
            rationale: "new tool needs execution scope".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: ProposedMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.kind_label(), "grant_delegation");
        assert_eq!(m2.tool_name(), "ironclaw");
    }

    #[test]
    fn all_mutation_kinds() {
        let mutations = vec![
            ProposedMutation::SetPortBinding {
                tool: "t".into(), port: 8080, rationale: "r".into(),
            },
            ProposedMutation::FillVaultEntry {
                tool: "t".into(), key_path: "k".into(), description: "d".into(),
            },
            ProposedMutation::GrantDelegation {
                tool: "t".into(), scopes: vec![], rationale: "r".into(),
            },
            ProposedMutation::UpdateManifest {
                tool: "t".into(), field: "f".into(), value: "v".into(), observed: "o".into(),
            },
            ProposedMutation::RestartTool {
                tool: "t".into(), rationale: "r".into(),
            },
        ];

        let labels: Vec<&str> = mutations.iter().map(|m| m.kind_label()).collect();
        assert_eq!(
            labels,
            vec!["set_port", "fill_vault", "grant_delegation", "update_manifest", "restart_tool"]
        );

        // All point to tool "t".
        for m in &mutations {
            assert_eq!(m.tool_name(), "t");
        }
    }
}
