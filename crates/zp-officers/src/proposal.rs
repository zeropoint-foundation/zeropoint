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
            Self::SetPortBinding {
                tool,
                port,
                rationale,
            } => {
                format!("Set {}'s port binding to {} ({})", tool, port, rationale)
            }
            Self::FillVaultEntry {
                tool,
                key_path,
                description,
            } => {
                format!(
                    "Add vault entry {} for {} ({})",
                    key_path, tool, description
                )
            }
            Self::GrantDelegation { tool, scopes, .. } => {
                format!("Grant delegation to {}: [{}]", tool, scopes.join(", "))
            }
            Self::UpdateManifest {
                tool, field, value, ..
            } => {
                format!("Update {}'s manifest: {} = {}", tool, field, value)
            }
            Self::RestartTool { tool, rationale } => {
                format!("Restart {} ({})", tool, rationale)
            }
        }
    }
}

// ── Governance capability scope vocabulary ──────────────────────────────
//
// Officers propose mutations; the operator grants proposal authority via
// delegation receipts. The scope vocabulary maps 1:1 to ProposedMutation
// variants — no upfront enumeration beyond what the observer actually needs.
//
// A delegation receipt with `GrantedCapability::Custom { name: GOVERNANCE_PROPOSE_CAPABILITY }`
// and `parameters: { "mutations": ["restart_tool", "set_port"] }` grants the
// officer the right to emit proposals of those specific kinds.
// `"mutations": ["*"]` grants all proposal kinds.

/// The capability name for governance proposal authority.
///
/// Used in `GrantedCapability::Custom { name, parameters }` delegation grants.
/// Officers check this to determine whether they're authorized to emit proposals.
pub const GOVERNANCE_PROPOSE_CAPABILITY: &str = "governance:propose";

/// All valid mutation scope strings, one per `ProposedMutation` variant.
pub const GOVERNANCE_MUTATION_SCOPES: &[&str] = &[
    "set_port",
    "fill_vault",
    "grant_delegation",
    "update_manifest",
    "restart_tool",
];

/// Check whether a `CapabilityGrant` authorizes a specific proposal mutation kind.
///
/// The grant must be:
/// 1. A `Custom` capability with name == `GOVERNANCE_PROPOSE_CAPABILITY`
/// 2. Have a `parameters.mutations` array that contains the mutation's `kind_label()`
///    or the wildcard `"*"`.
/// 3. Not expired.
pub fn grant_authorizes_mutation(grant: &zp_core::CapabilityGrant, mutation_kind: &str) -> bool {
    // Check expiry.
    if let Some(expires) = grant.expires_at {
        if expires < chrono::Utc::now() {
            return false;
        }
    }

    // Must be a Custom capability with the right name.
    let params = match &grant.capability {
        zp_core::GrantedCapability::Custom { name, parameters }
            if name == GOVERNANCE_PROPOSE_CAPABILITY =>
        {
            parameters
        }
        _ => return false,
    };

    // Check the mutations array in parameters.
    let mutations = match params.get("mutations").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return false,
    };

    mutations.iter().any(|v| {
        v.as_str()
            .map(|s| s == "*" || s == mutation_kind)
            .unwrap_or(false)
    })
}

/// Read-only view of an officer's governance delegation.
///
/// Constructed from chain delegation receipts by the sweep runner.
/// Officers use this to check whether they're authorized to propose
/// specific mutation kinds.
#[derive(Debug, Clone)]
pub struct OfficerDelegation {
    /// Mutation kinds this officer is authorized to propose.
    /// Empty = no proposal authority. Contains "*" = all kinds.
    authorized_mutations: Vec<String>,
}

impl OfficerDelegation {
    /// No delegation — officer can observe but not propose.
    pub fn none() -> Self {
        Self {
            authorized_mutations: Vec::new(),
        }
    }

    /// Build from a list of capability grants for this officer.
    ///
    /// Scans grants for `governance:propose` custom capabilities,
    /// collects all authorized mutation kinds.
    pub fn from_grants(grants: &[zp_core::CapabilityGrant]) -> Self {
        let mut mutations = Vec::new();
        for grant in grants {
            // Skip expired grants.
            if let Some(expires) = grant.expires_at {
                if expires < chrono::Utc::now() {
                    continue;
                }
            }
            if let zp_core::GrantedCapability::Custom { name, parameters } = &grant.capability {
                if name != GOVERNANCE_PROPOSE_CAPABILITY {
                    continue;
                }
                if let Some(arr) = parameters.get("mutations").and_then(|v| v.as_array()) {
                    for v in arr {
                        if let Some(s) = v.as_str() {
                            if !mutations.contains(&s.to_string()) {
                                mutations.push(s.to_string());
                            }
                        }
                    }
                }
            }
        }
        Self {
            authorized_mutations: mutations,
        }
    }

    /// Check if this delegation authorizes a specific mutation kind.
    pub fn can_propose(&self, mutation_kind: &str) -> bool {
        self.authorized_mutations
            .iter()
            .any(|s| s == "*" || s == mutation_kind)
    }

    /// Check if this officer has any proposal authority at all.
    pub fn has_any_authority(&self) -> bool {
        !self.authorized_mutations.is_empty()
    }

    /// The mutation kinds this officer is authorized to propose.
    pub fn authorized_mutations(&self) -> &[String] {
        &self.authorized_mutations
    }

    /// Filter a list of proposals, keeping only those this delegation authorizes.
    pub fn filter_proposals(&self, proposals: Vec<Proposal>) -> Vec<Proposal> {
        proposals
            .into_iter()
            .filter(|p| self.can_propose(p.mutation.kind_label()))
            .collect()
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
            summary: "ExampleTool port mismatch".into(),
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
                tool: "example-tool".into(),
                port: 8090,
                rationale: "observed on PID 12345".into(),
            },
            "forge",
        );
        assert_eq!(p.event_key(), "proposal:forge:set_port:example-tool");
        assert_eq!(p.status, ProposalStatus::Pending);
    }

    #[test]
    fn mutation_summary() {
        let m = ProposedMutation::RestartTool {
            tool: "example-tool".into(),
            rationale: "crash loop: 5 launches in 10 min".into(),
        };
        assert_eq!(m.kind_label(), "restart_tool");
        assert_eq!(m.tool_name(), "example-tool");
        assert!(m.summary().contains("Restart example-tool"));
    }

    #[test]
    fn mutation_serde_round_trip() {
        let m = ProposedMutation::GrantDelegation {
            tool: "example-tool".into(),
            scopes: vec!["tool:exec:example-tool".into()],
            rationale: "new tool needs execution scope".into(),
        };
        let json = serde_json::to_string(&m).unwrap();
        let m2: ProposedMutation = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.kind_label(), "grant_delegation");
        assert_eq!(m2.tool_name(), "example-tool");
    }

    #[test]
    fn all_mutation_kinds() {
        let mutations = vec![
            ProposedMutation::SetPortBinding {
                tool: "t".into(),
                port: 8080,
                rationale: "r".into(),
            },
            ProposedMutation::FillVaultEntry {
                tool: "t".into(),
                key_path: "k".into(),
                description: "d".into(),
            },
            ProposedMutation::GrantDelegation {
                tool: "t".into(),
                scopes: vec![],
                rationale: "r".into(),
            },
            ProposedMutation::UpdateManifest {
                tool: "t".into(),
                field: "f".into(),
                value: "v".into(),
                observed: "o".into(),
            },
            ProposedMutation::RestartTool {
                tool: "t".into(),
                rationale: "r".into(),
            },
        ];

        let labels: Vec<&str> = mutations.iter().map(|m| m.kind_label()).collect();
        assert_eq!(
            labels,
            vec![
                "set_port",
                "fill_vault",
                "grant_delegation",
                "update_manifest",
                "restart_tool"
            ]
        );

        // All point to tool "t".
        for m in &mutations {
            assert_eq!(m.tool_name(), "t");
        }
    }

    // ── Governance capability scope tests ────────────────────────────

    #[test]
    fn mutation_scopes_match_kind_labels() {
        // Every kind_label() must appear in GOVERNANCE_MUTATION_SCOPES.
        let mutations = vec![
            ProposedMutation::SetPortBinding {
                tool: "t".into(),
                port: 8080,
                rationale: "r".into(),
            },
            ProposedMutation::FillVaultEntry {
                tool: "t".into(),
                key_path: "k".into(),
                description: "d".into(),
            },
            ProposedMutation::GrantDelegation {
                tool: "t".into(),
                scopes: vec![],
                rationale: "r".into(),
            },
            ProposedMutation::UpdateManifest {
                tool: "t".into(),
                field: "f".into(),
                value: "v".into(),
                observed: "o".into(),
            },
            ProposedMutation::RestartTool {
                tool: "t".into(),
                rationale: "r".into(),
            },
        ];
        for m in &mutations {
            assert!(
                GOVERNANCE_MUTATION_SCOPES.contains(&m.kind_label()),
                "kind_label '{}' missing from GOVERNANCE_MUTATION_SCOPES",
                m.kind_label()
            );
        }
        // And the count matches — no stale entries.
        assert_eq!(GOVERNANCE_MUTATION_SCOPES.len(), mutations.len());
    }

    fn make_governance_grant(mutations: Vec<&str>) -> zp_core::CapabilityGrant {
        zp_core::CapabilityGrant {
            id: "grant-test".into(),
            capability: zp_core::GrantedCapability::Custom {
                name: GOVERNANCE_PROPOSE_CAPABILITY.into(),
                parameters: json!({ "mutations": mutations }),
            },
            constraints: vec![],
            grantor: "operator".into(),
            grantee: "forge".into(),
            trust_tier: zp_core::policy::TrustTier::Tier0,
            created_at: Utc::now(),
            expires_at: None,
            receipt_id: "receipt-test".into(),
            signature: None,
            signer_public_key: None,
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            provenance: Default::default(),
            issued_via: None,
            lease_policy: None,
            renewal_authorities: vec![],
            revocable_by: vec![],
            redelegation: Default::default(),
            revocation_anchor: None,
            last_renewed_at: None,
            renewal_count: 0,
            renews: None,
            grantee_type: None,
            task_description: None,
            context_receipts: vec![],
            subject_public_key: None,
        }
    }

    #[test]
    fn grant_authorizes_specific_mutation() {
        let grant = make_governance_grant(vec!["restart_tool", "set_port"]);
        assert!(grant_authorizes_mutation(&grant, "restart_tool"));
        assert!(grant_authorizes_mutation(&grant, "set_port"));
        assert!(!grant_authorizes_mutation(&grant, "fill_vault"));
        assert!(!grant_authorizes_mutation(&grant, "grant_delegation"));
    }

    #[test]
    fn grant_wildcard_authorizes_all() {
        let grant = make_governance_grant(vec!["*"]);
        for scope in GOVERNANCE_MUTATION_SCOPES {
            assert!(grant_authorizes_mutation(&grant, scope));
        }
    }

    #[test]
    fn expired_grant_rejected() {
        let mut grant = make_governance_grant(vec!["*"]);
        grant.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        assert!(!grant_authorizes_mutation(&grant, "restart_tool"));
    }

    #[test]
    fn wrong_capability_name_rejected() {
        let grant = zp_core::CapabilityGrant {
            id: "grant-test".into(),
            capability: zp_core::GrantedCapability::Custom {
                name: "some_other_cap".into(),
                parameters: json!({ "mutations": ["*"] }),
            },
            constraints: vec![],
            grantor: "operator".into(),
            grantee: "forge".into(),
            trust_tier: zp_core::policy::TrustTier::Tier0,
            created_at: Utc::now(),
            expires_at: None,
            receipt_id: "receipt-test".into(),
            signature: None,
            signer_public_key: None,
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 0,
            provenance: Default::default(),
            issued_via: None,
            lease_policy: None,
            renewal_authorities: vec![],
            revocable_by: vec![],
            redelegation: Default::default(),
            revocation_anchor: None,
            last_renewed_at: None,
            renewal_count: 0,
            renews: None,
            grantee_type: None,
            task_description: None,
            context_receipts: vec![],
            subject_public_key: None,
        };
        assert!(!grant_authorizes_mutation(&grant, "restart_tool"));
    }

    #[test]
    fn officer_delegation_none() {
        let d = OfficerDelegation::none();
        assert!(!d.has_any_authority());
        assert!(!d.can_propose("restart_tool"));
    }

    #[test]
    fn officer_delegation_from_grants() {
        let grants = vec![make_governance_grant(vec!["restart_tool", "set_port"])];
        let d = OfficerDelegation::from_grants(&grants);
        assert!(d.has_any_authority());
        assert!(d.can_propose("restart_tool"));
        assert!(d.can_propose("set_port"));
        assert!(!d.can_propose("fill_vault"));
    }

    #[test]
    fn officer_delegation_wildcard() {
        let grants = vec![make_governance_grant(vec!["*"])];
        let d = OfficerDelegation::from_grants(&grants);
        assert!(d.has_any_authority());
        for scope in GOVERNANCE_MUTATION_SCOPES {
            assert!(d.can_propose(scope));
        }
    }

    #[test]
    fn officer_delegation_filters_proposals() {
        let grants = vec![make_governance_grant(vec!["restart_tool"])];
        let d = OfficerDelegation::from_grants(&grants);

        let proposals = vec![
            Proposal::new(
                test_finding(),
                ProposedMutation::RestartTool {
                    tool: "example-tool".into(),
                    rationale: "crash loop".into(),
                },
                "forge",
            ),
            Proposal::new(
                test_finding(),
                ProposedMutation::SetPortBinding {
                    tool: "example-tool".into(),
                    port: 8090,
                    rationale: "observed".into(),
                },
                "forge",
            ),
        ];

        let filtered = d.filter_proposals(proposals);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].mutation.kind_label(), "restart_tool");
    }

    #[test]
    fn officer_delegation_skips_expired() {
        let mut grant = make_governance_grant(vec!["restart_tool"]);
        grant.expires_at = Some(Utc::now() - chrono::Duration::hours(1));
        let d = OfficerDelegation::from_grants(&[grant]);
        assert!(!d.has_any_authority());
    }
}
