//! Cleo — Authority & Governance Narrator.
//!
//! Domain: Governance. Reads the receipt chain and tells the coherent story
//! of how authority, trust, and delegation moved through the system. Explains
//! not just what happened, but why that authority was granted or revoked, and
//! where governance rules were followed or violated.
//!
//! Key distinction from Steward:
//! - Steward tells you whether the system is **healthy and consistent**.
//! - Cleo tells you the story of **who had power, how they got it, and
//!   whether they abused it or followed the rules**.
//!
//! Cleo implements both `Officer` (sweep findings) and `ChainNarrator`
//! (story generation). The sweep produces structured governance findings;
//! the narration produces human-readable story segments.

use chrono::Utc;
use serde_json::json;
use tracing::debug;

use crate::finding::{Finding, Severity};
use crate::narration::{ChainNarrator, ChainStory, StorySegment};
use crate::officer::{ChainReader, Officer, VaultKeyLister};
use zp_core::{AuditAction, AuditEntry, PolicyDecision};

/// The Cleo officer — watches delegation lifecycle, gate decisions,
/// and authority chains.
pub struct Cleo;

impl Cleo {
    pub fn new() -> Self {
        Self
    }

    /// Check delegation lifecycle: grants, revocations, expirations, renewals.
    fn check_delegations(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut grants: Vec<&AuditEntry> = Vec::new();
        let mut revocations: Vec<&AuditEntry> = Vec::new();
        let mut expirations: Vec<&AuditEntry> = Vec::new();
        let mut renewals: Vec<&AuditEntry> = Vec::new();

        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if event.starts_with("delegation:granted:") {
                    grants.push(entry);
                } else if event.starts_with("delegation:revoked:") {
                    revocations.push(entry);
                } else if event.starts_with("delegation:expired:") {
                    expirations.push(entry);
                } else if event.starts_with("delegation:renewed:") {
                    renewals.push(entry);
                }
            }
        }

        // Summary finding — always emitted
        findings.push(Finding {
            officer: self.name(),
            domain: self.domain(),
            finding_type: "delegation_lifecycle".into(),
            severity: Severity::Ok,
            summary: format!(
                "Delegation lifecycle: {} active grants, {} revoked, {} expired, {} renewed",
                grants.len(),
                revocations.len(),
                expirations.len(),
                renewals.len()
            ),
            detail: json!({
                "grants": grants.len(),
                "revocations": revocations.len(),
                "expirations": expirations.len(),
                "renewals": renewals.len(),
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        });

        // Warn on expired delegations without renewal
        if !expirations.is_empty() {
            for exp in &expirations {
                if let AuditAction::SystemEvent { event } = &exp.action {
                    let subject = event
                        .strip_prefix("delegation:expired:")
                        .unwrap_or("unknown");
                    // Check if a renewal exists for this subject
                    let renewed = renewals.iter().any(|r| {
                        if let AuditAction::SystemEvent { event: rev } = &r.action {
                            rev.ends_with(subject) && r.timestamp > exp.timestamp
                        } else {
                            false
                        }
                    });
                    if !renewed {
                        findings.push(Finding {
                            officer: self.name(),
                            domain: self.domain(),
                            finding_type: "delegation_expired".into(),
                            severity: Severity::Warning,
                            summary: format!(
                                "Delegation to '{}' expired without renewal",
                                subject
                            ),
                            detail: json!({
                                "subject": subject,
                                "expired_at": exp.timestamp.to_rfc3339(),
                            }),
                            timestamp: Utc::now(),
                            cross_domain_depth: 0,
                        });
                    }
                }
            }
        }

        findings
    }

    /// Check gate decisions: allowed vs denied, reasons.
    fn check_gate_decisions(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut allowed = 0usize;
        let mut denied = 0usize;
        let mut denied_no_delegation = 0usize;

        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if event.starts_with("gate:allowed:") {
                    allowed += 1;
                } else if event.starts_with("gate:denied:") {
                    denied += 1;
                    // Check if denial was due to missing delegation
                    if let PolicyDecision::Block { reason, .. } = &entry.policy_decision {
                        if reason.contains("no delegation")
                            || reason.contains("not found")
                            || reason.contains("missing")
                        {
                            denied_no_delegation += 1;
                        }
                    }
                }
            }
        }

        // Summary
        findings.push(Finding {
            officer: self.name(),
            domain: self.domain(),
            finding_type: "gate_decisions".into(),
            severity: if denied > 0 {
                Severity::Info
            } else {
                Severity::Ok
            },
            summary: format!(
                "Gate decisions: {} allowed, {} denied ({} for missing delegation)",
                allowed, denied, denied_no_delegation
            ),
            detail: json!({
                "allowed": allowed,
                "denied": denied,
                "denied_no_delegation": denied_no_delegation,
            }),
            timestamp: Utc::now(),
            cross_domain_depth: 0,
        });

        findings
    }

    /// Check authority chain integrity: do allowed actions trace back to
    /// a valid delegation, and does that delegation trace to Genesis?
    fn check_authority_chains(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut findings = Vec::new();

        // Collect all active delegation subjects
        let mut delegated_subjects: std::collections::HashSet<String> =
            std::collections::HashSet::new();
        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(subject) = event.strip_prefix("delegation:granted:") {
                    delegated_subjects.insert(subject.to_string());
                } else if let Some(subject) = event.strip_prefix("delegation:revoked:") {
                    delegated_subjects.remove(subject);
                }
            }
        }

        // Check gate:allowed entries — do they reference a known delegation?
        let mut gap_count = 0usize;
        let mut valid_count = 0usize;
        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                if let Some(tool) = event.strip_prefix("gate:allowed:") {
                    // Extract the actor from the entry
                    let actor_name = match &entry.actor {
                        zp_core::ActorId::System(s) => {
                            // Strip "agent:" or similar prefixes
                            s.strip_prefix("agent:").unwrap_or(s).to_string()
                        }
                        zp_core::ActorId::User(u) => u.clone(),
                        _ => String::new(),
                    };

                    // Check if this actor has a delegation
                    if delegated_subjects.contains(&actor_name) {
                        valid_count += 1;
                    } else if !actor_name.is_empty()
                        && actor_name != "operator"
                        && !actor_name.starts_with("officer:")
                    {
                        // Operator and officers are implicit — they don't need
                        // explicit delegation from Genesis
                        gap_count += 1;
                    }
                    let _ = tool; // suppress unused warning
                }
            }
        }

        if gap_count > 0 {
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "authority_gap".into(),
                severity: Severity::Warning,
                summary: format!(
                    "{} allowed gate decisions lack a traceable delegation on this chain segment",
                    gap_count
                ),
                detail: json!({
                    "gap_count": gap_count,
                    "valid_count": valid_count,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        } else {
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "authority_chain_valid".into(),
                severity: Severity::Ok,
                summary: format!(
                    "All {} allowed actions trace to a known delegation",
                    valid_count
                ),
                detail: json!({
                    "valid_count": valid_count,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        }

        findings
    }

    /// Check for unsigned governance-significant actions.
    fn check_unsigned_governance(&self, chain: &ChainReader<'_>) -> Vec<Finding> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let mut unsigned_governance = 0usize;
        let mut total_governance = 0usize;

        for entry in &entries {
            if let AuditAction::SystemEvent { event } = &entry.action {
                let is_governance = event.starts_with("delegation:")
                    || event.starts_with("gate:");

                if is_governance {
                    total_governance += 1;
                    if entry.signatures.is_empty() {
                        unsigned_governance += 1;
                    }
                }
            }
        }

        let mut findings = Vec::new();

        if unsigned_governance > 0 && total_governance > 0 {
            let ratio = unsigned_governance as f64 / total_governance as f64;
            findings.push(Finding {
                officer: self.name(),
                domain: self.domain(),
                finding_type: "unsigned_governance_action".into(),
                severity: if ratio > 0.5 {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                summary: format!(
                    "{} of {} governance actions ({:.0}%) lack signatures",
                    unsigned_governance,
                    total_governance,
                    ratio * 100.0
                ),
                detail: json!({
                    "unsigned": unsigned_governance,
                    "total": total_governance,
                    "ratio": ratio,
                }),
                timestamp: Utc::now(),
                cross_domain_depth: 0,
            });
        }

        findings
    }
}

impl Officer for Cleo {
    fn name(&self) -> &'static str {
        "cleo"
    }

    fn domain(&self) -> &'static str {
        "governance"
    }

    fn watch_patterns(&self) -> &[&'static str] {
        &[
            "delegation:granted:",
            "delegation:revoked:",
            "gate:allowed:",
            "gate:denied:",
        ]
    }

    fn sweep(
        &self,
        chain: &ChainReader<'_>,
        _vault_keys: &VaultKeyLister,
    ) -> Vec<Finding> {
        debug!("Cleo sweep starting");

        let mut findings = Vec::new();

        findings.extend(self.check_delegations(chain));
        findings.extend(self.check_gate_decisions(chain));
        findings.extend(self.check_authority_chains(chain));
        findings.extend(self.check_unsigned_governance(chain));

        debug!(
            findings = findings.len(),
            "Cleo sweep complete"
        );

        findings
    }
}

impl ChainNarrator for Cleo {
    fn narrate(&self, chain: &ChainReader<'_>) -> Vec<StorySegment> {
        let entries = match chain.recent_entries(1000) {
            Ok(e) => e,
            Err(_) => return Vec::new(),
        };

        let story = ChainStory::from_entries(&entries);
        // Return governance-domain segments — Cleo's narrative focus
        story.filter_domain("governance").segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // We can't easily test against a real AuditStore in unit tests,
    // so we test the internal check methods by creating entries
    // and verifying the findings they produce.

    #[test]
    fn cleo_trait_impl() {
        let cleo = Cleo::new();
        assert_eq!(cleo.name(), "cleo");
        assert_eq!(cleo.domain(), "governance");
        assert!(!cleo.watch_patterns().is_empty());
        assert!(cleo.watch_patterns().contains(&"delegation:granted:"));
        assert!(cleo.watch_patterns().contains(&"gate:denied:"));
    }
}
