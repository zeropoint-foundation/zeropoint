//! Bridge between governance events and the observation pipeline.
//!
//! Converts significant governance events into observation candidates that
//! feed into the memory promotion lifecycle. This implements the doctrine
//! requirement that "repeated patterns of governance decisions become
//! observations, which can be promoted through the memory lifecycle."
//!
//! Added in Phase 2.7 (M4-2).
//!
//! ## Design decisions
//!
//! **Conservative by default:** Only violations and anomalies generate
//! observations. Routine events (guard evaluations, health checks) are
//! skipped to avoid flooding the observation store. Operators can extend
//! the mapping via the `custom_filter` parameter.
//!
//! **Priority mapping:** Governance severity maps directly to observation
//! priority — policy violations are High, reputation changes are Medium,
//! routine operations are skipped entirely.

use chrono::Utc;
use zp_core::governance::{GovernanceDecision, GovernanceEvent, GovernanceEventType};

use crate::types::{Observation, ObservationPriority, SourceRange};

/// A candidate observation produced from a governance event.
///
/// This is the output of the bridge — ready to be ingested into the
/// observation store and enter the memory promotion pipeline.
#[derive(Debug, Clone)]
pub struct ObservationCandidate {
    /// Human-readable observation content.
    pub content: String,
    /// Priority for retention during reflection.
    pub priority: ObservationPriority,
    /// Category for grouping (always "governance" for bridge-produced observations).
    pub category: String,
    /// The governance event ID that produced this candidate.
    pub source_event_id: String,
}

/// Convert a governance event into an observation candidate.
///
/// Returns `None` for routine events that don't warrant memory retention.
/// The mapping is intentionally conservative: only violations, rejections,
/// and anomalies produce observations.
pub fn event_to_observation(event: &GovernanceEvent) -> Option<ObservationCandidate> {
    match &event.event_type {
        // === HIGH priority: security-relevant events ===

        GovernanceEventType::PolicyTierViolation => Some(ObservationCandidate {
            content: format!(
                "Policy tier violation by {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::High,
            category: "governance.violation".to_string(),
            source_event_id: event.id.clone(),
        }),

        GovernanceEventType::DelegationRejected => Some(ObservationCandidate {
            content: format!(
                "Delegation rejected for {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::High,
            category: "governance.violation".to_string(),
            source_event_id: event.id.clone(),
        }),

        GovernanceEventType::CapabilityRevoked => Some(ObservationCandidate {
            content: format!(
                "Capability revoked for {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::High,
            category: "governance.revocation".to_string(),
            source_event_id: event.id.clone(),
        }),

        GovernanceEventType::ReputationGateBlocked => Some(ObservationCandidate {
            content: format!(
                "Reputation gate blocked action by {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::High,
            category: "governance.reputation".to_string(),
            source_event_id: event.id.clone(),
        }),

        // === MEDIUM priority: notable but not security-critical ===

        GovernanceEventType::ReputationComputed => Some(ObservationCandidate {
            content: format!(
                "Reputation updated for {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::Medium,
            category: "governance.reputation".to_string(),
            source_event_id: event.id.clone(),
        }),

        GovernanceEventType::Escalation => Some(ObservationCandidate {
            content: format!(
                "Action escalated for {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::Medium,
            category: "governance.escalation".to_string(),
            source_event_id: event.id.clone(),
        }),

        GovernanceEventType::ReputationGateReview => Some(ObservationCandidate {
            content: format!(
                "Reputation gate requires review for {}: {}",
                format_actor(&event.actor),
                format_decision(&event.decision)
            ),
            priority: ObservationPriority::Medium,
            category: "governance.reputation".to_string(),
            source_event_id: event.id.clone(),
        }),

        GovernanceEventType::LinkSevered => Some(ObservationCandidate {
            content: format!(
                "Peer link severed with {}",
                format_actor(&event.actor),
            ),
            priority: ObservationPriority::Medium,
            category: "governance.mesh".to_string(),
            source_event_id: event.id.clone(),
        }),

        // Policy evaluation results that block actions are noteworthy
        GovernanceEventType::PolicyEvaluation
            if matches!(&event.decision, GovernanceDecision::Block { .. }) =>
        {
            Some(ObservationCandidate {
                content: format!(
                    "Policy blocked action by {}: {}",
                    format_actor(&event.actor),
                    format_decision(&event.decision)
                ),
                priority: ObservationPriority::Medium,
                category: "governance.policy".to_string(),
                source_event_id: event.id.clone(),
            })
        }

        // === SKIP: routine operations ===
        GovernanceEventType::GuardEvaluation
        | GovernanceEventType::PolicyEvaluation
        | GovernanceEventType::CapabilityGranted
        | GovernanceEventType::CapabilityDelegated
        | GovernanceEventType::ConsensusRequested
        | GovernanceEventType::ConsensusReached
        | GovernanceEventType::LinkEstablished
        | GovernanceEventType::PolicyAdvertised
        | GovernanceEventType::PolicyRequested
        | GovernanceEventType::PolicyTransferCompleted
        | GovernanceEventType::PolicyAgreementReached
        | GovernanceEventType::DelegationChainVerified
        | GovernanceEventType::AuditChallenged
        | GovernanceEventType::AuditResponseVerified
        | GovernanceEventType::PeerAuditVerified
        | GovernanceEventType::ReputationBroadcast
        | GovernanceEventType::ReputationReceived
        | GovernanceEventType::ReceiptForwarded
        | GovernanceEventType::ReceiptReceivedFromMesh
        | GovernanceEventType::MeshBridgeEstablished
        | GovernanceEventType::ReputationGateAllowed => None,
    }
}

/// Convert a batch of governance events into observations, filtering out
/// routine events and producing only the observation-worthy ones.
pub fn bridge_events(events: &[GovernanceEvent]) -> Vec<ObservationCandidate> {
    events.iter().filter_map(event_to_observation).collect()
}

/// Convert an `ObservationCandidate` into a full `Observation` with a
/// synthetic source range derived from the governance event ID.
pub fn candidate_to_observation(candidate: &ObservationCandidate) -> Observation {
    let now = Utc::now();
    let source_hash = blake3::hash(candidate.source_event_id.as_bytes())
        .to_hex()
        .to_string();

    Observation {
        id: format!("obs-gov-{}", uuid::Uuid::now_v7()),
        content: candidate.content.clone(),
        priority: candidate.priority,
        category: candidate.category.clone(),
        referenced_at: now,
        observed_at: now,
        relative_time: Some("just now".to_string()),
        source_range: SourceRange::new(
            "governance",
            &source_hash,
            &source_hash,
            0,
            0,
        ),
        superseded: false,
        token_estimate: Observation::estimate_tokens(&candidate.content),
        receipt_id: None,
    }
}

// ============================================================================
// Internal helpers
// ============================================================================

fn format_actor(actor: &zp_core::governance::GovernanceActor) -> String {
    match actor {
        zp_core::governance::GovernanceActor::Human { id } => format!("user:{}", id),
        zp_core::governance::GovernanceActor::Agent {
            destination_hash,
            trust_tier,
        } => format!("agent:{}(tier-{})", &destination_hash[..8.min(destination_hash.len())], trust_tier),
        zp_core::governance::GovernanceActor::System { component } => {
            format!("system:{}", component)
        }
    }
}

fn format_decision(decision: &GovernanceDecision) -> String {
    match decision {
        GovernanceDecision::Allow { conditions } => {
            if conditions.is_empty() {
                "allowed".to_string()
            } else {
                format!("allowed with conditions: {}", conditions.join(", "))
            }
        }
        GovernanceDecision::AllowWithConstraints {
            grant_id,
            applied_constraints,
        } => format!(
            "allowed via grant {} (constraints: {})",
            grant_id,
            applied_constraints.join(", ")
        ),
        GovernanceDecision::Block { reason, authority } => {
            format!("blocked by {}: {}", authority, reason)
        }
        GovernanceDecision::Escalate { reason, .. } => {
            format!("escalated: {}", reason)
        }
        GovernanceDecision::RequireConsensus { threshold, .. } => {
            format!("requires consensus: {:?}", threshold)
        }
        GovernanceDecision::ConsensusVote {
            approved, reason, ..
        } => {
            format!(
                "vote: {} ({})",
                if *approved { "approved" } else { "rejected" },
                reason.as_deref().unwrap_or("no reason")
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::governance::{ActionContext, GovernanceActor, GovernanceDecision};

    fn make_event(
        event_type: GovernanceEventType,
        decision: GovernanceDecision,
    ) -> GovernanceEvent {
        let actor = GovernanceActor::Agent {
            destination_hash: "abc123def456".to_string(),
            trust_tier: 1,
        };
        let ctx = ActionContext {
            action_type: "Test".to_string(),
            target: None,
            trust_tier: 1,
            risk_level: "Medium".to_string(),
        };
        GovernanceEvent::guard_evaluation(actor, ctx, decision)
            // Override the event_type since we can't easily construct other variants
            // through the typed constructors for test purposes
    }

    #[test]
    fn test_policy_violation_produces_high_priority() {
        let actor = GovernanceActor::Agent {
            destination_hash: "attacker_hash".to_string(),
            trust_tier: 0,
        };
        let ctx = ActionContext {
            action_type: "PolicyViolation".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "Critical".to_string(),
        };
        let decision = GovernanceDecision::Block {
            reason: "trust tier violation".to_string(),
            authority: "policy_engine".to_string(),
        };

        let mut event = GovernanceEvent::guard_evaluation(actor, ctx, decision);
        // Manually set event_type since we need PolicyTierViolation
        event.event_type = GovernanceEventType::PolicyTierViolation;

        let candidate = event_to_observation(&event);
        assert!(candidate.is_some());
        let c = candidate.unwrap();
        assert_eq!(c.priority, ObservationPriority::High);
        assert_eq!(c.category, "governance.violation");
    }

    #[test]
    fn test_delegation_rejected_produces_high_priority() {
        let actor = GovernanceActor::Agent {
            destination_hash: "bad_agent".to_string(),
            trust_tier: 0,
        };
        let ctx = ActionContext {
            action_type: "Delegation".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "High".to_string(),
        };

        let event = GovernanceEvent::delegation_rejected(
            actor,
            ctx,
            "scope escalation attempted".to_string(),
        );

        let candidate = event_to_observation(&event);
        assert!(candidate.is_some());
        assert_eq!(candidate.unwrap().priority, ObservationPriority::High);
    }

    #[test]
    fn test_routine_guard_evaluation_skipped() {
        let actor = GovernanceActor::System {
            component: "guard".to_string(),
        };
        let ctx = ActionContext {
            action_type: "Chat".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec![],
        };

        let event = GovernanceEvent::guard_evaluation(actor, ctx, decision);
        assert!(event_to_observation(&event).is_none());
    }

    #[test]
    fn test_policy_block_produces_medium_priority() {
        let actor = GovernanceActor::System {
            component: "policy_engine".to_string(),
        };
        let ctx = ActionContext {
            action_type: "Execute".to_string(),
            target: Some("python".to_string()),
            trust_tier: 1,
            risk_level: "High".to_string(),
        };
        let decision = GovernanceDecision::Block {
            reason: "untrusted execution".to_string(),
            authority: "policy_engine".to_string(),
        };

        let event = GovernanceEvent::policy_evaluation(actor, ctx, decision);
        let candidate = event_to_observation(&event);
        assert!(candidate.is_some());
        assert_eq!(candidate.unwrap().priority, ObservationPriority::Medium);
    }

    #[test]
    fn test_policy_allow_skipped() {
        let actor = GovernanceActor::System {
            component: "policy_engine".to_string(),
        };
        let ctx = ActionContext {
            action_type: "Read".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec![],
        };

        let event = GovernanceEvent::policy_evaluation(actor, ctx, decision);
        assert!(event_to_observation(&event).is_none());
    }

    #[test]
    fn test_bridge_events_filters_batch() {
        let actor = GovernanceActor::System {
            component: "guard".to_string(),
        };
        let ctx = ActionContext {
            action_type: "Chat".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };

        // 3 routine events + 1 rejection
        let events = vec![
            GovernanceEvent::guard_evaluation(
                actor.clone(),
                ctx.clone(),
                GovernanceDecision::Allow {
                    conditions: vec![],
                },
            ),
            GovernanceEvent::guard_evaluation(
                actor.clone(),
                ctx.clone(),
                GovernanceDecision::Allow {
                    conditions: vec![],
                },
            ),
            GovernanceEvent::delegation_rejected(
                GovernanceActor::Agent {
                    destination_hash: "bad".to_string(),
                    trust_tier: 0,
                },
                ctx.clone(),
                "depth exceeded".to_string(),
            ),
            GovernanceEvent::guard_evaluation(
                actor,
                ctx,
                GovernanceDecision::Allow {
                    conditions: vec![],
                },
            ),
        ];

        let candidates = bridge_events(&events);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].priority, ObservationPriority::High);
    }

    #[test]
    fn test_candidate_to_observation() {
        let candidate = ObservationCandidate {
            content: "Test violation detected".to_string(),
            priority: ObservationPriority::High,
            category: "governance.violation".to_string(),
            source_event_id: "gov-test-123".to_string(),
        };

        let obs = candidate_to_observation(&candidate);
        assert!(obs.id.starts_with("obs-gov-"));
        assert_eq!(obs.content, "Test violation detected");
        assert_eq!(obs.priority, ObservationPriority::High);
        assert_eq!(obs.category, "governance.violation");
        assert!(!obs.superseded);
    }
}
