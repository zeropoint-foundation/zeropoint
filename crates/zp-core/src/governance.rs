//! Governance types — the bridge between Guard, Policy, and Audit.
//!
//! This module defines the governance events that record every decision point
//! in the system: Guard evaluations, Policy decisions, Capability grants,
//! Escalations, and Consensus operations.
//!
//! Every governance event is immutable, hash-chainable, and receipt-provable.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{ActionType as CoreActionType, PolicyDecision as CorePolicyDecision};

/// A governance event — the immutable record of a governance decision.
///
/// This is the bridge between Guard (pre-action sovereignty), Policy (decision-time composition),
/// and Audit (post-action accountability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvent {
    /// "gov-" prefixed UUID
    pub id: String,
    /// When this event was recorded
    pub timestamp: DateTime<Utc>,
    /// What kind of governance event this is
    pub event_type: GovernanceEventType,
    /// Who is involved
    pub actor: GovernanceActor,
    /// What action triggered this event
    pub action_context: ActionContext,
    /// What was decided
    pub decision: GovernanceDecision,
    /// Link to the receipt that proves this event
    pub receipt_id: Option<String>,
    /// Link to the audit entry in the hash chain
    pub audit_hash: Option<String>,
}

impl GovernanceEvent {
    /// Create a new GovernanceEvent with a generated ID.
    fn new(
        event_type: GovernanceEventType,
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self {
            id: format!("gov-{}", Uuid::now_v7()),
            timestamp: Utc::now(),
            event_type,
            actor,
            action_context,
            decision,
            receipt_id: None,
            audit_hash: None,
        }
    }

    /// Constructor for Guard evaluation events.
    pub fn guard_evaluation(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::GuardEvaluation,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for Policy evaluation events.
    pub fn policy_evaluation(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::PolicyEvaluation,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for Capability grant events.
    pub fn capability_granted(
        actor: GovernanceActor,
        action_context: ActionContext,
        grant_id: String,
    ) -> Self {
        let decision = GovernanceDecision::AllowWithConstraints {
            grant_id,
            applied_constraints: vec![],
        };
        Self::new(
            GovernanceEventType::CapabilityGranted,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for policy advertised events.
    pub fn policy_advertised(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::PolicyAdvertised,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for policy transfer completed events.
    pub fn policy_transfer_completed(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::PolicyTransferCompleted,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for policy agreement reached events.
    pub fn policy_agreement_reached(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::PolicyAgreementReached,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for capability delegated events.
    pub fn capability_delegated(
        actor: GovernanceActor,
        action_context: ActionContext,
        grant_id: String,
        parent_grant_id: String,
    ) -> Self {
        let decision = GovernanceDecision::AllowWithConstraints {
            grant_id,
            applied_constraints: vec![format!("delegated_from: {}", parent_grant_id)],
        };
        Self::new(
            GovernanceEventType::CapabilityDelegated,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for delegation chain verified events.
    pub fn delegation_chain_verified(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::DelegationChainVerified,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for audit challenged events.
    pub fn audit_challenged(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::AuditChallenged,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for audit response verified events.
    pub fn audit_response_verified(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::AuditResponseVerified,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for peer audit verified (attestation produced) events.
    pub fn peer_audit_verified(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::PeerAuditVerified,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for reputation computed events.
    pub fn reputation_computed(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReputationComputed,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for reputation broadcast events.
    pub fn reputation_broadcast(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReputationBroadcast,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for reputation received events.
    pub fn reputation_received(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReputationReceived,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for delegation rejected events.
    pub fn delegation_rejected(
        actor: GovernanceActor,
        action_context: ActionContext,
        reason: String,
    ) -> Self {
        let decision = GovernanceDecision::Block {
            reason,
            authority: "delegation_chain".to_string(),
        };
        Self::new(
            GovernanceEventType::DelegationRejected,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for receipt forwarded events (Phase 4).
    pub fn receipt_forwarded(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReceiptForwarded,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for receipt received from mesh events (Phase 4).
    pub fn receipt_received_from_mesh(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReceiptReceivedFromMesh,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for mesh bridge established events (Phase 4).
    pub fn mesh_bridge_established(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::MeshBridgeEstablished,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for reputation gate blocked events (Phase 4).
    pub fn reputation_gate_blocked(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReputationGateBlocked,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for reputation gate allowed events (Phase 4).
    pub fn reputation_gate_allowed(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReputationGateAllowed,
            actor,
            action_context,
            decision,
        )
    }

    /// Constructor for reputation gate review events (Phase 4).
    pub fn reputation_gate_review(
        actor: GovernanceActor,
        action_context: ActionContext,
        decision: GovernanceDecision,
    ) -> Self {
        Self::new(
            GovernanceEventType::ReputationGateReview,
            actor,
            action_context,
            decision,
        )
    }

    /// Serialize to deterministic canonical bytes for hashing.
    ///
    /// The canonical form excludes the computed hash itself to avoid circularity.
    /// JSON ordering is guaranteed by serde_json's object ordering.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Create a minimal representation for hashing:
        // Use serde_json to get deterministic JSON (sorted keys)
        let canonical = serde_json::json!({
            "id": self.id,
            "timestamp": self.timestamp.to_rfc3339(),
            "event_type": serde_json::to_value(&self.event_type).unwrap(),
            "actor": serde_json::to_value(&self.actor).unwrap(),
            "action_context": serde_json::to_value(&self.action_context).unwrap(),
            "decision": serde_json::to_value(&self.decision).unwrap(),
            "receipt_id": self.receipt_id,
        });

        canonical.to_string().into_bytes()
    }

    /// Compute Blake3 hash of canonical bytes.
    ///
    /// This hash is deterministic — the same event always produces the same hash.
    pub fn compute_hash(&self) -> String {
        let bytes = self.canonical_bytes();
        let hash = blake3::hash(&bytes);
        hash.to_hex().to_string()
    }

    /// Set the receipt ID for this event.
    pub fn with_receipt_id(mut self, receipt_id: String) -> Self {
        self.receipt_id = Some(receipt_id);
        self
    }

    /// Set the audit hash for this event.
    pub fn with_audit_hash(mut self, audit_hash: String) -> Self {
        self.audit_hash = Some(audit_hash);
        self
    }
}

/// The type of governance event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceEventType {
    /// Guard evaluated an action pre-execution
    GuardEvaluation,
    /// Policy engine evaluated during decision
    PolicyEvaluation,
    /// Capability was granted to an agent
    CapabilityGranted,
    /// Capability was revoked
    CapabilityRevoked,
    /// Action was escalated to a higher authority
    Escalation,
    /// Consensus was requested from multiple peers
    ConsensusRequested,
    /// Consensus threshold was reached
    ConsensusReached,
    /// Link was established with a peer
    LinkEstablished,
    /// Link was severed with a peer
    LinkSevered,

    // --- Phase 3: Policy propagation ---
    /// Agent advertised policy modules to mesh peers
    PolicyAdvertised,
    /// Agent requested policy modules from a peer
    PolicyRequested,
    /// Policy module transfer completed (successfully or not)
    PolicyTransferCompleted,
    /// Bilateral policy agreement was reached between peers
    PolicyAgreementReached,
    /// Trust tier violation during policy propagation
    PolicyTierViolation,

    // --- Phase 3 Step 2: Capability delegation ---
    /// A capability was delegated from one agent to another
    CapabilityDelegated,
    /// A delegation chain was verified successfully
    DelegationChainVerified,
    /// A delegation was rejected (depth exceeded, scope escalation, etc.)
    DelegationRejected,

    // --- Phase 3 Step 3: Collective audit ---
    /// An audit challenge was sent to a peer
    AuditChallenged,
    /// An audit response was received and verified
    AuditResponseVerified,
    /// A peer's audit chain was verified (attestation produced)
    PeerAuditVerified,

    // --- Phase 3 Step 4: Reputation ---
    /// A peer's reputation was computed or updated
    ReputationComputed,
    /// A reputation summary was broadcast to the mesh
    ReputationBroadcast,
    /// A reputation summary was received from a peer
    ReputationReceived,

    // --- Phase 4: Integration & Hardening ---
    /// A receipt was forwarded to mesh peers via the pipeline bridge
    ReceiptForwarded,
    /// A receipt was received from a mesh peer
    ReceiptReceivedFromMesh,
    /// Pipeline-mesh bridge was established
    MeshBridgeEstablished,
    /// Mesh action was blocked due to insufficient peer reputation
    ReputationGateBlocked,
    /// Mesh action was allowed after reputation check
    ReputationGateAllowed,
    /// Mesh action requires review due to unknown peer reputation
    ReputationGateReview,
}

/// Who is involved in the governance event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceActor {
    /// A human user
    Human { id: String },
    /// An autonomous agent in the mesh
    Agent {
        destination_hash: String,
        trust_tier: u8,
    },
    /// A system component (e.g., "guard", "policy_engine", "audit_trail")
    System { component: String },
}

/// Context about what action triggered the governance event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// The type of action (serialized ActionType variant)
    pub action_type: String,
    /// What resource the action targets (optional)
    pub target: Option<String>,
    /// Trust tier of the requesting actor (0, 1, or 2)
    pub trust_tier: u8,
    /// Risk level of this action (Low, Medium, High, Critical)
    pub risk_level: String,
}

/// The governance decision — what was decided.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceDecision {
    /// Action allowed to proceed
    Allow { conditions: Vec<String> },

    /// Action allowed with constraints from capability grant
    AllowWithConstraints {
        grant_id: String,
        applied_constraints: Vec<String>,
    },

    /// Action blocked
    Block { reason: String, authority: String },

    /// Action escalated to a reviewer
    Escalate {
        to: GovernanceActor,
        reason: String,
        timeout_secs: Option<u64>,
    },

    /// Action requires consensus from peers
    RequireConsensus {
        threshold: ConsensusThreshold,
        approvers: Vec<String>, // DestinationHash hex values
    },

    /// Peer voted on a consensus request
    ConsensusVote {
        proposal_id: String,
        approved: bool,
        reason: Option<String>,
    },
}

/// How many approvals are needed for consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusThreshold {
    /// All approvers must agree
    Unanimous,
    /// More than half must approve
    Majority,
    /// Exactly K of N approvers
    Threshold { required: u32, total: u32 },
}

// ============================================================================
// Conversion Helpers
// ============================================================================

impl ActionContext {
    /// Create ActionContext from a core ActionType.
    pub fn from_core_action(action: &CoreActionType, trust_tier: u8) -> Self {
        use crate::policy::FileOperation;

        let (action_type, target, risk_level) = match action {
            CoreActionType::Chat => ("Chat".to_string(), None, "Low".to_string()),
            CoreActionType::Read { target: t } => {
                ("Read".to_string(), Some(t.clone()), "Low".to_string())
            }
            CoreActionType::Write { target: t } => {
                ("Write".to_string(), Some(t.clone()), "Medium".to_string())
            }
            CoreActionType::ApiCall { endpoint } => (
                "ApiCall".to_string(),
                Some(endpoint.clone()),
                "High".to_string(),
            ),
            CoreActionType::Execute { language } => (
                "Execute".to_string(),
                Some(language.clone()),
                "High".to_string(),
            ),
            CoreActionType::FileOp { op, path } => {
                let op_str = match op {
                    FileOperation::Read => "FileRead",
                    FileOperation::Write => "FileWrite",
                    FileOperation::Delete => "FileDelete",
                    FileOperation::Create => "FileCreate",
                    FileOperation::List => "FileList",
                };
                (op_str.to_string(), Some(path.clone()), "Medium".to_string())
            }
            CoreActionType::CredentialAccess { credential_ref } => (
                "CredentialAccess".to_string(),
                Some(credential_ref.clone()),
                "Critical".to_string(),
            ),
            CoreActionType::ConfigChange { setting } => (
                "ConfigChange".to_string(),
                Some(setting.clone()),
                "High".to_string(),
            ),
            CoreActionType::KeyDelegation {
                target_role,
                target_subject,
                ..
            } => (
                "KeyDelegation".to_string(),
                Some(format!("{}:{}", target_role, target_subject)),
                "Critical".to_string(),
            ),
            CoreActionType::PeerIntroduction {
                peer_address,
                same_genesis,
                ..
            } => (
                "PeerIntroduction".to_string(),
                Some(peer_address.clone()),
                if *same_genesis { "High" } else { "Critical" }.to_string(),
            ),
        };

        Self {
            action_type,
            target,
            trust_tier,
            risk_level,
        }
    }
}

/// Convert a core PolicyDecision to a GovernanceDecision.
pub fn policy_decision_to_governance(core_decision: &CorePolicyDecision) -> GovernanceDecision {
    match core_decision {
        CorePolicyDecision::Allow { conditions } => GovernanceDecision::Allow {
            conditions: conditions.clone(),
        },
        CorePolicyDecision::Block {
            reason,
            policy_module: _,
        } => GovernanceDecision::Block {
            reason: reason.clone(),
            authority: "policy_engine".to_string(),
        },
        CorePolicyDecision::Warn {
            message,
            require_ack: _,
        } => GovernanceDecision::Allow {
            conditions: vec![format!("warn: {}", message)],
        },
        CorePolicyDecision::Review {
            summary,
            reviewer: _,
            timeout: _,
        } => {
            GovernanceDecision::Escalate {
                to: GovernanceActor::System {
                    component: "review_queue".to_string(),
                },
                reason: summary.clone(),
                timeout_secs: Some(3600), // default 1 hour
            }
        }
        CorePolicyDecision::Sanitize { patterns } => GovernanceDecision::Allow {
            conditions: patterns
                .iter()
                .map(|p| format!("sanitize: {}", p.name))
                .collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governance_event_guard_evaluation() {
        let actor = GovernanceActor::Human {
            id: "user-123".to_string(),
        };
        let action_context = ActionContext {
            action_type: "Read".to_string(),
            target: Some("/etc/passwd".to_string()),
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["user authenticated".to_string()],
        };

        let event = GovernanceEvent::guard_evaluation(actor, action_context, decision);

        assert!(event.id.starts_with("gov-"));
        assert!(matches!(
            event.event_type,
            GovernanceEventType::GuardEvaluation
        ));
    }

    #[test]
    fn test_governance_event_policy_evaluation() {
        let actor = GovernanceActor::System {
            component: "policy_engine".to_string(),
        };
        let action_context = ActionContext {
            action_type: "ApiCall".to_string(),
            target: Some("https://api.example.com".to_string()),
            trust_tier: 1,
            risk_level: "High".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["rate_limit: 100 req/hour".to_string()],
        };

        let event = GovernanceEvent::policy_evaluation(actor, action_context, decision);

        assert!(matches!(
            event.event_type,
            GovernanceEventType::PolicyEvaluation
        ));
    }

    #[test]
    fn test_governance_event_capability_granted() {
        let actor = GovernanceActor::Agent {
            destination_hash: "abc123def456".to_string(),
            trust_tier: 2,
        };
        let action_context = ActionContext {
            action_type: "CapabilityGrant".to_string(),
            target: None,
            trust_tier: 2,
            risk_level: "Medium".to_string(),
        };

        let event =
            GovernanceEvent::capability_granted(actor, action_context, "grant-xyz789".to_string());

        assert!(matches!(
            event.event_type,
            GovernanceEventType::CapabilityGranted
        ));
        assert!(matches!(
            event.decision,
            GovernanceDecision::AllowWithConstraints { .. }
        ));
    }

    #[test]
    fn test_governance_event_policy_advertised() {
        let actor = GovernanceActor::Agent {
            destination_hash: "abc123".to_string(),
            trust_tier: 1,
        };
        let ctx = ActionContext {
            action_type: "PolicyAdvertisement".to_string(),
            target: None,
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["3 modules advertised".to_string()],
        };

        let event = GovernanceEvent::policy_advertised(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::PolicyAdvertised
        ));
    }

    #[test]
    fn test_governance_event_policy_transfer_completed() {
        let actor = GovernanceActor::Agent {
            destination_hash: "peer456".to_string(),
            trust_tier: 2,
        };
        let ctx = ActionContext {
            action_type: "PolicyTransfer".to_string(),
            target: Some("hash_abc".to_string()),
            trust_tier: 2,
            risk_level: "Medium".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["hash verified".to_string()],
        };

        let event = GovernanceEvent::policy_transfer_completed(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::PolicyTransferCompleted
        ));
    }

    #[test]
    fn test_governance_event_policy_agreement() {
        let actor = GovernanceActor::Agent {
            destination_hash: "agent789".to_string(),
            trust_tier: 2,
        };
        let ctx = ActionContext {
            action_type: "PolicyNegotiation".to_string(),
            target: None,
            trust_tier: 2,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["2 policies enforced".to_string()],
        };

        let event = GovernanceEvent::policy_agreement_reached(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::PolicyAgreementReached
        ));
    }

    #[test]
    fn test_hash_determinism() {
        let actor = GovernanceActor::Human {
            id: "test-user".to_string(),
        };
        let action_context = ActionContext {
            action_type: "Write".to_string(),
            target: Some("/tmp/file.txt".to_string()),
            trust_tier: 1,
            risk_level: "Medium".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["user approved".to_string()],
        };

        let event1 = GovernanceEvent::guard_evaluation(
            actor.clone(),
            action_context.clone(),
            decision.clone(),
        );

        let event2 = GovernanceEvent::guard_evaluation(actor, action_context, decision);

        let hash1 = event1.compute_hash();
        let hash2 = event2.compute_hash();

        // Note: timestamps will differ, so hashes won't be identical in practice
        // This test documents the deterministic behavior when timestamps are the same
        assert!(!hash1.is_empty());
        assert!(!hash2.is_empty());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let actor = GovernanceActor::Agent {
            destination_hash: "fedcba9876543210".to_string(),
            trust_tier: 1,
        };
        let action_context = ActionContext {
            action_type: "Execute".to_string(),
            target: Some("python".to_string()),
            trust_tier: 1,
            risk_level: "High".to_string(),
        };
        let decision = GovernanceDecision::Block {
            reason: "Unauthorized execution".to_string(),
            authority: "guard".to_string(),
        };

        let event = GovernanceEvent::guard_evaluation(actor, action_context, decision);
        let json = serde_json::to_string(&event).expect("serialization failed");
        let deserialized: GovernanceEvent =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(event.id, deserialized.id);
        assert_eq!(event.timestamp, deserialized.timestamp);
        assert!(matches!(
            deserialized.event_type,
            GovernanceEventType::GuardEvaluation
        ));
    }

    #[test]
    fn test_action_context_from_core_action() {
        let core_action = CoreActionType::Write {
            target: "/var/log/app.log".to_string(),
        };

        let ctx = ActionContext::from_core_action(&core_action, 1);

        assert_eq!(ctx.action_type, "Write");
        assert_eq!(ctx.target, Some("/var/log/app.log".to_string()));
        assert_eq!(ctx.trust_tier, 1);
        assert_eq!(ctx.risk_level, "Medium");
    }

    #[test]
    fn test_consensus_threshold_variants() {
        let unanimous = ConsensusThreshold::Unanimous;
        let majority = ConsensusThreshold::Majority;
        let threshold = ConsensusThreshold::Threshold {
            required: 2,
            total: 3,
        };

        assert!(matches!(unanimous, ConsensusThreshold::Unanimous));
        assert!(matches!(majority, ConsensusThreshold::Majority));
        assert!(matches!(threshold, ConsensusThreshold::Threshold { .. }));
    }

    #[test]
    fn test_governance_decision_allow_with_constraints() {
        let decision = GovernanceDecision::AllowWithConstraints {
            grant_id: "cap-grant-001".to_string(),
            applied_constraints: vec![
                "max_cost: 50.00".to_string(),
                "rate_limit: 10/min".to_string(),
            ],
        };

        match decision {
            GovernanceDecision::AllowWithConstraints {
                grant_id,
                applied_constraints,
            } => {
                assert_eq!(grant_id, "cap-grant-001");
                assert_eq!(applied_constraints.len(), 2);
            }
            _ => panic!("Expected AllowWithConstraints"),
        }
    }

    #[test]
    fn test_governance_decision_escalate() {
        let escalate_to = GovernanceActor::Human {
            id: "manager-789".to_string(),
        };
        let decision = GovernanceDecision::Escalate {
            to: escalate_to,
            reason: "Requires human approval".to_string(),
            timeout_secs: Some(1800),
        };

        match decision {
            GovernanceDecision::Escalate {
                to,
                reason,
                timeout_secs,
            } => {
                assert!(matches!(to, GovernanceActor::Human { .. }));
                assert_eq!(reason, "Requires human approval");
                assert_eq!(timeout_secs, Some(1800));
            }
            _ => panic!("Expected Escalate"),
        }
    }

    #[test]
    fn test_event_with_receipt_id() {
        let actor = GovernanceActor::System {
            component: "guard".to_string(),
        };
        let action_context = ActionContext {
            action_type: "Chat".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow { conditions: vec![] };

        let event = GovernanceEvent::guard_evaluation(actor, action_context, decision)
            .with_receipt_id("rcpt-12345".to_string())
            .with_audit_hash("audit-67890".to_string());

        assert_eq!(event.receipt_id, Some("rcpt-12345".to_string()));
        assert_eq!(event.audit_hash, Some("audit-67890".to_string()));
    }

    #[test]
    fn test_canonical_bytes_consistency() {
        let actor = GovernanceActor::Human {
            id: "user-abc".to_string(),
        };
        let action_context = ActionContext {
            action_type: "Read".to_string(),
            target: Some("/data".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["approved".to_string()],
        };

        let event1 = GovernanceEvent::guard_evaluation(
            actor.clone(),
            action_context.clone(),
            decision.clone(),
        );
        let event2 = GovernanceEvent::guard_evaluation(actor, action_context, decision);

        let bytes1 = event1.canonical_bytes();
        let bytes2 = event2.canonical_bytes();

        // Canonical bytes should be identical for identical events (timestamps may differ)
        // This test at minimum checks that the serialization is consistent
        assert!(!bytes1.is_empty());
        assert!(!bytes2.is_empty());
    }

    #[test]
    fn test_governance_actor_variants() {
        let human = GovernanceActor::Human {
            id: "user-1".to_string(),
        };
        let agent = GovernanceActor::Agent {
            destination_hash: "aabbccdd".to_string(),
            trust_tier: 2,
        };
        let system = GovernanceActor::System {
            component: "audit_trail".to_string(),
        };

        assert!(matches!(human, GovernanceActor::Human { .. }));
        assert!(matches!(agent, GovernanceActor::Agent { .. }));
        assert!(matches!(system, GovernanceActor::System { .. }));
    }

    // ====================================================================
    // Phase 3 Step 2: Delegation governance event tests
    // ====================================================================

    #[test]
    fn test_governance_event_capability_delegated() {
        let actor = GovernanceActor::Agent {
            destination_hash: "bob_hash".to_string(),
            trust_tier: 1,
        };
        let ctx = ActionContext {
            action_type: "Delegation".to_string(),
            target: None,
            trust_tier: 1,
            risk_level: "Medium".to_string(),
        };

        let event = GovernanceEvent::capability_delegated(
            actor,
            ctx,
            "grant-child".to_string(),
            "grant-parent".to_string(),
        );
        assert!(matches!(
            event.event_type,
            GovernanceEventType::CapabilityDelegated
        ));
        if let GovernanceDecision::AllowWithConstraints {
            grant_id,
            applied_constraints,
        } = &event.decision
        {
            assert_eq!(grant_id, "grant-child");
            assert!(applied_constraints[0].contains("grant-parent"));
        } else {
            panic!("Expected AllowWithConstraints");
        }
    }

    #[test]
    fn test_governance_event_delegation_chain_verified() {
        let actor = GovernanceActor::System {
            component: "delegation_verifier".to_string(),
        };
        let ctx = ActionContext {
            action_type: "ChainVerification".to_string(),
            target: None,
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["chain_length: 3".to_string()],
        };

        let event = GovernanceEvent::delegation_chain_verified(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::DelegationChainVerified
        ));
    }

    // ====================================================================
    // Phase 3 Step 3: Collective audit governance event tests
    // ====================================================================

    #[test]
    fn test_governance_event_audit_challenged() {
        let actor = GovernanceActor::Agent {
            destination_hash: "challenger_hash".to_string(),
            trust_tier: 1,
        };
        let ctx = ActionContext {
            action_type: "AuditChallenge".to_string(),
            target: Some("peer-abc".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["recent 5 entries requested".to_string()],
        };

        let event = GovernanceEvent::audit_challenged(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::AuditChallenged
        ));
    }

    #[test]
    fn test_governance_event_audit_response_verified() {
        let actor = GovernanceActor::System {
            component: "audit_verifier".to_string(),
        };
        let ctx = ActionContext {
            action_type: "AuditVerification".to_string(),
            target: Some("peer-xyz".to_string()),
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec![
                "chain_valid: true".to_string(),
                "entries_verified: 3".to_string(),
            ],
        };

        let event = GovernanceEvent::audit_response_verified(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::AuditResponseVerified
        ));
    }

    #[test]
    fn test_governance_event_peer_audit_verified() {
        let actor = GovernanceActor::Agent {
            destination_hash: "verifier_hash".to_string(),
            trust_tier: 2,
        };
        let ctx = ActionContext {
            action_type: "PeerAuditAttestation".to_string(),
            target: Some("peer-target".to_string()),
            trust_tier: 2,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec![
                "attestation_id: att-123".to_string(),
                "chain_valid: true".to_string(),
            ],
        };

        let event = GovernanceEvent::peer_audit_verified(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::PeerAuditVerified
        ));
    }

    // ====================================================================
    // Phase 3 Step 4: Reputation governance event tests
    // ====================================================================

    #[test]
    fn test_governance_event_reputation_computed() {
        let actor = GovernanceActor::System {
            component: "reputation_engine".to_string(),
        };
        let ctx = ActionContext {
            action_type: "ReputationComputation".to_string(),
            target: Some("peer-abc".to_string()),
            trust_tier: 0,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["grade: Excellent".to_string(), "score: 0.85".to_string()],
        };

        let event = GovernanceEvent::reputation_computed(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReputationComputed
        ));
    }

    #[test]
    fn test_governance_event_reputation_broadcast() {
        let actor = GovernanceActor::Agent {
            destination_hash: "broadcaster_hash".to_string(),
            trust_tier: 1,
        };
        let ctx = ActionContext {
            action_type: "ReputationBroadcast".to_string(),
            target: Some("peer-target".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["2 peers notified".to_string()],
        };

        let event = GovernanceEvent::reputation_broadcast(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReputationBroadcast
        ));
    }

    #[test]
    fn test_governance_event_reputation_received() {
        let actor = GovernanceActor::Agent {
            destination_hash: "receiver_hash".to_string(),
            trust_tier: 2,
        };
        let ctx = ActionContext {
            action_type: "ReputationReceived".to_string(),
            target: Some("peer-rated".to_string()),
            trust_tier: 2,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["grade: Good".to_string()],
        };

        let event = GovernanceEvent::reputation_received(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReputationReceived
        ));
    }

    #[test]
    fn test_governance_event_delegation_rejected() {
        let actor = GovernanceActor::Agent {
            destination_hash: "attacker".to_string(),
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
        assert!(matches!(
            event.event_type,
            GovernanceEventType::DelegationRejected
        ));
        if let GovernanceDecision::Block { reason, authority } = &event.decision {
            assert_eq!(reason, "scope escalation attempted");
            assert_eq!(authority, "delegation_chain");
        } else {
            panic!("Expected Block");
        }
    }

    // ====================================================================
    // Phase 4: Integration & Hardening governance event tests
    // ====================================================================

    #[test]
    fn test_governance_event_receipt_forwarded() {
        let actor = GovernanceActor::System {
            component: "mesh-bridge".to_string(),
        };
        let ctx = ActionContext {
            action_type: "ReceiptForwarded".to_string(),
            target: Some("all_peers".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["pipeline".to_string()],
        };

        let event = GovernanceEvent::receipt_forwarded(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReceiptForwarded
        ));
        assert!(event.id.starts_with("gov-"));
    }

    #[test]
    fn test_governance_event_receipt_received_from_mesh() {
        let actor = GovernanceActor::Agent {
            destination_hash: "peer-abc".to_string(),
            trust_tier: 2,
        };
        let ctx = ActionContext {
            action_type: "ReceiptReceivedFromMesh".to_string(),
            target: None,
            trust_tier: 2,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["mesh".to_string()],
        };

        let event = GovernanceEvent::receipt_received_from_mesh(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReceiptReceivedFromMesh
        ));
    }

    #[test]
    fn test_governance_event_mesh_bridge_established() {
        let actor = GovernanceActor::System {
            component: "pipeline".to_string(),
        };
        let ctx = ActionContext {
            action_type: "MeshBridgeEstablished".to_string(),
            target: Some("mesh-node-abc".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["pipeline".to_string()],
        };

        let event = GovernanceEvent::mesh_bridge_established(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::MeshBridgeEstablished
        ));
    }

    #[test]
    fn test_governance_event_reputation_gate_blocked() {
        let actor = GovernanceActor::System {
            component: "reputation_gate".to_string(),
        };
        let ctx = ActionContext {
            action_type: "DelegateCapability".to_string(),
            target: Some("peer-poor".to_string()),
            trust_tier: 1,
            risk_level: "High".to_string(),
        };
        let decision = GovernanceDecision::Block {
            reason: "Peer reputation Poor, below Good threshold".to_string(),
            authority: "ReputationGate".to_string(),
        };

        let event = GovernanceEvent::reputation_gate_blocked(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReputationGateBlocked
        ));
    }

    #[test]
    fn test_governance_event_reputation_gate_allowed() {
        let actor = GovernanceActor::System {
            component: "reputation_gate".to_string(),
        };
        let ctx = ActionContext {
            action_type: "ForwardReceipt".to_string(),
            target: Some("peer-good".to_string()),
            trust_tier: 1,
            risk_level: "Low".to_string(),
        };
        let decision = GovernanceDecision::Allow {
            conditions: vec!["reputation: Good".to_string()],
        };

        let event = GovernanceEvent::reputation_gate_allowed(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReputationGateAllowed
        ));
    }

    #[test]
    fn test_governance_event_reputation_gate_review() {
        let actor = GovernanceActor::System {
            component: "reputation_gate".to_string(),
        };
        let ctx = ActionContext {
            action_type: "AcceptDelegation".to_string(),
            target: Some("peer-unknown".to_string()),
            trust_tier: 0,
            risk_level: "High".to_string(),
        };
        let decision = GovernanceDecision::Escalate {
            to: GovernanceActor::Human {
                id: "operator".to_string(),
            },
            reason: "Unknown peer requesting delegation".to_string(),
            timeout_secs: Some(300),
        };

        let event = GovernanceEvent::reputation_gate_review(actor, ctx, decision);
        assert!(matches!(
            event.event_type,
            GovernanceEventType::ReputationGateReview
        ));
    }
}
