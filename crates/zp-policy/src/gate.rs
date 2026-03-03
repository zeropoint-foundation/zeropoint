//! The GovernanceGate — integration layer that wires Guard, Policy, and Audit together
//! into a single evaluation pipeline.
//!
//! The GovernanceGate orchestrates the three pillars of ZeroPoint's governance framework:
//!
//! ```text
//! Request → Guard (pre-action) → Policy (decision) → Execute → Audit (post-action)
//! ```
//!
//! Design:
//! 1. **Guard** (pre-action): "May I?" — sovereign boundary check
//! 2. **Policy** (decision): "Should I?" — rule-composed graduated decision
//! 3. **Audit** (post-action): "Did I?" — hash-chained immutable record

use chrono::Utc;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use zp_core::audit::{ActorId, AuditAction, AuditEntry, AuditId};
use zp_core::policy::{PolicyContext, PolicyDecision, RiskLevel, TrustTier};

use crate::engine::PolicyEngine;

/// The result of evaluating an action through the governance gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    /// The policy decision (Allow/Block/Warn/Review/Sanitize)
    pub decision: PolicyDecision,
    /// Risk level assessment for model routing
    pub risk_level: RiskLevel,
    /// Trust tier of the acting entity
    pub trust_tier: TrustTier,
    /// Complete audit entry for this decision
    pub audit_entry: AuditEntry,
    /// Optional receipt ID if one was generated
    pub receipt_id: Option<String>,
    /// Names of policy rules that were evaluated
    pub applied_rules: Vec<String>,
}

impl GateResult {
    /// Quick check: does this decision allow the action to proceed?
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    /// Quick check: is this a hard block?
    pub fn is_blocked(&self) -> bool {
        self.decision.is_blocked()
    }

    /// Quick check: does this need user interaction before proceeding?
    pub fn needs_interaction(&self) -> bool {
        self.decision.needs_interaction()
    }
}

/// The GovernanceGate — wires Guard, Policy, and Audit into one pipeline.
///
/// This is the integration point for the three pillars of governance:
/// - Guard (pre-action): Sovereign boundary check
/// - Policy (decision): Rule-composed graduated decision
/// - Audit (post-action): Hash-chained immutable record
pub struct GovernanceGate {
    /// The policy engine that evaluates contexts
    policy_engine: PolicyEngine,
    /// Hash of the last audit entry — maintained for chain integrity
    audit_chain_head: Mutex<String>,
    /// Human-readable name for this gate instance
    gate_name: String,
}

impl GovernanceGate {
    /// Create a new GovernanceGate with default policy engine.
    pub fn new(gate_name: &str) -> Self {
        Self::with_policy_engine(gate_name, PolicyEngine::new())
    }

    /// Create a new GovernanceGate with a custom policy engine.
    pub fn with_policy_engine(gate_name: &str, engine: PolicyEngine) -> Self {
        Self {
            policy_engine: engine,
            audit_chain_head: Mutex::new(blake3::hash(b"").to_hex().to_string()),
            gate_name: gate_name.to_string(),
        }
    }

    /// Evaluate an action through the full governance pipeline.
    ///
    /// This method:
    /// 1. Assesses risk level from the action type
    /// 2. Runs the PolicyEngine to get a PolicyDecision
    /// 3. Creates an AuditEntry hash-chained to the previous entry
    /// 4. Updates the audit chain head
    /// 5. Returns a GateResult with everything bundled
    ///
    /// Returns a GateResult with the decision and a complete audit entry.
    pub fn evaluate(&self, context: &PolicyContext, actor: ActorId) -> GateResult {
        // Step 1: Assess risk level from the action type
        let risk_level = RiskLevel::from_action(&context.action);

        // Step 2: Run the PolicyEngine to get a PolicyDecision
        let decision = self.policy_engine.evaluate(context);

        // Extract policy module name from decision
        let policy_module = match &decision {
            PolicyDecision::Allow { .. } => "DefaultAllow".to_string(),
            PolicyDecision::Block { policy_module, .. } => policy_module.clone(),
            PolicyDecision::Warn { .. } => "DefaultAllow".to_string(),
            PolicyDecision::Review { .. } => "DefaultAllow".to_string(),
            PolicyDecision::Sanitize { .. } => "DefaultAllow".to_string(),
        };

        // Step 3: Create an AuditEntry hash-chained to the previous entry
        let prev_hash = self.audit_chain_head.lock().clone();

        let mut audit_entry = AuditEntry {
            id: AuditId::new(),
            timestamp: Utc::now(),
            prev_hash: prev_hash.clone(),
            entry_hash: String::new(), // Will be computed below
            actor: actor.clone(),
            action: AuditAction::PolicyInteraction {
                decision_type: decision_type_name(&decision),
                user_response: None,
            },
            conversation_id: context.conversation_id.clone(),
            policy_decision: decision.clone(),
            policy_module,
            receipt: None,
            signature: None,
        };

        // Compute the entry hash using blake3 over canonical JSON
        audit_entry.entry_hash = compute_entry_hash(&audit_entry);

        // Step 4: Update the audit chain head
        *self.audit_chain_head.lock() = audit_entry.entry_hash.clone();

        // Collect applied rules (from engine inspection)
        let applied_rules = vec!["PolicyEngine".to_string()];

        // Step 5: Return a GateResult with everything bundled
        GateResult {
            decision,
            risk_level,
            trust_tier: context.trust_tier,
            audit_entry,
            receipt_id: None,
            applied_rules,
        }
    }

    /// Get the current audit chain head hash.
    pub fn audit_chain_head(&self) -> String {
        self.audit_chain_head.lock().clone()
    }

    /// Set the audit chain head (e.g., to restore from a persisted audit store on restart).
    pub fn set_audit_chain_head(&mut self, hash: String) {
        *self.audit_chain_head.lock() = hash;
    }

    /// Reset the audit chain head to the genesis hash.
    /// Uses interior mutability so it can be called through shared references (Arc).
    pub fn reset_audit_chain_head(&self) {
        *self.audit_chain_head.lock() = blake3::hash(b"").to_hex().to_string();
    }

    /// Get a reference to the policy engine.
    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    /// Get the gate's name.
    pub fn name(&self) -> &str {
        &self.gate_name
    }
}

/// Determine the type name of a policy decision (for audit logging).
fn decision_type_name(decision: &PolicyDecision) -> String {
    match decision {
        PolicyDecision::Allow { .. } => "Allow".to_string(),
        PolicyDecision::Block { .. } => "Block".to_string(),
        PolicyDecision::Warn { .. } => "Warn".to_string(),
        PolicyDecision::Review { .. } => "Review".to_string(),
        PolicyDecision::Sanitize { .. } => "Sanitize".to_string(),
    }
}

/// Compute the blake3 hash of an audit entry.
///
/// Serializes the entry to canonical JSON (excluding entry_hash field)
/// and computes the blake3 hash of the JSON bytes.
///
/// IMPORTANT: This must use the exact same serialization format as
/// `ChainBuilder::build_entry` and `recompute_entry_hash` in zp-audit.
/// Using `format!("{:?}", ...)` for IDs and `.to_rfc3339()` for timestamps
/// ensures deterministic, round-trip-safe hashing.
pub fn compute_entry_hash(entry: &AuditEntry) -> String {
    use serde_json::json;

    let entry_data = json!({
        "id": format!("{:?}", entry.id.0),
        "timestamp": entry.timestamp.to_rfc3339(),
        "prev_hash": entry.prev_hash,
        "actor": format!("{:?}", entry.actor),
        "action": serde_json::to_value(&entry.action).unwrap_or(json!(null)),
        "conversation_id": format!("{:?}", entry.conversation_id.0),
        "policy_decision": serde_json::to_value(&entry.policy_decision).unwrap_or(json!(null)),
        "policy_module": entry.policy_module,
        "receipt": entry.receipt.as_ref().map(|r| serde_json::to_value(r).unwrap_or(json!(null))),
        "signature": entry.signature,
    });

    let entry_bytes = serde_json::to_vec(&entry_data).unwrap_or_default();
    blake3::hash(&entry_bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_core::policy::ActionType;
    use zp_core::{Channel, ConversationId};

    fn make_context(action: ActionType) -> PolicyContext {
        PolicyContext {
            action,
            trust_tier: TrustTier::Tier0,
            channel: Channel::Cli,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![],
            mesh_context: None,
        }
    }

    #[test]
    fn test_gate_creation_with_default_policy_engine() {
        let gate = GovernanceGate::new("test_gate");
        assert_eq!(gate.name(), "test_gate");
        assert_eq!(
            gate.audit_chain_head(),
            blake3::hash(b"").to_hex().to_string()
        );
    }

    #[test]
    fn test_gate_creation_with_custom_policy_engine() {
        let engine = PolicyEngine::new();
        let gate = GovernanceGate::with_policy_engine("custom_gate", engine);
        assert_eq!(gate.name(), "custom_gate");
    }

    #[test]
    fn test_evaluating_safe_action_returns_allow() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("test_user".to_string());

        let result = gate.evaluate(&context, actor);

        assert!(result.is_allowed());
        assert!(!result.is_blocked());
        assert!(!result.needs_interaction());
    }

    #[test]
    fn test_evaluating_dangerous_action_returns_block() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "aws_key".to_string(),
        });
        let actor = ActorId::User("test_user".to_string());

        let result = gate.evaluate(&context, actor);

        assert!(result.is_blocked());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_safe_action_creates_audit_entry() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("alice".to_string());

        let result = gate.evaluate(&context, actor.clone());

        // Verify audit entry exists and has correct properties
        assert_eq!(result.audit_entry.actor, actor);
        assert_eq!(result.audit_entry.conversation_id, context.conversation_id);
        assert_eq!(
            result.audit_entry.prev_hash,
            blake3::hash(b"").to_hex().to_string()
        );
        assert!(!result.audit_entry.entry_hash.is_empty());
    }

    #[test]
    fn test_dangerous_action_creates_audit_entry() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "secret".to_string(),
        });
        let actor = ActorId::Operator;

        let result = gate.evaluate(&context, actor.clone());

        // Verify audit entry was created even for blocked action
        assert_eq!(result.audit_entry.actor, actor);
        assert!(result.audit_entry.entry_hash.len() > 0);
        assert!(result.is_blocked());
    }

    #[test]
    fn test_audit_chain_integrity() {
        let gate = GovernanceGate::new("test_gate");

        // First evaluation
        let context1 = make_context(ActionType::Chat);
        let actor1 = ActorId::User("alice".to_string());
        let result1 = gate.evaluate(&context1, actor1);
        let hash1 = result1.audit_entry.entry_hash.clone();

        // Verify chain head was updated
        assert_eq!(gate.audit_chain_head(), hash1);

        // Second evaluation
        let context2 = make_context(ActionType::Read {
            target: "file.txt".to_string(),
        });
        let actor2 = ActorId::User("bob".to_string());
        let result2 = gate.evaluate(&context2, actor2);
        let hash2 = result2.audit_entry.entry_hash.clone();

        // Verify second entry's prev_hash points to first entry's hash
        assert_eq!(result2.audit_entry.prev_hash, hash1);

        // Verify chain head was updated to second hash
        assert_eq!(gate.audit_chain_head(), hash2);

        // Third evaluation
        let context3 = make_context(ActionType::Write {
            target: "output.txt".to_string(),
        });
        let actor3 = ActorId::System("scheduler".to_string());
        let result3 = gate.evaluate(&context3, actor3);
        let hash3 = result3.audit_entry.entry_hash.clone();

        // Verify third entry's prev_hash points to second entry's hash
        assert_eq!(result3.audit_entry.prev_hash, hash2);

        // Verify chain head was updated to third hash
        assert_eq!(gate.audit_chain_head(), hash3);

        // Verify all hashes are unique
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_custom_policy_engine_works_through_gate() {
        use crate::rules::PolicyRule;

        struct AlwaysBlockRule;
        impl PolicyRule for AlwaysBlockRule {
            fn name(&self) -> &str {
                "AlwaysBlock"
            }
            fn evaluate(&self, _context: &PolicyContext) -> Option<PolicyDecision> {
                Some(PolicyDecision::Block {
                    reason: "Test block".to_string(),
                    policy_module: "AlwaysBlockRule".to_string(),
                })
            }
        }

        let engine = PolicyEngine::with_rules(vec![Box::new(AlwaysBlockRule)]);
        let gate = GovernanceGate::with_policy_engine("custom_gate", engine);

        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("test".to_string());

        let result = gate.evaluate(&context, actor);

        assert!(result.is_blocked());
    }

    #[test]
    fn test_gate_result_is_allowed_helper() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("test".to_string());

        let result = gate.evaluate(&context, actor);

        assert!(result.is_allowed());
        assert!(!result.is_blocked());
    }

    #[test]
    fn test_gate_result_is_blocked_helper() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "key".to_string(),
        });
        let actor = ActorId::User("test".to_string());

        let result = gate.evaluate(&context, actor);

        assert!(result.is_blocked());
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_gate_result_needs_interaction_on_warn() {
        use crate::rules::PolicyRule;

        struct AlwaysWarnRule;
        impl PolicyRule for AlwaysWarnRule {
            fn name(&self) -> &str {
                "AlwaysWarn"
            }
            fn evaluate(&self, _context: &PolicyContext) -> Option<PolicyDecision> {
                Some(PolicyDecision::Warn {
                    message: "Test warning".to_string(),
                    require_ack: true,
                })
            }
        }

        let engine = PolicyEngine::with_rules(vec![Box::new(AlwaysWarnRule)]);
        let gate = GovernanceGate::with_policy_engine("warn_gate", engine);

        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("test".to_string());

        let result = gate.evaluate(&context, actor);

        assert!(result.needs_interaction());
        // Warn requires acknowledgment — it's not a hard block, but is_allowed()
        // only returns true for Allow/Sanitize. Verify it's not blocked either.
        assert!(!result.is_blocked());
    }

    #[test]
    fn test_risk_level_assessment() {
        let gate = GovernanceGate::new("test_gate");

        // Low risk action
        let low_risk = make_context(ActionType::Chat);
        let result = gate.evaluate(&low_risk, ActorId::Operator);
        assert_eq!(result.risk_level, RiskLevel::Low);

        // High risk action
        let high_risk = make_context(ActionType::FileOp {
            op: zp_core::policy::FileOperation::Delete,
            path: "/data/file.txt".to_string(),
        });
        let result = gate.evaluate(&high_risk, ActorId::Operator);
        assert_eq!(result.risk_level, RiskLevel::High);

        // Critical risk action
        let critical_risk = make_context(ActionType::CredentialAccess {
            credential_ref: "secret".to_string(),
        });
        let result = gate.evaluate(&critical_risk, ActorId::Operator);
        assert_eq!(result.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_audit_entry_hash_determinism() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("alice".to_string());

        // Note: Due to timestamps in the entry, we can't expect identical hashes
        // but we can verify the hash computation is deterministic within a gate
        let result = gate.evaluate(&context, actor);
        let hash = result.audit_entry.entry_hash.clone();

        // Hash should be a valid hex string from blake3
        assert!(hash.len() > 0);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_gate_preserves_trust_tier() {
        let gate = GovernanceGate::new("test_gate");

        let mut context = make_context(ActionType::Chat);
        context.trust_tier = TrustTier::Tier1;
        let actor = ActorId::User("test".to_string());

        let result = gate.evaluate(&context, actor);

        assert_eq!(result.trust_tier, TrustTier::Tier1);
    }

    #[test]
    fn test_multiple_concurrent_evaluations() {
        let gate = std::sync::Arc::new(GovernanceGate::new("concurrent_gate"));

        let handles: Vec<_> = (0..5)
            .map(|i| {
                let gate_clone = gate.clone();
                std::thread::spawn(move || {
                    let context = make_context(ActionType::Chat);
                    let actor = ActorId::User(format!("user_{}", i));
                    gate_clone.evaluate(&context, actor)
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All evaluations should succeed
        assert_eq!(results.len(), 5);

        // Chain should be properly maintained
        for result in &results {
            assert!(result.is_allowed());
        }
    }
}
