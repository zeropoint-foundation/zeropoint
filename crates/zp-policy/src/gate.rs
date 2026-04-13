//! The GovernanceGate — integration layer that wires Guard and Policy together
//! into a single evaluation pipeline.
//!
//! # Architecture (post-recanonicalization)
//!
//! The GovernanceGate orchestrates two of the three pillars of ZeroPoint's
//! governance framework:
//!
//! ```text
//! Request → Guard (pre-action) → Policy (decision) → UnsealedEntry → AuditStore::append
//! ```
//!
//! Design:
//! 1. **Guard** (pre-action): "May I?" — sovereign boundary check
//! 2. **Policy** (decision): "Should I?" — rule-composed graduated decision
//! 3. **Audit** (post-action): the gate **does not own the audit chain**. It
//!    returns an [`UnsealedEntry`] that the caller hands to
//!    `zp_audit::AuditStore::append`, which atomically assigns chain
//!    position (`id`, `timestamp`, `prev_hash`, `entry_hash`) inside a
//!    `BEGIN IMMEDIATE` transaction. See `docs/audit-invariant.md`.
//!
//! Pre-recanonicalization, this file contained a second, disconnected
//! in-memory hash chain (`audit_chain_head: Mutex<String>`) plus its own
//! `compute_entry_hash` function that used `format!("{:?}", ...)` on IDs —
//! the exact AUDIT-02 bug, living inside a hash function. Both are deleted.
//! See `security/pentest-2026-04-06/RIPPLE-AUDIT.md` §R1.

use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use zp_audit::UnsealedEntry;
use zp_core::audit::{ActorId, AuditAction};
use zp_core::policy::{PolicyContext, PolicyDecision, RiskLevel, TrustTier};

use crate::engine::PolicyEngine;

/// The Guard — fast pre-filter stage of the Governance Gate.
///
/// Performs lightweight checks before the heavier PolicyEngine evaluation:
/// - Format validation (required fields present)
/// - Rate limiting (per-actor request throttling)
/// - Blocklist checking (immediately reject known-bad actors)
/// - Trust tier floor (minimum tier enforcement)
///
/// The Guard ensures that only well-formed, legitimate requests proceed to
/// the Policy stage. It acts as a sovereign boundary check ("May I?").
///
/// # Identity
///
/// The blocklist and rate tracker are keyed on `ActorId` directly, which
/// derives `Hash + Eq` in `zp-core`. Earlier versions keyed on
/// `format!("{:?}", actor)`, which silently broke on any Debug-format change
/// — see `RIPPLE-AUDIT.md` §R2.
pub struct Guard {
    /// Blocked actors.
    blocklist: Mutex<HashSet<ActorId>>,
    /// Per-actor request timestamps for rate limiting.
    rate_tracker: Mutex<HashMap<ActorId, Vec<Instant>>>,
    /// Maximum requests per actor per window.
    rate_limit: usize,
    /// Rate limiting window duration.
    rate_window: Duration,
    /// Minimum trust tier allowed.
    min_trust_tier: TrustTier,
}

impl Guard {
    /// Create a new Guard with sensible defaults.
    ///
    /// Defaults:
    /// - rate_limit: 100 requests
    /// - rate_window: 60 seconds
    /// - min_trust_tier: Tier0
    pub fn new() -> Self {
        Self::with_config(100, Duration::from_secs(60), TrustTier::Tier0)
    }

    /// Create a new Guard with custom configuration.
    pub fn with_config(
        rate_limit: usize,
        rate_window: Duration,
        min_trust_tier: TrustTier,
    ) -> Self {
        Self {
            blocklist: Mutex::new(HashSet::new()),
            rate_tracker: Mutex::new(HashMap::new()),
            rate_limit,
            rate_window,
            min_trust_tier,
        }
    }

    /// Check whether a request should be blocked by the guard.
    ///
    /// Returns `Some(PolicyDecision::Block)` if the guard rejects the request,
    /// `None` if the request passes all guard checks.
    pub fn check(&self, context: &PolicyContext, actor: &ActorId) -> Option<PolicyDecision> {
        // Step 1: Format validation
        if context.conversation_id.0.is_nil() {
            return Some(PolicyDecision::Block {
                reason: "Invalid context: missing conversation_id".to_string(),
                policy_module: "Guard::FormatValidation".to_string(),
            });
        }

        // Step 2: Blocklist check
        if self.is_blocked(actor) {
            return Some(PolicyDecision::Block {
                reason: format!("Actor {:?} is blocklisted", actor),
                policy_module: "Guard::Blocklist".to_string(),
            });
        }

        // Step 3: Trust tier floor
        if context.trust_tier < self.min_trust_tier {
            return Some(PolicyDecision::Block {
                reason: format!(
                    "Actor trust tier {:?} below minimum {:?}",
                    context.trust_tier, self.min_trust_tier
                ),
                policy_module: "Guard::TrustTierFloor".to_string(),
            });
        }

        // Step 4: Rate limiting
        if self.is_rate_limited(actor) {
            return Some(PolicyDecision::Block {
                reason: format!(
                    "Rate limit exceeded for actor {:?} ({} requests per {:?})",
                    actor, self.rate_limit, self.rate_window
                ),
                policy_module: "Guard::RateLimit".to_string(),
            });
        }

        None
    }

    /// Add an actor to the blocklist.
    pub fn block_actor(&self, actor: &ActorId) {
        self.blocklist.lock().insert(actor.clone());
    }

    /// Remove an actor from the blocklist.
    pub fn unblock_actor(&self, actor: &ActorId) {
        self.blocklist.lock().remove(actor);
    }

    /// Check if an actor is currently blocklisted.
    pub fn is_blocked(&self, actor: &ActorId) -> bool {
        self.blocklist.lock().contains(actor)
    }

    /// Check if an actor should be rate limited.
    fn is_rate_limited(&self, actor: &ActorId) -> bool {
        let now = Instant::now();
        let mut tracker = self.rate_tracker.lock();

        let timestamps = tracker.entry(actor.clone()).or_default();
        timestamps.retain(|t| now.duration_since(*t) < self.rate_window);

        let is_limited = timestamps.len() >= self.rate_limit;
        if !is_limited {
            timestamps.push(now);
        }
        is_limited
    }
}

impl Default for Guard {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of evaluating an action through the governance gate.
///
/// The gate **does not** produce a sealed `AuditEntry`. It produces an
/// [`UnsealedEntry`] that the caller passes to
/// `zp_audit::AuditStore::append`, which assigns chain position atomically.
/// See `docs/audit-invariant.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateResult {
    /// The policy decision (Allow/Block/Warn/Review/Sanitize)
    pub decision: PolicyDecision,
    /// Risk level assessment for model routing
    pub risk_level: RiskLevel,
    /// Trust tier of the acting entity
    pub trust_tier: TrustTier,
    /// Unsealed audit entry — caller appends this to the real chain.
    pub unsealed: UnsealedEntry,
    /// Optional receipt ID if one was generated
    pub receipt_id: Option<String>,
    /// Names of policy rules that were evaluated
    pub applied_rules: Vec<String>,
}

impl GateResult {
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    pub fn is_blocked(&self) -> bool {
        self.decision.is_blocked()
    }

    pub fn needs_interaction(&self) -> bool {
        self.decision.needs_interaction()
    }
}

/// The GovernanceGate — wires Guard and Policy into one pipeline.
///
/// Unlike the pre-recanonicalization version, this gate does **not** own
/// any audit chain state. The audit chain lives in `zp_audit::AuditStore`,
/// owned by exactly one component per process (in `zp-server`, that's
/// `AppState`). The gate's only responsibility toward the chain is to
/// produce an [`UnsealedEntry`] for the caller to append.
pub struct GovernanceGate {
    /// The guard — fast pre-filter stage
    guard: Guard,
    /// The policy engine that evaluates contexts
    policy_engine: PolicyEngine,
    /// Human-readable name for this gate instance
    gate_name: String,
}

impl GovernanceGate {
    pub fn new(gate_name: &str) -> Self {
        Self::with_policy_engine(gate_name, PolicyEngine::new())
    }

    pub fn with_policy_engine(gate_name: &str, engine: PolicyEngine) -> Self {
        Self::with_guard(gate_name, engine, Guard::new())
    }

    pub fn with_guard(gate_name: &str, engine: PolicyEngine, guard: Guard) -> Self {
        Self {
            guard,
            policy_engine: engine,
            gate_name: gate_name.to_string(),
        }
    }

    /// Evaluate an action through the full governance pipeline.
    ///
    /// Returns a [`GateResult`] carrying the decision, risk level, applied
    /// rules, and an [`UnsealedEntry`] ready for
    /// `zp_audit::AuditStore::append`.
    pub fn evaluate(&self, context: &PolicyContext, actor: ActorId) -> GateResult {
        // Stage 1: GUARD (fast pre-filter)
        let decision = if let Some(guard_block) = self.guard.check(context, &actor) {
            guard_block
        } else {
            // Stage 2: POLICY (graduated decision)
            self.policy_engine.evaluate(context)
        };

        let risk_level = RiskLevel::from_action(&context.action);

        let policy_module = match &decision {
            PolicyDecision::Allow { .. } => "DefaultAllow".to_string(),
            PolicyDecision::Block { policy_module, .. } => policy_module.clone(),
            PolicyDecision::Warn { .. } => "DefaultAllow".to_string(),
            PolicyDecision::Review { .. } => "DefaultAllow".to_string(),
            PolicyDecision::Sanitize { .. } => "DefaultAllow".to_string(),
        };

        // Stage 3: build an UnsealedEntry. The store will assign id,
        // timestamp, prev_hash, and entry_hash atomically.
        let unsealed = UnsealedEntry::new(
            actor,
            AuditAction::PolicyInteraction {
                decision_type: decision_type_name(&decision),
                user_response: None,
            },
            context.conversation_id.clone(),
            decision.clone(),
            policy_module,
        );

        let applied_rules = vec!["PolicyEngine".to_string()];

        GateResult {
            decision,
            risk_level,
            trust_tier: context.trust_tier,
            unsealed,
            receipt_id: None,
            applied_rules,
        }
    }

    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    pub fn name(&self) -> &str {
        &self.gate_name
    }

    pub fn rule_count(&self) -> usize {
        self.policy_engine.rule_count()
    }
}

fn decision_type_name(decision: &PolicyDecision) -> String {
    match decision {
        PolicyDecision::Allow { .. } => "Allow".to_string(),
        PolicyDecision::Block { .. } => "Block".to_string(),
        PolicyDecision::Warn { .. } => "Warn".to_string(),
        PolicyDecision::Review { .. } => "Review".to_string(),
        PolicyDecision::Sanitize { .. } => "Sanitize".to_string(),
    }
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
    fn test_safe_action_creates_unsealed_entry() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("alice".to_string());

        let result = gate.evaluate(&context, actor.clone());

        assert_eq!(result.unsealed.actor, actor);
        assert_eq!(result.unsealed.conversation_id, context.conversation_id);
        assert!(matches!(
            result.unsealed.action,
            AuditAction::PolicyInteraction { .. }
        ));
    }

    #[test]
    fn test_dangerous_action_creates_unsealed_entry() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "secret".to_string(),
        });
        let actor = ActorId::Operator;

        let result = gate.evaluate(&context, actor.clone());

        assert_eq!(result.unsealed.actor, actor);
        assert!(result.is_blocked());
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
        assert!(!result.is_blocked());
    }

    #[test]
    fn test_risk_level_assessment() {
        let gate = GovernanceGate::new("test_gate");

        let low_risk = make_context(ActionType::Chat);
        let result = gate.evaluate(&low_risk, ActorId::Operator);
        assert_eq!(result.risk_level, RiskLevel::Low);

        let high_risk = make_context(ActionType::FileOp {
            op: zp_core::policy::FileOperation::Delete,
            path: "/data/file.txt".to_string(),
        });
        let result = gate.evaluate(&high_risk, ActorId::Operator);
        assert_eq!(result.risk_level, RiskLevel::High);

        let critical_risk = make_context(ActionType::CredentialAccess {
            credential_ref: "secret".to_string(),
        });
        let result = gate.evaluate(&critical_risk, ActorId::Operator);
        assert_eq!(result.risk_level, RiskLevel::Critical);
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

        assert_eq!(results.len(), 5);
        for result in &results {
            assert!(result.is_allowed());
        }
    }

    // Guard-specific tests

    #[test]
    fn test_guard_blocks_blocklisted_actors() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("blocklisted_user".to_string());

        gate.guard().block_actor(&actor);

        let result = gate.evaluate(&context, actor);

        assert!(result.is_blocked());
    }

    #[test]
    fn test_guard_unblocks_actors() {
        let gate = GovernanceGate::new("test_gate");
        let guard = gate.guard();
        let actor = ActorId::User("unblocked_user".to_string());

        guard.block_actor(&actor);
        assert!(guard.is_blocked(&actor));

        guard.unblock_actor(&actor);
        assert!(!guard.is_blocked(&actor));
    }

    #[test]
    fn test_guard_enforces_minimum_trust_tier() {
        let guard = Guard::with_config(100, Duration::from_secs(60), TrustTier::Tier1);
        let mut context = make_context(ActionType::Chat);
        context.trust_tier = TrustTier::Tier0;
        let actor = ActorId::User("low_tier_user".to_string());

        let decision = guard.check(&context, &actor);

        assert!(decision.is_some());
        match decision.unwrap() {
            PolicyDecision::Block {
                reason,
                policy_module,
            } => {
                assert!(reason.contains("trust tier"));
                assert_eq!(policy_module, "Guard::TrustTierFloor");
            }
            _ => panic!("Expected block decision"),
        }
    }

    #[test]
    fn test_guard_allows_valid_requests() {
        let guard = Guard::new();
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("valid_user".to_string());

        let decision = guard.check(&context, &actor);

        assert!(decision.is_none());
    }

    #[test]
    fn test_guard_rate_limiting() {
        let guard = Guard::with_config(3, Duration::from_secs(60), TrustTier::Tier0);
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("rate_limited_user".to_string());

        for _ in 0..3 {
            let decision = guard.check(&context, &actor);
            assert!(decision.is_none(), "Request should pass guard");
        }

        let decision = guard.check(&context, &actor);
        assert!(decision.is_some(), "4th request should be rate limited");
        match decision.unwrap() {
            PolicyDecision::Block {
                reason,
                policy_module,
            } => {
                assert!(reason.contains("Rate limit"));
                assert_eq!(policy_module, "Guard::RateLimit");
            }
            _ => panic!("Expected block decision"),
        }
    }

    #[test]
    fn test_gate_guard_integration() {
        let gate = GovernanceGate::new("test_gate");
        let context = make_context(ActionType::Chat);
        let actor = ActorId::User("test_actor".to_string());

        gate.guard().block_actor(&actor);

        let result = gate.evaluate(&context, actor);

        assert!(result.is_blocked());
        assert_eq!(result.unsealed.policy_decision.is_blocked(), true);
    }

    #[test]
    fn test_guard_with_custom_config() {
        let guard = Guard::with_config(10, Duration::from_secs(30), TrustTier::Tier2);
        let mut context = make_context(ActionType::Chat);
        context.trust_tier = TrustTier::Tier1;
        let actor = ActorId::User("test".to_string());

        let decision = guard.check(&context, &actor);
        assert!(decision.is_some());
    }
}
