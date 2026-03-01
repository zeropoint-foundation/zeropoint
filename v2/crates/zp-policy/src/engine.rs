//! The policy evaluation engine — the heart of the graduated policy decision system.
//!
//! The engine chains multiple PolicyRule implementations and returns the most
//! restrictive decision according to the severity hierarchy:
//! Block > Review > Warn > Sanitize > Allow.
//!
//! Phase 2 adds WASM policy module support: the engine evaluates native Rust
//! rules first (constitutional rules are always first), then evaluates any
//! active WASM modules from the PolicyModuleRegistry.

use crate::policy_registry::PolicyModuleRegistry;
use crate::rules::{
    BulkOperationRule, CatastrophicActionRule, DefaultAllowRule, HarmPrincipleRule, PolicyRule,
    ReputationGateRule, SovereigntyRule,
};
use tracing::debug;
use zp_core::capability::{Capability, ModelClass, ModelPreference};
use zp_core::policy::{PolicyContext, PolicyDecision, RiskLevel};

/// The policy evaluation engine.
///
/// Maintains a set of native policy rules plus an optional WASM module registry.
/// Native rules are evaluated first, then WASM modules. The most restrictive
/// decision across all sources wins.
pub struct PolicyEngine {
    rules: Vec<Box<dyn PolicyRule>>,
    /// Optional WASM policy module registry.
    wasm_registry: Option<PolicyModuleRegistry>,
}

impl PolicyEngine {
    /// Create a new engine with the default set of native rules (no WASM).
    pub fn new() -> Self {
        Self::with_rules(Self::default_rules())
    }

    /// Create an engine with a custom set of native rules (no WASM).
    pub fn with_rules(rules: Vec<Box<dyn PolicyRule>>) -> Self {
        Self {
            rules,
            wasm_registry: None,
        }
    }

    /// Create an engine with default native rules plus a WASM registry.
    pub fn with_wasm(registry: PolicyModuleRegistry) -> Self {
        Self {
            rules: Self::default_rules(),
            wasm_registry: Some(registry),
        }
    }

    /// Attach a WASM policy module registry to this engine.
    pub fn set_wasm_registry(&mut self, registry: PolicyModuleRegistry) {
        self.wasm_registry = Some(registry);
    }

    /// Get a reference to the WASM registry, if one is attached.
    pub fn wasm_registry(&self) -> Option<&PolicyModuleRegistry> {
        self.wasm_registry.as_ref()
    }

    /// Get the default set of Phase 1 policy rules.
    ///
    /// Constitutional rules (HarmPrinciple, Sovereignty) are loaded first
    /// and evaluated first. They cannot be removed at runtime.
    /// Order: Constitutional → Catastrophic → Bulk → DefaultAllow
    fn default_rules() -> Vec<Box<dyn PolicyRule>> {
        vec![
            // Constitutional rules — the ZeroPoint Tenets, enforced in code.
            // These MUST be first. They cannot be overridden.
            Box::new(HarmPrincipleRule::new()),
            Box::new(SovereigntyRule::new()),
            // Operational rules
            Box::new(CatastrophicActionRule::new()),
            Box::new(BulkOperationRule::with_default_threshold()),
            // Phase 4: Reputation-gated mesh actions
            Box::new(ReputationGateRule::new()),
            // Permissive baseline — evaluated last
            Box::new(DefaultAllowRule::new()),
        ]
    }

    /// Add a rule to the engine.
    pub fn add_rule(&mut self, rule: Box<dyn PolicyRule>) {
        self.rules.push(rule);
    }

    /// Evaluate a policy context against all rules (native + WASM).
    ///
    /// Evaluation order:
    /// 1. Native Rust rules (constitutional first, then operational)
    /// 2. WASM policy modules (in registration/priority order)
    ///
    /// Returns the most restrictive decision according to:
    /// Block > Review > Warn > Sanitize > Allow.
    pub fn evaluate(&self, context: &PolicyContext) -> PolicyDecision {
        debug!(
            "Evaluating policy context: action={:?}, trust_tier={:?}",
            context.action, context.trust_tier
        );

        let mut decisions = Vec::new();

        // Phase 1: Evaluate native Rust rules
        for rule in &self.rules {
            if let Some(decision) = rule.evaluate(context) {
                debug!("Rule '{}' returned: {:?}", rule.name(), decision);
                decisions.push((rule.name().to_string(), decision));
            }
        }

        // Phase 2: Evaluate WASM policy modules
        if let Some(registry) = &self.wasm_registry {
            let wasm_decisions = registry.evaluate_all(context);
            for (name, decision) in wasm_decisions {
                debug!("WASM rule '{}' returned: {:?}", name, decision);
                decisions.push((name, decision));
            }
        }

        // Pick the most restrictive decision
        let final_decision = self.most_restrictive(decisions);
        debug!("Final policy decision: {:?}", final_decision);

        final_decision
    }

    /// Determine what capabilities are available for a given context.
    ///
    /// For Phase 1, this returns a basic set of capabilities based on
    /// the trust tier and the skills being invoked.
    ///
    /// In Phase 2, this will be extended by the WASM policy modules.
    pub fn capabilities_for(
        &self,
        context: &PolicyContext,
        skill_ids: &[String],
    ) -> Vec<Capability> {
        debug!("Determining capabilities for {} skills", skill_ids.len());

        let mut capabilities = Vec::new();

        // Basic Tier 0 capabilities - reading and safe operations
        capabilities.push(Capability {
            name: "read_files".to_string(),
            tools: vec![],
            source_skill: None,
        });

        capabilities.push(Capability {
            name: "basic_tools".to_string(),
            tools: vec![],
            source_skill: None,
        });

        // Add capabilities for each active skill
        for skill_id in skill_ids {
            capabilities.push(Capability {
                name: format!("skill_{}", skill_id),
                tools: vec![],
                source_skill: Some(skill_id.clone()),
            });
        }

        // Higher trust tiers unlock more capabilities
        match context.trust_tier {
            zp_core::policy::TrustTier::Tier0 => {
                // Tier 0: read-only and basic tools
            }
            zp_core::policy::TrustTier::Tier1 => {
                // Tier 1: add write and execution capabilities
                capabilities.push(Capability {
                    name: "write_files".to_string(),
                    tools: vec![],
                    source_skill: None,
                });
                capabilities.push(Capability {
                    name: "execute_code".to_string(),
                    tools: vec![],
                    source_skill: None,
                });
            }
            zp_core::policy::TrustTier::Tier2 => {
                // Tier 2: full capabilities including system operations
                capabilities.push(Capability {
                    name: "write_files".to_string(),
                    tools: vec![],
                    source_skill: None,
                });
                capabilities.push(Capability {
                    name: "execute_code".to_string(),
                    tools: vec![],
                    source_skill: None,
                });
                capabilities.push(Capability {
                    name: "system_commands".to_string(),
                    tools: vec![],
                    source_skill: None,
                });
            }
        }

        debug!("Returning {} capabilities", capabilities.len());
        capabilities
    }

    /// Determine the preferred model class for this request.
    ///
    /// Uses risk assessment based on the action type to recommend
    /// an appropriate model. Critical actions require strong models,
    /// while low-risk actions can use any model.
    pub fn model_for(&self, context: &PolicyContext) -> ModelPreference {
        let risk_level = RiskLevel::from_action(&context.action);

        debug!(
            "Assessing model preference for risk level: {:?}",
            risk_level
        );

        let (preference, reason, overridable) = match risk_level {
            RiskLevel::Low => (
                ModelClass::Any,
                "Low-risk action: any model is acceptable".to_string(),
                true,
            ),
            RiskLevel::Medium => (
                ModelClass::Strong,
                "Medium-risk action: prefer a capable model".to_string(),
                true,
            ),
            RiskLevel::High => (
                ModelClass::Strong,
                "High-risk action: prefer a strong model for reliability".to_string(),
                true,
            ),
            RiskLevel::Critical => (
                ModelClass::RequireStrong,
                "Critical-risk action: require a strong, well-tested model".to_string(),
                false,
            ),
        };

        ModelPreference {
            preference,
            reason,
            overridable,
        }
    }

    /// Determine the relative severity of a PolicyDecision.
    /// Used for comparison to find the most restrictive decision.
    fn decision_severity(decision: &PolicyDecision) -> u8 {
        match decision {
            PolicyDecision::Block { .. } => 5,
            PolicyDecision::Review { .. } => 4,
            PolicyDecision::Warn { .. } => 3,
            PolicyDecision::Sanitize { .. } => 2,
            PolicyDecision::Allow { .. } => 1,
        }
    }

    /// Select the most restrictive decision from a list.
    fn most_restrictive(&self, decisions: Vec<(String, PolicyDecision)>) -> PolicyDecision {
        if decisions.is_empty() {
            // Fallback: if no rules returned a decision, allow by default
            return PolicyDecision::Allow {
                conditions: vec!["No policy rules applied".to_string()],
            };
        }

        // Find the most restrictive
        decisions
            .into_iter()
            .max_by(|a, b| {
                let severity_a = Self::decision_severity(&a.1);
                let severity_b = Self::decision_severity(&b.1);
                severity_a.cmp(&severity_b)
            })
            .map(|(_, decision)| decision)
            .unwrap_or_else(|| PolicyDecision::Allow {
                conditions: vec!["No policy decision made".to_string()],
            })
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
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
            trust_tier: zp_core::policy::TrustTier::Tier0,
            channel: Channel::Cli,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![],
            mesh_context: None,
        }
    }

    #[test]
    fn engine_evaluates_catastrophic_actions() {
        let engine = PolicyEngine::new();
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "aws_key".to_string(),
        });

        let decision = engine.evaluate(&context);
        assert!(decision.is_blocked());
    }

    #[test]
    fn engine_allows_safe_actions() {
        let engine = PolicyEngine::new();
        let context = make_context(ActionType::Chat);

        let decision = engine.evaluate(&context);
        assert!(decision.is_allowed());
    }

    #[test]
    fn engine_warns_on_bulk_operations() {
        let engine = PolicyEngine::new();
        let context = make_context(ActionType::FileOp {
            op: zp_core::policy::FileOperation::Delete,
            path: "/data/*.txt".to_string(),
        });

        let decision = engine.evaluate(&context);
        assert!(matches!(decision, PolicyDecision::Warn { .. }));
    }

    #[test]
    fn engine_returns_most_restrictive_decision() {
        // Create an engine with multiple rules
        let engine = PolicyEngine::new();

        // All rules apply to Chat (should be Allow)
        let context = make_context(ActionType::Chat);
        let decision = engine.evaluate(&context);
        assert!(matches!(decision, PolicyDecision::Allow { .. }));

        // Catastrophic action (should be Block, even if other rules say Allow)
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "secret".to_string(),
        });
        let decision = engine.evaluate(&context);
        assert!(decision.is_blocked());
    }

    #[test]
    fn engine_provides_capabilities_by_tier() {
        let engine = PolicyEngine::new();

        let mut context = make_context(ActionType::Chat);
        context.trust_tier = zp_core::policy::TrustTier::Tier0;
        let caps = engine.capabilities_for(&context, &[]);
        // Tier 0 has read and basic tools
        assert!(caps.iter().any(|c| c.name == "read_files"));
        assert!(!caps.iter().any(|c| c.name == "write_files"));

        context.trust_tier = zp_core::policy::TrustTier::Tier1;
        let caps = engine.capabilities_for(&context, &[]);
        // Tier 1 has write and execute
        assert!(caps.iter().any(|c| c.name == "write_files"));
        assert!(caps.iter().any(|c| c.name == "execute_code"));

        context.trust_tier = zp_core::policy::TrustTier::Tier2;
        let caps = engine.capabilities_for(&context, &[]);
        // Tier 2 has everything
        assert!(caps.iter().any(|c| c.name == "system_commands"));
    }

    #[test]
    fn engine_determines_model_preference_by_risk() {
        let engine = PolicyEngine::new();

        // Low risk -> Any model
        let context = make_context(ActionType::Chat);
        let pref = engine.model_for(&context);
        assert_eq!(pref.preference, ModelClass::Any);
        assert!(pref.overridable);

        // Critical risk -> Strong model required
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "secret".to_string(),
        });
        let pref = engine.model_for(&context);
        assert_eq!(pref.preference, ModelClass::RequireStrong);
        assert!(!pref.overridable);
    }

    // ====================================================================
    // Constitutional Rules Integration Tests
    // ====================================================================

    #[test]
    fn engine_blocks_harmful_actions_via_harm_principle() {
        let engine = PolicyEngine::new();
        let context = make_context(ActionType::Write {
            target: "weapon_system".to_string(),
        });
        let decision = engine.evaluate(&context);
        assert!(
            decision.is_blocked(),
            "Engine should block harmful targets via HarmPrincipleRule"
        );
    }

    #[test]
    fn engine_blocks_sovereignty_violations() {
        let engine = PolicyEngine::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "disable_guard".to_string(),
        });
        let decision = engine.evaluate(&context);
        assert!(
            decision.is_blocked(),
            "Engine should block sovereignty violations via SovereigntyRule"
        );
    }

    #[test]
    fn engine_constitutional_rules_override_default_allow() {
        // Even though DefaultAllowRule says Allow, the constitutional rules must win
        let engine = PolicyEngine::new();

        let context = make_context(ActionType::ApiCall {
            endpoint: "surveillance_tracker".to_string(),
        });
        let decision = engine.evaluate(&context);
        assert!(
            decision.is_blocked(),
            "Constitutional Block must override DefaultAllow"
        );
    }

    #[test]
    fn engine_accepts_custom_rules() {
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
        let context = make_context(ActionType::Chat);

        let decision = engine.evaluate(&context);
        assert!(decision.is_blocked());
    }

    // ====================================================================
    // WASM Policy Module Integration Tests
    // ====================================================================

    /// WAT module that always returns Allow.
    const WASM_ALLOW_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "WasmAllow")
            (data (i32.const 64) "{\"Allow\":{\"conditions\":[\"wasm_allowed\"]}}")
            (global $bump (mut i32) (i32.const 1024))
            (func (export "name_ptr") (result i32) i32.const 0)
            (func (export "name_len") (result i32) i32.const 9)
            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                global.get $bump
                local.set $ptr
                global.get $bump
                local.get $size
                i32.add
                global.set $bump
                local.get $ptr
            )
            (func (export "evaluate") (param $ctx_ptr i32) (param $ctx_len i32) (result i32)
                i32.const 64
            )
            (func (export "evaluate_len") (result i32) i32.const 41)
        )
    "#;

    /// WAT module that always blocks.
    /// JSON: {"Block":{"reason":"no","policy_module":"WBlk"}}
    /// Length: 42 + 2 + 4 = 48
    const WASM_BLOCK_WAT: &str = r#"
        (module
            (memory (export "memory") 1)
            (data (i32.const 0) "WasmBlock")
            (data (i32.const 64) "{\"Block\":{\"reason\":\"no\",\"policy_module\":\"WBlk\"}}")
            (global $bump (mut i32) (i32.const 1024))
            (func (export "name_ptr") (result i32) i32.const 0)
            (func (export "name_len") (result i32) i32.const 9)
            (func (export "alloc") (param $size i32) (result i32)
                (local $ptr i32)
                global.get $bump
                local.set $ptr
                global.get $bump
                local.get $size
                i32.add
                global.set $bump
                local.get $ptr
            )
            (func (export "evaluate") (param $ctx_ptr i32) (param $ctx_len i32) (result i32)
                i32.const 64
            )
            (func (export "evaluate_len") (result i32) i32.const 48)
        )
    "#;

    #[test]
    fn engine_with_wasm_allow_module() {
        let registry = PolicyModuleRegistry::new().unwrap();
        registry.load(WASM_ALLOW_WAT.as_bytes()).unwrap();

        let engine = PolicyEngine::with_wasm(registry);
        let context = make_context(ActionType::Chat);

        // Native DefaultAllow + WASM Allow → Allow wins (most restrictive is still Allow)
        let decision = engine.evaluate(&context);
        assert!(decision.is_allowed());
    }

    #[test]
    fn engine_wasm_block_overrides_native_allow() {
        let registry = PolicyModuleRegistry::new().unwrap();
        registry.load(WASM_BLOCK_WAT.as_bytes()).unwrap();

        let engine = PolicyEngine::with_wasm(registry);
        let context = make_context(ActionType::Chat);

        // Native DefaultAllow says Allow, WASM says Block → Block wins
        let decision = engine.evaluate(&context);
        assert!(decision.is_blocked());
    }

    #[test]
    fn engine_native_constitutional_overrides_wasm_allow() {
        let registry = PolicyModuleRegistry::new().unwrap();
        registry.load(WASM_ALLOW_WAT.as_bytes()).unwrap();

        let engine = PolicyEngine::with_wasm(registry);
        // Sovereignty violation — native constitutional rule blocks this
        let context = make_context(ActionType::ConfigChange {
            setting: "disable_guard".to_string(),
        });

        let decision = engine.evaluate(&context);
        // Constitutional Block beats WASM Allow
        assert!(decision.is_blocked());
    }

    #[test]
    fn engine_without_wasm_registry_works() {
        // Engine with no WASM registry should work exactly as before
        let engine = PolicyEngine::new();
        assert!(engine.wasm_registry().is_none());

        let context = make_context(ActionType::Chat);
        let decision = engine.evaluate(&context);
        assert!(decision.is_allowed());
    }

    #[test]
    fn engine_set_wasm_registry_after_creation() {
        let mut engine = PolicyEngine::new();
        assert!(engine.wasm_registry().is_none());

        let registry = PolicyModuleRegistry::new().unwrap();
        registry.load(WASM_BLOCK_WAT.as_bytes()).unwrap();
        engine.set_wasm_registry(registry);

        assert!(engine.wasm_registry().is_some());

        let context = make_context(ActionType::Chat);
        let decision = engine.evaluate(&context);
        assert!(decision.is_blocked());
    }

    // ====================================================================
    // Reputation-Gated Policy Integration Tests (Phase 4)
    // ====================================================================

    use zp_core::policy::{MeshAction, MeshPeerContext};

    #[test]
    fn engine_blocks_poor_peer_delegation() {
        let engine = PolicyEngine::new();
        let mut context = make_context(ActionType::Chat);
        context.mesh_context = Some(MeshPeerContext {
            peer_address: "peer-abc".to_string(),
            reputation_grade: Some("Poor".to_string()),
            reputation_score: Some(0.15),
            mesh_action: MeshAction::DelegateCapability,
        });

        let decision = engine.evaluate(&context);
        assert!(
            decision.is_blocked(),
            "Engine should block poor peer delegation"
        );
    }

    #[test]
    fn engine_allows_good_peer_delegation() {
        let engine = PolicyEngine::new();
        let mut context = make_context(ActionType::Chat);
        context.mesh_context = Some(MeshPeerContext {
            peer_address: "peer-xyz".to_string(),
            reputation_grade: Some("Good".to_string()),
            reputation_score: Some(0.65),
            mesh_action: MeshAction::DelegateCapability,
        });

        let decision = engine.evaluate(&context);
        assert!(
            decision.is_allowed(),
            "Engine should allow good peer delegation"
        );
    }

    #[test]
    fn engine_reviews_unknown_peer_delegation() {
        let engine = PolicyEngine::new();
        let mut context = make_context(ActionType::Chat);
        context.mesh_context = Some(MeshPeerContext {
            peer_address: "peer-new".to_string(),
            reputation_grade: None,
            reputation_score: None,
            mesh_action: MeshAction::AcceptDelegation,
        });

        let decision = engine.evaluate(&context);
        // Review has severity 4 > Allow severity 1, so Review wins
        assert!(
            matches!(decision, PolicyDecision::Review { .. }),
            "Engine should require review for unknown peer delegation, got: {:?}",
            decision
        );
    }

    #[test]
    fn engine_reputation_gate_does_not_interfere_with_non_mesh() {
        let engine = PolicyEngine::new();
        // Normal context with no mesh_context should work as before
        let context = make_context(ActionType::Chat);
        let decision = engine.evaluate(&context);
        assert!(decision.is_allowed());
    }
}
