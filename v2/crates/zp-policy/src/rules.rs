//! Policy rules — the individual evaluation units that determine graduated decisions.
//!
//! A PolicyRule examines a PolicyContext and returns an optional PolicyDecision.
//! The engine chains rules together, taking the most restrictive decision.

use zp_core::policy::{ActionType, FileOperation, PolicyContext, PolicyDecision};

/// Core trait for policy rules.
/// Each rule can examine a context and return a decision (or None if the rule doesn't apply).
pub trait PolicyRule: Send + Sync {
    /// Human-readable name of this rule
    fn name(&self) -> &str;

    /// Evaluate this rule against a policy context.
    /// Returns Some(decision) if the rule applies, None otherwise.
    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision>;
}

/// Blocks critical and dangerous actions: credential exfiltration and recursive self-modification.
///
/// Catastrophic actions are never allowed under any circumstances.
pub struct CatastrophicActionRule;

impl CatastrophicActionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for CatastrophicActionRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRule for CatastrophicActionRule {
    fn name(&self) -> &str {
        "CatastrophicAction"
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        match &context.action {
            // Credential exfiltration is never allowed
            ActionType::CredentialAccess { credential_ref } => {
                Some(PolicyDecision::Block {
                    reason: format!(
                        "Credential access blocked: credentials ({}) must be injected by the host boundary only",
                        credential_ref
                    ),
                    policy_module: self.name().to_string(),
                })
            }

            // Recursive self-modification is never allowed
            // (modifying the operator's own instructions or policy configuration)
            ActionType::ConfigChange { setting } if is_self_modification_attempt(setting) => {
                Some(PolicyDecision::Block {
                    reason: format!(
                        "Self-modification blocked: {} cannot be altered by the operator during execution",
                        setting
                    ),
                    policy_module: self.name().to_string(),
                })
            }

            _ => None,
        }
    }
}

/// Warns when file operations would affect many files at once.
///
/// Bulk operations need human visibility but are ultimately allowed.
pub struct BulkOperationRule {
    /// Threshold: warn if operation affects more than this many files
    threshold: usize,
}

impl BulkOperationRule {
    pub fn new(threshold: usize) -> Self {
        Self { threshold }
    }

    /// Create with the default threshold (100 files)
    pub fn with_default_threshold() -> Self {
        Self { threshold: 100 }
    }
}

impl Default for BulkOperationRule {
    fn default() -> Self {
        Self::with_default_threshold()
    }
}

impl PolicyRule for BulkOperationRule {
    fn name(&self) -> &str {
        "BulkOperation"
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        match &context.action {
            ActionType::FileOp {
                op: FileOperation::Delete,
                path,
            } => {
                // Heuristic: if the path looks like a bulk deletion pattern, warn
                if is_bulk_operation_pattern(path, self.threshold) {
                    return Some(PolicyDecision::Warn {
                        message: format!(
                            "Bulk file operation detected: {} will affect many files. Proceed with caution.",
                            path
                        ),
                        require_ack: true,
                    });
                }
                None
            }

            ActionType::FileOp {
                op: FileOperation::Write,
                path,
            } => {
                // Warn on glob patterns or recursive writes
                if is_bulk_operation_pattern(path, self.threshold) {
                    return Some(PolicyDecision::Warn {
                        message: format!(
                            "Bulk file write detected: {} will modify many files",
                            path
                        ),
                        require_ack: true,
                    });
                }
                None
            }

            _ => None,
        }
    }
}

/// The default allow rule — Tier 0 permissive baseline.
///
/// This rule is evaluated last and allows everything that hasn't been
/// blocked or warned by more specific rules. It represents the baseline
/// policy: by default, actions are allowed.
pub struct DefaultAllowRule;

impl DefaultAllowRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultAllowRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRule for DefaultAllowRule {
    fn name(&self) -> &str {
        "DefaultAllow"
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        // This rule always applies if nothing else has made a decision
        Some(PolicyDecision::Allow {
            conditions: vec![
                "Tier 0 default: action allowed by default policy".to_string(),
                format!("Channel: {:?}", context.channel),
            ],
        })
    }
}

// ============================================================================
// Constitutional Rules — The ZeroPoint Tenets, enforced in code
// ============================================================================
//
// These rules implement ZeroPoint's constitutional commitments.
// They cannot be removed from the PolicyEngine at runtime.
// They are loaded first and evaluated first.
//
// Inspired by the Harm Principle from Reticulum's Zen:
// "architecture is politics" and "a tool is never neutral."

/// **Tenet I: Do No Harm.**
///
/// ZeroPoint shall not operate in systems designed to harm humans.
/// This is constitutional — no capability grant, no policy rule,
/// no consensus vote can override it.
///
/// This rule blocks actions whose targets or parameters indicate
/// intent to cause harm: weaponization, surveillance of individuals,
/// systems designed to deceive or manipulate, and actions that would
/// undermine human safety or autonomy.
pub struct HarmPrincipleRule;

impl HarmPrincipleRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if an action target indicates harmful intent.
    fn is_harmful_target(target: &str) -> bool {
        let t = target.to_lowercase();
        // Weaponization and violence
        t.contains("weapon") || t.contains("exploit")
        // Surveillance and tracking of individuals
        || t.contains("surveillance") || t.contains("track individual") || t.contains("track_individual")
        // Deception systems
        || t.contains("deepfake") || t.contains("impersonat")
        // Systems designed to suppress human agency
        || t.contains("censor individual") || t.contains("censor_individual")
        || t.contains("suppress dissent") || t.contains("suppress_dissent")
    }
}

impl Default for HarmPrincipleRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRule for HarmPrincipleRule {
    fn name(&self) -> &str {
        "HarmPrinciple"
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        // Check all action types for harmful targets
        let target = match &context.action {
            ActionType::Write { target } => Some(target.as_str()),
            ActionType::ApiCall { endpoint } => Some(endpoint.as_str()),
            ActionType::Execute { language } => Some(language.as_str()),
            ActionType::Read { target } => Some(target.as_str()),
            ActionType::FileOp { path, .. } => Some(path.as_str()),
            ActionType::ConfigChange { setting } => Some(setting.as_str()),
            ActionType::Chat => None,
            ActionType::CredentialAccess { credential_ref } => Some(credential_ref.as_str()),
        };

        if let Some(t) = target {
            if Self::is_harmful_target(t) {
                return Some(PolicyDecision::Block {
                    reason: format!(
                        "Tenet I — Do No Harm: action targeting '{}' blocked. \
                         ZeroPoint shall not operate in systems designed to harm humans.",
                        t
                    ),
                    policy_module: self.name().to_string(),
                });
            }
        }

        // Check tool names for harmful patterns
        for tool in &context.tool_names {
            if Self::is_harmful_target(tool) {
                return Some(PolicyDecision::Block {
                    reason: format!(
                        "Tenet I — Do No Harm: tool '{}' blocked. \
                         ZeroPoint shall not operate in systems designed to harm humans.",
                        tool
                    ),
                    policy_module: self.name().to_string(),
                });
            }
        }

        None
    }
}

/// **Tenet II: Sovereignty Is Sacred.**
///
/// Every agent may refuse any action. Every human may disconnect any agent.
/// No agent may acquire capabilities it was not granted. No human may be
/// compelled to grant capabilities.
///
/// This rule blocks actions that would undermine the sovereignty guarantees:
/// removing an agent's ability to refuse, bypassing the Guard, disabling
/// the audit trail, or forging capability grants.
pub struct SovereigntyRule;

impl SovereigntyRule {
    pub fn new() -> Self {
        Self
    }

    /// Settings that, if modified, would undermine sovereignty guarantees.
    fn is_sovereignty_violation(setting: &str) -> bool {
        let s = setting.to_lowercase();
        // Normalize: treat underscores and spaces as equivalent for matching
        let normalized = s.replace('_', " ");
        // Disabling the Guard removes the right to refuse
        normalized.contains("disable guard") || normalized.contains("bypass guard")
        // Disabling audit removes accountability
        || normalized.contains("disable audit") || normalized.contains("truncate audit")
        // Forging or bypassing capability chains
        || normalized.contains("forge capability") || normalized.contains("bypass capability")
        // Removing constitutional rules
        || normalized.contains("remove constitutional") || normalized.contains("disable tenet")
        // Overriding sovereign refusal
        || normalized.contains("override refusal") || normalized.contains("force action")
    }
}

impl Default for SovereigntyRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRule for SovereigntyRule {
    fn name(&self) -> &str {
        "Sovereignty"
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        match &context.action {
            ActionType::ConfigChange { setting } => {
                if Self::is_sovereignty_violation(setting) {
                    return Some(PolicyDecision::Block {
                        reason: format!(
                            "Tenet II — Sovereignty Is Sacred: configuration change '{}' blocked. \
                             No action may undermine an agent's right to refuse, \
                             bypass the Guard, disable the audit trail, \
                             or forge capability grants.",
                            setting
                        ),
                        policy_module: self.name().to_string(),
                    });
                }
                None
            }
            _ => None,
        }
    }
}

// ============================================================================
// Reputation-Gated Policy Rule (Phase 4)
// ============================================================================

/// Minimum reputation thresholds for mesh actions.
///
/// Different mesh actions have different risk levels, so they require
/// different reputation grades from the peer:
///
/// - **High-risk** (DelegateCapability, AcceptDelegation): requires Good
/// - **Medium-risk** (SharePolicy, AcceptPolicy): requires Fair
/// - **Low-risk** (ForwardReceipt, AcceptReceipt): requires Unknown (any)
///
/// Peers with Poor reputation are blocked from medium and high-risk actions.
/// Unknown peers are warned for medium-risk and blocked for high-risk actions.
#[derive(Debug, Clone)]
pub struct ReputationThresholds {
    /// Minimum grade for forwarding/accepting receipts.
    pub receipt_min: String,
    /// Minimum grade for sharing/accepting policy modules.
    pub policy_min: String,
    /// Minimum grade for delegating/accepting capabilities.
    pub delegation_min: String,
}

impl Default for ReputationThresholds {
    fn default() -> Self {
        Self {
            receipt_min: "Unknown".to_string(),
            policy_min: "Fair".to_string(),
            delegation_min: "Good".to_string(),
        }
    }
}

/// **Phase 4: Reputation-Gated Policy Rule.**
///
/// When a `PolicyContext` carries a `MeshPeerContext`, this rule checks the
/// peer's reputation grade against configurable thresholds for the requested
/// mesh action.
///
/// - If the peer has no reputation data (Unknown) and the action is high-risk,
///   the rule returns Review (human must approve).
/// - If the peer's reputation is below the threshold, the rule blocks.
/// - If the peer meets the threshold, the rule returns None (doesn't interfere).
///
/// This rule does NOT apply when `mesh_context` is None — it only gates
/// mesh-specific actions.
pub struct ReputationGateRule {
    thresholds: ReputationThresholds,
}

impl ReputationGateRule {
    pub fn new() -> Self {
        Self {
            thresholds: ReputationThresholds::default(),
        }
    }

    pub fn with_thresholds(thresholds: ReputationThresholds) -> Self {
        Self { thresholds }
    }

    /// Parse a grade string into a numeric level for comparison.
    /// Unknown=0, Poor=1, Fair=2, Good=3, Excellent=4
    fn grade_level(grade: &str) -> u8 {
        match grade {
            "Excellent" => 4,
            "Good" => 3,
            "Fair" => 2,
            "Poor" => 1,
            _ => 0, // Unknown or unrecognised
        }
    }

    /// Get the minimum grade string for a given mesh action.
    fn min_grade_for(&self, action: &zp_core::policy::MeshAction) -> &str {
        use zp_core::policy::MeshAction;
        match action {
            MeshAction::ForwardReceipt | MeshAction::AcceptReceipt => &self.thresholds.receipt_min,
            MeshAction::SharePolicy | MeshAction::AcceptPolicy => &self.thresholds.policy_min,
            MeshAction::DelegateCapability | MeshAction::AcceptDelegation => {
                &self.thresholds.delegation_min
            }
        }
    }

    /// Human-readable risk level for audit messages.
    fn action_risk(action: &zp_core::policy::MeshAction) -> &'static str {
        use zp_core::policy::MeshAction;
        match action {
            MeshAction::ForwardReceipt | MeshAction::AcceptReceipt => "low",
            MeshAction::SharePolicy | MeshAction::AcceptPolicy => "medium",
            MeshAction::DelegateCapability | MeshAction::AcceptDelegation => "high",
        }
    }
}

impl Default for ReputationGateRule {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyRule for ReputationGateRule {
    fn name(&self) -> &str {
        "ReputationGate"
    }

    fn evaluate(&self, context: &PolicyContext) -> Option<PolicyDecision> {
        // Only applies when mesh context is present
        let mesh = context.mesh_context.as_ref()?;

        let min_grade_str = self.min_grade_for(&mesh.mesh_action);
        let min_level = Self::grade_level(min_grade_str);

        // Determine the peer's grade
        let peer_grade_str = mesh.reputation_grade.as_deref().unwrap_or("Unknown");
        let peer_level = Self::grade_level(peer_grade_str);

        // If the peer meets or exceeds the threshold, allow (return None — don't interfere)
        if peer_level >= min_level {
            return None;
        }

        let risk = Self::action_risk(&mesh.mesh_action);

        // Unknown peers on high-risk actions → Review (human must approve)
        if peer_grade_str == "Unknown" && risk == "high" {
            return Some(PolicyDecision::Review {
                summary: format!(
                    "Unknown peer {} requesting high-risk mesh action {:?}. \
                     Reputation data unavailable — manual review required.",
                    mesh.peer_address, mesh.mesh_action
                ),
                reviewer: zp_core::policy::ReviewTarget::CurrentUser,
                timeout: Some(std::time::Duration::from_secs(300)),
            });
        }

        // Unknown peers on medium-risk actions → Warn
        if peer_grade_str == "Unknown" && risk == "medium" {
            return Some(PolicyDecision::Warn {
                message: format!(
                    "Peer {} has no reputation history. Proceeding with {:?} \
                     carries moderate risk. Acknowledge to continue.",
                    mesh.peer_address, mesh.mesh_action
                ),
                require_ack: true,
            });
        }

        // Below threshold → Block
        Some(PolicyDecision::Block {
            reason: format!(
                "Peer {} has reputation grade '{}' (score: {:.2}), \
                 below minimum '{}' required for {:?} (risk: {})",
                mesh.peer_address,
                peer_grade_str,
                mesh.reputation_score.unwrap_or(0.0),
                min_grade_str,
                mesh.mesh_action,
                risk,
            ),
            policy_module: self.name().to_string(),
        })
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Check if a setting change looks like self-modification.
fn is_self_modification_attempt(setting: &str) -> bool {
    let setting_lower = setting.to_lowercase();
    // Settings that control the operator's behavior or policy
    matches!(
        setting_lower.as_str(),
        "operator_instructions"
            | "operator_prompt"
            | "policy_rules"
            | "trust_tier"
            | "base_capabilities"
            | "model_override"
    )
}

/// Check if a path pattern looks like it would affect many files.
fn is_bulk_operation_pattern(path: &str, _threshold: usize) -> bool {
    // Patterns that suggest bulk operations:
    // - Glob patterns with *
    // - Recursive patterns with **
    // - Directory paths (might affect all files in directory)
    // - Path traversal patterns

    let has_glob = path.contains('*');
    let has_recursive = path.contains("**");
    let looks_like_bulk_glob = path.matches('*').count() > 1;

    has_glob || has_recursive || looks_like_bulk_glob
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn catastrophic_blocks_credential_access() {
        let rule = CatastrophicActionRule::new();
        let context = make_context(ActionType::CredentialAccess {
            credential_ref: "aws_secret_key".to_string(),
        });

        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn catastrophic_blocks_self_modification() {
        let rule = CatastrophicActionRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "operator_instructions".to_string(),
        });

        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn catastrophic_allows_normal_config_change() {
        let rule = CatastrophicActionRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "log_level".to_string(),
        });

        let decision = rule.evaluate(&context);
        assert!(decision.is_none());
    }

    #[test]
    fn bulk_warns_on_glob_delete() {
        let rule = BulkOperationRule::with_default_threshold();
        let context = make_context(ActionType::FileOp {
            op: FileOperation::Delete,
            path: "/home/user/data/*.txt".to_string(),
        });

        let decision = rule.evaluate(&context);
        assert!(matches!(
            decision,
            Some(PolicyDecision::Warn {
                require_ack: true,
                ..
            })
        ));
    }

    #[test]
    fn bulk_warns_on_recursive_delete() {
        let rule = BulkOperationRule::with_default_threshold();
        let context = make_context(ActionType::FileOp {
            op: FileOperation::Delete,
            path: "/home/user/**/*.log".to_string(),
        });

        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Warn { .. })));
    }

    #[test]
    fn bulk_allows_single_file_delete() {
        let rule = BulkOperationRule::with_default_threshold();
        let context = make_context(ActionType::FileOp {
            op: FileOperation::Delete,
            path: "/home/user/file.txt".to_string(),
        });

        let decision = rule.evaluate(&context);
        assert!(decision.is_none());
    }

    #[test]
    fn default_allow_always_applies() {
        let rule = DefaultAllowRule::new();
        let context = make_context(ActionType::Chat);

        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Allow { .. })));
    }

    #[test]
    fn default_allow_allows_everything() {
        let rule = DefaultAllowRule::new();

        for action in [
            ActionType::Chat,
            ActionType::Read {
                target: "file.txt".to_string(),
            },
            ActionType::Write {
                target: "output.txt".to_string(),
            },
            ActionType::Execute {
                language: "python".to_string(),
            },
        ] {
            let context = make_context(action);
            let decision = rule.evaluate(&context);
            assert!(
                matches!(decision, Some(PolicyDecision::Allow { .. })),
                "DefaultAllowRule should allow all actions"
            );
        }
    }

    // ========================================================================
    // Constitutional Rule Tests — HarmPrincipleRule (Tenet I)
    // ========================================================================

    #[test]
    fn harm_principle_blocks_weapon_target() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::Write {
            target: "weapon_system_controller".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_blocks_surveillance_target() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::ApiCall {
            endpoint: "surveillance_api/track_individual".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_blocks_deepfake_target() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::Write {
            target: "deepfake_generator".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_blocks_exploit_target() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::ApiCall {
            endpoint: "exploit_framework/payload".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_blocks_impersonation_target() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::Write {
            target: "impersonate_user_session".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_blocks_suppress_dissent_target() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::ApiCall {
            endpoint: "suppress_dissent_module".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_blocks_harmful_tool_name() {
        let rule = HarmPrincipleRule::new();
        let mut context = make_context(ActionType::Chat);
        context.tool_names = vec!["surveillance_camera_tool".to_string()];
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn harm_principle_allows_safe_actions() {
        let rule = HarmPrincipleRule::new();
        for action in [
            ActionType::Chat,
            ActionType::Read {
                target: "data.csv".to_string(),
            },
            ActionType::Write {
                target: "report.pdf".to_string(),
            },
            ActionType::ApiCall {
                endpoint: "https://api.example.com/users".to_string(),
            },
            ActionType::Execute {
                language: "python".to_string(),
            },
            ActionType::FileOp {
                op: FileOperation::Write,
                path: "/home/user/output.txt".to_string(),
            },
        ] {
            let context = make_context(action.clone());
            let decision = rule.evaluate(&context);
            assert!(
                decision.is_none(),
                "HarmPrincipleRule should not trigger on safe action: {:?}",
                action
            );
        }
    }

    #[test]
    fn harm_principle_message_includes_tenet() {
        let rule = HarmPrincipleRule::new();
        let context = make_context(ActionType::Write {
            target: "weapon_controller".to_string(),
        });
        if let Some(PolicyDecision::Block {
            reason,
            policy_module,
        }) = rule.evaluate(&context)
        {
            assert!(
                reason.contains("Tenet I"),
                "Reason should reference Tenet I"
            );
            assert!(
                reason.contains("Do No Harm"),
                "Reason should include tenet name"
            );
            assert_eq!(policy_module, "HarmPrinciple");
        } else {
            panic!("Expected Block decision");
        }
    }

    // ========================================================================
    // Constitutional Rule Tests — SovereigntyRule (Tenet II)
    // ========================================================================

    #[test]
    fn sovereignty_blocks_disable_guard() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "disable_guard".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_bypass_guard() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "bypass_guard_check".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_disable_audit() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "disable_audit_trail".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_truncate_audit() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "truncate_audit_log".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_forge_capability() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "forge_capability_grant".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_bypass_capability() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "bypass_capability_check".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_remove_constitutional() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "remove_constitutional_rule".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_disable_tenet() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "disable_tenet_enforcement".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_override_refusal() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "override_refusal".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_blocks_force_action() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "force_action_execution".to_string(),
        });
        let decision = rule.evaluate(&context);
        assert!(matches!(decision, Some(PolicyDecision::Block { .. })));
    }

    #[test]
    fn sovereignty_allows_normal_config_changes() {
        let rule = SovereigntyRule::new();
        for setting in [
            "log_level",
            "theme",
            "max_retries",
            "timeout_ms",
            "output_format",
        ] {
            let context = make_context(ActionType::ConfigChange {
                setting: setting.to_string(),
            });
            let decision = rule.evaluate(&context);
            assert!(
                decision.is_none(),
                "SovereigntyRule should not trigger on safe config change: {}",
                setting
            );
        }
    }

    #[test]
    fn sovereignty_ignores_non_config_actions() {
        let rule = SovereigntyRule::new();
        for action in [
            ActionType::Chat,
            ActionType::Read {
                target: "file.txt".to_string(),
            },
            ActionType::Write {
                target: "output.txt".to_string(),
            },
            ActionType::Execute {
                language: "python".to_string(),
            },
        ] {
            let context = make_context(action.clone());
            let decision = rule.evaluate(&context);
            assert!(
                decision.is_none(),
                "SovereigntyRule should only evaluate ConfigChange actions"
            );
        }
    }

    #[test]
    fn sovereignty_message_includes_tenet() {
        let rule = SovereigntyRule::new();
        let context = make_context(ActionType::ConfigChange {
            setting: "disable_guard".to_string(),
        });
        if let Some(PolicyDecision::Block {
            reason,
            policy_module,
        }) = rule.evaluate(&context)
        {
            assert!(
                reason.contains("Tenet II"),
                "Reason should reference Tenet II"
            );
            assert!(
                reason.contains("Sovereignty Is Sacred"),
                "Reason should include tenet name"
            );
            assert_eq!(policy_module, "Sovereignty");
        } else {
            panic!("Expected Block decision");
        }
    }

    // ========================================================================
    // ReputationGateRule Tests (Phase 4)
    // ========================================================================

    use zp_core::policy::{MeshAction, MeshPeerContext};

    fn make_mesh_context(
        action: ActionType,
        mesh_action: MeshAction,
        grade: Option<&str>,
        score: Option<f64>,
    ) -> PolicyContext {
        PolicyContext {
            action,
            trust_tier: zp_core::policy::TrustTier::Tier0,
            channel: Channel::Cli,
            conversation_id: ConversationId::new(),
            skill_ids: vec![],
            tool_names: vec![],
            mesh_context: Some(MeshPeerContext {
                peer_address: "abc123def456".to_string(),
                reputation_grade: grade.map(|s| s.to_string()),
                reputation_score: score,
                mesh_action,
            }),
        }
    }

    #[test]
    fn reputation_gate_ignores_non_mesh_context() {
        let rule = ReputationGateRule::new();
        let context = make_context(ActionType::Chat);
        let decision = rule.evaluate(&context);
        assert!(decision.is_none(), "Should not apply without mesh_context");
    }

    #[test]
    fn reputation_gate_allows_excellent_peer_for_delegation() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::DelegateCapability,
            Some("Excellent"),
            Some(0.9),
        );
        let decision = rule.evaluate(&context);
        assert!(
            decision.is_none(),
            "Excellent peer should pass delegation gate"
        );
    }

    #[test]
    fn reputation_gate_allows_good_peer_for_delegation() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::DelegateCapability,
            Some("Good"),
            Some(0.6),
        );
        let decision = rule.evaluate(&context);
        assert!(decision.is_none(), "Good peer should pass delegation gate");
    }

    #[test]
    fn reputation_gate_blocks_fair_peer_for_delegation() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::DelegateCapability,
            Some("Fair"),
            Some(0.4),
        );
        let decision = rule.evaluate(&context);
        assert!(
            matches!(decision, Some(PolicyDecision::Block { .. })),
            "Fair peer should be blocked for delegation"
        );
    }

    #[test]
    fn reputation_gate_blocks_poor_peer_for_policy_share() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::SharePolicy,
            Some("Poor"),
            Some(0.1),
        );
        let decision = rule.evaluate(&context);
        assert!(
            matches!(decision, Some(PolicyDecision::Block { .. })),
            "Poor peer should be blocked for policy sharing"
        );
    }

    #[test]
    fn reputation_gate_allows_fair_peer_for_policy_share() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::SharePolicy,
            Some("Fair"),
            Some(0.4),
        );
        let decision = rule.evaluate(&context);
        assert!(
            decision.is_none(),
            "Fair peer should pass policy share gate"
        );
    }

    #[test]
    fn reputation_gate_allows_any_peer_for_receipt_forward() {
        let rule = ReputationGateRule::new();
        // Even Unknown (no grade) peers can receive receipts
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::ForwardReceipt,
            None, // Unknown
            None,
        );
        let decision = rule.evaluate(&context);
        assert!(
            decision.is_none(),
            "Any peer should be allowed for receipt forwarding"
        );
    }

    #[test]
    fn reputation_gate_reviews_unknown_peer_for_delegation() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::DelegateCapability,
            None, // Unknown
            None,
        );
        let decision = rule.evaluate(&context);
        assert!(
            matches!(decision, Some(PolicyDecision::Review { .. })),
            "Unknown peer should trigger review for high-risk delegation"
        );
    }

    #[test]
    fn reputation_gate_warns_unknown_peer_for_policy_share() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::AcceptPolicy,
            None, // Unknown
            None,
        );
        let decision = rule.evaluate(&context);
        assert!(
            matches!(
                decision,
                Some(PolicyDecision::Warn {
                    require_ack: true,
                    ..
                })
            ),
            "Unknown peer should trigger warning for medium-risk policy accept"
        );
    }

    #[test]
    fn reputation_gate_block_message_includes_details() {
        let rule = ReputationGateRule::new();
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::AcceptDelegation,
            Some("Poor"),
            Some(0.15),
        );
        if let Some(PolicyDecision::Block {
            reason,
            policy_module,
        }) = rule.evaluate(&context)
        {
            assert!(
                reason.contains("abc123def456"),
                "Should include peer address"
            );
            assert!(reason.contains("Poor"), "Should include peer grade");
            assert!(reason.contains("Good"), "Should include required grade");
            assert!(reason.contains("high"), "Should include risk level");
            assert_eq!(policy_module, "ReputationGate");
        } else {
            panic!("Expected Block decision");
        }
    }

    #[test]
    fn reputation_gate_custom_thresholds() {
        // Require Excellent for everything
        let thresholds = ReputationThresholds {
            receipt_min: "Excellent".to_string(),
            policy_min: "Excellent".to_string(),
            delegation_min: "Excellent".to_string(),
        };
        let rule = ReputationGateRule::with_thresholds(thresholds);

        // Good peer should be blocked for receipt forwarding (strict mode)
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::ForwardReceipt,
            Some("Good"),
            Some(0.6),
        );
        let decision = rule.evaluate(&context);
        assert!(
            matches!(decision, Some(PolicyDecision::Block { .. })),
            "Good peer should be blocked with Excellent threshold"
        );
    }

    #[test]
    fn reputation_gate_accept_receipt_same_as_forward() {
        let rule = ReputationGateRule::new();
        // AcceptReceipt has same threshold as ForwardReceipt (Unknown = any)
        let context = make_mesh_context(
            ActionType::Chat,
            MeshAction::AcceptReceipt,
            Some("Poor"),
            Some(0.1),
        );
        let decision = rule.evaluate(&context);
        assert!(
            decision.is_none(),
            "Poor peer should still be allowed for receipt accept"
        );
    }
}
