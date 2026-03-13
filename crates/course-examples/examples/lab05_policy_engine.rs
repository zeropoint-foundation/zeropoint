//! Lab 5: The Policy Engine
//!
//! Policy engine with graduated decisions
//! Run: cargo run --example lab05_policy_engine -p course-examples

use zp_policy::{PolicyEngine, GovernanceGate};
use zp_core::policy::{ActionType, PolicyContext, TrustTier};
use zp_core::audit::ActorId;
use zp_core::{Channel, ConversationId};

/// Helper to build a PolicyContext with sensible defaults.
fn make_context(action: ActionType, tier: TrustTier) -> PolicyContext {
    PolicyContext {
        action,
        trust_tier: tier,
        channel: Channel::Cli,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: None,
    }
}

fn main() {
    let engine = PolicyEngine::new();

    let chat_context = make_context(ActionType::Chat, TrustTier::Tier1);
    let decision = engine.evaluate(&chat_context);
    println!("Chat decision: {:?}", decision);

    let exec_context = make_context(
        ActionType::Execute { language: "python".into() },
        TrustTier::Tier1,
    );
    let decision = engine.evaluate(&exec_context);
    println!("Execute decision: {:?}", decision);

    let cred_context = make_context(
        ActionType::CredentialAccess { credential_ref: "db-production".into() },
        TrustTier::Tier0,
    );
    let decision = engine.evaluate(&cred_context);
    println!("CredentialAccess at Tier0: {:?}", decision);

    let gate = GovernanceGate::new("lab-gate");
    let result = gate.evaluate(&chat_context, ActorId::User("alice".into()));

    println!("\nGovernanceGate result:");
    println!("  Decision: {:?}", result.decision);
    println!("  Risk level: {:?}", result.risk_level);
    println!("  Trust tier: {:?}", result.trust_tier);
    println!("  Applied rules: {:?}", result.applied_rules);
    println!("  is_allowed: {}", result.is_allowed());
    println!("  is_blocked: {}", result.is_blocked());
    println!("  needs_interaction: {}", result.needs_interaction());
}
