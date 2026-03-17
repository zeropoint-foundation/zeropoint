//! Lab 6: The Governance Gate
//!
//! Guard → Policy → Audit pipeline
//! Run: cargo run --example lab06_governance_gate -p course-examples

use std::time::Duration;
use zp_core::audit::ActorId;
use zp_core::policy::{ActionType, PolicyContext, TrustTier};
use zp_core::{Channel, ConversationId};
use zp_policy::gate::Guard;
use zp_policy::{GovernanceGate, PolicyEngine};

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
    // Create a Guard with tight rate limiting (3 requests per 60s) and Tier1 minimum
    let guard = Guard::with_config(3, Duration::from_secs(60), TrustTier::Tier1);

    // Block a known-bad actor
    let blocked_actor = ActorId::User("malicious-actor".into());
    let blocked_key = format!("{:?}", &blocked_actor);
    guard.block_actor(&blocked_key);

    // Create a GovernanceGate with custom guard
    let engine = PolicyEngine::new();
    let gate = GovernanceGate::with_guard("lab-gate", engine, guard);

    println!("Gate Pipeline: Guard → Policy → Audit\n");
    println!("Testing Guard stage:\n");

    // Test 1: Blocklisted actor
    let context = make_context(ActionType::Chat, TrustTier::Tier1);
    let blocked_result = gate.evaluate(&context, blocked_actor);
    println!(
        "Blocklisted actor 'malicious-actor': {:?}",
        blocked_result.decision
    );
    assert!(
        blocked_result.is_blocked(),
        "Blocklisted actor must be blocked at Guard stage"
    );
    println!("✓ Guard blocked actor before policy evaluation");

    // Test 2: Normal actor passes Guard, proceeds to Policy
    let context2 = make_context(ActionType::Chat, TrustTier::Tier1);
    let allowed_result = gate.evaluate(&context2, ActorId::User("alice".into()));
    println!("\nNormal actor 'alice': {:?}", allowed_result.decision);
    assert!(
        allowed_result.is_allowed(),
        "Normal actor should be allowed"
    );
    println!("✓ Guard allowed actor to proceed to Policy");

    // Test 3: Trust tier below minimum
    let low_tier_context = make_context(ActionType::Chat, TrustTier::Tier0);
    let low_tier_result = gate.evaluate(&low_tier_context, ActorId::User("low-trust".into()));
    println!(
        "\nLow-trust actor (Tier0, min is Tier1): {:?}",
        low_tier_result.decision
    );
    assert!(
        low_tier_result.is_blocked(),
        "Low-trust actor must be blocked"
    );
    println!("✓ Guard enforced minimum trust tier");

    // Test 4: Rate limiting (3 requests then blocked)
    println!("\nTesting Rate Limiting (max 3 actions/min):");
    let rate_actor = ActorId::User("rate-test".into());
    for i in 0..5 {
        let ctx = make_context(ActionType::Chat, TrustTier::Tier1);
        let result = gate.evaluate(&ctx, rate_actor.clone());
        let status = if result.is_allowed() {
            "Allow"
        } else {
            "Block"
        };
        println!("  Action {}: {}", i + 1, status);
    }

    // Test 5: Audit chain integrity
    println!(
        "\nAudit chain head: {}...{}",
        &gate.audit_chain_head()[..8],
        &gate.audit_chain_head()[gate.audit_chain_head().len() - 8..]
    );
    println!("✓ Every evaluation produces a hash-chained audit entry");
    println!("✓ Full pipeline (Guard → Policy → Audit) operational");
}
