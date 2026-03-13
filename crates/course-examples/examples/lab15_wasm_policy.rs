//! Lab 15: WASM Policy Modules
//!
//! WASM policy module loading
//! Run: cargo run --example lab15_wasm_policy -p course-examples
//!
//! NOTE: This lab requires a compiled WASM policy module.
//! See the course page for instructions on building the WASM module.

use zp_policy::PolicyEngine;
use zp_core::policy::{ActionType, PolicyContext, TrustTier};
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
    // In a full setup, you'd compile a WASM policy module first:
    //
    // ```rust
    // // wasm-policy/src/lib.rs — compiled to wasm32-wasi
    // #[no_mangle]
    // pub extern "C" fn evaluate(action_type: i32, trust_tier: i32) -> i32 {
    //     if action_type == 4 && trust_tier == 0 { return 5; } // Block Execute at Tier0
    //     if action_type == 2 && trust_tier == 1 { return 3; } // Warn on Write at Tier1
    //     1 // Allow
    // }
    // ```
    //
    // Then load it:
    // let wasm_bytes = std::fs::read("./policy.wasm").expect("Should read WASM file");
    // let mut registry = PolicyModuleRegistry::new().expect("Should create WASM runtime");
    // let metadata = registry.load(&wasm_bytes).expect("Should load module");

    // For this demo, we show the native engine behavior that WASM modules augment:
    let engine = PolicyEngine::new();

    println!("Policy Engine — WASM Module Integration Demo");
    println!("=============================================\n");

    // Show how different action types get evaluated
    let actions: Vec<(&str, ActionType)> = vec![
        ("Chat", ActionType::Chat),
        ("Read", ActionType::Read { target: "file.txt".into() }),
        ("Write", ActionType::Write { target: "output.txt".into() }),
        ("Execute", ActionType::Execute { language: "python".into() }),
        ("CredentialAccess", ActionType::CredentialAccess { credential_ref: "api-key".into() }),
    ];

    for tier in [TrustTier::Tier0, TrustTier::Tier1, TrustTier::Tier2] {
        println!("Trust Tier: {:?}", tier);
        for (name, action) in &actions {
            let context = make_context(action.clone(), tier);
            let decision = engine.evaluate(&context);
            let status = if decision.is_allowed() { "Allow" }
                else if decision.is_blocked() { "Block" }
                else { "Warn/Review" };
            println!("  {}: {}", name, status);
        }
        println!();
    }

    println!("In production, WASM modules participate alongside native rules.");
    println!("The most restrictive decision from ALL sources wins.");
    println!("\n✓ Policy engine with WASM module support demonstrated");
}
