//! Lab 1: Your First Key
//!
//! Key hierarchy: Genesis → Operator → Agent
//! Run: cargo run --example lab01_first_key -p course-examples

use zp_keys::{GenesisKey, OperatorKey, AgentKey};
use chrono::{Utc, Duration};

fn main() {
    // Step 1: Generate the genesis key
    let genesis = GenesisKey::generate("alice");
    println!("Genesis public key: {}", hex::encode(genesis.public_key()));
    println!("Genesis role: {:?}", genesis.certificate().body.role);

    // Step 2: Issue an operator key (expires in 365 days)
    let operator = OperatorKey::generate(
        "operator-alpha",
        &genesis,
        Some(Utc::now() + Duration::days(365)),
    );
    println!("\nOperator public key: {}", hex::encode(operator.public_key()));
    println!("Operator issuer: {}", operator.certificate().body.issuer_public_key);

    // Step 3: Issue an agent key (expires in 30 days)
    let agent = AgentKey::generate(
        "agent-001",
        &operator,
        Some(Utc::now() + Duration::days(30)),
    );
    println!("\nAgent public key: {}", hex::encode(agent.public_key()));
    println!("Agent depth: {}", agent.certificate().body.depth);

    // Step 4: Verify the chain
    assert_eq!(
        agent.certificate().body.issuer_public_key,
        hex::encode(operator.public_key()),
        "Agent's issuer must be the operator"
    );
    assert_eq!(
        operator.certificate().body.issuer_public_key,
        hex::encode(genesis.public_key()),
        "Operator's issuer must be genesis"
    );

    assert!(
        agent.certificate().verify_signature()
            .expect("Signature verification should not error"),
        "Agent certificate signature must verify"
    );
    assert!(
        operator.certificate().verify_signature()
            .expect("Signature verification should not error"),
        "Operator certificate signature must verify"
    );

    println!("\n✓ Full chain verified: Genesis → Operator → Agent");
    println!("  Depths: 0 → 1 → 2");
    println!("  Every signature verifies.");
}
