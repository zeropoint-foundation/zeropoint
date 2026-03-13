//! Lab 4: Delegation Chains
//!
//! Three-level delegation with invariant checking
//! Run: cargo run --example lab04_delegation_chains -p course-examples

use zp_core::capability_grant::{CapabilityGrant, GrantedCapability, Constraint};
use zp_core::delegation_chain::DelegationChain;
use zp_core::policy::TrustTier;
use chrono::{Utc, Duration};

fn main() {
    let root = CapabilityGrant::new(
        "genesis-hash".to_string(),
        "operator-hash".to_string(),
        GrantedCapability::Read { scope: vec!["data/**".into()] },
        "receipt-root".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(365))
    .with_max_delegation_depth(3);

    let level1 = CapabilityGrant::new(
        "operator-hash".to_string(),
        "agent-hash".to_string(),
        GrantedCapability::Read { scope: vec!["data/reports/**".into()] },
        "receipt-level1".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(90))
    .with_constraint(Constraint::RateLimit { max_actions: 100, window_secs: 3600 })
    .with_constraint(Constraint::RequireReceipt);

    let level2 = CapabilityGrant::new(
        "agent-hash".to_string(),
        "sub-agent-hash".to_string(),
        GrantedCapability::Read { scope: vec!["data/reports/billing/*".into()] },
        "receipt-level2".to_string(),
    )
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(7))
    .with_constraint(Constraint::RateLimit { max_actions: 20, window_secs: 3600 })
    .with_constraint(Constraint::RequireReceipt)
    .with_constraint(Constraint::TimeWindow { start_hour: 9, end_hour: 17 });

    match DelegationChain::verify(vec![root, level1, level2], true) {
        Ok(chain) => {
            println!("✓ Delegation chain verified ({} grants)", chain.grants().len());
            for (i, grant) in chain.grants().iter().enumerate() {
                println!("  Level {}: {} → {}", i, grant.grantor, grant.grantee);
                println!("    Scope: {:?}", grant.capability);
                println!("    Constraints: {}", grant.constraints.len());
            }
        }
        Err(e) => {
            println!("✗ Chain verification failed: {:?}", e);
        }
    }
}
