//! Lab 3: Capability Grants
//!
//! Capability grants with constraints
//! Run: cargo run --example lab03_capability_grants -p course-examples

use chrono::{Duration, Utc};
use zp_core::capability_grant::{CapabilityGrant, Constraint, GrantedCapability};
use zp_core::policy::TrustTier;

fn main() {
    let grantor = "operator-alpha-hash";
    let grantee = "agent-001-hash";

    let grant = CapabilityGrant::new(
        grantor.to_string(),
        grantee.to_string(),
        GrantedCapability::Read {
            scope: vec!["data/reports/*".into()],
        },
        "receipt-001".to_string(),
    )
    .with_constraint(Constraint::MaxCost(0.50))
    .with_constraint(Constraint::RateLimit {
        max_actions: 100,
        window_secs: 3600,
    })
    .with_constraint(Constraint::TimeWindow {
        start_hour: 9,
        end_hour: 17,
    })
    .with_constraint(Constraint::RequireReceipt)
    .with_trust_tier(TrustTier::Tier2)
    .with_expiration(Utc::now() + Duration::days(30))
    .with_max_delegation_depth(2);

    println!("Grant ID: {}", grant.id);
    println!("Capability: {:?}", grant.capability);
    println!("Constraints: {}", grant.constraints.len());
    for c in &grant.constraints {
        println!("  - {:?}", c);
    }
    println!("Trust tier: {:?}", grant.trust_tier);
    println!("Max delegation depth: {:?}", grant.max_delegation_depth);
    println!("Expires: {:?}", grant.expires_at);

    let api_grant = CapabilityGrant::new(
        grantor.to_string(),
        grantee.to_string(),
        GrantedCapability::ApiCall {
            endpoints: vec!["api.weather.com/**".into()],
        },
        "receipt-002".to_string(),
    )
    .with_constraint(Constraint::MaxCost(0.01))
    .with_constraint(Constraint::RateLimit {
        max_actions: 10,
        window_secs: 60,
    })
    .with_constraint(Constraint::ScopeRestriction {
        allowed: vec!["api.weather.com/v2/**".into()],
        denied: vec!["api.weather.com/v2/admin/**".into()],
    });

    println!("\nAPI Grant scope restriction:");
    for c in &api_grant.constraints {
        if let Constraint::ScopeRestriction { allowed, denied } = c {
            println!("  Allowed: {:?}", allowed);
            println!("  Denied: {:?}", denied);
        }
    }
    println!("✓ Both grants constructed with constraints");
}
