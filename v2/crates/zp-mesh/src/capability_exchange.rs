//! Capability negotiation at link establishment.
//!
//! When two agents form a link, they exchange capability offers and requests.
//! The result is a set of mutually agreed `CapabilityGrant`s that define what
//! each side is permitted to do over the link.
//!
//! ```text
//! Initiator                          Responder
//!     │                                  │
//!     │── CapabilityRequest ────────────▶│  (I want these, I offer these)
//!     │                                  │
//!     │◀──────────── CapabilityResponse ─│  (Granted these, denied these)
//!     │                                  │
//!     │═══ Link active with grants ═════▶│
//! ```
//!
//! Design constraints:
//! - Negotiation is bilateral: both sides propose and accept
//! - Most restrictive constraint wins when both sides restrict
//! - Each agreed grant is signed by the granting party
//! - Backward compatible: links without capabilities still work (empty grants)

use serde::{Deserialize, Serialize};
use zp_core::capability_grant::{CapabilityGrant, Constraint, GrantedCapability};
use zp_core::policy::TrustTier;

/// A request for capabilities, sent during link establishment.
///
/// The initiator says: "I would like these capabilities, and I offer you these."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Capabilities the sender is requesting from the peer
    pub requested: Vec<GrantedCapability>,
    /// Capabilities the sender is offering to the peer
    pub offered: Vec<GrantedCapability>,
    /// Trust tier the sender claims (peer may downgrade)
    pub claimed_tier: TrustTier,
}

/// A response to a capability request.
///
/// The responder says: "I grant you these (possibly constrained), I deny these."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResponse {
    /// Capabilities granted to the requester (may be subset of requested)
    pub granted: Vec<GrantedCapability>,
    /// Capabilities denied (with reasons)
    pub denied: Vec<DeniedCapability>,
    /// Capabilities the responder accepts from the offer
    pub accepted: Vec<GrantedCapability>,
    /// Trust tier assigned by the responder (may differ from claimed)
    pub assigned_tier: TrustTier,
}

/// A capability that was denied during negotiation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeniedCapability {
    /// What was denied
    pub capability: GrantedCapability,
    /// Why it was denied
    pub reason: String,
}

/// The result of a bilateral capability negotiation.
///
/// Contains the agreed grants for both directions of the link.
#[derive(Debug, Clone)]
pub struct NegotiationResult {
    /// Grants from the responder to the initiator
    pub initiator_grants: Vec<CapabilityGrant>,
    /// Grants from the initiator to the responder
    pub responder_grants: Vec<CapabilityGrant>,
    /// Capabilities that were denied
    pub denied: Vec<DeniedCapability>,
    /// Effective trust tier for this link
    pub effective_tier: TrustTier,
}

/// Policy for what capabilities a node is willing to grant.
///
/// Each node configures its own policy. During negotiation,
/// incoming requests are evaluated against this policy.
#[derive(Debug, Clone)]
pub struct CapabilityPolicy {
    /// Maximum trust tier we'll assign to any peer
    pub max_tier: TrustTier,
    /// Capabilities we're willing to grant (with constraints)
    pub grantable: Vec<GrantableCapability>,
    /// Default constraints applied to all grants
    pub default_constraints: Vec<Constraint>,
}

/// A capability we're willing to grant, with optional constraints.
#[derive(Debug, Clone)]
pub struct GrantableCapability {
    /// The capability type we can grant
    pub capability: GrantedCapability,
    /// Constraints we always apply to this capability
    pub constraints: Vec<Constraint>,
}

impl CapabilityPolicy {
    /// Create a restrictive policy that grants nothing.
    pub fn deny_all() -> Self {
        Self {
            max_tier: TrustTier::Tier0,
            grantable: Vec::new(),
            default_constraints: vec![Constraint::RequireReceipt],
        }
    }

    /// Create a permissive policy for testing.
    pub fn allow_all() -> Self {
        Self {
            max_tier: TrustTier::Tier2,
            grantable: vec![
                GrantableCapability {
                    capability: GrantedCapability::Read {
                        scope: vec!["*".to_string()],
                    },
                    constraints: vec![],
                },
                GrantableCapability {
                    capability: GrantedCapability::Write {
                        scope: vec!["*".to_string()],
                    },
                    constraints: vec![],
                },
                GrantableCapability {
                    capability: GrantedCapability::MeshSend {
                        destinations: vec!["*".to_string()],
                    },
                    constraints: vec![],
                },
            ],
            default_constraints: vec![],
        }
    }

    /// Evaluate a capability request against this policy.
    ///
    /// Returns which capabilities are granted (possibly with added constraints)
    /// and which are denied.
    pub fn evaluate_request(&self, request: &CapabilityRequest) -> CapabilityResponse {
        let mut granted = Vec::new();
        let mut denied = Vec::new();

        // Assign trust tier: minimum of claimed and our max
        let assigned_tier = min_tier(request.claimed_tier, self.max_tier);

        for requested in &request.requested {
            match self.find_matching_grantable(requested) {
                Some(grantable) => {
                    // Grant with the intersection of scopes
                    let narrowed = intersect_capability(requested, &grantable.capability);
                    granted.push(narrowed);
                }
                None => {
                    denied.push(DeniedCapability {
                        capability: requested.clone(),
                        reason: "Not in grantable set".to_string(),
                    });
                }
            }
        }

        // Accept offered capabilities (for now, accept all offers)
        let accepted = request.offered.clone();

        CapabilityResponse {
            granted,
            denied,
            accepted,
            assigned_tier,
        }
    }

    /// Find a grantable capability that matches the request.
    fn find_matching_grantable(
        &self,
        requested: &GrantedCapability,
    ) -> Option<&GrantableCapability> {
        self.grantable
            .iter()
            .find(|g| std::mem::discriminant(&g.capability) == std::mem::discriminant(requested))
    }
}

/// Negotiate capabilities between two parties.
///
/// This is the main entry point. Given:
/// - `our_policy`: what we're willing to grant
/// - `our_request`: what we want from the peer
/// - `their_request`: what the peer wants from us
/// - `our_identity` / `their_identity`: for grant signing metadata
///
/// Returns a `NegotiationResult` with grants for both directions.
pub fn negotiate(
    our_policy: &CapabilityPolicy,
    our_request: &CapabilityRequest,
    their_request: &CapabilityRequest,
    our_address: &str,
    their_address: &str,
    receipt_id: &str,
) -> NegotiationResult {
    // Evaluate what we grant them
    let our_response = our_policy.evaluate_request(their_request);

    // Build grants from us to them
    let responder_grants: Vec<CapabilityGrant> = our_response
        .granted
        .iter()
        .map(|cap| {
            let mut grant = CapabilityGrant::new(
                our_address.to_string(),
                their_address.to_string(),
                cap.clone(),
                receipt_id.to_string(),
            )
            .with_trust_tier(our_response.assigned_tier);

            // Apply default constraints from our policy
            for constraint in &our_policy.default_constraints {
                grant = grant.with_constraint(constraint.clone());
            }

            grant
        })
        .collect();

    // Build grants from them to us (based on what they offered that we requested)
    let initiator_grants: Vec<CapabilityGrant> =
        intersect_offers(&our_request.requested, &their_request.offered)
            .into_iter()
            .map(|cap| {
                CapabilityGrant::new(
                    their_address.to_string(),
                    our_address.to_string(),
                    cap,
                    receipt_id.to_string(),
                )
                .with_trust_tier(min_tier(our_request.claimed_tier, our_policy.max_tier))
            })
            .collect();

    let effective_tier = our_response.assigned_tier;

    NegotiationResult {
        initiator_grants,
        responder_grants,
        denied: our_response.denied,
        effective_tier,
    }
}

/// Find capabilities that appear in both requests and offers.
fn intersect_offers(
    requested: &[GrantedCapability],
    offered: &[GrantedCapability],
) -> Vec<GrantedCapability> {
    requested
        .iter()
        .filter_map(|req| {
            offered
                .iter()
                .find(|off| std::mem::discriminant(*off) == std::mem::discriminant(req))
                .map(|off| intersect_capability(req, off))
        })
        .collect()
}

/// Narrow a capability to the intersection of two scopes.
///
/// When both sides have scope restrictions, take the most restrictive.
/// A wildcard ("*") scope is the least restrictive.
fn intersect_capability(a: &GrantedCapability, b: &GrantedCapability) -> GrantedCapability {
    match (a, b) {
        (GrantedCapability::Read { scope: sa }, GrantedCapability::Read { scope: sb }) => {
            GrantedCapability::Read {
                scope: intersect_scopes(sa, sb),
            }
        }
        (GrantedCapability::Write { scope: sa }, GrantedCapability::Write { scope: sb }) => {
            GrantedCapability::Write {
                scope: intersect_scopes(sa, sb),
            }
        }
        (
            GrantedCapability::MeshSend { destinations: da },
            GrantedCapability::MeshSend { destinations: db },
        ) => GrantedCapability::MeshSend {
            destinations: intersect_scopes(da, db),
        },
        (
            GrantedCapability::ApiCall { endpoints: ea },
            GrantedCapability::ApiCall { endpoints: eb },
        ) => GrantedCapability::ApiCall {
            endpoints: intersect_scopes(ea, eb),
        },
        (
            GrantedCapability::Execute { languages: la },
            GrantedCapability::Execute { languages: lb },
        ) => GrantedCapability::Execute {
            languages: intersect_scopes(la, lb),
        },
        // For types where intersection doesn't apply, return the first
        _ => a.clone(),
    }
}

/// Intersect two scope lists.
///
/// - If either scope is ["*"], use the other (wildcard is least restrictive)
/// - Otherwise, return items present in both
fn intersect_scopes(a: &[String], b: &[String]) -> Vec<String> {
    let a_is_wildcard = a.len() == 1 && a[0] == "*";
    let b_is_wildcard = b.len() == 1 && b[0] == "*";

    match (a_is_wildcard, b_is_wildcard) {
        (true, true) => vec!["*".to_string()],
        (true, false) => b.to_vec(),
        (false, true) => a.to_vec(),
        (false, false) => {
            // Return items that appear in both, plus any where one is a prefix of the other
            let mut result = Vec::new();
            for item_a in a {
                for item_b in b {
                    if item_a == item_b {
                        result.push(item_a.clone());
                    } else if let Some(prefix) = item_a.strip_suffix("/*") {
                        if item_b.starts_with(prefix) {
                            // a is broader: "data/*" contains "data/public"
                            result.push(item_b.clone());
                        }
                    } else if let Some(prefix) = item_b.strip_suffix("/*") {
                        if item_a.starts_with(prefix) {
                            // b is broader
                            result.push(item_a.clone());
                        }
                    }
                }
            }
            if result.is_empty() {
                // No intersection — return empty (effectively denies)
                result
            } else {
                result
            }
        }
    }
}

/// Return the lower of two trust tiers.
fn min_tier(a: TrustTier, b: TrustTier) -> TrustTier {
    match (a, b) {
        (TrustTier::Tier0, _) | (_, TrustTier::Tier0) => TrustTier::Tier0,
        (TrustTier::Tier1, _) | (_, TrustTier::Tier1) => TrustTier::Tier1,
        _ => TrustTier::Tier2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deny_all_policy_denies_everything() {
        let policy = CapabilityPolicy::deny_all();
        let request = CapabilityRequest {
            requested: vec![
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                GrantedCapability::Write {
                    scope: vec!["data/*".to_string()],
                },
            ],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let response = policy.evaluate_request(&request);
        assert!(response.granted.is_empty());
        assert_eq!(response.denied.len(), 2);
        assert_eq!(response.assigned_tier, TrustTier::Tier0);
    }

    #[test]
    fn test_allow_all_policy_grants_matching() {
        let policy = CapabilityPolicy::allow_all();
        let request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let response = policy.evaluate_request(&request);
        assert_eq!(response.granted.len(), 1);
        assert!(response.denied.is_empty());
    }

    #[test]
    fn test_scope_intersection_wildcard() {
        // Wildcard intersected with specific → specific wins
        let result = intersect_scopes(
            &["*".to_string()],
            &["data/public".to_string(), "data/shared".to_string()],
        );
        assert_eq!(result, vec!["data/public", "data/shared"]);
    }

    #[test]
    fn test_scope_intersection_both_wildcards() {
        let result = intersect_scopes(&["*".to_string()], &["*".to_string()]);
        assert_eq!(result, vec!["*"]);
    }

    #[test]
    fn test_scope_intersection_prefix_narrowing() {
        // "data/*" intersected with "data/public" → "data/public"
        let result = intersect_scopes(&["data/*".to_string()], &["data/public".to_string()]);
        assert_eq!(result, vec!["data/public"]);
    }

    #[test]
    fn test_scope_intersection_no_overlap() {
        let result = intersect_scopes(&["alpha/a".to_string()], &["beta/b".to_string()]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_min_tier() {
        assert_eq!(
            min_tier(TrustTier::Tier0, TrustTier::Tier2),
            TrustTier::Tier0
        );
        assert_eq!(
            min_tier(TrustTier::Tier1, TrustTier::Tier2),
            TrustTier::Tier1
        );
        assert_eq!(
            min_tier(TrustTier::Tier2, TrustTier::Tier2),
            TrustTier::Tier2
        );
    }

    #[test]
    fn test_negotiate_bilateral() {
        let alice_policy = CapabilityPolicy::allow_all();
        let _bob_policy = CapabilityPolicy::allow_all();

        // Alice requests Read from Bob, offers Write to Bob
        let alice_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        // Bob requests Write from Alice, offers Read to Alice
        let bob_request = CapabilityRequest {
            requested: vec![GrantedCapability::Write {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        // Alice evaluates Bob's request against her policy
        let result = negotiate(
            &alice_policy,
            &alice_request,
            &bob_request,
            "alice_hash",
            "bob_hash",
            "receipt_001",
        );

        // Alice should have grants from Bob (he offered Read, she requested Read)
        assert!(
            !result.initiator_grants.is_empty(),
            "Alice should get grants from Bob's offers"
        );

        // Bob should have grants from Alice (he requested Write, she can grant it)
        assert!(
            !result.responder_grants.is_empty(),
            "Bob should get grants from Alice's policy"
        );
    }

    #[test]
    fn test_negotiate_partial_grant() {
        // Alice only grants Read, not Write
        let alice_policy = CapabilityPolicy {
            max_tier: TrustTier::Tier1,
            grantable: vec![GrantableCapability {
                capability: GrantedCapability::Read {
                    scope: vec!["public/*".to_string()],
                },
                constraints: vec![],
            }],
            default_constraints: vec![Constraint::RequireReceipt],
        };

        // Bob requests both Read and Write
        let bob_request = CapabilityRequest {
            requested: vec![
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                GrantedCapability::Write {
                    scope: vec!["*".to_string()],
                },
            ],
            offered: vec![],
            claimed_tier: TrustTier::Tier2,
        };

        let alice_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let result = negotiate(
            &alice_policy,
            &alice_request,
            &bob_request,
            "alice",
            "bob",
            "receipt_002",
        );

        // Read granted (narrowed to public/*), Write denied
        assert_eq!(result.responder_grants.len(), 1);
        assert_eq!(result.denied.len(), 1);
        assert_eq!(result.denied[0].capability.name(), "write");

        // Trust tier downgraded from Tier2 to Tier1 (Alice's max)
        assert_eq!(result.effective_tier, TrustTier::Tier1);

        // Default constraint (RequireReceipt) applied
        assert!(!result.responder_grants[0].constraints.is_empty());
    }

    #[test]
    fn test_negotiate_scope_narrowing() {
        // Alice grants Read on "data/*"
        let alice_policy = CapabilityPolicy {
            max_tier: TrustTier::Tier2,
            grantable: vec![GrantableCapability {
                capability: GrantedCapability::Read {
                    scope: vec!["data/*".to_string()],
                },
                constraints: vec![],
            }],
            default_constraints: vec![],
        };

        // Bob requests Read on "data/public" (narrower than what Alice offers)
        let bob_request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/public".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let result = negotiate(
            &alice_policy,
            &CapabilityRequest {
                requested: vec![],
                offered: vec![],
                claimed_tier: TrustTier::Tier0,
            },
            &bob_request,
            "alice",
            "bob",
            "receipt_003",
        );

        assert_eq!(result.responder_grants.len(), 1);
        // Scope should be narrowed to "data/public" (intersection of "data/*" and "data/public")
        if let GrantedCapability::Read { scope } = &result.responder_grants[0].capability {
            assert_eq!(scope, &vec!["data/public".to_string()]);
        } else {
            panic!("Expected Read capability");
        }
    }

    #[test]
    fn test_negotiate_empty_requests() {
        let policy = CapabilityPolicy::allow_all();
        let empty_request = CapabilityRequest {
            requested: vec![],
            offered: vec![],
            claimed_tier: TrustTier::Tier0,
        };

        let result = negotiate(
            &policy,
            &empty_request,
            &empty_request,
            "alice",
            "bob",
            "receipt_004",
        );

        assert!(result.initiator_grants.is_empty());
        assert!(result.responder_grants.is_empty());
        assert!(result.denied.is_empty());
    }

    #[test]
    fn test_negotiate_grants_have_correct_addresses() {
        let policy = CapabilityPolicy::allow_all();
        let request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["*".to_string()],
            }],
            offered: vec![],
            claimed_tier: TrustTier::Tier1,
        };

        let result = negotiate(
            &policy,
            &CapabilityRequest {
                requested: vec![],
                offered: vec![],
                claimed_tier: TrustTier::Tier0,
            },
            &request,
            "alice_addr",
            "bob_addr",
            "receipt_005",
        );

        // Grants from Alice to Bob
        assert_eq!(result.responder_grants.len(), 1);
        assert_eq!(result.responder_grants[0].grantor, "alice_addr");
        assert_eq!(result.responder_grants[0].grantee, "bob_addr");
    }

    #[test]
    fn test_capability_request_serialization() {
        let request = CapabilityRequest {
            requested: vec![GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            }],
            offered: vec![GrantedCapability::MeshSend {
                destinations: vec!["*".to_string()],
            }],
            claimed_tier: TrustTier::Tier1,
        };

        let json = serde_json::to_string(&request).unwrap();
        let restored: CapabilityRequest = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.requested.len(), 1);
        assert_eq!(restored.offered.len(), 1);
        assert_eq!(restored.claimed_tier, TrustTier::Tier1);
    }

    #[test]
    fn test_intersect_capability_read() {
        let a = GrantedCapability::Read {
            scope: vec!["*".to_string()],
        };
        let b = GrantedCapability::Read {
            scope: vec!["data/public".to_string()],
        };

        let result = intersect_capability(&a, &b);
        if let GrantedCapability::Read { scope } = result {
            assert_eq!(scope, vec!["data/public"]);
        } else {
            panic!("Expected Read");
        }
    }
}
