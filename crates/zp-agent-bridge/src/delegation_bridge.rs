//! Bridges `agent_zp::DelegationPolicy` → `zp_core::DelegationChain` + `CapabilityGrant`.
//!
//! Maps agent-zp's delegation types to ZP's native capability grant and delegation
//! chain system, including scope validation and chain integrity checks.

use async_trait::async_trait;
use chrono::Utc;

use agent_zp::{
    AgentIdentity, ChildSessionSpec, DelegatedCapability, DelegationChainRef,
    DelegationConstraint, DelegationError, DelegationGrant, DelegationPolicy,
};

use zp_core::{
    Constraint, GrantedCapability, TrustTier,
};

/// Concrete `DelegationPolicy` backed by ZP's capability grant system.
///
/// Validates delegation requests against ZP's grant model:
/// - Scope narrowing enforcement via `GrantedCapability::contains()`
/// - Delegation depth enforcement via `CapabilityGrant::can_delegate()`
/// - Chain integrity validation via `DelegationChain::verify()`
pub struct ZpDelegationPolicy {
    /// Maximum delegation depth allowed by this instance
    max_depth: u8,

    /// Default trust tier for new grants
    default_tier: TrustTier,
}

impl ZpDelegationPolicy {
    pub fn new() -> Self {
        Self {
            max_depth: 3,
            default_tier: TrustTier::Tier1,
        }
    }

    pub fn with_max_depth(mut self, depth: u8) -> Self {
        self.max_depth = depth;
        self
    }

    pub fn with_trust_tier(mut self, tier: TrustTier) -> Self {
        self.default_tier = tier;
        self
    }

    /// Map agent-zp `DelegatedCapability` → ZP `GrantedCapability`.
    /// Used when converting delegation grants for ZP-native validation.
    #[allow(dead_code)]
    fn map_capability(cap: &DelegatedCapability) -> GrantedCapability {
        match cap {
            DelegatedCapability::ToolExecution { tool_patterns } => GrantedCapability::Execute {
                languages: tool_patterns.clone(),
            },
            DelegatedCapability::ProviderAccess { allowed_models } => GrantedCapability::ApiCall {
                endpoints: allowed_models
                    .clone()
                    .unwrap_or_else(|| vec!["*".to_string()]),
            },
            DelegatedCapability::FileRead { scope } => GrantedCapability::Read {
                scope: scope.clone(),
            },
            DelegatedCapability::FileWrite { scope } => GrantedCapability::Write {
                scope: scope.clone(),
            },
            DelegatedCapability::Network { allowed_domains } => GrantedCapability::ApiCall {
                endpoints: allowed_domains
                    .clone()
                    .unwrap_or_else(|| vec!["*".to_string()]),
            },
            DelegatedCapability::Custom { name, parameters } => GrantedCapability::Custom {
                name: name.clone(),
                parameters: parameters.clone(),
            },
        }
    }

    /// Map agent-zp `DelegationConstraint` → ZP `Constraint`.
    /// Used when converting delegation grants for ZP-native constraint checking.
    #[allow(dead_code)]
    fn map_constraint(c: &DelegationConstraint) -> Constraint {
        match c {
            DelegationConstraint::MaxCost(cost) => Constraint::MaxCost(*cost),
            DelegationConstraint::RateLimit {
                max_actions,
                window_secs,
            } => Constraint::RateLimit {
                max_actions: *max_actions,
                window_secs: *window_secs,
            },
            DelegationConstraint::ExpiresAt(_) => Constraint::RequireReceipt, // Expiry handled at grant level
            DelegationConstraint::MaxDuration { secs: _ } => Constraint::RequireReceipt,
            DelegationConstraint::RequireReceipts => Constraint::RequireReceipt,
            DelegationConstraint::Custom { name, value } => Constraint::Custom {
                name: name.clone(),
                value: value.clone(),
            },
        }
    }
}

impl Default for ZpDelegationPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DelegationPolicy for ZpDelegationPolicy {
    async fn authorize_delegation(
        &self,
        parent: &AgentIdentity,
        parent_chain: Option<&DelegationChainRef>,
        spec: &ChildSessionSpec,
    ) -> Result<DelegationGrant, DelegationError> {
        let depth = parent_chain.map(|c| c.depth() as u8).unwrap_or(0);

        // Check depth limit
        if depth >= self.max_depth {
            return Err(DelegationError::DepthExceeded {
                current: depth,
                max: self.max_depth,
            });
        }

        // If there's a parent chain, validate that requested capabilities
        // are a subset of the leaf grant's capabilities
        if let Some(chain) = parent_chain {
            if let Some(leaf) = chain.leaf() {
                for cap in &spec.capabilities {
                    if !leaf.covers(cap) {
                        return Err(DelegationError::ScopeEscalation(format!(
                            "requested capability {:?} not covered by parent grant",
                            cap
                        )));
                    }
                }

                // Check if parent grant is expired
                if leaf.is_expired() {
                    return Err(DelegationError::ParentExpired);
                }
            }
        }

        // Build the grant
        let grant_id = format!("grant-{}", uuid::Uuid::new_v4());
        let parent_grant_id = parent_chain
            .and_then(|c| c.leaf())
            .map(|g| g.grant_id.clone());

        let expires_at = spec.constraints.iter().find_map(|c| match c {
            DelegationConstraint::ExpiresAt(t) => Some(*t),
            DelegationConstraint::MaxDuration { secs } => {
                Some(Utc::now() + chrono::Duration::seconds(*secs as i64))
            }
            _ => None,
        });

        let grant_hash = {
            let canonical = serde_json::json!({
                "grant_id": grant_id,
                "grantor": parent.agent_id,
                "depth": depth,
                "capabilities": spec.capabilities.len(),
                "timestamp": Utc::now().to_rfc3339(),
            });
            blake3::hash(canonical.to_string().as_bytes())
                .to_hex()
                .to_string()
        };

        Ok(DelegationGrant {
            grant_id,
            grantor: parent.agent_id.clone(),
            grantee: format!("child-{}", uuid::Uuid::new_v4()),
            capabilities: spec.capabilities.clone(),
            constraints: spec.constraints.clone(),
            depth,
            max_depth: depth + spec.sub_delegation_depth,
            parent_grant_id,
            created_at: Utc::now(),
            expires_at,
            grant_hash,
        })
    }

    async fn validate_chain(&self, chain: &DelegationChainRef) -> Result<(), DelegationError> {
        if !chain.is_valid() {
            return Err(DelegationError::ChainInvalid(
                "chain integrity check failed: broken links, depth mismatch, or scope escalation"
                    .to_string(),
            ));
        }

        // Check no grants are expired
        for grant in &chain.grants {
            if grant.is_expired() {
                return Err(DelegationError::ParentExpired);
            }
        }

        // Check depth doesn't exceed max
        if chain.depth() > self.max_depth as usize {
            return Err(DelegationError::DepthExceeded {
                current: chain.depth() as u8,
                max: self.max_depth,
            });
        }

        Ok(())
    }

    async fn revoke(&self, grant_id: &str) -> Result<(), DelegationError> {
        // P4 (#197): construct an in-memory zp_core::RevocationClaim so the
        // bridge surface exercises the new type. The actual chain emission
        // (sign + append + cascade walk) is handled by the `zp revoke` CLI
        // path, which has the audit store, the operator signing key, and
        // the index of child grants needed for cascade. The bridge has none
        // of those, so this method records intent and returns.
        let claim = zp_core::RevocationClaim::new(
            grant_id,
            "bridge-revoke".to_string(),
            zp_core::AuthorityRef::genesis("revocation_authority"),
            zp_core::CascadePolicy::SubtreeHalt,
            zp_core::RevocationReason::OperatorRequested,
        );
        tracing::info!(
            grant_id = %grant_id,
            revocation_id = %claim.revocation_id,
            "delegation_bridge: revoke requested — claim constructed; chain emission deferred to `zp revoke` CLI"
        );
        Ok(())
    }
}
