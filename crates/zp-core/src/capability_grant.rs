//! Capability grants — signed, portable capability tokens for ZeroPoint v2 governance.
//!
//! This module implements the core authorization mechanism for ZeroPoint. Capabilities are
//! granted at link establishment time and enforced locally by the Guard. They travel with
//! the agent across the mesh, signed and verifiable.
//!
//! From the governance framework: "Agents operate within capability envelopes — sets of
//! allowed actions with constraints. Capabilities are granted at link establishment time
//! and enforced locally by the Guard."

use chrono::{DateTime, Timelike, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::authority_ref::AuthorityRef;
use crate::governance::EventProvenance;
use crate::lease::LeasePolicy;
use crate::policy::{ActionType, TrustTier};

/// A signed, portable capability grant — the unit of authorization in ZeroPoint.
///
/// Capabilities are granted at link establishment time and enforced locally by the Guard.
/// They travel with the agent across the mesh, carrying proof of who granted them and
/// what constraints apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Unique grant identifier, prefixed with "grant-"
    pub id: String,

    /// What capability is being granted
    pub capability: GrantedCapability,

    /// Limits on how this capability can be exercised
    pub constraints: Vec<Constraint>,

    /// DestinationHash hex of who granted this capability
    pub grantor: String,

    /// DestinationHash hex of who received this capability
    pub grantee: String,

    /// Minimum trust tier required to exercise this capability
    pub trust_tier: TrustTier,

    /// Timestamp when this grant was created
    pub created_at: DateTime<Utc>,

    /// Optional expiration time. If None, the grant never expires.
    pub expires_at: Option<DateTime<Utc>>,

    /// Proof of grant — references a signed receipt that authorized this grant
    pub receipt_id: String,

    /// Ed25519 signature over the canonical form of this grant
    pub signature: Option<String>,

    /// Public key of the signer, in hex format
    pub signer_public_key: Option<String>,

    // --- Phase 3: Delegation Chain fields ---
    /// If this grant was delegated from another, the parent grant's ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<String>,

    /// How many hops from the original grant (0 = original, 1 = first delegation, etc.)
    #[serde(default)]
    pub delegation_depth: u8,

    /// Maximum allowed delegation depth. Delegated grants cannot exceed this.
    #[serde(default = "default_max_delegation_depth")]
    pub max_delegation_depth: u8,

    // --- Phase 3.2: Provenance tracking ---
    /// How this grant was created — operator-issued, delegated, or system-generated.
    /// Provenance determines what further actions are allowed (e.g., system-generated
    /// grants cannot be delegated and expire after a single use).
    #[serde(default)]
    pub provenance: GrantProvenance,

    // --- Phase 2.7 (M4-3): Event-level provenance for self-issuance prevention ---
    /// The governance event provenance that led to this grant being issued.
    /// A grant without `issued_via`, or with `issued_via` showing
    /// `EventOrigin::ExternalRequest` on an internal-only capability, MUST be
    /// rejected by the governance gate. This closes the SSRF self-grant vector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_via: Option<EventProvenance>,

    // --- P4 (#197): Standing delegation extensions -------------------------
    // Every field below is optional/defaulted so a grant created before the
    // standing-delegation work was wired in continues to behave exactly as
    // it did. A grant with `lease_policy: None` is a "classic" capability
    // grant: bounded by `expires_at`, no renewal cadence, no kill switch
    // beyond plain expiry.
    /// If set, this grant participates in lease-based renewal. `expires_at`
    /// advances by `lease_policy.lease_duration` on each successful renewal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_policy: Option<LeasePolicy>,

    /// Authorities permitted to renew this grant. Empty means no renewal —
    /// the grant runs to its `expires_at` and dies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renewal_authorities: Vec<AuthorityRef>,

    /// Authorities permitted to revoke this grant. Empty means only the
    /// issuer (matching the existing implicit behaviour pre-P4).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocable_by: Vec<AuthorityRef>,

    /// Whether this grant may be re-delegated, and how deep the subtree may
    /// go. Defaults to `Forbidden` so legacy callers stay locked down.
    #[serde(default)]
    pub redelegation: RedelegationPolicy,

    /// Optional anchor commitment id for revocation announcements.
    /// Populated when the truth anchor backend is configured (HCS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_anchor: Option<String>,

    /// When this grant was last renewed. None for grants that have never
    /// been renewed, including non-leased grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_renewed_at: Option<DateTime<Utc>>,

    /// How many successful renewals this grant has accumulated.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub renewal_count: u32,

    /// Hex-encoded Ed25519 public key bound to this grant's *subject*
    /// (the grantee node). When set, the lease renewal endpoint
    /// authenticates incoming requests by verifying their Ed25519
    /// signature against this key — no session cookie needed. This is the
    /// primary fleet-node authentication primitive: a delegate proves
    /// identity by signing with its key, not by holding a browser session.
    ///
    /// Optional for backward compatibility: pre-P4 grants had no subject
    /// key, so the chain entries don't need migration. Issued grants
    /// without a `subject_public_key` cannot be renewed via the heartbeat
    /// path — they must instead authenticate with a session token (the
    /// CLI / dashboard path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_public_key: Option<String>,

    /// If this grant was issued via `zp delegate --renew`, the grant_id of
    /// the prior active grant it replaces. This makes smooth renewal a
    /// first-class continuity relation in the chain: the receipt carrying
    /// `renews` points back to the prior grant so verifiers can reconstruct
    /// the full renewal lineage without a separate lookup.
    ///
    /// `None` for initial grants, `Some(prior_grant_id)` for renewals issued
    /// through the CLI renewal path. Distinct from `delegation:renewed:*`
    /// receipts (which represent lease heartbeat extensions by a running
    /// node); this field represents an operator-directed smooth renewal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renews: Option<String>,

    // --- Officer cadre gap-closing fields ----------------------------------

    /// What kind of entity holds this grant (operator, officer, agent,
    /// external tool). Identity is always a key (Principle 2), but knowing
    /// the *kind* behind the key lets Sentinel scope audit queries and lets
    /// cockpits render grants with appropriate context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantee_type: Option<GranteeType>,

    /// Human-readable summary of what this delegation is *for*.
    /// Not a constraint — purely for operator legibility in chain viewers
    /// and cockpit surfaces. Officers and agents can set this when
    /// requesting a grant so the operator sees intent, not just scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_description: Option<String>,

    /// Receipt IDs that provide context for why this grant was issued.
    /// E.g., a `gate:denied` receipt + an operator decision receipt that
    /// together motivated granting this capability. Distinct from
    /// `receipt_id` (the receipt that *carried* this grant) and
    /// `parent_grant_id` (the grant it chains from). Strengthens the
    /// audit narrative by linking the causal chain of events.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context_receipts: Vec<String>,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

/// How a capability grant was created.
///
/// Provenance tracking prevents SSRF-based self-issuance: the auth middleware
/// blocks internal-origin requests without external sessions, and
/// SystemGenerated grants cannot be delegated further.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum GrantProvenance {
    /// Issued directly by an operator with signing authority.
    OperatorIssued {
        /// Hex-encoded public key of the issuing operator.
        operator_key: String,
    },

    /// Delegated from an existing grant by a capability holder.
    Delegated {
        /// The parent grant that this was delegated from.
        parent_grant_id: String,
        /// Hex-encoded public key of the delegator.
        delegator_key: String,
    },

    /// Generated by the system for internal operations (e.g., pipeline
    /// orchestration, policy engine). Cannot be delegated and expires
    /// after a single use.
    SystemGenerated {
        /// Why the system generated this grant.
        reason: String,
    },

    /// A long-lived standing delegation under lease renewal (#197). Behaves
    /// like `OperatorIssued` for delegation/issuance checks but signals to
    /// validators and the cockpit that this grant is alive only as long as
    /// it is being renewed.
    Standing {
        /// Hex-encoded public key of the issuing operator.
        operator_key: String,
    },
}

impl Default for GrantProvenance {
    fn default() -> Self {
        GrantProvenance::OperatorIssued {
            operator_key: String::new(),
        }
    }
}

impl GrantProvenance {
    /// Whether this grant can be delegated to another entity.
    pub fn is_delegable(&self) -> bool {
        !matches!(self, GrantProvenance::SystemGenerated { .. })
    }

    /// Whether this grant expires after a single use.
    pub fn is_single_use(&self) -> bool {
        matches!(self, GrantProvenance::SystemGenerated { .. })
    }

    /// Whether this grant is a standing delegation under lease renewal.
    pub fn is_standing(&self) -> bool {
        matches!(self, GrantProvenance::Standing { .. })
    }
}

/// What kind of entity holds this grant.
///
/// Grantees are always identified by cryptographic key (`grantee` field),
/// but knowing the *kind* of entity behind the key lets Sentinel scope
/// audit queries and lets cockpits render grants with appropriate context.
/// Optional for backward compatibility — pre-officer grants have no type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GranteeType {
    /// A human operator (CLI, dashboard, cockpit).
    Operator,
    /// A ZP-native system officer (Steward, Sentinel, Forge).
    Officer,
    /// An external agent running under the Governed Agent Runtime.
    Agent,
    /// An external tool (MCP server, WASM module, webhook).
    ExternalTool,
}

/// Policy for re-delegating a grant downstream (#197).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RedelegationPolicy {
    /// Re-delegation is not permitted. The default — preserves pre-P4
    /// behaviour where any grant could be re-delegated up to
    /// `max_delegation_depth` but standing delegations stay locked unless
    /// the issuer explicitly opts in.
    #[default]
    Forbidden,

    /// Re-delegation is permitted, with a per-subtree depth ceiling.
    Allowed {
        /// Maximum depth the subtree rooted at this grant may reach.
        max_subtree_depth: u32,
    },

    /// Re-delegation is queued for issuer review. Not yet enforced — the
    /// queueing surface lands with the cockpit Fleet Grants tile.
    RequiresApproval,
}


fn default_max_delegation_depth() -> u8 {
    3
}

impl CapabilityGrant {
    /// Create a new capability grant with a builder-style constructor.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let grant = CapabilityGrant::new(
    ///     "grantor_hash",
    ///     "grantee_hash",
    ///     GrantedCapability::Read { scope: vec!["data/*".to_string()] },
    ///     "receipt_123",
    /// )
    /// .with_constraint(Constraint::MaxCost(10.0))
    /// .with_expiration(chrono::Utc::now() + chrono::Duration::hours(24));
    /// ```
    pub fn new(
        grantor: String,
        grantee: String,
        capability: GrantedCapability,
        receipt_id: String,
    ) -> Self {
        let id = format!("grant-{}", uuid::Uuid::now_v7());

        let provenance = GrantProvenance::OperatorIssued {
            operator_key: grantor.clone(),
        };

        Self {
            id,
            capability,
            constraints: Vec::new(),
            grantor,
            grantee,
            trust_tier: TrustTier::Tier0,
            created_at: Utc::now(),
            expires_at: None,
            receipt_id,
            signature: None,
            signer_public_key: None,
            parent_grant_id: None,
            delegation_depth: 0,
            max_delegation_depth: 3,
            provenance,
            issued_via: None,
            // P4 (#197): standing-delegation extensions default to absent so
            // a freshly constructed grant behaves exactly as it did pre-P4.
            lease_policy: None,
            renewal_authorities: Vec::new(),
            revocable_by: Vec::new(),
            redelegation: RedelegationPolicy::Forbidden,
            revocation_anchor: None,
            last_renewed_at: None,
            renewal_count: 0,
            subject_public_key: None,
            renews: None,
            // Officer cadre gap-closing fields default to absent so
            // pre-officer grants are byte-identical.
            grantee_type: None,
            task_description: None,
            context_receipts: Vec::new(),
        }
    }

    /// Create a new capability grant AND emit an AuthorizationClaim receipt.
    ///
    /// This is the preferred constructor — it ensures every grant has
    /// a corresponding typed receipt in the chain (C3-3).
    pub fn new_with_receipt(
        grantor: String,
        grantee: String,
        capability: GrantedCapability,
    ) -> (Self, zp_receipt::Receipt) {
        let scope = format!("{:?}", capability);
        let receipt = crate::receipt_emission::emit_authorization_receipt(
            &grantor,
            &scope,
        );
        let grant = Self::new(grantor, grantee, capability, receipt.id.clone());
        (grant, receipt)
    }

    /// Add a constraint to this grant (builder pattern).
    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Add multiple constraints at once (builder pattern).
    pub fn with_constraints(mut self, constraints: Vec<Constraint>) -> Self {
        self.constraints.extend(constraints);
        self
    }

    /// Set the trust tier required for this grant (builder pattern).
    pub fn with_trust_tier(mut self, tier: TrustTier) -> Self {
        self.trust_tier = tier;
        self
    }

    /// Set the expiration time for this grant (builder pattern).
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set the provenance of this grant (builder pattern).
    pub fn with_provenance(mut self, provenance: GrantProvenance) -> Self {
        self.provenance = provenance;
        self
    }

    /// Set the event provenance that led to this grant being issued (builder pattern).
    /// Required by Phase 2.7 (M4-3) for self-issuance prevention.
    pub fn with_issued_via(mut self, provenance: EventProvenance) -> Self {
        self.issued_via = Some(provenance);
        self
    }

    /// Validate that this grant was not self-issued via an external request.
    ///
    /// Returns `Err` if:
    /// - The grant has no `issued_via` provenance (legacy or forged)
    /// - The grant was issued via `EventOrigin::ExternalRequest` on an
    ///   internal-only capability (ConfigChange, CredentialAccess)
    ///
    /// This is the enforcement point for the SSRF self-grant vector closed
    /// by M4-3. The governance gate MUST call this before accepting any
    /// new capability grant.
    pub fn validate_issuance(&self) -> Result<(), IssuanceError> {
        // Non-delegable check runs first and unconditionally. It does not
        // depend on provenance: a reserved capability may not be placed in a
        // grant even by a fully-authorised local operator, because the point
        // is not who is asking but that the authority cannot be held by a
        // grantee at all. No-op while RESERVED_CAPABILITY_NAMES is empty.
        if let Some(reason) = reserved_class(&self.capability) {
            return Err(IssuanceError::ReservedCapability {
                capability: self.capability.name().to_string(),
                reserved_member: reason.member_id().to_string(),
            });
        }

        let provenance = self
            .issued_via
            .as_ref()
            .ok_or(IssuanceError::MissingProvenance)?;

        if provenance.is_external() && self.is_internal_only_capability() {
            return Err(IssuanceError::ExternalOnInternalCapability {
                capability: self.capability.name().to_string(),
                source_ip: match &provenance.origin {
                    crate::governance::EventOrigin::ExternalRequest { source_ip } => {
                        source_ip.clone()
                    }
                    _ => None,
                },
            });
        }

        Ok(())
    }

    /// Whether this capability is internal-only (should never be granted via
    /// external requests).
    fn is_internal_only_capability(&self) -> bool {
        matches!(
            self.capability,
            GrantedCapability::ConfigChange { .. } | GrantedCapability::CredentialAccess { .. }
        )
    }

    /// Set the expiration time to a relative duration from now (builder pattern).
    pub fn with_expiration_duration(mut self, duration: Duration) -> Self {
        self.expires_at =
            Some(Utc::now() + chrono::Duration::from_std(duration).unwrap_or_default());
        self
    }

    /// Set the signature and signer's public key (builder pattern).
    pub fn with_signature(mut self, signature: String, signer_public_key: String) -> Self {
        self.signature = Some(signature);
        self.signer_public_key = Some(signer_public_key);
        self
    }

    /// Set the maximum delegation depth (builder pattern).
    pub fn with_max_delegation_depth(mut self, depth: u8) -> Self {
        self.max_delegation_depth = depth;
        self
    }

    // --- P4 (#197): standing-delegation builder methods ------------------

    /// Attach a lease policy. The grant becomes a standing delegation —
    /// `expires_at` advances on each successful `renew()`. Caller usually
    /// also sets `with_renewal_authorities` and `with_revocable_by`.
    pub fn with_lease_policy(mut self, policy: LeasePolicy) -> Self {
        // Initial expiry is the lease window from now. Caller can override
        // with `with_expiration` afterwards.
        let lease_secs = policy.lease_duration.as_secs() as i64;
        self.expires_at = Some(self.created_at + chrono::Duration::seconds(lease_secs));
        self.lease_policy = Some(policy);
        self
    }

    /// Set the list of authorities permitted to renew this grant.
    pub fn with_renewal_authorities(mut self, authorities: Vec<AuthorityRef>) -> Self {
        self.renewal_authorities = authorities;
        self
    }

    /// Set the list of authorities permitted to revoke this grant.
    pub fn with_revocable_by(mut self, authorities: Vec<AuthorityRef>) -> Self {
        self.revocable_by = authorities;
        self
    }

    /// Set the re-delegation policy.
    pub fn with_redelegation_policy(mut self, policy: RedelegationPolicy) -> Self {
        self.redelegation = policy;
        self
    }

    /// Promote this grant to a standing delegation. The operator's hex
    /// public key is recorded for cockpit display and revocation routing.
    pub fn as_standing(mut self, operator_key: impl Into<String>) -> Self {
        self.provenance = GrantProvenance::Standing {
            operator_key: operator_key.into(),
        };
        self
    }

    /// Bind the subject (grantee) public key onto this grant. The lease
    /// renewal endpoint uses this key to authenticate heartbeat requests
    /// — the subject signs each renewal request with its corresponding
    /// secret key, no session cookie required.
    pub fn with_subject_public_key(mut self, pubkey_hex: impl Into<String>) -> Self {
        self.subject_public_key = Some(pubkey_hex.into());
        self
    }

    /// Set the grantee type (operator, officer, agent, external tool).
    pub fn with_grantee_type(mut self, grantee_type: GranteeType) -> Self {
        self.grantee_type = Some(grantee_type);
        self
    }

    /// Set a human-readable description of what this delegation is for.
    pub fn with_task_description(mut self, description: impl Into<String>) -> Self {
        self.task_description = Some(description.into());
        self
    }

    /// Set the context receipts — receipt IDs that motivated this grant.
    pub fn with_context_receipts(mut self, receipts: Vec<String>) -> Self {
        self.context_receipts = receipts;
        self
    }

    /// Verify a hex-encoded Ed25519 signature over `payload` against this
    /// grant's bound `subject_public_key`. Returns `false` if no key is
    /// bound, the key is malformed, the signature is malformed, or the
    /// signature does not verify.
    ///
    /// This is the primary authentication primitive for fleet operations:
    /// a delegate node holds the private half of `subject_public_key` and
    /// signs requests with it; the server verifies the signature here.
    pub fn verify_subject_signature(&self, payload: &[u8], signature_hex: &str) -> bool {
        let Some(pk_hex) = self.subject_public_key.as_deref() else {
            return false;
        };
        let Ok(pk_bytes) = hex::decode(pk_hex) else {
            return false;
        };
        let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.as_slice().try_into() else {
            return false;
        };
        let Ok(sig_bytes) = hex::decode(signature_hex) else {
            return false;
        };
        let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
            return false;
        };
        // Routes through the single canonical verify primitive (Seam 5).
        zp_receipt::verify::verify_signature(&pk_arr, payload, &sig_arr).is_ok()
    }

    /// Whether this grant has a lease attached.
    pub fn has_lease(&self) -> bool {
        self.lease_policy.is_some()
    }

    /// Whether this grant is currently inside its grace period — past the
    /// `expires_at` boundary but still within `lease_policy.grace_period`.
    pub fn is_in_grace_period(&self) -> bool {
        match (&self.lease_policy, self.expires_at) {
            (Some(policy), Some(expiry)) => {
                let now = Utc::now();
                if now <= expiry {
                    return false;
                }
                let grace_secs = policy.grace_period.as_secs() as i64;
                now <= expiry + chrono::Duration::seconds(grace_secs)
            }
            _ => false,
        }
    }

    /// Whether this grant is expired AND past its grace period.
    pub fn is_past_grace(&self) -> bool {
        match (&self.lease_policy, self.expires_at) {
            (Some(policy), Some(expiry)) => {
                let grace_secs = policy.grace_period.as_secs() as i64;
                Utc::now() > expiry + chrono::Duration::seconds(grace_secs)
            }
            // Lease policy attached but no expiry set yet: treat as alive.
            (Some(_), None) => false,
            // Without a lease policy, "past grace" is the classic expiry test.
            (None, _) => self.is_expired(),
        }
    }

    /// Renew this grant by extending `expires_at` by `lease_duration`.
    /// Returns `Err` if the grant has no lease policy or is past its
    /// grace period (unrenewable).
    pub fn renew(&mut self) -> Result<DateTime<Utc>, RenewalError> {
        let policy = self
            .lease_policy
            .as_ref()
            .ok_or(RenewalError::NoLeasePolicy)?;
        if self.is_past_grace() {
            return Err(RenewalError::PastGrace);
        }
        let lease_secs = policy.lease_duration.as_secs() as i64;
        let now = Utc::now();
        let new_expiry = now + chrono::Duration::seconds(lease_secs);
        self.expires_at = Some(new_expiry);
        self.last_renewed_at = Some(now);
        self.renewal_count += 1;
        Ok(new_expiry)
    }

    /// Delegate this grant to another agent, producing a child grant.
    ///
    /// The child grant:
    /// - Has a new ID and the delegator as grantor
    /// - References this grant as `parent_grant_id`
    /// - Has `delegation_depth = self.delegation_depth + 1`
    /// - Inherits `max_delegation_depth` from the parent
    /// - Must have equal or narrower scope (enforced by `GrantedCapability::contains`)
    /// - Inherits all parent constraints plus any additional ones
    /// - Inherits expiration: uses the earlier of parent's expiration or requested expiration
    /// - Trust tier is max(parent_tier, requested_tier) — never lower than parent
    ///
    /// Returns `Err` if delegation depth would exceed `max_delegation_depth`,
    /// or if the requested capability is not a subset of the parent's.
    pub fn delegate(
        &self,
        delegatee: String,
        capability: GrantedCapability,
        receipt_id: String,
    ) -> Result<Self, DelegationError> {
        // Non-delegable capabilities are refused ahead of every other check.
        // Ordering is deliberate: a reserved capability must produce the
        // reserved error, not a depth or scope error that happens to fire
        // first, so the refusal receipt names the real reason.
        //
        // Not directly testable while RESERVED_CAPABILITY_NAMES is empty —
        // this check cannot fire, so step 2 must add an ordering test
        // alongside its first table row. `lookup_reserved` is tested now;
        // the ordering it guards is not.
        if let Some(reason) = reserved_class(&capability) {
            return Err(DelegationError::ReservedCapability {
                capability: capability.name().to_string(),
                reserved_member: reason.member_id().to_string(),
            });
        }

        // Tier 5 (Ceremony) is the substrate's cold floor — no running
        // process may issue or re-delegate T5 authority. T5 is exercised
        // only during a genesis ceremony with the operator key physically
        // present. See `TrustTier::is_ceremony` for the enum invariant.
        if self.trust_tier.is_ceremony() {
            return Err(DelegationError::CeremonyTierNotDelegable);
        }

        // Check depth limit
        let new_depth = self.delegation_depth + 1;
        if new_depth > self.max_delegation_depth {
            return Err(DelegationError::DepthExceeded {
                current: self.delegation_depth,
                max: self.max_delegation_depth,
            });
        }

        // P4 (#197): re-delegation policy gate. Standing-delegation grants
        // can opt out of re-delegation entirely or constrain the subtree
        // depth, separately from the legacy `max_delegation_depth` ceiling.
        match &self.redelegation {
            RedelegationPolicy::Forbidden => {
                // Pre-P4 grants set this to default (Forbidden) but should
                // continue to allow re-delegation up to `max_delegation_depth`
                // — that is what the `max_delegation_depth` field was for.
                // We only enforce Forbidden when the grant is a Standing
                // delegation, where Forbidden is the explicit kill switch.
                if matches!(self.provenance, GrantProvenance::Standing { .. }) {
                    return Err(DelegationError::RedelegationForbidden);
                }
            }
            RedelegationPolicy::Allowed { max_subtree_depth } => {
                if new_depth as u32 > *max_subtree_depth {
                    return Err(DelegationError::SubtreeDepthExceeded {
                        depth: new_depth as u32,
                        max: *max_subtree_depth,
                    });
                }
            }
            RedelegationPolicy::RequiresApproval => {
                return Err(DelegationError::ApprovalRequired);
            }
        }

        // Verify the requested capability is a subset of the parent's
        if !self.capability.contains(&capability) {
            return Err(DelegationError::ScopeNotSubset {
                parent: self.capability.name().to_string(),
                requested: capability.name().to_string(),
            });
        }

        // Check the grant is still valid
        if self.is_expired() {
            return Err(DelegationError::ParentExpired);
        }

        let mut child = CapabilityGrant::new(
            self.grantee.clone(), // delegator becomes the grantor
            delegatee,
            capability,
            receipt_id,
        );

        child.parent_grant_id = Some(self.id.clone());
        child.delegation_depth = new_depth;
        child.max_delegation_depth = self.max_delegation_depth;

        // Inherit parent constraints
        child.constraints = self.constraints.clone();

        // Inherit trust tier (child can never be lower/more permissive than parent)
        child.trust_tier = self.trust_tier;

        // Inherit expiration (child can never outlive parent)
        child.expires_at = self.expires_at;

        // P4 (#197): propagate lease/renewal fields. The child cannot get
        // softer terms than its parent — child lease_duration ≤ parent's,
        // renewal_authorities ⊆ parent's, redelegation policy inherited.
        child.lease_policy = self.lease_policy.clone();
        child.renewal_authorities = self.renewal_authorities.clone();
        child.revocable_by = self.revocable_by.clone();
        child.redelegation = self.redelegation.clone();

        // Standing provenance propagates so downstream validators know this
        // subtree is alive only as long as the root keeps being renewed.
        if matches!(self.provenance, GrantProvenance::Standing { .. }) {
            child.provenance = GrantProvenance::Delegated {
                parent_grant_id: self.id.clone(),
                delegator_key: self.grantee.clone(),
            };
        }

        Ok(child)
    }

    /// Check if this grant is a delegated grant (not an original).
    pub fn is_delegated(&self) -> bool {
        self.parent_grant_id.is_some()
    }

    /// Check if this grant can still be delegated further.
    pub fn can_delegate(&self) -> bool {
        self.delegation_depth < self.max_delegation_depth && !self.is_expired()
    }

    /// Check if this grant has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    /// Check if this grant is still valid (not expired).
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// Check if this grant covers a given action type.
    ///
    /// Returns true if the granted capability matches the action, false otherwise.
    /// This does not check constraints — see `check_constraints()` for that.
    pub fn matches_action(&self, action: &ActionType) -> bool {
        match (&self.capability, action) {
            // Read grant matches Read actions
            (GrantedCapability::Read { scope: grant_scope }, ActionType::Read { target }) => {
                self.path_matches_scope(target, grant_scope)
            }

            // Write grant matches Write actions
            (GrantedCapability::Write { scope: grant_scope }, ActionType::Write { target }) => {
                self.path_matches_scope(target, grant_scope)
            }

            // Execute grant matches Execute actions
            (
                GrantedCapability::Execute {
                    languages: granted_langs,
                },
                ActionType::Execute { language },
            ) => granted_langs.contains(language) || granted_langs.contains(&"*".to_string()),

            // CredentialAccess grant matches CredentialAccess actions
            (
                GrantedCapability::CredentialAccess {
                    credential_refs: granted_refs,
                },
                ActionType::CredentialAccess { credential_ref },
            ) => granted_refs.contains(credential_ref) || granted_refs.contains(&"*".to_string()),

            // ApiCall grant matches ApiCall actions
            (
                GrantedCapability::ApiCall {
                    endpoints: granted_endpoints,
                },
                ActionType::ApiCall { endpoint },
            ) => self.endpoint_matches_scope(endpoint, granted_endpoints),

            // ConfigChange grant matches ConfigChange actions
            (
                GrantedCapability::ConfigChange {
                    settings: granted_settings,
                },
                ActionType::ConfigChange { setting },
            ) => granted_settings.contains(setting) || granted_settings.contains(&"*".to_string()),

            // MeshSend grant doesn't directly match ActionType (it's a custom capability)
            // but we include it for completeness
            (GrantedCapability::MeshSend { .. }, _) => false,

            // Custom capability requires explicit name matching
            (
                GrantedCapability::Custom {
                    name: _grant_name, ..
                },
                _,
            ) => {
                // Custom capabilities don't match standard ActionTypes
                false
            }

            // ToolCall grant matches ToolCall actions (Claim 4 enforcement).
            // Wildcard "*" in the tools list authorises any tool name.
            (GrantedCapability::ToolCall { tools }, ActionType::ToolCall { name }) => {
                tools.contains(name) || tools.contains(&"*".to_string())
            }

            // All other combinations don't match
            _ => false,
        }
    }

    /// The `ActionType` variants this grant's capability can *ever* authorise,
    /// ignoring scope.
    ///
    /// # Why this exists (defect 6, 2026-08-13)
    ///
    /// `matches_action` pairs each `GrantedCapability` with exactly one
    /// `ActionType`; every other pairing falls to `_ => false`. That is correct
    /// and it is invisible from outside. An operator can issue
    /// `capability: "execute", scope: ["*"]`, have it validated, signed and
    /// chained, and authorise no tool call whatsoever — while an auditor reading
    /// the chain sees `execute:*` and flags it as over-permissive. The grant is
    /// simultaneously a false positive for review and a false negative for use,
    /// and the two readings cancel, so nobody investigates.
    ///
    /// This makes the pairing legible without changing it.
    ///
    /// # Why it is derived and never stored
    ///
    /// The obvious fix is to write this set into the delegation receipt so the
    /// chain records what a grant *does* rather than what it is named. That was
    /// proposed and withdrawn. It is a pure function of `self.capability`, so a
    /// stored copy is a second source of truth for a fact the chain already
    /// carries — the same defect as five declarations of the local model
    /// (HARNESS-SEAM §3-C1) and three copies of `REGENT_TOOLS`
    /// (`zp-regent/src/tools.rs`). Worse, `ClaimMetadata::Delegation` is inside
    /// a *signed* receipt, so adding a field is a canonical-form change bought
    /// for a derivable convenience.
    ///
    /// Callers that want to show it — `zp grants --check`, a grant response —
    /// call this. Nothing serialises it.
    ///
    /// Kept adjacent to `matches_action` deliberately: the two must agree, and
    /// `satisfiable_actions_agrees_with_matches_action` proves they do.
    pub fn satisfiable_actions(&self) -> &'static [&'static str] {
        match &self.capability {
            GrantedCapability::Read { .. } => &["Read"],
            GrantedCapability::Write { .. } => &["Write"],
            GrantedCapability::Execute { .. } => &["Execute"],
            GrantedCapability::CredentialAccess { .. } => &["CredentialAccess"],
            GrantedCapability::ApiCall { .. } => &["ApiCall"],
            GrantedCapability::ConfigChange { .. } => &["ConfigChange"],
            GrantedCapability::ToolCall { .. } => &["ToolCall"],
            // No `ActionType` pairs with either of these, so `matches_action`
            // returns false for every action. A grant of one authorises nothing
            // the gate consults — which is the condition defect 6 exists to make
            // visible, not an oversight here.
            GrantedCapability::MeshSend { .. } | GrantedCapability::Custom { .. } => &[],
        }
    }

    /// Check if all constraints are satisfied for a given action context.
    ///
    /// Returns a list of constraint violations. Empty list means all constraints are satisfied.
    pub fn check_constraints(&self, context: &ConstraintContext) -> Vec<ConstraintViolation> {
        let mut violations = Vec::new();

        for constraint in &self.constraints {
            if let Some(violation) = constraint.check(context) {
                violations.push(violation);
            }
        }

        violations
    }

    /// Serialize this grant to canonical bytes for signing.
    ///
    /// Uses deterministic JSON serialization (sorted keys) to ensure that the same grant
    /// always produces the same bytes, regardless of field order. This is essential for
    /// signature verification.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Create a version without signature for canonicalization. P4 fields
        // are passed through; their `skip_serializing_if` attributes keep
        // pre-P4 grants byte-identical to their original canonical form.
        let canonical = CanonicalForm {
            id: self.id.clone(),
            capability: self.capability.clone(),
            constraints: self.constraints.clone(),
            grantor: self.grantor.clone(),
            grantee: self.grantee.clone(),
            trust_tier: self.trust_tier,
            created_at: self.created_at,
            expires_at: self.expires_at,
            receipt_id: self.receipt_id.clone(),
            parent_grant_id: self.parent_grant_id.clone(),
            delegation_depth: self.delegation_depth,
            max_delegation_depth: self.max_delegation_depth,
            lease_policy: self.lease_policy.clone(),
            renewal_authorities: self.renewal_authorities.clone(),
            revocable_by: self.revocable_by.clone(),
            redelegation: self.redelegation.clone(),
            revocation_anchor: self.revocation_anchor.clone(),
            last_renewed_at: self.last_renewed_at,
            renewal_count: self.renewal_count,
            subject_public_key: self.subject_public_key.clone(),
            grantee_type: self.grantee_type.clone(),
            task_description: self.task_description.clone(),
            context_receipts: self.context_receipts.clone(),
        };

        // Seam 17: route through the canonical helper so the byte form
        // matches every other signed structure in the workspace. The
        // helper lives in zp-receipt (because zp-core depends on
        // zp-receipt — see lib.rs); zp_core::canonical re-exports it.
        zp_receipt::canonical::canonical_bytes_of(&canonical).unwrap_or_default()
    }

    /// Sign this grant with an Ed25519 signing key.
    ///
    /// Computes the signature over `canonical_bytes()` and stores both the
    /// hex-encoded signature and the hex-encoded public key on the grant.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let canonical = self.canonical_bytes();
        let signature = signing_key.sign(&canonical);
        self.signature = Some(hex::encode(signature.to_bytes()));
        self.signer_public_key = Some(hex::encode(signing_key.verifying_key().to_bytes()));
    }

    /// Verify the Ed25519 signature on this grant.
    ///
    /// Returns true if the signature is valid against the stored public key
    /// and the canonical bytes of this grant. Returns false if no signature
    /// is present, or if verification fails.
    pub fn verify_signature(&self) -> bool {
        // Seam 5: route through the canonical verify primitive. The
        // pre-Seam-5 path open-coded `VerifyingKey::from_bytes`,
        // `Signature::from_bytes`, and `verify_strict(...).is_ok()` —
        // five separate failure modes hidden behind one bool. The helper
        // surfaces them as typed errors and uses the same primitive
        // every other verifier in the workspace uses.
        let (sig_hex, pubkey_hex) = match (&self.signature, &self.signer_public_key) {
            (Some(s), Some(p)) => (s, p),
            _ => return false,
        };

        let pubkey_bytes = match hex::decode(pubkey_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pubkey_bytes);

        let sig_bytes = match hex::decode(sig_hex) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);

        // Verify against canonical bytes (excludes signature itself).
        zp_receipt::verify::verify_signature(&pk, &self.canonical_bytes(), &sig).is_ok()
    }

    /// Helper: check if a path matches any glob pattern in scope.
    fn path_matches_scope(&self, path: &str, scope: &[String]) -> bool {
        if scope.contains(&"*".to_string()) {
            return true;
        }

        // Simple glob matching: "data/*" matches "data/foo" and "data/bar"
        scope.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix("/*") {
                path.starts_with(prefix)
            } else {
                pattern == path
            }
        })
    }

    /// Helper: check if an endpoint matches any pattern in scope.
    fn endpoint_matches_scope(&self, endpoint: &str, scope: &[String]) -> bool {
        if scope.contains(&"*".to_string()) {
            return true;
        }

        scope.iter().any(|pattern| {
            if let Some(prefix) = pattern.strip_suffix("/*") {
                endpoint.starts_with(prefix)
            } else {
                pattern == endpoint
            }
        })
    }
}

// Seam 20: hash-then-sign discipline via the canonical [`zp_receipt::Signable`]
// trait. The preimage delegates to the hand-rolled `canonical_bytes` method on
// `CapabilityGrant`, which already excludes the signature field by
// constructing a `CanonicalForm` view that omits it.
impl zp_receipt::Signable for CapabilityGrant {
    fn canonical_preimage(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

/// What capability is being granted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrantedCapability {
    /// Read files/data within scope
    Read { scope: Vec<String> },

    /// Write/modify files/data within scope
    Write { scope: Vec<String> },

    /// Execute code in specified languages
    Execute { languages: Vec<String> },

    /// Access specific credentials (by reference, not value)
    CredentialAccess { credential_refs: Vec<String> },

    /// Make API calls to specified endpoints
    ApiCall { endpoints: Vec<String> },

    /// System configuration changes
    ConfigChange { settings: Vec<String> },

    /// Send messages to specified destinations
    MeshSend { destinations: Vec<String> },

    /// Custom capability (for extensibility)
    Custom {
        name: String,
        parameters: serde_json::Value,
    },
    /// Named tool invocation — the Claim 4 capability kind.
    ///
    /// Grants the right to invoke specific MCP tools by name. Wildcard
    /// `"*"` authorises any tool. This is the only `GrantedCapability`
    /// variant that the gate's `lease_prereq_for_agent` checks at call time.
    ToolCall {
        /// Tool names this grant authorises, e.g. `["bash", "read"]` or `["*"]`.
        tools: Vec<String>,
    },
}

impl GrantedCapability {
    /// Human-readable name for this capability.
    pub fn name(&self) -> &str {
        match self {
            GrantedCapability::Read { .. } => "read",
            GrantedCapability::Write { .. } => "write",
            GrantedCapability::Execute { .. } => "execute",
            GrantedCapability::CredentialAccess { .. } => "credential_access",
            GrantedCapability::ApiCall { .. } => "api_call",
            GrantedCapability::ConfigChange { .. } => "config_change",
            GrantedCapability::MeshSend { .. } => "mesh_send",
            GrantedCapability::Custom { name, .. } => name,
            GrantedCapability::ToolCall { .. } => "tool_call",
        }
    }

    /// Check if `other` is a subset of (or equal to) this capability.
    ///
    /// Used during delegation to ensure the child grant doesn't exceed
    /// the parent's scope. A wildcard scope (`"*"`) contains everything.
    pub fn contains(&self, other: &GrantedCapability) -> bool {
        match (self, other) {
            (
                GrantedCapability::Read { scope: parent },
                GrantedCapability::Read { scope: child },
            ) => scope_contains(parent, child),
            (
                GrantedCapability::Write { scope: parent },
                GrantedCapability::Write { scope: child },
            ) => scope_contains(parent, child),
            (
                GrantedCapability::Execute { languages: parent },
                GrantedCapability::Execute { languages: child },
            ) => set_contains(parent, child),
            (
                GrantedCapability::CredentialAccess {
                    credential_refs: parent,
                },
                GrantedCapability::CredentialAccess {
                    credential_refs: child,
                },
            ) => set_contains(parent, child),
            (
                GrantedCapability::ApiCall { endpoints: parent },
                GrantedCapability::ApiCall { endpoints: child },
            ) => scope_contains(parent, child),
            (
                GrantedCapability::ConfigChange { settings: parent },
                GrantedCapability::ConfigChange { settings: child },
            ) => set_contains(parent, child),
            (
                GrantedCapability::MeshSend {
                    destinations: parent,
                },
                GrantedCapability::MeshSend {
                    destinations: child,
                },
            ) => set_contains(parent, child),
            (
                GrantedCapability::Custom { name: pn, .. },
                GrantedCapability::Custom { name: cn, .. },
            ) => pn == cn, // Custom capabilities must match by name; parameters not checked
            // ToolCall scope subsetting — used at delegation time to ensure a
            // child ToolCall grant doesn't exceed the parent's tool set.
            (
                GrantedCapability::ToolCall { tools: parent },
                GrantedCapability::ToolCall { tools: child },
            ) => set_contains(parent, child),
            _ => false, // Different capability types are never subsets
        }
    }
}

/// Check if `parent_scope` contains every entry in `child_scope`.
/// Supports glob patterns: `"data/*"` contains `"data/foo"`, and `"*"` contains everything.
fn scope_contains(parent: &[String], child: &[String]) -> bool {
    // Wildcard parent contains everything
    if parent.contains(&"*".to_string()) {
        return true;
    }
    // Every child entry must be covered by at least one parent entry
    child.iter().all(|c| {
        parent.iter().any(|p| {
            if p == c {
                true
            } else if let Some(prefix) = p.strip_suffix("/*") {
                c.starts_with(prefix)
            } else {
                false
            }
        })
    })
}

/// Check if `parent_set` contains every entry in `child_set`.
/// A wildcard (`"*"`) in parent means "everything is allowed".
fn set_contains(parent: &[String], child: &[String]) -> bool {
    if parent.contains(&"*".to_string()) {
        return true;
    }
    child.iter().all(|c| parent.contains(c))
}

/// Constraints that limit how a capability can be exercised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Constraint {
    /// Maximum cost per action (in currency units)
    MaxCost(f64),

    /// Rate limit: max actions within a time window
    RateLimit { max_actions: u32, window_secs: u64 },

    /// Scope restriction: allowed/denied paths
    ScopeRestriction {
        allowed: Vec<String>,
        denied: Vec<String>,
    },

    /// Every action must produce a receipt
    RequireReceipt,

    /// Must escalate to this actor type before executing
    RequireEscalation(String), // Actor type as string for serialization

    /// Time-of-day restriction
    TimeWindow { start_hour: u8, end_hour: u8 },

    /// Custom constraint
    Custom {
        name: String,
        value: serde_json::Value,
    },
}

impl Constraint {
    /// Check if this constraint is violated in the given context.
    /// Returns Some(violation) if violated, None if satisfied.
    pub fn check(&self, context: &ConstraintContext) -> Option<ConstraintViolation> {
        match self {
            Constraint::MaxCost(max) => {
                if context.estimated_cost > *max {
                    Some(ConstraintViolation {
                        constraint_name: "MaxCost".to_string(),
                        reason: format!(
                            "Estimated cost {} exceeds maximum {}",
                            context.estimated_cost, max
                        ),
                    })
                } else {
                    None
                }
            }

            Constraint::RateLimit {
                max_actions,
                window_secs,
            } => {
                if context.recent_action_count >= *max_actions {
                    Some(ConstraintViolation {
                        constraint_name: "RateLimit".to_string(),
                        reason: format!(
                            "Rate limit exceeded: {} actions in last {} seconds, max allowed: {}",
                            context.recent_action_count, window_secs, max_actions
                        ),
                    })
                } else {
                    None
                }
            }

            Constraint::ScopeRestriction { allowed, denied } => {
                let path = &context.resource_path;

                // Check denied list first (deny wins over allow)
                for denied_pattern in denied {
                    if Self::pattern_matches(path, denied_pattern) {
                        return Some(ConstraintViolation {
                            constraint_name: "ScopeRestriction".to_string(),
                            reason: format!("Path {} is in denied list", path),
                        });
                    }
                }

                // If allowed list is non-empty, path must match one of them
                if !allowed.is_empty() {
                    let is_allowed = allowed.iter().any(|p| Self::pattern_matches(path, p));
                    if !is_allowed {
                        return Some(ConstraintViolation {
                            constraint_name: "ScopeRestriction".to_string(),
                            reason: format!("Path {} is not in allowed list", path),
                        });
                    }
                }

                None
            }

            Constraint::RequireReceipt => {
                // This constraint is satisfied if we're tracking receipt generation
                // In the context of constraint checking, we assume this is satisfied
                // unless the runtime explicitly marks it as pending
                if context.receipt_id.is_none() {
                    Some(ConstraintViolation {
                        constraint_name: "RequireReceipt".to_string(),
                        reason: "This action requires a receipt but none is being generated"
                            .to_string(),
                    })
                } else {
                    None
                }
            }

            Constraint::RequireEscalation(actor_type) => {
                if Some(actor_type.clone()) != context.escalation_to {
                    Some(ConstraintViolation {
                        constraint_name: "RequireEscalation".to_string(),
                        reason: format!("This action requires escalation to {}", actor_type),
                    })
                } else {
                    None
                }
            }

            Constraint::TimeWindow {
                start_hour,
                end_hour,
            } => {
                let now = Utc::now();
                let current_hour = now.hour() as u8;

                let is_within_window = if start_hour < end_hour {
                    current_hour >= *start_hour && current_hour < *end_hour
                } else {
                    // Wraps around midnight
                    current_hour >= *start_hour || current_hour < *end_hour
                };

                if !is_within_window {
                    Some(ConstraintViolation {
                        constraint_name: "TimeWindow".to_string(),
                        reason: format!(
                            "Current time {} is outside allowed window {}:00 to {}:00",
                            current_hour, start_hour, end_hour
                        ),
                    })
                } else {
                    None
                }
            }

            Constraint::Custom { name: _, .. } => {
                // Custom constraints are not evaluated here
                None
            }
        }
    }

    /// Helper: check if a path matches a glob pattern.
    fn pattern_matches(path: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix("/*") {
            return path.starts_with(prefix);
        }

        path == pattern
    }
}

/// Context for evaluating constraints.
#[derive(Debug, Clone)]
pub struct ConstraintContext {
    /// Estimated cost of this action
    pub estimated_cost: f64,

    /// Number of similar actions performed recently
    pub recent_action_count: u32,

    /// Resource path being accessed
    pub resource_path: String,

    /// Optional receipt ID if being generated
    pub receipt_id: Option<String>,

    /// Actor type if escalation is in progress
    pub escalation_to: Option<String>,
}

impl ConstraintContext {
    /// Create a new constraint context.
    pub fn new(resource_path: String) -> Self {
        Self {
            estimated_cost: 0.0,
            recent_action_count: 0,
            resource_path,
            receipt_id: None,
            escalation_to: None,
        }
    }

    /// Builder: set estimated cost
    pub fn with_cost(mut self, cost: f64) -> Self {
        self.estimated_cost = cost;
        self
    }

    /// Builder: set recent action count
    pub fn with_recent_actions(mut self, count: u32) -> Self {
        self.recent_action_count = count;
        self
    }

    /// Builder: set receipt ID
    pub fn with_receipt_id(mut self, receipt_id: String) -> Self {
        self.receipt_id = Some(receipt_id);
        self
    }

    /// Builder: set escalation
    pub fn with_escalation(mut self, actor_type: String) -> Self {
        self.escalation_to = Some(actor_type);
        self
    }
}

/// A constraint violation — indicates why a constraint check failed.
#[derive(Debug, Clone)]
pub struct ConstraintViolation {
    /// Name of the constraint that was violated
    pub constraint_name: String,

    /// Human-readable reason for the violation
    pub reason: String,
}

// ── Non-delegable authority (NON-DELEGABLE-AUTHORITY-2026-08 step 1) ────
//
// Some authority must never appear in a grant, to any grantee, at any tier,
// at any depth. Until now the substrate has relied on the *absence* of a
// grant to mean "not delegated", where for this class it needs to mean
// "cannot be delegated". See docs/design/NON-DELEGABLE-AUTHORITY-2026-08.md.
//
// Step 1 lands the machinery with an EMPTY membership table. Every call site
// below is therefore a no-op at runtime — this commit cannot change the
// behaviour of any existing grant. Members are added in step 2, at which
// point the Layer A claim becomes real and the amendment cost of KEEL III.6
// applies.
//
// Why a name table rather than a match on `GrantedCapability` variants:
// none of N1–N5 is expressible as an existing variant. There is no
// `GenesisSign`, no `FormGraduation`. They could only ever arrive through
// `Custom { name }`, which is precisely the smuggling path this must cover.
// `GrantedCapability::name()` returns the custom name for `Custom` and the
// static name otherwise, so one lookup covers both shapes.

/// Which member of the non-delegable set a capability matched.
///
/// Numbering follows NON-DELEGABLE-AUTHORITY-2026-08 §3 so the code and the
/// spec can be read against each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedReason {
    /// N1 — Genesis signature. Delegating it collapses II.5 and the
    /// singular-sovereign-root property: signatures would trace to whoever
    /// last held the delegation, not to the operator.
    GenesisSignature,
    /// N2 — amendment of the reserved set itself. Without this the class is
    /// decorative: delegate the power to shorten the list, then shorten it.
    ReservedSetAmendment,
    /// N3 — revoking or rotating the operator's own Genesis. The recovery
    /// path is the sovereignty; delegable, it is a one-signature bypass of
    /// the M-of-N design.
    RootRevocation,
    /// N4 — Substrate Form graduation. A delegate could move the operator to
    /// Companion Form, surrendering the trust root to a vendor, without the
    /// operator present. Confirmed Layer A by operator direction 2026-08-13.
    FormGraduation,
    /// N5 — modification of constitutional rules. Already unbypassable by
    /// grants; N5 closes the adjacent door of delegating the modification
    /// authority.
    ConstitutionalModification,
    /// N6 — issuance of a grant naming any reserved member. Closure rule.
    ReservedGrantIssuance,
    /// **Not a spec member.** A probe used to keep the enforcement path live
    /// and observable while N1–N6 are still latent — none of them currently
    /// flows through the capability system, so without this the machinery
    /// would be unexercised at runtime. Numbered `N0` so it can never be
    /// mistaken for a spec member. Carries no Layer A claim and is removable
    /// in one line. See NON-DELEGABLE-AUTHORITY-2026-08 §13.7.
    Probe,
}

impl ReservedReason {
    /// Spec identifier, e.g. `"N1"`. Used in refusal receipts so a chain
    /// reader can resolve the refusal against the spec without the prose.
    pub fn member_id(self) -> &'static str {
        match self {
            ReservedReason::GenesisSignature => "N1",
            ReservedReason::ReservedSetAmendment => "N2",
            ReservedReason::RootRevocation => "N3",
            ReservedReason::FormGraduation => "N4",
            ReservedReason::ConstitutionalModification => "N5",
            ReservedReason::ReservedGrantIssuance => "N6",
            ReservedReason::Probe => "N0",
        }
    }

    /// Whether this is a real spec member rather than the liveness probe.
    /// Used by tests to assert that no Layer A claim has been made yet.
    pub fn is_spec_member(self) -> bool {
        !matches!(self, ReservedReason::Probe)
    }
}

impl std::fmt::Display for ReservedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            ReservedReason::GenesisSignature => "Genesis signature",
            ReservedReason::ReservedSetAmendment => "amendment of the reserved set",
            ReservedReason::RootRevocation => "root revocation",
            ReservedReason::FormGraduation => "Substrate Form graduation",
            ReservedReason::ConstitutionalModification => "constitutional-rule modification",
            ReservedReason::ReservedGrantIssuance => "issuance of a reserved grant",
            ReservedReason::Probe => "non-delegable liveness probe",
        };
        write!(f, "{} ({})", text, self.member_id())
    }
}

/// The name of the liveness probe. Colon-delimited and namespaced so it
/// cannot collide with a real capability name — existing names are bare
/// identifiers (`read`, `tool_call`) or operator-chosen `Custom` names.
pub const RESERVED_PROBE_CAPABILITY: &str = "zp:reserved:probe";

/// The non-delegable membership table.
///
/// **Contains no spec members.** The only row is the liveness probe, which
/// carries no Layer A claim: it exists because N1–N6 are all still latent —
/// none of Genesis signing, root revocation, constitutional modification or
/// Form graduation currently flows through the capability system — and
/// without it this enforcement path would never execute outside tests.
///
/// Adding a real row makes the corresponding authority structurally
/// undelegable everywhere `reserved_class` is consulted, and makes the
/// Layer A claim real. Do not add one without reading
/// NON-DELEGABLE-AUTHORITY-2026-08 §6 on amendment cost — removing a row
/// later is a release that peers can detect as non-conformant. And note §13.2:
/// a row only protects a name that some code path actually constructs.
const RESERVED_CAPABILITY_NAMES: &[(&str, ReservedReason)] =
    &[(RESERVED_PROBE_CAPABILITY, ReservedReason::Probe)];

/// Whether a capability is structurally reserved to the sovereign operator.
///
/// Returns `Some(reason)` if the capability may never be granted or
/// delegated to anyone, by anyone, at any tier or depth. This is distinct
/// from constitutional prohibition (which forbids the *act*, for everyone
/// including the operator) and from a capability merely not being granted
/// (which is delegable in principle).
///
/// Canonical enforcement helper — per Principle 8, every enforcement point
/// calls this rather than reimplementing the test.
pub fn reserved_class(capability: &GrantedCapability) -> Option<ReservedReason> {
    lookup_reserved(capability.name(), RESERVED_CAPABILITY_NAMES)
}

/// Table lookup, split out so it is testable against a non-empty table while
/// `RESERVED_CAPABILITY_NAMES` is still empty. Without this split, step 1
/// would ship an enforcement path with no executable test behind it.
fn lookup_reserved(
    name: &str,
    table: &[(&str, ReservedReason)],
) -> Option<ReservedReason> {
    table
        .iter()
        .find(|(reserved_name, _)| *reserved_name == name)
        .map(|(_, reason)| *reason)
}

/// Error type for delegation failures.
#[derive(Debug, Clone)]
pub enum DelegationError {
    /// Delegation depth would exceed the maximum allowed.
    DepthExceeded { current: u8, max: u8 },
    /// Requested capability is not a subset of the parent's scope.
    ScopeNotSubset { parent: String, requested: String },
    /// Parent grant has expired.
    ParentExpired,
    /// P4 (#197): the parent's RedelegationPolicy forbids further delegation.
    RedelegationForbidden,
    /// P4 (#197): the new depth would exceed the parent's per-subtree depth ceiling.
    SubtreeDepthExceeded { depth: u32, max: u32 },
    /// P4 (#197): the parent requires explicit issuer approval for re-delegation.
    ApprovalRequired,
    /// P4 (#197): the child's lease terms exceed the parent's (e.g., longer
    /// lease_duration, broader renewal_authorities).
    LeaseEscalation { reason: String },
    /// The parent grant is at Tier 5 (Ceremony). T5 is the cold floor —
    /// no running process may re-delegate it. T5 authority is exercised
    /// only during a genesis ceremony.
    CeremonyTierNotDelegable,
    /// The requested capability is in the non-delegable set. Unlike every
    /// other variant here, this one is not about the parent's terms — the
    /// capability itself may never be delegated, by anyone, at any tier or
    /// depth. See NON-DELEGABLE-AUTHORITY-2026-08.
    ReservedCapability {
        capability: String,
        reserved_member: String,
    },
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::DepthExceeded { current, max } => {
                write!(
                    f,
                    "delegation depth {} would exceed max {}",
                    current + 1,
                    max
                )
            }
            DelegationError::ScopeNotSubset { parent, requested } => {
                write!(
                    f,
                    "requested capability '{}' is not a subset of parent '{}'",
                    requested, parent
                )
            }
            DelegationError::ParentExpired => write!(f, "parent grant has expired"),
            DelegationError::RedelegationForbidden => {
                write!(f, "parent grant forbids re-delegation")
            }
            DelegationError::SubtreeDepthExceeded { depth, max } => {
                write!(
                    f,
                    "subtree depth {} exceeds parent's max_subtree_depth {}",
                    depth, max
                )
            }
            DelegationError::ApprovalRequired => {
                write!(f, "re-delegation requires explicit issuer approval")
            }
            DelegationError::LeaseEscalation { reason } => {
                write!(f, "lease escalation: {}", reason)
            }
            DelegationError::CeremonyTierNotDelegable => {
                write!(
                    f,
                    "tier 5 (ceremony) is non-delegable — exercised only during genesis ceremony"
                )
            }
            DelegationError::ReservedCapability {
                capability,
                reserved_member,
            } => {
                write!(
                    f,
                    "capability '{}' is reserved to the sovereign operator ({}) — it may not be delegated at any tier or depth",
                    capability, reserved_member
                )
            }
        }
    }
}

impl std::error::Error for DelegationError {}

/// Error type for lease-renewal failures (P4 / #197).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalError {
    /// The grant has no `lease_policy` — it is not renewable.
    NoLeasePolicy,
    /// The grant is past `expires_at + grace_period` — silently renewing
    /// after the grace window would violate the lease contract.
    PastGrace,
}

impl std::fmt::Display for RenewalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenewalError::NoLeasePolicy => write!(f, "grant has no lease policy"),
            RenewalError::PastGrace => write!(f, "grant is past its grace period"),
        }
    }
}

impl std::error::Error for RenewalError {}

/// Error type for grant issuance validation failures (M4-3).
#[derive(Debug, Clone)]
pub enum IssuanceError {
    /// The grant has no `issued_via` provenance — cannot verify origin.
    MissingProvenance,
    /// An external request attempted to issue an internal-only capability.
    ExternalOnInternalCapability {
        capability: String,
        source_ip: Option<String>,
    },
    /// The capability is in the non-delegable set — it may not be placed in
    /// a grant at all, regardless of origin, signer or tier.
    /// See NON-DELEGABLE-AUTHORITY-2026-08.
    ReservedCapability {
        capability: String,
        reserved_member: String,
    },
}

impl std::fmt::Display for IssuanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuanceError::MissingProvenance => {
                write!(f, "grant has no issued_via provenance — cannot verify origin")
            }
            IssuanceError::ExternalOnInternalCapability {
                capability,
                source_ip,
            } => {
                write!(
                    f,
                    "external request (IP: {}) attempted to issue internal-only capability '{}'",
                    source_ip.as_deref().unwrap_or("unknown"),
                    capability
                )
            }
            IssuanceError::ReservedCapability {
                capability,
                reserved_member,
            } => {
                write!(
                    f,
                    "capability '{}' is reserved to the sovereign operator ({}) — it may not be placed in a grant",
                    capability, reserved_member
                )
            }
        }
    }
}

impl std::error::Error for IssuanceError {}

/// Internal type for canonical serialization (excludes signature).
///
/// P4 (#197): standing-delegation fields use `skip_serializing_if` so an
/// untouched legacy grant produces the exact same canonical bytes — and
/// thus the same signature — as it did before P4 was wired in. New
/// standing grants include the additional fields, and their signatures
/// cover the lease policy and authority lists.
#[derive(Debug, Serialize, Deserialize)]
struct CanonicalForm {
    id: String,
    capability: GrantedCapability,
    constraints: Vec<Constraint>,
    grantor: String,
    grantee: String,
    trust_tier: TrustTier,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    receipt_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_grant_id: Option<String>,
    delegation_depth: u8,
    max_delegation_depth: u8,

    // ---- P4 standing delegation -----------------------------------------
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lease_policy: Option<LeasePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    renewal_authorities: Vec<AuthorityRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    revocable_by: Vec<AuthorityRef>,
    #[serde(default, skip_serializing_if = "is_default_redelegation")]
    redelegation: RedelegationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    revocation_anchor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_renewed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    renewal_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subject_public_key: Option<String>,

    // ---- Officer cadre gap-closing fields ----------------------------------
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grantee_type: Option<GranteeType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task_description: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    context_receipts: Vec<String>,
}

fn is_default_redelegation(p: &RedelegationPolicy) -> bool {
    matches!(p, RedelegationPolicy::Forbidden)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grant_creation() {
        let grant = CapabilityGrant::new(
            "grantor_hash".to_string(),
            "grantee_hash".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_123".to_string(),
        );

        assert!(grant.id.starts_with("grant-"));
        assert_eq!(grant.grantor, "grantor_hash");
        assert_eq!(grant.grantee, "grantee_hash");
        assert_eq!(grant.trust_tier, TrustTier::Tier0);
        assert!(grant.is_valid());
    }

    #[test]
    fn test_grant_builder_pattern() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            },
            "receipt_456".to_string(),
        )
        .with_constraint(Constraint::MaxCost(5.0))
        .with_trust_tier(TrustTier::Tier1)
        .with_expiration(Utc::now() + chrono::Duration::hours(24));

        assert_eq!(grant.constraints.len(), 1);
        assert_eq!(grant.trust_tier, TrustTier::Tier1);
        assert!(grant.expires_at.is_some());
    }

    #[test]
    fn test_grant_expiration() {
        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        assert!(!grant.is_expired());

        // Set expiration to the past
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(grant.is_expired());

        // Set expiration to the future
        grant.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
        assert!(!grant.is_expired());
    }

    #[test]
    fn test_action_matching_read() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/config".to_string(), "data/logs/*".to_string()],
            },
            "receipt".to_string(),
        );

        // Should match exact path
        assert!(grant.matches_action(&ActionType::Read {
            target: "data/config".to_string(),
        }));

        // Should match glob pattern
        assert!(grant.matches_action(&ActionType::Read {
            target: "data/logs/app.log".to_string(),
        }));

        // Should not match outside scope
        assert!(!grant.matches_action(&ActionType::Read {
            target: "other/file".to_string(),
        }));

        // Should not match different action type
        assert!(!grant.matches_action(&ActionType::Write {
            target: "data/config".to_string(),
        }));
    }

    #[test]
    fn test_action_matching_execute() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Execute {
                languages: vec!["python".to_string(), "bash".to_string()],
            },
            "receipt".to_string(),
        );

        assert!(grant.matches_action(&ActionType::Execute {
            language: "python".to_string(),
        }));

        assert!(grant.matches_action(&ActionType::Execute {
            language: "bash".to_string(),
        }));

        assert!(!grant.matches_action(&ActionType::Execute {
            language: "javascript".to_string(),
        }));
    }

    #[test]
    fn test_action_matching_wildcard() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        assert!(grant.matches_action(&ActionType::Read {
            target: "any/path".to_string(),
        }));

        assert!(grant.matches_action(&ActionType::Read {
            target: "another/file".to_string(),
        }));
    }

    #[test]
    fn test_constraint_max_cost() {
        let constraint = Constraint::MaxCost(10.0);

        let ctx = ConstraintContext::new("path".to_string()).with_cost(5.0);
        assert!(constraint.check(&ctx).is_none());

        let ctx = ConstraintContext::new("path".to_string()).with_cost(15.0);
        assert!(constraint.check(&ctx).is_some());
    }

    #[test]
    fn test_constraint_rate_limit() {
        let constraint = Constraint::RateLimit {
            max_actions: 5,
            window_secs: 60,
        };

        let ctx = ConstraintContext::new("path".to_string()).with_recent_actions(3);
        assert!(constraint.check(&ctx).is_none());

        let ctx = ConstraintContext::new("path".to_string()).with_recent_actions(5);
        assert!(constraint.check(&ctx).is_some());

        let ctx = ConstraintContext::new("path".to_string()).with_recent_actions(10);
        assert!(constraint.check(&ctx).is_some());
    }

    #[test]
    fn test_constraint_scope_restriction() {
        let constraint = Constraint::ScopeRestriction {
            allowed: vec!["data/*".to_string()],
            denied: vec!["data/secret".to_string()],
        };

        // Within allowed scope, not denied
        let ctx = ConstraintContext::new("data/public".to_string());
        assert!(constraint.check(&ctx).is_none());

        // Denied path
        let ctx = ConstraintContext::new("data/secret".to_string());
        assert!(constraint.check(&ctx).is_some());

        // Outside allowed scope
        let ctx = ConstraintContext::new("other/data".to_string());
        assert!(constraint.check(&ctx).is_some());
    }

    #[test]
    fn test_constraint_require_receipt() {
        let constraint = Constraint::RequireReceipt;

        let ctx =
            ConstraintContext::new("path".to_string()).with_receipt_id("receipt_123".to_string());
        assert!(constraint.check(&ctx).is_none());

        let ctx = ConstraintContext::new("path".to_string());
        assert!(constraint.check(&ctx).is_some());
    }

    #[test]
    fn test_constraint_time_window() {
        let constraint = Constraint::TimeWindow {
            start_hour: 9,
            end_hour: 17,
        };

        // We can't easily test specific hours without mocking time,
        // but we can verify the logic doesn't panic
        let ctx = ConstraintContext::new("path".to_string());
        let _ = constraint.check(&ctx);
    }

    #[test]
    fn test_check_constraints_empty() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        let ctx = ConstraintContext::new("path".to_string());
        let violations = grant.check_constraints(&ctx);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_check_constraints_multiple() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_constraint(Constraint::MaxCost(1.0))
        .with_constraint(Constraint::RateLimit {
            max_actions: 5,
            window_secs: 60,
        })
        .with_constraint(Constraint::RequireReceipt);

        // Violate multiple constraints
        let ctx = ConstraintContext::new("logs/app.log".to_string())
            .with_cost(5.0)
            .with_recent_actions(10);

        let violations = grant.check_constraints(&ctx);
        assert!(violations.len() >= 2);
    }

    #[test]
    fn test_canonical_bytes_deterministic() {
        let grant1 = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_constraint(Constraint::MaxCost(10.0));

        let grant2 = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_constraint(Constraint::MaxCost(10.0));

        // Force the same ID and timestamp for comparison —
        // two grants created at different instants will naturally
        // have different created_at values.
        let mut grant2 = grant2;
        grant2.id = grant1.id.clone();
        grant2.created_at = grant1.created_at;

        let bytes1 = grant1.canonical_bytes();
        let bytes2 = grant2.canonical_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_canonical_bytes_excludes_signature() {
        let grant1 = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        let mut grant2 = grant1.clone();

        // Add signature to grant2
        grant2.signature = Some("signature_abc".to_string());
        grant2.signer_public_key = Some("pubkey_xyz".to_string());

        // Canonical bytes should be the same (signatures don't affect them)
        let bytes1 = grant1.canonical_bytes();
        let bytes2 = grant2.canonical_bytes();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            },
            "receipt_123".to_string(),
        )
        .with_constraint(Constraint::MaxCost(5.0))
        .with_trust_tier(TrustTier::Tier1)
        .with_expiration(Utc::now() + chrono::Duration::hours(24));

        // Serialize to JSON
        let json = serde_json::to_string(&grant).expect("serialization failed");

        // Deserialize back
        let restored: CapabilityGrant =
            serde_json::from_str(&json).expect("deserialization failed");

        assert_eq!(grant.id, restored.id);
        assert_eq!(grant.grantor, restored.grantor);
        assert_eq!(grant.grantee, restored.grantee);
        assert_eq!(grant.trust_tier, restored.trust_tier);
        assert_eq!(grant.constraints.len(), restored.constraints.len());
    }

    #[test]
    fn test_granted_capability_names() {
        let read_cap = GrantedCapability::Read {
            scope: vec!["*".to_string()],
        };
        assert_eq!(read_cap.name(), "read");

        let write_cap = GrantedCapability::Write {
            scope: vec!["*".to_string()],
        };
        assert_eq!(write_cap.name(), "write");

        let exec_cap = GrantedCapability::Execute {
            languages: vec!["python".to_string()],
        };
        assert_eq!(exec_cap.name(), "execute");

        let custom_cap = GrantedCapability::Custom {
            name: "my_capability".to_string(),
            parameters: serde_json::json!({}),
        };
        assert_eq!(custom_cap.name(), "my_capability");
    }

    // ====================================================================
    // Ed25519 Signature Tests (Phase 2 Step 1)
    // ====================================================================

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_123".to_string(),
        )
        .with_constraint(Constraint::MaxCost(10.0));

        // Before signing — no signature
        assert!(!grant.verify_signature());

        // Sign
        grant.sign(&signing_key);
        assert!(grant.signature.is_some());
        assert!(grant.signer_public_key.is_some());

        // Verify
        assert!(
            grant.verify_signature(),
            "Signature should verify after signing"
        );
    }

    #[test]
    fn test_verify_rejects_unsigned_grant() {
        let grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );
        assert!(!grant.verify_signature());
    }

    #[test]
    fn test_verify_rejects_tampered_grant() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Write {
                scope: vec!["logs/*".to_string()],
            },
            "receipt".to_string(),
        );

        grant.sign(&signing_key);
        assert!(grant.verify_signature());

        // Tamper with the grant after signing
        grant.grantee = "attacker".to_string();
        assert!(
            !grant.verify_signature(),
            "Tampered grant should fail verification"
        );
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let wrong_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Execute {
                languages: vec!["python".to_string()],
            },
            "receipt".to_string(),
        );

        grant.sign(&signing_key);

        // Swap the public key to a different key
        grant.signer_public_key = Some(hex::encode(wrong_key.verifying_key().to_bytes()));
        assert!(
            !grant.verify_signature(),
            "Should fail with wrong public key"
        );
    }

    #[test]
    fn test_verify_rejects_invalid_hex_signature() {
        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        grant.signature = Some("not_valid_hex!!!".to_string());
        grant.signer_public_key = Some("also_not_hex".to_string());
        assert!(!grant.verify_signature());
    }

    #[test]
    fn test_verify_rejects_wrong_length_key() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        grant.sign(&signing_key);

        // Truncate the public key to wrong length
        grant.signer_public_key = Some(hex::encode([0u8; 16])); // 16 bytes, not 32
        assert!(!grant.verify_signature());
    }

    #[test]
    fn test_sign_preserves_grant_fields() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut grant = CapabilityGrant::new(
            "grantor_hash".to_string(),
            "grantee_hash".to_string(),
            GrantedCapability::ApiCall {
                endpoints: vec!["api/v1/*".to_string()],
            },
            "receipt_456".to_string(),
        )
        .with_constraint(Constraint::RateLimit {
            max_actions: 60,
            window_secs: 60,
        })
        .with_trust_tier(TrustTier::Tier1);

        let id_before = grant.id.clone();
        let grantor_before = grant.grantor.clone();

        grant.sign(&signing_key);

        // Signing should not alter any field except signature and signer_public_key
        assert_eq!(grant.id, id_before);
        assert_eq!(grant.grantor, grantor_before);
        assert_eq!(grant.trust_tier, TrustTier::Tier1);
        assert!(grant.verify_signature());
    }

    #[test]
    fn test_signed_grant_survives_serialization() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut grant = CapabilityGrant::new(
            "grantor".to_string(),
            "grantee".to_string(),
            GrantedCapability::MeshSend {
                destinations: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );

        grant.sign(&signing_key);
        assert!(grant.verify_signature());

        // Serialize → deserialize
        let json = serde_json::to_string(&grant).unwrap();
        let restored: CapabilityGrant = serde_json::from_str(&json).unwrap();

        // Signature should still verify after round-trip
        assert!(
            restored.verify_signature(),
            "Signature should survive serialization round-trip"
        );
    }

    // ====================================================================
    // Phase 3 Step 2: Capability Delegation Chain Tests
    // ====================================================================

    #[test]
    fn test_delegate_basic() {
        let parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt_1".to_string(),
        );

        let child = parent
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "receipt_2".to_string(),
            )
            .unwrap();

        assert!(child.id.starts_with("grant-"));
        assert_eq!(child.grantor, "bob"); // delegator becomes grantor
        assert_eq!(child.grantee, "charlie");
        assert_eq!(child.parent_grant_id, Some(parent.id.clone()));
        assert_eq!(child.delegation_depth, 1);
        assert_eq!(child.max_delegation_depth, 3);
        assert!(child.is_delegated());
    }

    #[test]
    fn test_delegate_chain_depth() {
        let g0 = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r0".to_string(),
        )
        .with_max_delegation_depth(2);

        let g1 = g0
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r1".to_string(),
            )
            .unwrap();
        assert_eq!(g1.delegation_depth, 1);

        let g2 = g1
            .delegate(
                "dave".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();
        assert_eq!(g2.delegation_depth, 2);

        // Depth 3 would exceed max of 2
        let err = g2.delegate(
            "eve".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r3".to_string(),
        );
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            DelegationError::DepthExceeded { .. }
        ));
    }

    #[test]
    fn test_delegate_scope_narrowing() {
        let parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "r".to_string(),
        );

        // Narrower scope: OK
        let narrow = parent.delegate(
            "charlie".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/public".to_string()],
            },
            "r2".to_string(),
        );
        assert!(narrow.is_ok());

        // Wider scope: should fail
        let wide = parent.delegate(
            "charlie".to_string(),
            GrantedCapability::Read {
                scope: vec!["other/*".to_string()],
            },
            "r3".to_string(),
        );
        assert!(wide.is_err());
        assert!(matches!(
            wide.unwrap_err(),
            DelegationError::ScopeNotSubset { .. }
        ));
    }

    #[test]
    fn test_delegate_wrong_capability_type() {
        let parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        );

        // Can't delegate a Write from a Read grant
        let err = parent.delegate(
            "charlie".to_string(),
            GrantedCapability::Write {
                scope: vec!["*".to_string()],
            },
            "r2".to_string(),
        );
        assert!(err.is_err());
        assert!(matches!(
            err.unwrap_err(),
            DelegationError::ScopeNotSubset { .. }
        ));
    }

    #[test]
    fn test_delegate_inherits_constraints() {
        let parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Execute {
                languages: vec!["python".to_string(), "bash".to_string()],
            },
            "r".to_string(),
        )
        .with_constraint(Constraint::MaxCost(10.0))
        .with_constraint(Constraint::RequireReceipt);

        let child = parent
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Execute {
                    languages: vec!["python".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();

        assert_eq!(child.constraints.len(), 2);
    }

    #[test]
    fn test_delegate_inherits_expiration() {
        let parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        )
        .with_expiration(Utc::now() + chrono::Duration::hours(1));

        let child = parent
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();

        // Child inherits parent's expiration
        assert!(child.expires_at.is_some());
        assert_eq!(child.expires_at, parent.expires_at);
    }

    #[test]
    fn test_delegate_expired_parent_fails() {
        let mut parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        );
        parent.expires_at = Some(Utc::now() - chrono::Duration::seconds(1));

        let err = parent.delegate(
            "charlie".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r2".to_string(),
        );
        assert!(err.is_err());
        assert!(matches!(err.unwrap_err(), DelegationError::ParentExpired));
    }

    #[test]
    fn test_can_delegate() {
        let grant = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        )
        .with_max_delegation_depth(1);

        assert!(grant.can_delegate());
        assert!(!grant.is_delegated());

        let child = grant
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();

        // child is at depth 1, max is 1 — can't delegate further
        assert!(!child.can_delegate());
        assert!(child.is_delegated());
    }

    #[test]
    fn test_capability_contains_wildcard() {
        let parent = GrantedCapability::Read {
            scope: vec!["*".to_string()],
        };
        let child = GrantedCapability::Read {
            scope: vec!["data/foo".to_string()],
        };
        assert!(parent.contains(&child));
    }

    #[test]
    fn test_capability_contains_glob() {
        let parent = GrantedCapability::ApiCall {
            endpoints: vec!["api/v1/*".to_string(), "api/v2/*".to_string()],
        };
        let child = GrantedCapability::ApiCall {
            endpoints: vec!["api/v1/users".to_string()],
        };
        assert!(parent.contains(&child));

        let outside = GrantedCapability::ApiCall {
            endpoints: vec!["api/v3/admin".to_string()],
        };
        assert!(!parent.contains(&outside));
    }

    #[test]
    fn test_capability_contains_different_types() {
        let read = GrantedCapability::Read {
            scope: vec!["*".to_string()],
        };
        let write = GrantedCapability::Write {
            scope: vec!["*".to_string()],
        };
        assert!(!read.contains(&write));
    }

    #[test]
    fn test_delegate_signed_chain() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let child_key = SigningKey::generate(&mut rand::rngs::OsRng);

        let mut parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "r1".to_string(),
        );
        parent.sign(&signing_key);
        assert!(parent.verify_signature());

        let mut child = parent
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["data/public".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();
        child.sign(&child_key);
        assert!(child.verify_signature());

        // Both are independently verifiable
        assert!(parent.verify_signature());
        assert!(child.verify_signature());
        assert_eq!(child.parent_grant_id, Some(parent.id.clone()));
    }

    #[test]
    fn test_delegated_grant_serialization_roundtrip() {
        let parent = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "r".to_string(),
        );

        let child = parent
            .delegate(
                "charlie".to_string(),
                GrantedCapability::Read {
                    scope: vec!["*".to_string()],
                },
                "r2".to_string(),
            )
            .unwrap();

        let json = serde_json::to_string(&child).unwrap();
        let restored: CapabilityGrant = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.parent_grant_id, child.parent_grant_id);
        assert_eq!(restored.delegation_depth, 1);
        assert_eq!(restored.max_delegation_depth, 3);
    }

    // ====================================================================
    // Phase 2.7 (M4-3): Self-issuance prevention tests
    // ====================================================================

    #[test]
    fn test_validate_issuance_with_user_action() {
        let grant = CapabilityGrant::new(
            "operator".to_string(),
            "agent".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_issued_via(EventProvenance::user_action("operator"));

        assert!(grant.validate_issuance().is_ok());
    }

    #[test]
    fn test_validate_issuance_missing_provenance() {
        let grant = CapabilityGrant::new(
            "operator".to_string(),
            "agent".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "receipt".to_string(),
        );
        // No issued_via set — should fail
        assert!(matches!(
            grant.validate_issuance(),
            Err(IssuanceError::MissingProvenance)
        ));
    }

    #[test]
    fn test_validate_issuance_external_on_internal_capability() {
        // ConfigChange is internal-only — external requests must be blocked
        let grant = CapabilityGrant::new(
            "ssrf-attacker".to_string(),
            "ssrf-attacker".to_string(),
            GrantedCapability::ConfigChange {
                settings: vec!["*".to_string()],
            },
            "forged-receipt".to_string(),
        )
        .with_issued_via(EventProvenance::external_request(
            "unknown",
            Some("10.0.0.99".to_string()),
        ));

        let result = grant.validate_issuance();
        assert!(matches!(
            result,
            Err(IssuanceError::ExternalOnInternalCapability { .. })
        ));
    }

    #[test]
    fn test_validate_issuance_external_on_credential_access() {
        // CredentialAccess is internal-only
        let grant = CapabilityGrant::new(
            "attacker".to_string(),
            "attacker".to_string(),
            GrantedCapability::CredentialAccess {
                credential_refs: vec!["*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_issued_via(EventProvenance::external_request("attacker", None));

        assert!(matches!(
            grant.validate_issuance(),
            Err(IssuanceError::ExternalOnInternalCapability { .. })
        ));
    }

    #[test]
    fn test_validate_issuance_external_on_read_ok() {
        // Read capability via external request is allowed
        let grant = CapabilityGrant::new(
            "remote-agent".to_string(),
            "local-agent".to_string(),
            GrantedCapability::Read {
                scope: vec!["public/*".to_string()],
            },
            "receipt".to_string(),
        )
        .with_issued_via(EventProvenance::external_request(
            "remote-agent",
            Some("192.168.1.50".to_string()),
        ));

        assert!(grant.validate_issuance().is_ok());
    }

    #[test]
    fn test_validate_issuance_system_internal_on_config_ok() {
        // System-internal origin on ConfigChange is legitimate (pipeline orchestration)
        let grant = CapabilityGrant::new(
            "pipeline".to_string(),
            "tool-proxy".to_string(),
            GrantedCapability::ConfigChange {
                settings: vec!["log_level".to_string()],
            },
            "receipt".to_string(),
        )
        .with_issued_via(EventProvenance::system_internal("pipeline"));

        assert!(grant.validate_issuance().is_ok());
    }

    #[test]
    fn test_issued_via_survives_serialization() {
        let grant = CapabilityGrant::new(
            "operator".to_string(),
            "agent".to_string(),
            GrantedCapability::Execute {
                languages: vec!["python".to_string()],
            },
            "receipt".to_string(),
        )
        .with_issued_via(
            EventProvenance::policy_evaluation("policy-engine")
                .with_authorization("auth-receipt-1"),
        );

        let json = serde_json::to_string(&grant).unwrap();
        let restored: CapabilityGrant = serde_json::from_str(&json).unwrap();

        assert!(restored.issued_via.is_some());
        assert!(restored.validate_issuance().is_ok());
    }

    // ────────────────────────────────────────────────────────────────────
    // P4 (#197) — standing delegation extension tests
    // ────────────────────────────────────────────────────────────────────

    #[test]
    fn p4_legacy_grant_canonical_bytes_unchanged() {
        // Backward-compat invariant: a grant created exactly the way pre-P4
        // code did (no lease, no authorities, default redelegation) must
        // produce the same canonical bytes as a hypothetical pre-P4 grant
        // would have. We assert this structurally: the JSON must NOT contain
        // any of the new field names when defaults are unset.
        let grant = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["data/*".to_string()],
            },
            "rcpt".to_string(),
        );
        let canonical = String::from_utf8(grant.canonical_bytes()).unwrap();
        assert!(
            !canonical.contains("lease_policy"),
            "default grant must not serialize lease_policy"
        );
        assert!(
            !canonical.contains("renewal_authorities"),
            "default grant must not serialize renewal_authorities"
        );
        assert!(
            !canonical.contains("revocable_by"),
            "default grant must not serialize revocable_by"
        );
        assert!(
            !canonical.contains("redelegation"),
            "default grant must not serialize redelegation when Forbidden"
        );
    }

    #[test]
    fn p4_standing_grant_round_trips() {
        let grant = CapabilityGrant::new(
            "genesis".to_string(),
            "artemis".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_lease_policy(crate::lease::LeasePolicy::standard_8h())
        .with_renewal_authorities(vec![crate::authority_ref::AuthorityRef::genesis(
            "lease_renewal",
        )])
        .with_revocable_by(vec![crate::authority_ref::AuthorityRef::genesis(
            "revocation_authority",
        )])
        .as_standing("operator-pubkey-hex");

        let json = serde_json::to_string(&grant).unwrap();
        let restored: CapabilityGrant = serde_json::from_str(&json).unwrap();
        assert!(restored.has_lease());
        assert_eq!(restored.renewal_authorities.len(), 1);
        assert_eq!(restored.revocable_by.len(), 1);
        assert!(matches!(
            restored.provenance,
            GrantProvenance::Standing { .. }
        ));
    }

    #[test]
    fn p4_renew_advances_expiry_and_increments_count() {
        let mut grant = CapabilityGrant::new(
            "genesis".to_string(),
            "artemis".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_lease_policy(crate::lease::LeasePolicy::standard_8h());

        let initial_expiry = grant.expires_at.unwrap();
        let initial_count = grant.renewal_count;

        // Sleep would be flaky — instead pull expires_at backwards by 1s
        // so the renewal advances it from a known earlier point.
        grant.expires_at = Some(initial_expiry - chrono::Duration::seconds(1));
        let new_expiry = grant.renew().expect("renew must succeed");

        assert!(new_expiry > initial_expiry - chrono::Duration::seconds(1));
        assert_eq!(grant.renewal_count, initial_count + 1);
        assert!(grant.last_renewed_at.is_some());
    }

    #[test]
    fn p4_renew_rejects_no_lease_policy() {
        let mut grant = CapabilityGrant::new(
            "alice".to_string(),
            "bob".to_string(),
            GrantedCapability::Read {
                scope: vec!["*".to_string()],
            },
            "rcpt".to_string(),
        );
        let err = grant.renew().unwrap_err();
        assert_eq!(err, RenewalError::NoLeasePolicy);
    }

    #[test]
    fn p4_renew_rejects_past_grace() {
        let mut grant = CapabilityGrant::new(
            "genesis".to_string(),
            "artemis".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_lease_policy(crate::lease::LeasePolicy {
            lease_duration: std::time::Duration::from_secs(60),
            grace_period: std::time::Duration::from_secs(10),
            renewal_interval: std::time::Duration::from_secs(30),
            failure_mode: crate::lease::LeaseFailureMode::HaltOnExpiry,
            max_consecutive_failures: 1,
        });
        // Push expiry far into the past so even with grace we're past it.
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(3600));
        let err = grant.renew().unwrap_err();
        assert_eq!(err, RenewalError::PastGrace);
    }

    #[test]
    fn p4_grace_period_logic() {
        let mut grant = CapabilityGrant::new(
            "genesis".to_string(),
            "artemis".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_lease_policy(crate::lease::LeasePolicy {
            lease_duration: std::time::Duration::from_secs(3600),
            grace_period: std::time::Duration::from_secs(300),
            renewal_interval: std::time::Duration::from_secs(900),
            failure_mode: crate::lease::LeaseFailureMode::HaltOnExpiry,
            max_consecutive_failures: 3,
        });

        // Alive: expiry far in the future.
        assert!(!grant.is_in_grace_period());
        assert!(!grant.is_past_grace());

        // Grace: expiry just barely in the past, still inside grace window.
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(60));
        assert!(grant.is_in_grace_period());
        assert!(!grant.is_past_grace());

        // Past grace: expiry well past + grace window.
        grant.expires_at = Some(Utc::now() - chrono::Duration::seconds(900));
        assert!(!grant.is_in_grace_period());
        assert!(grant.is_past_grace());
    }

    #[test]
    fn p4_redelegation_forbidden_blocks_standing_delegate() {
        let parent = CapabilityGrant::new(
            "genesis".to_string(),
            "subject1".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_max_delegation_depth(5)
        .with_lease_policy(crate::lease::LeasePolicy::standard_8h())
        .as_standing("op-key");

        // Standing + Forbidden (default) should reject re-delegation.
        let err = parent
            .delegate(
                "subject2".to_string(),
                GrantedCapability::Custom {
                    name: "tool-execution".to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt-child".to_string(),
            )
            .unwrap_err();
        match err {
            DelegationError::RedelegationForbidden => {}
            other => panic!("expected RedelegationForbidden, got {:?}", other),
        }
    }

    #[test]
    fn p4_redelegation_allowed_propagates_lease() {
        let parent = CapabilityGrant::new(
            "genesis".to_string(),
            "subject1".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_max_delegation_depth(3)
        .with_lease_policy(crate::lease::LeasePolicy::standard_8h())
        .with_renewal_authorities(vec![
            crate::authority_ref::AuthorityRef::genesis("lease_renewal"),
        ])
        .with_redelegation_policy(RedelegationPolicy::Allowed {
            max_subtree_depth: 2,
        });

        let child = parent
            .delegate(
                "subject2".to_string(),
                GrantedCapability::Custom {
                    name: "tool-execution".to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt-child".to_string(),
            )
            .expect("re-delegation should be allowed");
        assert!(child.has_lease(), "child must inherit lease policy");
        assert_eq!(child.renewal_authorities.len(), 1);
        assert_eq!(child.delegation_depth, 1);
    }

    #[test]
    fn t5_ceremony_grant_cannot_be_delegated() {
        let parent = CapabilityGrant::new(
            "genesis".to_string(),
            "council".to_string(),
            GrantedCapability::Custom {
                name: "council-authority".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_trust_tier(TrustTier::Tier5)
        .with_max_delegation_depth(3);

        let err = parent
            .delegate(
                "core".to_string(),
                GrantedCapability::Custom {
                    name: "council-authority".to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt-child".to_string(),
            )
            .unwrap_err();
        match err {
            DelegationError::CeremonyTierNotDelegable => {}
            other => panic!("expected CeremonyTierNotDelegable, got {:?}", other),
        }
    }

    #[test]
    fn t3_t4_grants_delegate_normally() {
        // Tier 3 (Core) and Tier 4 (Council) are delegable like any other
        // operational tier — only T5 is the cold floor.
        for tier in [TrustTier::Tier3, TrustTier::Tier4] {
            let parent = CapabilityGrant::new(
                "genesis".to_string(),
                "subject".to_string(),
                GrantedCapability::Custom {
                    name: "tool-execution".to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt".to_string(),
            )
            .with_trust_tier(tier)
            .with_max_delegation_depth(3);

            let child = parent
                .delegate(
                    "child".to_string(),
                    GrantedCapability::Custom {
                        name: "tool-execution".to_string(),
                        parameters: serde_json::Value::Null,
                    },
                    "rcpt-child".to_string(),
                )
                .expect("T3/T4 must delegate cleanly");
            assert_eq!(child.trust_tier, tier, "child inherits parent tier");
        }
    }

    #[test]
    fn tier_ladder_ordering_is_monotonic() {
        // PartialOrd derives lexically over variant order. The substrate
        // relies on this for ceiling comparisons; pin the invariant.
        assert!(TrustTier::Tier0 < TrustTier::Tier1);
        assert!(TrustTier::Tier1 < TrustTier::Tier2);
        assert!(TrustTier::Tier2 < TrustTier::Tier3);
        assert!(TrustTier::Tier3 < TrustTier::Tier4);
        assert!(TrustTier::Tier4 < TrustTier::Tier5);
    }

    #[test]
    fn tier_from_u8_round_trips_in_range() {
        for n in 0u8..=5u8 {
            let tier = TrustTier::from_u8(n).expect("0..=5 must parse");
            assert_eq!(tier.as_u8(), n);
        }
    }

    #[test]
    fn tier_from_u8_rejects_out_of_range() {
        assert!(TrustTier::from_u8(6).is_none());
        assert!(TrustTier::from_u8(7).is_none());
        assert!(TrustTier::from_u8(255).is_none());
    }

    #[test]
    fn is_ceremony_only_true_for_tier5() {
        assert!(!TrustTier::Tier0.is_ceremony());
        assert!(!TrustTier::Tier1.is_ceremony());
        assert!(!TrustTier::Tier2.is_ceremony());
        assert!(!TrustTier::Tier3.is_ceremony());
        assert!(!TrustTier::Tier4.is_ceremony());
        assert!(TrustTier::Tier5.is_ceremony());
    }

    #[test]
    fn p4_redelegation_subtree_depth_enforced() {
        let parent = CapabilityGrant::new(
            "genesis".to_string(),
            "subject1".to_string(),
            GrantedCapability::Custom {
                name: "x".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_max_delegation_depth(10) // not the limiter
        .with_redelegation_policy(RedelegationPolicy::Allowed {
            max_subtree_depth: 0, // limiter — no further delegation
        });
        let err = parent
            .delegate(
                "subject2".to_string(),
                GrantedCapability::Custom {
                    name: "x".to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt-child".to_string(),
            )
            .unwrap_err();
        match err {
            DelegationError::SubtreeDepthExceeded { depth, max } => {
                assert_eq!(depth, 1);
                assert_eq!(max, 0);
            }
            other => panic!("expected SubtreeDepthExceeded, got {:?}", other),
        }
    }

    // ── Non-delegable authority (NON-DELEGABLE-AUTHORITY-2026-08 step 1) ──
    //
    // The membership table ships empty, so these tests split in two: the
    // lookup mechanism is tested against a synthetic table, and the live
    // path is tested to prove it is currently inert. Step 2 replaces the
    // inertness tests with real membership tests.

    /// The table lookup matches by capability name, including the name
    /// carried by `Custom` — which is the only shape N1–N5 could take today,
    /// since none of them is an existing `GrantedCapability` variant.
    #[test]
    fn reserved_lookup_matches_custom_capability_name() {
        const TEST_TABLE: &[(&str, ReservedReason)] =
            &[("genesis_sign", ReservedReason::GenesisSignature)];

        let smuggled = GrantedCapability::Custom {
            name: "genesis_sign".to_string(),
            parameters: serde_json::Value::Null,
        };
        assert_eq!(
            lookup_reserved(smuggled.name(), TEST_TABLE),
            Some(ReservedReason::GenesisSignature)
        );

        let ordinary = GrantedCapability::Read {
            scope: vec!["*".to_string()],
        };
        assert_eq!(lookup_reserved(ordinary.name(), TEST_TABLE), None);
    }

    /// Lookup is exact, not prefix or substring — a capability whose name
    /// merely contains a reserved name is not itself reserved.
    #[test]
    fn reserved_lookup_is_exact_match() {
        const TEST_TABLE: &[(&str, ReservedReason)] =
            &[("genesis_sign", ReservedReason::GenesisSignature)];

        for near_miss in ["genesis_signx", "xgenesis_sign", "genesis", "GENESIS_SIGN"] {
            assert_eq!(
                lookup_reserved(near_miss, TEST_TABLE),
                None,
                "'{}' should not match",
                near_miss
            );
        }
    }

    /// Step-1 invariant: the shipped table carries the liveness probe and
    /// **no spec member**, so no Layer A claim has been made and no real
    /// authority has changed behaviour. Step 2 adds the first spec member and
    /// must update this test deliberately, not incidentally.
    #[test]
    fn reserved_set_contains_probe_only_no_spec_members() {
        assert_eq!(
            RESERVED_CAPABILITY_NAMES.len(),
            1,
            "expected only the liveness probe"
        );
        for (name, reason) in RESERVED_CAPABILITY_NAMES {
            assert!(
                !reason.is_spec_member(),
                "'{}' is a spec member ({}) — adding one carries the KEEL III.6 \
                 amendment cost and must be a deliberate change, not a drive-by",
                name,
                reason.member_id()
            );
        }
    }

    /// No ordinary capability matches. The probe is deliberately unreachable
    /// by any name a real grant would carry.
    #[test]
    fn ordinary_capabilities_are_never_reserved() {
        let every_variant = [
            GrantedCapability::Read { scope: vec![] },
            GrantedCapability::Write { scope: vec![] },
            GrantedCapability::Execute { languages: vec![] },
            GrantedCapability::CredentialAccess {
                credential_refs: vec![],
            },
            GrantedCapability::ApiCall { endpoints: vec![] },
            GrantedCapability::ConfigChange { settings: vec![] },
            GrantedCapability::MeshSend {
                destinations: vec![],
            },
            GrantedCapability::Custom {
                name: "anything".to_string(),
                parameters: serde_json::Value::Null,
            },
            GrantedCapability::ToolCall { tools: vec![] },
        ];
        for cap in &every_variant {
            assert!(
                reserved_class(cap).is_none(),
                "'{}' unexpectedly matched the reserved table",
                cap.name()
            );
        }
    }

    /// End-to-end at enforcement point 1: a grant naming a reserved
    /// capability is refused at issuance, and the error names the member.
    #[test]
    fn reserved_capability_is_refused_at_issuance() {
        let grant = CapabilityGrant::new(
            "genesis".to_string(),
            "some-agent".to_string(),
            GrantedCapability::Custom {
                name: RESERVED_PROBE_CAPABILITY.to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        );

        match grant.validate_issuance().unwrap_err() {
            IssuanceError::ReservedCapability {
                capability,
                reserved_member,
            } => {
                assert_eq!(capability, RESERVED_PROBE_CAPABILITY);
                assert_eq!(reserved_member, "N0");
            }
            other => panic!("expected ReservedCapability, got {:?}", other),
        }
    }

    /// The reserved check precedes the provenance check. A grant that is both
    /// reserved and missing `issued_via` must report the reserved refusal —
    /// the refusal has to name the real reason, not whichever check fired
    /// first. This is the ordering step 2 inherits.
    #[test]
    fn reserved_refusal_precedes_missing_provenance() {
        let grant = CapabilityGrant::new(
            "genesis".to_string(),
            "some-agent".to_string(),
            GrantedCapability::Custom {
                name: RESERVED_PROBE_CAPABILITY.to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        );
        // `new()` leaves issued_via = None, which would otherwise produce
        // MissingProvenance.
        assert!(grant.issued_via.is_none());
        assert!(matches!(
            grant.validate_issuance().unwrap_err(),
            IssuanceError::ReservedCapability { .. }
        ));
    }

    /// End-to-end at enforcement point 2: re-delegation of a reserved
    /// capability is refused, and refused ahead of the tier check — a Tier 5
    /// parent would otherwise return `CeremonyTierNotDelegable` and mask the
    /// real reason.
    #[test]
    fn reserved_capability_is_refused_at_delegation_ahead_of_tier() {
        let parent = CapabilityGrant::new(
            "genesis".to_string(),
            "subject1".to_string(),
            GrantedCapability::Custom {
                name: RESERVED_PROBE_CAPABILITY.to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_max_delegation_depth(5)
        .with_trust_tier(TrustTier::Tier5);

        match parent
            .delegate(
                "subject2".to_string(),
                GrantedCapability::Custom {
                    name: RESERVED_PROBE_CAPABILITY.to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt-child".to_string(),
            )
            .unwrap_err()
        {
            DelegationError::ReservedCapability {
                capability,
                reserved_member,
            } => {
                assert_eq!(capability, RESERVED_PROBE_CAPABILITY);
                assert_eq!(reserved_member, "N0");
            }
            other => panic!(
                "expected ReservedCapability to precede the tier check, got {:?}",
                other
            ),
        }
    }

    /// Regression guard: the new check sits at the top of `delegate()`, so
    /// an ordinary delegation must still succeed unchanged.
    #[test]
    fn reserved_check_does_not_disturb_ordinary_delegation() {
        let parent = CapabilityGrant::new(
            "genesis".to_string(),
            "subject1".to_string(),
            GrantedCapability::Custom {
                name: "tool-execution".to_string(),
                parameters: serde_json::Value::Null,
            },
            "rcpt".to_string(),
        )
        .with_max_delegation_depth(5);

        let child = parent
            .delegate(
                "subject2".to_string(),
                GrantedCapability::Custom {
                    name: "tool-execution".to_string(),
                    parameters: serde_json::Value::Null,
                },
                "rcpt-child".to_string(),
            )
            .expect("ordinary delegation must still succeed in step 1");
        assert_eq!(child.delegation_depth, 1);
    }

    /// Member ids are the spec's identifiers and are used in refusal
    /// receipts — a chain reader resolves the refusal against the spec by
    /// this string, so it is part of the wire contract, not a label.
    #[test]
    fn reserved_reason_member_ids_are_stable_and_distinct() {
        let all = [
            ReservedReason::GenesisSignature,
            ReservedReason::ReservedSetAmendment,
            ReservedReason::RootRevocation,
            ReservedReason::FormGraduation,
            ReservedReason::ConstitutionalModification,
            ReservedReason::ReservedGrantIssuance,
            ReservedReason::Probe,
        ];
        let ids: Vec<&str> = all.iter().map(|r| r.member_id()).collect();
        assert_eq!(ids, vec!["N1", "N2", "N3", "N4", "N5", "N6", "N0"]);

        let mut seen = std::collections::HashSet::new();
        for id in &ids {
            assert!(seen.insert(*id), "duplicate member id {}", id);
        }

        // The probe must never be mistaken for a spec member.
        assert!(!ReservedReason::Probe.is_spec_member());
        assert!(ReservedReason::GenesisSignature.is_spec_member());

        assert!(ReservedReason::GenesisSignature
            .to_string()
            .contains("N1"));
    }

    /// `satisfiable_actions` and `matches_action` must not be able to disagree.
    ///
    /// This is the guard that lets `satisfiable_actions` be a *derivation*
    /// rather than a stored field. Without it the two are just two hand-written
    /// tables, which is the arrangement this method was written to avoid.
    ///
    /// Scope is wildcarded throughout so the only thing under test is the
    /// capability-to-action-type pairing; scope narrowing has its own tests.
    #[test]
    fn satisfiable_actions_agrees_with_matches_action() {
        use crate::policy::{ActionType, FileOperation};

        // Exhaustive, no wildcard arm, on purpose: adding a variant to
        // `ActionType` breaks this build. That is the loud failure that keeps
        // `satisfiable_actions` honest when the action vocabulary grows.
        // Do not add a `_` arm — add the variant, and a sample below.
        fn action_kind(a: &ActionType) -> &'static str {
            match a {
                ActionType::Chat => "Chat",
                ActionType::Read { .. } => "Read",
                ActionType::Write { .. } => "Write",
                ActionType::ApiCall { .. } => "ApiCall",
                ActionType::Execute { .. } => "Execute",
                ActionType::FileOp { .. } => "FileOp",
                ActionType::CredentialAccess { .. } => "CredentialAccess",
                ActionType::ConfigChange { .. } => "ConfigChange",
                ActionType::KeyDelegation { .. } => "KeyDelegation",
                ActionType::PeerIntroduction { .. } => "PeerIntroduction",
                ActionType::ToolCall { .. } => "ToolCall",
                ActionType::InferenceRequest { .. } => "InferenceRequest",
            }
        }

        let star = || vec!["*".to_string()];
        let capabilities = vec![
            GrantedCapability::Read { scope: star() },
            GrantedCapability::Write { scope: star() },
            GrantedCapability::Execute { languages: star() },
            GrantedCapability::CredentialAccess { credential_refs: star() },
            GrantedCapability::ApiCall { endpoints: star() },
            GrantedCapability::ConfigChange { settings: star() },
            GrantedCapability::MeshSend { destinations: star() },
            GrantedCapability::Custom {
                name: "anything".to_string(),
                parameters: serde_json::Value::Null,
            },
            GrantedCapability::ToolCall { tools: star() },
        ];

        // Samples for the variants that can be constructed without inventing
        // field values. The remaining variants are still covered by
        // `action_kind`'s exhaustive match and by `no_unsampled_kinds` below.
        let actions = vec![
            ActionType::Chat,
            ActionType::Read { target: "anything".to_string() },
            ActionType::Write { target: "anything".to_string() },
            ActionType::ApiCall { endpoint: "https://anything".to_string() },
            ActionType::Execute { language: "python".to_string() },
            ActionType::FileOp {
                op: FileOperation::Read,
                path: "anything".to_string(),
            },
            ActionType::CredentialAccess { credential_ref: "anything".to_string() },
            ActionType::ConfigChange { setting: "anything".to_string() },
            ActionType::ToolCall { name: "anything".to_string() },
        ];

        for capability in &capabilities {
            let grant = CapabilityGrant::new(
                "grantor".to_string(),
                "grantee".to_string(),
                capability.clone(),
                "rcpt-test".to_string(),
            );
            let declared = grant.satisfiable_actions();

            for action in &actions {
                let kind = action_kind(action);
                let declared_says = declared.contains(&kind);
                let matcher_says = grant.matches_action(action);
                assert_eq!(
                    declared_says, matcher_says,
                    "disagreement for capability {:?} on action {}: \
                     satisfiable_actions says {}, matches_action says {}. \
                     These two describe the same pairing and must be changed \
                     together.",
                    capability, kind, declared_says, matcher_says
                );
            }

            // Every kind named must be one we actually exercised above —
            // otherwise the agreement check silently skips it.
            let sampled: Vec<&'static str> = actions.iter().map(action_kind).collect();
            for kind in declared {
                assert!(
                    sampled.contains(kind),
                    "satisfiable_actions names `{kind}` for {:?}, but no sample \
                     action of that kind exists, so agreement was never checked. \
                     Add one to `actions`.",
                    capability
                );
            }
        }
    }
}
