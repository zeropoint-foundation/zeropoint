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
use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};
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
        if pk_bytes.len() != 32 {
            return false;
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let Ok(verifying) = VerifyingKey::from_bytes(&pk_arr) else {
            return false;
        };

        let Ok(sig_bytes) = hex::decode(signature_hex) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        verifying.verify_strict(payload, &signature).is_ok()
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
    /// - Must have equal or narrower scope (enforced by `narrow_capability`)
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

            // All other combinations don't match
            _ => false,
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
        };

        // Serialize to JSON with sorted keys
        serde_json::to_vec(&canonical).unwrap_or_default()
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
        match (&self.signature, &self.signer_public_key) {
            (Some(sig_hex), Some(pubkey_hex)) => {
                // Parse the public key from hex
                let pubkey_bytes = match hex::decode(pubkey_hex) {
                    Ok(b) if b.len() == 32 => b,
                    _ => return false,
                };
                let mut key_array = [0u8; 32];
                key_array.copy_from_slice(&pubkey_bytes);

                let verifying_key = match VerifyingKey::from_bytes(&key_array) {
                    Ok(k) => k,
                    Err(_) => return false,
                };

                // Parse the signature from hex
                let sig_bytes = match hex::decode(sig_hex) {
                    Ok(b) if b.len() == 64 => b,
                    _ => return false,
                };
                let mut sig_array = [0u8; 64];
                sig_array.copy_from_slice(&sig_bytes);
                let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

                // Verify against canonical bytes (excludes signature itself)
                let canonical = self.canonical_bytes();
                verifying_key.verify_strict(&canonical, &signature).is_ok()
            }
            _ => false,
        }
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
}
