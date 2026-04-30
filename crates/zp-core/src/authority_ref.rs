//! Authority references — addressable principals that can renew or revoke a
//! standing delegation (#197).
//!
//! An `AuthorityRef` answers the question "who is allowed to renew/revoke
//! this grant?" without hard-coding the answer to a single key. The reference
//! resolves at validation time: a `Genesis` ref matches the issuing zone's
//! genesis node, a `GrantHolder` ref matches whichever node currently holds
//! the named grant, and an `AnchorVerified` ref defers to the external
//! anchor layer (future — used once HCS is wired in).

use serde::{Deserialize, Serialize};

use crate::capability_grant::GrantedCapability;

/// A reference to one of the authorities allowed to renew or revoke a grant.
///
/// Note: PartialEq is not derived because `GrantedCapability` itself does not
/// implement it. Equality is compared structurally by `(ref_type, grant_id,
/// capability_required.name())` in the few places it matters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityRef {
    /// How this authority is identified.
    pub ref_type: AuthorityRefType,

    /// For `GrantHolder` references, the grant id whose holder is the
    /// authority. None for `Genesis` and `AnchorVerified`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,

    /// The capability the referenced authority must hold to act on this
    /// grant. For renewal: usually a custom `lease_renewal` capability.
    /// For revocation: a custom `revocation_authority` capability.
    pub capability_required: GrantedCapability,
}

/// How an authority reference is resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRefType {
    /// The genesis node of the zone that issued this grant.
    Genesis,

    /// Whoever currently holds the grant identified by `grant_id`.
    GrantHolder,

    /// Verified out-of-band via the truth anchor layer (future — HCS topic
    /// inclusion proof). Treated as `Genesis` until the anchor client ships.
    AnchorVerified,
}

impl AuthorityRef {
    /// Quick constructor for "the genesis node, with custom capability X".
    pub fn genesis(capability_name: impl Into<String>) -> Self {
        Self {
            ref_type: AuthorityRefType::Genesis,
            grant_id: None,
            capability_required: GrantedCapability::Custom {
                name: capability_name.into(),
                parameters: serde_json::Value::Null,
            },
        }
    }

    /// Quick constructor for "the holder of grant G, with custom capability X".
    pub fn grant_holder(grant_id: impl Into<String>, capability_name: impl Into<String>) -> Self {
        Self {
            ref_type: AuthorityRefType::GrantHolder,
            grant_id: Some(grant_id.into()),
            capability_required: GrantedCapability::Custom {
                name: capability_name.into(),
                parameters: serde_json::Value::Null,
            },
        }
    }

    /// Whether this reference resolves locally without contacting the
    /// anchor layer. Only `AnchorVerified` is non-local.
    pub fn is_local(&self) -> bool {
        !matches!(self.ref_type, AuthorityRefType::AnchorVerified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_ref_is_local() {
        let r = AuthorityRef::genesis("lease_renewal");
        assert!(r.is_local());
        assert_eq!(r.ref_type, AuthorityRefType::Genesis);
        assert!(r.grant_id.is_none());
    }

    #[test]
    fn grant_holder_ref_carries_grant_id() {
        let r = AuthorityRef::grant_holder("grant-abc", "revocation_authority");
        assert!(r.is_local());
        assert_eq!(r.ref_type, AuthorityRefType::GrantHolder);
        assert_eq!(r.grant_id.as_deref(), Some("grant-abc"));
    }

    #[test]
    fn anchor_verified_is_not_local() {
        let r = AuthorityRef {
            ref_type: AuthorityRefType::AnchorVerified,
            grant_id: None,
            capability_required: GrantedCapability::Custom {
                name: "anchor_check".to_string(),
                parameters: serde_json::Value::Null,
            },
        };
        assert!(!r.is_local());
    }

    #[test]
    fn authority_ref_round_trips_through_json() {
        let r = AuthorityRef::grant_holder("grant-xyz", "lease_renewal");
        let s = serde_json::to_string(&r).unwrap();
        let parsed: AuthorityRef = serde_json::from_str(&s).unwrap();
        assert_eq!(r.ref_type, parsed.ref_type);
        assert_eq!(r.grant_id, parsed.grant_id);
        assert_eq!(
            r.capability_required.name(),
            parsed.capability_required.name()
        );
    }
}
