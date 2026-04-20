//! Typed receipt emission helpers (C3-3 wiring).
//!
//! Provides functions to generate correctly-typed receipts for
//! governance actions that previously emitted no receipts:
//!
//! - `emit_authorization_receipt` — for capability grant issuance
//! - `emit_delegation_receipt` — for key delegation/rotation certificates
//! - `emit_revocation_receipt` — for revoking old keys/grants
//!
//! Each helper sets the correct ReceiptType, ClaimSemantics, and
//! ClaimMetadata as required by the C3-1 validation rules.

use zp_receipt::{ClaimMetadata, ClaimSemantics, Receipt, Status};

/// Emit an AuthorizationClaim receipt when a capability grant is issued.
///
/// Required semantics: `AuthorizationGrant`
pub fn emit_authorization_receipt(
    grantor_id: &str,
    scope: &str,
) -> Receipt {
    Receipt::authorization(grantor_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorizationGrant)
        .claim_metadata(ClaimMetadata::Authorization {
            scope: scope.to_string(),
            grantor_id: grantor_id.to_string(),
            constraints: Default::default(),
        })
        .finalize()
}

/// Emit a DelegationClaim receipt when a key rotation certificate is issued.
///
/// Required semantics: `AuthorizationGrant`
pub fn emit_delegation_receipt(
    delegator_key: &str,
    delegate_key: &str,
    capability_scope: &str,
    rotation_cert_id: &str,
) -> Receipt {
    Receipt::delegation(delegator_key)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorizationGrant)
        .claim_metadata(ClaimMetadata::Delegation {
            capability_id: capability_scope.to_string(),
            delegator_id: delegator_key.to_string(),
            delegate_id: delegate_key.to_string(),
            max_depth: 0,
        })
        .parent(rotation_cert_id)
        .finalize()
}

/// Emit a RevocationClaim receipt when an old key or grant is revoked.
///
/// Required semantics: `IntegrityAttestation`
pub fn emit_revocation_receipt(
    revoker_id: &str,
    revoked_receipt_id: &str,
    reason: &str,
) -> Receipt {
    Receipt::revocation(revoker_id)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::IntegrityAttestation)
        .claim_metadata(ClaimMetadata::Revocation {
            revoked_receipt_id: revoked_receipt_id.to_string(),
            reason: reason.to_string(),
            revoker_id: revoker_id.to_string(),
        })
        .revokes_receipt(revoked_receipt_id)
        .finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zp_receipt::ReceiptType;

    #[test]
    fn authorization_receipt_has_correct_type_and_semantics() {
        let r = emit_authorization_receipt("operator-key-abc", "tool:launch:docker");
        assert_eq!(r.receipt_type, ReceiptType::AuthorizationClaim);
        assert_eq!(r.claim_semantics, ClaimSemantics::AuthorizationGrant);
        assert!(r.id.starts_with("auth-"));
        assert!(r.verify_hash());
    }

    #[test]
    fn delegation_receipt_has_correct_type_and_semantics() {
        let r = emit_delegation_receipt(
            "old-operator-key",
            "new-operator-key",
            "key_rotation:operator",
            "rotate-001",
        );
        assert_eq!(r.receipt_type, ReceiptType::DelegationClaim);
        assert_eq!(r.claim_semantics, ClaimSemantics::AuthorizationGrant);
        assert!(r.id.starts_with("dlgt-"));
        assert_eq!(r.parent_receipt_id.as_deref(), Some("rotate-001"));
        assert!(r.verify_hash());
    }

    #[test]
    fn revocation_receipt_has_correct_type_and_semantics() {
        let r = emit_revocation_receipt(
            "operator-key",
            "old-key-receipt-id",
            "key_rotation",
        );
        assert_eq!(r.receipt_type, ReceiptType::RevocationClaim);
        assert_eq!(r.claim_semantics, ClaimSemantics::IntegrityAttestation);
        assert!(r.id.starts_with("revk-"));
        assert!(r.revokes.contains(&"old-key-receipt-id".to_string()));
        assert!(r.verify_hash());
    }

    #[test]
    fn authorization_receipt_carries_metadata() {
        let r = emit_authorization_receipt("operator", "execute:docker");
        match &r.claim_metadata {
            Some(ClaimMetadata::Authorization { scope, grantor_id, .. }) => {
                assert_eq!(scope, "execute:docker");
                assert_eq!(grantor_id, "operator");
            }
            _ => panic!("Expected Authorization metadata"),
        }
    }

    #[test]
    fn delegation_receipt_carries_metadata() {
        let r = emit_delegation_receipt("old-key", "new-key", "signing:operator", "cert-1");
        match &r.claim_metadata {
            Some(ClaimMetadata::Delegation { delegator_id, delegate_id, capability_id, .. }) => {
                assert_eq!(delegator_id, "old-key");
                assert_eq!(delegate_id, "new-key");
                assert_eq!(capability_id, "signing:operator");
            }
            _ => panic!("Expected Delegation metadata"),
        }
    }

    #[test]
    fn revocation_receipt_carries_metadata() {
        let r = emit_revocation_receipt("revoker", "rcpt-old", "compromised");
        match &r.claim_metadata {
            Some(ClaimMetadata::Revocation { revoked_receipt_id, reason, revoker_id }) => {
                assert_eq!(revoked_receipt_id, "rcpt-old");
                assert_eq!(reason, "compromised");
                assert_eq!(revoker_id, "revoker");
            }
            _ => panic!("Expected Revocation metadata"),
        }
    }
}
