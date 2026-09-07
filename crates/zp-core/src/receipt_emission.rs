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

use crate::capability_grant::CapabilityGrant;
use crate::receipt_extensions as ext;

/// Emit an AuthorizationClaim receipt when a capability grant is issued.
///
/// Required semantics: `AuthorizationGrant`
pub fn emit_authorization_receipt(grantor_id: &str, scope: &str) -> Receipt {
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

/// Build the `DelegationClaim` receipt for an issued [`CapabilityGrant`].
///
/// This is the *shared* half of a contract that used to be two unrelated string
/// literals: the producer (Regent startup delegation, `zp-server`) writes these
/// extension keys, and `zp_audit::RecoveryEngine` reads them to rebuild
/// in-flight grants after a restart. Neither crate references the other, so
/// before this function existed the only thing keeping them in agreement was
/// that both had been typed correctly — and they had not: no producer attached
/// a receipt at all, so recovery read nothing and called it success.
///
/// Callers must use this rather than assembling the receipt inline. The
/// round-trip test in `zp-audit` exercises *this* function against the real
/// `RecoveryEngine`, so a producer that bypasses it is untested by construction.
///
/// Not signed here. `AuditStore::append` signs the entry and the entry hash
/// covers the receipt, so this claim is tamper-evident within the chain. A
/// receipt intended to travel off the machine needs its own signature — see
/// `docs/design/CHANNEL-BOUNDARY-2026-08.md`.
pub fn capability_grant_receipt(grant: &CapabilityGrant, scope: &str) -> Receipt {
    Receipt::delegation(&grant.grantor)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorizationGrant)
        .claim_metadata(ClaimMetadata::Delegation {
            capability_id: grant.id.clone(),
            delegator_id: grant.grantor.clone(),
            delegate_id: grant.grantee.clone(),
            max_depth: 0,
        })
        .extension(ext::CAPABILITY_GRANT_ID, serde_json::json!(grant.id))
        .extension(ext::CAPABILITY_SCOPE, serde_json::json!(scope))
        .extension(ext::CAPABILITY_GRANTEE, serde_json::json!(grant.grantee))
        .finalize()
}

/// Build the delegation + revocation receipt pair for a key rotation.
///
/// Shared for the same reason as [`capability_grant_receipt`]: `zp-keys` writes
/// these extensions and `zp_audit::reconstitute` reads them, and the two crates
/// never reference each other. Before this existed, `rotation.rs` built both
/// receipts inline and set **no extensions at all**, so key-lifecycle
/// reconstitution had nothing to read — `valid_operator_keys` and
/// `valid_agent_keys` could never be rebuilt from the chain.
///
/// `role` must be one of [`ext::ROLE_OPERATOR`], [`ext::ROLE_AGENT`] or
/// [`ext::ROLE_GENESIS`]. Do not pass a serialised `KeyRole`: serde emits
/// capitalised variant names, `reconstitute` matches lowercase, and the
/// mismatch is silent on both sides. Callers map their enum explicitly.
///
/// Returns `(delegation, revocation)`. The delegation receipt is parented to
/// the certificate id; the revocation attests that the old key is retired.
pub fn certificate_rotation_receipts(
    old_public_key: &str,
    new_public_key: &str,
    role: &str,
    certificate_id: &str,
) -> (Receipt, Receipt) {
    debug_assert!(
        role == ext::ROLE_OPERATOR || role == ext::ROLE_AGENT || role == ext::ROLE_GENESIS,
        "role must come from the receipt_extensions vocabulary, got {role:?}"
    );

    let delegation = Receipt::delegation(old_public_key)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::AuthorizationGrant)
        .claim_metadata(ClaimMetadata::Delegation {
            capability_id: format!("signing:{role}"),
            delegator_id: old_public_key.to_string(),
            delegate_id: new_public_key.to_string(),
            max_depth: 0,
        })
        .parent(certificate_id)
        .extension(
            ext::CERTIFICATE_PUBLIC_KEY,
            serde_json::json!(new_public_key),
        )
        .extension(ext::CERTIFICATE_ROLE, serde_json::json!(role))
        .finalize();

    let revocation = Receipt::revocation(old_public_key)
        .status(Status::Success)
        .claim_semantics(ClaimSemantics::IntegrityAttestation)
        .claim_metadata(ClaimMetadata::Revocation {
            revoked_receipt_id: old_public_key.to_string(),
            reason: "key_rotation".to_string(),
            revoker_id: old_public_key.to_string(),
        })
        .extension(
            ext::REVOCATION_REVOKED_KEY,
            serde_json::json!(old_public_key),
        )
        .finalize();

    (delegation, revocation)
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
        let r = emit_revocation_receipt("operator-key", "old-key-receipt-id", "key_rotation");
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
            Some(ClaimMetadata::Authorization {
                scope, grantor_id, ..
            }) => {
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
            Some(ClaimMetadata::Delegation {
                delegator_id,
                delegate_id,
                capability_id,
                ..
            }) => {
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
            Some(ClaimMetadata::Revocation {
                revoked_receipt_id,
                reason,
                revoker_id,
            }) => {
                assert_eq!(revoked_receipt_id, "rcpt-old");
                assert_eq!(reason, "compromised");
                assert_eq!(revoker_id, "revoker");
            }
            _ => panic!("Expected Revocation metadata"),
        }
    }
}
