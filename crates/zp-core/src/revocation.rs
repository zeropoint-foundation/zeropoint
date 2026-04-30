//! Revocation claims — explicit, signed grant terminations (#197).
//!
//! A `RevocationClaim` is the inverse of a grant: it ends a delegation
//! permanently, identifies the cascade behaviour, and is signed by an
//! authority listed on the original grant's `revocable_by` field. Once a
//! revocation lands on the chain, no further `delegation:renewed:*`
//! receipts may extend the target grant's lease — expiry and revocation
//! are equally terminal.
//!
//! This is distinct from `zp_core::receipt_emission::emit_revocation_receipt`,
//! which mints the typed `RevocationClaim` *receipt* (the canonical record
//! that lands on the chain). The `RevocationClaim` here is the in-memory
//! struct that callers build and sign before that receipt is emitted.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::{Deserialize, Serialize};

use crate::authority_ref::AuthorityRef;

/// An in-memory revocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationClaim {
    /// Unique claim identifier, prefixed `revoke-`.
    pub revocation_id: String,

    /// The grant being revoked.
    pub target_grant_id: String,

    /// What happens to grants delegated from the target.
    pub cascade: CascadePolicy,

    /// Hex-encoded Ed25519 public key of the issuing principal.
    pub issued_by: String,

    /// The authority reference proving the issuer has revocation rights.
    pub authority_ref: AuthorityRef,

    /// Grant ids walked to reach the target. Empty for direct revocations.
    /// Used by validators to confirm the issuer's authority transitively
    /// without re-walking the chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_chain: Vec<String>,

    /// Why the grant is being revoked.
    pub reason: RevocationReason,

    pub issued_at: DateTime<Utc>,

    /// Optional anchor commitment id. When the truth anchor backend is
    /// configured (HCS), this is the HCS message id of the revocation
    /// announcement. None until the anchor client ships.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_commitment: Option<String>,

    /// Hex-encoded Ed25519 signature over `canonical_bytes()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// What happens to grants delegated from a revoked grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CascadePolicy {
    /// Only the named grant is revoked. Children remain valid until their
    /// own expiry. Useful when the target grant was specifically compromised
    /// but downstream re-delegations were independent.
    GrantOnly,

    /// The grant and every grant in its subtree are revoked simultaneously.
    /// Default — the conservative choice.
    SubtreeHalt,

    /// The grant is revoked but children are re-rooted under the issuer
    /// (i.e., the revoker becomes their new parent). Reserved for orderly
    /// device hand-off; not yet implemented in the validator.
    SubtreeReroot,
}

impl Default for CascadePolicy {
    fn default() -> Self {
        CascadePolicy::SubtreeHalt
    }
}

/// Why a grant is being revoked. Surfaced in receipts for operator review
/// and shows up in `zp grants` output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Operator pressed the kill switch.
    OperatorRequested,

    /// The lease was not renewed in time. Emitted automatically by the
    /// expiry sweep, not by the operator.
    LeaseExpired,

    /// Compromise was detected (key loss, anomalous behaviour, mesh alert).
    CompromiseDetected,

    /// The grant violated a constitutional policy.
    PolicyViolation,

    /// A new grant supersedes this one. The replacement's id is recorded
    /// so verifiers can trace the handoff.
    Superseded {
        new_grant_id: String,
    },
}

impl RevocationClaim {
    /// Construct an unsigned revocation claim. Caller is expected to call
    /// [`Self::sign`] before submitting.
    pub fn new(
        target_grant_id: impl Into<String>,
        issued_by: impl Into<String>,
        authority_ref: AuthorityRef,
        cascade: CascadePolicy,
        reason: RevocationReason,
    ) -> Self {
        Self {
            revocation_id: format!("revoke-{}", uuid::Uuid::now_v7()),
            target_grant_id: target_grant_id.into(),
            cascade,
            issued_by: issued_by.into(),
            authority_ref,
            authority_chain: Vec::new(),
            reason,
            issued_at: Utc::now(),
            anchor_commitment: None,
            signature: None,
        }
    }

    /// Bytes covered by the signature: every field except `signature` itself.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let canonical = CanonicalForm {
            revocation_id: self.revocation_id.clone(),
            target_grant_id: self.target_grant_id.clone(),
            cascade: self.cascade,
            issued_by: self.issued_by.clone(),
            authority_ref: self.authority_ref.clone(),
            authority_chain: self.authority_chain.clone(),
            reason: self.reason.clone(),
            issued_at: self.issued_at,
            anchor_commitment: self.anchor_commitment.clone(),
        };
        serde_json::to_vec(&canonical).unwrap_or_default()
    }

    /// Sign this revocation claim with `signing_key`. The hex-encoded
    /// signature is stored on `self.signature`.
    pub fn sign(&mut self, signing_key: &SigningKey) {
        let canonical = self.canonical_bytes();
        let sig = signing_key.sign(&canonical);
        self.signature = Some(hex::encode(sig.to_bytes()));
    }

    /// Verify the signature against `self.issued_by` (the public key recorded
    /// at construction). Returns `false` if no signature is present, the
    /// public key is malformed, or the signature does not verify.
    pub fn verify_signature(&self) -> bool {
        let Some(sig_hex) = &self.signature else {
            return false;
        };
        let Ok(pubkey_bytes) = hex::decode(&self.issued_by) else {
            return false;
        };
        if pubkey_bytes.len() != 32 {
            return false;
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&pubkey_bytes);
        let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&key_arr) else {
            return false;
        };

        let Ok(sig_bytes) = hex::decode(sig_hex) else {
            return false;
        };
        if sig_bytes.len() != 64 {
            return false;
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        verifying
            .verify_strict(&self.canonical_bytes(), &signature)
            .is_ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct CanonicalForm {
    revocation_id: String,
    target_grant_id: String,
    cascade: CascadePolicy,
    issued_by: String,
    authority_ref: AuthorityRef,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    authority_chain: Vec<String>,
    reason: RevocationReason,
    issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_commitment: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;

    fn signing_key() -> SigningKey {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn cascade_default_is_subtree_halt() {
        assert_eq!(CascadePolicy::default(), CascadePolicy::SubtreeHalt);
    }

    #[test]
    fn revocation_id_is_prefixed() {
        let claim = RevocationClaim::new(
            "grant-target",
            "deadbeef",
            AuthorityRef::genesis("revocation_authority"),
            CascadePolicy::default(),
            RevocationReason::OperatorRequested,
        );
        assert!(claim.revocation_id.starts_with("revoke-"));
    }

    #[test]
    fn signature_round_trip_verifies() {
        let key = signing_key();
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());

        let mut claim = RevocationClaim::new(
            "grant-target",
            &pubkey_hex,
            AuthorityRef::genesis("revocation_authority"),
            CascadePolicy::SubtreeHalt,
            RevocationReason::OperatorRequested,
        );
        assert!(!claim.verify_signature(), "unsigned claim should not verify");

        claim.sign(&key);
        assert!(claim.verify_signature(), "freshly-signed claim must verify");

        // Tamper with target grant id — signature must fail.
        claim.target_grant_id.push('X');
        assert!(
            !claim.verify_signature(),
            "tampered claim must not verify"
        );
    }

    #[test]
    fn superseded_reason_carries_replacement_id() {
        let claim = RevocationClaim::new(
            "grant-old",
            "deadbeef",
            AuthorityRef::genesis("revocation_authority"),
            CascadePolicy::GrantOnly,
            RevocationReason::Superseded {
                new_grant_id: "grant-new".to_string(),
            },
        );
        let json = serde_json::to_string(&claim).unwrap();
        assert!(json.contains("grant-new"), "{}", json);
    }
}
