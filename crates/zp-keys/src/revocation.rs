//! Key revocation — signed certificates that invalidate previously issued keys.
//!
//! Phase 5.1: Implements the doctrine's compromise response for key revocation.
//!
//! A revocation certificate says: "I (the parent) revoke this child key."
//! The parent signs the revocation with their private key:
//!   - Genesis revokes operator keys
//!   - Operator revokes agent keys
//!
//! **Cascade rule:** Revoking an operator key invalidates all agent keys it signed.
//! The revocation store checks the full chain, not just the leaf.
//!
//! **Receipt preservation:** Existing receipts signed before revocation remain
//! verifiable, but with a `key-revoked-after-signing` annotation. Revocation
//! is prospective — it blocks new signatures, not retroactive truth.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::certificate::{Certificate, KeyRole};
use crate::error::KeyError;

// ============================================================================
// Revocation reason
// ============================================================================

/// Why a key is being revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Key material may have been exposed to an unauthorized party.
    Compromise,
    /// The key holder's role or authorization has been withdrawn.
    Superseded,
    /// The operator or agent is being decommissioned.
    CessationOfOperation,
    /// Administrative revocation — no specific technical cause.
    Administrative,
}

impl std::fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationReason::Compromise => write!(f, "compromise"),
            RevocationReason::Superseded => write!(f, "superseded"),
            RevocationReason::CessationOfOperation => write!(f, "cessation_of_operation"),
            RevocationReason::Administrative => write!(f, "administrative"),
        }
    }
}

// ============================================================================
// Revocation certificate
// ============================================================================

/// The signable body of a revocation certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationBody {
    /// Unique revocation certificate identifier.
    pub id: String,
    /// The certificate ID being revoked.
    pub revoked_cert_id: String,
    /// The public key being revoked (hex-encoded Ed25519).
    pub revoked_public_key: String,
    /// The role of the key being revoked.
    pub revoked_role: KeyRole,
    /// Why the key is being revoked.
    pub reason: RevocationReason,
    /// The revoker's public key (hex-encoded Ed25519).
    /// Must be the parent of the revoked key in the hierarchy.
    pub revoker_public_key: String,
    /// When this revocation was issued.
    pub revoked_at: DateTime<Utc>,
    /// Optional human-readable explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
}

/// A signed revocation certificate — a `RevocationBody` plus its Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationCertificate {
    /// The revocation body (what is signed).
    pub body: RevocationBody,
    /// Ed25519 signature over the canonical JSON of `body`, hex-encoded.
    pub signature: String,
}

impl RevocationCertificate {
    /// Create and sign a revocation certificate.
    ///
    /// The `revoker_signing_key` must belong to the parent of the revoked key:
    /// - Genesis key revokes operator keys
    /// - Operator key revokes agent keys
    pub fn issue(
        revoked_cert: &Certificate,
        reason: RevocationReason,
        revoker_signing_key: &SigningKey,
        revoker_role: KeyRole,
        explanation: Option<String>,
    ) -> Result<Self, KeyError> {
        // Validate that the revoker has authority over the revoked key.
        if !revoker_role.can_sign(revoked_cert.body.role) {
            return Err(KeyError::RoleMismatch {
                expected: format!("parent of {}", revoked_cert.body.role),
                found: revoker_role.to_string(),
            });
        }

        // Validate that the revoker's public key matches the cert's issuer.
        let revoker_pub = hex::encode(revoker_signing_key.verifying_key().to_bytes());
        if revoker_pub != revoked_cert.body.issuer_public_key {
            return Err(KeyError::BrokenChain {
                depth: revoked_cert.body.depth,
                reason: "revoker public key does not match certificate issuer".into(),
            });
        }

        let body = RevocationBody {
            id: format!("revoke-{}", uuid::Uuid::now_v7()),
            revoked_cert_id: revoked_cert.body.id.clone(),
            revoked_public_key: revoked_cert.body.public_key.clone(),
            revoked_role: revoked_cert.body.role,
            reason,
            revoker_public_key: revoker_pub,
            revoked_at: Utc::now(),
            explanation,
        };

        let canonical =
            serde_json::to_vec(&body).map_err(|e| KeyError::Serialization(e.to_string()))?;
        let sig = revoker_signing_key.sign(&canonical);

        info!(
            revoked_cert_id = %body.revoked_cert_id,
            revoked_key = %body.revoked_public_key,
            reason = %body.reason,
            "Revocation certificate issued"
        );

        Ok(RevocationCertificate {
            body,
            signature: hex::encode(sig.to_bytes()),
        })
    }

    /// Verify this revocation certificate's signature.
    pub fn verify_signature(&self) -> Result<bool, KeyError> {
        let revoker_bytes = hex::decode(&self.body.revoker_public_key)
            .map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;

        if revoker_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "revoker public key must be 32 bytes".into(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&revoker_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;

        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| KeyError::InvalidSignature(e.to_string()))?;

        if sig_bytes.len() != 64 {
            return Err(KeyError::InvalidSignature(
                "signature must be 64 bytes".into(),
            ));
        }

        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

        let canonical =
            serde_json::to_vec(&self.body).map_err(|e| KeyError::Serialization(e.to_string()))?;

        Ok(verifying_key.verify_strict(&canonical, &signature).is_ok())
    }

    /// Compute the Blake3 hash of this revocation certificate.
    pub fn content_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("revocation cert must serialize");
        blake3::hash(&canonical).to_hex().to_string()
    }
}

// ============================================================================
// Revocation store
// ============================================================================

/// Result of checking a key's revocation status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The key is not revoked — it can sign new receipts.
    Valid,
    /// The key itself has been directly revoked.
    Revoked {
        reason: RevocationReason,
        revoked_at: DateTime<Utc>,
    },
    /// The key's parent (operator) was revoked — cascade invalidation.
    /// The key itself wasn't directly revoked, but its trust chain is broken.
    ParentRevoked {
        revoked_parent_key: String,
        reason: RevocationReason,
        revoked_at: DateTime<Utc>,
    },
}

impl RevocationStatus {
    /// Whether this key is allowed to sign new receipts.
    pub fn is_valid(&self) -> bool {
        matches!(self, RevocationStatus::Valid)
    }

    /// Whether a receipt signed by this key before revocation should carry
    /// a `key-revoked-after-signing` annotation.
    pub fn needs_annotation(&self, receipt_signed_at: DateTime<Utc>) -> bool {
        match self {
            RevocationStatus::Valid => false,
            RevocationStatus::Revoked { revoked_at, .. } => receipt_signed_at < *revoked_at,
            RevocationStatus::ParentRevoked { revoked_at, .. } => receipt_signed_at < *revoked_at,
        }
    }
}

/// In-memory revocation store.
///
/// Tracks revoked keys and supports cascade checks. In production, this
/// would be backed by the mesh distribution layer (Phase 5 roadmap).
#[derive(Debug, Default)]
pub struct RevocationStore {
    /// Direct revocations: revoked public key (hex) → revocation certificate.
    revocations: HashMap<String, RevocationCertificate>,
    /// Cascade index: operator public key (hex) → agent public keys it signed.
    /// Used to efficiently check if an agent's parent operator was revoked.
    operator_agents: HashMap<String, Vec<String>>,
}

impl RevocationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a revocation certificate after verifying its signature.
    pub fn register(&mut self, cert: RevocationCertificate) -> Result<(), KeyError> {
        // Verify the revocation signature.
        if !cert.verify_signature()? {
            return Err(KeyError::InvalidSignature(
                "revocation certificate signature invalid".into(),
            ));
        }

        let revoked_key = cert.body.revoked_public_key.clone();

        info!(
            revoked_key = %revoked_key,
            reason = %cert.body.reason,
            "Revocation registered"
        );

        self.revocations.insert(revoked_key, cert);
        Ok(())
    }

    /// Register a parent→child relationship for cascade tracking.
    ///
    /// Call this when an operator signs an agent certificate so the store
    /// knows which agents to invalidate if the operator is revoked.
    pub fn register_delegation(&mut self, operator_public_key: &str, agent_public_key: &str) {
        self.operator_agents
            .entry(operator_public_key.to_string())
            .or_default()
            .push(agent_public_key.to_string());
    }

    /// Check the revocation status of a public key (hex-encoded).
    ///
    /// Checks both direct revocation and cascade (parent revoked).
    pub fn check(&self, public_key: &str) -> RevocationStatus {
        // Direct revocation check.
        if let Some(cert) = self.revocations.get(public_key) {
            return RevocationStatus::Revoked {
                reason: cert.body.reason,
                revoked_at: cert.body.revoked_at,
            };
        }

        // Cascade check: is this key's operator revoked?
        // Walk all revoked operator keys and check if this agent is in their list.
        for (operator_key, agents) in &self.operator_agents {
            if agents.contains(&public_key.to_string()) {
                if let Some(operator_revocation) = self.revocations.get(operator_key) {
                    return RevocationStatus::ParentRevoked {
                        revoked_parent_key: operator_key.clone(),
                        reason: operator_revocation.body.reason,
                        revoked_at: operator_revocation.body.revoked_at,
                    };
                }
            }
        }

        RevocationStatus::Valid
    }

    /// Get all agent keys that are cascade-invalidated by an operator revocation.
    pub fn cascade_revoked_agents(&self, operator_public_key: &str) -> Vec<String> {
        if self.revocations.contains_key(operator_public_key) {
            self.operator_agents
                .get(operator_public_key)
                .cloned()
                .unwrap_or_default()
        } else {
            vec![]
        }
    }

    /// Total number of direct revocations registered.
    pub fn revocation_count(&self) -> usize {
        self.revocations.len()
    }

    /// Check if a specific certificate ID has been revoked.
    pub fn is_cert_revoked(&self, cert_id: &str) -> bool {
        self.revocations
            .values()
            .any(|r| r.body.revoked_cert_id == cert_id)
    }
}

// ============================================================================
// Integration with CertificateChain verification
// ============================================================================

/// Verify a certificate chain with revocation checking.
///
/// This extends `CertificateChain::verify()` with revocation status checks
/// for every certificate in the chain. If any key in the chain has been
/// revoked, verification fails.
pub fn verify_chain_with_revocation(
    certificates: &[Certificate],
    store: &RevocationStore,
) -> Result<(), KeyError> {
    for cert in certificates {
        match store.check(&cert.body.public_key) {
            RevocationStatus::Valid => {}
            RevocationStatus::Revoked { reason, .. } => {
                return Err(KeyError::BrokenChain {
                    depth: cert.body.depth,
                    reason: format!("key {} revoked (reason: {})", cert.body.subject, reason),
                });
            }
            RevocationStatus::ParentRevoked {
                revoked_parent_key,
                reason,
                ..
            } => {
                warn!(
                    subject = %cert.body.subject,
                    parent_key = %revoked_parent_key,
                    "Certificate invalidated by parent key revocation"
                );
                return Err(KeyError::BrokenChain {
                    depth: cert.body.depth,
                    reason: format!(
                        "key {} invalidated by parent revocation (reason: {})",
                        cert.body.subject, reason
                    ),
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{Certificate, KeyRole};
    use rand::rngs::OsRng;

    fn gen_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn setup_chain() -> (
        SigningKey,
        SigningKey,
        SigningKey,
        Certificate,
        Certificate,
        Certificate,
    ) {
        let genesis_key = gen_key();
        let operator_key = gen_key();
        let agent_key = gen_key();

        let genesis_pub = genesis_key.verifying_key().to_bytes();
        let operator_pub = operator_key.verifying_key().to_bytes();
        let agent_pub = agent_key.verifying_key().to_bytes();

        let genesis_cert = Certificate::issue(
            "genesis".into(),
            KeyRole::Genesis,
            &genesis_pub,
            &genesis_key,
            None,
            None,
        );

        let operator_cert = Certificate::issue(
            "operator-alpha".into(),
            KeyRole::Operator,
            &operator_pub,
            &genesis_key,
            Some(genesis_cert.content_hash()),
            None,
        );

        let agent_cert = Certificate::issue(
            "agent-001".into(),
            KeyRole::Agent,
            &agent_pub,
            &operator_key,
            Some(operator_cert.content_hash()),
            None,
        );

        (
            genesis_key,
            operator_key,
            agent_key,
            genesis_cert,
            operator_cert,
            agent_cert,
        )
    }

    #[test]
    fn revoke_agent_key() {
        let (_, operator_key, _, _, _, agent_cert) = setup_chain();

        let revocation = RevocationCertificate::issue(
            &agent_cert,
            RevocationReason::Compromise,
            &operator_key,
            KeyRole::Operator,
            Some("Agent key compromised during incident response".into()),
        )
        .unwrap();

        assert!(revocation.verify_signature().unwrap());
        assert_eq!(revocation.body.revoked_role, KeyRole::Agent);
        assert_eq!(revocation.body.reason, RevocationReason::Compromise);
    }

    #[test]
    fn revoke_operator_key() {
        let (genesis_key, _, _, _, operator_cert, _) = setup_chain();

        let revocation = RevocationCertificate::issue(
            &operator_cert,
            RevocationReason::CessationOfOperation,
            &genesis_key,
            KeyRole::Genesis,
            None,
        )
        .unwrap();

        assert!(revocation.verify_signature().unwrap());
        assert_eq!(revocation.body.revoked_role, KeyRole::Operator);
    }

    #[test]
    fn wrong_revoker_role_rejected() {
        let (_, _, agent_key, _, _, agent_cert) = setup_chain();

        // Agent cannot revoke another agent.
        let result = RevocationCertificate::issue(
            &agent_cert,
            RevocationReason::Administrative,
            &agent_key,
            KeyRole::Agent,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::RoleMismatch { .. }));
    }

    #[test]
    fn wrong_issuer_key_rejected() {
        let (_, _, _, _, _, agent_cert) = setup_chain();

        // A different operator (not the one who signed the agent cert) tries to revoke.
        let rogue_operator = gen_key();
        let result = RevocationCertificate::issue(
            &agent_cert,
            RevocationReason::Compromise,
            &rogue_operator,
            KeyRole::Operator,
            None,
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::BrokenChain { .. }));
    }

    #[test]
    fn store_direct_revocation() {
        let (_, operator_key, _, _, _, agent_cert) = setup_chain();

        let revocation = RevocationCertificate::issue(
            &agent_cert,
            RevocationReason::Compromise,
            &operator_key,
            KeyRole::Operator,
            None,
        )
        .unwrap();

        let mut store = RevocationStore::new();
        store.register(revocation).unwrap();

        let status = store.check(&agent_cert.body.public_key);
        assert!(matches!(
            status,
            RevocationStatus::Revoked {
                reason: RevocationReason::Compromise,
                ..
            }
        ));
        assert!(!status.is_valid());
    }

    #[test]
    fn store_cascade_revocation() {
        let (genesis_key, _, _, _, operator_cert, agent_cert) = setup_chain();

        // Register the operator→agent relationship.
        let mut store = RevocationStore::new();
        store.register_delegation(&operator_cert.body.public_key, &agent_cert.body.public_key);

        // Revoke the operator.
        let revocation = RevocationCertificate::issue(
            &operator_cert,
            RevocationReason::Compromise,
            &genesis_key,
            KeyRole::Genesis,
            None,
        )
        .unwrap();
        store.register(revocation).unwrap();

        // Operator is directly revoked.
        let op_status = store.check(&operator_cert.body.public_key);
        assert!(matches!(op_status, RevocationStatus::Revoked { .. }));

        // Agent is cascade-revoked.
        let agent_status = store.check(&agent_cert.body.public_key);
        assert!(matches!(
            agent_status,
            RevocationStatus::ParentRevoked { .. }
        ));
        assert!(!agent_status.is_valid());

        // Cascade list includes the agent.
        let cascaded = store.cascade_revoked_agents(&operator_cert.body.public_key);
        assert_eq!(cascaded.len(), 1);
        assert_eq!(cascaded[0], agent_cert.body.public_key);
    }

    #[test]
    fn receipt_annotation_logic() {
        let now = Utc::now();
        let before_revocation = now - chrono::Duration::hours(1);

        let status = RevocationStatus::Revoked {
            reason: RevocationReason::Compromise,
            revoked_at: now,
        };

        // Receipt signed before revocation should be annotated (still valid, but flagged).
        assert!(status.needs_annotation(before_revocation));

        // Receipt signed after revocation should NOT be annotated (it's just invalid).
        let after_revocation = now + chrono::Duration::hours(1);
        assert!(!status.needs_annotation(after_revocation));
    }

    #[test]
    fn verify_chain_with_revocation_blocks_revoked() {
        let (genesis_key, _, _, genesis_cert, operator_cert, agent_cert) = setup_chain();

        let mut store = RevocationStore::new();

        // Chain is valid before any revocation.
        let certs = vec![
            genesis_cert.clone(),
            operator_cert.clone(),
            agent_cert.clone(),
        ];
        assert!(verify_chain_with_revocation(&certs, &store).is_ok());

        // Revoke the operator.
        let revocation = RevocationCertificate::issue(
            &operator_cert,
            RevocationReason::Superseded,
            &genesis_key,
            KeyRole::Genesis,
            None,
        )
        .unwrap();
        store.register(revocation).unwrap();

        // Chain verification now fails at the operator.
        let result = verify_chain_with_revocation(&certs, &store);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_revocation_rejected() {
        let (_, operator_key, _, _, _, agent_cert) = setup_chain();

        let mut revocation = RevocationCertificate::issue(
            &agent_cert,
            RevocationReason::Compromise,
            &operator_key,
            KeyRole::Operator,
            None,
        )
        .unwrap();

        // Tamper with the reason.
        revocation.body.reason = RevocationReason::Administrative;

        // Signature should now be invalid.
        let mut store = RevocationStore::new();
        let result = store.register(revocation);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::InvalidSignature(_)));
    }

    #[test]
    fn cert_id_lookup() {
        let (_, operator_key, _, _, _, agent_cert) = setup_chain();

        let revocation = RevocationCertificate::issue(
            &agent_cert,
            RevocationReason::Administrative,
            &operator_key,
            KeyRole::Operator,
            None,
        )
        .unwrap();

        let mut store = RevocationStore::new();
        store.register(revocation).unwrap();

        assert!(store.is_cert_revoked(&agent_cert.body.id));
        assert!(!store.is_cert_revoked("nonexistent-cert-id"));
    }

    #[test]
    fn unrevoked_key_is_valid() {
        let store = RevocationStore::new();
        let status = store.check("some-random-hex-key");
        assert_eq!(status, RevocationStatus::Valid);
        assert!(status.is_valid());
    }
}
