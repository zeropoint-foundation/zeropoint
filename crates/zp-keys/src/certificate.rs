//! Certificates — signed attestations that bind a public key to a role.
//!
//! A certificate says: "I (the issuer) attest that this public key belongs to
//! this subject, with this role, valid until this time." The issuer signs the
//! certificate body with their private key, and anyone with the issuer's public
//! key can verify it.
//!
//! Certificates are the links in the trust chain. A genesis key signs operator
//! certificates, operators sign agent certificates.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::KeyError;

/// The role a key plays in the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyRole {
    /// Root of trust — self-signed, one per deployment.
    Genesis,
    /// Node operator — signed by genesis.
    Operator,
    /// Agent instance — signed by operator.
    Agent,
}

impl KeyRole {
    /// Expected depth in the certificate chain.
    pub fn expected_depth(&self) -> u8 {
        match self {
            KeyRole::Genesis => 0,
            KeyRole::Operator => 1,
            KeyRole::Agent => 2,
        }
    }

    /// Can this role sign certificates for the given child role?
    pub fn can_sign(&self, child: KeyRole) -> bool {
        matches!(
            (self, child),
            (KeyRole::Genesis, KeyRole::Operator) | (KeyRole::Operator, KeyRole::Agent)
        )
    }
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRole::Genesis => write!(f, "genesis"),
            KeyRole::Operator => write!(f, "operator"),
            KeyRole::Agent => write!(f, "agent"),
        }
    }
}

/// The signable body of a certificate (everything except the signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateBody {
    /// Unique certificate identifier.
    pub id: String,
    /// Human-readable subject name (e.g., operator name, agent ID).
    pub subject: String,
    /// The role this key plays in the hierarchy.
    pub role: KeyRole,
    /// The subject's Ed25519 public key (32 bytes, hex-encoded).
    pub public_key: String,
    /// The issuer's Ed25519 public key (32 bytes, hex-encoded).
    /// For genesis certificates, this equals `public_key` (self-signed).
    pub issuer_public_key: String,
    /// When this certificate was issued.
    pub issued_at: DateTime<Utc>,
    /// When this certificate expires (None = no expiration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Depth in the hierarchy (0 = genesis, 1 = operator, 2 = agent).
    pub depth: u8,
    /// Blake3 hash of the issuer's certificate (None for genesis).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_cert_hash: Option<String>,
}

/// A signed certificate — a `CertificateBody` plus its Ed25519 signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    /// The certificate body (what is signed).
    pub body: CertificateBody,
    /// Ed25519 signature over the canonical JSON of `body`, hex-encoded.
    pub signature: String,
}

impl Certificate {
    /// Create and sign a certificate.
    pub fn issue(
        subject: String,
        role: KeyRole,
        subject_public_key: &[u8; 32],
        issuer_signing_key: &SigningKey,
        issuer_cert_hash: Option<String>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let issuer_public_key = issuer_signing_key.verifying_key().to_bytes();

        let body = CertificateBody {
            id: format!("cert-{}", uuid::Uuid::now_v7()),
            subject,
            role,
            public_key: hex::encode(subject_public_key),
            issuer_public_key: hex::encode(issuer_public_key),
            issued_at: Utc::now(),
            expires_at,
            depth: role.expected_depth(),
            issuer_cert_hash,
        };

        let canonical = serde_json::to_vec(&body).expect("certificate body must serialize");
        let sig = issuer_signing_key.sign(&canonical);

        Certificate {
            body,
            signature: hex::encode(sig.to_bytes()),
        }
    }

    /// Verify this certificate's signature against the issuer's public key.
    pub fn verify_signature(&self) -> Result<bool, KeyError> {
        let issuer_bytes = hex::decode(&self.body.issuer_public_key)
            .map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;

        if issuer_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "issuer public key must be 32 bytes".into(),
            ));
        }

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&issuer_bytes);

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

    /// Check if this certificate has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires) = self.body.expires_at {
            Utc::now() > expires
        } else {
            false
        }
    }

    /// Compute the Blake3 hash of this certificate (used as issuer_cert_hash in children).
    pub fn content_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("certificate must serialize");
        blake3::hash(&canonical).to_hex().to_string()
    }
}

/// An ordered chain of certificates from genesis (index 0) to leaf (last).
///
/// Once verified, the chain guarantees:
/// 1. Every signature is valid
/// 2. Each certificate's issuer matches the previous certificate's subject key
/// 3. Roles follow the hierarchy: Genesis → Operator → Agent
/// 4. Depths are monotonically increasing (0, 1, 2)
/// 5. No certificate has expired
/// 6. Issuer cert hashes link correctly
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateChain {
    certificates: Vec<Certificate>,
}

impl CertificateChain {
    /// Verify a chain of certificates.
    ///
    /// The chain must be ordered from genesis (root) to leaf.
    /// All signatures, roles, depths, expirations, and linkage are checked.
    pub fn verify(certificates: Vec<Certificate>) -> Result<Self, KeyError> {
        if certificates.is_empty() {
            return Err(KeyError::BrokenChain {
                depth: 0,
                reason: "empty certificate chain".into(),
            });
        }

        // Validate genesis (root)
        let genesis = &certificates[0];
        if genesis.body.role != KeyRole::Genesis {
            return Err(KeyError::RoleMismatch {
                expected: "genesis".into(),
                found: genesis.body.role.to_string(),
            });
        }
        if genesis.body.depth != 0 {
            return Err(KeyError::BrokenChain {
                depth: 0,
                reason: "genesis depth must be 0".into(),
            });
        }
        // Genesis is self-signed
        if genesis.body.public_key != genesis.body.issuer_public_key {
            return Err(KeyError::BrokenChain {
                depth: 0,
                reason: "genesis must be self-signed".into(),
            });
        }
        if !genesis.verify_signature()? {
            return Err(KeyError::InvalidSignature(
                "genesis signature invalid".into(),
            ));
        }
        if genesis.is_expired() {
            return Err(KeyError::CertificateExpired {
                subject: genesis.body.subject.clone(),
                expired_at: genesis
                    .body
                    .expires_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            });
        }

        // Walk the chain
        for i in 1..certificates.len() {
            let parent = &certificates[i - 1];
            let child = &certificates[i];

            // Depth must increment by 1
            let expected_depth = parent.body.depth + 1;
            if child.body.depth != expected_depth {
                return Err(KeyError::BrokenChain {
                    depth: child.body.depth,
                    reason: format!(
                        "expected depth {}, found {}",
                        expected_depth, child.body.depth
                    ),
                });
            }

            // Max depth is 2 (agent level)
            if child.body.depth > 2 {
                return Err(KeyError::DepthExceeded {
                    max: 2,
                    attempted: child.body.depth,
                });
            }

            // Parent role must be allowed to sign child role
            if !parent.body.role.can_sign(child.body.role) {
                return Err(KeyError::RoleMismatch {
                    expected: format!("child of {}", parent.body.role),
                    found: child.body.role.to_string(),
                });
            }

            // Child's issuer key must be parent's subject key
            if child.body.issuer_public_key != parent.body.public_key {
                return Err(KeyError::BrokenChain {
                    depth: child.body.depth,
                    reason: "issuer public key does not match parent's key".into(),
                });
            }

            // Issuer cert hash must match parent's hash
            if let Some(ref hash) = child.body.issuer_cert_hash {
                let parent_hash = parent.content_hash();
                if hash != &parent_hash {
                    return Err(KeyError::BrokenChain {
                        depth: child.body.depth,
                        reason: "issuer_cert_hash does not match parent certificate".into(),
                    });
                }
            }

            // Verify signature
            if !child.verify_signature()? {
                return Err(KeyError::InvalidSignature(format!(
                    "certificate at depth {} has invalid signature",
                    child.body.depth
                )));
            }

            // Check expiration
            if child.is_expired() {
                return Err(KeyError::CertificateExpired {
                    subject: child.body.subject.clone(),
                    expired_at: child
                        .body
                        .expires_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default(),
                });
            }
        }

        Ok(Self { certificates })
    }

    /// Verify this chain against a known genesis public key.
    ///
    /// This is the primary verification entry point: "I trust this genesis key.
    /// Does this chain lead back to it?"
    pub fn verify_against_genesis(
        certificates: Vec<Certificate>,
        genesis_public_key: &[u8; 32],
    ) -> Result<Self, KeyError> {
        let chain = Self::verify(certificates)?;
        let genesis_hex = hex::encode(genesis_public_key);
        if chain.genesis().body.public_key != genesis_hex {
            return Err(KeyError::GenesisMismatch);
        }
        Ok(chain)
    }

    /// The genesis certificate (root of trust).
    pub fn genesis(&self) -> &Certificate {
        &self.certificates[0]
    }

    /// The leaf certificate (the end entity).
    pub fn leaf(&self) -> &Certificate {
        self.certificates.last().unwrap()
    }

    /// Number of certificates in the chain.
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Whether the chain is empty (should never be true for a verified chain).
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// All certificates in order from genesis to leaf.
    pub fn certificates(&self) -> &[Certificate] {
        &self.certificates
    }

    /// The genesis public key for this chain.
    pub fn genesis_public_key(&self) -> Result<[u8; 32], KeyError> {
        let bytes = hex::decode(&self.genesis().body.public_key)
            .map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// The leaf's public key.
    pub fn leaf_public_key(&self) -> Result<[u8; 32], KeyError> {
        let bytes = hex::decode(&self.leaf().body.public_key)
            .map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn gen_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn test_genesis_self_signed() {
        let key = gen_key();
        let pub_key = key.verifying_key().to_bytes();
        let cert = Certificate::issue(
            "zeropoint-genesis".into(),
            KeyRole::Genesis,
            &pub_key,
            &key,
            None,
            None,
        );

        assert!(cert.verify_signature().unwrap());
        assert_eq!(cert.body.role, KeyRole::Genesis);
        assert_eq!(cert.body.depth, 0);
        assert_eq!(cert.body.public_key, cert.body.issuer_public_key);
    }

    #[test]
    fn test_full_chain_genesis_operator_agent() {
        let genesis_key = gen_key();
        let operator_key = gen_key();
        let agent_key = gen_key();

        let genesis_pub = genesis_key.verifying_key().to_bytes();
        let operator_pub = operator_key.verifying_key().to_bytes();
        let agent_pub = agent_key.verifying_key().to_bytes();

        // Genesis self-signs
        let genesis_cert = Certificate::issue(
            "zeropoint-genesis".into(),
            KeyRole::Genesis,
            &genesis_pub,
            &genesis_key,
            None,
            None,
        );

        // Genesis signs operator
        let operator_cert = Certificate::issue(
            "operator-alpha".into(),
            KeyRole::Operator,
            &operator_pub,
            &genesis_key,
            Some(genesis_cert.content_hash()),
            None,
        );

        // Operator signs agent
        let agent_cert = Certificate::issue(
            "agent-001".into(),
            KeyRole::Agent,
            &agent_pub,
            &operator_key,
            Some(operator_cert.content_hash()),
            None,
        );

        // Verify the full chain
        let chain =
            CertificateChain::verify(vec![genesis_cert, operator_cert, agent_cert]).unwrap();

        assert_eq!(chain.len(), 3);
        assert_eq!(chain.genesis().body.subject, "zeropoint-genesis");
        assert_eq!(chain.leaf().body.subject, "agent-001");
        assert_eq!(chain.leaf().body.role, KeyRole::Agent);
    }

    #[test]
    fn test_verify_against_known_genesis() {
        let genesis_key = gen_key();
        let operator_key = gen_key();

        let genesis_pub = genesis_key.verifying_key().to_bytes();
        let operator_pub = operator_key.verifying_key().to_bytes();

        let genesis_cert = Certificate::issue(
            "zeropoint-genesis".into(),
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

        // Verify against the correct genesis
        let chain = CertificateChain::verify_against_genesis(
            vec![genesis_cert, operator_cert],
            &genesis_pub,
        )
        .unwrap();
        assert_eq!(chain.len(), 2);

        // Verify against a wrong genesis should fail
        let wrong_key = gen_key();
        let wrong_pub = wrong_key.verifying_key().to_bytes();
        let err =
            CertificateChain::verify_against_genesis(chain.certificates().to_vec(), &wrong_pub)
                .unwrap_err();
        assert!(matches!(err, KeyError::GenesisMismatch));
    }

    #[test]
    fn test_tampered_certificate_fails() {
        let genesis_key = gen_key();
        let operator_key = gen_key();

        let genesis_pub = genesis_key.verifying_key().to_bytes();
        let operator_pub = operator_key.verifying_key().to_bytes();

        let genesis_cert = Certificate::issue(
            "zeropoint-genesis".into(),
            KeyRole::Genesis,
            &genesis_pub,
            &genesis_key,
            None,
            None,
        );

        let mut operator_cert = Certificate::issue(
            "operator-alpha".into(),
            KeyRole::Operator,
            &operator_pub,
            &genesis_key,
            Some(genesis_cert.content_hash()),
            None,
        );

        // Tamper with the subject
        operator_cert.body.subject = "impostor".into();

        let err = CertificateChain::verify(vec![genesis_cert, operator_cert]).unwrap_err();
        assert!(matches!(err, KeyError::InvalidSignature(_)));
    }

    #[test]
    fn test_wrong_issuer_fails() {
        let genesis_key = gen_key();
        let rogue_key = gen_key();
        let operator_key = gen_key();

        let genesis_pub = genesis_key.verifying_key().to_bytes();
        let operator_pub = operator_key.verifying_key().to_bytes();

        let genesis_cert = Certificate::issue(
            "zeropoint-genesis".into(),
            KeyRole::Genesis,
            &genesis_pub,
            &genesis_key,
            None,
            None,
        );

        // Rogue signs the operator cert instead of genesis
        let operator_cert = Certificate::issue(
            "operator-alpha".into(),
            KeyRole::Operator,
            &operator_pub,
            &rogue_key,
            Some(genesis_cert.content_hash()),
            None,
        );

        let err = CertificateChain::verify(vec![genesis_cert, operator_cert]).unwrap_err();
        assert!(matches!(err, KeyError::BrokenChain { .. }));
    }

    #[test]
    fn test_role_mismatch_fails() {
        let genesis_key = gen_key();
        let agent_key = gen_key();

        let genesis_pub = genesis_key.verifying_key().to_bytes();
        let agent_pub = agent_key.verifying_key().to_bytes();

        let genesis_cert = Certificate::issue(
            "zeropoint-genesis".into(),
            KeyRole::Genesis,
            &genesis_pub,
            &genesis_key,
            None,
            None,
        );

        // Genesis directly signs an agent (skipping operator) — wrong!
        // We'll manually construct this to bypass the role check in issue()
        let mut agent_cert = Certificate::issue(
            "agent-rogue".into(),
            KeyRole::Agent,
            &agent_pub,
            &genesis_key,
            Some(genesis_cert.content_hash()),
            None,
        );
        // Fix depth to 1 to look like it follows genesis
        agent_cert.body.depth = 1;

        let err = CertificateChain::verify(vec![genesis_cert, agent_cert]).unwrap_err();
        assert!(matches!(err, KeyError::RoleMismatch { .. }));
    }

    #[test]
    fn test_expired_certificate_fails() {
        let genesis_key = gen_key();
        let genesis_pub = genesis_key.verifying_key().to_bytes();

        let expired = chrono::Utc::now() - chrono::Duration::hours(1);
        let cert = Certificate::issue(
            "expired-genesis".into(),
            KeyRole::Genesis,
            &genesis_pub,
            &genesis_key,
            None,
            Some(expired),
        );

        let err = CertificateChain::verify(vec![cert]).unwrap_err();
        assert!(matches!(err, KeyError::CertificateExpired { .. }));
    }

    #[test]
    fn test_genesis_only_chain() {
        let key = gen_key();
        let pub_key = key.verifying_key().to_bytes();
        let cert = Certificate::issue(
            "standalone".into(),
            KeyRole::Genesis,
            &pub_key,
            &key,
            None,
            None,
        );

        let chain = CertificateChain::verify(vec![cert]).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.genesis().body.role, KeyRole::Genesis);
        assert_eq!(chain.leaf().body.role, KeyRole::Genesis);
    }
}
