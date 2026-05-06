//! Key hierarchy types — typed wrappers for each level of the trust chain.
//!
//! These types hold both the private key material and the certificate that
//! attests their role. They provide ergonomic methods for issuing child
//! certificates without exposing raw signing key manipulation.

use crate::certificate::{Certificate, CertificateChain, KeyRole};
use crate::error::KeyError;
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

/// The genesis key — absolute root of trust.
///
/// Generated once per ZeroPoint deployment. Self-signed. Signs operator
/// certificates. If this key is compromised, the entire trust hierarchy
/// must be regenerated.
///
/// Secrets are zeroized on drop.
pub struct GenesisKey {
    signing_key: SigningKey,
    certificate: Certificate,
}

impl Drop for GenesisKey {
    fn drop(&mut self) {
        // Overwrite key material
        self.signing_key = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl GenesisKey {
    /// Generate a new genesis key with a self-signed certificate.
    pub fn generate(subject: &str) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();

        let certificate = Certificate::issue(
            subject.to_string(),
            KeyRole::Genesis,
            &public_key,
            &signing_key,
            None,
            None,
        );

        Self {
            signing_key,
            certificate,
        }
    }

    /// Restore from existing key material and certificate.
    pub fn from_parts(secret: [u8; 32], certificate: Certificate) -> Result<Self, KeyError> {
        if certificate.body.role != KeyRole::Genesis {
            return Err(KeyError::RoleMismatch {
                expected: "genesis".into(),
                found: certificate.body.role.to_string(),
            });
        }
        let signing_key = SigningKey::from_bytes(&secret);
        Ok(Self {
            signing_key,
            certificate,
        })
    }

    /// Issue an operator certificate signed by this genesis key.
    pub fn issue_operator(
        &self,
        subject: &str,
        operator_public_key: &[u8; 32],
        expires_at: Option<DateTime<Utc>>,
    ) -> Certificate {
        Certificate::issue(
            subject.to_string(),
            KeyRole::Operator,
            operator_public_key,
            &self.signing_key,
            Some(self.certificate.content_hash()),
            expires_at,
        )
    }

    /// The genesis certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The genesis public key (32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Export the secret key bytes. Handle with extreme care.
    pub fn secret_key(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }

    /// Borrow the internal Ed25519 signing key.
    ///
    /// Used by callers that need a `&SigningKey` reference (e.g., rotation
    /// certificate co-signing). Prefer `secret_key()` for raw bytes export.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// An operator key — represents a node operator in the hierarchy.
///
/// Signed by a genesis key. Signs agent certificates. One per node operator.
pub struct OperatorKey {
    signing_key: SigningKey,
    certificate: Certificate,
    /// The genesis certificate that signed this operator (needed for chain construction).
    genesis_certificate: Certificate,
}

impl Drop for OperatorKey {
    fn drop(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl OperatorKey {
    /// Generate a new operator key and have it certified by the genesis key.
    pub fn generate(
        subject: &str,
        genesis: &GenesisKey,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let certificate = genesis.issue_operator(subject, &public_key, expires_at);

        Self {
            signing_key,
            certificate,
            genesis_certificate: genesis.certificate().clone(),
        }
    }

    /// Restore from existing key material, certificate, and genesis certificate.
    pub fn from_parts(
        secret: [u8; 32],
        certificate: Certificate,
        genesis_certificate: Certificate,
    ) -> Result<Self, KeyError> {
        if certificate.body.role != KeyRole::Operator {
            return Err(KeyError::RoleMismatch {
                expected: "operator".into(),
                found: certificate.body.role.to_string(),
            });
        }
        let signing_key = SigningKey::from_bytes(&secret);
        Ok(Self {
            signing_key,
            certificate,
            genesis_certificate,
        })
    }

    /// Issue an agent certificate signed by this operator key.
    pub fn issue_agent(
        &self,
        subject: &str,
        agent_public_key: &[u8; 32],
        expires_at: Option<DateTime<Utc>>,
    ) -> Certificate {
        Certificate::issue(
            subject.to_string(),
            KeyRole::Agent,
            agent_public_key,
            &self.signing_key,
            Some(self.certificate.content_hash()),
            expires_at,
        )
    }

    /// Build the certificate chain from genesis to this operator.
    pub fn chain(&self) -> Result<CertificateChain, KeyError> {
        CertificateChain::verify(vec![
            self.genesis_certificate.clone(),
            self.certificate.clone(),
        ])
    }

    /// The operator certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The genesis certificate that backs this operator.
    pub fn genesis_certificate(&self) -> &Certificate {
        &self.genesis_certificate
    }

    /// The operator's public key (32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Export the secret key bytes. Handle with care.
    pub fn secret_key(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }

    /// Sign data with this operator's key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(data).to_bytes()
    }

    /// Borrow the internal Ed25519 signing key.
    ///
    /// Used by callers that need a `&SigningKey` reference (e.g., grant signing,
    /// audit chain entries). Prefer `sign()` for simple data signing.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

/// An agent key — represents a specific agent instance.
///
/// Signed by an operator key. This is what travels on the mesh.
/// Other nodes verify the chain: agent cert → operator cert → genesis cert.
pub struct AgentKey {
    signing_key: SigningKey,
    certificate: Certificate,
    /// The operator certificate that signed this agent.
    operator_certificate: Certificate,
    /// The genesis certificate (root of trust).
    genesis_certificate: Certificate,
}

impl Drop for AgentKey {
    fn drop(&mut self) {
        self.signing_key = SigningKey::from_bytes(&[0u8; 32]);
    }
}

impl AgentKey {
    /// Generate a new agent key and have it certified by the operator key.
    pub fn generate(
        subject: &str,
        operator: &OperatorKey,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let certificate = operator.issue_agent(subject, &public_key, expires_at);

        Self {
            signing_key,
            certificate,
            operator_certificate: operator.certificate().clone(),
            genesis_certificate: operator.genesis_certificate().clone(),
        }
    }

    /// Restore from existing key material and certificates.
    pub fn from_parts(
        secret: [u8; 32],
        certificate: Certificate,
        operator_certificate: Certificate,
        genesis_certificate: Certificate,
    ) -> Result<Self, KeyError> {
        if certificate.body.role != KeyRole::Agent {
            return Err(KeyError::RoleMismatch {
                expected: "agent".into(),
                found: certificate.body.role.to_string(),
            });
        }
        let signing_key = SigningKey::from_bytes(&secret);
        Ok(Self {
            signing_key,
            certificate,
            operator_certificate,
            genesis_certificate,
        })
    }

    /// Build the full certificate chain from genesis to this agent.
    pub fn chain(&self) -> Result<CertificateChain, KeyError> {
        CertificateChain::verify(vec![
            self.genesis_certificate.clone(),
            self.operator_certificate.clone(),
            self.certificate.clone(),
        ])
    }

    /// Verify this agent's chain against a known genesis public key.
    pub fn verify_against_genesis(
        &self,
        genesis_public_key: &[u8; 32],
    ) -> Result<CertificateChain, KeyError> {
        CertificateChain::verify_against_genesis(
            vec![
                self.genesis_certificate.clone(),
                self.operator_certificate.clone(),
                self.certificate.clone(),
            ],
            genesis_public_key,
        )
    }

    /// Sign data with this agent's key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(data).to_bytes()
    }

    /// The agent certificate.
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// The full chain as portable certificates (for sending to peers).
    pub fn portable_chain(&self) -> Vec<Certificate> {
        vec![
            self.genesis_certificate.clone(),
            self.operator_certificate.clone(),
            self.certificate.clone(),
        ]
    }

    /// The agent's public key (32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Export the secret key bytes. Handle with care.
    pub fn secret_key(&self) -> [u8; 32] {
        *self.signing_key.as_bytes()
    }

    /// Borrow the internal Ed25519 signing key.
    ///
    /// Used by callers that need a `&SigningKey` reference (e.g., rotation
    /// certificate signing). Prefer `sign()` for simple data signing.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_hierarchy_generation() {
        let genesis = GenesisKey::generate("zeropoint-foundation");
        let operator = OperatorKey::generate("operator-alpha", &genesis, None);
        let agent = AgentKey::generate("agent-001", &operator, None);

        // Verify the full chain
        let chain = agent.chain().unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.genesis().body.subject, "zeropoint-foundation");
        assert_eq!(chain.leaf().body.subject, "agent-001");
    }

    #[test]
    fn test_verify_against_genesis() {
        let genesis = GenesisKey::generate("zp-root");
        let operator = OperatorKey::generate("op-1", &genesis, None);
        let agent = AgentKey::generate("agent-x", &operator, None);

        let genesis_pub = genesis.public_key();

        // Should verify against the correct genesis
        let chain = agent.verify_against_genesis(&genesis_pub).unwrap();
        assert_eq!(chain.len(), 3);

        // Should fail against a different genesis
        let rogue = GenesisKey::generate("rogue-genesis");
        let err = agent
            .verify_against_genesis(&rogue.public_key())
            .unwrap_err();
        assert!(matches!(err, KeyError::GenesisMismatch));
    }

    #[test]
    fn test_agent_sign_and_verify() {
        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        let data = b"hello from agent";
        let sig = agent.sign(data);

        // Verify with the agent's public key from the chain via the
        // canonical verify primitive (Seam 5).
        let chain = agent.chain().unwrap();
        let leaf_pub = chain.leaf_public_key().unwrap();
        zp_receipt::verify::verify_signature(&leaf_pub, data, &sig)
            .expect("agent signature must verify under chain leaf key");
    }

    #[test]
    fn test_portable_chain() {
        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        // Get portable chain (just certificates, no secrets)
        let certs = agent.portable_chain();
        assert_eq!(certs.len(), 3);

        // A remote node can verify this chain with only the genesis public key
        let chain = CertificateChain::verify_against_genesis(certs, &genesis.public_key()).unwrap();
        assert_eq!(chain.leaf().body.subject, "a");
    }

    #[test]
    fn test_operator_chain() {
        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("op", &genesis, None);

        let chain = operator.chain().unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.genesis().body.subject, "g");
        assert_eq!(chain.leaf().body.subject, "op");
    }

    #[test]
    fn test_from_parts_roundtrip() {
        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        // Extract parts
        let secret = agent.secret_key();
        let cert = agent.certificate().clone();
        let op_cert = operator.certificate().clone();
        let gen_cert = genesis.certificate().clone();

        // Reconstruct
        let restored = AgentKey::from_parts(secret, cert, op_cert, gen_cert).unwrap();
        assert_eq!(restored.public_key(), agent.public_key());

        // Verify the restored chain
        let chain = restored.chain().unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_expired_operator() {
        let genesis = GenesisKey::generate("g");
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let operator = OperatorKey::generate("expired-op", &genesis, Some(past));

        let err = operator.chain().unwrap_err();
        assert!(matches!(err, KeyError::CertificateExpired { .. }));
    }
}
