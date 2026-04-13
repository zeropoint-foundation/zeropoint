//! Key rotation — verifiable key succession without identity loss.
//!
//! Phase 5.4: Implements seamless key rotation for the compromise plane.
//!
//! A rotation certificate says: "I (the old key) am being replaced by this
//! new key." The old key signs the rotation, creating a verifiable succession
//! chain. The node's identity is preserved across rotations because the
//! rotation certificate proves continuity.
//!
//! **Succession chain:** Multiple rotations form an ordered chain:
//!   key_v1 → key_v2 → key_v3 → ...
//! Any key in the chain can be traced back to the original through the
//! rotation certificates.
//!
//! **Receipt preservation:** Old-key-signed receipts remain verifiable via
//! the rotation chain. The verifier walks the succession chain backward to
//! find the signing key's position in the identity's history.
//!
//! **Lazy capability update:** Capability grants and delegation chains update
//! their key references lazily — on next verification, the rotation chain
//! is consulted to resolve old-key references to the current key.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use crate::certificate::KeyRole;
use crate::error::KeyError;

// ============================================================================
// Rotation certificate
// ============================================================================

/// The signable body of a rotation certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationBody {
    /// Unique rotation certificate identifier.
    pub id: String,
    /// The old public key being rotated out (hex-encoded Ed25519).
    pub old_public_key: String,
    /// The new public key being rotated in (hex-encoded Ed25519).
    pub new_public_key: String,
    /// The role of the key being rotated (preserved across rotation).
    pub role: KeyRole,
    /// When this rotation takes effect.
    pub effective_at: DateTime<Utc>,
    /// Sequence number in the rotation chain (0 = first rotation).
    pub sequence: u32,
    /// Hash of the previous rotation certificate (None for first rotation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_rotation_hash: Option<String>,
    /// Optional human-readable reason for the rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A signed rotation certificate — a `RotationBody` plus Ed25519 signatures.
///
/// The rotation is signed by BOTH the old key (proving possession) and
/// optionally co-signed by the parent key (proving authority). The old key
/// signature is mandatory; the parent co-signature adds defense-in-depth
/// but is not required for the rotation to be valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationCertificate {
    /// The rotation body (what is signed).
    pub body: RotationBody,
    /// Ed25519 signature by the OLD key over the canonical JSON of `body`.
    pub old_key_signature: String,
    /// Optional Ed25519 signature by the PARENT key (co-sign for defense-in-depth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_key_signature: Option<String>,
}

impl RotationCertificate {
    /// Create and sign a rotation certificate.
    ///
    /// The `old_signing_key` signs the rotation to prove possession.
    /// The `new_public_key` is the key being rotated to.
    pub fn issue(
        old_signing_key: &SigningKey,
        new_public_key: &[u8; 32],
        role: KeyRole,
        sequence: u32,
        prev_rotation_hash: Option<String>,
        reason: Option<String>,
    ) -> Result<Self, KeyError> {
        let old_pub = hex::encode(old_signing_key.verifying_key().to_bytes());
        let new_pub = hex::encode(new_public_key);

        if old_pub == new_pub {
            return Err(KeyError::InvalidKeyMaterial(
                "old and new keys must be different".into(),
            ));
        }

        let body = RotationBody {
            id: format!("rotate-{}", uuid::Uuid::now_v7()),
            old_public_key: old_pub,
            new_public_key: new_pub,
            role,
            effective_at: Utc::now(),
            sequence,
            prev_rotation_hash,
            reason,
        };

        let canonical =
            serde_json::to_vec(&body).map_err(|e| KeyError::Serialization(e.to_string()))?;
        let sig = old_signing_key.sign(&canonical);

        info!(
            old_key = %body.old_public_key,
            new_key = %body.new_public_key,
            role = %body.role,
            sequence = body.sequence,
            "Rotation certificate issued"
        );

        Ok(RotationCertificate {
            body,
            old_key_signature: hex::encode(sig.to_bytes()),
            parent_key_signature: None,
        })
    }

    /// Add a parent key co-signature (defense-in-depth).
    ///
    /// For operator rotation, the genesis key co-signs.
    /// For agent rotation, the operator key co-signs.
    pub fn co_sign(&mut self, parent_signing_key: &SigningKey) -> Result<(), KeyError> {
        let canonical =
            serde_json::to_vec(&self.body).map_err(|e| KeyError::Serialization(e.to_string()))?;
        let sig = parent_signing_key.sign(&canonical);
        self.parent_key_signature = Some(hex::encode(sig.to_bytes()));
        Ok(())
    }

    /// Verify the old key's signature on the rotation.
    pub fn verify_old_key_signature(&self) -> Result<bool, KeyError> {
        verify_signature(
            &self.old_key_signature,
            &self.body.old_public_key,
            &self.body,
        )
    }

    /// Verify the parent key's co-signature (if present).
    pub fn verify_parent_signature(&self, parent_public_key: &str) -> Result<bool, KeyError> {
        match &self.parent_key_signature {
            Some(sig) => verify_signature(sig, parent_public_key, &self.body),
            None => Ok(false),
        }
    }

    /// Compute the Blake3 hash of this rotation certificate.
    pub fn content_hash(&self) -> String {
        let canonical = serde_json::to_vec(self).expect("rotation cert must serialize");
        blake3::hash(&canonical).to_hex().to_string()
    }
}

/// Shared signature verification logic.
fn verify_signature(
    signature_hex: &str,
    public_key_hex: &str,
    body: &RotationBody,
) -> Result<bool, KeyError> {
    let key_bytes =
        hex::decode(public_key_hex).map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;

    if key_bytes.len() != 32 {
        return Err(KeyError::InvalidKeyMaterial(
            "public key must be 32 bytes".into(),
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|e| KeyError::InvalidKeyMaterial(e.to_string()))?;

    let sig_bytes =
        hex::decode(signature_hex).map_err(|e| KeyError::InvalidSignature(e.to_string()))?;

    if sig_bytes.len() != 64 {
        return Err(KeyError::InvalidSignature(
            "signature must be 64 bytes".into(),
        ));
    }

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    let canonical = serde_json::to_vec(body).map_err(|e| KeyError::Serialization(e.to_string()))?;

    Ok(verifying_key.verify_strict(&canonical, &signature).is_ok())
}

// ============================================================================
// Rotation chain (succession tracker)
// ============================================================================

/// Tracks the succession chain for a key identity.
///
/// Given any historical key, the chain can resolve it to the current
/// active key. This enables:
/// - Old-key receipts to remain verifiable (walk chain to find the key's epoch)
/// - Lazy capability grant updates (resolve old key ref → current key)
/// - Mesh peer identity continuity (same identity, new key material)
#[derive(Debug, Default)]
pub struct RotationChain {
    /// Rotation certificates in order: old_key → rotation cert.
    rotations: HashMap<String, RotationCertificate>,
    /// Current active key for each identity root.
    /// Maps the original (first) key → current key.
    current_keys: HashMap<String, String>,
    /// Reverse map: any key (old or current) → identity root (original key).
    identity_roots: HashMap<String, String>,
}

impl RotationChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a rotation certificate after verifying its signature.
    pub fn register(&mut self, cert: RotationCertificate) -> Result<(), KeyError> {
        // Verify the old key's signature.
        if !cert.verify_old_key_signature()? {
            return Err(KeyError::InvalidSignature(
                "rotation certificate old-key signature invalid".into(),
            ));
        }

        // Verify sequence ordering.
        if cert.body.sequence > 0 {
            if let Some(prev) = self.rotations.get(&cert.body.old_public_key) {
                if cert.body.sequence != prev.body.sequence + 1 {
                    return Err(KeyError::BrokenChain {
                        depth: 0,
                        reason: format!(
                            "rotation sequence gap: expected {}, found {}",
                            prev.body.sequence + 1,
                            cert.body.sequence
                        ),
                    });
                }
            }
        }

        let old_key = cert.body.old_public_key.clone();
        let new_key = cert.body.new_public_key.clone();

        // Find or create the identity root for this key.
        let root = self
            .identity_roots
            .get(&old_key)
            .cloned()
            .unwrap_or_else(|| old_key.clone());

        // Update maps.
        self.current_keys.insert(root.clone(), new_key.clone());
        self.identity_roots.insert(new_key.clone(), root.clone());
        self.identity_roots.insert(old_key.clone(), root);
        self.rotations.insert(old_key.clone(), cert);

        info!(
            old_key = %old_key,
            new_key = %new_key,
            "Rotation registered"
        );

        Ok(())
    }

    /// Resolve any key (old or current) to the current active key.
    ///
    /// Returns None if the key has no rotation history (it is its own
    /// current key or is unknown).
    pub fn resolve_current(&self, key: &str) -> Option<&str> {
        let root = self.identity_roots.get(key)?;
        self.current_keys.get(root).map(|s| s.as_str())
    }

    /// Check if two keys are the same identity (connected by rotation chain).
    pub fn same_identity(&self, key_a: &str, key_b: &str) -> bool {
        if key_a == key_b {
            return true;
        }

        let root_a = self.identity_roots.get(key_a);
        let root_b = self.identity_roots.get(key_b);

        match (root_a, root_b) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Get the identity root for a key (the original key before any rotations).
    pub fn identity_root(&self, key: &str) -> Option<&str> {
        self.identity_roots.get(key).map(|s| s.as_str())
    }

    /// Get all historical keys for an identity (including current).
    pub fn key_history(&self, key: &str) -> Vec<String> {
        let root = match self.identity_roots.get(key) {
            Some(r) => r.clone(),
            None => return vec![key.to_string()],
        };

        let mut history = vec![root.clone()];
        let mut current = root;

        while let Some(cert) = self.rotations.get(&current) {
            history.push(cert.body.new_public_key.clone());
            current = cert.body.new_public_key.clone();
        }

        history
    }

    /// Total number of rotations registered.
    pub fn rotation_count(&self) -> usize {
        self.rotations.len()
    }

    /// Get the rotation certificate for a specific old key.
    pub fn get_rotation(&self, old_key: &str) -> Option<&RotationCertificate> {
        self.rotations.get(old_key)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn gen_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn basic_rotation() {
        let old_key = gen_key();
        let new_key = gen_key();
        let new_pub = new_key.verifying_key().to_bytes();

        let cert = RotationCertificate::issue(
            &old_key,
            &new_pub,
            KeyRole::Operator,
            0,
            None,
            Some("Scheduled rotation".into()),
        )
        .unwrap();

        assert!(cert.verify_old_key_signature().unwrap());
        assert_eq!(cert.body.role, KeyRole::Operator);
        assert_eq!(cert.body.sequence, 0);
    }

    #[test]
    fn rotation_with_parent_cosign() {
        let genesis_key = gen_key();
        let old_operator = gen_key();
        let new_operator = gen_key();
        let new_pub = new_operator.verifying_key().to_bytes();

        let mut cert =
            RotationCertificate::issue(&old_operator, &new_pub, KeyRole::Operator, 0, None, None)
                .unwrap();

        cert.co_sign(&genesis_key).unwrap();

        assert!(cert.verify_old_key_signature().unwrap());
        assert!(cert
            .verify_parent_signature(&hex::encode(genesis_key.verifying_key().to_bytes()))
            .unwrap());
    }

    #[test]
    fn same_key_rotation_rejected() {
        let key = gen_key();
        let pub_bytes = key.verifying_key().to_bytes();

        let result = RotationCertificate::issue(&key, &pub_bytes, KeyRole::Agent, 0, None, None);

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyError::InvalidKeyMaterial(_)
        ));
    }

    #[test]
    fn tampered_rotation_rejected() {
        let old_key = gen_key();
        let new_key = gen_key();
        let new_pub = new_key.verifying_key().to_bytes();

        let mut cert =
            RotationCertificate::issue(&old_key, &new_pub, KeyRole::Agent, 0, None, None).unwrap();

        // Tamper with the new key.
        let rogue_key = gen_key();
        cert.body.new_public_key = hex::encode(rogue_key.verifying_key().to_bytes());

        // Signature should now be invalid.
        let mut chain = RotationChain::new();
        let result = chain.register(cert);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), KeyError::InvalidSignature(_)));
    }

    #[test]
    fn rotation_chain_resolve() {
        let key_v1 = gen_key();
        let key_v2 = gen_key();
        let key_v3 = gen_key();

        let v2_pub = key_v2.verifying_key().to_bytes();
        let v3_pub = key_v3.verifying_key().to_bytes();

        let v1_hex = hex::encode(key_v1.verifying_key().to_bytes());
        let v2_hex = hex::encode(v2_pub);
        let v3_hex = hex::encode(v3_pub);

        let mut chain = RotationChain::new();

        // v1 → v2
        let cert1 =
            RotationCertificate::issue(&key_v1, &v2_pub, KeyRole::Operator, 0, None, None).unwrap();
        let cert1_hash = cert1.content_hash();
        chain.register(cert1).unwrap();

        // v2 → v3
        let cert2 = RotationCertificate::issue(
            &key_v2,
            &v3_pub,
            KeyRole::Operator,
            1,
            Some(cert1_hash),
            None,
        )
        .unwrap();
        chain.register(cert2).unwrap();

        // All keys resolve to v3 (current).
        assert_eq!(chain.resolve_current(&v1_hex).unwrap(), v3_hex);
        assert_eq!(chain.resolve_current(&v2_hex).unwrap(), v3_hex);
        assert_eq!(chain.resolve_current(&v3_hex).unwrap(), v3_hex);
    }

    #[test]
    fn same_identity_check() {
        let key_v1 = gen_key();
        let key_v2 = gen_key();
        let unrelated = gen_key();

        let v2_pub = key_v2.verifying_key().to_bytes();

        let v1_hex = hex::encode(key_v1.verifying_key().to_bytes());
        let v2_hex = hex::encode(v2_pub);
        let unrelated_hex = hex::encode(unrelated.verifying_key().to_bytes());

        let mut chain = RotationChain::new();
        let cert =
            RotationCertificate::issue(&key_v1, &v2_pub, KeyRole::Agent, 0, None, None).unwrap();
        chain.register(cert).unwrap();

        // v1 and v2 are the same identity.
        assert!(chain.same_identity(&v1_hex, &v2_hex));
        assert!(chain.same_identity(&v2_hex, &v1_hex));

        // Unrelated key is a different identity.
        assert!(!chain.same_identity(&v1_hex, &unrelated_hex));
    }

    #[test]
    fn key_history() {
        let key_v1 = gen_key();
        let key_v2 = gen_key();
        let key_v3 = gen_key();

        let v2_pub = key_v2.verifying_key().to_bytes();
        let v3_pub = key_v3.verifying_key().to_bytes();

        let v1_hex = hex::encode(key_v1.verifying_key().to_bytes());
        let v2_hex = hex::encode(v2_pub);
        let v3_hex = hex::encode(v3_pub);

        let mut chain = RotationChain::new();

        let cert1 =
            RotationCertificate::issue(&key_v1, &v2_pub, KeyRole::Operator, 0, None, None).unwrap();
        let cert1_hash = cert1.content_hash();
        chain.register(cert1).unwrap();

        let cert2 = RotationCertificate::issue(
            &key_v2,
            &v3_pub,
            KeyRole::Operator,
            1,
            Some(cert1_hash),
            None,
        )
        .unwrap();
        chain.register(cert2).unwrap();

        // History from any key should show the full chain.
        let history = chain.key_history(&v1_hex);
        assert_eq!(
            history,
            vec![v1_hex.clone(), v2_hex.clone(), v3_hex.clone()]
        );

        let history = chain.key_history(&v3_hex);
        assert_eq!(history, vec![v1_hex, v2_hex, v3_hex]);
    }

    #[test]
    fn no_parent_signature_returns_false() {
        let old_key = gen_key();
        let new_key = gen_key();
        let new_pub = new_key.verifying_key().to_bytes();

        let cert = RotationCertificate::issue(&old_key, &new_pub, KeyRole::Operator, 0, None, None)
            .unwrap();

        // No co-sign → verify_parent_signature returns false.
        let genesis_key = gen_key();
        assert!(!cert
            .verify_parent_signature(&hex::encode(genesis_key.verifying_key().to_bytes()))
            .unwrap());
    }

    #[test]
    fn rotation_count() {
        let mut chain = RotationChain::new();
        assert_eq!(chain.rotation_count(), 0);

        let key_v1 = gen_key();
        let key_v2 = gen_key();
        let v2_pub = key_v2.verifying_key().to_bytes();

        let cert =
            RotationCertificate::issue(&key_v1, &v2_pub, KeyRole::Agent, 0, None, None).unwrap();
        chain.register(cert).unwrap();

        assert_eq!(chain.rotation_count(), 1);
    }
}
