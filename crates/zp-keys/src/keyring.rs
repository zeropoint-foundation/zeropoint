//! Keyring — persistent storage for the key hierarchy.
//!
//! Stores keys and certificates to `~/.zeropoint/keys/`:
//! ```text
//! ~/.zeropoint/keys/
//!   genesis.json        ← genesis certificate (public only by default)
//!   genesis.secret      ← genesis secret key (optional, for key ceremonies)
//!   operator.json       ← operator certificate
//!   operator.secret     ← operator secret key
//!   agents/
//!     agent-001.json    ← agent certificate chain
//!     agent-001.secret  ← agent secret key
//! ```
//!
//! Secret files are 32-byte raw key material. Certificate files are JSON.

use std::path::{Path, PathBuf};

use crate::certificate::Certificate;
use crate::error::KeyError;
use crate::hierarchy::{AgentKey, GenesisKey, OperatorKey};

/// Persistent keyring backed by the filesystem.
pub struct Keyring {
    base_dir: PathBuf,
}

/// What's stored in the keyring (public info only).
#[derive(Debug)]
pub struct KeyringStatus {
    pub has_genesis: bool,
    pub has_genesis_secret: bool,
    pub has_operator: bool,
    pub has_operator_secret: bool,
    pub agent_count: usize,
    pub agent_names: Vec<String>,
}

impl Keyring {
    /// Open or create a keyring at the given directory.
    pub fn open(base_dir: impl Into<PathBuf>) -> Result<Self, KeyError> {
        let base_dir = base_dir.into();
        std::fs::create_dir_all(&base_dir)?;
        std::fs::create_dir_all(base_dir.join("agents"))?;
        Ok(Self { base_dir })
    }

    /// Open the default keyring at `~/.zeropoint/keys/`.
    pub fn open_default() -> Result<Self, KeyError> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        Self::open(home.join(".zeropoint").join("keys"))
    }

    /// Get the keyring directory path.
    pub fn path(&self) -> &Path {
        &self.base_dir
    }

    /// Check what's in the keyring without loading secrets.
    pub fn status(&self) -> KeyringStatus {
        let agents_dir = self.base_dir.join("agents");
        let agent_names: Vec<String> = std::fs::read_dir(&agents_dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with(".json") {
                    Some(name.trim_end_matches(".json").to_string())
                } else {
                    None
                }
            })
            .collect();

        KeyringStatus {
            has_genesis: self.base_dir.join("genesis.json").exists(),
            has_genesis_secret: self.base_dir.join("genesis.secret").exists(),
            has_operator: self.base_dir.join("operator.json").exists(),
            has_operator_secret: self.base_dir.join("operator.secret").exists(),
            agent_count: agent_names.len(),
            agent_names,
        }
    }

    // ── Genesis ─────────────────────────────────────────────────

    /// Save a genesis key (certificate + optional secret).
    pub fn save_genesis(&self, genesis: &GenesisKey, save_secret: bool) -> Result<(), KeyError> {
        let cert_json = serde_json::to_string_pretty(genesis.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("genesis.json"), cert_json)?;

        if save_secret {
            std::fs::write(self.base_dir.join("genesis.secret"), genesis.secret_key())?;
        }

        Ok(())
    }

    /// Load the genesis certificate (public only).
    pub fn load_genesis_certificate(&self) -> Result<Certificate, KeyError> {
        let path = self.base_dir.join("genesis.json");
        let json = std::fs::read_to_string(&path)?;
        serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))
    }

    /// Load the full genesis key (with secret). Fails if secret is not stored.
    pub fn load_genesis(&self) -> Result<GenesisKey, KeyError> {
        let cert = self.load_genesis_certificate()?;
        let secret_path = self.base_dir.join("genesis.secret");
        let secret_bytes = std::fs::read(&secret_path)?;
        if secret_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "genesis secret must be 32 bytes".into(),
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        GenesisKey::from_parts(secret, cert)
    }

    // ── Operator ────────────────────────────────────────────────

    /// Save an operator key (certificate + secret).
    pub fn save_operator(&self, operator: &OperatorKey) -> Result<(), KeyError> {
        let cert_json = serde_json::to_string_pretty(operator.certificate())
            .map_err(|e| KeyError::Serialization(e.to_string()))?;
        std::fs::write(self.base_dir.join("operator.json"), cert_json)?;
        std::fs::write(
            self.base_dir.join("operator.secret"),
            operator.secret_key(),
        )?;
        Ok(())
    }

    /// Load the operator key (with secret).
    pub fn load_operator(&self) -> Result<OperatorKey, KeyError> {
        let cert_path = self.base_dir.join("operator.json");
        let json = std::fs::read_to_string(&cert_path)?;
        let cert: Certificate =
            serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))?;

        let secret_path = self.base_dir.join("operator.secret");
        let secret_bytes = std::fs::read(&secret_path)?;
        if secret_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "operator secret must be 32 bytes".into(),
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);

        let genesis_cert = self.load_genesis_certificate()?;
        OperatorKey::from_parts(secret, cert, genesis_cert)
    }

    // ── Agents ──────────────────────────────────────────────────

    /// Save an agent key (chain + secret).
    pub fn save_agent(&self, name: &str, agent: &AgentKey) -> Result<(), KeyError> {
        let chain = agent.portable_chain();
        let chain_json = serde_json::to_string_pretty(&chain)
            .map_err(|e| KeyError::Serialization(e.to_string()))?;

        let agents_dir = self.base_dir.join("agents");
        std::fs::write(agents_dir.join(format!("{}.json", name)), chain_json)?;
        std::fs::write(
            agents_dir.join(format!("{}.secret", name)),
            agent.secret_key(),
        )?;
        Ok(())
    }

    /// Load an agent key by name.
    pub fn load_agent(&self, name: &str) -> Result<AgentKey, KeyError> {
        let agents_dir = self.base_dir.join("agents");

        let chain_path = agents_dir.join(format!("{}.json", name));
        let json = std::fs::read_to_string(&chain_path)?;
        let certs: Vec<Certificate> =
            serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))?;

        if certs.len() != 3 {
            return Err(KeyError::BrokenChain {
                depth: 0,
                reason: format!("expected 3 certificates, found {}", certs.len()),
            });
        }

        let secret_path = agents_dir.join(format!("{}.secret", name));
        let secret_bytes = std::fs::read(&secret_path)?;
        if secret_bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(
                "agent secret must be 32 bytes".into(),
            ));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);

        AgentKey::from_parts(
            secret,
            certs[2].clone(),
            certs[1].clone(),
            certs[0].clone(),
        )
    }

    /// Load just the portable certificate chain for an agent (no secrets).
    pub fn load_agent_chain(&self, name: &str) -> Result<Vec<Certificate>, KeyError> {
        let path = self.base_dir.join("agents").join(format!("{}.json", name));
        let json = std::fs::read_to_string(&path)?;
        serde_json::from_str(&json).map_err(|e| KeyError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyring_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        // Generate full hierarchy
        let genesis = GenesisKey::generate("test-genesis");
        let operator = OperatorKey::generate("test-operator", &genesis, None);
        let agent = AgentKey::generate("test-agent-001", &operator, None);

        // Save
        keyring.save_genesis(&genesis, true).unwrap();
        keyring.save_operator(&operator).unwrap();
        keyring.save_agent("agent-001", &agent).unwrap();

        // Check status
        let status = keyring.status();
        assert!(status.has_genesis);
        assert!(status.has_genesis_secret);
        assert!(status.has_operator);
        assert!(status.has_operator_secret);
        assert_eq!(status.agent_count, 1);
        assert_eq!(status.agent_names, vec!["agent-001"]);

        // Load and verify
        let loaded_genesis = keyring.load_genesis().unwrap();
        assert_eq!(loaded_genesis.public_key(), genesis.public_key());

        let loaded_operator = keyring.load_operator().unwrap();
        assert_eq!(loaded_operator.public_key(), operator.public_key());

        let loaded_agent = keyring.load_agent("agent-001").unwrap();
        assert_eq!(loaded_agent.public_key(), agent.public_key());

        // Verify the loaded agent's chain
        let chain = loaded_agent.chain().unwrap();
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn test_keyring_without_genesis_secret() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("g");
        keyring.save_genesis(&genesis, false).unwrap();

        let status = keyring.status();
        assert!(status.has_genesis);
        assert!(!status.has_genesis_secret);

        // Loading the full genesis key should fail
        assert!(keyring.load_genesis().is_err());

        // But the certificate should still be loadable
        let cert = keyring.load_genesis_certificate().unwrap();
        assert_eq!(cert.body.subject, "g");
    }

    #[test]
    fn test_portable_chain_verification() {
        let dir = tempfile::tempdir().unwrap();
        let keyring = Keyring::open(dir.path().join("keys")).unwrap();

        let genesis = GenesisKey::generate("g");
        let operator = OperatorKey::generate("o", &genesis, None);
        let agent = AgentKey::generate("a", &operator, None);

        keyring.save_genesis(&genesis, false).unwrap();
        keyring.save_operator(&operator).unwrap();
        keyring.save_agent("a", &agent).unwrap();

        // A remote node loads just the certificate chain (no secrets)
        let certs = keyring.load_agent_chain("a").unwrap();
        assert_eq!(certs.len(), 3);

        // Verify against the genesis public key
        let chain = crate::certificate::CertificateChain::verify_against_genesis(
            certs,
            &genesis.public_key(),
        )
        .unwrap();
        assert_eq!(chain.leaf().body.subject, "a");
    }
}
