//! Bridges `agent_zp::SovereigntyBridge` → `zp_keys::SovereigntyProvider`.
//!
//! Wraps ZP's native sovereignty detection and provider system so claw-code-rust
//! can create sovereignty-rooted sessions without depending on ZP crates directly.

use async_trait::async_trait;
use blake3;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hex;
use tracing;

use agent_zp::{AgentIdentity, SovereigntyBridge, SovereigntyError, SovereigntyStatus};
use zp_keys::sovereignty::{
    detect_all_providers, provider_for, ProviderStatus, SovereigntyMode,
};

/// Concrete `SovereigntyBridge` backed by ZP's native sovereignty system.
///
/// Wraps `zp_keys::sovereignty` detection and provider access, translating
/// between agent-zp's bridge types and ZP's native types.
pub struct ZpSovereigntyBridge;

impl ZpSovereigntyBridge {
    pub fn new() -> Self {
        Self
    }

    /// Resolve a mode string (e.g., "touchid", "trezor") to a `SovereigntyMode`.
    fn resolve_mode(mode: &str) -> Result<SovereigntyMode, SovereigntyError> {
        match mode.to_lowercase().as_str() {
            "touchid" | "touch_id" => Ok(SovereigntyMode::TouchId),
            "fingerprint" => Ok(SovereigntyMode::Fingerprint),
            "face" | "face_enroll" => Ok(SovereigntyMode::FaceEnroll),
            "windows_hello" | "windowshello" => Ok(SovereigntyMode::WindowsHello),
            "yubikey" => Ok(SovereigntyMode::YubiKey),
            "ledger" => Ok(SovereigntyMode::Ledger),
            "trezor" => Ok(SovereigntyMode::Trezor),
            "onlykey" => Ok(SovereigntyMode::OnlyKey),
            "login_password" | "loginpassword" | "password" => Ok(SovereigntyMode::LoginPassword),
            "file_based" | "filebased" | "file" => Ok(SovereigntyMode::FileBased),
            _ => Err(SovereigntyError::Other(format!(
                "unknown sovereignty mode: {}",
                mode
            ))),
        }
    }
}

impl Default for ZpSovereigntyBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SovereigntyBridge for ZpSovereigntyBridge {
    async fn detect_providers(&self) -> Vec<SovereigntyStatus> {
        let capabilities = detect_all_providers();

        capabilities
            .into_iter()
            .map(|cap| SovereigntyStatus {
                mode: format!("{:?}", cap.mode).to_lowercase(),
                display_name: cap.mode.display_name().to_string(),
                available: cap.available
                    && cap.implementation_status == ProviderStatus::Ready,
                enrolled: !cap.requires_enrollment,
                description: cap.description,
            })
            .collect()
    }

    async fn verify_presence(&self, mode: &str) -> Result<(), SovereigntyError> {
        let sov_mode = Self::resolve_mode(mode)?;
        let provider = provider_for(sov_mode);

        provider.verify_presence().map_err(|e| {
            if e.is_transient() {
                SovereigntyError::VerificationFailed(e.to_string())
            } else {
                SovereigntyError::Other(e.to_string())
            }
        })?;

        tracing::debug!(mode = mode, "Sovereignty presence verified via ZP provider");
        Ok(())
    }

    async fn create_identity(
        &self,
        mode: &str,
        session_nonce: &str,
    ) -> Result<AgentIdentity, SovereigntyError> {
        let sov_mode = Self::resolve_mode(mode)?;
        let provider = provider_for(sov_mode);

        // Step 1: Verify presence
        provider.verify_presence().map_err(|e| {
            SovereigntyError::VerificationFailed(format!(
                "{} presence verification failed: {}",
                mode, e
            ))
        })?;

        // Step 2: Load Genesis seed
        let genesis_seed = provider.load_secret().map_err(|e| {
            SovereigntyError::SecretLoadFailed(format!(
                "{} secret load failed: {}",
                mode, e
            ))
        })?;

        // Step 3: Derive Ed25519 session keypair from genesis_seed + session_nonce
        // session_seed = blake3(genesis_seed || session_nonce), truncated to 32 bytes
        let mut hasher = blake3::Hasher::new();
        hasher.update(&genesis_seed);
        hasher.update(session_nonce.as_bytes());
        let session_seed = hasher.finalize();

        let signing_key = SigningKey::from_bytes(session_seed.as_bytes());
        let verifying_key: VerifyingKey = (&signing_key).into();

        // Step 4: Derive agent_id from public key (hex-encoded first 16 bytes)
        let pubkey_bytes = verifying_key.to_bytes();
        let agent_id = hex::encode(&pubkey_bytes[..16]);

        // Step 5: Sign session parameters (agent_id || timestamp || session_nonce)
        let created_at = chrono::Utc::now();
        let mut message = Vec::new();
        message.extend_from_slice(agent_id.as_bytes());
        message.extend_from_slice(created_at.to_rfc3339().as_bytes());
        message.extend_from_slice(session_nonce.as_bytes());
        let signature = signing_key.sign(&message);

        // Token format: hex(signature || public_key) — 64 + 32 = 96 bytes → 192 hex chars
        let mut token_bytes = Vec::with_capacity(96);
        token_bytes.extend_from_slice(&signature.to_bytes());
        token_bytes.extend_from_slice(&pubkey_bytes);
        let session_token = hex::encode(&token_bytes);

        let identity = AgentIdentity {
            agent_id,
            session_token,
            sovereignty_mode: mode.to_string(),
            created_at,
            session_nonce: session_nonce.to_string(),
        };

        tracing::info!(
            mode = mode,
            agent_id = %identity.agent_id,
            "Sovereignty-rooted identity created via ZP provider"
        );

        Ok(identity)
    }

    async fn reverify(&self, identity: &AgentIdentity) -> Result<(), SovereigntyError> {
        if identity.sovereignty_mode == "none" {
            // Transient identity — no reverification needed
            return Ok(());
        }

        self.verify_presence(&identity.sovereignty_mode).await?;
        tracing::trace!(
            agent_id = %identity.agent_id,
            mode = %identity.sovereignty_mode,
            "Sovereignty re-verification passed"
        );
        Ok(())
    }
}
