// crates/zp-keys/src/sovereignty/login_password.rs
//
// Login password sovereignty provider — OS credential store with default access.
//
// This is the solid default. The Genesis secret is stored in the platform's
// credential store (macOS Keychain, Linux Secret Service, Windows Credential
// Manager) with the user's login password as the gate.

use super::{ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// Login password provider (OS credential store).
pub struct LoginPasswordProvider;

impl SovereigntyProvider for LoginPasswordProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::LoginPassword
    }

    fn detect(&self) -> ProviderCapability {
        let available = cfg!(feature = "os-keychain");
        let store_name = if cfg!(target_os = "macos") {
            "macOS Keychain"
        } else if cfg!(target_os = "linux") {
            "Secret Service"
        } else if cfg!(target_os = "windows") {
            "Windows Credential Manager"
        } else {
            "OS credential store"
        };

        ProviderCapability {
            mode: SovereigntyMode::LoginPassword,
            available,
            description: if available {
                format!("{} available — login password gates the secret", store_name)
            } else {
                "OS credential store not available (os-keychain feature disabled)".into()
            },
            requires_enrollment: false,
            detail: Some(store_name.to_string()),
            implementation_status: super::ProviderStatus::Ready,
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        crate::keyring::save_genesis_to_credential_store(secret)
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        crate::keyring::load_genesis_from_credential_store()
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        // Login password mode has no separate presence check —
        // the OS gates the Keychain read with the login password.
        // If we can read the secret, presence is verified.
        //
        // We don't actually load the secret here (to avoid unnecessary
        // Keychain prompts), just return Ok. The real gate is at load time.
        Ok(())
    }
}
