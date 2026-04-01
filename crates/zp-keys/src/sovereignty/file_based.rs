// crates/zp-keys/src/sovereignty/file_based.rs
//
// File-based sovereignty provider — secret on disk with file permissions.
//
// For headless servers, CI, or systems without a credential store.
// Weakest option — any process with user privileges can read the file.
// Recommended only for automated deployments.

use super::{ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// File-based provider (disk storage).
pub struct FileProvider;

impl SovereigntyProvider for FileProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::FileBased
    }

    fn detect(&self) -> ProviderCapability {
        ProviderCapability {
            mode: SovereigntyMode::FileBased,
            available: true, // Always available
            description: "File on disk — for headless servers and CI only".into(),
            requires_enrollment: false,
            detail: None,
            implementation_status: super::ProviderStatus::Ready,
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        let home = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zeropoint")
            .join("keys");
        std::fs::create_dir_all(&home)?;

        let path = home.join("genesis.secret");
        std::fs::write(&path, secret)?;

        // Restrict permissions on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }

        tracing::info!("Genesis secret written to disk (file-based sovereignty)");
        Ok(())
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        let path = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zeropoint")
            .join("keys")
            .join("genesis.secret");

        let bytes = std::fs::read(&path)?;
        if bytes.len() != 32 {
            return Err(KeyError::InvalidKeyMaterial(format!(
                "genesis.secret has wrong length: {} (expected 32)",
                bytes.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        Ok(secret)
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        // File-based mode has no presence verification.
        // The file is always accessible to the user process.
        Ok(())
    }
}
