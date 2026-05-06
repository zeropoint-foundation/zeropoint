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
        let keys_dir = zp_core::paths::keys_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("ZeroPoint/keys"));
        std::fs::create_dir_all(&keys_dir)?;

        // CRIT-8: atomic write via tmpfile + rename, mode 0600 from
        // creation. Eliminates the chmod-after-write race the audit
        // flagged in the original write-then-set_permissions sequence.
        let path = keys_dir.join("genesis.secret");
        crate::secret_file::write_atomic(&path, secret)?;

        tracing::info!("Genesis secret written to disk (file-based sovereignty)");
        Ok(())
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        let path = zp_core::paths::keys_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("ZeroPoint/keys"))
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
