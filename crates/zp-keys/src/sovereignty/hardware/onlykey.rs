// crates/zp-keys/src/sovereignty/hardware/onlykey.rs
//
// OnlyKey hardware token sovereignty provider.
//
// Uses OnlyKey's challenge-response (HMACSHA1 in a configured slot)
// to derive a wrapping key. The Genesis secret is encrypted with this
// key and stored locally.
//
// Dependencies: feature-gated behind `hw-onlykey`
// - `hidapi` for raw USB HID communication

use super::super::{EnrollmentResult, ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// OnlyKey sovereignty provider.
pub struct OnlyKeyProvider;

impl SovereigntyProvider for OnlyKeyProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::OnlyKey
    }

    fn detect(&self) -> ProviderCapability {
        detect_onlykey_basic()
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        let _ = secret;
        Err(KeyError::CredentialStore(
            "OnlyKey support not yet implemented — coming in v0.3".into(),
        ))
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        Err(KeyError::CredentialStore(
            "OnlyKey support not yet implemented — coming in v0.3".into(),
        ))
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        Err(KeyError::CredentialStore(
            "OnlyKey support not yet implemented — coming in v0.3".into(),
        ))
    }

    fn enroll(&self) -> Result<Option<EnrollmentResult>, KeyError> {
        Err(KeyError::CredentialStore(
            "OnlyKey enrollment not yet implemented — coming in v0.3".into(),
        ))
    }
}

fn detect_onlykey_basic() -> ProviderCapability {
    let found = if cfg!(target_os = "macos") {
        std::process::Command::new("ioreg")
            .args(["-p", "IOUSB", "-l"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                // OnlyKey USB vendor:product IDs
                stdout.contains("1d50:60fc") || stdout.contains("OnlyKey")
            })
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        std::process::Command::new("lsusb")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("1d50:60fc")
            })
            .unwrap_or(false)
    } else {
        false
    };

    ProviderCapability {
        mode: SovereigntyMode::OnlyKey,
        available: found,
        description: if found {
            "OnlyKey detected — full support coming in v0.3".into()
        } else {
            "OnlyKey support coming in v0.3".into()
        },
        requires_enrollment: true,
        detail: None,
        implementation_status: super::super::ProviderStatus::DetectionOnly,
    }
}
