// crates/zp-keys/src/sovereignty/hardware/ledger.rs
//
// Ledger hardware wallet sovereignty provider.
//
// Uses a Ledger app (or the generic Bitcoin/Ethereum app) to derive
// a wrapping key from a BIP-32 path specific to ZeroPoint. The Genesis
// secret is encrypted with this key and stored locally.
//
// Dependencies: feature-gated behind `hw-ledger`
// - `ledger-transport-hid` for USB HID communication
// - `ledger-apdu` for APDU command construction

use super::super::{ProviderCapability, SovereigntyMode, SovereigntyProvider, EnrollmentResult};
use crate::error::KeyError;

/// Ledger sovereignty provider.
pub struct LedgerProvider;

impl SovereigntyProvider for LedgerProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::Ledger
    }

    fn detect(&self) -> ProviderCapability {
        detect_ledger_basic()
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        let _ = secret;
        Err(KeyError::CredentialStore(
            "Ledger support not yet implemented — coming in v0.3".into(),
        ))
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        Err(KeyError::CredentialStore(
            "Ledger support not yet implemented — coming in v0.3".into(),
        ))
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        Err(KeyError::CredentialStore(
            "Ledger support not yet implemented — coming in v0.3".into(),
        ))
    }

    fn enroll(&self) -> Result<Option<EnrollmentResult>, KeyError> {
        Err(KeyError::CredentialStore(
            "Ledger enrollment not yet implemented — coming in v0.3".into(),
        ))
    }
}

fn detect_ledger_basic() -> ProviderCapability {
    let found = if cfg!(target_os = "macos") {
        std::process::Command::new("ioreg")
            .args(["-p", "IOUSB", "-l"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("Ledger") || stdout.contains("2c97:") // Ledger USB vendor ID
            })
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        std::process::Command::new("lsusb")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("2c97:") // Ledger USB vendor ID
            })
            .unwrap_or(false)
    } else {
        false
    };

    ProviderCapability {
        mode: SovereigntyMode::Ledger,
        available: found,
        description: if found {
            "Ledger device detected".into()
        } else {
            "No Ledger device detected — connect your Ledger to use this mode".into()
        },
        requires_enrollment: true,
        detail: None,
        implementation_status: super::super::ProviderStatus::DetectionOnly,
    }
}
