// crates/zp-keys/src/sovereignty/hardware/yubikey.rs
//
// YubiKey sovereignty provider.
//
// Uses FIDO2 hmac-secret extension to derive a wrapping key from the
// YubiKey. The Genesis secret is encrypted with this key and stored
// locally. Every load requires the YubiKey to be physically present
// and touched (if PIN + touch policy is configured).
//
// Alternative: PIV slot 9a can do RSA/EC operations, but FIDO2
// hmac-secret is more universal (works on all YubiKey 5+ models).
//
// Dependencies: feature-gated behind `hw-yubikey`
// - `ctap-hid-fido2` crate for FIDO2 hmac-secret
// - `hidapi` for USB HID communication

use super::super::{ProviderCapability, SovereigntyMode, SovereigntyProvider, EnrollmentResult};
use crate::error::KeyError;

// These on-disk filenames are only referenced inside the `hw-yubikey`
// feature-gated enroll/load paths. Without the feature, the provider is a
// detection-only stub and the constants are unused — silence dead-code here
// rather than at every call site.
#[cfg_attr(not(feature = "hw-yubikey"), allow(dead_code))]
const ENCRYPTED_SECRET_FILE: &str = "yubikey_wrapped.bin";
#[cfg_attr(not(feature = "hw-yubikey"), allow(dead_code))]
const YUBIKEY_CREDENTIAL_ID_FILE: &str = "yubikey_credential.bin";

/// YubiKey sovereignty provider.
pub struct YubiKeyProvider;

impl SovereigntyProvider for YubiKeyProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::YubiKey
    }

    fn detect(&self) -> ProviderCapability {
        #[cfg(feature = "hw-yubikey")]
        {
            detect_yubikey()
        }

        #[cfg(not(feature = "hw-yubikey"))]
        {
            // Even without the feature, check for USB HID devices
            // that look like YubiKeys via simple heuristic
            detect_yubikey_basic()
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        #[cfg(feature = "hw-yubikey")]
        {
            save_yubikey_secret(secret)
        }

        #[cfg(not(feature = "hw-yubikey"))]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "YubiKey support requires the 'hw-yubikey' feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(feature = "hw-yubikey")]
        {
            load_yubikey_secret()
        }

        #[cfg(not(feature = "hw-yubikey"))]
        {
            Err(KeyError::CredentialStore(
                "YubiKey support requires the 'hw-yubikey' feature".into(),
            ))
        }
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        #[cfg(feature = "hw-yubikey")]
        {
            verify_yubikey_presence()
        }

        #[cfg(not(feature = "hw-yubikey"))]
        {
            Err(KeyError::CredentialStore(
                "YubiKey support requires the 'hw-yubikey' feature".into(),
            ))
        }
    }

    fn enroll(&self) -> Result<Option<EnrollmentResult>, KeyError> {
        #[cfg(feature = "hw-yubikey")]
        {
            enroll_yubikey().map(Some)
        }

        #[cfg(not(feature = "hw-yubikey"))]
        {
            Err(KeyError::CredentialStore(
                "YubiKey support requires the 'hw-yubikey' feature".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Basic detection (no feature gate — uses system commands)
// ---------------------------------------------------------------------------

/// Detect YubiKey presence without the full crate.
/// Uses `ioreg` on macOS or `lsusb` on Linux to check for Yubico USB devices.
fn detect_yubikey_basic() -> ProviderCapability {
    let found = if cfg!(target_os = "macos") {
        std::process::Command::new("ioreg")
            .args(["-p", "IOUSB", "-l", "-n", "YubiKey"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("YubiKey") || stdout.contains("Yubico")
            })
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        std::process::Command::new("lsusb")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("1050:") // Yubico USB vendor ID
            })
            .unwrap_or(false)
    } else {
        false
    };

    ProviderCapability {
        mode: SovereigntyMode::YubiKey,
        available: found,
        description: if found {
            "YubiKey detected (enable 'hw-yubikey' feature for full support)".into()
        } else {
            "No YubiKey detected — insert your YubiKey to use this mode".into()
        },
        requires_enrollment: true,
        detail: None,
        implementation_status: super::super::ProviderStatus::DetectionOnly,
    }
}

// ---------------------------------------------------------------------------
// Full YubiKey implementation (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "hw-yubikey")]
fn detect_yubikey() -> ProviderCapability {
    // TODO: Use ctap-hid-fido2 to enumerate FIDO2 devices
    // For now, fall back to basic detection
    let mut cap = detect_yubikey_basic();
    if cap.available {
        cap.description = "YubiKey detected — FIDO2 hmac-secret available".into();
    }
    cap
}

#[cfg(feature = "hw-yubikey")]
fn enroll_yubikey() -> Result<EnrollmentResult, KeyError> {
    // TODO: Full FIDO2 credential creation flow:
    // 1. Open FIDO2 device via ctap-hid-fido2
    // 2. Create a resident credential with hmac-secret extension
    // 3. Store the credential ID for later use
    // 4. Derive the wrapping key from hmac-secret(credential, salt)
    //
    // For now, return a descriptive error about the expected flow
    Err(KeyError::CredentialStore(
        "YubiKey FIDO2 enrollment not yet implemented — coming in v0.3".into(),
    ))
}

#[cfg(feature = "hw-yubikey")]
fn save_yubikey_secret(secret: &[u8; 32]) -> Result<(), KeyError> {
    // TODO: Full flow:
    // 1. Load credential ID from enrollment
    // 2. Challenge YubiKey with hmac-secret to derive wrapping key
    // 3. Encrypt genesis secret with wrapping key
    // 4. Store encrypted secret to yubikey_wrapped.bin
    let _ = secret;
    Err(KeyError::CredentialStore(
        "YubiKey secret storage not yet implemented — coming in v0.3".into(),
    ))
}

#[cfg(feature = "hw-yubikey")]
fn load_yubikey_secret() -> Result<[u8; 32], KeyError> {
    // TODO: Reverse of save:
    // 1. Load credential ID
    // 2. Load encrypted secret from yubikey_wrapped.bin
    // 3. Challenge YubiKey to re-derive wrapping key
    // 4. Decrypt and return
    Err(KeyError::CredentialStore(
        "YubiKey secret loading not yet implemented — coming in v0.3".into(),
    ))
}

#[cfg(feature = "hw-yubikey")]
fn verify_yubikey_presence() -> Result<(), KeyError> {
    // TODO: Quick presence check via FIDO2 getInfo
    Err(KeyError::CredentialStore(
        "YubiKey presence verification not yet implemented — coming in v0.3".into(),
    ))
}
