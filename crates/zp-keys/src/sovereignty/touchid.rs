// crates/zp-keys/src/sovereignty/touchid.rs
//
// Touch ID sovereignty provider — macOS Secure Enclave biometric gating.
//
// v0.1 (current): Uses the `keyring` crate for storage and `bioutil -w`
//   for application-layer biometric verification before load.
//
// v0.2 (planned): Uses `security-framework` crate with
//   kSecAccessControlBiometryCurrentSet for OS-level enforcement.
//   The Secure Enclave gates every read — no application-layer check needed.

use super::{ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// Touch ID provider for macOS.
pub struct TouchIdProvider;

impl SovereigntyProvider for TouchIdProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::TouchId
    }

    fn detect(&self) -> ProviderCapability {
        #[cfg(target_os = "macos")]
        {
            detect_touchid()
        }

        #[cfg(not(target_os = "macos"))]
        {
            ProviderCapability {
                mode: SovereigntyMode::TouchId,
                available: false,
                description: "Touch ID is only available on macOS".into(),
                requires_enrollment: false,
                detail: None,
                implementation_status: super::ProviderStatus::Ready,
            }
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        #[cfg(all(target_os = "macos", feature = "os-keychain"))]
        {
            save_touchid_secret(secret)
        }

        #[cfg(not(all(target_os = "macos", feature = "os-keychain")))]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "Touch ID requires macOS with os-keychain feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(all(target_os = "macos", feature = "os-keychain"))]
        {
            load_touchid_secret()
        }

        #[cfg(not(all(target_os = "macos", feature = "os-keychain")))]
        {
            Err(KeyError::CredentialStore(
                "Touch ID requires macOS with os-keychain feature".into(),
            ))
        }
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        #[cfg(target_os = "macos")]
        {
            verify_touchid()
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(KeyError::CredentialStore(
                "Touch ID verification only available on macOS".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// macOS implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn detect_touchid() -> ProviderCapability {
    // bioutil -rs reports biometric status without triggering a prompt
    let biometric_check = std::process::Command::new("bioutil")
        .args(["-rs"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match biometric_check {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let bio_name = if stdout.contains("Face") {
                "Face ID"
            } else {
                "Touch ID"
            };
            ProviderCapability {
                mode: SovereigntyMode::TouchId,
                available: true,
                description: format!("{} available (Secure Enclave)", bio_name),
                requires_enrollment: false, // OS handles enrollment
                detail: Some(bio_name.to_string()),
                implementation_status: super::ProviderStatus::Ready,
            }
        }
        Ok(_) => {
            // bioutil ran but no biometric enrolled
            ProviderCapability {
                mode: SovereigntyMode::TouchId,
                available: false,
                description: "No biometric enrolled — enroll in System Preferences".into(),
                requires_enrollment: false,
                detail: None,
                implementation_status: super::ProviderStatus::Ready,
            }
        }
        Err(_) => {
            // bioutil not found — try system_profiler
            let sp_check = std::process::Command::new("system_profiler")
                .args(["SPiBridgeDataType"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .output();

            match sp_check {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("Touch ID") || stdout.contains("Fingerprint") {
                        ProviderCapability {
                            mode: SovereigntyMode::TouchId,
                            available: true,
                            description: "Touch ID hardware detected (Secure Enclave)".into(),
                            requires_enrollment: false,
                            detail: Some("Touch ID".to_string()),
                            implementation_status: super::ProviderStatus::Ready,
                        }
                    } else {
                        ProviderCapability {
                            mode: SovereigntyMode::TouchId,
                            available: false,
                            description: "No Touch ID hardware found".into(),
                            requires_enrollment: false,
                            detail: None,
                            implementation_status: super::ProviderStatus::Ready,
                        }
                    }
                }
                Err(_) => ProviderCapability {
                    mode: SovereigntyMode::TouchId,
                    available: false,
                    description: "Could not detect biometric hardware".into(),
                    requires_enrollment: false,
                    detail: None,
                    implementation_status: super::ProviderStatus::Ready,
                },
            }
        }
    }
}

/// Verify Touch ID / Face ID by triggering an actual biometric scan.
///
/// Uses `bioutil -w` which prompts the user for biometric verification.
/// This is the v0.1 application-layer check. v0.2 will make this
/// unnecessary once kSecAccessControlBiometryCurrentSet gates the
/// Keychain item at the OS level.
#[cfg(target_os = "macos")]
fn verify_touchid() -> Result<(), KeyError> {
    let output = std::process::Command::new("bioutil")
        .args(["-w"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            KeyError::CredentialStore(format!(
                "bioutil not available: {} — is Touch ID enrolled?",
                e
            ))
        })?;

    if output.status.success() {
        tracing::info!("Touch ID verification succeeded");
        Ok(())
    } else {
        Err(KeyError::CredentialStore(
            "Touch ID verification failed — touch your fingerprint sensor or try again".into(),
        ))
    }
}

/// Store the Genesis secret in Keychain with Touch ID gating.
///
/// v0.1: Stores via `keyring` crate (standard Keychain access).
///       Biometric verification happens at load time via `bioutil -w`.
///
/// v0.2: Will use Security.framework with kSecAccessControlBiometryCurrentSet
///       so the OS itself enforces biometric on every Keychain read.
#[cfg(all(target_os = "macos", feature = "os-keychain"))]
fn save_touchid_secret(secret: &[u8; 32]) -> Result<(), KeyError> {
    // First, verify Touch ID works — prompt the user now
    // so they know it's active and consent to biometric gating.
    verify_touchid().map_err(|e| {
        KeyError::CredentialStore(format!(
            "Touch ID verification failed during enrollment: {}. \
             Cannot enable biometric gating without a successful scan.",
            e
        ))
    })?;

    let entry = keyring::Entry::new(
        crate::keyring::GENESIS_KEYCHAIN_SERVICE,
        crate::keyring::GENESIS_KEYCHAIN_ACCOUNT,
    )
    .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;

    entry
        .set_password(&hex::encode(secret))
        .map_err(|e| KeyError::CredentialStore(format!("store error: {}", e)))?;

    tracing::info!(
        "Genesis secret stored in Keychain with Touch ID verification \
         (application-layer gating, v0.1)"
    );

    // TODO v0.2: Replace with Security.framework SecItemAdd using
    // kSecAccessControlBiometryCurrentSet. Requires:
    // - security-framework crate with SecAccessControl support
    // - Delete existing item, re-add with biometric access control
    // - Test on actual Touch ID / Face ID hardware

    Ok(())
}

/// Load the Genesis secret, requiring Touch ID verification first.
#[cfg(all(target_os = "macos", feature = "os-keychain"))]
fn load_touchid_secret() -> Result<[u8; 32], KeyError> {
    // v0.1: Application-layer biometric check before reading Keychain
    verify_touchid()?;

    // Load from Keychain (same as login password path)
    crate::keyring::load_genesis_from_credential_store()
}
