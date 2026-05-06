// crates/zp-keys/src/sovereignty/fingerprint.rs
//
// Linux fingerprint reader sovereignty provider via fprintd.
//
// Linux doesn't have OS-level biometric access control on keyring items
// the way macOS does with SecAccessControl. Instead, the secret lives in
// Secret Service and every READ is gated by fprintd-verify. The verify
// must succeed before we release the secret.

use super::{ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// Fingerprint provider for Linux (fprintd).
pub struct FingerprintProvider;

impl SovereigntyProvider for FingerprintProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::Fingerprint
    }

    fn detect(&self) -> ProviderCapability {
        #[cfg(target_os = "linux")]
        {
            detect_fprintd()
        }

        #[cfg(not(target_os = "linux"))]
        {
            ProviderCapability {
                mode: SovereigntyMode::Fingerprint,
                available: false,
                description: "Fingerprint reader (fprintd) is only available on Linux".into(),
                requires_enrollment: false,
                detail: None,
                implementation_status: super::ProviderStatus::Ready,
            }
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        #[cfg(all(target_os = "linux", feature = "os-keychain"))]
        {
            save_fprintd_secret(secret)
        }

        #[cfg(not(all(target_os = "linux", feature = "os-keychain")))]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "Fingerprint gating requires Linux with fprintd and os-keychain feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(all(target_os = "linux", feature = "os-keychain"))]
        {
            load_fprintd_secret()
        }

        #[cfg(not(all(target_os = "linux", feature = "os-keychain")))]
        {
            Err(KeyError::CredentialStore(
                "Fingerprint gating requires Linux with fprintd and os-keychain feature".into(),
            ))
        }
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        #[cfg(target_os = "linux")]
        {
            verify_fprintd()
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(KeyError::CredentialStore(
                "fprintd verification only available on Linux".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Linux implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn detect_fprintd() -> ProviderCapability {
    let fprintd_check = std::process::Command::new("systemctl")
        .args(["is-active", "fprintd"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match fprintd_check {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if stdout == "active" {
                // Check if fingers are enrolled
                let enrolled = std::process::Command::new("fprintd-list")
                    .arg(whoami::username_os())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .output()
                    .map(|o| {
                        let out = String::from_utf8_lossy(&o.stdout);
                        out.contains("finger") && !out.contains("no fingers")
                    })
                    .unwrap_or(false);

                if enrolled {
                    ProviderCapability {
                        mode: SovereigntyMode::Fingerprint,
                        available: true,
                        description: "Fingerprint reader available (fprintd)".into(),
                        requires_enrollment: false,
                        detail: Some("fprintd".to_string()),
                        implementation_status: super::ProviderStatus::Ready,
                    }
                } else {
                    ProviderCapability {
                        mode: SovereigntyMode::Fingerprint,
                        available: false,
                        description: "fprintd active but no fingers enrolled — run fprintd-enroll"
                            .into(),
                        requires_enrollment: true,
                        detail: None,
                        implementation_status: super::ProviderStatus::Ready,
                    }
                }
            } else {
                ProviderCapability {
                    mode: SovereigntyMode::Fingerprint,
                    available: false,
                    description: "fprintd service not active".into(),
                    requires_enrollment: false,
                    detail: None,
                    implementation_status: super::ProviderStatus::Ready,
                }
            }
        }
        Err(_) => ProviderCapability {
            mode: SovereigntyMode::Fingerprint,
            available: false,
            description: "fprintd not installed".into(),
            requires_enrollment: false,
            detail: None,
            implementation_status: super::ProviderStatus::Ready,
        },
    }
}

#[cfg(target_os = "linux")]
fn verify_fprintd() -> Result<(), KeyError> {
    let username = whoami::username();
    let output = std::process::Command::new("fprintd-verify")
        .arg(&username)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            KeyError::CredentialStore(format!("fprintd-verify failed to launch: {}", e))
        })?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("verify-match") {
            Ok(())
        } else {
            Err(KeyError::CredentialStore(
                "Fingerprint did not match — try again or switch to login password mode".into(),
            ))
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(KeyError::CredentialStore(format!(
            "Fingerprint verification failed: {}",
            stderr.trim()
        )))
    }
}

#[cfg(all(target_os = "linux", feature = "os-keychain"))]
fn save_fprintd_secret(secret: &[u8; 32]) -> Result<(), KeyError> {
    // Verify fingerprint works before committing to this mode
    verify_fprintd()?;

    let entry = keyring::Entry::new(
        crate::keyring::genesis_keychain_service(),
        crate::keyring::genesis_keychain_account(),
    )
    .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;

    entry
        .set_password(&hex::encode(secret))
        .map_err(|e| KeyError::CredentialStore(format!("store error: {}", e)))?;

    tracing::info!("Genesis secret stored in Secret Service with fprintd biometric gating");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "os-keychain"))]
fn load_fprintd_secret() -> Result<[u8; 32], KeyError> {
    verify_fprintd()?;
    crate::keyring::load_genesis_from_credential_store()
}
