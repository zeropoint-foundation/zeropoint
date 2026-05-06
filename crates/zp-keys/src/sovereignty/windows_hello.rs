// crates/zp-keys/src/sovereignty/windows_hello.rs
//
// Windows Hello sovereignty provider — TPM 2.0 biometric gating.
//
// v0.1 (current): Detection via PowerShell WMI queries to check for
//   Windows Hello capability (TPM, biometric hardware, enrollment status).
//   Storage uses `keyring` crate (Windows Credential Manager) with a
//   PowerShell-invoked UserConsentVerifier prompt before load.
//
// v0.2 (planned): Native WinRT bindings via the `windows` crate for
//   UserConsentVerifier and KeyCredentialManager APIs. No PowerShell shims.
//   Direct TPM-backed key creation with biometric access policy.

use super::{ProviderCapability, SovereigntyMode, SovereigntyProvider};
use crate::error::KeyError;

/// Windows Hello provider — fingerprint, face, or PIN backed by TPM 2.0.
pub struct WindowsHelloProvider;

impl SovereigntyProvider for WindowsHelloProvider {
    fn mode(&self) -> SovereigntyMode {
        SovereigntyMode::WindowsHello
    }

    fn detect(&self) -> ProviderCapability {
        #[cfg(target_os = "windows")]
        {
            detect_windows_hello()
        }

        #[cfg(not(target_os = "windows"))]
        {
            ProviderCapability {
                mode: SovereigntyMode::WindowsHello,
                available: false,
                description: "Windows Hello is only available on Windows".into(),
                requires_enrollment: false,
                detail: None,
                implementation_status: super::ProviderStatus::Partial,
            }
        }
    }

    fn save_secret(&self, secret: &[u8; 32]) -> Result<(), KeyError> {
        #[cfg(all(target_os = "windows", feature = "os-keychain"))]
        {
            save_windows_hello_secret(secret)
        }

        #[cfg(not(all(target_os = "windows", feature = "os-keychain")))]
        {
            let _ = secret;
            Err(KeyError::CredentialStore(
                "Windows Hello requires Windows with os-keychain feature".into(),
            ))
        }
    }

    fn load_secret(&self) -> Result<[u8; 32], KeyError> {
        #[cfg(all(target_os = "windows", feature = "os-keychain"))]
        {
            load_windows_hello_secret()
        }

        #[cfg(not(all(target_os = "windows", feature = "os-keychain")))]
        {
            Err(KeyError::CredentialStore(
                "Windows Hello requires Windows with os-keychain feature".into(),
            ))
        }
    }

    fn verify_presence(&self) -> Result<(), KeyError> {
        #[cfg(target_os = "windows")]
        {
            verify_windows_hello()
        }

        #[cfg(not(target_os = "windows"))]
        {
            Err(KeyError::CredentialStore(
                "Windows Hello verification only available on Windows".into(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn detect_windows_hello() -> ProviderCapability {
    // Check TPM availability via PowerShell WMI
    let tpm_check = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-WmiObject -Namespace 'root\\cimv2\\Security\\MicrosoftTpm' -Class Win32_Tpm -ErrorAction SilentlyContinue).IsEnabled_InitialValue",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let tpm_available = match &tpm_check {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.trim().eq_ignore_ascii_case("true")
        }
        Err(_) => false,
    };

    // Check Windows Hello enrollment status via dsregcmd or KeyCredentialManager
    let hello_check = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            // Check if Windows Hello biometric enrollment exists
            "try { \
                $status = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WinBio' -ErrorAction SilentlyContinue; \
                $bio = Get-WmiObject -Class Win32_BiometricDevice -Namespace 'root\\cimv2' -ErrorAction SilentlyContinue; \
                if ($bio) { Write-Output 'biometric_hw_present' } \
                elseif ((Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\PassportForWork' -ErrorAction SilentlyContinue)) { Write-Output 'hello_configured' } \
                else { Write-Output 'hello_available' } \
            } catch { Write-Output 'check_failed' }",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    let (bio_detail, bio_available) = match &hello_check {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            match stdout.as_str() {
                "biometric_hw_present" => ("Biometric hardware detected".to_string(), true),
                "hello_configured" => ("Windows Hello configured".to_string(), true),
                "hello_available" => ("Windows Hello available (PIN-only)".to_string(), true),
                _ => ("Windows Hello check inconclusive".to_string(), false),
            }
        }
        Err(_) => ("Could not query Windows Hello status".to_string(), false),
    };

    if tpm_available {
        ProviderCapability {
            mode: SovereigntyMode::WindowsHello,
            available: true,
            description: format!("{}, TPM 2.0 active", bio_detail),
            requires_enrollment: false, // Windows handles enrollment
            detail: Some(if bio_available {
                "Windows Hello (biometric + TPM)".to_string()
            } else {
                "Windows Hello (PIN + TPM)".to_string()
            }),
            implementation_status: super::ProviderStatus::Partial,
        }
    } else if bio_available {
        // No TPM but biometric hardware exists — still usable, weaker
        ProviderCapability {
            mode: SovereigntyMode::WindowsHello,
            available: true,
            description: format!("{} (no TPM — software-backed)", bio_detail),
            requires_enrollment: false,
            detail: Some("Windows Hello (software-backed)".to_string()),
            implementation_status: super::ProviderStatus::Partial,
        }
    } else {
        ProviderCapability {
            mode: SovereigntyMode::WindowsHello,
            available: false,
            description: "Windows Hello not available — no TPM or biometric hardware detected"
                .into(),
            requires_enrollment: false,
            detail: None,
            implementation_status: super::ProviderStatus::Partial,
        }
    }
}

/// Verify Windows Hello by triggering a UserConsentVerifier prompt.
///
/// v0.1: Uses PowerShell to invoke a credential prompt.
/// v0.2: Will use the `windows` crate WinRT bindings for
///   Windows.Security.Credentials.UI.UserConsentVerifier.
#[cfg(target_os = "windows")]
fn verify_windows_hello() -> Result<(), KeyError> {
    // Use PowerShell to trigger a Windows Hello verification prompt
    // via the UserConsentVerifier API
    let output = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            r#"
            Add-Type -AssemblyName System.Runtime.WindowsRuntime
            $null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType=WindowsRuntime]
            $asyncOp = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync("ZeroPoint: Verify your identity")
            $result = $asyncOp.GetAwaiter().GetResult()
            if ($result -eq [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) {
                Write-Output "verified"
            } else {
                Write-Output "failed:$result"
            }
            "#,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| {
            KeyError::CredentialStore(format!(
                "Failed to invoke Windows Hello verification: {}",
                e
            ))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if stdout == "verified" {
        tracing::info!("Windows Hello verification succeeded");
        Ok(())
    } else {
        Err(KeyError::CredentialStore(format!(
            "Windows Hello verification failed: {}",
            stdout
        )))
    }
}

/// Store the Genesis secret in Windows Credential Manager with Hello gating.
///
/// v0.1: Stores via `keyring` crate (Windows Credential Manager).
///       Windows Hello verification happens before store and before load.
///
/// v0.2: Will use KeyCredentialManager for TPM-backed storage with
///       biometric access policy, eliminating the application-layer check.
#[cfg(all(target_os = "windows", feature = "os-keychain"))]
fn save_windows_hello_secret(secret: &[u8; 32]) -> Result<(), KeyError> {
    // First, verify Windows Hello works — prompt the user now
    verify_windows_hello().map_err(|e| {
        KeyError::CredentialStore(format!(
            "Windows Hello verification failed during enrollment: {}. \
             Cannot enable biometric gating without a successful verification.",
            e
        ))
    })?;

    let entry = keyring::Entry::new(
        crate::keyring::genesis_keychain_service(),
        crate::keyring::genesis_keychain_account(),
    )
    .map_err(|e| KeyError::CredentialStore(format!("entry error: {}", e)))?;

    entry
        .set_password(&hex::encode(secret))
        .map_err(|e| KeyError::CredentialStore(format!("store error: {}", e)))?;

    tracing::info!(
        "Genesis secret stored in Windows Credential Manager with Hello verification \
         (application-layer gating, v0.1)"
    );

    // TODO v0.2: Replace with KeyCredentialManager API via `windows` crate.
    // Use KeyCredentialManager.RequestCreateAsync to create a TPM-backed
    // credential that requires Windows Hello for every access.
    // The `windows` crate provides:
    //   windows::Security::Credentials::KeyCredentialManager
    //   windows::Security::Credentials::UI::UserConsentVerifier

    Ok(())
}

/// Load the Genesis secret, requiring Windows Hello verification first.
#[cfg(all(target_os = "windows", feature = "os-keychain"))]
fn load_windows_hello_secret() -> Result<[u8; 32], KeyError> {
    // v0.1: Application-layer Hello check before reading Credential Manager
    verify_windows_hello()?;

    // Load from Windows Credential Manager (same storage as login password path)
    crate::keyring::load_genesis_from_credential_store()
}
