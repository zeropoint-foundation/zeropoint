// crates/zp-keys/src/biometric.rs
//
// COMPATIBILITY SHIM — delegates to the sovereignty module.
//
// This module existed before the sovereignty provider system was introduced.
// It defined SovereigntyMode, BiometricCapability, and detection functions.
// Those now live in sovereignty/ and sovereignty/detection/ respectively.
//
// This file re-exports everything for backward compatibility so that
// existing code importing from `zp_keys::biometric::*` continues to work.
// New code should import from `zp_keys::sovereignty::*` directly.

// Re-export the sovereignty mode (was defined here, now in sovereignty/)
pub use crate::sovereignty::SovereigntyMode;

// Re-export detection types and functions (now in sovereignty/detection/)
pub use crate::sovereignty::detection::{
    detect_biometric, BiometricCapability, BiometricType, Platform,
};

// Re-export the legacy biometric save/load functions.
// These now delegate to the TouchId and Fingerprint providers.
pub use crate::sovereignty::fingerprint::FingerprintProvider;
pub use crate::sovereignty::touchid::TouchIdProvider;

use crate::error::KeyError;

/// Store a genesis secret with biometric access control.
/// Compatibility wrapper — delegates to the appropriate sovereignty provider.
#[cfg(feature = "os-keychain")]
pub fn save_genesis_biometric(secret: &[u8; 32]) -> Result<(), KeyError> {
    use crate::sovereignty::SovereigntyProvider;

    let cap = detect_biometric();
    if !cap.available {
        return Err(KeyError::CredentialStore(
            "Biometric hardware not available — select login password mode instead".into(),
        ));
    }

    match cap.platform {
        Platform::MacOS => TouchIdProvider.save_secret(secret),
        Platform::Linux => FingerprintProvider.save_secret(secret),
        _ => Err(KeyError::CredentialStore(
            "Biometric gating not supported on this platform".into(),
        )),
    }
}

#[cfg(not(feature = "os-keychain"))]
pub fn save_genesis_biometric(_secret: &[u8; 32]) -> Result<(), KeyError> {
    Err(KeyError::CredentialStore(
        "OS credential store not available (enable 'os-keychain' feature)".into(),
    ))
}

/// Load genesis secret with biometric verification.
/// Compatibility wrapper — delegates to the appropriate sovereignty provider.
#[cfg(feature = "os-keychain")]
pub fn load_genesis_biometric() -> Result<[u8; 32], KeyError> {
    use crate::sovereignty::SovereigntyProvider;

    let cap = detect_biometric();
    match cap.platform {
        Platform::MacOS => TouchIdProvider.load_secret(),
        Platform::Linux => FingerprintProvider.load_secret(),
        _ => Err(KeyError::CredentialStore(
            "Biometric load not supported on this platform".into(),
        )),
    }
}

#[cfg(not(feature = "os-keychain"))]
pub fn load_genesis_biometric() -> Result<[u8; 32], KeyError> {
    Err(KeyError::CredentialStore(
        "OS credential store not available (enable 'os-keychain' feature)".into(),
    ))
}

/// Verify biometric on macOS via bioutil.
/// Compatibility wrapper — delegates to TouchIdProvider.
#[cfg(target_os = "macos")]
pub fn verify_biometric_macos() -> Result<(), KeyError> {
    use crate::sovereignty::SovereigntyProvider;
    TouchIdProvider.verify_presence()
}

#[cfg(not(target_os = "macos"))]
pub fn verify_biometric_macos() -> Result<(), KeyError> {
    Err(KeyError::CredentialStore(
        "macOS biometric verification only available on macOS".into(),
    ))
}

/// Verify fingerprint on Linux via fprintd-verify.
/// Compatibility wrapper — delegates to FingerprintProvider.
#[cfg(target_os = "linux")]
pub fn verify_fingerprint_linux() -> Result<(), KeyError> {
    use crate::sovereignty::SovereigntyProvider;
    FingerprintProvider.verify_presence()
}

#[cfg(not(target_os = "linux"))]
pub fn verify_fingerprint_linux() -> Result<(), KeyError> {
    Err(KeyError::CredentialStore(
        "fprintd-verify only available on Linux".into(),
    ))
}
