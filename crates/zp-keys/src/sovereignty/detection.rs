// crates/zp-keys/src/sovereignty/detection.rs
//
// Platform detection utilities shared across sovereignty providers.
//
// This module provides the platform/hardware detection that the old
// biometric.rs used to own. The detection types (BiometricCapability,
// BiometricType, Platform) are retained for backward compatibility
// with the onboarding detection step.

use serde::{Deserialize, Serialize};

/// Detected biometric hardware capability (legacy API for onboarding step 1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricCapability {
    pub available: bool,
    pub biometric_type: Option<BiometricType>,
    pub credential_store_available: bool,
    pub platform: Platform,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometricType {
    TouchId,
    FaceId,
    Fprintd,
    WindowsHello,
}

impl std::fmt::Display for BiometricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BiometricType::TouchId => write!(f, "Touch ID"),
            BiometricType::FaceId => write!(f, "Face ID"),
            BiometricType::Fprintd => write!(f, "Fingerprint (fprintd)"),
            BiometricType::WindowsHello => write!(f, "Windows Hello"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    MacOS,
    Linux,
    Windows,
    Unknown,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::MacOS => write!(f, "macOS"),
            Platform::Linux => write!(f, "Linux"),
            Platform::Windows => write!(f, "Windows"),
            Platform::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect the current platform.
pub fn detect_platform() -> Platform {
    if cfg!(target_os = "macos") {
        Platform::MacOS
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Unknown
    }
}

/// Legacy detection API — wraps the new provider detection into the
/// old BiometricCapability format for backward compatibility with
/// the onboarding step 1 UI.
pub fn detect_biometric() -> BiometricCapability {
    use super::fingerprint::FingerprintProvider;
    use super::touchid::TouchIdProvider;
    use super::SovereigntyProvider;

    let platform = detect_platform();

    // Check Touch ID (macOS) or fingerprint (Linux)
    let (available, biometric_type, description) = match platform {
        Platform::MacOS => {
            let cap = TouchIdProvider.detect();
            let bio_type = if cap.available {
                cap.detail.as_deref().map(|d| {
                    if d.contains("Face") {
                        BiometricType::FaceId
                    } else {
                        BiometricType::TouchId
                    }
                })
            } else {
                None
            };
            (cap.available, bio_type, cap.description)
        }
        Platform::Linux => {
            let cap = FingerprintProvider.detect();
            let bio_type = if cap.available {
                Some(BiometricType::Fprintd)
            } else {
                None
            };
            (cap.available, bio_type, cap.description)
        }
        _ => (false, None, "No biometric hardware detected".into()),
    };

    BiometricCapability {
        available,
        biometric_type,
        credential_store_available: cfg!(feature = "os-keychain"),
        platform,
        description,
    }
}
