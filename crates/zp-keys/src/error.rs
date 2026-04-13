//! Error types for the key hierarchy and sovereignty system.

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("certificate chain broken at depth {depth}: {reason}")]
    BrokenChain { depth: u8, reason: String },

    #[error("certificate expired: {subject} expired at {expired_at}")]
    CertificateExpired { subject: String, expired_at: String },

    #[error("role mismatch: expected {expected}, found {found}")]
    RoleMismatch { expected: String, found: String },

    #[error("depth exceeded: max {max}, attempted {attempted}")]
    DepthExceeded { max: u8, attempted: u8 },

    #[error("invalid key material: {0}")]
    InvalidKeyMaterial(String),

    #[error("keyring I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("genesis key mismatch: chain root does not match expected genesis")]
    GenesisMismatch,

    #[error("OS credential store error: {0}")]
    CredentialStore(String),

    // ── Sovereignty provider errors ──────────────────────────────
    // These distinguish failure modes so the ceremony can respond correctly.
    /// The hardware device is not connected or not responding.
    /// Transient — retry after the user connects the device.
    #[error("device not found: {0}")]
    DeviceNotFound(String),

    /// The provider requires enrollment before first use (e.g., face capture,
    /// hardware wallet pairing). The user needs to complete setup.
    #[error("provider not enrolled: {0}")]
    NotEnrolled(String),

    /// Biometric verification failed (wrong finger, face mismatch, etc.).
    /// Transient — the user can try again.
    #[error("biometric verification failed: {0}")]
    BiometricFailed(String),

    /// The enrolled device doesn't match (e.g., different YubiKey serial,
    /// different Trezor). Security-critical — may indicate device swap.
    #[error("device mismatch: {0}")]
    DeviceMismatch(String),

    /// Stored enrollment data or encrypted secret is corrupted.
    /// Recovery mnemonic required.
    #[error("enrollment data corrupted: {0}")]
    EnrollmentCorrupted(String),

    /// The user cancelled the operation on the device (e.g., pressed
    /// "Reject" on Trezor screen, didn't touch YubiKey).
    #[error("user cancelled on device: {0}")]
    UserCancelled(String),

    /// The sovereignty provider is not yet implemented.
    /// The ceremony should not offer this provider.
    #[error("provider not implemented: {0}")]
    NotImplemented(String),
}

impl KeyError {
    /// Whether this error is transient and the operation might succeed on retry.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            KeyError::DeviceNotFound(_) | KeyError::BiometricFailed(_) | KeyError::UserCancelled(_)
        )
    }

    /// Whether this error indicates a security concern that should be surfaced.
    pub fn is_security_concern(&self) -> bool {
        matches!(
            self,
            KeyError::DeviceMismatch(_) | KeyError::EnrollmentCorrupted(_)
        )
    }
}
