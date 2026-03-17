//! Error types for the key hierarchy.

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
}
