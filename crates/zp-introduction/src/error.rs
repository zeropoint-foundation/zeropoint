//! Errors for the introduction protocol.

use zp_keys::KeyError;

#[derive(Debug, thiserror::Error)]
pub enum IntroductionError {
    #[error("chain verification failed: {0}")]
    ChainVerification(#[from] KeyError),

    #[error("introduction denied by policy: {reason}")]
    PolicyDenied { reason: String },

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("challenge failed: expected {expected}, got {actual}")]
    ChallengeFailed { expected: String, actual: String },

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("protocol timeout")]
    Timeout,
}
