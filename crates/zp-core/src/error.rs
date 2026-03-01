//! Error types for ZeroPoint v2.

use thiserror::Error;

/// Top-level error type for ZeroPoint operations.
#[derive(Debug, Error)]
pub enum ZpError {
    // -- Policy errors --
    #[error("action blocked by policy: {reason}")]
    PolicyBlocked {
        reason: String,
        policy_module: String,
    },

    #[error("action requires review: {summary}")]
    PolicyReviewRequired { summary: String },

    // -- Credential errors --
    #[error("credential access denied: skill '{skill}' cannot use credential '{credential}'")]
    CredentialDenied { skill: String, credential: String },

    #[error("credential not found: {0}")]
    CredentialNotFound(String),

    #[error("credential vault error: {0}")]
    VaultError(String),

    // -- Provider errors --
    #[error("no provider available for request")]
    NoProvider,

    #[error("provider error ({provider}): {message}")]
    ProviderError { provider: String, message: String },

    // -- Skill errors --
    #[error("skill not found: {0}")]
    SkillNotFound(String),

    #[error("skill execution failed: {0}")]
    SkillExecFailed(String),

    // -- WASM errors --
    #[error("WASM module error: {0}")]
    WasmError(String),

    #[error("WASM fuel exhausted for module: {0}")]
    WasmFuelExhausted(String),

    // -- Audit errors --
    #[error("audit chain integrity violated: {0}")]
    AuditChainBroken(String),

    #[error("audit write failed: {0}")]
    AuditWriteFailed(String),

    // -- Trust errors --
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),

    #[error("trust chain broken at: {0}")]
    TrustChainBroken(String),

    // -- Storage errors --
    #[error("database error: {0}")]
    Database(String),

    // -- General --
    #[error("configuration error: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl From<rusqlite::Error> for ZpError {
    fn from(e: rusqlite::Error) -> Self {
        ZpError::Database(e.to_string())
    }
}

impl From<serde_json::Error> for ZpError {
    fn from(e: serde_json::Error) -> Self {
        ZpError::Serialization(e.to_string())
    }
}
