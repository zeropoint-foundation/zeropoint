//! Error types for the Regent cognitive layer.

/// Errors from Regent operations.
#[derive(Debug, thiserror::Error)]
pub enum RegentError {
    #[error("inference error: {0}")]
    Inference(String),

    #[error("chain read error: {0}")]
    ChainRead(String),

    #[error("officer query error: {0}")]
    OfficerQuery(String),

    #[error("receipt emission error: {0}")]
    ReceiptEmission(String),

    #[error("context window exceeded: {current} tokens > {limit} limit")]
    ContextOverflow { current: usize, limit: usize },

    #[error("no inference backend available")]
    NoBackend,

    #[error("operator intervention required: {reason}")]
    OperatorRequired { reason: String },

    #[error("delegation insufficient for action: {action}")]
    InsufficientDelegation { action: String },

    #[error("tool execution error: {0}")]
    Execution(String),

    #[error("intent parse error: {0}")]
    IntentParse(String),
}
