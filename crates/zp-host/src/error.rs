//! Error types for the host-function boundary.

use thiserror::Error;

/// Errors from HostContext operations.
#[derive(Debug, Error)]
pub enum HostError {
    /// The governance gate blocked the action before it could be executed.
    ///
    /// The gate decision receipt has already been written to the audit chain
    /// before this error is returned, so the denial is always on-chain.
    #[error("Gate denied: {reason}")]
    GateDenied { reason: String },

    /// The OS rejected the side effect (spawn failed, file write failed,
    /// permission denied, etc.).  The gate allowed the action; this is a
    /// post-gate I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The audit store rejected the receipt append.  The action was NOT
    /// executed — the host treats an unappendable audit chain as fatal for
    /// governed actions (signing-is-gravity: a receipt that can't land means
    /// the action can't be authorized).
    #[error("Audit store rejected receipt: {0}")]
    AuditError(String),

    /// The outbound HTTP call failed (connection error, timeout, etc.).
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
}
