//! Execution engine error types.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Runtime '{0}' is not available on this system")]
    RuntimeNotFound(String),

    #[error("Runtime '{0}' is disabled by execution policy")]
    RuntimeDisabled(String),

    #[error("Execution timed out after {0}ms")]
    Timeout(u64),

    #[error("Execution killed: memory limit exceeded ({0} bytes)")]
    MemoryLimitExceeded(u64),

    #[error("Output limit exceeded: {0} bytes (max {1})")]
    OutputLimitExceeded(usize, usize),

    #[error("Sandbox setup failed: {0}")]
    SandboxError(String),

    #[error("Capability '{0}' denied by execution policy")]
    CapabilityDenied(String),

    #[error("Code contains blocked pattern: {0}")]
    BlockedPattern(String),

    #[error("Process spawn failed: {0}")]
    SpawnFailed(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type ExecutionResult<T> = Result<T, ExecutionError>;
