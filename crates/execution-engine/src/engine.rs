//! The execution engine — the top-level API that adaptors call.
//!
//! Usage:
//! ```ignore
//! let engine = ExecutionEngine::new().await?;
//! let result = engine.execute(ExecutionRequest {
//!     runtime: Runtime::Python,
//!     code: "print('hello')".to_string(),
//!     ..Default::default()
//! }).await?;
//! println!("stdout: {}", result.stdout);
//! println!("receipt: {:?}", result.receipt);
//! ```

use crate::error::{ExecutionError, ExecutionResult};
use crate::executor::{self, Runtime};
use crate::receipt::{self, ExecutionReceipt, ExecutionTiming, ResourceUsage};
use crate::sandbox::SandboxConfig;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// A request to execute code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    /// Unique request ID (used to correlate with shim's execution_request)
    pub request_id: String,
    /// Which runtime to use
    pub runtime: Runtime,
    /// The code to execute
    pub code: String,
    /// Optional arguments to pass to the script
    pub args: Vec<String>,
    /// Override sandbox config (None = use engine defaults)
    pub sandbox_override: Option<SandboxConfig>,
    /// Agent that requested this execution (for audit trail)
    pub agent_id: String,
    /// Deployment receipt ID to reference (for environment attestation chain)
    pub deployment_receipt_id: Option<Uuid>,
}

impl Default for ExecutionRequest {
    fn default() -> Self {
        Self {
            request_id: format!(
                "exec-{}",
                Uuid::new_v4().to_string().split('-').next().unwrap_or("x")
            ),
            runtime: Runtime::Python,
            code: String::new(),
            args: vec![],
            sandbox_override: None,
            agent_id: "unknown".to_string(),
            deployment_receipt_id: None,
        }
    }
}

/// The result of an execution — output + receipt.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// Stdout from the execution
    pub stdout: String,
    /// Stderr from the execution
    pub stderr: String,
    /// Exit code
    pub exit_code: i32,
    /// Whether execution completed successfully
    pub success: bool,
    /// Whether execution timed out
    pub timed_out: bool,
    /// Cryptographic receipt for the receipt chain
    pub receipt: ExecutionReceipt,
}

/// Detected runtime info
#[derive(Debug, Clone)]
struct RuntimeInfo {
    version: String,
    path: PathBuf,
}

/// The ZeroPoint Deterministic Execution Engine.
///
/// This replaces Docker as the execution boundary for agentic frameworks.
/// It manages runtime detection, sandbox lifecycle, and receipt generation.
pub struct ExecutionEngine {
    /// Detected runtimes on this host
    runtimes: HashMap<Runtime, RuntimeInfo>,
    /// Default sandbox config
    default_config: SandboxConfig,
    /// Total executions counter
    execution_count: Arc<Mutex<u64>>,
    /// Execution history (for debugging, bounded)
    recent_receipts: Arc<Mutex<Vec<ExecutionReceipt>>>,
}

impl ExecutionEngine {
    /// Initialize the engine by detecting available runtimes.
    pub async fn new() -> ExecutionResult<Self> {
        let detected = executor::detect_runtimes().await;

        let mut runtimes = HashMap::new();
        for (runtime, version, path) in &detected {
            tracing::info!(
                "Execution engine: detected {} {} at {}",
                runtime.as_str(),
                version,
                path.display()
            );
            runtimes.insert(
                *runtime,
                RuntimeInfo {
                    version: version.clone(),
                    path: path.clone(),
                },
            );
        }

        if runtimes.is_empty() {
            tracing::warn!(
                "Execution engine: no runtimes detected — engine will be non-functional"
            );
        }

        Ok(Self {
            runtimes,
            default_config: SandboxConfig::default(),
            execution_count: Arc::new(Mutex::new(0)),
            recent_receipts: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Create with a custom default sandbox config.
    pub async fn with_config(config: SandboxConfig) -> ExecutionResult<Self> {
        let mut engine = Self::new().await?;
        engine.default_config = config;
        Ok(engine)
    }

    /// Check if a runtime is available.
    pub fn has_runtime(&self, runtime: Runtime) -> bool {
        self.runtimes.contains_key(&runtime)
    }

    /// Get all available runtimes.
    pub fn available_runtimes(&self) -> Vec<Runtime> {
        self.runtimes.keys().copied().collect()
    }

    /// Execute code and return the result with a receipt.
    ///
    /// This is the primary entry point. It:
    /// 1. Validates the runtime is available
    /// 2. Creates a sandbox directory
    /// 3. Executes the code
    /// 4. Generates a receipt
    /// 5. Cleans up the sandbox
    pub async fn execute(&self, request: ExecutionRequest) -> ExecutionResult<ExecOutcome> {
        let runtime_info = self
            .runtimes
            .get(&request.runtime)
            .ok_or_else(|| ExecutionError::RuntimeNotFound(request.runtime.as_str().to_string()))?;

        let config = request
            .sandbox_override
            .as_ref()
            .unwrap_or(&self.default_config);

        // Compute input hash before execution
        let input_canonical = format!(
            "code={}\nruntime={}\nargs={:?}",
            request.code,
            request.runtime.as_str(),
            request.args
        );
        let input_hash: [u8; 32] = blake3::hash(input_canonical.as_bytes()).into();
        let input_hash_hex = receipt::bytes_to_hex(input_hash);

        // Create sandbox directory
        let sandbox = tempfile::TempDir::new().map_err(|e| {
            ExecutionError::SandboxError(format!("Failed to create sandbox dir: {}", e))
        })?;

        tracing::info!(
            "Executing {} code in sandbox {} (request={})",
            request.runtime.as_str(),
            sandbox.path().display(),
            request.request_id,
        );

        let queue_start = std::time::Instant::now();

        // Execute
        let exec_result = executor::execute_sandboxed(
            request.runtime,
            &request.code,
            sandbox.path(),
            &runtime_info.path,
            config,
        )
        .await;

        // Generate receipt regardless of success/failure
        let receipt_id = Uuid::new_v4();
        let completed_at = Utc::now();

        match exec_result {
            Ok(output) => {
                // Compute output hash
                let output_canonical = format!(
                    "exit_code={}\nstderr={}\nstdout={}",
                    output.exit_code, output.stderr, output.stdout
                );
                let output_hash: [u8; 32] = blake3::hash(output_canonical.as_bytes()).into();
                let output_hash_hex = receipt::bytes_to_hex(output_hash);

                // Compute queue wait time using saturating subtraction to avoid
                // underflow when wall_ms > elapsed (shouldn't happen, but defensive).
                let elapsed_ms = queue_start.elapsed().as_millis() as u64;
                let queue_ms = elapsed_ms.saturating_sub(output.wall_ms);

                let mut receipt = ExecutionReceipt {
                    receipt_id,
                    request_id: request.request_id.clone(),
                    agent_id: request.agent_id.clone(),
                    runtime: request.runtime.as_str().to_string(),
                    input_hash: input_hash_hex,
                    output_hash: output_hash_hex,
                    exit_code: output.exit_code,
                    success: output.exit_code == 0,
                    timing: ExecutionTiming {
                        wall_ms: output.wall_ms,
                        queue_ms,
                        first_output_ms: None,
                    },
                    resources: ResourceUsage {
                        peak_memory_bytes: None, // TODO: measure via cgroups or /proc
                        stdout_bytes: output.stdout.len(),
                        stderr_bytes: output.stderr.len(),
                        files_written: 0,
                        bytes_written: 0,
                    },
                    deployment_receipt_id: request.deployment_receipt_id,
                    completed_at,
                    receipt_hash: String::new(),
                };
                receipt.receipt_hash = receipt.compute_hash();

                // Track
                {
                    let mut count = self.execution_count.lock().await;
                    *count += 1;
                }
                {
                    let mut receipts = self.recent_receipts.lock().await;
                    receipts.push(receipt.clone());
                    if receipts.len() > 100 {
                        receipts.drain(0..50); // Keep last 50
                    }
                }

                tracing::info!(
                    "Execution complete: request={}, runtime={}, exit_code={}, wall_ms={}, receipt={}",
                    request.request_id,
                    request.runtime.as_str(),
                    output.exit_code,
                    output.wall_ms,
                    &receipt.receipt_hash[..16],
                );

                Ok(ExecOutcome {
                    stdout: output.stdout,
                    stderr: output.stderr,
                    exit_code: output.exit_code,
                    success: output.exit_code == 0,
                    timed_out: output.timed_out,
                    receipt,
                })
            }
            Err(e) => {
                tracing::warn!(
                    "Execution failed: request={}, runtime={}, error={}",
                    request.request_id,
                    request.runtime.as_str(),
                    e,
                );

                // Still produce a receipt for failed executions
                let error_output = format!("ExecutionError: {}", e);
                let output_hash: [u8; 32] = blake3::hash(error_output.as_bytes()).into();

                let mut receipt = ExecutionReceipt {
                    receipt_id,
                    request_id: request.request_id.clone(),
                    agent_id: request.agent_id.clone(),
                    runtime: request.runtime.as_str().to_string(),
                    input_hash: input_hash_hex,
                    output_hash: receipt::bytes_to_hex(output_hash),
                    exit_code: -1,
                    success: false,
                    timing: ExecutionTiming {
                        wall_ms: queue_start.elapsed().as_millis() as u64,
                        queue_ms: 0,
                        first_output_ms: None,
                    },
                    resources: ResourceUsage {
                        peak_memory_bytes: None,
                        stdout_bytes: 0,
                        stderr_bytes: error_output.len(),
                        files_written: 0,
                        bytes_written: 0,
                    },
                    deployment_receipt_id: request.deployment_receipt_id,
                    completed_at,
                    receipt_hash: String::new(),
                };
                receipt.receipt_hash = receipt.compute_hash();

                {
                    let mut count = self.execution_count.lock().await;
                    *count += 1;
                }

                Err(e)
            }
        }
    }

    /// Get total execution count.
    pub async fn execution_count(&self) -> u64 {
        *self.execution_count.lock().await
    }

    /// Get recent execution receipts.
    pub async fn recent_receipts(&self) -> Vec<ExecutionReceipt> {
        self.recent_receipts.lock().await.clone()
    }

    /// Get engine status for health checks and diagnostics.
    pub fn status(&self) -> EngineStatus {
        EngineStatus {
            available: !self.runtimes.is_empty(),
            runtimes: self
                .runtimes
                .iter()
                .map(|(rt, info)| (*rt, info.version.clone()))
                .collect(),
            total_executions: 0, // Sync snapshot — use execution_count() for async
        }
    }
}

/// Engine status snapshot (sync-safe, no locks).
#[derive(Debug, Clone)]
pub struct EngineStatus {
    /// Whether the engine has at least one runtime available
    pub available: bool,
    /// Detected runtimes and their versions
    pub runtimes: Vec<(Runtime, String)>,
    /// Total executions (note: sync snapshot, may be stale)
    pub total_executions: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_engine_initialization() {
        let engine = ExecutionEngine::new().await.unwrap();
        // Should detect at least one runtime in most environments
        let runtimes = engine.available_runtimes();
        tracing::info!("Detected runtimes: {:?}", runtimes);
        // Don't assert specific runtimes — depends on host
    }
}
