//! Execution receipts — cryptographic proof of what ran, what it produced,
//! and the environment it ran in.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Immutable receipt for a single code execution.
/// Every execution produces one of these, regardless of success or failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionReceipt {
    /// Unique receipt ID
    pub receipt_id: Uuid,

    /// ID of the execution request that produced this receipt
    pub request_id: String,

    /// Agent that requested this execution (for audit trail)
    pub agent_id: String,

    /// Runtime that executed the code
    pub runtime: String,

    /// Blake3 hash of the input (code + arguments)
    pub input_hash: String,

    /// Blake3 hash of the output (stdout + stderr + exit_code)
    pub output_hash: String,

    /// Exit code of the process
    pub exit_code: i32,

    /// Whether execution completed successfully (exit_code == 0 and no timeout)
    pub success: bool,

    /// Execution timing
    pub timing: ExecutionTiming,

    /// Resource usage
    pub resources: ResourceUsage,

    /// Reference to the deployment receipt that attested the runtime environment.
    /// If None, the engine is running in bare-process mode (no deployment receipt).
    pub deployment_receipt_id: Option<Uuid>,

    /// Timestamp when execution completed
    pub completed_at: DateTime<Utc>,

    /// Overall receipt hash — Blake3 of all fields above, sorted canonically.
    /// This hash can be anchored in the receipt chain.
    pub receipt_hash: String,
}

/// Execution timing breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTiming {
    /// Wall clock time in milliseconds
    pub wall_ms: u64,
    /// Queue wait time (time between request and process start)
    pub queue_ms: u64,
    /// Time to first output byte
    pub first_output_ms: Option<u64>,
}

/// Resource usage metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Peak resident set size in bytes (if measurable)
    pub peak_memory_bytes: Option<u64>,
    /// Stdout bytes produced
    pub stdout_bytes: usize,
    /// Stderr bytes produced
    pub stderr_bytes: usize,
    /// Files written to sandbox (count)
    pub files_written: u32,
    /// Total bytes written to sandbox filesystem
    pub bytes_written: u64,
}

impl ExecutionReceipt {
    /// Compute the canonical receipt hash from all fields.
    ///
    /// Fields are sorted alphabetically by key to ensure deterministic ordering.
    /// The `agent_id` is included so the audit trail is tamper-evident.
    pub fn compute_hash(&self) -> String {
        let canonical = format!(
            "agent_id={}\ncompleted_at={}\ndeployment_receipt_id={}\nexit_code={}\ninput_hash={}\noutput_hash={}\nreceipt_id={}\nrequest_id={}\nruntime={}\nsuccess={}\ntiming.wall_ms={}",
            self.agent_id,
            self.completed_at.to_rfc3339(),
            self.deployment_receipt_id.map(|u| u.to_string()).unwrap_or_default(),
            self.exit_code,
            self.input_hash,
            self.output_hash,
            self.receipt_id,
            self.request_id,
            self.runtime,
            self.success,
            self.timing.wall_ms,
        );
        let hash: [u8; 32] = blake3::hash(canonical.as_bytes()).into();
        bytes_to_hex(hash)
    }
}

/// Encode a blake3 hash as a lowercase hex string.
///
/// Shared utility — used by both engine.rs and receipt.rs to avoid duplication.
pub fn bytes_to_hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in &bytes {
        write!(s, "{:02x}", b).ok();
    }
    s
}
