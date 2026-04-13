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
    /// **Canonical preimage (Sweep 1, 2026-04-07):**
    /// The preimage is built via `serde_json::json!` with fields in a fixed
    /// lexicographic order, matching the pattern established by
    /// `zp_audit::chain::compute_entry_hash` and `zp_receipt::hasher::canonical_hash`.
    /// This replaces the previous ad-hoc format-string preimage, which was
    /// fragile (silent hash drift on field reorder) and non-canonical.
    ///
    /// The `receipt_hash` field itself is NEVER included in the preimage —
    /// otherwise the hash would depend on itself.
    pub fn compute_hash(&self) -> String {
        // Build canonical JSON preimage with ordered keys.
        // Field order here is the contract — any change is a breaking
        // hash-schema change and must be versioned.
        let preimage = serde_json::json!({
            "agent_id": self.agent_id,
            "completed_at": self.completed_at.to_rfc3339(),
            "deployment_receipt_id": self.deployment_receipt_id
                .map(|u| u.to_string())
                .unwrap_or_default(),
            "exit_code": self.exit_code,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "receipt_id": self.receipt_id.to_string(),
            "request_id": self.request_id,
            "resources": {
                "bytes_written": self.resources.bytes_written,
                "files_written": self.resources.files_written,
                "peak_memory_bytes": self.resources.peak_memory_bytes,
                "stdout_bytes": self.resources.stdout_bytes,
                "stderr_bytes": self.resources.stderr_bytes,
            },
            "runtime": self.runtime,
            "success": self.success,
            "timing": {
                "first_output_ms": self.timing.first_output_ms,
                "queue_ms": self.timing.queue_ms,
                "wall_ms": self.timing.wall_ms,
            },
        });
        let canonical = serde_json::to_vec(&preimage)
            .expect("canonical JSON serialization of ExecutionReceipt cannot fail");
        let hash: [u8; 32] = blake3::hash(&canonical).into();
        bytes_to_hex(hash)
    }

    /// Verify that `receipt_hash` matches a freshly recomputed hash.
    ///
    /// Callers that read `ExecutionReceipt` from a store (or across the
    /// network) MUST call this before trusting the receipt's contents.
    /// A `false` result indicates either tampering or a hash-schema drift
    /// (e.g. field added to `compute_hash` without re-stamping stored
    /// receipts).
    pub fn verify_hash(&self) -> bool {
        self.compute_hash() == self.receipt_hash
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    fn sample_receipt() -> ExecutionReceipt {
        let mut r = ExecutionReceipt {
            receipt_id: Uuid::nil(),
            request_id: "req-1".into(),
            agent_id: "agent-1".into(),
            runtime: "python".into(),
            input_hash: "i".into(),
            output_hash: "o".into(),
            exit_code: 0,
            success: true,
            timing: ExecutionTiming {
                wall_ms: 10,
                queue_ms: 1,
                first_output_ms: Some(2),
            },
            resources: ResourceUsage {
                peak_memory_bytes: Some(100),
                stdout_bytes: 5,
                stderr_bytes: 0,
                files_written: 0,
                bytes_written: 0,
            },
            deployment_receipt_id: None,
            completed_at: DateTime::parse_from_rfc3339("2026-04-07T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            receipt_hash: String::new(),
        };
        r.receipt_hash = r.compute_hash();
        r
    }

    #[test]
    fn test_compute_hash_is_deterministic() {
        let a = sample_receipt();
        let b = sample_receipt();
        assert_eq!(a.receipt_hash, b.receipt_hash);
    }

    #[test]
    fn test_verify_hash_passes_on_sealed_receipt() {
        let r = sample_receipt();
        assert!(r.verify_hash(), "sealed receipt must self-verify");
    }

    #[test]
    fn test_verify_hash_fails_on_tamper() {
        let mut r = sample_receipt();
        r.exit_code = 1; // tamper
        assert!(!r.verify_hash(), "tampered receipt must NOT verify");
    }

    #[test]
    fn test_roundtrip_preserves_hash() {
        // Serialize → deserialize → recompute → compare.
        // This is the AUDIT-02 regression guard: if Debug-format ever crept
        // back in, the JSON round-trip would re-canonicalize and the hash
        // would drift.
        let r = sample_receipt();
        let json = serde_json::to_string(&r).unwrap();
        let r2: ExecutionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r.receipt_hash, r2.receipt_hash);
        assert!(r2.verify_hash());
        assert_eq!(r2.compute_hash(), r.compute_hash());
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
