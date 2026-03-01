//! Core types matching the receipt.schema.json specification.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Version of the receipt schema.
pub const RECEIPT_SCHEMA_VERSION: &str = "1.0.0";

// ============================================================================
// Receipt — the top-level type
// ============================================================================

/// Portable, cryptographically verifiable proof of execution.
///
/// This is the fundamental trust primitive of the ZeroPoint protocol.
/// Every action — code execution, API call, payment, content access — produces
/// a Receipt that can be independently verified by any party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Unique identifier (prefixed: rcpt-, intn-, dsgn-, appr-)
    pub id: String,

    /// Schema version for forward compatibility
    pub version: String,

    /// Stage in the provenance chain
    pub receipt_type: ReceiptType,

    /// Parent receipt in the provenance chain (None for intent receipts)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,

    /// Outcome of the action
    pub status: Status,

    /// Blake3 hash of the canonical JSON body (all fields except signature)
    pub content_hash: String,

    /// Ed25519 signature over content_hash (base64)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Public key of the signer (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_public_key: Option<String>,

    /// Assurance level
    pub trust_grade: TrustGrade,

    /// When this receipt was created
    pub created_at: DateTime<Utc>,

    /// Who performed the action
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor: Option<Executor>,

    /// What was done
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,

    /// Timing information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timing: Option<Timing>,

    /// Resource consumption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<Resources>,

    /// Artifacts produced
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outputs: Option<Vec<OutputArtifact>>,

    /// I/O stream hashes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_hashes: Option<IoHashes>,

    /// Policy evaluation result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyDecision>,

    /// Error details (if failed/denied/timeout)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorDetail>,

    /// Redacted fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redactions: Option<Vec<Redaction>>,

    /// Hash-chain linkage metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<ChainMetadata>,

    /// Vendor/domain extensions (reverse-domain keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<HashMap<String, serde_json::Value>>,
}

impl Receipt {
    /// Start building an execution receipt.
    pub fn execution(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Execution, executor_id)
    }

    /// Start building an intent receipt (root of chain).
    pub fn intent(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Intent, executor_id)
    }

    /// Start building a design receipt.
    pub fn design(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Design, executor_id)
    }

    /// Start building an approval receipt.
    pub fn approval(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Approval, executor_id)
    }

    /// Start building a payment receipt.
    pub fn payment(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Payment, executor_id)
    }

    /// Start building an access receipt.
    pub fn access(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::Access, executor_id)
    }

    /// Verify the content_hash matches the receipt body.
    pub fn verify_hash(&self) -> bool {
        let computed = crate::canonical_hash(self);
        computed == self.content_hash
    }

    /// Verify the Ed25519 signature.
    #[cfg(feature = "signing")]
    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<bool, String> {
        crate::Signer::verify_receipt(self, public_key)
    }

    /// Check if this receipt is the root of a chain.
    pub fn is_root(&self) -> bool {
        self.receipt_type == ReceiptType::Intent && self.parent_receipt_id.is_none()
    }

    /// Check if the action succeeded.
    pub fn is_success(&self) -> bool {
        self.status == Status::Success
    }
}

// ============================================================================
// Enums
// ============================================================================

/// The stage in the provenance chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptType {
    /// User's original request (root of chain)
    Intent,
    /// Plan created to fulfill the intent
    Design,
    /// Authorization decision
    Approval,
    /// Actual execution and results
    Execution,
    /// Financial transaction (agent web extension)
    Payment,
    /// Content/API access (agent web extension)
    Access,
}

impl ReceiptType {
    /// Returns the ID prefix for this receipt type.
    pub fn id_prefix(&self) -> &'static str {
        match self {
            ReceiptType::Intent => "intn",
            ReceiptType::Design => "dsgn",
            ReceiptType::Approval => "appr",
            ReceiptType::Execution => "rcpt",
            ReceiptType::Payment => "pymt",
            ReceiptType::Access => "accs",
        }
    }

    /// Returns the expected parent type in a standard chain.
    pub fn expected_parent(&self) -> Option<ReceiptType> {
        match self {
            ReceiptType::Intent => None,
            ReceiptType::Design => Some(ReceiptType::Intent),
            ReceiptType::Approval => Some(ReceiptType::Design),
            ReceiptType::Execution => Some(ReceiptType::Approval),
            ReceiptType::Payment => Some(ReceiptType::Execution),
            ReceiptType::Access => Some(ReceiptType::Approval),
        }
    }
}

impl std::fmt::Display for ReceiptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptType::Intent => write!(f, "intent"),
            ReceiptType::Design => write!(f, "design"),
            ReceiptType::Approval => write!(f, "approval"),
            ReceiptType::Execution => write!(f, "execution"),
            ReceiptType::Payment => write!(f, "payment"),
            ReceiptType::Access => write!(f, "access"),
        }
    }
}

/// Outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Success,
    Partial,
    Failed,
    Denied,
    Timeout,
    Pending,
}

/// Assurance level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TrustGrade {
    /// Signed receipt only
    #[default]
    D,
    /// Sandboxed execution (container/VM/jail)
    C,
    /// Hardware key + OS integrity
    B,
    /// TEE with hardware root of trust
    A,
}

/// Type of executor entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutorType {
    Agent,
    Human,
    Service,
    Pipeline,
    Role,
}

/// Category of action performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    CodeExecution,
    ShellCommand,
    ToolCall,
    ApiRequest,
    FileOperation,
    Payment,
    ContentAccess,
    Delegation,
    PolicyEvaluation,
    PlanCreation,
    ApprovalDecision,
}

/// Policy evaluation decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Escalate,
    AuditOnly,
}

/// Trust tier for policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTier {
    Tier0,
    Tier1,
    Tier2,
}

/// Type of redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionType {
    Credential,
    Pii,
    Secret,
    SensitiveOutput,
}

// ============================================================================
// Nested structs
// ============================================================================

/// Identity of the entity that performed the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Executor {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executor_type: Option<ExecutorType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
}

/// Description of the action performed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

impl Action {
    /// Convenience: code execution action.
    pub fn code_execution(runtime: &str, exit_code: i32) -> Self {
        Self {
            action_type: ActionType::CodeExecution,
            name: Some(runtime.to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: Some(exit_code),
            detail: None,
        }
    }

    /// Convenience: shell command action.
    pub fn shell_command(command_hash: &str, exit_code: i32) -> Self {
        Self {
            action_type: ActionType::ShellCommand,
            name: Some("shell".to_string()),
            input_hash: Some(command_hash.to_string()),
            output_hash: None,
            exit_code: Some(exit_code),
            detail: None,
        }
    }

    /// Convenience: tool call action.
    pub fn tool_call(tool_name: &str) -> Self {
        Self {
            action_type: ActionType::ToolCall,
            name: Some(tool_name.to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: None,
        }
    }

    /// Convenience: payment action.
    pub fn payment(amount_usd: f64, recipient: &str) -> Self {
        Self {
            action_type: ActionType::Payment,
            name: Some("payment".to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: Some(serde_json::json!({
                "amount_usd": amount_usd,
                "recipient": recipient,
            })),
        }
    }

    /// Convenience: API access action.
    pub fn api_request(endpoint: &str, method: &str) -> Self {
        Self {
            action_type: ActionType::ApiRequest,
            name: Some(endpoint.to_string()),
            input_hash: None,
            output_hash: None,
            exit_code: None,
            detail: Some(serde_json::json!({ "method": method })),
        }
    }
}

/// Timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timing {
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued_ms: Option<u64>,
}

/// Resource consumption.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_seconds: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_peak_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_written_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_bytes_received: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_input: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_output: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
}

/// Output artifact with integrity hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputArtifact {
    pub path: String,
    pub hash: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Hashes of I/O streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoHashes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_size: Option<u64>,
}

/// Policy evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<TrustTier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// Error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub recoverable: bool,
}

/// Redaction record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction_type: Option<RedactionType>,
    pub target: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_hash: Option<String>,
}

/// Hash-chain linkage metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
}
