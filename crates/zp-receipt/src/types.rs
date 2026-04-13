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

    /// When this receipt expires (None = no expiry).
    /// Execution claims default to 90 days. Memory promotion claims persist indefinitely.
    /// Delegation claims expire with the capability grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Type-specific claim metadata.
    /// Each claim type carries metadata appropriate to its semantics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_metadata: Option<ClaimMetadata>,

    /// The epistemic semantics of the signature on this receipt.
    /// Defaults to AuthorshipProof (I made this) for backward compatibility.
    #[serde(default = "default_claim_semantics")]
    pub claim_semantics: ClaimSemantics,

    /// ID of the receipt that supersedes this one (soft replacement).
    /// The original claim still exists but is no longer the active version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,

    /// Timestamp when this receipt was revoked.
    /// A revoked receipt is permanently invalidated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
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

    /// Start building an observation claim receipt.
    pub fn observation(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::ObservationClaim, executor_id)
    }

    /// Start building a policy claim receipt.
    pub fn policy_claim(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::PolicyClaim, executor_id)
    }

    /// Start building an authorization claim receipt.
    pub fn authorization(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::AuthorizationClaim, executor_id)
    }

    /// Start building a memory promotion claim receipt.
    pub fn memory_promotion(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::MemoryPromotionClaim, executor_id)
    }

    /// Start building a delegation claim receipt.
    pub fn delegation(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::DelegationClaim, executor_id)
    }

    /// Start building a narrative synthesis claim receipt.
    pub fn narrative_synthesis(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::NarrativeSynthesisClaim, executor_id)
    }

    /// Start building a reflection claim receipt.
    pub fn reflection(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::ReflectionClaim, executor_id)
    }

    /// Start building a revocation claim receipt.
    pub fn revocation(executor_id: &str) -> crate::ReceiptBuilder {
        crate::ReceiptBuilder::new(ReceiptType::RevocationClaim, executor_id)
    }

    /// Verify the content_hash matches the receipt body.
    pub fn verify_hash(&self) -> bool {
        let computed = crate::canonical_hash(self);
        computed == self.content_hash
    }

    /// Check if this receipt has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map_or(false, |exp| Utc::now() > exp)
    }

    /// Check if this receipt is still active (not revoked, superseded, or expired).
    pub fn is_active(&self) -> bool {
        !self.is_expired()
            && self.revoked_at.is_none()
            && self.superseded_by.is_none()
    }

    /// Mark this receipt as superseded by another receipt.
    /// The original claim still exists for auditability but `is_active()` returns false.
    pub fn supersede(&mut self, new_receipt_id: &str) {
        self.superseded_by = Some(new_receipt_id.to_string());
    }

    /// Revoke this receipt. Returns a RevocationClaim receipt that should be
    /// appended to the chain as proof of revocation.
    pub fn revoke(
        &mut self,
        revoker_id: &str,
        reason: &str,
    ) -> crate::ReceiptBuilder {
        self.revoked_at = Some(Utc::now());

        Receipt::revocation(revoker_id)
            .parent(&self.id)
            .claim_metadata(ClaimMetadata::Revocation {
                revoked_receipt_id: self.id.clone(),
                reason: reason.to_string(),
                revoker_id: revoker_id.to_string(),
            })
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
///
/// Phase 2.1 adds typed claim variants beyond the original provenance chain.
/// The new claim types carry explicit semantics and type-specific metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptType {
    // --- Original provenance chain types ---
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

    // --- Phase 2.1: Typed claim extensions ---
    /// An observation recorded by an observer agent
    ObservationClaim,
    /// A policy evaluation or constitutional rule invocation
    PolicyClaim,
    /// An authorization decision with explicit scope and constraints
    AuthorizationClaim,
    /// Promotion of knowledge from working memory to long-term memory
    MemoryPromotionClaim,
    /// Delegation of a capability from one agent to another
    DelegationClaim,
    /// Synthesis of multiple observations into a narrative summary
    NarrativeSynthesisClaim,
    /// Revocation of a previously issued receipt
    RevocationClaim,

    // --- Phase 4.1: Cognition plane receipt types ---
    /// A reflection (consolidation pass) over observations by a reflector agent
    ReflectionClaim,
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
            ReceiptType::ObservationClaim => "obsv",
            ReceiptType::PolicyClaim => "plcy",
            ReceiptType::AuthorizationClaim => "auth",
            ReceiptType::MemoryPromotionClaim => "mpro",
            ReceiptType::DelegationClaim => "dlgt",
            ReceiptType::NarrativeSynthesisClaim => "nrtv",
            ReceiptType::RevocationClaim => "revk",
            ReceiptType::ReflectionClaim => "rflt",
        }
    }

    /// Returns the expected parent type in a standard chain.
    ///
    /// The original six types form a strict provenance chain.
    /// The new claim types are more flexible — they can attach to any
    /// existing receipt as context. Returns None when the parent type
    /// is unconstrained (caller must supply a valid parent_receipt_id).
    pub fn expected_parent(&self) -> Option<ReceiptType> {
        match self {
            ReceiptType::Intent => None,
            ReceiptType::Design => Some(ReceiptType::Intent),
            ReceiptType::Approval => Some(ReceiptType::Design),
            ReceiptType::Execution => Some(ReceiptType::Approval),
            ReceiptType::Payment => Some(ReceiptType::Execution),
            ReceiptType::Access => Some(ReceiptType::Approval),
            // Typed claims can reference any receipt as parent
            ReceiptType::ObservationClaim => None,
            ReceiptType::PolicyClaim => None,
            ReceiptType::AuthorizationClaim => None,
            ReceiptType::MemoryPromotionClaim => None,
            ReceiptType::DelegationClaim => None,
            ReceiptType::NarrativeSynthesisClaim => None,
            ReceiptType::RevocationClaim => None,
            ReceiptType::ReflectionClaim => None,
        }
    }

    /// Returns the default expiration duration for this receipt type.
    /// None means the receipt never expires.
    pub fn default_expiry(&self) -> Option<chrono::Duration> {
        match self {
            ReceiptType::Execution => Some(chrono::Duration::days(90)),
            ReceiptType::DelegationClaim => Some(chrono::Duration::days(30)),
            ReceiptType::AuthorizationClaim => Some(chrono::Duration::days(30)),
            // Memory promotion and narrative synthesis persist indefinitely
            ReceiptType::MemoryPromotionClaim => None,
            ReceiptType::NarrativeSynthesisClaim => None,
            // Everything else: no default expiry
            _ => None,
        }
    }

    /// Whether this is one of the original provenance chain types.
    pub fn is_provenance_type(&self) -> bool {
        matches!(
            self,
            ReceiptType::Intent
                | ReceiptType::Design
                | ReceiptType::Approval
                | ReceiptType::Execution
                | ReceiptType::Payment
                | ReceiptType::Access
        )
    }

    /// Whether this is a typed claim extension (Phase 2.1+).
    pub fn is_claim_type(&self) -> bool {
        !self.is_provenance_type()
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
            ReceiptType::ObservationClaim => write!(f, "observation_claim"),
            ReceiptType::PolicyClaim => write!(f, "policy_claim"),
            ReceiptType::AuthorizationClaim => write!(f, "authorization_claim"),
            ReceiptType::MemoryPromotionClaim => write!(f, "memory_promotion_claim"),
            ReceiptType::DelegationClaim => write!(f, "delegation_claim"),
            ReceiptType::NarrativeSynthesisClaim => write!(f, "narrative_synthesis_claim"),
            ReceiptType::RevocationClaim => write!(f, "revocation_claim"),
            ReceiptType::ReflectionClaim => write!(f, "reflection_claim"),
        }
    }
}

/// The epistemic meaning of the signature on a receipt.
///
/// This is a critical semantic distinction introduced in Phase 2.3.
/// Signing a receipt with `AuthorshipProof` semantics proves who created it
/// but does NOT assert that the content is true. Only `TruthAssertion`
/// semantics can be used for memory promotion (Phase 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimSemantics {
    /// "I made this." Proves authorship/origin. Default for all existing receipts.
    AuthorshipProof,
    /// "This hasn't changed." Proves content integrity since a prior state.
    IntegrityAttestation,
    /// "I believe this is true." Required for memory promotion and knowledge claims.
    TruthAssertion,
    /// "I permit this." Used for authorization grants and delegation claims.
    AuthorizationGrant,
}

impl Default for ClaimSemantics {
    fn default() -> Self {
        ClaimSemantics::AuthorshipProof
    }
}

fn default_claim_semantics() -> ClaimSemantics {
    ClaimSemantics::default()
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

// ============================================================================
// Phase 2.1: Typed Claim Metadata
// ============================================================================

/// Type-specific metadata carried by claim receipts.
///
/// Each claim type has distinct validation requirements and semantics.
/// The variant must match the `receipt_type` — e.g. an `ObservationClaim`
/// receipt must carry `ClaimMetadata::Observation`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "claim_type")]
pub enum ClaimMetadata {
    /// Metadata for an observation recorded by an observer agent.
    Observation {
        /// What was observed (e.g., "tool_invocation", "policy_violation")
        observation_type: String,
        /// The agent or system that produced the observation
        observer_id: String,
        /// Confidence level (0.0 - 1.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<f64>,
        /// Tags for categorization
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tags: Vec<String>,
    },

    /// Metadata for a policy evaluation claim.
    Policy {
        /// The policy rule that was evaluated
        rule_id: String,
        /// The constitutional principle, if any
        #[serde(skip_serializing_if = "Option::is_none")]
        principle: Option<String>,
        /// Whether the policy was satisfied
        satisfied: bool,
        /// Explanation of the evaluation
        #[serde(skip_serializing_if = "Option::is_none")]
        rationale: Option<String>,
    },

    /// Metadata for an authorization claim.
    Authorization {
        /// Scope of the authorization (e.g., "tool:launch", "proxy:openai")
        scope: String,
        /// Who granted the authorization
        grantor_id: String,
        /// Constraints on the authorization (e.g., rate limits, time bounds)
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        constraints: HashMap<String, serde_json::Value>,
    },

    /// Metadata for a memory promotion claim.
    MemoryPromotion {
        /// Where the knowledge came from (e.g., "working_memory", "observation")
        source_stage: String,
        /// Where it was promoted to (e.g., "episodic", "semantic", "procedural")
        target_stage: String,
        /// Evidence supporting the promotion
        promotion_evidence: String,
        /// Who reviewed and approved the promotion
        #[serde(skip_serializing_if = "Option::is_none")]
        reviewer: Option<String>,
    },

    /// Metadata for a delegation claim.
    Delegation {
        /// The capability being delegated
        capability_id: String,
        /// Who is delegating
        delegator_id: String,
        /// Who receives the delegation
        delegate_id: String,
        /// Maximum depth of re-delegation allowed (0 = no re-delegation)
        #[serde(default)]
        max_depth: u32,
    },

    /// Metadata for a narrative synthesis claim.
    NarrativeSynthesis {
        /// The observation receipt IDs that were synthesized
        source_observation_ids: Vec<String>,
        /// The synthesis method (e.g., "temporal_summary", "anomaly_report")
        synthesis_method: String,
        /// The agent that performed the synthesis
        synthesizer_id: String,
    },

    /// Metadata for a reflection (consolidation) claim.
    /// Produced by the Reflector agent when it merges/upgrades/downgrades/drops observations.
    Reflection {
        /// IDs of observations consumed (merged, upgraded, downgraded, completed)
        consumed_observation_ids: Vec<String>,
        /// IDs of new observations produced by the consolidation
        produced_observation_ids: Vec<String>,
        /// IDs of observations dropped (pruned entirely)
        dropped_observation_ids: Vec<String>,
        /// Total observation tokens before reflection
        tokens_before: usize,
        /// Total observation tokens after reflection
        tokens_after: usize,
        /// Compression ratio (tokens_after / tokens_before)
        compression_ratio: f64,
        /// The reflector agent that performed the consolidation
        reflector_id: String,
    },

    /// Metadata for a revocation claim.
    Revocation {
        /// The receipt ID being revoked
        revoked_receipt_id: String,
        /// Why it was revoked
        reason: String,
        /// Who authorized the revocation
        revoker_id: String,
    },
}
