//! Audit trail types — the structural record of everything that happens.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::PolicyDecision;
use crate::types::{ConversationId, Receipt, SignatureBlock};

/// Unique identifier for an audit entry.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditId(pub Uuid);

impl AuditId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for AuditId {
    fn default() -> Self {
        Self::new()
    }
}

/// A single entry in the hash-chained audit trail.
/// Structurally impossible to act without creating one of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: AuditId,
    pub timestamp: DateTime<Utc>,
    /// Hash of the previous entry — the chain link
    pub prev_hash: String,
    /// Hash of this entry (computed over all fields except this one)
    pub entry_hash: String,
    /// Who did this — user, operator, or system
    pub actor: ActorId,
    /// What happened
    pub action: AuditAction,
    /// The conversation this occurred in
    pub conversation_id: ConversationId,
    /// The policy decision that authorized (or blocked) this action
    pub policy_decision: PolicyDecision,
    /// Which policy module made the decision
    pub policy_module: String,
    /// Execution proof, if applicable
    pub receipt: Option<Receipt>,
    /// Signature blocks attesting this entry. Algorithm-agile (mirrors
    /// [`Receipt::signatures`]): each block carries `(algorithm, key_id,
    /// signature_b64)` over the entry hash. Empty before signing; populated
    /// by [`zp_audit::AuditStore::append`] when the store holds a signer.
    /// Canonical ordering (`(algorithm.as_str(), key_id)`) is preserved so
    /// the JSON form is deterministic.
    #[serde(default)]
    pub signatures: Vec<SignatureBlock>,
}

/// Who performed an action.
///
/// `ActorId` is used as a map/set key (e.g. `Guard`'s blocklist, rate limiter).
/// It therefore derives `Hash` + `Eq` and **must not** be keyed by a
/// `format!("{:?}", ...)` string. The prior pattern — hashing Debug output as
/// a canonical identity — is forbidden by `docs/audit-invariant.md` §Non-negotiables.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActorId {
    User(String),
    Operator,
    System(String),
    Skill(String),
}

/// What action was recorded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditAction {
    /// User sent a message
    MessageReceived { content_hash: String },
    /// Operator generated a response
    ResponseGenerated { model: String, content_hash: String },
    /// A tool was invoked
    ToolInvoked {
        tool_name: String,
        arguments_hash: String,
    },
    /// A tool execution completed
    ToolCompleted {
        tool_name: String,
        success: bool,
        output_hash: String,
    },
    /// A credential was injected into a tool call
    CredentialInjected {
        credential_ref: String,
        skill_id: String,
    },
    /// A policy decision was made (Warn acknowledged, Review completed, etc.)
    PolicyInteraction {
        decision_type: String,
        user_response: Option<String>,
    },
    /// Output was sanitized
    OutputSanitized {
        patterns_applied: Vec<String>,
        fields_redacted: usize,
    },
    /// A skill was activated for a request
    SkillActivated { skill_id: String },
    /// A new skill was proposed by the learning loop
    SkillProposed {
        skill_id: String,
        pattern_count: usize,
    },
    /// A skill was approved by a human
    SkillApproved { skill_id: String, approver: String },
    /// System startup/shutdown
    SystemEvent { event: String },
    /// An API call was proxied through ZP governance
    ApiCallProxied {
        provider: String,
        endpoint: String,
        tokens_input: u64,
        tokens_output: u64,
        cost_usd: f64,
    },
}
