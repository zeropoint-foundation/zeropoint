//! Core vocabulary types used across ZeroPoint v2.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a conversation.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConversationId(pub Uuid);

impl ConversationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for ConversationId {
    fn default() -> Self {
        Self::new()
    }
}

/// Unique identifier for a message within a conversation.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageId(pub Uuid);

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

/// A request from the interface layer into the deterministic core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: MessageId,
    pub conversation_id: ConversationId,
    pub content: String,
    pub channel: Channel,
    pub timestamp: DateTime<Utc>,
    pub metadata: RequestMetadata,
}

impl Request {
    pub fn new(conversation_id: ConversationId, content: String, channel: Channel) -> Self {
        Self {
            id: MessageId::new(),
            conversation_id,
            content,
            channel,
            timestamp: Utc::now(),
            metadata: RequestMetadata::default(),
        }
    }
}

/// Where a request originated from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Channel {
    Cli,
    Api,
    Slack { channel_id: String },
    Discord { channel_id: String },
    WebDashboard,
}

/// Optional metadata attached to a request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMetadata {
    /// If the user explicitly requested a specific model
    pub model_override: Option<String>,
    /// Attached files or context
    pub attachments: Vec<Attachment>,
}

/// A file or data attachment on a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub name: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

/// The response from the operator back to the user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub id: MessageId,
    pub conversation_id: ConversationId,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub model_used: String,
    pub timestamp: DateTime<Utc>,
}

/// A tool invocation within a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub result: Option<ToolResult>,
}

/// The result of executing a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub success: bool,
    pub output: serde_json::Value,
    pub receipt: Option<Receipt>,
}

/// Re-export the Receipt type from zp-receipt.
///
/// This is the protocol-level receipt type — a portable, cryptographically
/// verifiable proof that an action was executed. Can be independently
/// verified by any service.
pub type Receipt = zp_receipt::Receipt;

/// Re-export key receipt types for convenience.
pub use zp_receipt::{
    Action as ReceiptAction, ActionType, Executor as ReceiptExecutor, ReceiptChain, ReceiptType,
    ReceiptVerifier, SignatureAlgorithm, SignatureBlock, Signer as ReceiptSigner,
    Status as ReceiptStatus, TrustGrade, VerificationResult,
};

/// A message in conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: MessageId,
    pub conversation_id: ConversationId,
    pub role: MessageRole,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub timestamp: DateTime<Utc>,
}

/// Who sent a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageRole {
    User,
    Operator,
    System,
    Tool,
}

/// The identity of the single operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorIdentity {
    pub name: String,
    pub base_prompt: String,
}

impl Default for OperatorIdentity {
    fn default() -> Self {
        Self {
            name: "ZeroPoint".to_string(),
            base_prompt: concat!(
                "You are ZeroPoint, an AI assistant with access to tools and skills. ",
                "You help users accomplish tasks effectively and safely. ",
                "You have access to whatever tools the current request requires — ",
                "use them as needed to complete the task."
            )
            .to_string(),
        }
    }
}

/// Session context for a single interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub conversation_id: ConversationId,
    pub message_count: usize,
    pub trust_tier: crate::policy::TrustTier,
    pub channel: Channel,
}
