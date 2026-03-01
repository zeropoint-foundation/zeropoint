//! Episode types for the learning loop.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::PolicyDecision;
use crate::types::{ConversationId, ToolCall};

/// A recorded episode — one complete interaction cycle.
/// Every interaction is a potential skill input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    pub id: EpisodeId,
    pub conversation_id: ConversationId,
    pub timestamp: DateTime<Utc>,
    /// The user's request (content hash, not raw content for privacy)
    pub request_hash: String,
    /// What request category was detected
    pub request_category: String,
    /// Tools that were used
    pub tools_used: Vec<ToolCall>,
    /// Skills that were active
    pub active_skills: Vec<String>,
    /// Which model handled it
    pub model_used: String,
    /// How it went
    pub outcome: Outcome,
    /// User feedback if any
    pub feedback: Option<Feedback>,
    /// How long it took
    pub duration_ms: u64,
    /// Policy decisions that were made
    pub policy_decisions: Vec<PolicyDecision>,
}

/// Unique identifier for an episode.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpisodeId(pub Uuid);

impl EpisodeId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for EpisodeId {
    fn default() -> Self {
        Self::new()
    }
}

/// How an interaction went.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Outcome {
    Success,
    Failure {
        reason: String,
    },
    Partial {
        completed: Vec<String>,
        failed: Vec<String>,
    },
}

/// User feedback on an interaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feedback {
    pub rating: FeedbackRating,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeedbackRating {
    Positive,
    Negative,
    Correction(String),
}

/// A detected pattern across multiple episodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    pub id: String,
    /// Episodes that contributed to this pattern
    pub episode_ids: Vec<EpisodeId>,
    /// What the pattern describes
    pub description: String,
    /// Common tool sequence
    pub tool_sequence: Vec<String>,
    /// How confident the detector is (0.0 to 1.0)
    pub confidence: f64,
    /// How many times this pattern has occurred
    pub occurrence_count: usize,
}
