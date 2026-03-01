//! Skill types — the unit of reusable behavior.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::capability::ToolDefinition;

/// Unique identifier for a skill.
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct SkillId(pub String);

impl SkillId {
    pub fn new(name: &str) -> Self {
        Self(name.to_string())
    }

    pub fn generated() -> Self {
        Self(format!("skill-{}", Uuid::now_v7()))
    }
}

impl std::fmt::Display for SkillId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A skill manifest declares what a skill can do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    /// Human-readable name
    pub name: String,
    /// What this skill does
    pub description: String,
    /// Version
    pub version: String,
    /// Tools this skill provides
    pub tools: Vec<ToolDefinition>,
    /// Credentials this skill requires (resolved at host boundary)
    #[serde(default)]
    pub required_credentials: Vec<String>,
    /// Keywords for skill matching
    #[serde(default)]
    pub keywords: Vec<String>,
    /// Optional prompt template for LLM reasoning
    pub prompt_template: Option<String>,
}

/// Where a skill came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SkillOrigin {
    /// Ships with ZeroPoint
    BuiltIn,
    /// Learned from interaction patterns
    Extracted { episode_ids: Vec<String> },
    /// Community-contributed
    Community { author: String },
    /// Organization-specific
    Enterprise { org_id: String },
}

/// Runtime statistics for a skill.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillStats {
    pub invocation_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub avg_latency_ms: f64,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

impl SkillStats {
    pub fn success_rate(&self) -> f64 {
        if self.invocation_count == 0 {
            return 0.0;
        }
        self.success_count as f64 / self.invocation_count as f64
    }
}

/// A skill candidate proposed by the learning loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillCandidate {
    pub id: SkillId,
    pub manifest: SkillManifest,
    pub origin: SkillOrigin,
    /// How confident the pattern detector is
    pub confidence: f64,
    /// How many episodes contributed to this pattern
    pub episode_count: usize,
    /// Status in the approval pipeline
    pub status: CandidateStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CandidateStatus {
    Proposed,
    UnderReview,
    Approved,
    Rejected { reason: String },
}
