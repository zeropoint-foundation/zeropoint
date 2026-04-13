//! Core types for the memory promotion system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A memory entry tracked through the promotion lifecycle.
///
/// Each memory starts as an observation and may be promoted through
/// increasingly trusted stages, each requiring receipt-backed authorization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Unique identifier for this memory entry.
    pub id: String,

    /// The content of the memory.
    pub content: String,

    /// Category for grouping (inherited from observation).
    pub category: String,

    /// Current promotion stage.
    pub stage: MemoryStage,

    /// The observation ID this memory originated from (if any).
    pub source_observation_id: Option<String>,

    /// Receipt IDs that authorized each stage transition.
    /// Ordered chronologically — last entry is the most recent promotion.
    pub promotion_receipts: Vec<String>,

    /// Confidence score (0.0–1.0), accumulated across observations.
    pub confidence: f64,

    /// How many times this memory has been reinforced across contexts.
    pub reinforcement_count: u32,

    /// When this memory was first created.
    pub created_at: DateTime<Utc>,

    /// When this memory last changed stage.
    pub last_promoted_at: DateTime<Utc>,

    /// When this memory was last reinforced by new evidence.
    pub last_reinforced_at: DateTime<Utc>,

    /// Who reviewed this memory (for Remembered+ stages).
    pub reviewer: Option<String>,

    /// Expiry time based on stage-specific rules (Phase 4.4).
    pub expires_at: Option<DateTime<Utc>>,

    /// Next scheduled review date (Phase 4.4).
    pub review_due_at: Option<DateTime<Utc>>,
}

/// The promotion stage of a memory entry.
///
/// Maps to the doctrine's epistemic trust levels but at the memory
/// (not entity) granularity. Each stage requires a specific receipt type
/// and authority level for promotion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStage {
    /// Raw receipt chain output. No observation yet.
    Transient = 0,
    /// Observer agent distilled receipts into an observation.
    /// Backed by an ObservationClaim receipt.
    Observed = 1,
    /// Reflector agent consolidated observations.
    /// Backed by a ReflectionClaim receipt.
    Interpreted = 2,
    /// Policy engine evaluated and approved.
    /// Backed by a PolicyClaim receipt.
    Trusted = 3,
    /// Promotion engine confirmed cross-context reinforcement.
    /// Backed by a MemoryPromotionClaim receipt with TruthAssertion semantics.
    Remembered = 4,
    /// Human review and operator signature.
    /// Backed by a MemoryPromotionClaim receipt with operator key.
    IdentityBearing = 5,
}

impl MemoryStage {
    /// The receipt type required to reach this stage.
    pub fn required_receipt_type(&self) -> Option<&'static str> {
        match self {
            MemoryStage::Transient => None,
            MemoryStage::Observed => Some("observation_claim"),
            MemoryStage::Interpreted => Some("reflection_claim"),
            MemoryStage::Trusted => Some("policy_claim"),
            MemoryStage::Remembered => Some("memory_promotion_claim"),
            MemoryStage::IdentityBearing => Some("memory_promotion_claim"),
        }
    }

    /// Whether TruthAssertion claim semantics are required.
    pub fn requires_truth_assertion(&self) -> bool {
        matches!(self, MemoryStage::Remembered | MemoryStage::IdentityBearing)
    }

    /// Whether human review is required.
    pub fn requires_human_review(&self) -> bool {
        matches!(self, MemoryStage::IdentityBearing)
    }

    /// Next stage in the promotion path.
    pub fn next(&self) -> Option<MemoryStage> {
        match self {
            MemoryStage::Transient => Some(MemoryStage::Observed),
            MemoryStage::Observed => Some(MemoryStage::Interpreted),
            MemoryStage::Interpreted => Some(MemoryStage::Trusted),
            MemoryStage::Trusted => Some(MemoryStage::Remembered),
            MemoryStage::Remembered => Some(MemoryStage::IdentityBearing),
            MemoryStage::IdentityBearing => None,
        }
    }
}

impl std::fmt::Display for MemoryStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryStage::Transient => write!(f, "transient"),
            MemoryStage::Observed => write!(f, "observed"),
            MemoryStage::Interpreted => write!(f, "interpreted"),
            MemoryStage::Trusted => write!(f, "trusted"),
            MemoryStage::Remembered => write!(f, "remembered"),
            MemoryStage::IdentityBearing => write!(f, "identity_bearing"),
        }
    }
}

/// A request to promote a memory entry to the next stage.
#[derive(Debug, Clone)]
pub struct PromotionRequest {
    /// The memory entry to promote.
    pub memory_id: String,
    /// Target stage (must be one above current).
    pub target_stage: MemoryStage,
    /// Evidence supporting the promotion.
    pub evidence: String,
    /// Who is requesting the promotion (agent or operator key).
    pub requestor: String,
    /// For Remembered+: who reviewed and approved.
    pub reviewer: Option<String>,
}

/// Result of a promotion attempt.
#[derive(Debug, Clone)]
pub enum PromotionResult {
    /// Promotion succeeded. Contains the receipt ID.
    Promoted { receipt_id: String },
    /// Promotion denied with reason.
    Denied { reason: String },
    /// Memory not found.
    NotFound,
}

/// Thresholds for automatic promotion consideration.
#[derive(Debug, Clone)]
pub struct PromotionThresholds {
    /// Minimum confidence to consider for Trusted stage.
    pub trusted_confidence: f64,
    /// Minimum reinforcement count for Remembered stage.
    pub remembered_reinforcement_count: u32,
    /// Minimum confidence for Remembered stage.
    pub remembered_confidence: f64,
}

impl Default for PromotionThresholds {
    fn default() -> Self {
        Self {
            trusted_confidence: 0.7,
            remembered_reinforcement_count: 3,
            remembered_confidence: 0.85,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_ordering() {
        assert!(MemoryStage::IdentityBearing > MemoryStage::Remembered);
        assert!(MemoryStage::Remembered > MemoryStage::Trusted);
        assert!(MemoryStage::Trusted > MemoryStage::Interpreted);
        assert!(MemoryStage::Interpreted > MemoryStage::Observed);
        assert!(MemoryStage::Observed > MemoryStage::Transient);
    }

    #[test]
    fn stage_next() {
        assert_eq!(MemoryStage::Transient.next(), Some(MemoryStage::Observed));
        assert_eq!(MemoryStage::Observed.next(), Some(MemoryStage::Interpreted));
        assert_eq!(MemoryStage::IdentityBearing.next(), None);
    }

    #[test]
    fn truth_assertion_requirements() {
        assert!(!MemoryStage::Observed.requires_truth_assertion());
        assert!(!MemoryStage::Trusted.requires_truth_assertion());
        assert!(MemoryStage::Remembered.requires_truth_assertion());
        assert!(MemoryStage::IdentityBearing.requires_truth_assertion());
    }

    #[test]
    fn human_review_requirements() {
        assert!(!MemoryStage::Remembered.requires_human_review());
        assert!(MemoryStage::IdentityBearing.requires_human_review());
    }
}
