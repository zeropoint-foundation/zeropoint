//! Core types for the observational memory system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Priority level for an observation, determining retention behavior
/// during reflection (garbage collection) passes.
///
/// Ordered from lowest to highest retention priority so that
/// `Ord` reflects importance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ObservationPriority {
    /// Resolved / finished items — lowest retention priority.
    /// Mastra equivalent: ✅
    Completed,
    /// Background context, preferences, general knowledge.
    /// Mastra equivalent: 🟢
    Low,
    /// Active project details, ongoing work, technical decisions.
    /// Mastra equivalent: 🟡
    Medium,
    /// Critical constraints, blockers, security issues, urgent deadlines.
    /// Mastra equivalent: 🔴
    High,
}

impl ObservationPriority {
    /// Emoji representation matching Mastra's convention.
    pub fn emoji(&self) -> &'static str {
        match self {
            Self::Completed => "✅",
            Self::Low => "🟢",
            Self::Medium => "🟡",
            Self::High => "🔴",
        }
    }

    /// Parse from string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "completed" | "done" | "resolved" => Some(Self::Completed),
            "low" | "background" => Some(Self::Low),
            "medium" | "active" => Some(Self::Medium),
            "high" | "critical" | "urgent" => Some(Self::High),
            _ => None,
        }
    }
}

impl std::fmt::Display for ObservationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed => write!(f, "completed"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

/// Links an observation back to the raw receipts it was derived from.
///
/// When ZeroPoint's receipt chain is active, this enables cryptographic
/// verification: the observation can be checked against the original
/// receipt range by rehashing the source receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRange {
    /// Chain ID of the source receipt chain.
    pub chain_id: String,
    /// Blake3 hash of the first receipt in the range (inclusive).
    pub start_hash: String,
    /// Blake3 hash of the last receipt in the range (inclusive).
    pub end_hash: String,
    /// Sequence number of the first receipt.
    pub start_sequence: u64,
    /// Sequence number of the last receipt.
    pub end_sequence: u64,
    /// Number of source receipts compressed into this observation.
    pub receipt_count: u64,
}

impl SourceRange {
    /// Create a new source range.
    pub fn new(
        chain_id: impl Into<String>,
        start_hash: impl Into<String>,
        end_hash: impl Into<String>,
        start_sequence: u64,
        end_sequence: u64,
    ) -> Self {
        let count = end_sequence.saturating_sub(start_sequence) + 1;
        Self {
            chain_id: chain_id.into(),
            start_hash: start_hash.into(),
            end_hash: end_hash.into(),
            start_sequence,
            end_sequence,
            receipt_count: count,
        }
    }

    /// Compute a deterministic hash of this source range for use as
    /// the observation receipt's `input_hash`.
    pub fn content_hash(&self) -> String {
        let input = format!(
            "{}:{}:{}:{}:{}",
            self.chain_id, self.start_hash, self.end_hash, self.start_sequence, self.end_sequence
        );
        blake3::hash(input.as_bytes()).to_hex().to_string()
    }
}

/// A single compressed observation backed by a receipt.
///
/// Observations are the primary unit of compressed memory. Each distills
/// one or more raw receipts (tool calls, messages, actions) into a concise,
/// prioritized factual statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observation {
    /// Unique ID for this observation (matches the receipt ID).
    pub id: String,
    /// Human-readable observation text.
    pub content: String,
    /// Priority for retention during reflection.
    pub priority: ObservationPriority,
    /// Category for grouping related observations (e.g., "project", "preference").
    pub category: String,
    /// When the observed event(s) actually occurred.
    pub referenced_at: DateTime<Utc>,
    /// When this observation was created.
    pub observed_at: DateTime<Utc>,
    /// Relative time annotation ("2 days ago", "last week").
    pub relative_time: Option<String>,
    /// Hash range of source receipts this observation distills.
    pub source_range: SourceRange,
    /// Whether this observation has been superseded by a reflection.
    pub superseded: bool,
    /// Estimated token count for this observation's content.
    pub token_estimate: usize,
    /// Receipt ID that backs this observation (for chain verification).
    pub receipt_id: Option<String>,
}

impl Observation {
    /// Compute a deterministic content hash for this observation.
    pub fn content_hash(&self) -> String {
        let input = format!(
            "{}:{}:{}:{}",
            self.content,
            self.priority,
            self.category,
            self.referenced_at.to_rfc3339()
        );
        blake3::hash(input.as_bytes()).to_hex().to_string()
    }

    /// Simple token estimation: ~4 chars per token.
    pub fn estimate_tokens(content: &str) -> usize {
        content.len().div_ceil(4)
    }
}

/// A reflection pass that consolidates observations.
///
/// Reflections are the garbage-collection mechanism. When the observation
/// store exceeds the reflection threshold, a Reflector agent merges,
/// upgrades, downgrades, and prunes observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reflection {
    /// Unique ID for this reflection.
    pub id: String,
    /// When this reflection occurred.
    pub reflected_at: DateTime<Utc>,
    /// Observation IDs that were consumed (superseded) by this reflection.
    pub consumed_observation_ids: Vec<String>,
    /// New observations produced by the reflection.
    pub produced_observations: Vec<Observation>,
    /// Observation IDs that were dropped (too low priority, stale).
    pub dropped_observation_ids: Vec<String>,
    /// Total observation tokens before reflection.
    pub tokens_before: usize,
    /// Total observation tokens after reflection.
    pub tokens_after: usize,
    /// Receipt ID that backs this reflection.
    pub receipt_id: Option<String>,
}

impl Reflection {
    /// Compute the compression ratio achieved by this reflection.
    pub fn compression_ratio(&self) -> f64 {
        if self.tokens_before == 0 {
            1.0
        } else {
            self.tokens_after as f64 / self.tokens_before as f64
        }
    }
}

/// Actions the Reflector agent can take on observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "lowercase")]
pub enum ReflectorAction {
    /// Merge multiple observations into one richer observation.
    Merge {
        source_ids: Vec<String>,
        result: ObservationData,
    },
    /// Upgrade an observation's priority.
    Upgrade {
        source_ids: Vec<String>,
        result: ObservationData,
    },
    /// Downgrade an observation's priority.
    Downgrade {
        source_ids: Vec<String>,
        result: ObservationData,
    },
    /// Mark an observation as completed/resolved.
    Complete { source_ids: Vec<String> },
    /// Drop an observation entirely (no longer relevant).
    Drop { source_ids: Vec<String> },
}

/// Data payload for a new or updated observation from the Reflector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationData {
    pub content: String,
    pub priority: ObservationPriority,
    pub category: String,
    pub referenced_at: DateTime<Utc>,
    pub relative_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ordering() {
        assert!(ObservationPriority::High > ObservationPriority::Medium);
        assert!(ObservationPriority::Medium > ObservationPriority::Low);
        assert!(ObservationPriority::Low > ObservationPriority::Completed);
    }

    #[test]
    fn priority_display() {
        assert_eq!(ObservationPriority::High.to_string(), "high");
        assert_eq!(ObservationPriority::Completed.emoji(), "✅");
    }

    #[test]
    fn priority_parse() {
        assert_eq!(
            ObservationPriority::from_str_loose("HIGH"),
            Some(ObservationPriority::High)
        );
        assert_eq!(
            ObservationPriority::from_str_loose("critical"),
            Some(ObservationPriority::High)
        );
        assert_eq!(ObservationPriority::from_str_loose("unknown"), None);
    }

    #[test]
    fn source_range_hash_deterministic() {
        let sr = SourceRange::new("chain-1", "aaa", "bbb", 0, 5);
        let h1 = sr.content_hash();
        let h2 = sr.content_hash();
        assert_eq!(h1, h2);
        assert_eq!(sr.receipt_count, 6);
    }

    #[test]
    fn observation_token_estimate() {
        // "hello world" = 11 chars ≈ 3 tokens
        assert_eq!(Observation::estimate_tokens("hello world"), 3);
        assert_eq!(Observation::estimate_tokens(""), 0);
    }

    #[test]
    fn reflection_compression_ratio() {
        let r = Reflection {
            id: "r1".into(),
            reflected_at: Utc::now(),
            consumed_observation_ids: vec![],
            produced_observations: vec![],
            dropped_observation_ids: vec![],
            tokens_before: 1000,
            tokens_after: 400,
            receipt_id: None,
        };
        assert!((r.compression_ratio() - 0.4).abs() < f64::EPSILON);
    }
}
