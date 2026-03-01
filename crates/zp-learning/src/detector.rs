//! Pattern detection across episodes for skill discovery and optimization.

use std::collections::HashMap;
use tracing::{debug, info};
use uuid::Uuid;

use zp_core::episode::{Episode, EpisodeId, Pattern};

use crate::store::{EpisodeStore, StoreError};

/// Result type for pattern detection operations.
pub type Result<T> = std::result::Result<T, PatternDetectorError>;

/// Errors that can occur during pattern detection.
#[derive(Debug)]
pub enum PatternDetectorError {
    Store(StoreError),
    Detection(String),
}

impl std::fmt::Display for PatternDetectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatternDetectorError::Store(e) => write!(f, "store error: {}", e),
            PatternDetectorError::Detection(msg) => write!(f, "detection error: {}", msg),
        }
    }
}

impl std::error::Error for PatternDetectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PatternDetectorError::Store(e) => Some(e),
            PatternDetectorError::Detection(_) => None,
        }
    }
}

impl From<StoreError> for PatternDetectorError {
    fn from(err: StoreError) -> Self {
        PatternDetectorError::Store(err)
    }
}

/// Detects patterns across episodes for learning and optimization.
///
/// In Phase 1, this uses simple frequency analysis:
/// - Looks at recent episodes in the same category
/// - Groups by tool sequence
/// - If N or more episodes share the same sequence, creates a pattern
/// - Confidence is based on how consistent the sequences are
pub struct PatternDetector {
    /// Minimum number of episodes required to form a pattern (default: 3)
    min_occurrences: usize,
}

impl PatternDetector {
    /// Creates a new pattern detector with default settings.
    pub fn new() -> Self {
        Self { min_occurrences: 3 }
    }

    /// Creates a pattern detector with a custom minimum occurrence threshold.
    pub fn with_min_occurrences(min_occurrences: usize) -> Self {
        Self { min_occurrences }
    }

    /// Checks if the given episode matches any existing patterns and returns
    /// a new pattern if enough similar episodes are found.
    pub fn check(&self, episode: &Episode, store: &EpisodeStore) -> Result<Option<Pattern>> {
        // Retrieve recent episodes in the same category
        let recent_episodes = store.by_category(&episode.request_category, 100)?;

        if recent_episodes.is_empty() {
            debug!(category = %episode.request_category, "no recent episodes in category");
            return Ok(None);
        }

        // Convert tool calls to tool names for sequence analysis
        let episode_tool_sequence: Vec<String> = episode
            .tools_used
            .iter()
            .map(|tc| tc.tool_name.clone())
            .collect();

        // Group episodes by their tool sequences
        let mut sequence_map: HashMap<Vec<String>, Vec<EpisodeId>> = HashMap::new();

        for recent_episode in &recent_episodes {
            let sequence: Vec<String> = recent_episode
                .tools_used
                .iter()
                .map(|tc| tc.tool_name.clone())
                .collect();

            sequence_map
                .entry(sequence)
                .or_default()
                .push(recent_episode.id.clone());
        }

        // Find if the current episode's sequence meets the threshold
        let matching_episodes = sequence_map.get(&episode_tool_sequence);

        if let Some(matching) = matching_episodes {
            let occurrence_count = matching.len();

            if occurrence_count >= self.min_occurrences {
                // Calculate confidence based on consistency
                // For Phase 1: confidence = occurrence_count / total_episodes * 0.9 (capped at 0.95)
                let total_episodes = recent_episodes.len();
                let raw_confidence = occurrence_count as f64 / total_episodes as f64;
                let confidence = (raw_confidence * 0.9).min(0.95);

                // Build the pattern description
                let tool_names = episode_tool_sequence.join(" -> ");
                let description = format!(
                    "Pattern in {} category: {} tool sequence used {} times",
                    episode.request_category, tool_names, occurrence_count
                );

                let pattern = Pattern {
                    id: Uuid::now_v7().to_string(),
                    episode_ids: matching.clone(),
                    description,
                    tool_sequence: episode_tool_sequence.clone(),
                    confidence,
                    occurrence_count,
                };

                info!(
                    pattern_id = %pattern.id,
                    category = %episode.request_category,
                    occurrences = occurrence_count,
                    confidence = pattern.confidence,
                    "detected pattern"
                );

                return Ok(Some(pattern));
            }
        }

        debug!(
            category = %episode.request_category,
            sequence_len = episode_tool_sequence.len(),
            occurrences = matching_episodes.map(|m| m.len()).unwrap_or(0),
            threshold = self.min_occurrences,
            "tool sequence below threshold"
        );

        Ok(None)
    }

    /// Analyzes all episodes in a given category to find patterns.
    /// Returns all detected patterns that meet the threshold.
    pub fn analyze_category(&self, category: &str, store: &EpisodeStore) -> Result<Vec<Pattern>> {
        let episodes = store.by_category(category, 1000)?;

        if episodes.len() < self.min_occurrences {
            debug!(
                category,
                episode_count = episodes.len(),
                threshold = self.min_occurrences,
                "not enough episodes in category for pattern detection"
            );
            return Ok(vec![]);
        }

        // Group episodes by their tool sequences
        let mut sequence_map: HashMap<Vec<String>, Vec<EpisodeId>> = HashMap::new();

        for episode in &episodes {
            let sequence: Vec<String> = episode
                .tools_used
                .iter()
                .map(|tc| tc.tool_name.clone())
                .collect();

            sequence_map
                .entry(sequence)
                .or_default()
                .push(episode.id.clone());
        }

        // Convert sequences that meet the threshold into patterns
        let mut patterns = Vec::new();

        for (sequence, episode_ids) in sequence_map.iter() {
            if episode_ids.len() >= self.min_occurrences {
                let tool_names = sequence.join(" -> ");
                let raw_confidence = episode_ids.len() as f64 / episodes.len() as f64;
                let confidence = (raw_confidence * 0.9).min(0.95);

                let pattern = Pattern {
                    id: Uuid::now_v7().to_string(),
                    episode_ids: episode_ids.clone(),
                    description: format!(
                        "Pattern in {} category: {} tool sequence used {} times",
                        category,
                        tool_names,
                        episode_ids.len()
                    ),
                    tool_sequence: sequence.clone(),
                    confidence,
                    occurrence_count: episode_ids.len(),
                };

                patterns.push(pattern);
            }
        }

        // Sort by confidence descending
        patterns.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        info!(
            category,
            pattern_count = patterns.len(),
            episode_count = episodes.len(),
            "completed category analysis"
        );

        Ok(patterns)
    }

    /// Gets the minimum occurrence threshold.
    pub fn min_occurrences(&self) -> usize {
        self.min_occurrences
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use zp_core::episode::Outcome;
    use zp_core::types::{ConversationId, ToolCall};

    fn create_test_episode(
        conversation_id: &ConversationId,
        category: &str,
        tools: Vec<&str>,
    ) -> Episode {
        Episode {
            id: EpisodeId::new(),
            conversation_id: conversation_id.clone(),
            timestamp: Utc::now(),
            request_hash: "test_hash".to_string(),
            request_category: category.to_string(),
            tools_used: tools
                .iter()
                .map(|name| ToolCall {
                    tool_name: name.to_string(),
                    arguments: serde_json::json!({}),
                    result: None,
                })
                .collect(),
            active_skills: vec![],
            model_used: "test_model".to_string(),
            outcome: Outcome::Success,
            feedback: None,
            duration_ms: 100,
            policy_decisions: vec![],
        }
    }

    #[test]
    fn test_pattern_detection_threshold() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let detector = PatternDetector::with_min_occurrences(3);
        let conversation_id = ConversationId::new();

        // Create 3 episodes with the same tool sequence
        for _ in 0..3 {
            let episode = create_test_episode(&conversation_id, "search", vec!["query", "parse"]);
            store.record(&episode).unwrap();
        }

        // Check if pattern is detected
        let test_episode = create_test_episode(&conversation_id, "search", vec!["query", "parse"]);
        let pattern = detector.check(&test_episode, &store).unwrap();

        assert!(pattern.is_some());
        let p = pattern.unwrap();
        assert_eq!(p.occurrence_count, 3);
        assert_eq!(p.tool_sequence, vec!["query", "parse"]);
    }

    #[test]
    fn test_pattern_below_threshold() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let detector = PatternDetector::with_min_occurrences(3);
        let conversation_id = ConversationId::new();

        // Create only 2 episodes with the same tool sequence
        for _ in 0..2 {
            let episode = create_test_episode(&conversation_id, "search", vec!["query", "parse"]);
            store.record(&episode).unwrap();
        }

        // Check if pattern is NOT detected
        let test_episode = create_test_episode(&conversation_id, "search", vec!["query", "parse"]);
        let pattern = detector.check(&test_episode, &store).unwrap();

        assert!(pattern.is_none());
    }

    #[test]
    fn test_analyze_category() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let detector = PatternDetector::with_min_occurrences(2);
        let conversation_id = ConversationId::new();

        // Create episodes with different sequences
        for _ in 0..3 {
            let episode = create_test_episode(&conversation_id, "search", vec!["a", "b"]);
            store.record(&episode).unwrap();
        }

        for _ in 0..2 {
            let episode = create_test_episode(&conversation_id, "search", vec!["c", "d"]);
            store.record(&episode).unwrap();
        }

        let patterns = detector.analyze_category("search", &store).unwrap();

        // Should find 2 patterns: (a, b) with 3 occurrences and (c, d) with 2 occurrences
        assert_eq!(patterns.len(), 2);

        // First pattern should be (a, b) with highest confidence
        assert_eq!(patterns[0].tool_sequence, vec!["a", "b"]);
        assert_eq!(patterns[0].occurrence_count, 3);
    }

    #[test]
    fn test_confidence_calculation() {
        let store = EpisodeStore::open(":memory:").unwrap();
        let detector = PatternDetector::with_min_occurrences(3);
        let conversation_id = ConversationId::new();

        // Create 3 episodes with same sequence (60% of 5)
        for _ in 0..3 {
            let episode = create_test_episode(&conversation_id, "test", vec!["x", "y"]);
            store.record(&episode).unwrap();
        }

        // Create 2 different episodes
        let episode2 = create_test_episode(&conversation_id, "test", vec!["a", "b"]);
        store.record(&episode2).unwrap();

        let episode3 = create_test_episode(&conversation_id, "test", vec!["p", "q"]);
        store.record(&episode3).unwrap();

        let test_episode = create_test_episode(&conversation_id, "test", vec!["x", "y"]);
        let pattern = detector.check(&test_episode, &store).unwrap();

        assert!(pattern.is_some());
        let p = pattern.unwrap();

        // Confidence = (3/5) * 0.9 = 0.54
        assert!(p.confidence >= 0.5 && p.confidence <= 0.6);
    }
}
