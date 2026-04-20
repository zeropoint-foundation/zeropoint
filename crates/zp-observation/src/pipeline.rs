//! Cognition pipeline: Observer/Reflector agent orchestration.
//!
//! Phase 4.2: Integrates the Observer and Reflector agents into the ZeroPoint
//! pipeline as threshold-triggered tasks. The Observer fires when the receipt
//! chain grows past `observation_threshold * (1 - buffer_fraction)`. The
//! Reflector fires when observation tokens exceed `reflection_threshold`.
//!
//! Graceful degradation: if the LLM provider is unavailable, falls back to
//! Tier 1 heuristic extraction (keyword-based observation, no reflection).

use chrono::Utc;
use tracing::{info, warn};

use crate::config::ObservationConfig;
use crate::observer::{build_observer_prompt, parse_observer_output};
use crate::receipts::{generate_observation_receipts, generate_reflection_receipt};
use crate::reflector::{apply_reflector_actions, build_reflector_prompt, parse_reflector_output};
use crate::store::ObservationStore;
use crate::types::{Observation, ObservationPriority, Reflection, SourceRange};
use zp_receipt::Receipt;

// ============================================================================
// Tier 1 heuristic fallback
// ============================================================================

/// Tier 1 heuristic observer: keyword-based observation extraction without LLM.
///
/// This is the graceful degradation path from the `claw-code-rust` bridge
/// pattern. When the LLM provider is unavailable, observations are extracted
/// using simple heuristics: each message becomes a Low-priority observation
/// with the first 100 characters as content.
pub fn tier1_observe(
    messages: &[(String, String)],
    source_range: &SourceRange,
) -> Vec<Observation> {
    let now = Utc::now();
    messages
        .iter()
        .filter(|(_, content)| !content.trim().is_empty())
        .map(|(role, content)| {
            let truncated = if content.len() > 100 {
                format!("{}...", &content[..97])
            } else {
                content.clone()
            };

            Observation {
                id: format!("obs-t1-{}", uuid::Uuid::now_v7()),
                content: truncated.clone(),
                priority: infer_priority(content),
                category: infer_category(role, content),
                referenced_at: now,
                observed_at: now,
                relative_time: Some("just now".to_string()),
                source_range: source_range.clone(),
                superseded: false,
                token_estimate: Observation::estimate_tokens(&truncated),
                receipt_id: None,
            }
        })
        .collect()
}

/// Simple priority inference from content keywords.
fn infer_priority(content: &str) -> ObservationPriority {
    let lower = content.to_lowercase();
    if lower.contains("critical")
        || lower.contains("security")
        || lower.contains("blocker")
        || lower.contains("urgent")
        || lower.contains("vulnerability")
    {
        ObservationPriority::High
    } else if lower.contains("done")
        || lower.contains("completed")
        || lower.contains("resolved")
        || lower.contains("fixed")
    {
        ObservationPriority::Completed
    } else if lower.contains("working on")
        || lower.contains("implementing")
        || lower.contains("added")
        || lower.contains("changed")
    {
        ObservationPriority::Medium
    } else {
        ObservationPriority::Low
    }
}

/// Simple category inference from role and content keywords.
fn infer_category(role: &str, content: &str) -> String {
    let lower = content.to_lowercase();
    if lower.contains("auth") || lower.contains("login") || lower.contains("credential") {
        "auth".to_string()
    } else if lower.contains("test") || lower.contains("assert") {
        "testing".to_string()
    } else if lower.contains("deploy") || lower.contains("release") {
        "deployment".to_string()
    } else if lower.contains("error") || lower.contains("bug") || lower.contains("fix") {
        "debugging".to_string()
    } else if role == "system" || role == "tool" {
        "system".to_string()
    } else {
        "general".to_string()
    }
}

// ============================================================================
// CognitionPipeline — orchestrator
// ============================================================================

/// Result of running the observer.
pub struct ObserverResult {
    /// New observations created.
    pub observations: Vec<Observation>,
    /// Receipts generated for the observations.
    pub receipts: Vec<Receipt>,
    /// Whether the LLM was used (false = Tier 1 fallback).
    pub used_llm: bool,
}

/// Result of running the reflector.
pub struct ReflectorResult {
    /// The reflection record.
    pub reflection: Reflection,
    /// Receipt generated for the reflection.
    pub receipt: Receipt,
}

/// Orchestrates the Observer/Reflector cycle for the cognition plane.
///
/// This struct holds references to the observation store and configuration,
/// and provides methods that the main pipeline calls at the right moments.
/// It does NOT own the LLM — the pipeline passes LLM responses in.
pub struct CognitionPipeline {
    config: ObservationConfig,
    observer_id: String,
    reflector_id: String,
}

impl CognitionPipeline {
    pub fn new(config: ObservationConfig, agent_id: &str) -> Self {
        Self {
            config,
            observer_id: format!("{}-observer", agent_id),
            reflector_id: format!("{}-reflector", agent_id),
        }
    }

    /// Access the configuration.
    pub fn config(&self) -> &ObservationConfig {
        &self.config
    }

    /// Check if the observer should trigger based on current token count.
    pub fn should_observe(&self, current_receipt_tokens: usize) -> bool {
        self.config.should_observe(current_receipt_tokens)
    }

    /// Check if the reflector should trigger based on observation token count.
    pub fn should_reflect(&self, store: &ObservationStore) -> bool {
        let tokens = store.total_token_estimate().unwrap_or(0);
        self.config.should_reflect(tokens)
    }

    /// Run the observer using LLM output.
    ///
    /// The caller is responsible for:
    /// 1. Building the prompt via `observer_prompt()`
    /// 2. Calling the LLM with `OBSERVER_SYSTEM_PROMPT` as system
    /// 3. Passing the LLM response here
    ///
    /// This method parses the output, generates receipts, and stores observations.
    pub fn process_observer_output(
        &self,
        llm_output: &str,
        source_range: &SourceRange,
        store: &ObservationStore,
        chain_parent_receipt_id: Option<&str>,
    ) -> Result<ObserverResult, String> {
        let mut observations = parse_observer_output(llm_output, source_range);

        if observations.is_empty() {
            info!("Observer produced no observations from LLM output");
            return Ok(ObserverResult {
                observations: vec![],
                receipts: vec![],
                used_llm: true,
            });
        }

        let receipts = generate_observation_receipts(
            &mut observations,
            &self.observer_id,
            chain_parent_receipt_id,
        );

        // Store observations.
        for obs in &observations {
            store
                .append(obs)
                .map_err(|e| format!("Failed to store observation: {}", e))?;
        }

        info!(
            count = observations.len(),
            observer = %self.observer_id,
            "Observer produced observations via LLM"
        );

        Ok(ObserverResult {
            observations,
            receipts,
            used_llm: true,
        })
    }

    /// Run the Tier 1 heuristic observer (no LLM required).
    pub fn observe_tier1(
        &self,
        messages: &[(String, String)],
        source_range: &SourceRange,
        store: &ObservationStore,
        chain_parent_receipt_id: Option<&str>,
    ) -> Result<ObserverResult, String> {
        let mut observations = tier1_observe(messages, source_range);

        if observations.is_empty() {
            return Ok(ObserverResult {
                observations: vec![],
                receipts: vec![],
                used_llm: false,
            });
        }

        let receipts = generate_observation_receipts(
            &mut observations,
            &self.observer_id,
            chain_parent_receipt_id,
        );

        for obs in &observations {
            store
                .append(obs)
                .map_err(|e| format!("Failed to store observation: {}", e))?;
        }

        warn!(
            count = observations.len(),
            "Observer fell back to Tier 1 heuristic extraction"
        );

        Ok(ObserverResult {
            observations,
            receipts,
            used_llm: false,
        })
    }

    /// Build the observer prompt for the given messages.
    pub fn observer_prompt(&self, messages: &[(String, String)]) -> String {
        build_observer_prompt(messages)
    }

    /// Build the reflector prompt from the current observation store.
    pub fn reflector_prompt(&self, store: &ObservationStore) -> Result<String, String> {
        let active = store
            .get_active()
            .map_err(|e| format!("Failed to get active observations: {}", e))?;

        if active.is_empty() {
            return Err("No active observations to reflect on".to_string());
        }

        Ok(build_reflector_prompt(&active))
    }

    /// Run the reflector using LLM output.
    ///
    /// The caller is responsible for:
    /// 1. Building the prompt via `reflector_prompt()`
    /// 2. Calling the LLM with `REFLECTOR_SYSTEM_PROMPT` as system
    /// 3. Passing the LLM response here
    ///
    /// This method parses actions, applies them, generates a receipt, and
    /// updates the store.
    pub fn process_reflector_output(
        &self,
        llm_output: &str,
        store: &ObservationStore,
        chain_parent_receipt_id: Option<&str>,
    ) -> Result<ReflectorResult, String> {
        let active = store
            .get_active()
            .map_err(|e| format!("Failed to get active observations: {}", e))?;

        let tokens_before = store.total_token_estimate().unwrap_or(0);

        // Parse reflector actions from LLM output.
        let actions = parse_reflector_output(llm_output);

        if actions.is_empty() {
            return Err("Reflector produced no actions".to_string());
        }

        // Apply actions to produce the state transition.
        let (consumed_ids, produced_observations, dropped_ids) =
            apply_reflector_actions(&active, &actions);

        // Build the Reflection record.
        let reflection_id = format!("rflt-{}", uuid::Uuid::now_v7());
        let tokens_after = produced_observations
            .iter()
            .map(|o| o.token_estimate)
            .sum::<usize>()
            + active
                .iter()
                .filter(|o| !consumed_ids.contains(&o.id) && !dropped_ids.contains(&o.id))
                .map(|o| o.token_estimate)
                .sum::<usize>();

        let reflection = Reflection {
            id: reflection_id,
            reflected_at: Utc::now(),
            consumed_observation_ids: consumed_ids,
            produced_observations,
            dropped_observation_ids: dropped_ids,
            tokens_before,
            tokens_after,
            receipt_id: None,
        };

        // Generate the reflection receipt.
        let receipt =
            generate_reflection_receipt(&reflection, &self.reflector_id, chain_parent_receipt_id);

        // Apply to store: mark consumed/dropped as superseded, insert produced.
        store
            .record_reflection(&reflection)
            .map_err(|e| format!("Failed to record reflection: {}", e))?;

        let ratio = reflection.compression_ratio();
        info!(
            consumed = reflection.consumed_observation_ids.len(),
            produced = reflection.produced_observations.len(),
            dropped_count = reflection.dropped_observation_ids.len(),
            tokens_before,
            tokens_after,
            compression_pct = format!("{:.1}%", ratio * 100.0),
            reflector = %self.reflector_id,
            "Reflector consolidation complete"
        );

        Ok(ReflectorResult {
            reflection,
            receipt,
        })
    }

    /// Get the observer system prompt.
    pub fn observer_system_prompt(&self) -> &'static str {
        crate::OBSERVER_SYSTEM_PROMPT
    }

    /// Get the reflector system prompt.
    pub fn reflector_system_prompt(&self) -> &'static str {
        crate::REFLECTOR_SYSTEM_PROMPT
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_source_range() -> SourceRange {
        SourceRange::new("test-chain", "hash_start", "hash_end", 0, 10)
    }

    fn make_store() -> (ObservationStore, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("obs.db");
        let store = ObservationStore::new(&path).unwrap();
        (store, dir)
    }

    #[test]
    fn tier1_fallback_produces_observations() {
        let messages = vec![
            (
                "user".to_string(),
                "We have a critical security vulnerability in the auth module".to_string(),
            ),
            (
                "assistant".to_string(),
                "I'll fix the authentication bypass immediately".to_string(),
            ),
        ];

        let sr = make_source_range();
        let observations = tier1_observe(&messages, &sr);

        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].priority, ObservationPriority::High); // "critical" + "security" + "vulnerability"
        assert_eq!(observations[0].category, "auth"); // "auth" keyword
    }

    #[test]
    fn tier1_infers_priority_correctly() {
        assert_eq!(
            infer_priority("This is a critical blocker"),
            ObservationPriority::High
        );
        assert_eq!(
            infer_priority("Task completed successfully"),
            ObservationPriority::Completed
        );
        assert_eq!(
            infer_priority("Working on the new feature"),
            ObservationPriority::Medium
        );
        assert_eq!(
            infer_priority("Just some context"),
            ObservationPriority::Low
        );
    }

    #[test]
    fn cognition_pipeline_threshold_checks() {
        let config = ObservationConfig::default();
        let pipeline = CognitionPipeline::new(config.clone(), "test-agent");

        // Default threshold: 30_000 * 0.8 = 24_000
        assert!(!pipeline.should_observe(20_000));
        assert!(pipeline.should_observe(25_000));
    }

    #[test]
    fn observer_processes_llm_output() {
        let (store, _dir) = make_store();
        let pipeline = CognitionPipeline::new(ObservationConfig::default(), "test-agent");
        let sr = make_source_range();

        // Simulate LLM output.
        let llm_output = r#"{"content": "TLS configured on port 8443", "priority": "high", "category": "security", "referenced_at": "2026-04-13T10:00:00Z"}
{"content": "Rate limiter set to 100 req/s", "priority": "medium", "category": "infrastructure", "referenced_at": "2026-04-13T10:01:00Z"}"#;

        let result = pipeline
            .process_observer_output(llm_output, &sr, &store, None)
            .unwrap();

        assert_eq!(result.observations.len(), 2);
        assert_eq!(result.receipts.len(), 2);
        assert!(result.used_llm);

        // Observations should be stored.
        assert_eq!(store.active_count().unwrap(), 2);

        // Each observation should have a receipt ID.
        for obs in &result.observations {
            assert!(obs.receipt_id.is_some());
        }
    }

    #[test]
    fn reflector_consolidates_observations() {
        let (store, _dir) = make_store();
        let pipeline = CognitionPipeline::new(ObservationConfig::default(), "test-agent");
        let sr = make_source_range();

        // Add some observations first.
        let obs1 = Observation {
            id: "obs-1".to_string(),
            content: "Server runs on port 8443".to_string(),
            priority: ObservationPriority::Medium,
            category: "infrastructure".to_string(),
            referenced_at: Utc::now(),
            observed_at: Utc::now(),
            relative_time: None,
            source_range: sr.clone(),
            superseded: false,
            token_estimate: 6,
            receipt_id: None,
        };
        let obs2 = Observation {
            id: "obs-2".to_string(),
            content: "TLS enabled on port 8443".to_string(),
            priority: ObservationPriority::High,
            category: "security".to_string(),
            referenced_at: Utc::now(),
            observed_at: Utc::now(),
            relative_time: None,
            source_range: sr.clone(),
            superseded: false,
            token_estimate: 5,
            receipt_id: None,
        };
        store.append(&obs1).unwrap();
        store.append(&obs2).unwrap();

        // Simulate reflector merging the two.
        let llm_output = r#"{"action": "merge", "source_ids": ["obs-1", "obs-2"], "result": {"content": "Server runs on port 8443 with TLS enabled", "priority": "high", "category": "infrastructure", "referenced_at": "2026-04-13T10:00:00Z"}}"#;

        let result = pipeline
            .process_reflector_output(llm_output, &store, None)
            .unwrap();

        assert!(!result.reflection.consumed_observation_ids.is_empty());
        assert!(!result.reflection.produced_observations.is_empty());
        assert!(result.receipt.id.starts_with("rflt-"));

        // Original observations should be superseded.
        let active = store.get_active().unwrap();
        assert_eq!(active.len(), 1); // Only the merged result remains.
    }
}
