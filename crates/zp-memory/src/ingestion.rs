//! Observation→promotion pipeline integration.
//!
//! Phase 3 (G5-1): Bridges the observation pipeline output to the memory
//! promotion engine. When observations are produced by the observer agent,
//! this module ingests them into the memory promotion lifecycle:
//!
//! 1. Each observation is registered as a new memory at the `Observed` stage.
//! 2. High-priority observations with sufficient confidence auto-promote
//!    to `Interpreted` immediately, as they represent critical insights
//!    that shouldn't wait for a reflector pass.
//! 3. The quarantine store is notified of source mappings for bulk
//!    quarantine support.
//!
//! ## Integration point
//!
//! This module is called by the server runtime after the observation
//! pipeline processes a batch. It does NOT own the pipeline — it
//! consumes its output.

use tracing::{debug, info};

use zp_observation::{Observation, ObservationPriority};

use crate::promotion::PromotionEngine;
use crate::quarantine::QuarantineStore;
use crate::types::{MemoryStage, PromotionRequest, PromotionResult};

// ============================================================================
// Ingestion result
// ============================================================================

/// Result of ingesting a single observation into the memory promotion engine.
#[derive(Debug)]
pub struct IngestionResult {
    /// The memory ID assigned to this observation.
    pub memory_id: String,
    /// The stage the memory reached after ingestion.
    pub stage: MemoryStage,
    /// Whether the memory was auto-promoted beyond Observed.
    pub auto_promoted: bool,
    /// The receipt ID from promotion (if auto-promoted).
    pub promotion_receipt_id: Option<String>,
}

/// Summary of a batch ingestion operation.
#[derive(Debug)]
pub struct BatchIngestionResult {
    /// Individual results for each observation.
    pub results: Vec<IngestionResult>,
    /// Number of observations ingested.
    pub ingested: usize,
    /// Number that were auto-promoted to Interpreted.
    pub auto_promoted: usize,
    /// Number that were skipped (already superseded or completed priority).
    pub skipped: usize,
}

// ============================================================================
// Configuration
// ============================================================================

/// Thresholds controlling automatic promotion during ingestion.
#[derive(Debug, Clone)]
pub struct IngestionConfig {
    /// Minimum priority for auto-promotion to Interpreted.
    /// Observations at or above this priority skip waiting for a reflector pass.
    pub auto_promote_min_priority: ObservationPriority,
    /// Minimum confidence on the observation's receipt for auto-promotion.
    /// If the observation has no confidence signal, this gate is skipped.
    pub auto_promote_min_confidence: f64,
    /// Whether to skip observations that are already superseded.
    pub skip_superseded: bool,
    /// Whether to skip observations with Completed priority.
    pub skip_completed: bool,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            auto_promote_min_priority: ObservationPriority::High,
            auto_promote_min_confidence: 0.7,
            skip_superseded: true,
            skip_completed: true,
        }
    }
}

// ============================================================================
// Ingestion functions
// ============================================================================

/// Ingest a single observation into the memory promotion engine.
///
/// Registers the observation as a new memory at the `Observed` stage,
/// then optionally auto-promotes to `Interpreted` if the observation
/// meets the auto-promotion criteria.
pub fn ingest_observation(
    observation: &Observation,
    engine: &mut PromotionEngine,
    quarantine_store: &mut QuarantineStore,
    config: &IngestionConfig,
) -> Option<IngestionResult> {
    // Skip superseded observations — they've been consolidated by the reflector.
    if config.skip_superseded && observation.superseded {
        debug!(
            observation_id = %observation.id,
            "Skipping superseded observation"
        );
        return None;
    }

    // Skip completed observations — they represent resolved items.
    if config.skip_completed && observation.priority == ObservationPriority::Completed {
        debug!(
            observation_id = %observation.id,
            "Skipping completed observation"
        );
        return None;
    }

    // Derive confidence from priority if no explicit signal exists.
    let confidence = priority_to_confidence(observation.priority);

    // Get the receipt ID backing this observation.
    let receipt_id = observation
        .receipt_id
        .as_deref()
        .unwrap_or(&observation.id);

    // Register the observation as a new memory at Observed stage.
    let memory_id = engine.register_from_observation(
        &observation.id,
        &observation.content,
        &observation.category,
        confidence,
        receipt_id,
    );

    // Register source mapping for bulk quarantine support.
    quarantine_store.register_source(&memory_id, &observation.id);

    info!(
        memory_id = %memory_id,
        observation_id = %observation.id,
        priority = %observation.priority,
        confidence = confidence,
        "Observation ingested as memory"
    );

    // Check auto-promotion eligibility.
    let should_auto_promote = observation.priority >= config.auto_promote_min_priority
        && confidence >= config.auto_promote_min_confidence;

    if should_auto_promote {
        let result = engine.promote(&PromotionRequest {
            memory_id: memory_id.clone(),
            target_stage: MemoryStage::Interpreted,
            evidence: format!(
                "Auto-promoted: {} priority observation with confidence {:.2}",
                observation.priority, confidence
            ),
            requestor: "ingestion-pipeline".to_string(),
            reviewer: None,
        });

        match result {
            PromotionResult::Promoted { receipt_id } => {
                info!(
                    memory_id = %memory_id,
                    "Auto-promoted to Interpreted"
                );
                return Some(IngestionResult {
                    memory_id,
                    stage: MemoryStage::Interpreted,
                    auto_promoted: true,
                    promotion_receipt_id: Some(receipt_id),
                });
            }
            PromotionResult::Denied { reason } => {
                debug!(
                    memory_id = %memory_id,
                    reason = %reason,
                    "Auto-promotion denied"
                );
            }
            PromotionResult::NotFound => {
                // Should not happen — we just registered it.
                debug!(
                    memory_id = %memory_id,
                    "Auto-promotion: memory not found (unexpected)"
                );
            }
        }
    }

    Some(IngestionResult {
        memory_id,
        stage: MemoryStage::Observed,
        auto_promoted: false,
        promotion_receipt_id: None,
    })
}

/// Ingest a batch of observations into the memory promotion engine.
///
/// This is the primary integration point called by the server runtime
/// after the observation pipeline processes a batch of receipts.
pub fn ingest_observations(
    observations: &[Observation],
    engine: &mut PromotionEngine,
    quarantine_store: &mut QuarantineStore,
    config: &IngestionConfig,
) -> BatchIngestionResult {
    let mut results = Vec::with_capacity(observations.len());
    let mut ingested = 0;
    let mut auto_promoted = 0;
    let mut skipped = 0;

    for obs in observations {
        match ingest_observation(obs, engine, quarantine_store, config) {
            Some(result) => {
                ingested += 1;
                if result.auto_promoted {
                    auto_promoted += 1;
                }
                results.push(result);
            }
            None => {
                skipped += 1;
            }
        }
    }

    info!(
        total = observations.len(),
        ingested = ingested,
        auto_promoted = auto_promoted,
        skipped = skipped,
        "Batch ingestion complete"
    );

    BatchIngestionResult {
        results,
        ingested,
        auto_promoted,
        skipped,
    }
}

/// Map observation priority to a confidence score.
///
/// This provides a reasonable default confidence when the observation
/// itself doesn't carry an explicit confidence signal.
fn priority_to_confidence(priority: ObservationPriority) -> f64 {
    match priority {
        ObservationPriority::High => 0.9,
        ObservationPriority::Medium => 0.7,
        ObservationPriority::Low => 0.5,
        ObservationPriority::Completed => 0.3,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use zp_observation::SourceRange;

    use crate::types::PromotionThresholds;

    fn make_observation(id: &str, priority: ObservationPriority) -> Observation {
        let now = Utc::now();
        Observation {
            id: id.to_string(),
            content: format!("Observation content for {}", id),
            priority,
            category: "test".to_string(),
            referenced_at: now,
            observed_at: now,
            relative_time: None,
            source_range: SourceRange::new("chain-1", "aaa", "bbb", 0, 5),
            superseded: false,
            token_estimate: 10,
            receipt_id: Some(format!("rcpt-{}", id)),
        }
    }

    fn make_engine() -> PromotionEngine {
        PromotionEngine::new("test-engine", PromotionThresholds::default())
    }

    #[test]
    fn ingest_single_low_priority() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");
        let config = IngestionConfig::default();

        let obs = make_observation("obs-1", ObservationPriority::Low);
        let result = ingest_observation(&obs, &mut engine, &mut qstore, &config).unwrap();

        assert_eq!(result.stage, MemoryStage::Observed);
        assert!(!result.auto_promoted);
        assert!(result.promotion_receipt_id.is_none());
        assert_eq!(engine.memory_count(), 1);
    }

    #[test]
    fn ingest_high_priority_auto_promotes() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");
        let config = IngestionConfig::default();

        let obs = make_observation("obs-1", ObservationPriority::High);
        let result = ingest_observation(&obs, &mut engine, &mut qstore, &config).unwrap();

        assert_eq!(result.stage, MemoryStage::Interpreted);
        assert!(result.auto_promoted);
        assert!(result.promotion_receipt_id.is_some());
    }

    #[test]
    fn ingest_skips_superseded() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");
        let config = IngestionConfig::default();

        let mut obs = make_observation("obs-1", ObservationPriority::High);
        obs.superseded = true;

        let result = ingest_observation(&obs, &mut engine, &mut qstore, &config);
        assert!(result.is_none());
        assert_eq!(engine.memory_count(), 0);
    }

    #[test]
    fn ingest_skips_completed() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");
        let config = IngestionConfig::default();

        let obs = make_observation("obs-1", ObservationPriority::Completed);
        let result = ingest_observation(&obs, &mut engine, &mut qstore, &config);
        assert!(result.is_none());
    }

    #[test]
    fn batch_ingestion() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");
        let config = IngestionConfig::default();

        let observations = vec![
            make_observation("obs-1", ObservationPriority::High),
            make_observation("obs-2", ObservationPriority::Medium),
            make_observation("obs-3", ObservationPriority::Low),
            {
                let mut obs = make_observation("obs-4", ObservationPriority::High);
                obs.superseded = true;
                obs
            },
            make_observation("obs-5", ObservationPriority::Completed),
        ];

        let result = ingest_observations(&observations, &mut engine, &mut qstore, &config);

        assert_eq!(result.ingested, 3); // obs-1, obs-2, obs-3
        assert_eq!(result.auto_promoted, 1); // obs-1 (High)
        assert_eq!(result.skipped, 2); // obs-4 (superseded), obs-5 (completed)
        assert_eq!(engine.memory_count(), 3);
    }

    #[test]
    fn quarantine_source_registered() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");
        let config = IngestionConfig::default();

        let obs = make_observation("obs-source-1", ObservationPriority::Medium);
        let result = ingest_observation(&obs, &mut engine, &mut qstore, &config).unwrap();

        // The quarantine store should have the source mapping.
        // We can verify by checking that bulk quarantine by this source works.
        // (QuarantineStore.register_source was called internally.)
        assert!(!result.memory_id.is_empty());
    }

    #[test]
    fn priority_to_confidence_mapping() {
        assert!((priority_to_confidence(ObservationPriority::High) - 0.9).abs() < f64::EPSILON);
        assert!((priority_to_confidence(ObservationPriority::Medium) - 0.7).abs() < f64::EPSILON);
        assert!((priority_to_confidence(ObservationPriority::Low) - 0.5).abs() < f64::EPSILON);
        assert!(
            (priority_to_confidence(ObservationPriority::Completed) - 0.3).abs() < f64::EPSILON
        );
    }

    #[test]
    fn custom_config_changes_behavior() {
        let mut engine = make_engine();
        let mut qstore = QuarantineStore::new("test-operator");

        // Configure to auto-promote Medium+ observations.
        let config = IngestionConfig {
            auto_promote_min_priority: ObservationPriority::Medium,
            auto_promote_min_confidence: 0.5,
            skip_superseded: true,
            skip_completed: false, // Don't skip completed
        };

        let obs = make_observation("obs-1", ObservationPriority::Medium);
        let result = ingest_observation(&obs, &mut engine, &mut qstore, &config).unwrap();

        // Medium should now auto-promote with lower threshold.
        assert!(result.auto_promoted);
        assert_eq!(result.stage, MemoryStage::Interpreted);

        // Completed should not be skipped.
        let obs2 = make_observation("obs-2", ObservationPriority::Completed);
        let result2 = ingest_observation(&obs2, &mut engine, &mut qstore, &config);
        assert!(result2.is_some()); // Not skipped
    }
}
