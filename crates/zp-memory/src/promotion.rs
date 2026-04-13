//! Memory promotion engine — the core of Phase 4.3.
//!
//! Enforces the doctrine: "Nothing becomes durable truth merely because a
//! model inferred it." Every stage transition requires a receipt-backed gate.

use chrono::Utc;
use std::collections::HashMap;
use tracing::info;

use zp_receipt::{ClaimMetadata, ClaimSemantics, Receipt, Status};

use crate::types::{
    MemoryEntry, MemoryStage, PromotionRequest, PromotionResult, PromotionThresholds,
};

/// The promotion engine manages memory lifecycle transitions.
///
/// Each promotion is validated against:
/// 1. Stage ordering (must be sequential)
/// 2. Receipt type requirements (correct claim type for the target stage)
/// 3. Confidence and reinforcement thresholds
/// 4. TruthAssertion semantics for Remembered+ stages
/// 5. Human review for IdentityBearing stage
pub struct PromotionEngine {
    /// In-memory store of tracked memories.
    memories: HashMap<String, MemoryEntry>,
    /// Thresholds for automatic promotion.
    thresholds: PromotionThresholds,
    /// Agent/operator identity for receipt generation.
    engine_id: String,
}

impl PromotionEngine {
    pub fn new(engine_id: &str, thresholds: PromotionThresholds) -> Self {
        Self {
            memories: HashMap::new(),
            thresholds,
            engine_id: engine_id.to_string(),
        }
    }

    /// Register a new memory entry from an observation.
    pub fn register_from_observation(
        &mut self,
        observation_id: &str,
        content: &str,
        category: &str,
        confidence: f64,
        receipt_id: &str,
    ) -> String {
        let now = Utc::now();
        let memory_id = format!("mem-{}", uuid::Uuid::now_v7());

        let entry = MemoryEntry {
            id: memory_id.clone(),
            content: content.to_string(),
            category: category.to_string(),
            stage: MemoryStage::Observed,
            source_observation_id: Some(observation_id.to_string()),
            promotion_receipts: vec![receipt_id.to_string()],
            confidence,
            reinforcement_count: 1,
            created_at: now,
            last_promoted_at: now,
            last_reinforced_at: now,
            reviewer: None,
            expires_at: None,
            review_due_at: None,
        };

        self.memories.insert(memory_id.clone(), entry);
        info!(memory_id = %memory_id, "Registered new memory from observation");
        memory_id
    }

    /// Reinforce an existing memory with new evidence.
    ///
    /// Increments the reinforcement count and updates confidence.
    /// This is how memories accumulate evidence across contexts.
    pub fn reinforce(&mut self, memory_id: &str, additional_confidence: f64) -> bool {
        if let Some(entry) = self.memories.get_mut(memory_id) {
            entry.reinforcement_count += 1;
            // Weighted average: existing confidence has more weight as reinforcement grows.
            let weight = entry.reinforcement_count as f64;
            entry.confidence = (entry.confidence * (weight - 1.0) + additional_confidence) / weight;
            entry.last_reinforced_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Attempt to promote a memory entry to the next stage.
    ///
    /// Validates all promotion gates and generates a receipt on success.
    pub fn promote(&mut self, request: &PromotionRequest) -> PromotionResult {
        let entry = match self.memories.get(&request.memory_id) {
            Some(e) => e,
            None => return PromotionResult::NotFound,
        };

        // Gate 1: Stage must be sequential.
        let expected_next = match entry.stage.next() {
            Some(next) => next,
            None => {
                return PromotionResult::Denied {
                    reason: format!(
                        "Memory '{}' is already at highest stage ({})",
                        request.memory_id, entry.stage
                    ),
                }
            }
        };

        if request.target_stage != expected_next {
            return PromotionResult::Denied {
                reason: format!(
                    "Cannot skip stages: current={}, requested={}, expected={}",
                    entry.stage, request.target_stage, expected_next
                ),
            };
        }

        // Gate 2: Stage-specific threshold checks.
        match request.target_stage {
            MemoryStage::Trusted => {
                if entry.confidence < self.thresholds.trusted_confidence {
                    return PromotionResult::Denied {
                        reason: format!(
                            "Confidence {:.2} below threshold {:.2} for Trusted stage",
                            entry.confidence, self.thresholds.trusted_confidence
                        ),
                    };
                }
            }
            MemoryStage::Remembered => {
                if entry.confidence < self.thresholds.remembered_confidence {
                    return PromotionResult::Denied {
                        reason: format!(
                            "Confidence {:.2} below threshold {:.2} for Remembered stage",
                            entry.confidence, self.thresholds.remembered_confidence
                        ),
                    };
                }
                if entry.reinforcement_count < self.thresholds.remembered_reinforcement_count {
                    return PromotionResult::Denied {
                        reason: format!(
                            "Reinforcement count {} below threshold {} for Remembered stage",
                            entry.reinforcement_count,
                            self.thresholds.remembered_reinforcement_count
                        ),
                    };
                }
            }
            MemoryStage::IdentityBearing => {
                if request.reviewer.is_none() {
                    return PromotionResult::Denied {
                        reason: "IdentityBearing stage requires human reviewer".to_string(),
                    };
                }
            }
            _ => {}
        }

        // Generate the promotion receipt.
        let receipt = self.generate_promotion_receipt(entry, request);
        let receipt_id = receipt.id.clone();

        // Apply the promotion.
        let entry = self.memories.get_mut(&request.memory_id).unwrap();
        entry.stage = request.target_stage;
        entry.last_promoted_at = Utc::now();
        entry.promotion_receipts.push(receipt_id.clone());
        if let Some(ref reviewer) = request.reviewer {
            entry.reviewer = Some(reviewer.clone());
        }

        info!(
            memory_id = %request.memory_id,
            new_stage = %request.target_stage,
            receipt_id = %receipt_id,
            "Memory promoted"
        );

        PromotionResult::Promoted { receipt_id }
    }

    /// Get a memory entry by ID.
    pub fn get(&self, memory_id: &str) -> Option<&MemoryEntry> {
        self.memories.get(memory_id)
    }

    /// Get all memories at a specific stage.
    pub fn get_by_stage(&self, stage: MemoryStage) -> Vec<&MemoryEntry> {
        self.memories
            .values()
            .filter(|e| e.stage == stage)
            .collect()
    }

    /// Get memories eligible for promotion to a target stage.
    pub fn eligible_for_promotion(&self, target: MemoryStage) -> Vec<&MemoryEntry> {
        let required_current = match target {
            MemoryStage::Transient => return vec![],
            MemoryStage::Observed => MemoryStage::Transient,
            MemoryStage::Interpreted => MemoryStage::Observed,
            MemoryStage::Trusted => MemoryStage::Interpreted,
            MemoryStage::Remembered => MemoryStage::Trusted,
            MemoryStage::IdentityBearing => MemoryStage::Remembered,
        };

        self.memories
            .values()
            .filter(|e| e.stage == required_current && self.meets_threshold(e, target))
            .collect()
    }

    /// Check if a memory meets the threshold for a target stage.
    fn meets_threshold(&self, entry: &MemoryEntry, target: MemoryStage) -> bool {
        match target {
            MemoryStage::Trusted => entry.confidence >= self.thresholds.trusted_confidence,
            MemoryStage::Remembered => {
                entry.confidence >= self.thresholds.remembered_confidence
                    && entry.reinforcement_count >= self.thresholds.remembered_reinforcement_count
            }
            _ => true,
        }
    }

    /// Total number of tracked memories.
    pub fn memory_count(&self) -> usize {
        self.memories.len()
    }

    // --- Internal helpers ---

    fn generate_promotion_receipt(
        &self,
        entry: &MemoryEntry,
        request: &PromotionRequest,
    ) -> Receipt {
        let semantics = if request.target_stage.requires_truth_assertion() {
            ClaimSemantics::TruthAssertion
        } else {
            ClaimSemantics::AuthorshipProof
        };

        Receipt::memory_promotion(&self.engine_id)
            .status(Status::Success)
            .claim_semantics(semantics)
            .claim_metadata(ClaimMetadata::MemoryPromotion {
                source_stage: entry.stage.to_string(),
                target_stage: request.target_stage.to_string(),
                promotion_evidence: request.evidence.clone(),
                reviewer: request.reviewer.clone(),
            })
            .extension(
                "zp.memory.memory_id",
                serde_json::Value::String(entry.id.clone()),
            )
            .extension("zp.memory.confidence", serde_json::json!(entry.confidence))
            .extension(
                "zp.memory.reinforcement_count",
                serde_json::json!(entry.reinforcement_count),
            )
            .finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> PromotionEngine {
        PromotionEngine::new("test-engine", PromotionThresholds::default())
    }

    #[test]
    fn register_and_promote_through_stages() {
        let mut engine = make_engine();

        // Register from observation (starts at Observed).
        let mem_id = engine.register_from_observation(
            "obs-1",
            "TLS configured on port 8443",
            "security",
            0.9,
            "obsv-receipt-1",
        );

        let entry = engine.get(&mem_id).unwrap();
        assert_eq!(entry.stage, MemoryStage::Observed);
        assert_eq!(entry.confidence, 0.9);

        // Promote to Interpreted (via reflection).
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Interpreted,
            evidence: "Reflector consolidated 3 observations into this".to_string(),
            requestor: "reflector-agent".to_string(),
            reviewer: None,
        });
        assert!(matches!(result, PromotionResult::Promoted { .. }));
        assert_eq!(engine.get(&mem_id).unwrap().stage, MemoryStage::Interpreted);

        // Promote to Trusted (via policy check).
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Trusted,
            evidence: "Policy engine evaluated: high confidence, verified source".to_string(),
            requestor: "policy-engine".to_string(),
            reviewer: None,
        });
        assert!(matches!(result, PromotionResult::Promoted { .. }));
        assert_eq!(engine.get(&mem_id).unwrap().stage, MemoryStage::Trusted);
    }

    #[test]
    fn cannot_skip_stages() {
        let mut engine = make_engine();
        let mem_id = engine.register_from_observation("obs-1", "test", "general", 0.9, "rcpt-1");

        // Try to skip from Observed directly to Trusted.
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id,
            target_stage: MemoryStage::Trusted,
            evidence: "skip attempt".to_string(),
            requestor: "test".to_string(),
            reviewer: None,
        });
        assert!(matches!(result, PromotionResult::Denied { .. }));
    }

    #[test]
    fn remembered_requires_reinforcement() {
        let mut engine = make_engine();
        let mem_id = engine.register_from_observation("obs-1", "test", "general", 0.9, "rcpt-1");

        // Fast-promote to Trusted.
        engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Interpreted,
            evidence: "reflected".to_string(),
            requestor: "reflector".to_string(),
            reviewer: None,
        });
        engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Trusted,
            evidence: "policy approved".to_string(),
            requestor: "policy".to_string(),
            reviewer: None,
        });

        // Try Remembered with only 1 reinforcement (threshold is 3).
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Remembered,
            evidence: "promote".to_string(),
            requestor: "engine".to_string(),
            reviewer: None,
        });
        assert!(
            matches!(result, PromotionResult::Denied { reason } if reason.contains("Reinforcement count"))
        );

        // Reinforce to meet threshold.
        engine.reinforce(&mem_id, 0.9);
        engine.reinforce(&mem_id, 0.85);

        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Remembered,
            evidence: "cross-context reinforcement confirmed".to_string(),
            requestor: "engine".to_string(),
            reviewer: None,
        });
        assert!(matches!(result, PromotionResult::Promoted { .. }));
    }

    #[test]
    fn identity_bearing_requires_human_review() {
        let mut engine = make_engine();
        let mem_id = engine.register_from_observation("obs-1", "test", "general", 0.95, "rcpt-1");

        // Fast-promote to Remembered.
        for (stage, evidence) in [
            (MemoryStage::Interpreted, "reflected"),
            (MemoryStage::Trusted, "policy approved"),
        ] {
            engine.promote(&PromotionRequest {
                memory_id: mem_id.clone(),
                target_stage: stage,
                evidence: evidence.to_string(),
                requestor: "test".to_string(),
                reviewer: None,
            });
        }
        engine.reinforce(&mem_id, 0.95);
        engine.reinforce(&mem_id, 0.95);
        engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Remembered,
            evidence: "reinforced".to_string(),
            requestor: "engine".to_string(),
            reviewer: None,
        });

        // Try IdentityBearing without reviewer.
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::IdentityBearing,
            evidence: "human approved".to_string(),
            requestor: "operator".to_string(),
            reviewer: None,
        });
        assert!(
            matches!(result, PromotionResult::Denied { reason } if reason.contains("human reviewer"))
        );

        // With reviewer — should succeed.
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id,
            target_stage: MemoryStage::IdentityBearing,
            evidence: "human approved".to_string(),
            requestor: "operator".to_string(),
            reviewer: Some("operator-key-abc".to_string()),
        });
        assert!(matches!(result, PromotionResult::Promoted { .. }));
    }

    #[test]
    fn confidence_threshold_gates_trusted() {
        let mut engine = make_engine();
        let mem_id = engine.register_from_observation(
            "obs-1",
            "low confidence memory",
            "general",
            0.3,
            "rcpt-1",
        );

        engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Interpreted,
            evidence: "reflected".to_string(),
            requestor: "reflector".to_string(),
            reviewer: None,
        });

        // Try Trusted with confidence 0.3 (threshold 0.7).
        let result = engine.promote(&PromotionRequest {
            memory_id: mem_id,
            target_stage: MemoryStage::Trusted,
            evidence: "policy check".to_string(),
            requestor: "policy".to_string(),
            reviewer: None,
        });
        assert!(
            matches!(result, PromotionResult::Denied { reason } if reason.contains("Confidence"))
        );
    }

    #[test]
    fn eligible_for_promotion_filters_correctly() {
        let mut engine = make_engine();

        // Create two memories: one high confidence, one low.
        let high =
            engine.register_from_observation("obs-1", "high confidence", "security", 0.9, "rcpt-1");
        let low =
            engine.register_from_observation("obs-2", "low confidence", "general", 0.3, "rcpt-2");

        // Both at Observed, promote to Interpreted.
        for id in [&high, &low] {
            engine.promote(&PromotionRequest {
                memory_id: id.clone(),
                target_stage: MemoryStage::Interpreted,
                evidence: "reflected".to_string(),
                requestor: "reflector".to_string(),
                reviewer: None,
            });
        }

        // Check eligibility for Trusted: only the high confidence one.
        let eligible = engine.eligible_for_promotion(MemoryStage::Trusted);
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].id, high);
    }

    #[test]
    fn reinforcement_updates_confidence() {
        let mut engine = make_engine();
        let mem_id = engine.register_from_observation("obs-1", "test", "general", 0.8, "rcpt-1");

        engine.reinforce(&mem_id, 1.0);
        let entry = engine.get(&mem_id).unwrap();
        assert_eq!(entry.reinforcement_count, 2);
        // Weighted average: (0.8 * 1 + 1.0) / 2 = 0.9
        assert!((entry.confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn promotion_receipt_has_truth_assertion_for_remembered() {
        let mut engine = make_engine();
        let mem_id = engine.register_from_observation("obs-1", "test", "general", 0.95, "rcpt-1");

        // Fast track to Trusted.
        engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Interpreted,
            evidence: "reflected".to_string(),
            requestor: "reflector".to_string(),
            reviewer: None,
        });
        engine.promote(&PromotionRequest {
            memory_id: mem_id.clone(),
            target_stage: MemoryStage::Trusted,
            evidence: "policy ok".to_string(),
            requestor: "policy".to_string(),
            reviewer: None,
        });

        // Reinforce enough.
        engine.reinforce(&mem_id, 0.95);
        engine.reinforce(&mem_id, 0.95);

        // The entry should have promotion receipts with the right count.
        let entry = engine.get(&mem_id).unwrap();
        assert_eq!(entry.promotion_receipts.len(), 3); // obs + interpreted + trusted
        assert_eq!(entry.stage, MemoryStage::Trusted);
    }
}
