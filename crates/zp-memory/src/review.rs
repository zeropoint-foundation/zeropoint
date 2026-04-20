//! Human review gate for memory promotion.
//!
//! Phase 3 (G5-2): Promotion from Trusted → Remembered and from
//! Remembered → IdentityBearing must require human review. This module
//! implements the review queue, pending promotion tracking, and decision
//! processing.
//!
//! ## Design
//!
//! When a promotion to a review-gated stage is requested, instead of
//! immediately promoting, the system creates a `PendingPromotion` in the
//! `ReviewQueue`. The operator reviews via CLI (`zp memory review`) and
//! renders a `ReviewDecision`: Approve, Reject, or Defer.
//!
//! ## Receipt semantics
//!
//! - Approve: generates a `MemoryPromotionClaim` with
//!   `ClaimSemantics::TruthAssertion` (human-asserted truth).
//! - Reject: optionally demotes or quarantines the memory.
//! - Defer: extends the review window (up to max deferrals).

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::types::{MemoryStage, PromotionRequest};

// ============================================================================
// Review types
// ============================================================================

/// A pending promotion that requires human review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingPromotion {
    /// Unique ID for this review request.
    pub id: String,
    /// The memory being considered for promotion.
    pub memory_id: String,
    /// Current stage of the memory.
    pub current_stage: MemoryStage,
    /// Target stage (the proposed promotion).
    pub target_stage: MemoryStage,
    /// Evidence supporting the promotion.
    pub evidence: String,
    /// Who requested the promotion.
    pub requestor: String,
    /// When the review was requested.
    pub requested_at: DateTime<Utc>,
    /// When this review expires (default: 7 days).
    pub expires_at: DateTime<Utc>,
    /// Number of times this review has been deferred.
    pub deferral_count: u32,
    /// Maximum allowed deferrals before auto-rejection.
    pub max_deferrals: u32,
}

/// Human review decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewDecision {
    /// Approve promotion. Generates MemoryPromotionClaim with
    /// ClaimSemantics::TruthAssertion.
    Approve {
        /// The human reviewer's identity (operator key or name).
        reviewer: String,
        /// Optional comment from the reviewer.
        comment: Option<String>,
    },
    /// Reject promotion. Memory remains at current stage.
    /// Optionally demote or quarantine.
    Reject {
        /// Reason for rejection.
        reason: String,
        /// What to do with the memory.
        action: ReviewAction,
        /// The human reviewer's identity.
        reviewer: String,
    },
    /// Defer — keep in review queue, extend expiry.
    Defer {
        /// Reason for deferral.
        reason: String,
        /// The human reviewer's identity.
        reviewer: String,
    },
}

/// What to do when a promotion is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewAction {
    /// Keep the memory at its current stage.
    KeepAtCurrentStage,
    /// Demote the memory to a lower stage.
    Demote(MemoryStage),
    /// Quarantine the memory for further investigation.
    Quarantine,
}

/// Result of processing a review decision.
#[derive(Debug)]
pub enum ReviewOutcome {
    /// Promotion approved — includes the promotion request to execute.
    Approved {
        promotion_request: PromotionRequest,
    },
    /// Promotion rejected.
    Rejected {
        memory_id: String,
        reason: String,
        action: ReviewAction,
    },
    /// Review deferred — extended expiry.
    Deferred {
        review_id: String,
        new_expires_at: DateTime<Utc>,
        deferral_count: u32,
    },
    /// Review expired — auto-rejected after timeout.
    Expired {
        review_id: String,
        memory_id: String,
    },
    /// Error — review not found or already processed.
    NotFound {
        review_id: String,
    },
    /// Deferral limit exceeded — auto-rejected.
    DeferralLimitReached {
        review_id: String,
        memory_id: String,
        max_deferrals: u32,
    },
}

// ============================================================================
// Review queue
// ============================================================================

/// Configuration for the review queue.
#[derive(Debug, Clone)]
pub struct ReviewQueueConfig {
    /// Default review window duration.
    pub review_window: Duration,
    /// Extension per deferral.
    pub deferral_extension: Duration,
    /// Maximum number of deferrals before auto-rejection.
    pub max_deferrals: u32,
}

impl Default for ReviewQueueConfig {
    fn default() -> Self {
        Self {
            review_window: Duration::days(7),
            deferral_extension: Duration::days(3),
            max_deferrals: 3,
        }
    }
}

/// The review queue manages pending promotions awaiting human review.
#[derive(Debug)]
pub struct ReviewQueue {
    /// Pending reviews: review_id → pending promotion.
    pending: HashMap<String, PendingPromotion>,
    /// Completed reviews (for audit trail): review_id → (decision, processed_at).
    completed: Vec<CompletedReview>,
    /// Configuration.
    config: ReviewQueueConfig,
}

/// Record of a completed review, for audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedReview {
    pub review_id: String,
    pub memory_id: String,
    pub decision: ReviewDecision,
    pub processed_at: DateTime<Utc>,
}

impl ReviewQueue {
    pub fn new(config: ReviewQueueConfig) -> Self {
        Self {
            pending: HashMap::new(),
            completed: Vec::new(),
            config,
        }
    }

    /// Submit a promotion for human review.
    ///
    /// Returns the review ID. The promotion is held in the queue until
    /// a human processes it via `process_decision()`.
    pub fn submit_for_review(
        &mut self,
        memory_id: &str,
        current_stage: MemoryStage,
        target_stage: MemoryStage,
        evidence: &str,
        requestor: &str,
    ) -> String {
        let now = Utc::now();
        let review_id = format!("review-{}", uuid::Uuid::now_v7());

        let pending = PendingPromotion {
            id: review_id.clone(),
            memory_id: memory_id.to_string(),
            current_stage,
            target_stage,
            evidence: evidence.to_string(),
            requestor: requestor.to_string(),
            requested_at: now,
            expires_at: now + self.config.review_window,
            deferral_count: 0,
            max_deferrals: self.config.max_deferrals,
        };

        info!(
            review_id = %review_id,
            memory_id = %memory_id,
            from = %current_stage,
            to = %target_stage,
            expires_at = %pending.expires_at,
            "Promotion submitted for human review"
        );

        self.pending.insert(review_id.clone(), pending);
        review_id
    }

    /// Process a human review decision.
    pub fn process_decision(
        &mut self,
        review_id: &str,
        decision: ReviewDecision,
    ) -> ReviewOutcome {
        let pending = match self.pending.remove(review_id) {
            Some(p) => p,
            None => return ReviewOutcome::NotFound { review_id: review_id.to_string() },
        };

        // Check expiry.
        if Utc::now() > pending.expires_at {
            info!(
                review_id = %review_id,
                memory_id = %pending.memory_id,
                "Review expired"
            );
            return ReviewOutcome::Expired {
                review_id: review_id.to_string(),
                memory_id: pending.memory_id,
            };
        }

        let now = Utc::now();

        match &decision {
            ReviewDecision::Approve { reviewer, comment } => {
                info!(
                    review_id = %review_id,
                    memory_id = %pending.memory_id,
                    reviewer = %reviewer,
                    comment = ?comment,
                    "Promotion approved by human reviewer"
                );

                self.completed.push(CompletedReview {
                    review_id: review_id.to_string(),
                    memory_id: pending.memory_id.clone(),
                    decision: decision.clone(),
                    processed_at: now,
                });

                ReviewOutcome::Approved {
                    promotion_request: PromotionRequest {
                        memory_id: pending.memory_id,
                        target_stage: pending.target_stage,
                        evidence: pending.evidence,
                        requestor: pending.requestor,
                        reviewer: Some(reviewer.clone()),
                    },
                }
            }

            ReviewDecision::Reject { reason, action, reviewer } => {
                info!(
                    review_id = %review_id,
                    memory_id = %pending.memory_id,
                    reviewer = %reviewer,
                    reason = %reason,
                    "Promotion rejected by human reviewer"
                );

                self.completed.push(CompletedReview {
                    review_id: review_id.to_string(),
                    memory_id: pending.memory_id.clone(),
                    decision: decision.clone(),
                    processed_at: now,
                });

                ReviewOutcome::Rejected {
                    memory_id: pending.memory_id,
                    reason: reason.clone(),
                    action: action.clone(),
                }
            }

            ReviewDecision::Defer { reason, reviewer } => {
                let new_deferral_count = pending.deferral_count + 1;

                if new_deferral_count > pending.max_deferrals {
                    warn!(
                        review_id = %review_id,
                        memory_id = %pending.memory_id,
                        max_deferrals = pending.max_deferrals,
                        "Deferral limit reached — auto-rejecting"
                    );

                    self.completed.push(CompletedReview {
                        review_id: review_id.to_string(),
                        memory_id: pending.memory_id.clone(),
                        decision: decision.clone(),
                        processed_at: now,
                    });

                    return ReviewOutcome::DeferralLimitReached {
                        review_id: review_id.to_string(),
                        memory_id: pending.memory_id,
                        max_deferrals: pending.max_deferrals,
                    };
                }

                let new_expires_at = pending.expires_at + self.config.deferral_extension;

                info!(
                    review_id = %review_id,
                    memory_id = %pending.memory_id,
                    reviewer = %reviewer,
                    reason = %reason,
                    deferral = new_deferral_count,
                    new_expires_at = %new_expires_at,
                    "Review deferred"
                );

                // Put it back in the queue with updated state.
                let mut updated = pending;
                updated.deferral_count = new_deferral_count;
                updated.expires_at = new_expires_at;
                self.pending.insert(review_id.to_string(), updated);

                ReviewOutcome::Deferred {
                    review_id: review_id.to_string(),
                    new_expires_at,
                    deferral_count: new_deferral_count,
                }
            }
        }
    }

    /// Get all pending reviews, sorted by expiry (soonest first).
    pub fn pending_reviews(&self) -> Vec<&PendingPromotion> {
        let mut reviews: Vec<_> = self.pending.values().collect();
        reviews.sort_by_key(|p| p.expires_at);
        reviews
    }

    /// Get pending reviews for a specific memory.
    pub fn pending_for_memory(&self, memory_id: &str) -> Vec<&PendingPromotion> {
        self.pending
            .values()
            .filter(|p| p.memory_id == memory_id)
            .collect()
    }

    /// Sweep expired reviews, returning the expired review IDs.
    pub fn sweep_expired(&mut self) -> Vec<String> {
        let now = Utc::now();
        let expired_ids: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| now > p.expires_at)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &expired_ids {
            if let Some(pending) = self.pending.remove(id) {
                info!(
                    review_id = %id,
                    memory_id = %pending.memory_id,
                    "Expired review swept"
                );
                self.completed.push(CompletedReview {
                    review_id: id.clone(),
                    memory_id: pending.memory_id,
                    decision: ReviewDecision::Reject {
                        reason: "Review expired".to_string(),
                        action: ReviewAction::KeepAtCurrentStage,
                        reviewer: "system".to_string(),
                    },
                    processed_at: now,
                });
            }
        }

        expired_ids
    }

    /// Number of pending reviews.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Completed review history.
    pub fn completed_reviews(&self) -> &[CompletedReview] {
        &self.completed
    }

    /// Check whether a given stage transition requires human review.
    pub fn requires_review(target_stage: MemoryStage) -> bool {
        matches!(
            target_stage,
            MemoryStage::Remembered | MemoryStage::IdentityBearing
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_queue() -> ReviewQueue {
        ReviewQueue::new(ReviewQueueConfig::default())
    }

    #[test]
    fn submit_and_approve() {
        let mut queue = make_queue();

        let review_id = queue.submit_for_review(
            "mem-1",
            MemoryStage::Trusted,
            MemoryStage::Remembered,
            "Strong cross-context reinforcement",
            "promotion-engine",
        );

        assert_eq!(queue.pending_count(), 1);

        let outcome = queue.process_decision(
            &review_id,
            ReviewDecision::Approve {
                reviewer: "operator-key-abc".to_string(),
                comment: Some("Verified across 5 sessions".to_string()),
            },
        );

        assert!(matches!(outcome, ReviewOutcome::Approved { .. }));
        if let ReviewOutcome::Approved { promotion_request } = outcome {
            assert_eq!(promotion_request.memory_id, "mem-1");
            assert_eq!(promotion_request.target_stage, MemoryStage::Remembered);
            assert_eq!(promotion_request.reviewer.as_deref(), Some("operator-key-abc"));
        }
        assert_eq!(queue.pending_count(), 0);
        assert_eq!(queue.completed_reviews().len(), 1);
    }

    #[test]
    fn submit_and_reject() {
        let mut queue = make_queue();

        let review_id = queue.submit_for_review(
            "mem-1",
            MemoryStage::Remembered,
            MemoryStage::IdentityBearing,
            "Candidate for identity",
            "engine",
        );

        let outcome = queue.process_decision(
            &review_id,
            ReviewDecision::Reject {
                reason: "Not consistent enough".to_string(),
                action: ReviewAction::Demote(MemoryStage::Trusted),
                reviewer: "operator".to_string(),
            },
        );

        assert!(matches!(outcome, ReviewOutcome::Rejected { .. }));
        if let ReviewOutcome::Rejected { action, .. } = outcome {
            assert!(matches!(action, ReviewAction::Demote(MemoryStage::Trusted)));
        }
    }

    #[test]
    fn submit_and_defer() {
        let mut queue = make_queue();

        let review_id = queue.submit_for_review(
            "mem-1",
            MemoryStage::Trusted,
            MemoryStage::Remembered,
            "evidence",
            "engine",
        );

        let original_expiry = queue.pending.get(&review_id).unwrap().expires_at;

        let outcome = queue.process_decision(
            &review_id,
            ReviewDecision::Defer {
                reason: "Need more data".to_string(),
                reviewer: "operator".to_string(),
            },
        );

        assert!(matches!(outcome, ReviewOutcome::Deferred { .. }));
        if let ReviewOutcome::Deferred { deferral_count, new_expires_at, .. } = outcome {
            assert_eq!(deferral_count, 1);
            assert!(new_expires_at > original_expiry);
        }

        // Still in queue.
        assert_eq!(queue.pending_count(), 1);
        assert_eq!(queue.pending.get(&review_id).unwrap().deferral_count, 1);
    }

    #[test]
    fn deferral_limit_reached() {
        let mut queue = ReviewQueue::new(ReviewQueueConfig {
            max_deferrals: 1,
            ..Default::default()
        });

        let review_id = queue.submit_for_review(
            "mem-1",
            MemoryStage::Trusted,
            MemoryStage::Remembered,
            "evidence",
            "engine",
        );

        // First deferral should succeed.
        let outcome = queue.process_decision(
            &review_id,
            ReviewDecision::Defer {
                reason: "wait".to_string(),
                reviewer: "operator".to_string(),
            },
        );
        assert!(matches!(outcome, ReviewOutcome::Deferred { .. }));

        // Second deferral should hit the limit.
        let outcome = queue.process_decision(
            &review_id,
            ReviewDecision::Defer {
                reason: "still waiting".to_string(),
                reviewer: "operator".to_string(),
            },
        );
        assert!(matches!(outcome, ReviewOutcome::DeferralLimitReached { .. }));
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn not_found_for_unknown_review() {
        let mut queue = make_queue();
        let outcome = queue.process_decision(
            "nonexistent",
            ReviewDecision::Approve {
                reviewer: "op".to_string(),
                comment: None,
            },
        );
        assert!(matches!(outcome, ReviewOutcome::NotFound { .. }));
    }

    #[test]
    fn pending_reviews_sorted_by_expiry() {
        let mut queue = make_queue();

        queue.submit_for_review("mem-1", MemoryStage::Trusted, MemoryStage::Remembered, "ev", "eng");
        queue.submit_for_review("mem-2", MemoryStage::Trusted, MemoryStage::Remembered, "ev", "eng");

        let reviews = queue.pending_reviews();
        assert_eq!(reviews.len(), 2);
        assert!(reviews[0].expires_at <= reviews[1].expires_at);
    }

    #[test]
    fn requires_review_for_gated_stages() {
        assert!(ReviewQueue::requires_review(MemoryStage::Remembered));
        assert!(ReviewQueue::requires_review(MemoryStage::IdentityBearing));
        assert!(!ReviewQueue::requires_review(MemoryStage::Observed));
        assert!(!ReviewQueue::requires_review(MemoryStage::Interpreted));
        assert!(!ReviewQueue::requires_review(MemoryStage::Trusted));
        assert!(!ReviewQueue::requires_review(MemoryStage::Transient));
    }

    #[test]
    fn reject_with_quarantine_action() {
        let mut queue = make_queue();

        let review_id = queue.submit_for_review(
            "mem-suspect",
            MemoryStage::Trusted,
            MemoryStage::Remembered,
            "suspicious evidence",
            "engine",
        );

        let outcome = queue.process_decision(
            &review_id,
            ReviewDecision::Reject {
                reason: "Evidence appears fabricated".to_string(),
                action: ReviewAction::Quarantine,
                reviewer: "operator".to_string(),
            },
        );

        if let ReviewOutcome::Rejected { action, .. } = outcome {
            assert!(matches!(action, ReviewAction::Quarantine));
        } else {
            panic!("Expected Rejected outcome");
        }
    }

    #[test]
    fn pending_for_specific_memory() {
        let mut queue = make_queue();

        queue.submit_for_review("mem-1", MemoryStage::Trusted, MemoryStage::Remembered, "ev", "eng");
        queue.submit_for_review("mem-2", MemoryStage::Trusted, MemoryStage::Remembered, "ev", "eng");
        queue.submit_for_review("mem-1", MemoryStage::Remembered, MemoryStage::IdentityBearing, "ev", "eng");

        let mem1_reviews = queue.pending_for_memory("mem-1");
        assert_eq!(mem1_reviews.len(), 2);

        let mem2_reviews = queue.pending_for_memory("mem-2");
        assert_eq!(mem2_reviews.len(), 1);
    }
}
