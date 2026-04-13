//! Memory lifecycle rules: expiry, review scheduling, and demotion.
//!
//! Phase 4.4: Implements the doctrine's temporal gates on memory persistence.
//! Expired memories are not deleted — they are demoted and their receipts
//! preserved for audit. The observation chain remains intact; only the
//! epistemic status changes.

use chrono::{DateTime, Duration, Utc};
use tracing::{info, warn};

use crate::types::{MemoryEntry, MemoryStage};

// ============================================================================
// Stage-specific lifecycle parameters
// ============================================================================

/// Get the default expiry duration for a memory stage.
///
/// | Stage           | Expiry       | Rationale                                     |
/// |-----------------|--------------|-----------------------------------------------|
/// | Observed        | 24 hours     | Stale observations are first to be pruned      |
/// | Interpreted     | 7 days       | Without reinforcement, interpretation decays   |
/// | Trusted         | Never        | But reviewed every 30 days                     |
/// | Remembered      | Never        | But reviewed annually                          |
/// | IdentityBearing | Never        | Permanent, appealable only via operator receipt |
pub fn default_expiry(stage: MemoryStage) -> Option<Duration> {
    match stage {
        MemoryStage::Transient => Some(Duration::hours(1)),
        MemoryStage::Observed => Some(Duration::hours(24)),
        MemoryStage::Interpreted => Some(Duration::days(7)),
        // Trusted and above never expire automatically
        _ => None,
    }
}

/// Get the review interval for a memory stage.
///
/// | Stage           | Review Interval |
/// |-----------------|-----------------|
/// | Trusted         | 30 days         |
/// | Remembered      | 365 days        |
/// | IdentityBearing | Never (permanent) |
pub fn review_interval(stage: MemoryStage) -> Option<Duration> {
    match stage {
        MemoryStage::Trusted => Some(Duration::days(30)),
        MemoryStage::Remembered => Some(Duration::days(365)),
        _ => None,
    }
}

// ============================================================================
// Lifecycle operations
// ============================================================================

/// Apply default expiry and review schedule to a memory entry based on its stage.
///
/// Called after every promotion to set or update the lifecycle timers.
pub fn apply_lifecycle_rules(entry: &mut MemoryEntry) {
    let now = Utc::now();

    // Set expiry based on stage.
    entry.expires_at = default_expiry(entry.stage).map(|d| now + d);

    // Set next review date based on stage.
    entry.review_due_at = review_interval(entry.stage).map(|d| now + d);
}

/// Check if a memory has expired.
pub fn is_expired(entry: &MemoryEntry) -> bool {
    entry
        .expires_at
        .map_or(false, |exp| Utc::now() > exp)
}

/// Check if a memory is due for review.
pub fn is_review_due(entry: &MemoryEntry) -> bool {
    entry
        .review_due_at
        .map_or(false, |due| Utc::now() > due)
}

/// Result of running the expiry sweep.
#[derive(Debug, Default)]
pub struct ExpirySweepResult {
    /// Memory IDs that were demoted due to expiry.
    pub expired_ids: Vec<String>,
    /// Memory IDs that are due for review.
    pub review_due_ids: Vec<String>,
}

/// Run the expiry and review sweep across all memories.
///
/// Returns which memories expired and which are due for review.
/// Does NOT modify entries — the caller applies demotions.
pub fn sweep_lifecycle(memories: &[&MemoryEntry]) -> ExpirySweepResult {
    let mut result = ExpirySweepResult::default();

    for entry in memories {
        if is_expired(entry) {
            result.expired_ids.push(entry.id.clone());
        } else if is_review_due(entry) {
            result.review_due_ids.push(entry.id.clone());
        }
    }

    result
}

/// Compute the demotion target for an expired memory.
///
/// - Observed → dropped (too stale to keep)
/// - Interpreted → Observed (loses interpretation, keeps raw observation)
/// - Trusted (review overdue, not reaffirmed) → Interpreted
///
/// Returns None if the memory should be marked as expired/inactive
/// rather than demoted to a lower stage.
pub fn demotion_target(stage: MemoryStage) -> Option<MemoryStage> {
    match stage {
        MemoryStage::Transient => None, // Just drop it
        MemoryStage::Observed => None,  // Too stale, mark inactive
        MemoryStage::Interpreted => Some(MemoryStage::Observed),
        MemoryStage::Trusted => Some(MemoryStage::Interpreted),
        MemoryStage::Remembered => Some(MemoryStage::Trusted),
        MemoryStage::IdentityBearing => {
            // IdentityBearing requires explicit operator appeal — no auto-demotion
            None
        }
    }
}

/// Apply demotion to a memory entry.
///
/// Returns the new stage (or None if the memory should be deactivated).
pub fn demote(entry: &mut MemoryEntry) -> Option<MemoryStage> {
    let target = demotion_target(entry.stage);

    if let Some(new_stage) = target {
        let old_stage = entry.stage;
        entry.stage = new_stage;
        entry.last_promoted_at = Utc::now();

        // Reset lifecycle timers for the new stage.
        apply_lifecycle_rules(entry);

        info!(
            memory_id = %entry.id,
            from = %old_stage,
            to = %new_stage,
            "Memory demoted"
        );
    } else {
        warn!(
            memory_id = %entry.id,
            stage = %entry.stage,
            "Memory expired with no demotion target — marking inactive"
        );
    }

    target
}

/// Reaffirm a memory during review, resetting its review timer.
///
/// Called when new evidence supports the memory during a review cycle.
pub fn reaffirm(entry: &mut MemoryEntry) {
    let now = Utc::now();
    entry.last_reinforced_at = now;

    // Reset review timer.
    entry.review_due_at = review_interval(entry.stage).map(|d| now + d);

    info!(
        memory_id = %entry.id,
        stage = %entry.stage,
        next_review = ?entry.review_due_at,
        "Memory reaffirmed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MemoryStage;
    use chrono::Utc;

    fn make_entry(stage: MemoryStage) -> MemoryEntry {
        let now = Utc::now();
        MemoryEntry {
            id: "mem-test".to_string(),
            content: "test memory".to_string(),
            category: "test".to_string(),
            stage,
            source_observation_id: None,
            promotion_receipts: vec![],
            confidence: 0.9,
            reinforcement_count: 5,
            created_at: now,
            last_promoted_at: now,
            last_reinforced_at: now,
            reviewer: None,
            expires_at: None,
            review_due_at: None,
        }
    }

    #[test]
    fn default_expiry_values() {
        assert_eq!(default_expiry(MemoryStage::Observed), Some(Duration::hours(24)));
        assert_eq!(default_expiry(MemoryStage::Interpreted), Some(Duration::days(7)));
        assert_eq!(default_expiry(MemoryStage::Trusted), None);
        assert_eq!(default_expiry(MemoryStage::Remembered), None);
        assert_eq!(default_expiry(MemoryStage::IdentityBearing), None);
    }

    #[test]
    fn review_interval_values() {
        assert_eq!(review_interval(MemoryStage::Observed), None);
        assert_eq!(review_interval(MemoryStage::Trusted), Some(Duration::days(30)));
        assert_eq!(review_interval(MemoryStage::Remembered), Some(Duration::days(365)));
        assert_eq!(review_interval(MemoryStage::IdentityBearing), None);
    }

    #[test]
    fn lifecycle_rules_applied_correctly() {
        let mut entry = make_entry(MemoryStage::Observed);
        apply_lifecycle_rules(&mut entry);

        assert!(entry.expires_at.is_some());
        assert!(entry.review_due_at.is_none()); // Observed has no review

        let mut entry = make_entry(MemoryStage::Trusted);
        apply_lifecycle_rules(&mut entry);

        assert!(entry.expires_at.is_none()); // Trusted doesn't expire
        assert!(entry.review_due_at.is_some()); // But has a 30-day review
    }

    #[test]
    fn expiry_detection() {
        let mut entry = make_entry(MemoryStage::Observed);

        // Not expired yet.
        entry.expires_at = Some(Utc::now() + Duration::hours(1));
        assert!(!is_expired(&entry));

        // Expired.
        entry.expires_at = Some(Utc::now() - Duration::hours(1));
        assert!(is_expired(&entry));
    }

    #[test]
    fn review_due_detection() {
        let mut entry = make_entry(MemoryStage::Trusted);

        // Not due yet.
        entry.review_due_at = Some(Utc::now() + Duration::days(1));
        assert!(!is_review_due(&entry));

        // Due.
        entry.review_due_at = Some(Utc::now() - Duration::days(1));
        assert!(is_review_due(&entry));
    }

    #[test]
    fn demotion_targets() {
        assert_eq!(demotion_target(MemoryStage::Observed), None);
        assert_eq!(demotion_target(MemoryStage::Interpreted), Some(MemoryStage::Observed));
        assert_eq!(demotion_target(MemoryStage::Trusted), Some(MemoryStage::Interpreted));
        assert_eq!(demotion_target(MemoryStage::Remembered), Some(MemoryStage::Trusted));
        assert_eq!(demotion_target(MemoryStage::IdentityBearing), None); // No auto-demotion
    }

    #[test]
    fn demote_changes_stage() {
        let mut entry = make_entry(MemoryStage::Trusted);
        let result = demote(&mut entry);

        assert_eq!(result, Some(MemoryStage::Interpreted));
        assert_eq!(entry.stage, MemoryStage::Interpreted);
        // Should now have an expiry (Interpreted expires in 7 days).
        assert!(entry.expires_at.is_some());
    }

    #[test]
    fn reaffirm_resets_review_timer() {
        let mut entry = make_entry(MemoryStage::Trusted);
        entry.review_due_at = Some(Utc::now() - Duration::days(1)); // Overdue

        reaffirm(&mut entry);

        // Review timer should be reset to ~30 days from now.
        let due = entry.review_due_at.unwrap();
        let diff = due - Utc::now();
        assert!(diff.num_days() >= 29);
    }

    #[test]
    fn sweep_finds_expired_and_due() {
        let mut expired = make_entry(MemoryStage::Observed);
        expired.id = "expired-1".to_string();
        expired.expires_at = Some(Utc::now() - Duration::hours(1));

        let mut due = make_entry(MemoryStage::Trusted);
        due.id = "review-due-1".to_string();
        due.review_due_at = Some(Utc::now() - Duration::days(1));

        let mut healthy = make_entry(MemoryStage::Remembered);
        healthy.id = "healthy-1".to_string();
        healthy.review_due_at = Some(Utc::now() + Duration::days(100));

        let entries: Vec<&MemoryEntry> = vec![&expired, &due, &healthy];
        let result = sweep_lifecycle(&entries);

        assert_eq!(result.expired_ids, vec!["expired-1"]);
        assert_eq!(result.review_due_ids, vec!["review-due-1"]);
    }
}
