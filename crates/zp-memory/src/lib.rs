//! Memory promotion engine for ZeroPoint's cognition plane.
//!
//! Phase 4.3: Implements the doctrine's truth transition lifecycle.
//! Nothing becomes durable truth merely because a model inferred it.
//!
//! The promotion lifecycle maps epistemic stages to receipt-backed gates:
//!
//! | Stage          | Source                      | Receipt Type           |
//! |----------------|-----------------------------|------------------------|
//! | Transient      | Raw receipt chain output    | —                      |
//! | Observed       | Observer agent distillation | ObservationClaim       |
//! | Interpreted    | Reflector consolidation     | ReflectionClaim        |
//! | Trusted        | Policy gate + evidence      | PolicyClaim            |
//! | Remembered     | Promotion engine approval   | MemoryPromotionClaim   |
//! | IdentityBearing| Human review + signing      | MemoryPromotionClaim   |

pub mod compromise;
pub mod ingestion;
pub mod lifecycle;
pub mod promotion;
pub mod quarantine;
pub mod review;
pub mod sharing;
pub mod types;

pub use compromise::{
    quarantine_compromised_memories, CompromiseQuarantineResult, CompromiseReport,
};
pub use ingestion::{
    ingest_observation, ingest_observations, BatchIngestionResult, IngestionConfig, IngestionResult,
};
pub use lifecycle::{
    apply_lifecycle_rules, default_expiry, demote, demotion_target, is_expired, is_review_due,
    reaffirm, review_interval, sweep_lifecycle, ExpirySweepResult,
};
pub use promotion::PromotionEngine;
pub use review::{
    CompletedReview, PendingPromotion, ReviewAction, ReviewDecision, ReviewOutcome, ReviewQueue,
    ReviewQueueConfig,
};
pub use quarantine::{
    BulkQuarantineResult, QuarantineReason, QuarantineRecord, QuarantineStore, ReinstatementResult,
};
pub use sharing::{
    can_share, format_for_delegation, merge_memories, MergeResult, SharedMemory, SharingContext,
};
pub use types::*;
