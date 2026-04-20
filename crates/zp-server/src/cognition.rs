//! Cognition pipeline integration — G5-1: Observation→promotion wiring.
//!
//! Exposes the `CognitionPipeline` (Observer/Reflector cycle) as API endpoints
//! so observations accumulate from the receipt chain and promote through the
//! memory lifecycle.
//!
//! ## Endpoints
//!
//! - `POST /api/v1/cognition/observe` — Trigger observation (Tier 1 heuristic
//!   if no LLM output provided, or process LLM output if given).
//! - `POST /api/v1/cognition/reflect` — Trigger reflection/consolidation.
//! - `GET  /api/v1/cognition/status` — Current observation store stats +
//!   whether observer/reflector should activate.
//! - `GET  /api/v1/cognition/observations` — List active observations.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use zp_memory::{
    MemoryStage, PendingPromotion, ReviewAction, ReviewDecision, ReviewOutcome, ReviewQueue,
};
use zp_observation::types::SourceRange;

use crate::AppState;

// ============================================================================
// Request / response types
// ============================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserveRequest {
    /// Optional LLM output to process. If absent, Tier 1 heuristic is used.
    pub llm_output: Option<String>,
    /// Messages to observe (for Tier 1 fallback). Each entry is (role, content).
    pub messages: Option<Vec<(String, String)>>,
    /// Optional parent receipt ID for chaining.
    pub chain_parent_receipt_id: Option<String>,
}

#[derive(Serialize)]
pub struct ObserveResponse {
    pub observations_created: usize,
    pub receipts_generated: usize,
    pub used_llm: bool,
    pub total_active: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReflectRequest {
    /// LLM output containing reflector actions.
    pub llm_output: String,
    /// Optional parent receipt ID for chaining.
    pub chain_parent_receipt_id: Option<String>,
}

#[derive(Serialize)]
pub struct ReflectResponse {
    pub consumed: usize,
    pub produced: usize,
    pub dropped: usize,
    pub tokens_before: usize,
    pub tokens_after: usize,
    pub compression_ratio: f64,
}

#[derive(Serialize)]
pub struct CognitionStatus {
    pub active_observations: usize,
    pub total_tokens: usize,
    pub should_observe: bool,
    pub should_reflect: bool,
    pub observer_threshold: usize,
    pub reflector_threshold: usize,
}

#[derive(Serialize)]
pub struct ObservationSummary {
    pub id: String,
    pub content: String,
    pub priority: String,
    pub category: String,
    pub superseded: bool,
}

// ============================================================================
// Handlers
// ============================================================================

/// `POST /api/v1/cognition/observe` — trigger observation.
pub async fn observe_handler(
    State(state): State<AppState>,
    Json(body): Json<ObserveRequest>,
) -> Result<Json<ObserveResponse>, (StatusCode, String)> {
    let obs_store = state.0.observation_store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Observation store not available".to_string(),
    ))?;

    let cognition = state.0.cognition_pipeline.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Cognition pipeline not initialized".to_string(),
    ))?;

    let store = obs_store.lock().unwrap();

    let source_range = SourceRange::new(
        "api-observe",
        &format!("req-{}", uuid::Uuid::now_v7()),
        &format!("req-{}", uuid::Uuid::now_v7()),
        0,
        0,
    );

    let result = if let Some(llm_output) = &body.llm_output {
        // LLM-powered observation
        cognition
            .process_observer_output(
                llm_output,
                &source_range,
                &store,
                body.chain_parent_receipt_id.as_deref(),
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    } else {
        // Tier 1 heuristic fallback
        let messages = body.messages.unwrap_or_default();
        cognition
            .observe_tier1(
                &messages,
                &source_range,
                &store,
                body.chain_parent_receipt_id.as_deref(),
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?
    };

    let total_active = store.active_count().unwrap_or(0);

    Ok(Json(ObserveResponse {
        observations_created: result.observations.len(),
        receipts_generated: result.receipts.len(),
        used_llm: result.used_llm,
        total_active,
    }))
}

/// `POST /api/v1/cognition/reflect` — trigger reflection/consolidation.
pub async fn reflect_handler(
    State(state): State<AppState>,
    Json(body): Json<ReflectRequest>,
) -> Result<Json<ReflectResponse>, (StatusCode, String)> {
    let obs_store = state.0.observation_store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Observation store not available".to_string(),
    ))?;

    let cognition = state.0.cognition_pipeline.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Cognition pipeline not initialized".to_string(),
    ))?;

    let store = obs_store.lock().unwrap();

    let result = cognition
        .process_reflector_output(
            &body.llm_output,
            &store,
            body.chain_parent_receipt_id.as_deref(),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let ratio = result.reflection.compression_ratio();

    Ok(Json(ReflectResponse {
        consumed: result.reflection.consumed_observation_ids.len(),
        produced: result.reflection.produced_observations.len(),
        dropped: result.reflection.dropped_observation_ids.len(),
        tokens_before: result.reflection.tokens_before,
        tokens_after: result.reflection.tokens_after,
        compression_ratio: ratio,
    }))
}

/// `GET /api/v1/cognition/status` — observation pipeline status.
pub async fn cognition_status_handler(
    State(state): State<AppState>,
) -> Result<Json<CognitionStatus>, (StatusCode, String)> {
    let obs_store = state.0.observation_store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Observation store not available".to_string(),
    ))?;

    let cognition = state.0.cognition_pipeline.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Cognition pipeline not initialized".to_string(),
    ))?;

    let store = obs_store.lock().unwrap();
    let active = store.active_count().unwrap_or(0);
    let tokens = store.total_token_estimate().unwrap_or(0);
    let config = cognition.config();

    Ok(Json(CognitionStatus {
        active_observations: active,
        total_tokens: tokens,
        should_observe: config.should_observe(tokens),
        should_reflect: config.should_reflect(tokens),
        observer_threshold: config.observer_activation_threshold(),
        reflector_threshold: config.reflection_threshold,
    }))
}

/// `GET /api/v1/cognition/observations` — list active observations.
pub async fn list_observations_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<ObservationSummary>>, (StatusCode, String)> {
    let obs_store = state.0.observation_store.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Observation store not available".to_string(),
    ))?;

    let store = obs_store.lock().unwrap();
    let active = store
        .get_active()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Store error: {}", e)))?;

    let summaries: Vec<ObservationSummary> = active
        .into_iter()
        .map(|obs| ObservationSummary {
            id: obs.id,
            content: obs.content,
            priority: format!("{:?}", obs.priority),
            category: obs.category,
            superseded: obs.superseded,
        })
        .collect();

    Ok(Json(summaries))
}

// ============================================================================
// G5-2: Human review gate endpoints
// ============================================================================

#[derive(Serialize)]
pub struct PendingReviewSummary {
    pub id: String,
    pub memory_id: String,
    pub current_stage: String,
    pub target_stage: String,
    pub evidence: String,
    pub requestor: String,
    pub requested_at: String,
    pub expires_at: String,
    pub deferral_count: u32,
    pub max_deferrals: u32,
}

impl From<&PendingPromotion> for PendingReviewSummary {
    fn from(p: &PendingPromotion) -> Self {
        Self {
            id: p.id.clone(),
            memory_id: p.memory_id.clone(),
            current_stage: format!("{}", p.current_stage),
            target_stage: format!("{}", p.target_stage),
            evidence: p.evidence.clone(),
            requestor: p.requestor.clone(),
            requested_at: p.requested_at.to_rfc3339(),
            expires_at: p.expires_at.to_rfc3339(),
            deferral_count: p.deferral_count,
            max_deferrals: p.max_deferrals,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitReviewRequest {
    pub memory_id: String,
    pub current_stage: String,
    pub target_stage: String,
    pub evidence: String,
    pub requestor: String,
}

#[derive(Serialize)]
pub struct SubmitReviewResponse {
    pub review_id: String,
    pub requires_review: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "decision")]
pub enum ReviewDecisionRequest {
    #[serde(rename = "approve")]
    Approve {
        reviewer: String,
        comment: Option<String>,
    },
    #[serde(rename = "reject")]
    Reject {
        reviewer: String,
        reason: String,
        /// "keep", "quarantine", or "demote:<stage>"
        action: String,
    },
    #[serde(rename = "defer")]
    Defer {
        reviewer: String,
        reason: String,
    },
}

#[derive(Serialize)]
pub struct ReviewDecisionResponse {
    pub outcome: String,
    pub detail: String,
}

/// Parse a stage string into a MemoryStage.
fn parse_stage(s: &str) -> Result<MemoryStage, String> {
    match s.to_lowercase().as_str() {
        "transient" => Ok(MemoryStage::Transient),
        "observed" => Ok(MemoryStage::Observed),
        "interpreted" => Ok(MemoryStage::Interpreted),
        "trusted" => Ok(MemoryStage::Trusted),
        "remembered" => Ok(MemoryStage::Remembered),
        "identitybearing" | "identity_bearing" | "identity-bearing" => {
            Ok(MemoryStage::IdentityBearing)
        }
        other => Err(format!("Unknown memory stage: {}", other)),
    }
}

/// Parse the action string from a reject decision.
fn parse_review_action(s: &str) -> Result<ReviewAction, String> {
    match s.to_lowercase().as_str() {
        "keep" => Ok(ReviewAction::KeepAtCurrentStage),
        "quarantine" => Ok(ReviewAction::Quarantine),
        s if s.starts_with("demote:") => {
            let stage_str = &s[7..];
            let stage = parse_stage(stage_str)?;
            Ok(ReviewAction::Demote(stage))
        }
        other => Err(format!(
            "Unknown review action: {} (expected 'keep', 'quarantine', or 'demote:<stage>')",
            other
        )),
    }
}

/// `GET /api/v1/cognition/reviews` — list pending reviews.
pub async fn list_reviews_handler(
    State(state): State<AppState>,
) -> Result<Json<Vec<PendingReviewSummary>>, (StatusCode, String)> {
    let review_queue = state.0.review_queue.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Review queue not available".to_string(),
    ))?;

    let queue = review_queue.lock().unwrap();
    let reviews: Vec<PendingReviewSummary> = queue
        .pending_reviews()
        .into_iter()
        .map(PendingReviewSummary::from)
        .collect();

    Ok(Json(reviews))
}

/// `POST /api/v1/cognition/reviews` — submit a promotion for review.
pub async fn submit_review_handler(
    State(state): State<AppState>,
    Json(body): Json<SubmitReviewRequest>,
) -> Result<Json<SubmitReviewResponse>, (StatusCode, String)> {
    let review_queue = state.0.review_queue.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Review queue not available".to_string(),
    ))?;

    let target_stage = parse_stage(&body.target_stage)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let current_stage = parse_stage(&body.current_stage)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Check if this stage transition requires review.
    let requires_review = ReviewQueue::requires_review(target_stage);

    if !requires_review {
        return Ok(Json(SubmitReviewResponse {
            review_id: String::new(),
            requires_review: false,
        }));
    }

    let mut queue = review_queue.lock().unwrap();
    let review_id = queue.submit_for_review(
        &body.memory_id,
        current_stage,
        target_stage,
        &body.evidence,
        &body.requestor,
    );

    Ok(Json(SubmitReviewResponse {
        review_id,
        requires_review: true,
    }))
}

/// `POST /api/v1/cognition/reviews/:id/decide` — process a review decision.
pub async fn decide_review_handler(
    State(state): State<AppState>,
    Path(review_id): Path<String>,
    Json(body): Json<ReviewDecisionRequest>,
) -> Result<Json<ReviewDecisionResponse>, (StatusCode, String)> {
    let review_queue = state.0.review_queue.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Review queue not available".to_string(),
    ))?;

    let decision = match body {
        ReviewDecisionRequest::Approve { reviewer, comment } => {
            ReviewDecision::Approve { reviewer, comment }
        }
        ReviewDecisionRequest::Reject {
            reviewer,
            reason,
            action,
        } => {
            let parsed_action = parse_review_action(&action)
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            ReviewDecision::Reject {
                reason,
                action: parsed_action,
                reviewer,
            }
        }
        ReviewDecisionRequest::Defer { reviewer, reason } => {
            ReviewDecision::Defer { reason, reviewer }
        }
    };

    let mut queue = review_queue.lock().unwrap();
    let outcome = queue.process_decision(&review_id, decision);

    let (outcome_str, detail) = match outcome {
        ReviewOutcome::Approved { promotion_request } => (
            "approved".to_string(),
            format!(
                "Memory {} promoted to {}",
                promotion_request.memory_id, promotion_request.target_stage
            ),
        ),
        ReviewOutcome::Rejected {
            memory_id, reason, ..
        } => ("rejected".to_string(), format!("{}: {}", memory_id, reason)),
        ReviewOutcome::Deferred {
            review_id,
            new_expires_at,
            deferral_count,
        } => (
            "deferred".to_string(),
            format!(
                "Review {} deferred (count: {}, new expiry: {})",
                review_id, deferral_count, new_expires_at
            ),
        ),
        ReviewOutcome::Expired {
            review_id,
            memory_id,
        } => (
            "expired".to_string(),
            format!("Review {} for memory {} has expired", review_id, memory_id),
        ),
        ReviewOutcome::NotFound { review_id } => {
            return Err((
                StatusCode::NOT_FOUND,
                format!("Review {} not found", review_id),
            ));
        }
        ReviewOutcome::DeferralLimitReached {
            review_id,
            max_deferrals,
            ..
        } => (
            "deferral_limit_reached".to_string(),
            format!(
                "Review {} exceeded max deferrals ({}), auto-rejected",
                review_id, max_deferrals
            ),
        ),
    };

    Ok(Json(ReviewDecisionResponse {
        outcome: outcome_str,
        detail,
    }))
}

/// Response for POST /api/v1/cognition/reviews/sweep.
#[derive(Serialize)]
pub struct SweepReviewsResponse {
    pub swept: usize,
    pub expired_ids: Vec<String>,
}

/// `POST /api/v1/cognition/reviews/sweep` — sweep expired reviews.
pub async fn sweep_reviews_handler(
    State(state): State<AppState>,
) -> Result<Json<SweepReviewsResponse>, (StatusCode, String)> {
    let review_queue = state.0.review_queue.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Review queue not available".to_string(),
    ))?;

    let mut queue = review_queue.lock().unwrap();
    let expired = queue.sweep_expired();

    Ok(Json(SweepReviewsResponse {
        swept: expired.len(),
        expired_ids: expired,
    }))
}
