//! Analysis Engine — receipt chain intelligence for governed tools.
//!
//! This module bridges ZeroPoint's receipt chain into the MLE STAR and
//! Monte Carlo engines, enabling tools like IronClaw to organically learn
//! about their own behavior through the governance layer.
//!
//! ## Architecture
//!
//! ```text
//!   Receipt Chain (audit store)
//!       │
//!       ▼
//!   ReceiptObserver         ← scans chain, converts events → Observations
//!       │
//!       ├──► MLE STAR       ← builds expertise profiles per tool
//!       │      │
//!       │      ▼
//!       │    ExpertiseProfile, ReadinessAssessment, Hypotheses
//!       │
//!       └──► Monte Carlo    ← risk simulation using expertise data
//!              │
//!              ▼
//!            SimulationResults, RiskAssessment
//! ```
//!
//! ## Progressive Disclosure
//!
//! Tools discover analysis capabilities through a three-tier index:
//!
//!   Tier 1 — `/api/v1/analysis/index`       → capability listing
//!   Tier 2 — `/api/v1/analysis/expertise`    → tool profiles + readiness
//!   Tier 3 — `/api/v1/analysis/simulate`     → Monte Carlo deep analysis
//!
//! Every query emits a receipt, so the analysis itself is auditable.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::RwLock;

use mle_star_engine::{LearningContext, MLEStarConfig, MLEStarEngine, Observation};
use monte_carlo_engine::{MonteCarloConfig, MonteCarloEngine, ParameterBounds};

use crate::tool_chain;
use crate::AppState;
use zp_audit::AuditStore;
use zp_core::{AuditAction, AuditEntry};

// ── Shared analysis state ──────────────────────────────────────────────

/// Analysis engines, shared across handlers via AppState.
pub struct AnalysisEngines {
    pub mle_star: MLEStarEngine,
    pub monte_carlo: MonteCarloEngine,
    /// Tracks the last chain index we scanned, so we only process new receipts.
    pub last_scanned_index: RwLock<usize>,
}

impl Default for AnalysisEngines {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisEngines {
    pub fn new() -> Self {
        Self {
            mle_star: MLEStarEngine::with_config(
                MLEStarConfig::default()
                    .with_min_observations(5) // lower threshold for tool lifecycle events
                    .with_confidence_threshold(0.6)
                    .with_hypothesis_generation(true)
                    .with_sensitivity_analysis(true),
            ),
            monte_carlo: MonteCarloEngine::with_config(
                MonteCarloConfig::default()
                    .with_num_simulations(5000)
                    .with_confidence_level(0.95),
            ),
            last_scanned_index: RwLock::new(0),
        }
    }

    /// Scan new receipt chain entries and convert them to MLE STAR observations.
    ///
    /// This is the bridge: receipt chain events → statistical observations.
    /// Called before each analysis query to ensure we have the latest data.
    ///
    /// `get_entries` returns newest-first, so we reverse to process in order.
    /// We track the total count to avoid re-processing entries.
    pub async fn ingest_receipts(&self, audit_store: &Arc<std::sync::Mutex<AuditStore>>) {
        let entries = {
            let store = match audit_store.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            // Get all tool lifecycle entries (newest first)
            match store.get_entries(tool_chain::tool_lifecycle_conv_id(), 1000) {
                Ok(e) => e,
                Err(_) => return,
            }
        };

        let total = entries.len();
        let mut last_idx = self.last_scanned_index.write().await;

        if total <= *last_idx {
            return; // no new entries
        }

        // entries is newest-first; the "new" ones are at indices 0..(total - last_idx)
        let new_count = total - *last_idx;
        let new_entries = &entries[..new_count];

        // Process oldest-first so observations accumulate in chronological order
        for entry in new_entries.iter().rev() {
            if let Some(obs) = receipt_to_observation(entry) {
                if let Err(e) = self.mle_star.observe(obs).await {
                    tracing::warn!("Failed to record observation: {}", e);
                }
            }
        }

        *last_idx = total;
    }
}

/// Convert a single audit entry into an MLE STAR observation (if applicable).
fn receipt_to_observation(entry: &AuditEntry) -> Option<Observation> {
    let event = match &entry.action {
        AuditAction::SystemEvent { event } => event,
        _ => return None,
    };

    if !event.starts_with("tool:") {
        return None;
    }

    let parts: Vec<&str> = event.splitn(4, ':').collect();
    if parts.len() < 3 {
        return None;
    }

    match parts[1] {
        "configured" => {
            let tool = parts[2];
            let obs = Observation::new(tool, "lifecycle:configured")
                .with_success(true)
                .with_quality(1.0)
                .with_duration(0);
            Some(obs)
        }
        "preflight" if parts.len() >= 4 => {
            let sub = parts[2];
            let tool = parts[3];
            match sub {
                "passed" => {
                    let obs = Observation::new(tool, "lifecycle:preflight")
                        .with_success(true)
                        .with_quality(1.0)
                        .with_duration(0);
                    Some(obs)
                }
                "failed" => {
                    let obs = Observation::new(tool, "lifecycle:preflight")
                        .with_success(false)
                        .with_quality(0.0)
                        .with_duration(0)
                        .with_output_metric("issues", 1.0);
                    Some(obs)
                }
                _ => None,
            }
        }
        "launched" => {
            let tool = parts[2];
            // Parse duration from detail if available (e.g., "cmd=... port=9100")
            let obs = Observation::new(tool, "lifecycle:launch")
                .with_success(true)
                .with_quality(1.0)
                .with_duration(0);
            Some(obs)
        }
        "stopped" => {
            let tool = parts[2];
            // Graceful stop is a neutral observation — not failure
            let obs = Observation::new(tool, "lifecycle:stop")
                .with_success(true)
                .with_quality(0.5) // neutral — not great, not bad
                .with_duration(0);
            Some(obs)
        }
        "crashed" => {
            let tool = parts[2];
            let obs = Observation::new(tool, "lifecycle:crash")
                .with_success(false)
                .with_quality(0.0)
                .with_duration(0);
            Some(obs)
        }
        "health" if parts.len() >= 4 => {
            let status = parts[2];
            let tool = parts[3];
            let (success, quality) = match status {
                "up" => (true, 1.0),
                "degraded" => (true, 0.4),
                "down" => (false, 0.0),
                _ => return None,
            };
            let obs = Observation::new(tool, "health:check")
                .with_success(success)
                .with_quality(quality)
                .with_duration(0);
            Some(obs)
        }
        "port" if parts.len() >= 4 && parts[2] == "assigned" => {
            // Event format: tool:port:assigned:{name}:{port}
            // parts[3] contains "{name}:{port}" since we used splitn(4)
            let tool = parts[3].split(':').next().unwrap_or(parts[3]);
            let obs = Observation::new(tool, "lifecycle:port")
                .with_success(true)
                .with_quality(1.0)
                .with_duration(0);
            Some(obs)
        }
        "codebase" if parts.len() >= 4 => {
            // tool:codebase:tree:toolname, tool:codebase:read:toolname, etc.
            let action = parts[2]; // tree, read, search
            let tool = parts[3];
            let obs = Observation::new(tool, format!("codebase:{}", action))
                .with_success(true)
                .with_quality(1.0)
                .with_duration(0);
            Some(obs)
        }
        _ => None,
    }
}

// ── API handlers ───────────────────────────────────────────────────────

/// Query parameters for the analysis index.
#[derive(Deserialize)]
pub struct IndexQuery {
    /// Tool requesting the index (for receipt chain auditing).
    pub tool: Option<String>,
}

/// `GET /api/v1/analysis/index` — progressive disclosure tier 1.
///
/// Returns the capabilities available through the analysis API,
/// including what engines are active and what endpoints exist.
pub async fn index_handler(
    State(state): State<AppState>,
    Query(q): Query<IndexQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tool = q.tool.as_deref().unwrap_or("unknown");

    // Emit receipt for the discovery itself
    let event = format!("tool:analysis:discover:{}", tool);
    let detail = "tier=index".to_string();
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "engines": {
                "mle_star": {
                    "name": "MLE STAR Engine",
                    "purpose": "Expertise pre-learning — builds statistical profiles of tool behavior from receipt chain data",
                    "capabilities": [
                        "observe — record tool execution observations",
                        "prelearn — build expertise profile before production use",
                        "readiness — assess production readiness with data-driven scoring",
                        "hypotheses — generate testable predictions from expertise"
                    ],
                    "endpoint": "/api/v1/analysis/expertise"
                },
                "monte_carlo": {
                    "name": "Monte Carlo Simulation Engine",
                    "purpose": "Probabilistic risk assessment — simulate tool behavior under uncertainty",
                    "capabilities": [
                        "simulate — run stochastic simulations with configurable parameters",
                        "compare — A/B test two outcome distributions",
                        "risk — Value at Risk, Conditional VaR, max drawdown analysis"
                    ],
                    "endpoint": "/api/v1/analysis/simulate"
                }
            },
            "data_source": "Receipt chain (audit store) — all tool lifecycle events are automatically ingested",
            "receipt_types_consumed": [
                "tool:configured:*",
                "tool:preflight:passed:*",
                "tool:preflight:failed:*",
                "tool:launched:*",
                "tool:stopped:*",
                "tool:crashed:*",
                "tool:health:up:*",
                "tool:health:down:*",
                "tool:health:degraded:*",
                "tool:port:assigned:*",
                "tool:codebase:tree:*",
                "tool:codebase:read:*",
                "tool:codebase:search:*"
            ],
            "progressive_disclosure": {
                "tier_1": "/api/v1/analysis/index — capability discovery (you are here)",
                "tier_2": "/api/v1/analysis/expertise?tool=<name> — expertise profiles + readiness",
                "tier_3": "/api/v1/analysis/simulate — Monte Carlo deep analysis"
            }
        })),
    )
}

/// Query parameters for expertise endpoint.
#[derive(Deserialize)]
pub struct ExpertiseQuery {
    /// Target tool to get expertise for.
    pub target: String,
    /// Tool making the request (for auditing).
    pub tool: Option<String>,
    /// Whether to include hypotheses in the response.
    pub hypotheses: Option<bool>,
}

/// `GET /api/v1/analysis/expertise` — progressive disclosure tier 2.
///
/// Returns the MLE STAR expertise profile for a tool, including
/// readiness assessment and optional hypotheses.
pub async fn expertise_handler(
    State(state): State<AppState>,
    Query(q): Query<ExpertiseQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tool = q.tool.as_deref().unwrap_or("unknown");
    let engines = &state.0.analysis;

    // Ingest latest receipts before answering
    engines.ingest_receipts(&state.0.audit_store).await;

    let obs_count = engines.mle_star.observation_count(&q.target).await;

    // Emit receipt
    let event = format!("tool:analysis:expertise:{}:{}", tool, q.target);
    let detail = format!("observations={}", obs_count);
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    if obs_count == 0 {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "target": q.target,
                "status": "no_data",
                "message": format!(
                    "No observations recorded for '{}'. Launch and use the tool to start building expertise.",
                    q.target
                ),
                "observation_count": 0,
                "hint": "Receipt chain events (configure, preflight, launch, health checks) automatically generate observations."
            })),
        );
    }

    // Run pre-learning
    let context = LearningContext::new().with_hypothesis_generation(q.hypotheses.unwrap_or(true));
    let result = engines.mle_star.prelearn(&q.target, &context).await;

    match result {
        Ok(prelearn) => {
            let mut response = serde_json::json!({
                "target": q.target,
                "status": if prelearn.readiness.production_ready { "ready" } else { "learning" },
                "observation_count": prelearn.expertise.observation_count,
                "profile": {
                    "success_rate": prelearn.expertise.overall_success_rate,
                    "quality": prelearn.expertise.overall_quality,
                    "confidence": prelearn.expertise.profile_confidence,
                    "capabilities": prelearn.expertise.capability_estimates,
                    "task_affinities": prelearn.expertise.task_affinities,
                    "patterns": prelearn.expertise.performance_patterns,
                },
                "readiness": {
                    "score": prelearn.readiness.score,
                    "production_ready": prelearn.readiness.production_ready,
                    "data_gaps": prelearn.readiness.data_gaps,
                    "recommended_tests": prelearn.readiness.recommended_tests,
                    "warnings": prelearn.readiness.warnings,
                },
                "recommendations": prelearn.recommendations,
                "warnings": prelearn.warnings,
                "duration_ms": prelearn.duration_ms,
            });

            if q.hypotheses.unwrap_or(true) && !prelearn.hypotheses.is_empty() {
                response["hypotheses"] = serde_json::json!(prelearn.hypotheses);
            }

            (StatusCode::OK, Json(response))
        }
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "target": q.target,
                "status": "insufficient_data",
                "observation_count": obs_count,
                "message": e.to_string(),
                "hint": "Continue using the tool to accumulate observations."
            })),
        ),
    }
}

/// Query parameters for listing all tool expertise.
#[derive(Deserialize)]
pub struct ListQuery {
    pub tool: Option<String>,
}

/// `GET /api/v1/analysis/tools` — list all tools with observation data.
pub async fn tools_handler(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tool = q.tool.as_deref().unwrap_or("unknown");
    let engines = &state.0.analysis;

    // Ingest latest receipts
    engines.ingest_receipts(&state.0.audit_store).await;

    let targets = engines.mle_star.list_targets().await;

    // For each target, get basic stats
    let mut tool_summaries = Vec::new();
    for target in &targets {
        let count = engines.mle_star.observation_count(target).await;
        let readiness = engines.mle_star.assess_readiness_for(target).await;
        tool_summaries.push(serde_json::json!({
            "name": target,
            "observation_count": count,
            "readiness_score": readiness.score,
            "production_ready": readiness.production_ready,
        }));
    }

    // Emit receipt
    let event = format!("tool:analysis:list:{}", tool);
    let detail = format!("targets={}", targets.len());
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tools": tool_summaries,
            "total": targets.len(),
        })),
    )
}

/// Request body for Monte Carlo simulation.
#[derive(Deserialize)]
pub struct SimulateRequest {
    /// Tool being analyzed.
    pub target: String,
    /// Tool making the request (for auditing).
    pub tool: Option<String>,
    /// Number of simulations to run (default: 5000).
    pub simulations: Option<usize>,
    /// Parameter to simulate: "success_rate", "quality", "latency".
    pub metric: Option<String>,
}

/// `POST /api/v1/analysis/simulate` — progressive disclosure tier 3.
///
/// Runs a Monte Carlo simulation using the tool's expertise profile
/// to project performance distributions and risk metrics.
pub async fn simulate_handler(
    State(state): State<AppState>,
    Json(req): Json<SimulateRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let tool = req.tool.as_deref().unwrap_or("unknown");
    let engines = &state.0.analysis;

    // Ingest latest receipts
    engines.ingest_receipts(&state.0.audit_store).await;

    // Get expertise profile for the target
    let expertise = match engines.mle_star.get_expertise(&req.target).await {
        Some(e) => e,
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "target": req.target,
                    "status": "no_expertise",
                    "message": format!(
                        "No expertise profile for '{}'. Use /api/v1/analysis/expertise first to build one.",
                        req.target
                    ),
                })),
            );
        }
    };

    let metric = req.metric.as_deref().unwrap_or("success_rate");

    // Extract the capability estimate for the requested metric
    let estimate = match expertise.capability_estimates.get(metric) {
        Some(e) => e,
        None => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "target": req.target,
                    "metric": metric,
                    "status": "no_data",
                    "message": format!("No capability estimate for metric '{}'. Available: {:?}",
                        metric, expertise.capability_estimates.keys().collect::<Vec<_>>()),
                })),
            );
        }
    };

    // Configure simulation around the estimated parameter
    let mean = estimate.estimate;
    let se = estimate.standard_error.max(0.01); // floor to avoid zero variance

    // Create parameter bounds centered on the estimate
    let bounds = vec![ParameterBounds::new(
        metric,
        (mean - 3.0 * se).max(0.0),
        (mean + 3.0 * se).min(1.0),
    )
    .with_distribution(monte_carlo_engine::DistributionHint::Normal { mean, std_dev: se })];

    let num_sims = req.simulations.unwrap_or(5000);
    let mc = MonteCarloEngine::with_config(
        MonteCarloConfig::default()
            .with_num_simulations(num_sims)
            .with_confidence_level(0.95),
    );

    // Run simulation: sample from the estimated distribution
    let metric_key = metric.to_string();
    let sim_result = mc
        .simulate(&bounds, move |params| {
            // The evaluation function returns the sampled metric value
            params.get(&metric_key).unwrap_or(0.0)
        })
        .await;

    // Emit receipt
    let event = format!("tool:analysis:simulate:{}:{}", tool, req.target);
    let detail = format!("metric={} simulations={}", metric, num_sims);
    tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

    match sim_result {
        Ok(results) => {
            let dist = &results.experimental_distribution;
            let ci = &results.confidence_intervals;

            let mut response = serde_json::json!({
                "target": req.target,
                "metric": metric,
                "simulations": num_sims,
                "distribution": {
                    "mean": dist.mean,
                    "median": dist.median,
                    "std_dev": dist.std_dev,
                    "skewness": dist.skewness,
                    "percentiles": dist.percentiles,
                },
                "confidence_intervals": {
                    "mean_ci": ci.mean_ci,
                    "median_ci": ci.median_ci,
                },
                "expertise_basis": {
                    "estimate": estimate.estimate,
                    "standard_error": estimate.standard_error,
                    "observation_count": estimate.observation_count,
                },
            });

            // Risk assessment is optional (only present when comparing distributions)
            if let Some(risk) = &results.risk_assessment {
                response["risk"] = serde_json::json!({
                    "var_95": risk.value_at_risk,
                    "cvar_95": risk.conditional_var,
                    "max_drawdown": risk.max_drawdown,
                    "risk_adjusted_score": risk.risk_adjusted_score,
                });
            }

            (StatusCode::OK, Json(response))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Simulation failed: {}", e),
                "target": req.target,
                "metric": metric,
            })),
        ),
    }
}
