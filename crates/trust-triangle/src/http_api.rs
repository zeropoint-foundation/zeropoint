//! HTTP API for Trust Triangle nodes.
//!
//! Each node exposes three endpoints:
//! - POST /api/v1/introduce — introduction protocol
//! - POST /api/v1/query — data query (requires prior introduction)
//! - GET /health — node health check

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};

use zp_introduction::request::IntroductionRequest;
use zp_introduction::response::IntroductionResponse;

use crate::data::{ClinicDb, PharmacyDb};
use crate::node::NodeContext;
use crate::types::{HealthResponse, QueryRequest, QueryResponse};

/// The role a node plays in the demo.
#[derive(Debug, Clone)]
pub enum NodeRole {
    Clinic,
    Pharmacy,
}

/// Shared state for the HTTP server.
pub struct AppState {
    pub ctx: NodeContext,
    pub role: NodeRole,
    pub clinic_db: Option<ClinicDb>,
    pub pharmacy_db: Option<PharmacyDb>,
}

/// Build the Axum router for a node.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/introduce", post(handle_introduce))
        .route("/api/v1/query", post(handle_query))
        .route("/health", get(handle_health))
        .with_state(state)
}

/// POST /api/v1/introduce
async fn handle_introduce(
    State(state): State<Arc<AppState>>,
    Json(request): Json<IntroductionRequest>,
) -> Result<Json<IntroductionResponse>, (StatusCode, String)> {
    let (response, decision) = state
        .ctx
        .handle_introduction(&request)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    tracing::info!(
        node = %state.ctx.node_name,
        decision = ?decision,
        "Introduction handled"
    );

    Ok(Json(response))
}

/// POST /api/v1/query
async fn handle_query(
    State(state): State<Arc<AppState>>,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, (StatusCode, String)> {
    let response = match state.role {
        NodeRole::Clinic => {
            let db = state
                .clinic_db
                .as_ref()
                .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "No clinic database".into()))?;
            crate::clinic::handle_query(&state.ctx, db, &request)
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?
        }
        NodeRole::Pharmacy => {
            let db = state
                .pharmacy_db
                .as_ref()
                .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "No pharmacy database".into()))?;
            crate::pharmacy::handle_query(&state.ctx, db, &request)
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?
        }
    };

    tracing::info!(
        node = %state.ctx.node_name,
        redacted = response.redacted_count,
        "Query handled"
    );

    Ok(Json(response))
}

/// GET /health
async fn handle_health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        node: state.ctx.node_name.clone(),
        genesis_fingerprint: state.ctx.genesis_fingerprint(),
        status: "ok".into(),
    })
}
