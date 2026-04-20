//! Fleet management API handlers — node registry, heartbeat, and status.
//!
//! These endpoints expose the `NodeRegistry` from `zp-mesh` so fleet operators
//! can monitor node health, trigger heartbeats, and query fleet-wide status.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use serde::Deserialize;

use crate::AppState;
use zp_mesh::NodeHeartbeat;

/// POST /api/v1/fleet/heartbeat — register or refresh a node.
pub async fn fleet_heartbeat_handler(
    State(state): State<AppState>,
    Json(heartbeat): Json<NodeHeartbeat>,
) -> (StatusCode, Json<Value>) {
    let node_id = heartbeat.node_id.clone();
    state.0.node_registry.heartbeat(heartbeat).await;

    // Broadcast heartbeat as SSE event
    let item = crate::events::EventStreamItem::system(
        "node_heartbeat",
        format!("heartbeat from {}", node_id),
    );
    crate::events::broadcast_event(&state.0.event_tx, item);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "node_id": node_id,
        })),
    )
}

/// GET /api/v1/fleet/nodes — list all fleet nodes.
pub async fn fleet_nodes_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    let nodes = state.0.node_registry.list_nodes().await;
    (
        StatusCode::OK,
        Json(serde_json::to_value(&nodes).unwrap_or_default()),
    )
}

/// GET /api/v1/fleet/nodes/:id — get a single node by ID.
pub async fn fleet_node_detail_handler(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.0.node_registry.get_node(&node_id).await {
        Some(node) => (
            StatusCode::OK,
            Json(serde_json::to_value(&node).unwrap_or_default()),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "node not found",
                "node_id": node_id,
            })),
        ),
    }
}

/// GET /api/v1/fleet/summary — fleet-wide status summary.
pub async fn fleet_summary_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    // Run a sweep first to update stale/offline status
    state.0.node_registry.sweep().await;
    let summary = state.0.node_registry.summary().await;
    (
        StatusCode::OK,
        Json(serde_json::to_value(&summary).unwrap_or_default()),
    )
}

// ---------------------------------------------------------------------------
// Policy distribution endpoints (P5-3)
// ---------------------------------------------------------------------------

/// Request body for initiating a policy push.
#[derive(Deserialize)]
pub struct PolicyPushRequest {
    pub policy_version: String,
    pub policy_hash: String,
}

/// POST /api/v1/fleet/policy/push — push a policy version to all online fleet nodes.
pub async fn fleet_policy_push_handler(
    State(state): State<AppState>,
    Json(req): Json<PolicyPushRequest>,
) -> (StatusCode, Json<Value>) {
    let rollout_id = state
        .0
        .policy_distributor
        .push_policy(req.policy_version.clone(), req.policy_hash)
        .await;

    // Broadcast as SSE event
    let item = crate::events::EventStreamItem::system(
        "policy_push",
        format!("policy rollout {} initiated for {}", rollout_id, req.policy_version),
    );
    crate::events::broadcast_event(&state.0.event_tx, item);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "initiated",
            "rollout_id": rollout_id,
        })),
    )
}

/// GET /api/v1/fleet/policy/rollouts — list all rollout IDs.
pub async fn fleet_rollouts_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    let ids = state.0.policy_distributor.list_rollouts().await;
    (StatusCode::OK, Json(serde_json::json!({ "rollouts": ids })))
}

/// GET /api/v1/fleet/policy/rollouts/:id — get rollout summary.
pub async fn fleet_rollout_detail_handler(
    State(state): State<AppState>,
    Path(rollout_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    match state.0.policy_distributor.rollout_summary(&rollout_id).await {
        Some(summary) => (
            StatusCode::OK,
            Json(serde_json::to_value(&summary).unwrap_or_default()),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "rollout not found" })),
        ),
    }
}

/// Request body for acknowledging a policy delivery.
#[derive(Deserialize)]
pub struct PolicyAckRequest {
    pub node_id: String,
}

/// POST /api/v1/fleet/policy/rollouts/:id/ack — acknowledge policy application.
pub async fn fleet_rollout_ack_handler(
    State(state): State<AppState>,
    Path(rollout_id): Path<String>,
    Json(req): Json<PolicyAckRequest>,
) -> (StatusCode, Json<Value>) {
    let acked = state
        .0
        .policy_distributor
        .acknowledge(&rollout_id, &req.node_id)
        .await;

    if acked {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "acknowledged" })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "rollout or node not found" })),
        )
    }
}

// ---------------------------------------------------------------------------
// Node management endpoints
// ---------------------------------------------------------------------------

/// DELETE /api/v1/fleet/nodes/:id — deregister a node.
pub async fn fleet_deregister_handler(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> (StatusCode, Json<Value>) {
    let removed = state.0.node_registry.deregister(&node_id).await;
    if removed {
        (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "deregistered",
                "node_id": node_id,
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "node not found",
                "node_id": node_id,
            })),
        )
    }
}
