//! P6-4: WASM policy runtime integration — server endpoints for managing
//! WASM policy modules at runtime.
//!
//! All WASM-specific functionality is behind `cfg(feature = "policy-wasm")`.
//! Non-WASM builds get fallback handlers that return 503.
//!
//! Endpoints:
//!   POST /api/v1/policy/wasm/load         — load a WASM module from base64
//!   GET  /api/v1/policy/wasm              — list loaded modules
//!   POST /api/v1/policy/wasm/:hash/disable — disable a module
//!   POST /api/v1/policy/wasm/:hash/enable  — re-enable a module

use axum::{extract::State, http::StatusCode, Json};

use crate::AppState;

// ── Feature-gated handlers ─────────────────────────────────────────────

/// POST /api/v1/policy/wasm/load
///
/// Load a WASM policy module. Body: `{ "wasm_base64": "..." }`.
/// The module must export the required ABI (name_ptr, name_len, alloc, evaluate, evaluate_len).
#[cfg(feature = "policy-wasm")]
pub async fn wasm_load_handler(
    State(state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    use base64::Engine as _;

    let wasm_b64 = match body.get("wasm_base64").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Missing field: wasm_base64" })),
            );
        }
    };

    let wasm_bytes = match base64::engine::general_purpose::STANDARD.decode(wasm_b64) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("Invalid base64: {}", e) })),
            );
        }
    };

    // Access the WASM registry through the governance gate
    let registry = match state.0.gate.wasm_registry() {
        Some(r) => r,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "WASM policy registry not initialized",
                    "hint": "GovernanceGate must be created with PolicyEngine::with_wasm()",
                })),
            );
        }
    };

    match registry.load(&wasm_bytes) {
        Ok(metadata) => {
            tracing::info!(
                "Loaded WASM policy module '{}' (hash: {}, {} bytes)",
                metadata.name,
                metadata.content_hash,
                metadata.size_bytes
            );

            // Emit audit event
            crate::tool_chain::emit_tool_receipt(
                &state.0.audit_store,
                &format!("policy:wasm:loaded:{}", metadata.content_hash),
                Some(&format!("name={} size={}", metadata.name, metadata.size_bytes)),
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "ok": true,
                    "module": {
                        "name": metadata.name,
                        "content_hash": metadata.content_hash,
                        "size_bytes": metadata.size_bytes,
                    },
                })),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Failed to load WASM module: {}", e),
            })),
        ),
    }
}

/// GET /api/v1/policy/wasm — list loaded WASM policy modules.
#[cfg(feature = "policy-wasm")]
pub async fn wasm_list_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let (modules, runtime_available) = match state.0.gate.wasm_registry() {
        Some(r) => {
            let entries: Vec<serde_json::Value> = r
                .list()
                .into_iter()
                .map(|(meta, status)| {
                    serde_json::json!({
                        "name": meta.name,
                        "content_hash": meta.content_hash,
                        "size_bytes": meta.size_bytes,
                        "status": format!("{:?}", status),
                    })
                })
                .collect();
            (entries, true)
        }
        None => (Vec::new(), false),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "modules": modules,
            "count": modules.len(),
            "runtime_available": runtime_available,
        })),
    )
}

/// POST /api/v1/policy/wasm/:hash/disable
#[cfg(feature = "policy-wasm")]
pub async fn wasm_disable_handler(
    State(state): State<AppState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.0.gate.wasm_registry() {
        Some(r) => {
            if r.disable(&hash) {
                tracing::info!("Disabled WASM policy module: {}", hash);
                crate::tool_chain::emit_tool_receipt(
                    &state.0.audit_store,
                    &format!("policy:wasm:disabled:{}", hash),
                    None,
                );
                (StatusCode::OK, Json(serde_json::json!({ "ok": true, "hash": hash, "status": "disabled" })))
            } else {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("Module {} not found", hash) })))
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "WASM runtime not initialized" })),
        ),
    }
}

/// POST /api/v1/policy/wasm/:hash/enable
#[cfg(feature = "policy-wasm")]
pub async fn wasm_enable_handler(
    State(state): State<AppState>,
    axum::extract::Path(hash): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.0.gate.wasm_registry() {
        Some(r) => {
            if r.enable(&hash) {
                tracing::info!("Enabled WASM policy module: {}", hash);
                crate::tool_chain::emit_tool_receipt(
                    &state.0.audit_store,
                    &format!("policy:wasm:enabled:{}", hash),
                    None,
                );
                (StatusCode::OK, Json(serde_json::json!({ "ok": true, "hash": hash, "status": "active" })))
            } else {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": format!("Module {} not found", hash) })))
            }
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "WASM runtime not initialized" })),
        ),
    }
}

// ── Fallback handlers (non-WASM builds) ────────────────────────────────

#[cfg(not(feature = "policy-wasm"))]
pub async fn wasm_load_handler(
    State(_state): State<AppState>,
    Json(_body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    wasm_unavailable()
}

#[cfg(not(feature = "policy-wasm"))]
pub async fn wasm_list_handler(
    State(_state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    wasm_unavailable()
}

#[cfg(not(feature = "policy-wasm"))]
pub async fn wasm_disable_handler(
    State(_state): State<AppState>,
    axum::extract::Path(_hash): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    wasm_unavailable()
}

#[cfg(not(feature = "policy-wasm"))]
pub async fn wasm_enable_handler(
    State(_state): State<AppState>,
    axum::extract::Path(_hash): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    wasm_unavailable()
}

#[cfg(not(feature = "policy-wasm"))]
fn wasm_unavailable() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "WASM policy runtime not available",
            "hint": "Build with --features policy-wasm to enable",
        })),
    )
}
