//! HTTP handlers for the operator artifact library.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use zp_artifacts::{
    Library, LibraryError, LibraryFilter, LibraryStateFilter,
    artifact::{ArtifactId, ArtifactKind},
    kinds::chain_narration::{self, ChainNarrationComposition, NormalizedReceipt},
};
use zp_receipt::{ClaimMetadata, ReceiptBuilder, ClaimSemantics, ReceiptType, Status};

use crate::AppState;

// ── compose ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ComposeRequest {
    pub receipts: Vec<NormalizedReceipt>,
    #[serde(default)]
    pub voice_anchor: String,
    #[serde(default = "default_provider")]
    pub llm_provider: String,
    #[serde(default = "default_model")]
    pub llm_model: String,
}

fn default_provider() -> String { "anthropic".to_string() }
fn default_model() -> String { "claude-3-5-sonnet".to_string() }

pub async fn compose_handler(
    State(_state): State<AppState>,
    Json(req): Json<ComposeRequest>,
) -> Response {
    let Some(comp) = chain_narration::build_composition(
        &req.receipts,
        &req.voice_anchor,
        &req.llm_provider,
        &req.llm_model,
    ) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "receipts list is empty"}))).into_response();
    };
    (StatusCode::OK, Json(comp)).into_response()
}

// ── submit ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    pub composition: ChainNarrationComposition,
    pub llm_middle: String,
    pub operator_id: Option<String>,
    pub supersedes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub artifact_id: String,
}

pub async fn submit_handler(
    State(state): State<AppState>,
    Json(req): Json<SubmitRequest>,
) -> Response {
    let operator_id = req.operator_id
        .unwrap_or_else(|| state.0.identity.destination_hash.clone());

    let supersedes = match req.supersedes.as_deref() {
        Some(hex) => match ArtifactId::from_hex(hex) {
            Ok(id) => Some(id),
            Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("bad supersedes id: {e}")}))).into_response(),
        },
        None => None,
    };

    match chain_narration::generate_candidate(
        state.0.artifact_library.as_ref(),
        req.composition,
        &req.llm_middle,
        &operator_id,
        supersedes,
    ).await {
        Ok(id) => (StatusCode::OK, Json(SubmitResponse { artifact_id: id.to_hex() })).into_response(),
        Err(e) => library_err(e),
    }
}

// ── list ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub kind: Option<String>,
    pub state: Option<String>,
    pub limit: Option<usize>,
}

pub async fn list_handler(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Response {
    let filter = LibraryFilter {
        kind: q.kind.as_deref().and_then(parse_kind),
        state: q.state.as_deref().and_then(parse_state_filter),
        operator_id: Some(state.0.identity.destination_hash.clone()),
        limit: q.limit.unwrap_or(50),
        ..Default::default()
    };
    match state.0.artifact_library.list(&filter).await {
        Ok(ids) => {
            let hex_ids: Vec<String> = ids.iter().map(|id| id.to_hex()).collect();
            (StatusCode::OK, Json(serde_json::json!({"artifact_ids": hex_ids}))).into_response()
        }
        Err(e) => library_err(e),
    }
}

// ── get ───────────────────────────────────────────────────────────────────────

pub async fn get_handler(
    State(state): State<AppState>,
    Path(id_hex): Path<String>,
) -> Response {
    let id = match ArtifactId::from_hex(&id_hex) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid artifact id"}))).into_response(),
    };
    match state.0.artifact_library.get(&id).await {
        Ok(Some(art)) => (StatusCode::OK, Json(art)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response(),
        Err(e) => library_err(e),
    }
}

// ── sign ──────────────────────────────────────────────────────────────────────

pub async fn sign_handler(
    State(state): State<AppState>,
    Path(id_hex): Path<String>,
) -> Response {
    let id = match ArtifactId::from_hex(&id_hex) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid artifact id"}))).into_response(),
    };

    let signing_key = &state.0.identity.signing_key;
    let pubkey = signing_key.verifying_key().to_bytes();

    // Get artifact kind before signing (for receipt metadata)
    let kind_str = match state.0.artifact_library.get(&id).await {
        Ok(Some(art)) => art.kind.as_str().to_string(),
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "not found"}))).into_response(),
        Err(e) => return library_err(e),
    };

    match state.0.artifact_library.sign(&id, signing_key, pubkey).await {
        Ok(()) => {
            // Emit ArtifactSignedClaim on the audit chain
            let operator_id = &state.0.identity.destination_hash;
            let receipt = ReceiptBuilder::new(ReceiptType::ArtifactSignedClaim, operator_id)
                .status(Status::Success)
                .claim_semantics(ClaimSemantics::AuthorizationGrant)
                .claim_metadata(ClaimMetadata::ArtifactSigned {
                    artifact_id: id_hex.clone(),
                    kind: kind_str,
                    supersedes: None,
                })
                .finalize();

            if let Ok(mut store) = state.0.audit_store.lock() {
                let unsealed = zp_audit::UnsealedEntry::new(
                    zp_core::ActorId::User(operator_id.clone()),
                    zp_core::AuditAction::SystemEvent {
                        event: "artifact:signed".to_string(),
                    },
                    zp_core::ConversationId::new(),
                    zp_core::PolicyDecision::Allow { conditions: vec![] },
                    "artifact-library",
                )
                .with_receipt(receipt);
                let _ = store.append(unsealed);
            }

            (StatusCode::OK, Json(serde_json::json!({"signed": true, "artifact_id": id_hex}))).into_response()
        }
        Err(e) => library_err(e),
    }
}

// ── reject ────────────────────────────────────────────────────────────────────

pub async fn reject_handler(
    State(state): State<AppState>,
    Path(id_hex): Path<String>,
) -> Response {
    let id = match ArtifactId::from_hex(&id_hex) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid artifact id"}))).into_response(),
    };
    match state.0.artifact_library.reject(&id).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"rejected": true, "artifact_id": id_hex}))).into_response(),
        Err(e) => library_err(e),
    }
}

// ── canonical ─────────────────────────────────────────────────────────────────

pub async fn canonical_handler(
    State(state): State<AppState>,
    Path(kind_str): Path<String>,
) -> Response {
    let Some(kind) = parse_kind(&kind_str) else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "unknown kind — valid: chain_narration"}))).into_response();
    };
    let operator_id = &state.0.identity.destination_hash;
    match state.0.artifact_library.latest_signed(&kind, operator_id).await {
        Ok(Some(art)) => (StatusCode::OK, Json(art)).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "no signed artifact for this kind"}))).into_response(),
        Err(e) => library_err(e),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse_kind(s: &str) -> Option<ArtifactKind> {
    match s {
        "chain_narration" => Some(ArtifactKind::ChainNarration),
        _ => None,
    }
}

fn parse_state_filter(s: &str) -> Option<LibraryStateFilter> {
    match s {
        "candidate" => Some(LibraryStateFilter::Candidate),
        "signed" => Some(LibraryStateFilter::Signed),
        "superseded" => Some(LibraryStateFilter::Superseded),
        "rejected" => Some(LibraryStateFilter::Rejected),
        _ => None,
    }
}

fn library_err(e: LibraryError) -> Response {
    let (status, msg) = match &e {
        LibraryError::NotFound(_) => (StatusCode::NOT_FOUND, e.to_string()),
        LibraryError::WrongState(_) => (StatusCode::CONFLICT, e.to_string()),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}
