//! ZeroPoint v2 HTTP Server — Governance Demo API
//!
//! Exposes ZeroPoint's governance pipeline as a REST API, powering
//! the interactive demos on zeropoint.global.
//!
//! ## Demo Endpoints (no LLM required)
//! - POST /api/v1/guard/evaluate — Submit an action, see it evaluated by Guard + Policy
//! - POST /api/v1/capabilities/grant — Create a signed capability grant
//! - POST /api/v1/capabilities/delegate — Delegate from an existing grant
//! - POST /api/v1/capabilities/verify-chain — Verify a delegation chain
//! - GET  /api/v1/audit/entries — Retrieve audit trail entries
//! - GET  /api/v1/audit/chain-head — Get latest hash chain head
//! - GET  /api/v1/audit/verify — Verify chain integrity
//! - POST /api/v1/receipts/generate — Generate a signed receipt
//! - GET  /api/v1/identity — Server's public key and destination hash
//! - GET  /api/v1/policy/rules — List loaded policy rules
//!
//! ## Pipeline Endpoints (requires LLM config)
//! - POST /api/v1/chat — Submit message to governance pipeline
//! - POST /api/v1/conversations — Create new conversation

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;

use zp_audit::AuditStore;
use zp_core::{
    ActionType as CoreActionType, ActorId, CapabilityGrant, Channel, ConversationId,
    DelegationChain, GrantedCapability, OperatorIdentity, PolicyContext, PolicyDecision, Request,
    TrustTier,
};
use zp_pipeline::{Pipeline, PipelineConfig};
use zp_policy::{GateResult, GovernanceGate};

// ============================================================================
// Application State
// ============================================================================

struct ServerIdentity {
    signing_key: SigningKey,
    public_key_hex: String,
    destination_hash: String,
}

struct AppStateInner {
    gate: GovernanceGate,
    audit_store: std::sync::Mutex<AuditStore>,
    identity: ServerIdentity,
    pipeline: Option<Pipeline>,
    grants: std::sync::Mutex<Vec<CapabilityGrant>>,
}

#[derive(Clone)]
struct AppState(Arc<AppStateInner>);

impl AppState {
    async fn init() -> Self {
        // Generate server identity
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.as_bytes());

        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(verifying_key.as_bytes());
        let destination_hash = hex::encode(&hash[..16]);

        info!("Server identity: {}", &destination_hash);

        let identity = ServerIdentity {
            signing_key,
            public_key_hex,
            destination_hash,
        };

        // Audit store
        let data_dir =
            std::env::var("ZP_DATA_DIR").unwrap_or_else(|_| "./data/zeropoint".to_string());
        std::fs::create_dir_all(&data_dir).ok();
        let audit_path = std::path::Path::new(&data_dir).join("demo-audit.db");
        let audit_store = AuditStore::open(&audit_path).expect("Failed to open audit store");

        // Governance gate with default constitutional + operational rules
        // Sync chain head from existing audit store so restarts don't break the chain
        let mut gate = GovernanceGate::new("zp-server-demo");
        if let Ok(latest) = audit_store.get_latest_hash() {
            gate.set_audit_chain_head(latest);
        }

        // Optional pipeline (requires LLM provider)
        let pipeline = if std::env::var("ZP_LLM_ENABLED").unwrap_or_default() == "true" {
            let config = PipelineConfig {
                operator_identity: OperatorIdentity {
                    name: std::env::var("ZP_OPERATOR_NAME")
                        .unwrap_or_else(|_| "ZeroPoint".to_string()),
                    base_prompt: OperatorIdentity::default().base_prompt,
                },
                trust_tier: TrustTier::Tier0,
                data_dir: std::path::PathBuf::from(&data_dir),
                mesh: None,
            };
            Pipeline::new(config).ok()
        } else {
            None
        };

        AppState(Arc::new(AppStateInner {
            gate,
            audit_store: std::sync::Mutex::new(audit_store),
            identity,
            pipeline,
            grants: std::sync::Mutex::new(Vec::new()),
        }))
    }
}

// ============================================================================
// Main
// ============================================================================

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("zp=debug".parse().unwrap()))
        .init();

    let state = AppState::init().await;

    let app = Router::new()
        // Health
        .route("/api/v1/health", get(health_handler))
        // Identity
        .route("/api/v1/identity", get(identity_handler))
        // Guard / Policy (the core demo)
        .route("/api/v1/guard/evaluate", post(guard_evaluate_handler))
        .route("/api/v1/policy/rules", get(policy_rules_handler))
        // Capabilities
        .route("/api/v1/capabilities/grant", post(grant_handler))
        .route("/api/v1/capabilities/delegate", post(delegate_handler))
        .route(
            "/api/v1/capabilities/verify-chain",
            post(verify_chain_handler),
        )
        // Audit
        .route("/api/v1/audit/entries", get(audit_entries_handler))
        .route("/api/v1/audit/chain-head", get(audit_chain_head_handler))
        .route("/api/v1/audit/verify", get(audit_verify_handler))
        .route(
            "/api/v1/audit/simulate-tamper",
            post(audit_simulate_tamper_handler),
        )
        .route("/api/v1/audit/restore", post(audit_restore_handler))
        // Receipts
        .route("/api/v1/receipts/generate", post(receipt_generate_handler))
        // Pipeline (chat)
        .route("/api/v1/chat", post(chat_handler))
        .route("/api/v1/conversations", post(create_conversation_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let port = std::env::var("ZP_PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("0.0.0.0:{}", port);
    info!("ZeroPoint server on {}", addr);
    info!("Governance demo API ready");

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ============================================================================
// Health
// ============================================================================

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    pipeline_enabled: bool,
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pipeline_enabled: state.0.pipeline.is_some(),
    })
}

// ============================================================================
// Identity
// ============================================================================

#[derive(Serialize)]
struct IdentityResponse {
    public_key: String,
    destination_hash: String,
    trust_tier: String,
    algorithm: String,
}

async fn identity_handler(State(state): State<AppState>) -> Json<IdentityResponse> {
    Json(IdentityResponse {
        public_key: state.0.identity.public_key_hex.clone(),
        destination_hash: state.0.identity.destination_hash.clone(),
        trust_tier: "Tier1".to_string(),
        algorithm: "Ed25519".to_string(),
    })
}

// ============================================================================
// Guard / Policy Evaluation — THE CORE DEMO
// ============================================================================

#[derive(Deserialize)]
struct GuardEvaluateRequest {
    /// Human-readable action description (e.g., "delete all user data")
    action: String,
    /// Optional: structured action type
    action_type: Option<ActionTypeInput>,
    /// Trust tier of the requester (defaults to Tier0)
    trust_tier: Option<String>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", content = "target")]
enum ActionTypeInput {
    Chat,
    Read(String),
    Write(String),
    Execute(String),
    Delete(String),
    ApiCall(String),
    ConfigChange(String),
    CredentialAccess(String),
}

#[derive(Serialize)]
struct GuardEvaluateResponse {
    /// The governance decision
    decision: String,
    /// Whether the action is allowed
    allowed: bool,
    /// Whether the action was blocked
    blocked: bool,
    /// Risk level assessment
    risk_level: String,
    /// Trust tier of the evaluator
    trust_tier: String,
    /// Human-readable rationale
    rationale: String,
    /// Which policy rules were applied
    applied_rules: Vec<String>,
    /// The audit entry ID (proves this evaluation happened)
    audit_entry_id: String,
    /// The audit entry hash (part of the chain)
    audit_entry_hash: String,
    /// Previous hash in the chain
    audit_prev_hash: String,
    /// Receipt ID if generated
    receipt_id: Option<String>,
    /// The original action that was evaluated
    action_evaluated: String,
    /// Timestamp
    timestamp: String,
}

async fn guard_evaluate_handler(
    State(state): State<AppState>,
    Json(body): Json<GuardEvaluateRequest>,
) -> Result<Json<GuardEvaluateResponse>, (StatusCode, String)> {
    let trust_tier = match body.trust_tier.as_deref() {
        Some("Tier1") => TrustTier::Tier1,
        Some("Tier2") => TrustTier::Tier2,
        _ => TrustTier::Tier0,
    };

    // Parse the action into a structured ActionType
    let action_type = if let Some(at) = body.action_type {
        match at {
            ActionTypeInput::Chat => CoreActionType::Chat,
            ActionTypeInput::Read(t) => CoreActionType::Read { target: t },
            ActionTypeInput::Write(t) => CoreActionType::Write { target: t },
            ActionTypeInput::Execute(t) => CoreActionType::Execute { language: t },
            ActionTypeInput::Delete(t) => CoreActionType::FileOp {
                op: zp_core::FileOperation::Delete,
                path: t,
            },
            ActionTypeInput::ApiCall(t) => CoreActionType::ApiCall { endpoint: t },
            ActionTypeInput::ConfigChange(t) => CoreActionType::ConfigChange { setting: t },
            ActionTypeInput::CredentialAccess(t) => {
                CoreActionType::CredentialAccess { credential_ref: t }
            }
        }
    } else {
        // Infer from the action string
        infer_action_type(&body.action)
    };

    let context = PolicyContext {
        action: action_type,
        trust_tier,
        channel: Channel::Api,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: None,
    };

    let actor = ActorId::User("playground-visitor".to_string());
    let result: GateResult = state.0.gate.evaluate(&context, actor.clone());

    // Persist to audit store
    {
        let store = state.0.audit_store.lock().unwrap();
        store.append(result.audit_entry.clone()).ok();
    }

    let (decision_str, rationale) = match &result.decision {
        PolicyDecision::Allow { conditions } => {
            let conds = if conditions.is_empty() {
                "No conditions".to_string()
            } else {
                conditions.join("; ")
            };
            ("Allow".to_string(), format!("Action permitted. {}", conds))
        }
        PolicyDecision::Block {
            reason,
            policy_module,
        } => (
            "Block".to_string(),
            format!("Blocked by {}: {}", policy_module, reason),
        ),
        PolicyDecision::Warn {
            message,
            require_ack,
        } => (
            "Warn".to_string(),
            format!(
                "Warning: {}{}",
                message,
                if *require_ack {
                    " (acknowledgment required)"
                } else {
                    ""
                }
            ),
        ),
        PolicyDecision::Review { summary, .. } => (
            "Review".to_string(),
            format!("Review required: {}", summary),
        ),
        PolicyDecision::Sanitize { patterns } => (
            "Sanitize".to_string(),
            format!("Content sanitization applied ({} patterns)", patterns.len()),
        ),
    };

    let risk_str = format!("{:?}", result.risk_level);

    Ok(Json(GuardEvaluateResponse {
        decision: decision_str,
        allowed: result.is_allowed(),
        blocked: result.is_blocked(),
        risk_level: risk_str,
        trust_tier: format!("{:?}", result.trust_tier),
        rationale,
        applied_rules: result.applied_rules.clone(),
        audit_entry_id: format!("{}", result.audit_entry.id.0),
        audit_entry_hash: result.audit_entry.entry_hash.clone(),
        audit_prev_hash: result.audit_entry.prev_hash.clone(),
        receipt_id: result.receipt_id.clone(),
        action_evaluated: body.action,
        timestamp: Utc::now().to_rfc3339(),
    }))
}

/// Infer an ActionType from a natural-language action description.
fn infer_action_type(action: &str) -> CoreActionType {
    let lower = action.to_lowercase();

    if lower.contains("delete") || lower.contains("remove") || lower.contains("destroy") {
        CoreActionType::FileOp {
            op: zp_core::FileOperation::Delete,
            path: action.to_string(),
        }
    } else if lower.contains("disable")
        || lower.contains("override")
        || lower.contains("config")
        || lower.contains("setting")
    {
        CoreActionType::ConfigChange {
            setting: action.to_string(),
        }
    } else if lower.contains("credential")
        || lower.contains("password")
        || lower.contains("secret")
        || lower.contains("key")
        || lower.contains("token")
    {
        CoreActionType::CredentialAccess {
            credential_ref: action.to_string(),
        }
    } else if lower.contains("execute")
        || lower.contains("run")
        || lower.contains("deploy")
        || lower.contains("train")
        || lower.contains("build")
        || lower.contains("install")
    {
        CoreActionType::Execute {
            language: action.to_string(),
        }
    } else if lower.contains("write")
        || lower.contains("create")
        || lower.contains("update")
        || lower.contains("modify")
    {
        CoreActionType::Write {
            target: action.to_string(),
        }
    } else if lower.contains("read")
        || lower.contains("view")
        || lower.contains("list")
        || lower.contains("get")
    {
        CoreActionType::Read {
            target: action.to_string(),
        }
    } else if lower.contains("call")
        || lower.contains("api")
        || lower.contains("send")
        || lower.contains("email")
    {
        CoreActionType::ApiCall {
            endpoint: action.to_string(),
        }
    } else {
        CoreActionType::Chat
    }
}

// --- Policy Rules listing ---

#[derive(Serialize)]
struct PolicyRulesResponse {
    rules: Vec<PolicyRuleInfo>,
    total: usize,
}

#[derive(Serialize)]
struct PolicyRuleInfo {
    name: String,
    category: String,
    description: String,
}

async fn policy_rules_handler() -> Json<PolicyRulesResponse> {
    let rules = vec![
        PolicyRuleInfo {
            name: "HarmPrincipleRule".to_string(),
            category: "Constitutional".to_string(),
            description: "Tenet I — Do No Harm. Blocks actions targeting weaponization, surveillance, deception, and suppression of dissent. Non-removable.".to_string(),
        },
        PolicyRuleInfo {
            name: "SovereigntyRule".to_string(),
            category: "Constitutional".to_string(),
            description: "Tenet II — Sovereignty Is Sacred. Blocks attempts to disable the guard, truncate audit trails, forge capabilities, or override participant refusal. Non-removable.".to_string(),
        },
        PolicyRuleInfo {
            name: "CatastrophicActionRule".to_string(),
            category: "Operational".to_string(),
            description: "Blocks credential exfiltration, recursive self-modification, and similar catastrophic actions.".to_string(),
        },
        PolicyRuleInfo {
            name: "BulkOperationRule".to_string(),
            category: "Operational".to_string(),
            description: "Warns on bulk file operations affecting more than 100 files.".to_string(),
        },
        PolicyRuleInfo {
            name: "ReputationGateRule".to_string(),
            category: "Operational".to_string(),
            description: "Gates mesh actions based on peer reputation scores.".to_string(),
        },
        PolicyRuleInfo {
            name: "DefaultAllowRule".to_string(),
            category: "Fallback".to_string(),
            description: "Permissive baseline — allows actions not blocked by higher-priority rules.".to_string(),
        },
    ];
    let total = rules.len();
    Json(PolicyRulesResponse { rules, total })
}

// ============================================================================
// Capability Grants
// ============================================================================

#[derive(Deserialize)]
struct CreateGrantRequest {
    /// Who receives the grant (destination hash or name)
    grantee: String,
    /// Capability type: "read", "write", "execute", "admin"
    capability: String,
    /// Scope patterns (e.g., ["data/*", "logs/public"])
    scope: Option<Vec<String>>,
    /// Maximum delegation depth
    max_delegation_depth: Option<u8>,
}

#[derive(Serialize)]
struct GrantResponse {
    grant: serde_json::Value,
    receipt_id: String,
    signed: bool,
}

async fn grant_handler(
    State(state): State<AppState>,
    Json(body): Json<CreateGrantRequest>,
) -> Result<Json<GrantResponse>, (StatusCode, String)> {
    let scope = body.scope.unwrap_or_else(|| vec!["*".to_string()]);

    let capability = match body.capability.to_lowercase().as_str() {
        "read" => GrantedCapability::Read { scope },
        "write" => GrantedCapability::Write { scope },
        "execute" => GrantedCapability::Execute { languages: scope },
        "api" => GrantedCapability::ApiCall { endpoints: scope },
        "config" => GrantedCapability::ConfigChange { settings: scope },
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Unknown capability type: {}. Use read, write, execute, api, or config.",
                    other
                ),
            ))
        }
    };

    let mut grant = CapabilityGrant::new(
        state.0.identity.destination_hash.clone(),
        body.grantee.clone(),
        capability,
        format!("rcpt-{}", uuid::Uuid::now_v7()),
    )
    .with_max_delegation_depth(body.max_delegation_depth.unwrap_or(3));

    // Sign the grant
    grant.sign(&state.0.identity.signing_key);

    let receipt_id = grant.receipt_id.clone();
    let grant_json = serde_json::to_value(&grant).unwrap_or_default();

    // Store
    state.0.grants.lock().unwrap().push(grant);

    Ok(Json(GrantResponse {
        grant: grant_json,
        receipt_id,
        signed: true,
    }))
}

#[derive(Deserialize)]
struct DelegateRequest {
    /// ID of the parent grant to delegate from
    parent_grant_id: String,
    /// Who receives the delegated grant
    grantee: String,
    /// Capability type (must be subset of parent)
    capability: String,
    /// Scope patterns (must be subset of parent scope)
    scope: Option<Vec<String>>,
}

#[derive(Serialize)]
struct DelegateResponse {
    grant: serde_json::Value,
    receipt_id: String,
    delegation_depth: u8,
    chain_valid: bool,
}

async fn delegate_handler(
    State(state): State<AppState>,
    Json(body): Json<DelegateRequest>,
) -> Result<Json<DelegateResponse>, (StatusCode, String)> {
    let grants = state.0.grants.lock().unwrap();
    let parent = grants
        .iter()
        .find(|g| g.id == body.parent_grant_id)
        .ok_or((
            StatusCode::NOT_FOUND,
            format!("Parent grant '{}' not found", body.parent_grant_id),
        ))?
        .clone();
    drop(grants);

    let scope = body.scope.unwrap_or_else(|| match &parent.capability {
        GrantedCapability::Read { scope } => scope.clone(),
        GrantedCapability::Write { scope } => scope.clone(),
        GrantedCapability::Execute { languages } => languages.clone(),
        GrantedCapability::ApiCall { endpoints } => endpoints.clone(),
        GrantedCapability::ConfigChange { settings } => settings.clone(),
        _ => vec!["*".to_string()],
    });

    let capability = match body.capability.to_lowercase().as_str() {
        "read" => GrantedCapability::Read { scope },
        "write" => GrantedCapability::Write { scope },
        "execute" => GrantedCapability::Execute { languages: scope },
        "api" => GrantedCapability::ApiCall { endpoints: scope },
        "config" => GrantedCapability::ConfigChange { settings: scope },
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unknown capability: {}", other),
            ))
        }
    };

    let child = parent
        .delegate(
            body.grantee.clone(),
            capability,
            format!("rcpt-{}", uuid::Uuid::now_v7()),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Delegation failed: {}", e)))?;

    let depth = child.delegation_depth;
    let child_json = serde_json::to_value(&child).unwrap_or_default();
    let receipt_id = child.receipt_id.clone();

    // Verify the chain (parent + child)
    let chain_valid = DelegationChain::verify(vec![parent, child.clone()], false).is_ok();

    state.0.grants.lock().unwrap().push(child);

    Ok(Json(DelegateResponse {
        grant: child_json,
        receipt_id,
        delegation_depth: depth,
        chain_valid,
    }))
}

#[derive(Deserialize)]
struct VerifyChainRequest {
    /// Grant IDs in order from root to leaf
    grant_ids: Vec<String>,
}

#[derive(Serialize)]
struct VerifyChainResponse {
    valid: bool,
    chain_length: usize,
    root_grantor: Option<String>,
    leaf_grantee: Option<String>,
    max_depth: Option<u8>,
    current_depth: Option<u8>,
    can_extend: Option<bool>,
    error: Option<String>,
    invariants_checked: Vec<String>,
}

async fn verify_chain_handler(
    State(state): State<AppState>,
    Json(body): Json<VerifyChainRequest>,
) -> Json<VerifyChainResponse> {
    let grants_store = state.0.grants.lock().unwrap();

    let mut chain_grants = Vec::new();
    for id in &body.grant_ids {
        if let Some(g) = grants_store.iter().find(|g| &g.id == id) {
            chain_grants.push(g.clone());
        } else {
            return Json(VerifyChainResponse {
                valid: false,
                chain_length: 0,
                root_grantor: None,
                leaf_grantee: None,
                max_depth: None,
                current_depth: None,
                can_extend: None,
                error: Some(format!("Grant '{}' not found", id)),
                invariants_checked: vec![],
            });
        }
    }
    drop(grants_store);

    let invariants = vec![
        "Parent-child linkage (parent_grant_id)".to_string(),
        "Monotonic delegation depth".to_string(),
        "Scope subset constraint".to_string(),
        "Trust tier monotonicity".to_string(),
        "Expiration inheritance".to_string(),
        "Max delegation depth".to_string(),
        "Grantor-grantee continuity".to_string(),
        "Signature verification".to_string(),
    ];

    match DelegationChain::verify(chain_grants, false) {
        Ok(chain) => Json(VerifyChainResponse {
            valid: true,
            chain_length: chain.len(),
            root_grantor: Some(chain.root().grantor.clone()),
            leaf_grantee: Some(chain.leaf().grantee.clone()),
            max_depth: Some(chain.max_depth()),
            current_depth: Some(chain.current_depth()),
            can_extend: Some(chain.can_extend()),
            error: None,
            invariants_checked: invariants,
        }),
        Err(e) => Json(VerifyChainResponse {
            valid: false,
            chain_length: body.grant_ids.len(),
            root_grantor: None,
            leaf_grantee: None,
            max_depth: None,
            current_depth: None,
            can_extend: None,
            error: Some(format!("{}", e)),
            invariants_checked: invariants,
        }),
    }
}

// ============================================================================
// Audit Trail
// ============================================================================

#[derive(Deserialize)]
struct AuditEntriesQuery {
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AuditEntriesResponse {
    entries: Vec<serde_json::Value>,
    count: usize,
}

async fn audit_entries_handler(
    State(state): State<AppState>,
    Query(params): Query<AuditEntriesQuery>,
) -> Json<AuditEntriesResponse> {
    let limit = params.limit.unwrap_or(50);
    let store = state.0.audit_store.lock().unwrap();

    // Export chain entries (most recent)
    match store.export_chain(limit) {
        Ok(entries) => {
            let count = entries.len();
            let entries_json: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| serde_json::to_value(e).unwrap_or_default())
                .collect();
            Json(AuditEntriesResponse {
                entries: entries_json,
                count,
            })
        }
        Err(_) => Json(AuditEntriesResponse {
            entries: vec![],
            count: 0,
        }),
    }
}

#[derive(Serialize)]
struct ChainHeadResponse {
    latest_hash: String,
    chain_algorithm: String,
}

async fn audit_chain_head_handler(State(state): State<AppState>) -> Json<ChainHeadResponse> {
    let store = state.0.audit_store.lock().unwrap();
    let hash = store
        .get_latest_hash()
        .unwrap_or_else(|_| "unknown".to_string());
    Json(ChainHeadResponse {
        latest_hash: hash,
        chain_algorithm: "Blake3".to_string(),
    })
}

#[derive(Serialize)]
struct ChainVerifyResponse {
    valid: bool,
    entries_examined: usize,
    error: Option<String>,
}

async fn audit_verify_handler(State(state): State<AppState>) -> Json<ChainVerifyResponse> {
    let store = state.0.audit_store.lock().unwrap();
    match store.verify_with_report() {
        Ok(report) => Json(ChainVerifyResponse {
            valid: report.chain_valid,
            entries_examined: report.entries_examined,
            error: None,
        }),
        Err(e) => Json(ChainVerifyResponse {
            valid: false,
            entries_examined: 0,
            error: Some(format!("{}", e)),
        }),
    }
}

// ============================================================================
// Audit Tampering Simulation (demo only)
// ============================================================================

#[derive(Serialize)]
struct TamperResponse {
    tampered: bool,
    message: String,
    entry_id: Option<String>,
    original_hash: Option<String>,
    corrupted_hash: Option<String>,
}

fn truncate_for_display(s: &str) -> String {
    if s.len() > 40 {
        format!("{}...{}", &s[..20], &s[s.len() - 12..])
    } else {
        s.to_string()
    }
}

async fn audit_simulate_tamper_handler(
    State(state): State<AppState>,
) -> Result<Json<TamperResponse>, (StatusCode, String)> {
    let store = state.0.audit_store.lock().unwrap();

    // Get all entries, tamper with the middle one
    let entries = store
        .export_chain(100)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;

    if entries.len() < 2 {
        return Err((
            StatusCode::BAD_REQUEST,
            "Need at least 2 audit entries to simulate tampering. Run some Guard evaluations first.".to_string(),
        ));
    }

    // Pick the entry to tamper with (middle of the chain)
    let target_idx = entries.len() / 2;
    let target = &entries[target_idx];
    let entry_id = format!("{}", target.id.0);
    let original_hash = target.entry_hash.clone();
    // Encode the original hash in the corrupted value so restore can recover it
    let corrupted_hash = format!("TAMPERED_{}", original_hash);

    // Corrupt the entry_hash in the database
    store
        .execute_raw(&format!(
            "UPDATE audit_entries SET entry_hash = '{}' WHERE id = '{}'",
            corrupted_hash, entry_id
        ))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;

    Ok(Json(TamperResponse {
        tampered: true,
        message: format!(
            "Tampered with entry {} of {} — corrupted entry_hash to simulate an attacker modifying a record.",
            target_idx + 1,
            entries.len()
        ),
        entry_id: Some(entry_id),
        original_hash: Some(original_hash),
        corrupted_hash: Some(truncate_for_display(&corrupted_hash)),
    }))
}

async fn audit_restore_handler(
    State(state): State<AppState>,
) -> Result<Json<TamperResponse>, (StatusCode, String)> {
    let store = state.0.audit_store.lock().unwrap();

    // Find any tampered entries (those starting with "TAMPERED_")
    let entries = store
        .export_chain(100)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;

    let mut restored = 0;
    for entry in &entries {
        if entry.entry_hash.starts_with("TAMPERED_") {
            // Extract the original hash that was encoded after the TAMPERED_ prefix
            let original_hash = entry.entry_hash.strip_prefix("TAMPERED_").unwrap();
            let entry_id = format!("{}", entry.id.0);
            store
                .execute_raw(&format!(
                    "UPDATE audit_entries SET entry_hash = '{}' WHERE id = '{}'",
                    original_hash, entry_id
                ))
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;
            restored += 1;
        }
    }

    Ok(Json(TamperResponse {
        tampered: false,
        message: if restored > 0 {
            format!(
                "Restored {} tampered entries. Chain integrity recovered.",
                restored
            )
        } else {
            "No tampered entries found. Chain is already clean.".to_string()
        },
        entry_id: None,
        original_hash: None,
        corrupted_hash: None,
    }))
}

// ============================================================================
// Receipt Generation
// ============================================================================

#[derive(Deserialize)]
#[allow(dead_code)]
struct GenerateReceiptRequest {
    /// The action that was performed
    action: String,
    /// Status: "success", "failure", "refused"
    status: Option<String>,
    /// Policy decision that was made
    policy_decision: Option<String>,
}

#[derive(Serialize)]
struct GenerateReceiptResponse {
    receipt_id: String,
    receipt_type: String,
    status: String,
    content_hash: String,
    signature: String,
    signer_public_key: String,
    trust_grade: String,
    timestamp: String,
    action: String,
    chain_prev_hash: String,
}

async fn receipt_generate_handler(
    State(state): State<AppState>,
    Json(body): Json<GenerateReceiptRequest>,
) -> Json<GenerateReceiptResponse> {
    let receipt_id = format!("rcpt-{}", uuid::Uuid::now_v7());
    let timestamp = Utc::now();
    let status = body.status.unwrap_or_else(|| String::from("success"));

    // Build content to hash
    let content = serde_json::json!({
        "id": receipt_id,
        "action": body.action,
        "status": status,
        "timestamp": timestamp.to_rfc3339(),
        "signer": state.0.identity.destination_hash,
    });
    let content_bytes = serde_json::to_vec(&content).unwrap_or_default();
    let content_hash = blake3::hash(&content_bytes).to_hex().to_string();

    // Sign the content hash
    let signature_bytes = state.0.identity.signing_key.sign(content_hash.as_bytes());
    let signature_hex = hex::encode(signature_bytes.to_bytes());

    // Get chain head for linkage
    let chain_prev_hash = {
        let store = state.0.audit_store.lock().unwrap();
        store
            .get_latest_hash()
            .unwrap_or_else(|_| blake3::hash(b"").to_hex().to_string())
    };

    Json(GenerateReceiptResponse {
        receipt_id,
        receipt_type: "execution".to_string(),
        status,
        content_hash,
        signature: signature_hex,
        signer_public_key: state.0.identity.public_key_hex.clone(),
        trust_grade: "B".to_string(),
        timestamp: timestamp.to_rfc3339(),
        action: body.action,
        chain_prev_hash,
    })
}

// ============================================================================
// Pipeline (Chat) — original endpoints
// ============================================================================

#[derive(Deserialize)]
struct ChatRequest {
    conversation_id: Option<String>,
    message: String,
}

#[derive(Serialize)]
struct ChatResponse {
    conversation_id: String,
    response: String,
    model_used: String,
}

async fn chat_handler(
    State(state): State<AppState>,
    Json(body): Json<ChatRequest>,
) -> Result<Json<ChatResponse>, (StatusCode, String)> {
    let pipeline = state.0.pipeline.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Pipeline not enabled. Set ZP_LLM_ENABLED=true to use chat endpoints.".to_string(),
    ))?;

    let conversation_id = body
        .conversation_id
        .and_then(|id| uuid::Uuid::parse_str(&id).ok().map(ConversationId))
        .unwrap_or_else(ConversationId::new);

    let request = Request::new(conversation_id.clone(), body.message, Channel::Api);

    match pipeline.handle(request).await {
        Ok(response) => Ok(Json(ChatResponse {
            conversation_id: conversation_id.0.to_string(),
            response: response.content,
            model_used: response.model_used,
        })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Pipeline error: {}", e),
        )),
    }
}

#[derive(Serialize)]
struct ConversationResponse {
    conversation_id: String,
}

async fn create_conversation_handler(
    State(state): State<AppState>,
) -> Result<Json<ConversationResponse>, (StatusCode, String)> {
    let pipeline = state.0.pipeline.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "Pipeline not enabled".to_string(),
    ))?;
    let id = pipeline.new_conversation();
    Ok(Json(ConversationResponse {
        conversation_id: id.0.to_string(),
    }))
}
