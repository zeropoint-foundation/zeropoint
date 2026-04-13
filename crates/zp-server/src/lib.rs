//! ZeroPoint v2 Server Library
//!
//! Exposes the governance API as a library so it can be embedded
//! in the unified `zp` binary.

pub mod analysis;
pub mod attestations;
pub mod codebase;
pub mod exec_ws;
pub mod onboard;
pub mod proxy;
pub mod security;
pub mod tool_chain;
pub mod tool_ports;
pub mod tool_proxy;
pub mod tool_state;

use axum::http::HeaderValue;
use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{error, info, warn};

use zp_audit::AuditStore;
use zp_core::{
    ActionType as CoreActionType, ActorId, CapabilityGrant, Channel, ConversationId,
    DelegationChain, GrantedCapability, OperatorIdentity, PolicyContext, PolicyDecision, Request,
    TrustTier,
};
use zp_pipeline::{Pipeline, PipelineConfig};
use zp_policy::{GateResult, GovernanceGate};

// ============================================================================
// Configuration
// ============================================================================

pub struct ServerConfig {
    pub bind_addr: String,
    pub port: u16,
    pub data_dir: String,
    pub home_dir: std::path::PathBuf,
    pub open_dashboard: bool,
    pub llm_enabled: bool,
    pub operator_name: String,
    /// Optional path to the Bridge UI dist directory.
    /// When set, serves the Bridge at /bridge.
    pub bridge_dir: Option<std::path::PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let port: u16 = std::env::var("ZP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);
        let bind = std::env::var("ZP_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let home = dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join(".zeropoint");

        Self {
            bind_addr: bind,
            port,
            data_dir: std::env::var("ZP_DATA_DIR")
                .unwrap_or_else(|_| home.join("data").to_string_lossy().to_string()),
            home_dir: home,
            open_dashboard: true,
            llm_enabled: std::env::var("ZP_LLM_ENABLED").unwrap_or_default() == "true",
            operator_name: std::env::var("ZP_OPERATOR_NAME")
                .unwrap_or_else(|_| "ZeroPoint".to_string()),
            bridge_dir: std::env::var("ZP_BRIDGE_DIR")
                .ok()
                .map(std::path::PathBuf::from),
        }
    }
}

impl ServerConfig {
    /// Construct from the unified `ZpConfig` (new canonical path).
    pub fn from_zp_config(cfg: &zp_config::ZpConfig) -> Self {
        Self {
            bind_addr: cfg.bind.value.clone(),
            port: cfg.port.value,
            data_dir: cfg.data_dir.value.to_string_lossy().to_string(),
            home_dir: cfg.home_dir.value.clone(),
            open_dashboard: cfg.open_dashboard.value,
            llm_enabled: cfg.llm_enabled.value,
            operator_name: cfg.operator_name.value.clone(),
            bridge_dir: std::env::var("ZP_BRIDGE_DIR")
                .ok()
                .map(std::path::PathBuf::from),
        }
    }
}

// ============================================================================
// Genesis Ceremony
// ============================================================================

/// Genesis record — written once at first run, never modified.
#[derive(Serialize, Deserialize, Clone)]
pub struct GenesisRecord {
    pub timestamp: String,
    pub public_key: String,
    pub destination_hash: String,
    pub algorithm: String,
    pub initial_posture_score: u8,
    pub constitutional_rules: Vec<String>,
    pub chain_genesis_hash: String,
}

/// Load or create the node's persistent Ed25519 identity.
///
/// Priority:
/// 1. **Operator key from keyring** (Genesis→Operator hierarchy) — the correct path.
///    The signing key is the Operator's Ed25519 key from `~/.zeropoint/keys/`.
/// 2. **Legacy `identity.key` file** — for deployments that predate the hierarchy.
///    Loads the raw Ed25519 key and logs a migration notice.
/// 3. **First run (Genesis)** — no identity exists. Generates a new Ed25519 key
///    and writes `identity.key` as a bootstrap. The onboarding flow will later
///    create the full hierarchy and the next server start will use path 1.
/// Canon permission check run at server startup. Refuses to boot if:
/// - `~/.zeropoint` or `~/.zeropoint/keys` is not 0700
/// - any `*.secret` or `*.secret.enc` file is group- or world-readable
/// - a plaintext `genesis.secret` or `operator.secret` filename exists
#[cfg(unix)]
fn enforce_canon_permissions(home_dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    for dir in [home_dir.to_path_buf(), home_dir.join("keys")] {
        if dir.exists() {
            let mode = std::fs::metadata(&dir)
                .map_err(|e| format!("failed to stat {:?}: {}", dir, e))?
                .permissions()
                .mode()
                & 0o777;
            if mode != 0o700 {
                return Err(format!(
                    "refusing to start: {:?} has mode {:o}, expected 0700 (canon). \
                     Run `chmod 700 {:?}` to fix.",
                    dir, mode, dir
                ));
            }
        }
    }
    let keys_dir = home_dir.join("keys");
    if keys_dir.exists() {
        for entry in std::fs::read_dir(&keys_dir)
            .map_err(|e| format!("failed to read {:?}: {}", keys_dir, e))?
        {
            let entry = entry.map_err(|e| format!("dir entry error: {}", e))?;
            let path = entry.path();
            let name = entry.file_name().into_string().unwrap_or_default();
            if name.ends_with(".secret") || name.ends_with(".secret.enc") {
                let mode = std::fs::metadata(&path)
                    .map_err(|e| format!("failed to stat {:?}: {}", path, e))?
                    .permissions()
                    .mode()
                    & 0o777;
                if mode != 0o600 {
                    return Err(format!(
                        "refusing to start: {:?} has mode {:o}, expected 0600 (canon). \
                         A root-owned secret is group- or world-readable.",
                        path, mode
                    ));
                }
                if name == "genesis.secret" || name == "operator.secret" {
                    return Err(format!(
                        "refusing to start: plaintext secret {:?} found. \
                         Canon stores root keys in the OS credential store or encrypted \
                         at rest ({}.enc). Run the rotation runbook.",
                        path, name
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_canon_permissions(_home_dir: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// Build a `ServerIdentity` from a loaded `OperatorKey` and log the source.
fn finalize_operator_identity(
    operator: zp_keys::hierarchy::OperatorKey,
    source: &str,
) -> (ServerIdentity, bool) {
    use sha2::{Digest, Sha256};
    let pub_bytes = operator.public_key();
    let public_key_hex = hex::encode(pub_bytes);
    let hash = Sha256::digest(&pub_bytes);
    let destination_hash = hex::encode(&hash[..16]);
    let signing_key = SigningKey::from_bytes(&operator.secret_key());

    info!(
        "Identity from Operator key ({}): {}...{}",
        source,
        &public_key_hex[..12],
        &public_key_hex[public_key_hex.len() - 8..]
    );

    (
        ServerIdentity {
            signing_key,
            public_key_hex,
            destination_hash,
            operator_key: Some(operator),
            from_hierarchy: true,
        },
        false,
    )
}

/// Sovereignty-aware Operator load.
///
/// Reads the configured sovereignty mode from `genesis.json`, asks the
/// matching provider to unwrap the Genesis secret (which may trigger a
/// biometric scan or hardware-wallet confirmation), then hands that
/// secret to the keyring to decrypt the on-disk `operator.secret.enc`
/// blob. The Genesis secret is zeroized before this function returns.
fn load_operator_via_sovereignty_provider(
    keyring: &zp_keys::Keyring,
    genesis_record_path: &std::path::Path,
) -> Result<zp_keys::hierarchy::OperatorKey, String> {
    use zeroize::Zeroize;

    let raw = std::fs::read_to_string(genesis_record_path)
        .map_err(|e| format!("failed to read genesis.json: {}", e))?;
    let record: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse genesis.json: {}", e))?;
    let mode_str = record
        .get("sovereignty_mode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "genesis.json missing sovereignty_mode".to_string())?;
    let mode = zp_keys::SovereigntyMode::from_onboard_str(mode_str).resolve();

    let provider = zp_keys::provider_for(mode);
    let mut genesis_secret = provider
        .load_secret()
        .map_err(|e| format!("{} provider could not unlock Genesis: {}", mode.display_name(), e))?;

    let result = keyring
        .load_operator_with_genesis_secret(&genesis_secret)
        .map_err(|e| format!("operator decrypt failed: {}", e));

    genesis_secret.zeroize();
    result
}

fn load_or_create_identity(config: &ServerConfig) -> (ServerIdentity, bool) {
    use sha2::{Digest, Sha256};
    if let Err(msg) = enforce_canon_permissions(&config.home_dir) {
        error!("{}", msg);
        eprintln!("\x1b[31m✗\x1b[0m {}", msg);
        std::process::exit(1);
    }
    let keyring_path = config.home_dir.join("keys");
    let genesis_record_path = config.home_dir.join("genesis.json");
    let identity_path = config.home_dir.join("identity.key");

    // ── Path 1: Operator key from the hierarchy ────────────────────────
    //
    // Canon order:
    //   1a. Fast path — credential store. Works for Keychain / Touch ID /
    //       Windows Hello / Secret Service where the OS holds the Operator
    //       secret directly. No Genesis unwrap needed.
    //   1b. Sovereignty-provider path — for hardware wallets, file-based,
    //       and biometric modes that don't stage the Operator secret in
    //       the OS credential store, read the sovereignty mode from
    //       genesis.json, ask that provider to unwrap the Genesis secret
    //       (which may trigger a biometric / HW presence prompt), then
    //       decrypt the on-disk operator.secret.enc blob with a vault key
    //       derived from the Genesis secret.
    //
    // If genesis.json exists but both paths fail, the identity is set up
    // but unreachable — we hard-error instead of silently bootstrapping a
    // new temp key, which would split the identity.
    if let Ok(keyring) = zp_keys::Keyring::open(&keyring_path) {
        // 1a — credential store fast path
        if let Ok(operator) = keyring.load_operator() {
            return finalize_operator_identity(operator, "credential store");
        }

        // 1b — sovereignty-provider unwrap path
        if genesis_record_path.exists() {
            match load_operator_via_sovereignty_provider(&keyring, &genesis_record_path) {
                Ok(operator) => {
                    return finalize_operator_identity(operator, "sovereignty provider");
                }
                Err(msg) => {
                    let err = format!(
                        "refusing to start: genesis.json is present but the Operator key \
                         could not be unlocked ({}). Run `zp init` only if you intend to \
                         reinitialize, or follow the rotation runbook to recover.",
                        msg
                    );
                    error!("{}", err);
                    eprintln!("\x1b[31m✗\x1b[0m {}", err);
                    std::process::exit(1);
                }
            }
        }
    }

    // Canon: no legacy identity.key migration. If it's sitting on disk
    // without a genesis record it's a leftover from a pre-canon build and
    // the operator should rotate, not silently adopt it.
    if identity_path.exists() && !genesis_record_path.exists() {
        let err = format!(
            "refusing to start: legacy plaintext {:?} is present without a genesis \
             record. Archive and remove it, then run `zp init` to establish a \
             canonical identity.",
            identity_path
        );
        error!("{}", err);
        eprintln!("\x1b[31m✗\x1b[0m {}", err);
        std::process::exit(1);
    }

    // ── Path 2: First run — bootstrap identity ─────────────────────────
    // Pre-onboarding the server still needs *some* signing key so the
    // /onboard HTTP surface can respond. This is NOT Genesis and NOT
    // Operator — it's a disposable transport key, rotated away the moment
    // `zp init` completes and writes genesis.json.
    std::fs::create_dir_all(&config.home_dir).expect("Failed to create ~/.zeropoint");
    let key = SigningKey::generate(&mut rand::rngs::OsRng);

    // Write bootstrap key with restrictive permissions.
    // This is temporary — the onboarding flow creates the full hierarchy
    // (Genesis→Operator) and the next server start will use Path 1.
    std::fs::write(&identity_path, key.to_bytes()).expect("Failed to write identity key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600)).ok();
    }

    let verifying_key = key.verifying_key();
    let public_key_hex = hex::encode(verifying_key.as_bytes());
    let hash = Sha256::digest(verifying_key.as_bytes());
    let destination_hash = hex::encode(&hash[..16]);

    (
        ServerIdentity {
            signing_key: key,
            public_key_hex,
            destination_hash,
            operator_key: None,
            from_hierarchy: false,
        },
        true,
    )
}

/// Perform the Genesis ceremony — canonicalize the initial state.
///
/// NOTE: This does NOT write genesis.json — that is the onboarding ceremony's
/// responsibility. The onboarding flow writes a full genesis record with operator
/// name, sovereignty mode, and constitutional gates. This function only logs the
/// bootstrap banner and initializes the audit chain hash.
fn perform_genesis(identity: &ServerIdentity, config: &ServerConfig) {
    let genesis_path = config.home_dir.join("genesis.json");
    if genesis_path.exists() {
        return; // Already canonicalized by onboarding
    }

    info!("═══════════════════════════════════════════════════════");
    info!("  ZEROPOINT — AWAITING GENESIS");
    info!("═══════════════════════════════════════════════════════");
    info!("");
    info!("  Bootstrap identity generated:");
    info!(
        "  Public key:    {}...{}",
        &identity.public_key_hex[..16],
        &identity.public_key_hex[identity.public_key_hex.len() - 8..]
    );
    info!("  Destination:   {}", identity.destination_hash);
    info!("  Algorithm:     Ed25519");
    info!("");
    info!("  → Complete onboarding at /onboard to create your Genesis record.");
    info!("    The Genesis ceremony establishes your operator identity,");
    info!("    sovereignty provider, and constitutional bedrock.");
    info!("═══════════════════════════════════════════════════════");
    info!("");
}

// ============================================================================
// Application State (public)
// ============================================================================

pub struct ServerIdentity {
    /// The Ed25519 signing key — sourced from the Operator key in the certificate
    /// hierarchy (Genesis→Operator). Falls back to legacy `identity.key` file
    /// for deployments that predate the hierarchy, with automatic migration.
    pub signing_key: SigningKey,
    pub public_key_hex: String,
    pub destination_hash: String,
    /// The Operator key from the zp-keys hierarchy, if available.
    /// Holds the certificate chain (Genesis→Operator) for verifiable signing.
    /// `None` only during the Genesis ceremony itself (before the Operator key exists).
    pub operator_key: Option<zp_keys::hierarchy::OperatorKey>,
    /// Whether the identity was sourced from the key hierarchy (true) or
    /// the legacy `identity.key` file (false). Used for migration awareness.
    pub from_hierarchy: bool,
}

pub struct AppStateInner {
    pub gate: GovernanceGate,
    pub audit_store: std::sync::Mutex<AuditStore>,
    pub identity: ServerIdentity,
    pub pipeline: Option<Pipeline>,
    pub grants: std::sync::Mutex<Vec<CapabilityGrant>>,
    pub data_dir: String,
    /// Vault key resolved once at startup from the OS credential store.
    /// Cached here so we never hit the Keychain again during the session.
    pub vault_key: Option<zp_keys::ResolvedVaultKey>,
    /// Manages port assignments for governed tools so they don't collide.
    pub port_allocator: tool_ports::PortAllocator,
    /// MLE STAR + Monte Carlo analysis engines fed by receipt chain data.
    pub analysis: analysis::AnalysisEngines,
    /// Server port — needed by proxy for subdomain URL generation.
    pub config_port: u16,
}

#[derive(Clone)]
pub struct AppState(pub Arc<AppStateInner>);

impl AppState {
    pub async fn init(config: &ServerConfig) -> Self {
        // Load or create persistent identity (Genesis on first run)
        let (identity, is_genesis) = load_or_create_identity(config);

        if is_genesis {
            perform_genesis(&identity, config);
        } else {
            info!("Server identity: {}", &identity.destination_hash);
        }

        // Audit store
        std::fs::create_dir_all(&config.data_dir).ok();
        let audit_path = std::path::Path::new(&config.data_dir).join("audit.db");
        let audit_store = AuditStore::open(&audit_path).expect("Failed to open audit store");

        // Governance gate
        let mut gate = GovernanceGate::new(&identity.destination_hash);
        if let Ok(latest) = audit_store.get_latest_hash() {
            gate.set_audit_chain_head(latest);
        }

        // Optional pipeline
        let pipeline = if config.llm_enabled {
            let pipeline_config = PipelineConfig {
                operator_identity: OperatorIdentity {
                    name: config.operator_name.clone(),
                    base_prompt: OperatorIdentity::default().base_prompt,
                },
                trust_tier: TrustTier::Tier0,
                data_dir: std::path::PathBuf::from(&config.data_dir),
                mesh: None,
            };
            Pipeline::new(pipeline_config).ok()
        } else {
            None
        };

        // Initialize attestation database
        attestations::init_attestation_db(&config.data_dir)
            .expect("Failed to initialize attestation database");

        // Resolve vault key once at startup — this is the single Keychain access.
        // Cached for the lifetime of the server so the OS never re-prompts.
        let vault_key = {
            let home = dirs::home_dir().unwrap_or_default().join(".zeropoint");
            match zp_keys::Keyring::open(home.join("keys"))
                .and_then(|kr| zp_keys::resolve_vault_key(&kr))
            {
                Ok(resolved) => {
                    info!(
                        "Vault key resolved (source: {:?}) — cached for session",
                        resolved.source
                    );
                    Some(resolved)
                }
                Err(e) => {
                    info!("Vault key not available: {} — vault operations will require re-auth", e);
                    None
                }
            }
        };

        let audit_store = std::sync::Mutex::new(audit_store);

        // Receipt: keychain access is a trust-relevant event on the chain
        if vault_key.is_some() {
            let source_str = vault_key.as_ref()
                .map(|v| format!("{:?}", v.source))
                .unwrap_or_default();
            tool_chain::emit_tool_receipt(
                &audit_store,
                "system:keychain:accessed",
                Some(&format!("source={}", source_str)),
            );
        }

        // Port allocator — manages the 9100–9199 range for governed tools
        let port_allocator = tool_ports::PortAllocator::new(
            std::path::Path::new(&config.data_dir),
        );

        AppState(Arc::new(AppStateInner {
            gate,
            audit_store,
            identity,
            pipeline,
            grants: std::sync::Mutex::new(Vec::new()),
            data_dir: config.data_dir.clone(),
            vault_key,
            port_allocator,
            analysis: analysis::AnalysisEngines::new(),
            config_port: config.port,
        }))
    }
}

// ============================================================================
// Build Application Router (public)
// ============================================================================

pub fn build_app(state: AppState, config: &ServerConfig) -> Router {
    // CORS: allow *.localhost subdomains (tool proxies), localhost, and production.
    // Subdomain proxy means tool pages at ember.localhost:3000 need to call
    // ZP APIs at localhost:3000 — that's cross-origin, so CORS must allow it.
    let port = config.port;
    let cors = if config.bind_addr == "127.0.0.1" || config.bind_addr == "localhost" {
        CorsLayer::new()
            .allow_origin(tower_http::cors::AllowOrigin::predicate(
                move |origin: &HeaderValue, _parts: &axum::http::request::Parts| {
                    let Ok(origin_str) = origin.to_str() else { return false };
                    if origin_str == format!("http://localhost:{}", port)
                        || origin_str == format!("http://127.0.0.1:{}", port)
                    {
                        return true;
                    }
                    // Allow any *.localhost:{port} subdomain
                    if origin_str.starts_with("http://")
                        && origin_str.ends_with(&format!(".localhost:{}", port))
                    {
                        return true;
                    }
                    origin_str == "https://zeropoint.global"
                },
            ))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    } else {
        CorsLayer::new()
            .allow_origin("https://zeropoint.global".parse::<HeaderValue>().unwrap())
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };

    let mut router = Router::new()
        // Root: redirect to onboarding if no genesis, otherwise dashboard
        .route("/", get(root_handler))
        .route("/dashboard", get(dashboard_handler))
        // Health
        .route("/api/v1/health", get(health_handler))
        // Identity
        .route("/api/v1/identity", get(identity_handler))
        // Gate evaluation (SDK endpoint)
        .route("/api/v1/evaluate", post(guard_evaluate_handler))
        // Guard / Policy (legacy)
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
        .route("/api/v1/audit/clear", post(audit_clear_handler))
        // Receipts
        .route("/api/v1/receipts/generate", post(receipt_generate_handler))
        // Pipeline (chat)
        .route("/api/v1/chat", post(chat_handler))
        .route("/api/v1/conversations", post(create_conversation_handler))
        // Stats
        .route("/api/v1/stats", get(stats_handler))
        // Security posture + topology
        .route("/api/v1/security/posture", get(security_posture_handler))
        .route("/api/v1/security/topology", get(topology_handler))
        // Configured tools (cockpit)
        .route("/api/v1/tools", get(tools_handler))
        .route("/api/v1/tools/launch", post(tools_launch_handler))
        .route("/api/v1/tools/stop", post(tools_stop_handler))
        .route("/api/v1/tools/log", get(tools_log_handler))
        .route("/api/v1/tools/preflight", post(tools_preflight_handler))
        .route("/api/v1/tools/preflight", get(tools_preflight_status_handler))
        .route("/api/v1/tools/receipt", post(tools_receipt_handler))
        .route("/api/v1/tools/chain", get(tools_chain_handler))
        .route("/api/v1/tools/ports", get(tool_proxy::port_assignments_handler))
        .route("/api/v1/tools/:tool_name/preflight", post(tools_single_preflight_handler))
        .route("/api/v1/tools/:tool_name/configure", post(tools_configure_handler))
        .route("/api/v1/tools/:tool_name/repair", post(tools_repair_handler))
        // Governed codebase — self-describing trust infrastructure
        .route("/api/v1/codebase/tree", get(codebase::tree_handler))
        .route("/api/v1/codebase/read", get(codebase::read_handler))
        .route("/api/v1/codebase/search", get(codebase::search_handler))
        // Analysis engines — receipt chain intelligence (MLE STAR + Monte Carlo)
        .route("/api/v1/analysis/index", get(analysis::index_handler))
        .route("/api/v1/analysis/expertise", get(analysis::expertise_handler))
        .route("/api/v1/analysis/tools", get(analysis::tools_handler))
        .route("/api/v1/analysis/simulate", post(analysis::simulate_handler))
        // System state — derived from receipt chain (the big one)
        .route("/api/v1/system/state", get(tool_state::system_state_handler))
        // Tool paths are now subdomain-based: http://{name}.localhost:3000/
        // No legacy /tools/{name}/ routes — clean break.
        // Genesis record
        .route("/api/v1/genesis", get(genesis_handler))
        // Attestations
        .route(
            "/api/v1/attestations",
            post(attestations::issue_attestation_handler),
        )
        .route(
            "/api/v1/attestations",
            get(attestations::lookup_attestation_handler),
        )
        .route(
            "/api/v1/attestations/all",
            get(attestations::list_attestations_handler),
        )
        // Anonymous course analytics
        .route(
            "/api/v1/analytics/event",
            post(attestations::record_analytics_handler),
        )
        .route(
            "/api/v1/analytics/course",
            get(attestations::course_analytics_handler),
        )
        // API Proxy — governance-aware LLM provider proxy
        .route("/api/v1/proxy/*proxy_path", post(proxy::proxy_handler))
        // WebSocket endpoint for Bridge UI
        .route("/wss", get(ws_upgrade_handler))
        // Governed execution surface — cockpit terminal
        .route("/ws/exec", get(exec_ws::exec_ws_handler))
        // Onboard: browser-based onboarding flow
        .route("/onboard", get(onboard_page_handler))
        .route("/api/onboard/ws", get(onboard::onboard_ws_handler))
        // Speak: live TTS reader (Piper voice-tuner-server companion)
        .route("/speak", get(speak_page_handler))
        // Ecosystem: interactive knowledge graph + provenance chain + live state
        .route("/ecosystem", get(ecosystem_page_handler))
        .layer(cors)
        .with_state(state.clone());

    // ── Subdomain proxy middleware ─────────────────────────────────
    // This MUST wrap the entire router as an outer layer so it runs
    // BEFORE route matching.  When Host is `{tool}.localhost:3000`,
    // the request is proxied to the tool's port — explicit routes
    // like "/" and "/dashboard" are never reached.  For bare
    // `localhost:3000`, the middleware passes through to the router.
    let proxy_state = state;
    router = router.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let state = proxy_state.clone();
            async move {
                // Extract Host header
                let host = req.headers()
                    .get(axum::http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if let Some(tool_name) = tool_proxy::extract_subdomain(&host) {
                    // Subdomain request → proxy to tool, skip all routes.
                    // We must inject CORS headers ourselves because the
                    // CORS layer sits inside this middleware and never runs
                    // for proxied responses.
                    let origin = req.headers()
                        .get(axum::http::header::ORIGIN)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let path = req.uri().path().trim_start_matches('/').to_string();
                    let mut resp = match tool_proxy::proxy_inner(&state, &tool_name, &path, req).await {
                        Ok(resp) => resp,
                        Err(status) => status.into_response(),
                    };

                    // Add CORS headers for allowed origins (dashboard at
                    // localhost:{port} or sibling subdomains).
                    let cfg_port = state.0.config_port;
                    let allowed = origin == format!("http://localhost:{}", cfg_port)
                        || origin == format!("http://127.0.0.1:{}", cfg_port)
                        || (origin.starts_with("http://")
                            && origin.ends_with(&format!(".localhost:{}", cfg_port)));
                    if allowed {
                        let headers = resp.headers_mut();
                        headers.insert(
                            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
                            origin.parse().unwrap_or_else(|_| HeaderValue::from_static("*")),
                        );
                        headers.insert(
                            axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
                            HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
                        );
                        headers.insert(
                            axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
                            HeaderValue::from_static("*"),
                        );
                    }

                    resp
                } else {
                    // Bare localhost → normal route matching
                    next.run(req).await
                }
            }
        },
    ));

    // Serve static assets (CSS, JS, narration audio, etc.)
    // Single authoritative location: $ZP_ASSETS_DIR or ~/.zeropoint/assets/
    // In dev: `./zp-dev.sh html` copies source files here for hot reload.
    // In release: compiled-in HTML serves via resolve_html_asset(); static
    //   files (narration MP3s, images) live here permanently.
    let assets_dir = std::env::var("ZP_ASSETS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| config.home_dir.join("assets"));
    if assets_dir.exists() {
        info!("Assets:     http://localhost:{}/assets/  ({})", config.port, assets_dir.display());
    } else {
        info!("Assets:     {} (not yet created)", assets_dir.display());
    }
    let assets_service = ServeDir::new(&assets_dir);
    router = router.nest_service("/assets", assets_service);

    // Serve Bridge UI static files if configured.
    if let Some(ref bridge_dir) = config.bridge_dir {
        if bridge_dir.exists() {
            info!("Bridge UI: http://localhost:{}/bridge", config.port);
            let index_path = bridge_dir.join("index.html");
            let index_html: &'static str = Box::leak(
                std::fs::read_to_string(&index_path)
                    .unwrap_or_else(|_| "<h1>Bridge index.html not found</h1>".to_string())
                    .into_boxed_str(),
            );
            router = router
                .route("/bridge", get(move || async move { Html(index_html) }));
        } else {
            tracing::warn!(
                "ZP_BRIDGE_DIR={:?} does not exist, Bridge UI disabled",
                bridge_dir
            );
        }
    }

    info!("Tool proxy: http://{{tool}}.localhost:{}/", config.port);

    router
}

// ============================================================================
// Run Server (public entry point)
// ============================================================================

pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
    let addr = format!("{}:{}", config.bind_addr, config.port);

    // Security warning for non-localhost binding
    if config.bind_addr != "127.0.0.1" && config.bind_addr != "localhost" {
        tracing::warn!(
            "Binding to {} — this exposes the server to the network. \
             TLS is recommended for non-localhost deployments.",
            addr
        );
    }

    let open_dashboard = config.open_dashboard;
    let dashboard_port = config.port;
    let state = AppState::init(&config).await;
    let app = build_app(state, &config);

    info!("ZeroPoint server on {}", addr);
    info!("Dashboard: http://localhost:{}", config.port);
    info!("Onboard:   http://localhost:{}/onboard", config.port);
    info!("Trust is infrastructure.");

    // Open browser if requested
    if open_dashboard {
        let url = format!("http://localhost:{}", dashboard_port);
        open_browser(&url);
    }

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn().ok();
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn().ok();
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()
            .ok();
    }
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
    /// Whether the identity is sourced from the key hierarchy (true) or legacy file (false).
    from_hierarchy: bool,
    /// The key role: "operator" if from hierarchy, "bootstrap" if legacy.
    key_role: String,
}

async fn identity_handler(State(state): State<AppState>) -> Json<IdentityResponse> {
    let key_role = if state.0.identity.from_hierarchy {
        "operator"
    } else {
        "bootstrap"
    };
    Json(IdentityResponse {
        public_key: state.0.identity.public_key_hex.clone(),
        destination_hash: state.0.identity.destination_hash.clone(),
        trust_tier: "Tier1".to_string(),
        algorithm: "Ed25519".to_string(),
        from_hierarchy: state.0.identity.from_hierarchy,
        key_role: key_role.to_string(),
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
    chain_links_valid: usize,
    error: Option<String>,
    issues: Vec<String>,
    has_tampered_entries: bool,
}

async fn audit_verify_handler(State(state): State<AppState>) -> Json<ChainVerifyResponse> {
    let store = state.0.audit_store.lock().unwrap();

    // Check for unrestore tampered entries
    let has_tampered = store
        .export_chain(1000)
        .map(|entries| {
            entries
                .iter()
                .any(|e| e.entry_hash.starts_with("TAMPERED_"))
        })
        .unwrap_or(false);

    match store.verify_with_report() {
        Ok(report) => {
            let mut issues = report.issues.clone();
            if has_tampered {
                issues.insert(
                    0,
                    "Unrestored tampered entries detected — click Restore Chain".to_string(),
                );
            }
            Json(ChainVerifyResponse {
                valid: report.chain_valid && !has_tampered,
                entries_examined: report.entries_examined,
                chain_links_valid: report.chain_links_valid,
                error: None,
                issues,
                has_tampered_entries: has_tampered,
            })
        }
        Err(e) => Json(ChainVerifyResponse {
            valid: false,
            entries_examined: 0,
            chain_links_valid: 0,
            error: Some(format!("{}", e)),
            issues: vec![format!("{}", e)],
            has_tampered_entries: has_tampered,
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
            "Need at least 2 audit entries to simulate tampering. Run some Guard evaluations first."
                .to_string(),
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
// Audit Clear (reset chain)
// ============================================================================

#[derive(Serialize)]
struct AuditClearResponse {
    cleared: bool,
    entries_removed: usize,
    message: String,
}

async fn audit_clear_handler(
    State(state): State<AppState>,
) -> Result<Json<AuditClearResponse>, (StatusCode, String)> {
    let store = state.0.audit_store.lock().unwrap();

    let count = store
        .clear()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("{}", e)))?;

    drop(store);

    // Reset the gate's chain head to genesis so new entries chain correctly
    state.0.gate.reset_audit_chain_head();

    Ok(Json(AuditClearResponse {
        cleared: true,
        entries_removed: count,
        message: format!(
            "Cleared {} audit entries. Chain reset to genesis. Restart server or run an evaluation to begin a fresh chain.",
            count
        ),
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

// ============================================================================
// WebSocket Handler — Bridge UI real-time connection
// ============================================================================

/// Upgrade HTTP → WebSocket at /wss
async fn ws_upgrade_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| ws_connection(socket, state))
}

/// Handle a single WebSocket connection from the Bridge UI.
///
/// The client sends JSON frames like:
///   { "type": "message", "role": "architect", "content": "Hello" }
///   { "type": "health" }
///   { "type": "HCSApprovalDecision", "payload": { ... } }
///
/// We route "message" into the deterministic pipeline and stream the
/// response back in the format the Bridge expects.
async fn ws_connection(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    // Track conversation across the session
    let conversation_id = ConversationId::new();

    info!(
        "WebSocket client connected (conversation: {:?})",
        conversation_id
    );

    while let Some(msg) = receiver.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!("WebSocket recv error: {}", e);
                break;
            }
        };

        let text = match msg {
            WsMessage::Text(t) => t,
            WsMessage::Close(_) => break,
            WsMessage::Ping(d) => {
                let _ = sender.send(WsMessage::Pong(d)).await;
                continue;
            }
            _ => continue,
        };

        // Parse the JSON frame
        let frame: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                let err = serde_json::json!({
                    "type": "Error",
                    "message": format!("Invalid JSON: {}", e)
                });
                let _ = sender.send(WsMessage::Text(err.to_string())).await;
                continue;
            }
        };

        let msg_type = frame.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match msg_type {
            // ---- Health / keepalive ----
            "health" => {
                let resp = serde_json::json!({
                    "type": "health",
                    "status": "ok",
                    "pipeline_enabled": state.0.pipeline.is_some(),
                    "version": env!("CARGO_PKG_VERSION"),
                });
                let _ = sender.send(WsMessage::Text(resp.to_string())).await;
            }

            // ---- Chat message ----
            "message" => {
                let content = frame
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let role = frame
                    .get("role")
                    .and_then(|v| v.as_str())
                    .unwrap_or("architect")
                    .to_string();

                if content.is_empty() {
                    let err = serde_json::json!({
                        "type": "Error",
                        "message": "Empty message content"
                    });
                    let _ = sender.send(WsMessage::Text(err.to_string())).await;
                    continue;
                }

                // Check pipeline availability
                let pipeline = match state.0.pipeline.as_ref() {
                    Some(p) => p,
                    None => {
                        // No LLM pipeline — echo back a helpful message
                        let resp = serde_json::json!({
                            "type": "message",
                            "success": true,
                            "response": format!(
                                "Pipeline not enabled. Set ZP_LLM_ENABLED=true to enable LLM responses. (Received: {})",
                                content
                            ),
                            "officer": role,
                            "message_id": uuid::Uuid::now_v7().to_string(),
                            "conversation_id": conversation_id.0.to_string(),
                        });
                        let _ = sender.send(WsMessage::Text(resp.to_string())).await;
                        continue;
                    }
                };

                // Build the deterministic core Request
                let request = Request::new(conversation_id.clone(), content, Channel::WebDashboard);

                // Send stream-start so the UI shows the officer is working
                let stream_start = serde_json::json!({
                    "type": "OfficerStreamStart",
                    "officer": role,
                });
                let _ = sender.send(WsMessage::Text(stream_start.to_string())).await;

                // Route through the pipeline
                match pipeline.handle(request).await {
                    Ok(response) => {
                        // Send the complete response
                        let stream_end = serde_json::json!({
                            "type": "OfficerStreamEnd",
                            "officer": role,
                            "full_text": response.content,
                        });
                        let _ = sender.send(WsMessage::Text(stream_end.to_string())).await;

                        // Also send the simple response format for compatibility
                        let simple = serde_json::json!({
                            "type": "message",
                            "success": true,
                            "response": response.content,
                            "officer": role,
                            "message_id": response.id.0.to_string(),
                            "conversation_id": response.conversation_id.0.to_string(),
                        });
                        let _ = sender.send(WsMessage::Text(simple.to_string())).await;
                    }
                    Err(e) => {
                        let err = serde_json::json!({
                            "type": "OfficerStreamEnd",
                            "officer": role,
                            "full_text": format!("Error: {}", e),
                        });
                        let _ = sender.send(WsMessage::Text(err.to_string())).await;
                    }
                }
            }

            // ---- HCS Approval Decision (from Trust section) ----
            "HCSApprovalDecision" => {
                // Acknowledge — actual HCS processing is future work
                let ack = serde_json::json!({
                    "type": "HCSApprovalStatus",
                    "pendingCount": 0,
                });
                let _ = sender.send(WsMessage::Text(ack.to_string())).await;
            }

            // ---- Voice transcription ----
            "VoiceTranscribe" => {
                // Placeholder — voice processing is future work
                let resp = serde_json::json!({
                    "type": "TranscriptionResponse",
                    "success": false,
                    "text": "",
                    "error": "Voice transcription not yet implemented on server"
                });
                let _ = sender.send(WsMessage::Text(resp.to_string())).await;
            }

            // ---- Unknown types — log and ignore ----
            other => {
                tracing::debug!("Unhandled WebSocket message type: {}", other);
            }
        }
    }

    info!(
        "WebSocket client disconnected (conversation: {:?})",
        conversation_id
    );
}

// ============================================================================
// Stats Handler
// ============================================================================

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_audit_entries: usize,
    pub chain_valid: bool,
    pub pipeline_enabled: bool,
    pub policy_rules_loaded: usize,
    pub grants_active: usize,
}

async fn stats_handler(State(state): State<AppState>) -> Json<StatsResponse> {
    let store = state.0.audit_store.lock().unwrap();
    let entries = store.export_chain(10000).unwrap_or_default();
    let chain_valid = store
        .verify_with_report()
        .map(|r| r.chain_valid)
        .unwrap_or(false);
    drop(store);

    let grants_count = state.0.grants.lock().unwrap().len();

    Json(StatsResponse {
        total_audit_entries: entries.len(),
        chain_valid,
        pipeline_enabled: state.0.pipeline.is_some(),
        policy_rules_loaded: 6, // constitutional + operational rules
        grants_active: grants_count,
    })
}

// ============================================================================
// Security Posture Handler
// ============================================================================

async fn security_posture_handler(
    State(state): State<AppState>,
) -> Json<security::SecurityPosture> {
    Json(security::assess(&state))
}

async fn topology_handler() -> Json<security::NetworkTopology> {
    Json(security::topology())
}

// ============================================================================
// Tools / Cockpit Handler
// ============================================================================

/// A configured tool for the agentic cockpit.
#[derive(Serialize)]
struct CockpitTool {
    name: String,
    path: String,
    status: String,          // "governed", "configured", "unconfigured"
    governance: String,      // "genesis-bound", "unanchored", "none"
    providers: Vec<String>,  // provider names found in .env.example
    launch: ToolLaunch,      // how to open this tool
    ready: bool,             // preflight passed?
    preflight_issues: Vec<String>, // failures from last preflight
    verified: bool,          // Tier 2: all required capabilities verified?
    capabilities: Vec<tool_chain::CapabilityChainState>, // per-capability results
}

/// How a cockpit tile launches its tool.
#[derive(Serialize)]
struct ToolLaunch {
    kind: String,        // "web", "docker", "cli"
    url: Option<String>, // http://localhost:{port} if web
    port: Option<u16>,   // detected port
    cmd: Option<String>, // launch command if cli/docker
}

/// Port variable names to scan in .env, ordered by priority.
/// Used by detect_tool_port() for the tools listing display.
/// The actual launch port is managed by PortAllocator (tool_ports.rs).
const PORT_VAR_NAMES: &[&str] = &[
    "PORT", "GATEWAY_PORT", "APP_PORT", "SERVER_PORT", "API_PORT",
    "WEBUI_PORT", "LISTEN_PORT", "HTTP_PORT",
];

/// Try to detect a web port from a tool's .env or .env.example.
///
/// Scans for all recognised port variables then returns the one with the
/// highest priority (earliest in `PORT_VAR_NAMES`).  This ensures tools
/// that expose both a UI gateway and a webhook server resolve to the
/// browsable port rather than whichever var appears first in the file.
fn detect_tool_port(tool_path: &std::path::Path) -> Option<u16> {
    let mut best: Option<(usize, u16)> = None; // (priority index, port)

    for filename in &[".env", ".env.example"] {
        let file = tool_path.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&file) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains('=') {
                    continue;
                }
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let val = val.trim().trim_matches('"').trim_matches('\'')
                        .split('#').next().unwrap_or("").trim();
                    if let Some(priority) = PORT_VAR_NAMES.iter().position(|&p| p == key) {
                        if let Ok(port) = val.parse::<u16>() {
                            if best.map_or(true, |(bp, _)| priority < bp) {
                                best = Some((priority, port));
                            }
                        }
                    }
                }
            }
            // If .env had a match, don't fall through to .env.example
            if best.is_some() {
                return best.map(|(_, p)| p);
            }
        }
    }
    best.map(|(_, p)| p)
}

/// Determine the launch method for a tool.
///
/// Priority logic:
///   1. Cargo.toml present → native Rust tool (run via `cargo run --release`)
///      - If docker-compose.yml also exists, it provides deps (Postgres, Redis, etc.)
///        and gets started first automatically.
///   2. Web tool with detectable port:
///      a. pnpm-lock.yaml → local-first via `pnpm start` (preferred)
///      b. package-lock.json → local-first via `npm start`
///      c. docker-compose.yml → containerized
///   3. docker-compose.yml only → containerized tool
///   4. start.sh / package.json / Makefile → scripted tool (pnpm > npm)
///   5. None of the above → CLI fallback
fn detect_launch(tool_path: &std::path::Path) -> ToolLaunch {
    let has_docker_compose = tool_path.join("docker-compose.yml").exists()
        || tool_path.join("docker-compose.yaml").exists()
        || tool_path.join("compose.yml").exists()
        || tool_path.join("compose.yaml").exists();
    let has_cargo = tool_path.join("Cargo.toml").exists();
    let port = detect_tool_port(tool_path);

    if has_cargo {
        // Native Rust tool — compose provides deps, cargo runs the app
        let deps_cmd = if has_docker_compose {
            format!("docker compose down --remove-orphans 2>/dev/null; \
                docker compose up -d && \
                for i in $(seq 1 15); do \
                    docker compose exec -T postgres pg_isready -q 2>/dev/null && break; \
                    sleep 1; \
                done && ")
        } else {
            String::new()
        };
        let cmd = format!("cd '{}' && {}cargo run --release", tool_path.display(), deps_cmd);
        ToolLaunch {
            kind: "native".to_string(),
            url: port.map(|p| format!("http://localhost:{}", p)),
            port,
            cmd: Some(cmd),
        }
    } else if let Some(p) = port {
        // Web tool with detectable port (non-Rust)
        // Prefer local package manager execution when available (pnpm > npm > docker)
        let has_package_json = tool_path.join("package.json").exists();
        let has_pnpm_lock = tool_path.join("pnpm-lock.yaml").exists();
        let has_npm_lock = tool_path.join("package-lock.json").exists();

        let cmd = if has_package_json && (has_pnpm_lock || has_npm_lock) {
            // Local-first: run via package manager (pnpm preferred)
            let pkg_mgr = if has_pnpm_lock { "pnpm" } else { "npm" };
            // Build-before-start: Next.js needs .next/BUILD_ID (dev mode creates .next/ without it)
            let has_next_build = tool_path.join(".next").join("BUILD_ID").exists();
            let has_dist = tool_path.join("dist").exists();
            let has_build_dir = tool_path.join("build").exists();
            let needs_build = !has_next_build && !has_dist && !has_build_dir;
            let build_prefix = if needs_build {
                format!("{} run build && ", pkg_mgr)
            } else {
                String::new()
            };

            // Next.js standalone: if .next/standalone/server.js exists
            // (pre-built via CI or manual webpack build), use node directly
            // since `next start` doesn't work with standalone output.
            // In practice, Turbopack (Next 16 default) ignores standalone
            // config, so most local tools just use `pnpm start` normally.
            let standalone_server = tool_path.join(".next/standalone/server.js");
            if standalone_server.exists() {
                Some(format!(
                    "cd '{}' && {}HOSTNAME=0.0.0.0 node .next/standalone/server.js",
                    tool_path.display(), build_prefix
                ))
            } else {
                Some(format!("cd '{}' && {}{} start", tool_path.display(), build_prefix, pkg_mgr))
            }
        } else if has_docker_compose {
            Some(format!("cd '{}' && docker compose down --remove-orphans 2>/dev/null; docker compose up -d", tool_path.display()))
        } else {
            None
        };
        let kind = if has_package_json && has_pnpm_lock {
            "pnpm"
        } else if has_package_json && has_npm_lock {
            "npm"
        } else if has_docker_compose {
            "docker"
        } else {
            "web"
        };
        ToolLaunch {
            kind: kind.to_string(),
            url: Some(format!("http://localhost:{}", p)),
            port: Some(p),
            cmd,
        }
    } else if has_docker_compose {
        // Fully containerized tool
        ToolLaunch {
            kind: "docker".to_string(),
            url: None,
            port: None,
            cmd: Some(format!("cd '{}' && docker compose down --remove-orphans 2>/dev/null; docker compose up -d", tool_path.display())),
        }
    } else {
        // Scripted or CLI — check for start.sh, npm, make
        let scripts = ["start.sh", "run.sh", "launch.sh"];
        let script = scripts.iter().find(|s| tool_path.join(s).exists());
        let cmd = if let Some(s) = script {
            format!("cd '{}' && bash '{}'", tool_path.display(), s)
        } else if tool_path.join("package.json").exists() {
            // Detect package manager: pnpm (pnpm-lock.yaml) > npm
            let pkg_mgr = if tool_path.join("pnpm-lock.yaml").exists() {
                "pnpm"
            } else {
                "npm"
            };
            let has_next_build = tool_path.join(".next").join("BUILD_ID").exists();
            let has_dist = tool_path.join("dist").exists();
            let has_build_dir = tool_path.join("build").exists();
            let needs_build = !has_next_build && !has_dist && !has_build_dir;
            let build_prefix = if needs_build {
                format!("{} run build && ", pkg_mgr)
            } else {
                String::new()
            };
            format!("cd '{}' && {}{} start", tool_path.display(), build_prefix, pkg_mgr)
        } else if tool_path.join("Makefile").exists() {
            format!("cd '{}' && make start", tool_path.display())
        } else {
            format!("cd '{}'", tool_path.display())
        };
        ToolLaunch {
            kind: "cli".to_string(),
            url: None,
            port: None,
            cmd: Some(cmd),
        }
    }
}

/// Scan ~/projects for tools and return their governance status.
/// Used by the dashboard cockpit to render app launcher tiles.
///
/// Readiness is derived from the **audit chain** (canonical source),
/// with a fallback to the preflight JSON cache for backward compat.
async fn tools_handler(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    if !scan_path.exists() {
        return Json(serde_json::json!({
            "tools": [],
            "scan_path": scan_path.display().to_string(),
        }));
    }

    let results = zp_engine::scan::scan_tools(&scan_path);
    let home = dirs::home_dir().unwrap_or_default().join(".zeropoint");
    let has_genesis = home.join("genesis.json").exists();

    // ── Chain state: canonical source of truth ──────────────
    let chain_state = tool_chain::query_tool_readiness(&state.0.audit_store);

    // ── Fallback: JSON cache (for tools preflighted before chain was wired) ──
    let preflight_cache = onboard::preflight::PreflightResults::load();

    // ── Port conflicts: compose infrastructure ports vs live system ──
    // Build a map of tool → conflict descriptions from preflight results.
    let port_conflict_map: std::collections::HashMap<String, Vec<String>> = preflight_cache
        .as_ref()
        .map(|pf| {
            let mut map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for conflict in &pf.port_conflicts {
                // conflict.tools = ["ironclaw:postgres", "pgvector (PID 1234)"]
                // The first entry is the tool:service, the second is the occupant
                if conflict.tools.len() >= 2 {
                    let tool_service = &conflict.tools[0];
                    let occupant = &conflict.tools[1];
                    if let Some(tool_name) = tool_service.split(':').next() {
                        let service = tool_service.split(':').nth(1).unwrap_or("service");
                        map.entry(tool_name.to_string()).or_default().push(
                            format!("Port {} ({}) blocked by {}", conflict.port, service, occupant)
                        );
                    }
                }
            }
            map
        })
        .unwrap_or_default();

    let tools: Vec<CockpitTool> = results.tools.into_iter().map(|tool| {
        // Check if .env exists and was written by zp configure
        let env_path = tool.path.join(".env");
        let (status, governance) = if env_path.exists() {
            let is_zp = std::fs::read_to_string(&env_path)
                .map(|c| c.contains("Generated by: zp configure"))
                .unwrap_or(false);
            if is_zp && has_genesis {
                ("governed".to_string(), "genesis-bound".to_string())
            } else if is_zp {
                ("configured".to_string(), "unanchored".to_string())
            } else {
                ("configured".to_string(), "none".to_string())
            }
        } else {
            ("unconfigured".to_string(), "none".to_string())
        };

        let launch = detect_launch(&tool.path);

        // Derive readiness: chain first, then JSON fallback
        let (ready, preflight_issues) = if let Some(cs) = chain_state.get(&tool.name) {
            // Chain has receipts for this tool — use chain state
            (cs.ready, cs.preflight_issues.clone())
        } else if let Some(ref pf) = preflight_cache {
            // Fallback to JSON cache
            if let Some(tp) = pf.tools.iter().find(|t| t.name == tool.name) {
                let issues: Vec<String> = tp.checks.iter()
                    .filter(|c| c.status == "fail")
                    .map(|c| c.detail.clone())
                    .collect();
                (tp.ready, issues)
            } else {
                (false, vec!["Not preflighted yet".to_string()])
            }
        } else {
            (false, vec!["Preflight not run".to_string()])
        };

        // Merge any compose port conflicts into preflight issues
        let mut all_issues = preflight_issues;
        if let Some(conflicts) = port_conflict_map.get(&tool.name) {
            all_issues.extend(conflicts.iter().cloned());
        }
        let effective_ready = ready && port_conflict_map.get(&tool.name).is_none();

        // Derive verification state from chain
        let (verified, capabilities) = if let Some(cs) = chain_state.get(&tool.name) {
            (cs.verified, cs.capabilities.clone())
        } else {
            (false, vec![])
        };

        CockpitTool {
            name: tool.name,
            path: tool.path.display().to_string(),
            status,
            governance,
            providers: tool.provider_vars,
            launch,
            ready: effective_ready,
            preflight_issues: all_issues,
            verified,
            capabilities,
        }
    }).collect();

    let chain_receipts = !chain_state.is_empty();
    Json(serde_json::json!({
        "tools": tools,
        "scan_path": scan_path.display().to_string(),
        "has_genesis": has_genesis,
        "chain_receipts": chain_receipts,
    }))
}

// ── Tool Lifecycle ──────────────────────────────────────────────────────────

/// PID file directory: ~/.zeropoint/pids/
fn pid_dir() -> std::path::PathBuf {
    let dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".zeropoint")
        .join("pids");
    std::fs::create_dir_all(&dir).ok();
    dir
}

/// Write a PID file for a launched tool.
fn write_pid_file(name: &str, pid: u32) {
    let path = pid_dir().join(format!("{}.pid", name));
    std::fs::write(&path, pid.to_string()).ok();
}

/// Read a stored PID for a tool, if it exists and the process is still alive.
fn read_live_pid(name: &str) -> Option<u32> {
    let path = pid_dir().join(format!("{}.pid", name));
    let contents = std::fs::read_to_string(&path).ok()?;
    let pid: u32 = contents.trim().parse().ok()?;
    // Check if process is alive (kill -0)
    let alive = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if alive {
        Some(pid)
    } else {
        // Stale PID file — clean it up
        std::fs::remove_file(&path).ok();
        None
    }
}

/// Kill a tool's process tree gracefully (SIGTERM), then SIGKILL if needed.
///
/// IMPORTANT: We only kill the specific PID and its children — never the
/// process group (negative PID).  The spawned `sh -c` inherits the ZP
/// server's process group, so `kill -TERM -<pid>` would kill the server.
fn kill_tool_process(name: &str, pid: u32) -> bool {
    info!("Stopping {} (PID {})", name, pid);

    // For docker-compose tools, try `docker compose down` first
    let tool_path = dirs::home_dir()
        .unwrap_or_default()
        .join("projects")
        .join(name);
    let has_compose = tool_path.join("docker-compose.yml").exists()
        || tool_path.join("docker-compose.yaml").exists()
        || tool_path.join("compose.yml").exists()
        || tool_path.join("compose.yaml").exists();

    if has_compose {
        info!("Compose tool detected — running docker compose down for {}", name);
        let _ = std::process::Command::new("docker")
            .args(["compose", "down"])
            .current_dir(&tool_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // Find child processes first (they won't die when parent gets SIGTERM)
    let children = find_child_pids(pid);

    // SIGTERM the main process
    let term_result = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // SIGTERM each child
    for child_pid in &children {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &child_pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // Brief wait for graceful shutdown
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check if still alive
    let still_alive = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if still_alive {
        warn!("{} (PID {}) didn't stop gracefully, sending SIGKILL", name, pid);
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    // SIGKILL any surviving children
    for child_pid in &children {
        let _ = std::process::Command::new("kill")
            .args(["-9", &child_pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    // Clean up PID file
    let pid_path = pid_dir().join(format!("{}.pid", name));
    std::fs::remove_file(&pid_path).ok();

    term_result.map(|s| s.success()).unwrap_or(false) || !still_alive
}

/// Find child PIDs of a given parent using `pgrep -P <pid>`.
fn find_child_pids(parent: u32) -> Vec<u32> {
    let output = std::process::Command::new("pgrep")
        .args(["-P", &parent.to_string()])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect()
        }
        _ => vec![],
    }
}

/// Also kill anything listening on the port (safety net for orphaned processes).
fn kill_port_occupant(port: u16) {
    // lsof -ti :<port> returns PIDs of anything on that port
    if let Ok(output) = std::process::Command::new("lsof")
        .args(["-ti", &format!(":{}", port)])
        .output()
    {
        if output.status.success() {
            let pids = String::from_utf8_lossy(&output.stdout);
            for pid_str in pids.trim().lines() {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    info!("Killing orphaned process {} on port {}", pid, port);
                    let _ = std::process::Command::new("kill")
                        .args(["-TERM", &pid.to_string()])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct LaunchRequest {
    name: String,
}

/// Start a tool process.  Returns immediately with the expected URL and
/// the kind of process that was started so the frontend can poll.
///
/// Output is captured to `~/.zeropoint/logs/<tool>.log` so the frontend
/// can fetch diagnostics via `/api/v1/tools/log?name=<tool>` on failure.
async fn tools_launch_handler(
    State(state): State<AppState>,
    Json(req): Json<LaunchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    let tool_path = scan_path.join(&req.name);
    if !tool_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Tool '{}' not found in ~/projects/", req.name),
            })),
        );
    }

    // ── Preflight gate (server-side enforcement) ───────────────────
    // The audit chain is the canonical source of tool readiness.
    // If preflight hasn't passed, refuse to launch.  This prevents
    // direct API calls from bypassing the dashboard's client-side gate.
    let chain_state = tool_chain::query_tool_readiness(&state.0.audit_store);
    if let Some(cs) = chain_state.get(&req.name) {
        if !cs.ready {
            let issues = if cs.preflight_issues.is_empty() {
                vec!["Preflight not passed".to_string()]
            } else {
                cs.preflight_issues.clone()
            };
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("{} is not ready — preflight required", req.name),
                    "preflight_issues": issues,
                    "configured": cs.configured,
                    "preflight_passed": cs.preflight_passed,
                })),
            );
        }
    }
    // If tool has no chain state at all, allow launch (first-time tools
    // that were never preflighted can still be started manually).
    // The dashboard will prompt for preflight, but the API stays permissive
    // for tools that don't need it (simple scripts, etc.).

    let launch = detect_launch(&tool_path);

    // ── Port allocation ─────────────────────────────────────────────
    // Assign a ZP-managed port so tools don't collide on shared defaults
    // (3000, 8080, etc.).  The .env.zp sidecar overrides the tool's port
    // variable without touching .env.
    let port_var = tool_ports::detect_port_var(&tool_path);
    let assignment = match state.0.port_allocator.get_or_assign(&req.name, &port_var) {
        Ok(a) => a,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Port allocation failed: {}", e),
                })),
            );
        }
    };

    if let Err(e) = tool_ports::write_env_zp(&tool_path, &req.name, &assignment) {
        warn!("Failed to write .env.zp for {}: {}", req.name, e);
        // Non-fatal — tool will use its default port
    }

    // Use the launch command from detect_launch (single source of truth)
    let start_cmd = match launch.cmd.clone() {
        Some(cmd) => cmd,
        None => {
            let has_env = tool_path.join(".env").exists();
            let has_example = tool_path.join(".env.example").exists();
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "error": format!("No launch method found for '{}'", req.name),
                    "hint": "ZeroPoint looks for: docker-compose.yml, start.sh, run.sh, Makefile, or package.json",
                    "has_env": has_env,
                    "has_env_example": has_example,
                    "path": tool_path.display().to_string(),
                })),
            );
        }
    };

    // Log file for diagnostics: ~/.zeropoint/logs/<tool>.log
    let log_dir = dirs::home_dir()
        .unwrap_or_default()
        .join(".zeropoint")
        .join("logs");
    std::fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join(format!("{}.log", req.name));

    // Prepend .env.zp sourcing so the tool picks up ZP-assigned port
    let full_cmd = format!(
        "{}{}", tool_ports::env_zp_preamble(), start_cmd
    );

    // Wrap the command so stdout+stderr go to the log file
    let logged_cmd = format!(
        "{{ {} ; }} > '{}' 2>&1",
        full_cmd,
        log_path.display()
    );

    // ── Stop-before-start ──────────────────────────────────────────
    // If the tool is already running, kill it cleanly before relaunching.
    let mut restarted = false;
    if let Some(old_pid) = read_live_pid(&req.name) {
        info!(
            "Cockpit relaunch: {} already running (PID {}), stopping first",
            req.name, old_pid
        );
        kill_tool_process(&req.name, old_pid);
        // Emit stopped receipt so the chain has no gap
        let stopped_event = tool_chain::ToolEvent::stopped(&req.name);
        let detail = format!("pid={} reason=relaunch", old_pid);
        tool_chain::emit_tool_receipt(
            &state.0.audit_store,
            &stopped_event,
            Some(&detail),
        );
        restarted = true;
        // Brief pause to let the port release (async-safe)
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    // Safety net: also clear anything squatting on the port
    kill_port_occupant(assignment.port);
    // Brief pause after port cleanup (async-safe)
    if !restarted {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    info!(
        "Cockpit launch: {} → {} (port :{})",
        req.name, full_cmd, assignment.port
    );
    // Create the child in its own process group (PGID = child PID).
    // This isolates the tool from the ZP server's process group so that
    // killing the tool never accidentally kills the server.
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    let spawn_result = std::process::Command::new("sh")
        .arg("-c")
        .arg(&logged_cmd)
        .current_dir(&tool_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0) // new process group, isolated from ZP server
        .spawn();

    match spawn_result {
        Ok(child) => {
            // Track the PID so we can stop it later
            write_pid_file(&req.name, child.id());
            // Emit port assignment receipt
            let port_event = tool_state::events::port_assigned(&req.name, assignment.port);
            let port_detail = format!("var={}", assignment.port_var);
            tool_chain::emit_tool_receipt(
                &state.0.audit_store,
                &port_event,
                Some(&port_detail),
            );

            // Emit launched receipt into the chain
            let event = tool_chain::ToolEvent::launched(&req.name);
            let launch_detail = format!("cmd={} port={}", full_cmd, assignment.port);
            tool_chain::emit_tool_receipt(
                &state.0.audit_store,
                &event,
                Some(&launch_detail),
            );

            // ── Capability Verification (Tier 1 + Tier 2) ──────────
            // If the tool has a [verification] section in its manifest,
            // spawn a background task that probes after health-up to confirm
            // credentials are not just delivered but actually working.
            {
                let manifest_path = tool_path.join(".zp-configure.toml");
                if manifest_path.exists() {
                    if let Ok(manifest) = zp_engine::capability::load_manifest(&manifest_path) {
                        if let Some(verification) = manifest.verification.clone() {
                            let vname = req.name.clone();
                            let vport = assignment.port;
                            let vmanifest = manifest.clone();
                            let vstate = state.clone(); // Clone the Arc<AppStateInner>
                            tokio::spawn(async move {
                                tracing::info!(
                                    "verify[{}]: scheduled — will probe after {}s delay",
                                    vname, verification.delay_secs
                                );
                                let result = onboard::verify::verify_tool_capabilities(
                                    &vname,
                                    vport,
                                    &vmanifest,
                                    &verification,
                                    &vstate.0.audit_store,
                                ).await;
                                let verified = !result.capabilities.is_empty()
                                    && result.capabilities.iter().all(|c| c.status != "failed");
                                tracing::info!(
                                    "verify[{}]: complete — providers={}, capabilities={}/{} verified={}",
                                    vname,
                                    if result.providers_resolved { "resolved" } else { "skipped" },
                                    result.capabilities.iter().filter(|c| c.status == "verified").count(),
                                    result.capabilities.len(),
                                    verified,
                                );
                            });
                        }
                    }
                }
            }

            // The proxy URL is the canonical way to reach the tool.
            // Subdomain-based: http://{name}.localhost:{port}/
            let proxy_url = format!("http://{}.localhost:{}/", req.name, state.0.config_port);
            let raw_url = format!("http://127.0.0.1:{}", assignment.port);

            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "status": if restarted { "restarting" } else { "starting" },
                    "name": req.name,
                    "cmd": full_cmd,
                    "url": proxy_url,
                    "raw_url": raw_url,
                    "port": assignment.port,
                    "kind": launch.kind,
                    "pid": child.id(),
                })),
            )
        }
        Err(e) => {
            let hint = if e.kind() == std::io::ErrorKind::NotFound {
                "Shell not found — is 'sh' available?"
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                "Permission denied — check the tool's file permissions."
            } else {
                "Try running the command manually in your terminal."
            };
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to start: {}", e),
                    "cmd": start_cmd,
                    "hint": hint,
                })),
            )
        }
    }
}

/// Stop a running tool process.
async fn tools_stop_handler(
    State(state): State<AppState>,
    Json(req): Json<LaunchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    match read_live_pid(&req.name) {
        Some(pid) => {
            let killed = kill_tool_process(&req.name, pid);

            // Also clear the port if we know it
            if let Some(assignment) = state.0.port_allocator.get_assigned(&req.name) {
                kill_port_occupant(assignment.port);
            }

            // Emit stopped receipt into the audit chain
            let event = tool_chain::ToolEvent::stopped(&req.name);
            let detail = format!("pid={}", pid);
            tool_chain::emit_tool_receipt(
                &state.0.audit_store,
                &event,
                Some(&detail),
            );

            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "stopped",
                    "name": req.name,
                    "pid": pid,
                    "killed": killed,
                })),
            )
        }
        None => {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "status": "not_running",
                    "name": req.name,
                    "message": format!("No running process found for '{}'", req.name),
                })),
            )
        }
    }
}

/// Return the last 50 lines of a tool's launch log for diagnostics.
async fn tools_log_handler(
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let name = match params.get("name") {
        Some(n) => n,
        None => return Json(serde_json::json!({ "error": "Missing 'name' parameter" })),
    };

    let log_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".zeropoint")
        .join("logs")
        .join(format!("{}.log", name));

    if !log_path.exists() {
        return Json(serde_json::json!({
            "name": name,
            "log": null,
            "message": "No launch log found. Tool may not have been started from the cockpit.",
        }));
    }

    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    let tail_start = if lines.len() > 50 { lines.len() - 50 } else { 0 };
    let tail: String = lines[tail_start..].join("\n");

    Json(serde_json::json!({
        "name": name,
        "log": tail,
        "lines": lines.len(),
        "path": log_path.display().to_string(),
    }))
}

// ── Tool Preflight ──────────────────────────────────────────────────────────

/// Run preflight checks on all configured tools (POST).
/// This pulls docker images, installs deps, fixes permissions, etc.
async fn tools_preflight_handler(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    let (results, _events) = onboard::preflight::run_preflight(
        &scan_path,
        Some(&state.0.audit_store),
    ).await;
    Json(serde_json::to_value(&results).unwrap_or_default())
}

/// Get cached preflight results without re-running (GET).
async fn tools_preflight_status_handler() -> Json<serde_json::Value> {
    match onboard::preflight::PreflightResults::load() {
        Some(results) => Json(serde_json::to_value(&results).unwrap_or_default()),
        None => Json(serde_json::json!({
            "error": "No preflight results. POST /api/v1/tools/preflight to run.",
        })),
    }
}

/// Run preflight scoped to a single tool (POST).
///
/// Unlike the full preflight endpoint, this targets one tool by name,
/// always forces a fresh run, and returns that tool's result directly.
async fn tools_single_preflight_handler(
    State(state): State<AppState>,
    axum::extract::Path(tool_name): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    // Verify the tool directory exists before running preflight.
    let tool_path = scan_path.join(&tool_name);
    if !tool_path.is_dir() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Tool '{}' not found in {}", tool_name, scan_path.display()),
            })),
        );
    }

    let (results, _events) = onboard::preflight::run_preflight_single(
        &scan_path,
        &tool_name,
        Some(&state.0.audit_store),
    ).await;

    // Extract the single tool's result from the full results vec.
    let tool_result = results.tools.iter()
        .find(|t| t.name.eq_ignore_ascii_case(&tool_name));

    match tool_result {
        Some(result) => {
            let status = if result.ready { StatusCode::OK } else { StatusCode::CONFLICT };
            (status, Json(serde_json::json!({
                "tool": result.name,
                "ready": result.ready,
                "launch_method": result.launch_method,
                "checks": result.checks,
                "auto_fixed": result.auto_fixed,
            })))
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Tool '{}' was not evaluated — may lack .env or .env.example", tool_name),
            })),
        ),
    }
}

// ============================================================================
// Tool configure / repair — ecosystem self-healing actions
// ============================================================================

/// POST /api/v1/tools/:tool_name/configure
///
/// Actions:
///   - `reassign_port`: Release the tool's current port assignment and
///     let the allocator pick a new one. Useful when a port is in use by
///     another process.
async fn tools_configure_handler(
    State(state): State<AppState>,
    axum::extract::Path(tool_name): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let action = body.get("action").and_then(|a| a.as_str()).unwrap_or("");

    match action {
        "reassign_port" => {
            // Release the old assignment
            state.0.port_allocator.release(&tool_name);

            // Detect the port var and tool path
            let scan_path = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("projects");
            let tool_path = scan_path.join(&tool_name);
            let port_var = tool_ports::detect_port_var(&tool_path);

            // Re-assign to next free port
            match state.0.port_allocator.get_or_assign(&tool_name, &port_var) {
                Ok(assignment) => {
                    // Re-write .env.zp with new port
                    if tool_path.exists() {
                        if let Err(e) = tool_ports::write_env_zp(
                            &tool_path,
                            &tool_name,
                            &assignment,
                        ) {
                            tracing::warn!("Failed to write .env.zp for {}: {}", tool_name, e);
                        }
                    }

                    tracing::info!(
                        "Reassigned {}: new port {}",
                        tool_name, assignment.port
                    );

                    (StatusCode::OK, Json(serde_json::json!({
                        "ok": true,
                        "tool": tool_name,
                        "new_port": assignment.port,
                        "port_var": port_var,
                    })))
                }
                Err(e) => {
                    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                        "error": format!("Port reassignment failed: {}", e),
                    })))
                }
            }
        }
        _ => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Unknown configure action: '{}'", action),
                "valid_actions": ["reassign_port"],
            })))
        }
    }
}

/// POST /api/v1/tools/:tool_name/repair
///
/// Actions:
///   - `fix_docker_network`: Remove orphaned Docker network so compose can adopt it.
async fn tools_repair_handler(
    axum::extract::Path(tool_name): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let action = body.get("action").and_then(|a| a.as_str()).unwrap_or("");

    match action {
        "fix_docker_network" => {
            // docker network rm <tool_name>_with (common pattern for compose networks)
            let network_candidates = vec![
                format!("{}_with", tool_name),
                format!("{}_default", tool_name),
                tool_name.clone(),
            ];

            let mut removed = Vec::new();
            let mut errors = Vec::new();

            for network in &network_candidates {
                let output = std::process::Command::new("docker")
                    .args(["network", "rm", network])
                    .output();

                match output {
                    Ok(o) if o.status.success() => {
                        removed.push(network.clone());
                        tracing::info!("Removed Docker network: {}", network);
                    }
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        // "No such network" is expected for non-existent candidates
                        if !stderr.contains("No such network") && !stderr.contains("not found") {
                            errors.push(format!("{}: {}", network, stderr.trim()));
                        }
                    }
                    Err(e) => {
                        errors.push(format!("docker not available: {}", e));
                        break;
                    }
                }
            }

            if !removed.is_empty() || errors.is_empty() {
                (StatusCode::OK, Json(serde_json::json!({
                    "ok": true,
                    "removed_networks": removed,
                    "hint": "Run preflight again to verify the fix.",
                })))
            } else {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                    "error": "Could not remove Docker networks",
                    "details": errors,
                })))
            }
        }
        _ => {
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("Unknown repair action: '{}'", action),
                "valid_actions": ["fix_docker_network"],
            })))
        }
    }
}

// ============================================================================
// Tool-issued lifecycle receipts (tools attest to their own state)
// ============================================================================

/// Accept a lifecycle receipt from a tool (POST).
///
/// Tools call this to announce their own state transitions:
///   { "name": "IronClaw", "event": "setup:complete", "detail": "Admin created" }
///
/// The receipt is emitted into the audit chain under the tool lifecycle
/// namespace, signed with ZeroPoint's identity. This is how tools
/// participate in the receipt chain without needing their own signing keys.
async fn tools_receipt_handler(
    State(state): State<AppState>,
    Json(body): Json<tool_chain::ToolReceiptRequest>,
) -> Json<serde_json::Value> {
    let event = format!("tool:{}:{}", body.event, body.name);
    let detail = body.detail.as_deref();

    match tool_chain::emit_tool_receipt(&state.0.audit_store, &event, detail) {
        Some(hash) => Json(serde_json::json!({
            "ok": true,
            "event": event,
            "entry_hash": hash,
        })),
        None => Json(serde_json::json!({
            "ok": false,
            "error": "Failed to append to audit chain",
        })),
    }
}

/// Return tool readiness state derived from the audit chain (GET).
///
/// This is the canonical view — the cockpit can call this to see
/// which lifecycle receipts exist for each tool.
async fn tools_chain_handler(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let chain_state = tool_chain::query_tool_readiness(&state.0.audit_store);
    let tools: Vec<&tool_chain::ToolChainState> = chain_state.values().collect();
    Json(serde_json::json!({
        "tools": tools,
        "source": "audit_chain",
    }))
}

// ============================================================================
// Dashboard Handler (Verification Surface)
// ============================================================================

// Embedded fallbacks — used only if the on-disk file is missing.
const DASHBOARD_HTML_FALLBACK: &str = include_str!("../assets/dashboard.html");
const ONBOARD_HTML_FALLBACK: &str = include_str!("../assets/onboard.html");
const SPEAK_HTML_FALLBACK: &str = include_str!("../assets/speak.html");
const ECOSYSTEM_HTML_FALLBACK: &str = include_str!("../assets/ecosystem.html");

/// Resolve an HTML asset: check $ZP_ASSETS_DIR or ~/.zeropoint/assets/{name}
/// first (override), then fall back to the compiled-in copy.
///
/// Two-tier system:
///   1. Override dir  — hot-reload via `./zp-dev.sh html`, or persistent files
///   2. Compiled-in   — always available, matches last Rust build
fn resolve_html_asset(name: &str, fallback: &'static str) -> String {
    // 1. Override: $ZP_ASSETS_DIR or ~/.zeropoint/assets/<name>
    let override_dir = std::env::var("ZP_ASSETS_DIR")
        .map(std::path::PathBuf::from)
        .ok()
        .or_else(|| dirs::home_dir().map(|h| h.join(".zeropoint").join("assets")));

    if let Some(dir) = override_dir {
        let path = dir.join(name);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            return contents;
        }
    }

    // 2. Compiled-in fallback
    fallback.to_string()
}

/// Root handler: redirect to /onboard if no genesis ceremony has been completed,
/// otherwise serve the dashboard.
async fn root_handler() -> Response {
    let genesis_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("genesis.json");

    // Check for a complete genesis record (one with an operator field from onboarding)
    let has_complete_genesis = if let Ok(contents) = std::fs::read_to_string(&genesis_path) {
        if let Ok(record) = serde_json::from_str::<serde_json::Value>(&contents) {
            record.get("operator").and_then(|v| v.as_str()).is_some()
        } else {
            false
        }
    } else {
        false
    };

    if has_complete_genesis {
        Html(resolve_html_asset("dashboard.html", DASHBOARD_HTML_FALLBACK)).into_response()
    } else {
        Redirect::temporary("/onboard").into_response()
    }
}

async fn dashboard_handler() -> Html<String> {
    Html(resolve_html_asset("dashboard.html", DASHBOARD_HTML_FALLBACK))
}

async fn onboard_page_handler() -> Html<String> {
    Html(resolve_html_asset("onboard.html", ONBOARD_HTML_FALLBACK))
}

async fn speak_page_handler() -> Html<String> {
    Html(resolve_html_asset("speak.html", SPEAK_HTML_FALLBACK))
}

async fn ecosystem_page_handler() -> Html<String> {
    Html(resolve_html_asset("ecosystem.html", ECOSYSTEM_HTML_FALLBACK))
}

// ============================================================================
// Genesis Record Handler
// ============================================================================

async fn genesis_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let home = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".zeropoint")
        .join("genesis.json");

    if let Ok(contents) = std::fs::read_to_string(&home) {
        // Return raw JSON — supports both server-genesis and onboard-genesis formats
        if let Ok(mut record) = serde_json::from_str::<serde_json::Value>(&contents) {
            // Annotate with live identity hierarchy status
            if let Some(obj) = record.as_object_mut() {
                obj.insert(
                    "identity_from_hierarchy".to_string(),
                    serde_json::Value::Bool(state.0.identity.from_hierarchy),
                );
                if state.0.identity.from_hierarchy {
                    obj.insert(
                        "active_operator_key".to_string(),
                        serde_json::Value::String(state.0.identity.public_key_hex.clone()),
                    );
                }
            }
            return Json(record);
        }
    }

    Json(serde_json::json!({
        "error": "No genesis record found"
    }))
}
