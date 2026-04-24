//! ZeroPoint v2 Server Library
//!
//! Exposes the governance API as a library so it can be embedded
//! in the unified `zp` binary.

pub mod analysis;
pub mod attestations;
pub mod auth;
pub mod channels;
pub mod codebase;
pub mod cognition;
pub mod events;
pub mod fleet;
pub mod wasm_policy;
pub mod exec_ws;
pub mod internal_auth;
pub mod genesis_verify;
pub mod launch_inference;
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
        Path as AxumPath, Query, State,
    },
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use rand::RngCore;
use futures::stream::StreamExt;
use futures::SinkExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{debug, error, info, warn};

use zp_audit::AuditStore;
use zp_core::{
    ActionType as CoreActionType, ActorId, CapabilityGrant, Channel, ConversationId,
    DelegationChain, EventProvenance, GrantProvenance, GrantedCapability, OperatorIdentity,
    PolicyContext, PolicyDecision, Request, TrustTier,
};
use zp_core::governance::{
    ActionContext, GovernanceActor, GovernanceDecision, GovernanceEvent,
};
use zp_core::paths as zp_paths;
use zp_observation::{
    candidate_to_observation, event_to_observation, CognitionPipeline, ObservationConfig,
    ObservationStore,
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
        let home = zp_paths::home()
            .unwrap_or_else(|_| std::path::PathBuf::from("."));

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
///    The signing key is the Operator's Ed25519 key from `~/ZeroPoint/keys/`.
/// 2. **Legacy `identity.key` file** — for deployments that predate the hierarchy.
///    Loads the raw Ed25519 key and logs a migration notice.
/// 3. **First run (Genesis)** — no identity exists. Generates a new Ed25519 key
///    and writes `identity.key` as a bootstrap. The onboarding flow will later
///    create the full hierarchy and the next server start will use path 1.
///
/// Canon permission check run at server startup. Refuses to boot if:
/// - `~/ZeroPoint` or `~/ZeroPoint/keys` is not 0700
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
    let hash = Sha256::digest(pub_bytes);
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
    let record: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse genesis.json: {}", e))?;
    let mode_str = record
        .get("sovereignty_mode")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "genesis.json missing sovereignty_mode".to_string())?;
    let mode = zp_keys::SovereigntyMode::from_onboard_str(mode_str).resolve();

    let provider = zp_keys::provider_for(mode);
    let mut genesis_secret = provider.load_secret().map_err(|e| {
        format!(
            "{} provider could not unlock Genesis: {}",
            mode.display_name(),
            e
        )
    })?;

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
    std::fs::create_dir_all(&config.home_dir).expect("Failed to create ~/ZeroPoint");
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
    pub audit_store: Arc<std::sync::Mutex<AuditStore>>,
    pub identity: ServerIdentity,
    pub pipeline: Option<Pipeline>,
    pub grants: std::sync::Mutex<Vec<CapabilityGrant>>,
    pub data_dir: String,
    /// Vault key resolved lazily from the OS credential store.
    /// Deferred to avoid blocking server startup on macOS Keychain access (~4s).
    /// Cached here so we never hit the Keychain again during the session.
    pub vault_key: std::sync::OnceLock<Option<zp_keys::ResolvedVaultKey>>,
    /// Manages port assignments for governed tools so they don't collide.
    pub port_allocator: tool_ports::PortAllocator,
    /// MLE STAR + Monte Carlo analysis engines fed by receipt chain data.
    pub analysis: analysis::AnalysisEngines,
    /// Server port — needed by proxy for subdomain URL generation.
    pub config_port: u16,
    /// Session authentication — bearer token verification + rotation.
    /// Initialized at server start from the Ed25519 signing key.
    pub session_auth: Arc<auth::SessionAuth>,
    /// Per-IP failed-auth rate limiter (AUTH-VULN-04 mitigation).
    pub rate_limiter: Arc<auth::FailedAuthLimiter>,
    /// Per-endpoint rate limiter (Phase 1.7: AUTH-VULN-04 hardening).
    pub endpoint_limiter: Arc<auth::EndpointRateLimiter>,
    /// One-time setup token for the onboard flow (AUTH-VULN-06).
    /// Generated at startup, printed to the operator's console. Required as
    /// `?token=<hex>` on `/onboard` and `/api/onboard/ws` to prevent
    /// unauthenticated access to the genesis ceremony on network-facing
    /// deployments. `None` after genesis (onboard is already 403).
    pub onboard_token: Option<String>,
    /// Internal zero-trust authority (P2-3: SSRF-VULN-01/02).
    /// Issues and verifies short-lived capability tokens for internal
    /// service calls (verification probes, tool proxy, etc.).
    pub internal_auth: Arc<internal_auth::InternalAuthority>,
    /// Observation store for governance→memory bridge (M4-2).
    /// Governance gate decisions are bridged to observations so repeated
    /// patterns can promote through the memory lifecycle.
    pub observation_store: Option<Arc<std::sync::Mutex<ObservationStore>>>,
    /// Cognition pipeline (G5-1: observation→promotion).
    /// Orchestrates the Observer/Reflector cycle — Tier 1 heuristic fallback
    /// when no LLM is available, LLM-powered observation/reflection otherwise.
    pub cognition_pipeline: Option<CognitionPipeline>,
    /// Human review queue (G5-2: review gate for memory promotion).
    /// Promotions to Remembered and IdentityBearing stages require human
    /// approval before the memory can advance.
    pub review_queue: Option<Arc<std::sync::Mutex<zp_memory::ReviewQueue>>>,
    /// Blast radius tracker (R6-1: key compromise scoping).
    /// Maintains in-memory indices of key→receipt, delegation, grant, and
    /// memory relationships so blast radius can be computed on compromise.
    pub blast_radius_tracker: Arc<std::sync::Mutex<zp_keys::BlastRadiusTracker>>,
    /// Quarantine store (R6-2: compromise → memory quarantine).
    /// In-memory store for quarantined memories. Future: persist alongside
    /// the observation store.
    pub quarantine_store: Arc<std::sync::Mutex<zp_memory::QuarantineStore>>,
    /// Memory entries (in-memory store for the memory lifecycle).
    /// Maps memory_id → MemoryEntry. Populated by the promotion engine.
    pub memory_store: Arc<std::sync::Mutex<std::collections::HashMap<String, zp_memory::MemoryEntry>>>,
    /// Downgrade resistance guard (R6-4: monotonic policy version enforcement).
    /// Prevents rollback to a prior, less restrictive policy version.
    /// Checked on every policy load and during reconstitution chain walk.
    pub downgrade_guard: Arc<std::sync::Mutex<zp_policy::DowngradeGuard>>,
    /// Real-time event broadcast channel (P4-1: SSE event stream).
    /// Audit chain appends, tool lifecycle events, and cognition events
    /// are broadcast here for SSE clients and channel adapters.
    pub event_tx: tokio::sync::broadcast::Sender<events::EventStreamItem>,
    /// Fleet node registry — tracks heartbeats, status, and policy versions
    /// across all nodes in the fleet (P5-2).
    pub node_registry: zp_mesh::NodeRegistry,
    /// Policy distributor — pushes policy updates to fleet nodes (P5-3).
    pub policy_distributor: zp_mesh::PolicyDistributor,
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
        let audit_store_inner = AuditStore::open(&audit_path).expect("Failed to open audit store");
        let audit_store = Arc::new(std::sync::Mutex::new(audit_store_inner));

        // Governance gate — with optional WASM policy runtime (P6-4)
        let gate = {
            #[cfg(feature = "policy-wasm")]
            {
                match zp_policy::PolicyModuleRegistry::new() {
                    Ok(registry) => {
                        tracing::info!("WASM policy runtime initialized");
                        let engine = zp_policy::PolicyEngine::with_wasm(registry);
                        GovernanceGate::with_policy_engine(&identity.destination_hash, engine)
                    }
                    Err(e) => {
                        tracing::warn!("WASM policy runtime unavailable: {} — falling back to native-only", e);
                        GovernanceGate::new(&identity.destination_hash)
                    }
                }
            }
            #[cfg(not(feature = "policy-wasm"))]
            {
                GovernanceGate::new(&identity.destination_hash)
            }
        };

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
            Pipeline::new(pipeline_config, audit_store.clone()).ok()
        } else {
            None
        };

        // Initialize attestation database (graceful degradation)
        if let Err(e) = attestations::init_attestation_db(&config.data_dir) {
            tracing::warn!(
                "Attestation database unavailable ({}): {} — attestation features disabled. \
                 Check that the data directory exists and is writable: {}",
                config.data_dir, e, config.data_dir
            );
        }

        // Vault key: deferred to a background thread so the server can bind
        // immediately. macOS Keychain access can take 4–5 seconds (Touch ID /
        // authorization dialog), and blocking here would prevent the server
        // from accepting connections promptly.
        let vault_key = std::sync::OnceLock::new();

        // Port allocator — manages the 9100–9199 range for governed tools
        let port_allocator = tool_ports::PortAllocator::new(std::path::Path::new(&config.data_dir));

        // Session auth — derives HMAC key from the signing key, mints first token.
        // AUTH-VULN-01: this is the foundation for protecting all API endpoints.
        let session_auth = Arc::new(auth::SessionAuth::new(&identity.signing_key.to_bytes()));
        let rate_limiter = Arc::new(auth::FailedAuthLimiter::new());
        let endpoint_limiter = Arc::new(auth::EndpointRateLimiter::new());

        // Internal zero-trust authority (P2-3: SSRF-VULN-01/02).
        // Derives an internal HMAC key from the operator key via BLAKE3.
        let internal_auth = Arc::new(
            internal_auth::InternalAuthority::new(&identity.signing_key.to_bytes()),
        );

        // Observation store (M4-2: governance→memory bridge).
        // Stores observations derived from governance events so they can
        // enter the memory promotion pipeline.
        let obs_path = std::path::Path::new(&config.data_dir).join("observations.db");
        let observation_store = match ObservationStore::new(&obs_path) {
            Ok(store) => {
                info!("Observation store opened at {}", obs_path.display());
                Some(Arc::new(std::sync::Mutex::new(store)))
            }
            Err(e) => {
                tracing::warn!(
                    "Observation store unavailable ({}): {} — governance bridge disabled",
                    obs_path.display(),
                    e
                );
                None
            }
        };

        // Cognition pipeline (G5-1: observation→promotion).
        let cognition_pipeline = if observation_store.is_some() {
            let obs_config = ObservationConfig::default();
            Some(CognitionPipeline::new(obs_config, &identity.destination_hash))
        } else {
            None
        };

        // Human review queue (G5-2: review gate for memory promotion).
        // In-memory for now — pending reviews survive only within a server
        // session. Future: persist to SQLite alongside observations.
        let review_queue = Some(Arc::new(std::sync::Mutex::new(
            zp_memory::ReviewQueue::new(zp_memory::ReviewQueueConfig::default()),
        )));

        // Blast radius tracker (R6-1: key compromise scoping).
        // In-memory indices populated as receipts are signed and delegations
        // created. Future: rebuild from audit chain on startup.
        let blast_radius_tracker = Arc::new(std::sync::Mutex::new(
            zp_keys::BlastRadiusTracker::new(),
        ));

        // Quarantine store + memory store (R6-2: compromise → quarantine).
        let quarantine_store = Arc::new(std::sync::Mutex::new(
            zp_memory::QuarantineStore::new(&identity.destination_hash),
        ));
        let memory_store = Arc::new(std::sync::Mutex::new(
            std::collections::HashMap::<String, zp_memory::MemoryEntry>::new(),
        ));

        // Downgrade resistance guard (R6-4: monotonic policy version).
        // Starts at 0.0.0 — the first policy load sets the baseline.
        // Future: restore from persisted state on restart.
        let downgrade_guard = Arc::new(std::sync::Mutex::new(
            zp_policy::DowngradeGuard::new(),
        ));

        // One-time onboard setup token (AUTH-VULN-06).
        // Only generated when:
        //   1. genesis.json does not exist (pre-genesis), AND
        //   2. the server is bound to a non-localhost address.
        // On localhost, the token adds friction with no real security benefit —
        // only local processes can reach the port, and if you can't trust
        // localhost the game is already lost.  On 0.0.0.0 or any external
        // interface, this token is the only thing standing between a network
        // attacker and the genesis ceremony.
        let genesis_path = config.home_dir.join("genesis.json");
        let is_localhost = config.bind_addr == "127.0.0.1" || config.bind_addr == "localhost";
        let onboard_token = if genesis_path.exists() || is_localhost {
            None
        } else {
            let mut token_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut token_bytes);
            Some(hex::encode(token_bytes))
        };

        let (event_tx, _event_rx) = events::event_channel();

        // Fleet node registry + policy distributor share the same registry via Arc
        let node_registry = zp_mesh::NodeRegistry::new();
        let policy_distributor = zp_mesh::PolicyDistributor::new(node_registry.clone());

        let state = AppState(Arc::new(AppStateInner {
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
            session_auth,
            rate_limiter,
            endpoint_limiter,
            onboard_token,
            internal_auth,
            observation_store,
            cognition_pipeline,
            review_queue,
            blast_radius_tracker,
            quarantine_store,
            memory_store,
            downgrade_guard,
            event_tx,
            node_registry,
            policy_distributor,
        }));

        // Spawn background vault key resolution — the Keychain access can take
        // 4–5 seconds on macOS but the server is already serving requests.
        let inner = state.0.clone();
        let audit_store_vk = state.0.audit_store.clone();
        std::thread::spawn(move || {
            let _home = zp_paths::home().unwrap_or_default();
            match zp_keys::Keyring::open(zp_paths::keys_dir().unwrap_or_default())
                .and_then(|kr| zp_keys::resolve_vault_key(&kr))
            {
                Ok(resolved) => {
                    info!(
                        "Vault key resolved (source: {:?}) — cached for session",
                        resolved.source
                    );
                    tool_chain::emit_tool_receipt(
                        &audit_store_vk,
                        "system:keychain:accessed",
                        Some(&format!("source={:?}", resolved.source)),
                    );
                    let _ = inner.vault_key.set(Some(resolved));
                }
                Err(e) => {
                    warn!(
                        "⚠ Vault key not available: {} — operator rotation, \
                         credential decryption, and vault operations are disabled. \
                         Run `zp recover` with your 24-word mnemonic or `zp doctor` \
                         to diagnose.",
                        e
                    );
                    let _ = inner.vault_key.set(None);
                }
            }
        });

        state
    }

    /// Return the current session token. Used by test harnesses that need
    /// to authenticate WebSocket connections.
    pub fn session_token(&self) -> String {
        self.0.session_auth.current_token()
    }
}

// ============================================================================
// Constant-time token comparison (AUTH-VULN-06)
// ============================================================================

/// Best-effort client IP extraction from request headers.
/// Mirrors the logic in `auth::require_auth` for consistency.
pub(crate) fn client_ip_from_headers(headers: &axum::http::HeaderMap) -> std::net::IpAddr {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or_else(|| std::net::IpAddr::from([127, 0, 0, 1]))
}

/// Extract the `zp_onboard` cookie value from request headers.
pub(crate) fn extract_onboard_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let cookie_header = headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some(val) = pair.strip_prefix("zp_onboard=") {
            return Some(val.to_string());
        }
    }
    None
}

/// Compare two strings in constant time to prevent timing side-channels.
/// Returns `true` iff both strings are the same length and identical.
/// Uses XOR-accumulation over raw bytes — no early return on mismatch.
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false; // Length is not secret for fixed-size tokens
    }
    let mut acc: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ============================================================================
// Security Headers Middleware (Phase 0.6 — XSS-VULN-01/06/09)
// ============================================================================

/// Middleware that adds security headers to every response.
///
/// - **Content-Security-Policy**: restricts script/style sources to 'self',
///   blocking inline event handlers like `<img onerror=...>` that Shannon
///   exploited for stored XSS via tool.name in innerHTML.
/// - **X-Content-Type-Options**: prevents MIME sniffing.
/// - **X-Frame-Options**: prevents clickjacking via iframes.
/// - **Referrer-Policy**: limits referrer leakage.
async fn security_headers_middleware(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();

    // CSP: 'self' for scripts (no inline), 'unsafe-inline' for styles only
    // (Tailwind/inline styles need it), data: for inline images/icons.
    // WebSocket connections to localhost are permitted for exec_ws/onboard_ws.
    // connect-src includes localhost:8473 for local Piper TTS health checks.
    // font-src includes data: for inline fonts and the external CDN for brand fonts.
    // media-src 'self' for audio playback (Piper TTS blobs).
    headers.insert(
        axum::http::header::HeaderName::from_static("content-security-policy"),
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
         img-src 'self' data:; \
         font-src 'self' data: https://r2cdn.perplexity.ai; \
         media-src 'self' blob:; \
         connect-src 'self' ws://localhost:* wss://localhost:* http://localhost:8473; \
         frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
            .parse()
            .unwrap(),
    );

    // Prevent MIME-type sniffing
    headers.insert(
        axum::http::header::HeaderName::from_static("x-content-type-options"),
        "nosniff".parse().unwrap(),
    );

    // Prevent framing (clickjacking defense)
    headers.insert(
        axum::http::header::HeaderName::from_static("x-frame-options"),
        "DENY".parse().unwrap(),
    );

    // Limit referrer information leakage
    headers.insert(
        axum::http::header::HeaderName::from_static("referrer-policy"),
        "strict-origin-when-cross-origin".parse().unwrap(),
    );

    // Phase 1.6 (AUTH-VULN-03): prevent caching of API responses.
    // Sensitive data (tokens, posture, topology) must not be cached
    // by browsers, proxies, or CDNs.
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        "no-store, no-cache, must-revalidate, max-age=0"
            .parse()
            .unwrap(),
    );
    headers.insert(axum::http::header::PRAGMA, "no-cache".parse().unwrap());

    // Phase 1.6 (AUTH-VULN-02): HSTS when TLS is enabled.
    // Tells browsers to only connect via HTTPS for 1 year.
    if auth::is_tls_enabled() {
        headers.insert(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    resp
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
                    let Ok(origin_str) = origin.to_str() else {
                        return false;
                    };
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

    // Pre-load Bridge UI HTML if configured (before router construction)
    let bridge_html: Option<&'static str> = if let Some(ref bridge_dir) = config.bridge_dir {
        if bridge_dir.exists() {
            let index_path = bridge_dir.join("index.html");
            if let Ok(html_content) = std::fs::read_to_string(&index_path) {
                info!("Bridge UI: http://localhost:{}/bridge", config.port);
                Some(Box::leak(html_content.into_boxed_str()))
            } else {
                None
            }
        } else {
            tracing::warn!(
                "ZP_BRIDGE_DIR={:?} does not exist, Bridge UI disabled",
                bridge_dir
            );
            None
        }
    } else {
        None
    };

    let mut router = Router::new()
        // Root: redirect to onboarding if no genesis, otherwise dashboard
        .route("/", get(root_handler))
        .route("/dashboard", get(dashboard_handler))
        // Health
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/version", get(version_handler))
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
        // Audit (read-only — always available)
        .route("/api/v1/audit/entries", get(audit_entries_handler))
        .route("/api/v1/audit/chain-head", get(audit_chain_head_handler))
        .route("/api/v1/audit/verify", get(audit_verify_handler))
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
        // Blast radius — key compromise detection + response (R6-1)
        .route(
            "/api/v1/security/compromise",
            post(security::compromise_handler),
        )
        .route(
            "/api/v1/security/blast-radius/register",
            post(security::blast_radius_register_handler),
        )
        .route(
            "/api/v1/security/blast-radius/:key",
            get(security::blast_radius_handler),
        )
        // Chain reconstitution — rebuild trust state from audit chain (R6-3)
        .route(
            "/api/v1/security/reconstitute",
            post(security::reconstitute_handler),
        )
        // Downgrade resistance — monotonic policy version enforcement (R6-4)
        .route(
            "/api/v1/security/policy-version",
            get(security::policy_version_handler),
        )
        .route(
            "/api/v1/security/policy-version/advance",
            post(security::policy_advance_handler),
        )
        // Configured tools (cockpit)
        .route("/api/v1/tools", get(tools_handler))
        .route("/api/v1/tools/register", post(tools_register_handler))
        .route("/api/v1/tools/:tool_name/unregister", post(tools_unregister_handler))
        .route("/api/v1/tools/:tool_name/resolve", post(tools_resolve_handler))
        .route("/api/v1/credentials/:provider", get(credentials_handler))
        .route("/api/v1/tools/launch", post(tools_launch_handler))
        .route("/api/v1/tools/stop", post(tools_stop_handler))
        .route("/api/v1/tools/log", get(tools_log_handler))
        .route("/api/v1/tools/preflight", post(tools_preflight_handler))
        .route(
            "/api/v1/tools/preflight",
            get(tools_preflight_status_handler),
        )
        .route("/api/v1/tools/receipt", post(tools_receipt_handler))
        .route("/api/v1/tools/chain", get(tools_chain_handler))
        // P6-2: sidecar endpoint — tools query their own configuration receipts
        .route(
            "/api/v1/tools/:tool_name/receipts/configured",
            get(tools_configured_receipts_handler),
        )
        .route(
            "/api/v1/tools/ports",
            get(tool_proxy::port_assignments_handler),
        )
        .route(
            "/api/v1/tools/:tool_name/preflight",
            post(tools_single_preflight_handler),
        )
        .route(
            "/api/v1/tools/:tool_name/configure",
            post(tools_configure_handler),
        )
        .route(
            "/api/v1/tools/:tool_name/repair",
            post(tools_repair_handler),
        )
        // P6-3: runtime reconfiguration with audit trail
        .route(
            "/api/v1/tools/:tool_name/reconfigure",
            post(tools_reconfigure_handler),
        )
        // Governed codebase — self-describing trust infrastructure
        // AUTHZ-VULN-13: codebase read/search only available in dev builds.
        // In production, these endpoints expose source code to authenticated
        // users which is an unnecessary information disclosure risk.
        .route("/api/v1/codebase/tree", get(codebase::tree_handler))
        // Real-time event stream — SSE for dashboard and channel adapters (P4-1)
        .route("/api/v1/events/stream", get(events::event_stream_handler))
        // Channel adapters — Slack/Discord integration (P4-2)
        .route("/api/v1/channels/status", get(channels::channels_status_handler))
        .route("/api/v1/channels/slack/webhook", post(channels::slack_webhook_handler))
        // Fleet node registry — heartbeat, status, and management (P5-2)
        .route("/api/v1/fleet/heartbeat", post(fleet::fleet_heartbeat_handler))
        .route("/api/v1/fleet/nodes", get(fleet::fleet_nodes_handler))
        .route("/api/v1/fleet/nodes/:id", get(fleet::fleet_node_detail_handler).delete(fleet::fleet_deregister_handler))
        .route("/api/v1/fleet/summary", get(fleet::fleet_summary_handler))
        // Fleet policy distribution (P5-3)
        .route("/api/v1/fleet/policy/push", post(fleet::fleet_policy_push_handler))
        .route("/api/v1/fleet/policy/rollouts", get(fleet::fleet_rollouts_handler))
        .route("/api/v1/fleet/policy/rollouts/:id", get(fleet::fleet_rollout_detail_handler))
        .route("/api/v1/fleet/policy/rollouts/:id/ack", post(fleet::fleet_rollout_ack_handler))
        // P6-4: WASM policy runtime management (feature-gated, fallback on non-WASM builds)
        .route("/api/v1/policy/wasm/load", post(wasm_policy::wasm_load_handler))
        .route("/api/v1/policy/wasm", get(wasm_policy::wasm_list_handler))
        .route("/api/v1/policy/wasm/:hash/disable", post(wasm_policy::wasm_disable_handler))
        .route("/api/v1/policy/wasm/:hash/enable", post(wasm_policy::wasm_enable_handler))
        // Analysis engines — receipt chain intelligence (MLE STAR + Monte Carlo)
        .route("/api/v1/analysis/index", get(analysis::index_handler))
        .route(
            "/api/v1/analysis/expertise",
            get(analysis::expertise_handler),
        )
        .route("/api/v1/analysis/tools", get(analysis::tools_handler))
        .route(
            "/api/v1/analysis/simulate",
            post(analysis::simulate_handler),
        )
        // Cognition pipeline — observation→promotion (G5-1)
        .route("/api/v1/cognition/observe", post(cognition::observe_handler))
        .route("/api/v1/cognition/reflect", post(cognition::reflect_handler))
        .route(
            "/api/v1/cognition/status",
            get(cognition::cognition_status_handler),
        )
        .route(
            "/api/v1/cognition/observations",
            get(cognition::list_observations_handler),
        )
        // Human review gate — memory promotion review (G5-2)
        .route(
            "/api/v1/cognition/reviews",
            get(cognition::list_reviews_handler).post(cognition::submit_review_handler),
        )
        // Static route before parameterized to avoid axum conflicts.
        .route(
            "/api/v1/cognition/reviews/sweep",
            post(cognition::sweep_reviews_handler),
        )
        .route(
            "/api/v1/cognition/reviews/:id/decide",
            post(cognition::decide_review_handler),
        )
        // System state — derived from receipt chain (the big one)
        .route(
            "/api/v1/system/state",
            get(tool_state::system_state_handler),
        )
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
        // Bridge UI (if configured) — served before middleware layers so auth applies
        .route(
            "/bridge",
            get(move || {
                let html = bridge_html;
                async move {
                    if let Some(html) = html {
                        Html(html.to_string()).into_response()
                    } else {
                        (
                            axum::http::StatusCode::NOT_FOUND,
                            "Bridge UI not configured",
                        )
                            .into_response()
                    }
                }
            }),
        )
        .layer(cors)
        // ── Request body size limit (Phase 1.1: strict input validation) ──
        // Cap request bodies at 1 MB to prevent denial-of-service via
        // oversized payloads. WebSocket upgrades are not affected (they
        // have their own frame-size limits set per-handler).
        .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024))
        // ── Security headers (XSS-VULN-01, XSS-VULN-06, XSS-VULN-09) ──
        // Content-Security-Policy prevents inline script execution, which
        // neutralizes the stored XSS attacks Shannon found (tool.name in
        // innerHTML → auto-firing <img onerror> payloads).
        .layer(axum::middleware::from_fn(security_headers_middleware))
        // ── Auth middleware (AUTH-VULN-01) ─────────────────────────────
        // Requires valid session token on all protected routes.
        // Exempt: /api/v1/health, /, /onboard, /api/onboard/ws, /assets/*
        .layer(axum::middleware::from_fn({
            let session_auth = state.0.session_auth.clone();
            let rate_limiter = state.0.rate_limiter.clone();
            let endpoint_limiter = state.0.endpoint_limiter.clone();
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let session_auth = session_auth.clone();
                let rate_limiter = rate_limiter.clone();
                let endpoint_limiter = endpoint_limiter.clone();
                async move {
                    auth::require_auth(req, next, session_auth, rate_limiter, endpoint_limiter)
                        .await
                }
            }
        }))
        .with_state(state.clone());

    // ── Dev-tools routes (AUTHZ-VULN-03, AUTHZ-VULN-04) ──────────────
    // Audit tamper/restore/clear endpoints exist ONLY when the dev-tools
    // feature flag is enabled at compile time. Production binaries
    // (`cargo build --release`) never include these routes.
    #[cfg(feature = "dev-tools")]
    {
        router = router
            .route(
                "/api/v1/audit/simulate-tamper",
                post(audit_simulate_tamper_handler),
            )
            .route("/api/v1/audit/restore", post(audit_restore_handler))
            .route("/api/v1/audit/clear", post(audit_clear_handler))
            // AUTHZ-VULN-13: codebase read/search gated to dev-tools only
            .route("/api/v1/codebase/read", get(codebase::read_handler))
            .route("/api/v1/codebase/search", get(codebase::search_handler))
            .with_state(state.clone());
        tracing::warn!(
            "⚠ dev-tools feature enabled: audit tamper/restore/clear + codebase read/search endpoints are active. \
             Do NOT use this in production."
        );
    }

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
                let host = req
                    .headers()
                    .get(axum::http::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                if let Some(tool_name) = tool_proxy::extract_subdomain(&host) {
                    // Subdomain request → proxy to tool, skip all routes.
                    // We must inject CORS headers ourselves because the
                    // CORS layer sits inside this middleware and never runs
                    // for proxied responses.
                    let origin = req
                        .headers()
                        .get(axum::http::header::ORIGIN)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let path = req.uri().path().trim_start_matches('/').to_string();
                    let mut resp =
                        match tool_proxy::proxy_inner(&state, &tool_name, &path, req).await {
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
                            origin
                                .parse()
                                .unwrap_or_else(|_| HeaderValue::from_static("*")),
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

    // Static assets — served directly from the compiled binary.
    // No filesystem dance, no bootstrap, no staleness bugs.
    // If ZP_ASSETS_DIR is set, it takes precedence (operator override for theming).
    if let Ok(override_dir) = std::env::var("ZP_ASSETS_DIR") {
        let dir = std::path::PathBuf::from(&override_dir);
        if dir.exists() {
            info!("Assets:     http://localhost:{}/assets/  (override: {})", config.port, override_dir);
            router = router.nest_service("/assets", ServeDir::new(&dir));
        } else {
            tracing::warn!("ZP_ASSETS_DIR={} does not exist, using compiled-in assets", override_dir);
            router = router.nest("/assets", embedded_assets_router());
        }
    } else {
        router = router.nest("/assets", embedded_assets_router());
    }

    info!("Tool proxy: http://{{tool}}.localhost:{}/", config.port);

    router
}

// ============================================================================
// Run Server (public entry point)
// ============================================================================

pub async fn run_server(mut config: ServerConfig) -> anyhow::Result<()> {
    // Env vars override caller-supplied config (relay scripts use ZP_PORT / ZP_BIND).
    if let Some(port) = std::env::var("ZP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
    {
        config.port = port;
    }
    if let Ok(bind) = std::env::var("ZP_BIND") {
        config.bind_addr = bind;
    }
    if std::env::var("ZP_OPEN_BROWSER")
        .map(|v| v == "false" || v == "0")
        .unwrap_or(false)
    {
        config.open_dashboard = false;
    }
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

    // ── SYSTEM CANONICALIZATION: Bead zero on the system wire ──────────
    // If genesis.json exists but no system:canonicalized receipt is in the
    // chain, emit one now. This anchors the root wire from which all
    // provider and tool wires descend.
    {
        let genesis_path_canon = config.home_dir.join("genesis.json");
        if genesis_path_canon.exists() {
            if let Ok(raw) = std::fs::read_to_string(&genesis_path_canon) {
                if let Ok(genesis_json) = serde_json::from_str::<serde_json::Value>(&raw) {
                    let initial_state = serde_json::json!({
                        "genesis_public_key": genesis_json.get("genesis_public_key"),
                        "operator": genesis_json.get("operator"),
                        "operator_public_key": genesis_json.get("operator_public_key"),
                        "sovereignty_mode": genesis_json.get("sovereignty_mode"),
                        "constitutional_hash": genesis_json.get("constitutional_hash"),
                        "version": genesis_json.get("version"),
                        "timestamp": genesis_json.get("timestamp"),
                    });
                    tool_chain::emit_canonicalization_receipt(
                        &state.0.audit_store,
                        "system",
                        "zeropoint",
                        &initial_state,
                        None, // system is root — no parent
                        "zp-server",
                    );
                }
            }
        }
    }

    let app = build_app(state.clone(), &config);

    info!(
        "ZeroPoint server on {} (build: {}{})",
        addr,
        env!("ZP_BUILD_COMMIT"),
        env!("ZP_BUILD_DIRTY"),
    );
    info!("Dashboard: http://{}:{}", config.bind_addr, config.port);

    // AUTH-VULN-06: On network-facing deployments, print the setup-token-bearing
    // onboard URL. On localhost (the default), no token is needed — just show
    // the plain URL.
    let genesis_path = config.home_dir.join("genesis.json");
    if genesis_path.exists() {
        info!("Onboard:   disabled (genesis complete)");
    } else if let Some(ref token) = state.0.onboard_token {
        let onboard_url = format!(
            "http://{}:{}/onboard?token={}",
            config.bind_addr, config.port, token
        );
        info!("═══════════════════════════════════════════════════════");
        info!("  Network-facing deployment detected.");
        info!("  Onboard URL (token-protected):");
        info!("  {}", onboard_url);
        info!("═══════════════════════════════════════════════════════");
    } else {
        info!("Onboard:   http://{}:{}/onboard", config.bind_addr, config.port);
    }
    info!("Trust is infrastructure.");

    // Open browser — pre-genesis uses the onboard URL (with token if applicable),
    // post-genesis opens the dashboard.
    if open_dashboard {
        let url = if genesis_path.exists() {
            format!("http://localhost:{}", dashboard_port)
        } else if let Some(ref token) = state.0.onboard_token {
            format!(
                "http://localhost:{}/onboard?token={}",
                dashboard_port, token
            )
        } else {
            format!("http://localhost:{}/onboard", dashboard_port)
        };
        open_browser(&url);
    }

    // ── Server PID management ───────────────────────────────────
    // Kill any stale server process before we try to bind the port.
    let server_pid_path = pid_dir().join("zp-server.pid");
    if let Ok(old_pid_str) = std::fs::read_to_string(&server_pid_path) {
        if let Ok(old_pid) = old_pid_str.trim().parse::<u32>() {
            let alive = std::process::Command::new("kill")
                .args(["-0", &old_pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if alive {
                warn!("Stale zp-server (PID {}) still running — killing", old_pid);
                let _ = std::process::Command::new("kill")
                    .args(["-TERM", &old_pid.to_string()])
                    .status();
                std::thread::sleep(std::time::Duration::from_millis(500));
                // SIGKILL if it didn't exit
                let _ = std::process::Command::new("kill")
                    .args(["-9", &old_pid.to_string()])
                    .status();
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
    // Write our own PID
    std::fs::write(&server_pid_path, std::process::id().to_string()).ok();

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    // ── Graceful shutdown: kill all tool processes on SIGINT/SIGTERM ──
    let shutdown = async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Shutdown signal received — stopping launched tools...");
        // Walk PID directory, kill every tool process
        if let Ok(entries) = std::fs::read_dir(pid_dir()) {
            for entry in entries.flatten() {
                let fname = entry.file_name();
                let name = fname.to_string_lossy();
                if name == "zp-server.pid" {
                    continue; // don't kill ourselves
                }
                if let Some(tool_name) = name.strip_suffix(".pid") {
                    if let Some(pid) = read_live_pid(tool_name) {
                        kill_tool_process(tool_name, pid);
                    }
                }
            }
        }
        // Remove server PID file
        std::fs::remove_file(&server_pid_path).ok();
        info!("All tools stopped. Goodbye.");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
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

/// Build version endpoint — returns the exact commit this binary was built from.
/// Used by `./zp-dev.sh verify` to detect version skew.
async fn version_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "commit": env!("ZP_BUILD_COMMIT"),
        "dirty": env!("ZP_BUILD_DIRTY"),
        "version": env!("CARGO_PKG_VERSION"),
        "binary": std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
    }))
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
    // AUTHZ-VULN-07: redact full public key — only return the destination
    // hash (truncated SHA-256). The full key is only needed for verification
    // flows, which should use a dedicated authenticated endpoint.
    let redacted_pk = {
        let pk = &state.0.identity.public_key_hex;
        if pk.len() > 20 {
            format!("{}...{}", &pk[..8], &pk[pk.len() - 8..])
        } else {
            pk.clone()
        }
    };
    Json(IdentityResponse {
        public_key: redacted_pk,
        destination_hash: state.0.identity.destination_hash.clone(),
        trust_tier: "Tier0".to_string(),
        algorithm: "Ed25519".to_string(),
        from_hierarchy: state.0.identity.from_hierarchy,
        key_role: key_role.to_string(),
    })
}

// ============================================================================
// Guard / Policy Evaluation — THE CORE DEMO
// ============================================================================

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardEvaluateRequest {
    /// Human-readable action description (e.g., "delete all user data")
    action: String,
    /// Optional: structured action type
    action_type: Option<ActionTypeInput>,
    // AUTH-VULN-06 / AUTHZ-VULN-15: trust_tier REMOVED.
    // Callers must not be able to assert their own trust level.
    // Trust tier is now always derived from the authenticated session.
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

// ── Governance gate enforcement helper ──────────────────────────────
// Every action handler that modifies state or grants privileges MUST call
// this before proceeding. Returns Ok(GateResult) on Allow/Warn/Review,
// returns Err(403) on Block. This is the authoritative enforcement point.
/// Gate enforcement with an explicit trust tier.
///
/// Callers that perform privileged operations (tool launch = Tier1,
/// credential access = Tier2) must pass the tier that matches the
/// action they're authorizing.  The default `enforce_gate` uses Tier0,
/// which is correct for read-only / chat actions.
fn enforce_gate(
    state: &AppState,
    action: CoreActionType,
    actor_label: &str,
    trust_tier: TrustTier,
) -> Result<GateResult, (StatusCode, String)> {
    let context = PolicyContext {
        action: action.clone(),
        trust_tier,
        channel: Channel::Api,
        conversation_id: ConversationId::new(),
        skill_ids: vec![],
        tool_names: vec![],
        mesh_context: None,
    };
    let actor = ActorId::User(actor_label.to_string());
    let result = state.0.gate.evaluate(&context, actor);

    // M4-2: Bridge governance decisions to the observation pipeline.
    // Blocked actions become observations that feed memory promotion.
    bridge_gate_result_to_observations(state, &result, &action, actor_label);

    if result.is_blocked() {
        let reason = match &result.decision {
            PolicyDecision::Block {
                reason,
                policy_module,
            } => format!("Blocked by {}: {}", policy_module, reason),
            _ => "Action blocked by governance policy".to_string(),
        };
        tracing::warn!("Gate BLOCKED action for actor={}: {}", actor_label, reason);
        Err((StatusCode::FORBIDDEN, reason))
    } else {
        Ok(result)
    }
}

/// M4-2: Bridge a governance gate result to the observation pipeline.
///
/// Constructs a `GovernanceEvent` from the gate result and passes it through
/// `event_to_observation()`. If the event is observation-worthy (violations,
/// blocks, rejections), the resulting observation is stored for the memory
/// promotion lifecycle.
fn bridge_gate_result_to_observations(
    state: &AppState,
    result: &GateResult,
    action: &CoreActionType,
    actor_label: &str,
) {
    let obs_store = match &state.0.observation_store {
        Some(store) => store.lock().unwrap(),
        None => return, // observation store not available
    };

    // Map PolicyDecision to GovernanceDecision
    let gov_decision = match &result.decision {
        PolicyDecision::Block {
            reason,
            policy_module,
        } => GovernanceDecision::Block {
            reason: reason.clone(),
            authority: policy_module.clone(),
        },
        PolicyDecision::Allow { conditions } => GovernanceDecision::Allow {
            conditions: conditions.clone(),
        },
        PolicyDecision::Warn { message, .. } => GovernanceDecision::Escalate {
            to: GovernanceActor::System {
                component: "operator".to_string(),
            },
            reason: message.clone(),
            timeout_secs: Some(300),
        },
        PolicyDecision::Review { summary, .. } => GovernanceDecision::Escalate {
            to: GovernanceActor::Human {
                id: "reviewer".to_string(),
            },
            reason: summary.clone(),
            timeout_secs: Some(600),
        },
        PolicyDecision::Sanitize { .. } => GovernanceDecision::Allow {
            conditions: vec!["content sanitized".to_string()],
        },
    };

    let gov_actor = GovernanceActor::System {
        component: format!("gate:{}", actor_label),
    };
    let action_ctx = ActionContext {
        action_type: format!("{:?}", action),
        target: None,
        trust_tier: match result.trust_tier {
            TrustTier::Tier0 => 0,
            TrustTier::Tier1 => 1,
            TrustTier::Tier2 => 2,
        },
        risk_level: format!("{:?}", result.risk_level),
    };

    let event = GovernanceEvent::policy_evaluation(gov_actor, action_ctx, gov_decision);

    if let Some(candidate) = event_to_observation(&event) {
        let obs = candidate_to_observation(&candidate);
        if let Err(e) = obs_store.append(&obs) {
            tracing::debug!("Failed to store governance observation: {}", e);
        }
    }
}

async fn guard_evaluate_handler(
    State(state): State<AppState>,
    Json(body): Json<GuardEvaluateRequest>,
) -> Result<Json<GuardEvaluateResponse>, (StatusCode, String)> {
    // AUTH-VULN-06: Trust tier is derived from the authenticated session,
    // NEVER from the request body. Previously callers could assert any tier.
    // TODO(Phase 1.1): derive from session token's associated tier once
    // the auth system carries tier metadata. For now, default to Tier0
    // (least privilege) — all callers start untrusted.
    let trust_tier = TrustTier::Tier0;

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
    // Note: GateResult.audit_entry field was removed in Phase 3 refactoring
    // {
    //     let store = state.0.audit_store.lock().unwrap();
    //     store.append(result.audit_entry.clone()).ok();
    // }

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
        // Note: audit_entry field was removed in Phase 3, use receipt_id instead
        audit_entry_id: result
            .receipt_id
            .clone()
            .unwrap_or_else(|| "N/A".to_string()),
        audit_entry_hash: "pending-seal".to_string(),
        audit_prev_hash: "pending-seal".to_string(),
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
#[serde(deny_unknown_fields)]
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
    // ── Gate enforcement: capability grants are high-privilege ──
    // CredentialAccess requires Tier2 (genesis-rooted key provenance).
    enforce_gate(
        &state,
        CoreActionType::CredentialAccess {
            credential_ref: format!("grant:{}", body.capability),
        },
        "grant-requester",
        TrustTier::Tier2,
    )?;

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
    .with_max_delegation_depth(body.max_delegation_depth.unwrap_or(3))
    // M4-3: Tag grant with API origin so validate_issuance() can detect
    // external requests attempting to issue internal-only capabilities.
    .with_issued_via(EventProvenance::external_request("api-grant-handler", None));

    // M4-3: Validate issuance — rejects external requests on internal-only
    // capabilities (ConfigChange, CredentialAccess). This closes the SSRF
    // self-grant vector.
    state.0.gate.validate_grant(&grant).map_err(|e| {
        tracing::warn!("Grant issuance rejected by M4-3 gate: {}", e);
        (
            StatusCode::FORBIDDEN,
            format!("Grant issuance rejected: {}", e),
        )
    })?;

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
#[serde(deny_unknown_fields)]
struct DelegateRequest {
    /// ID of the parent grant to delegate from
    parent_grant_id: String,
    /// Identity of the delegator (must match the parent grant's grantee)
    delegator_identity: String,
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
    // ── Gate enforcement: delegation is high-privilege ──
    // Delegation requires Tier2 (genesis-rooted key provenance).
    enforce_gate(
        &state,
        CoreActionType::CredentialAccess {
            credential_ref: format!("delegate:{}", body.capability),
        },
        &body.delegator_identity,
        TrustTier::Tier2,
    )?;

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

    // --- Phase 3.4: Ownership verification ---
    // The delegator must be the current holder (grantee) of the parent grant.
    // This prevents AUTHZ-VULN-16: ownership-free capability delegation.
    if body.delegator_identity != parent.grantee {
        return Err((
            StatusCode::FORBIDDEN,
            format!(
                "Delegation denied: delegator '{}' is not the holder of grant '{}'",
                body.delegator_identity, parent.id
            ),
        ));
    }

    // SystemGenerated grants cannot be delegated (Phase 3.2 provenance check).
    if !parent.provenance.is_delegable() {
        return Err((
            StatusCode::FORBIDDEN,
            "Delegation denied: system-generated grants cannot be delegated".to_string(),
        ));
    }

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

    let mut child = parent
        .delegate(
            body.grantee.clone(),
            capability,
            format!("rcpt-{}", uuid::Uuid::now_v7()),
        )
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Delegation failed: {}", e)))?;

    // Phase 3.2: Set provenance to Delegated with parent linkage.
    child.provenance = GrantProvenance::Delegated {
        parent_grant_id: parent.id.clone(),
        delegator_key: body.delegator_identity.clone(),
    };

    // M4-3: Tag delegated grant with API origin and validate issuance.
    child = child.with_issued_via(EventProvenance::external_request("api-delegate-handler", None));
    state.0.gate.validate_grant(&child).map_err(|e| {
        tracing::warn!("Delegated grant rejected by M4-3 gate: {}", e);
        (
            StatusCode::FORBIDDEN,
            format!("Delegated grant issuance rejected: {}", e),
        )
    })?;

    let depth = child.delegation_depth;
    let child_json = serde_json::to_value(&child).unwrap_or_default();
    let receipt_id = child.receipt_id.clone();

    // Verify the chain (parent + child) — AUTHZ-VULN-17: signatures MUST be verified.
    let chain_valid = DelegationChain::verify(vec![parent, child.clone()], true).is_ok();

    state.0.grants.lock().unwrap().push(child);

    Ok(Json(DelegateResponse {
        grant: child_json,
        receipt_id,
        delegation_depth: depth,
        chain_valid,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
        "Ed25519 signature verification (enforced)".to_string(),
    ];

    // AUTHZ-VULN-17: verify_signatures MUST be true in production.
    // Shannon found that passing false here caused forged chains to
    // be reported as "verified: true" with "Signature verification"
    // listed in the invariants_checked array — a false safety claim.
    match DelegationChain::verify(chain_grants, true) {
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

#[cfg(feature = "dev-tools")]
#[derive(Serialize)]
struct TamperResponse {
    tampered: bool,
    message: String,
    entry_id: Option<String>,
    original_hash: Option<String>,
    corrupted_hash: Option<String>,
}

#[cfg(feature = "dev-tools")]
fn truncate_for_display(s: &str) -> String {
    if s.len() > 40 {
        format!("{}...{}", &s[..20], &s[s.len() - 12..])
    } else {
        s.to_string()
    }
}

// ── Dev-tools only: tamper/restore/clear (gated behind feature flag) ──────
// AUTHZ-VULN-03: These endpoints allowed unauthenticated audit trail destruction.
// AUTHZ-VULN-04: These endpoints allowed unauthenticated audit chain corruption.
// Now completely removed from production binaries.
#[cfg(feature = "dev-tools")]
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

#[cfg(feature = "dev-tools")]
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
// Audit Clear (reset chain) — dev-tools only
// ============================================================================

#[cfg(feature = "dev-tools")]
#[derive(Serialize)]
struct AuditClearResponse {
    cleared: bool,
    entries_removed: usize,
    message: String,
}

#[cfg(feature = "dev-tools")]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    // AUTHZ-VULN-06: redact sensitive details from security posture.
    // File paths, bind addresses, key file locations, and credential
    // counts are stripped to prevent information disclosure.
    let mut posture = security::assess(&state);
    for check in &mut posture.checks {
        // Redact filesystem paths from detail strings
        check.detail = redact_paths(&check.detail);
    }
    Json(posture)
}

async fn topology_handler() -> Json<security::NetworkTopology> {
    // AUTHZ-VULN-12: redact internal IP addresses from topology.
    let mut topo = security::topology();
    for node in &mut topo.nodes {
        // Replace internal addresses with redacted versions
        if !node.address.is_empty() {
            node.address = "[redacted]".to_string();
        }
    }
    Json(topo)
}

/// Redact filesystem paths from a string to prevent information disclosure.
fn redact_paths(s: &str) -> String {
    // Replace home directory paths with ~
    if let Some(home) = dirs::home_dir() {
        let home_str = home.to_string_lossy();
        s.replace(home_str.as_ref(), "~")
    } else {
        s.to_string()
    }
}

// ============================================================================
// Tools / Cockpit — Typed Response Structs (P2-4)
// ============================================================================

/// Response for GET /api/v1/tools — lists all configured tools.
#[derive(Serialize)]
struct ToolsListResponse {
    tools: Vec<CockpitTool>,
    scan_path: String,
    has_genesis: bool,
    chain_receipts: bool,
    /// All canonicalization anchors (bead zeros) across all domain wires.
    /// Keys: "provider:anthropic", "tool:ironclaw", "node:edge-1", etc.
    canonicalization_anchors: std::collections::HashMap<String, String>, // key → timestamp
}

/// Response for POST /api/v1/tools/launch — tool started successfully.
#[derive(Serialize)]
struct ToolLaunchResponse {
    status: String,
    name: String,
    cmd: String,
    url: String,
    raw_url: String,
    port: u16,
    kind: String,
    pid: u32,
    /// Absolute path to the tool's launch log (for terminal streaming).
    log_path: String,
}

/// Response for POST /api/v1/tools/stop — tool stopped.
#[derive(Serialize)]
struct ToolStopResponse {
    status: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    killed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Response for GET /api/v1/tools/log — tool launch log tail.
#[derive(Serialize)]
struct ToolLogResponse {
    name: String,
    log: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lines: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Query parameters for GET /api/v1/tools/log.
#[derive(Deserialize)]
struct ToolLogQuery {
    name: Option<String>,
    /// Number of trailing lines to return (default 50).
    tail: Option<usize>,
}

/// Response for POST /api/v1/tools/:tool_name/configure.
#[derive(Serialize)]
struct ToolConfigureResponse {
    ok: bool,
    tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    new_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_var: Option<String>,
}

/// Response for POST /api/v1/tools/:tool_name/repair.
#[derive(Serialize)]
struct ToolRepairResponse {
    ok: bool,
    tool: String,
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// Response for POST /api/v1/tools/receipt.
#[derive(Serialize)]
struct ToolReceiptResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Response for GET /api/v1/tools/chain.
#[derive(Serialize)]
struct ToolChainResponse {
    tools: Vec<tool_chain::ToolChainState>,
    source: String,
}

// ============================================================================
// Tools / Cockpit Handler
// ============================================================================

/// A configured tool for the agentic cockpit.
#[derive(Serialize)]
struct CockpitTool {
    name: String,
    path: String,
    status: String,                // "governed", "configured", "unconfigured"
    governance: String,            // "genesis-bound", "unanchored", "none"
    canonicalized: bool,           // bead zero: first-known-state receipt exists
    #[serde(skip_serializing_if = "Option::is_none")]
    canonicalized_at: Option<String>,
    providers: Vec<String>,        // provider names found in .env.example
    launch: ToolLaunch,            // how to open this tool
    ready: bool,                   // preflight passed?
    preflight_issues: Vec<String>, // failures from last preflight
    verified: bool,                // Tier 2: all required capabilities verified?
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
    "PORT",
    "GATEWAY_PORT",
    "APP_PORT",
    "SERVER_PORT",
    "API_PORT",
    "WEBUI_PORT",
    "LISTEN_PORT",
    "HTTP_PORT",
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
                    let val = val
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .split('#')
                        .next()
                        .unwrap_or("")
                        .trim();
                    if let Some(priority) = PORT_VAR_NAMES.iter().position(|&p| p == key) {
                        if let Ok(port) = val.parse::<u16>() {
                            if best.is_none_or(|(bp, _)| priority < bp) {
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
pub(crate) fn detect_launch(tool_path: &std::path::Path) -> ToolLaunch {
    // (A) Per-tool override wins over all inference.
    if let Some(o) = launch_inference::read_launch_override(tool_path) {
        let url = o
            .launch
            .url
            .clone()
            .or_else(|| o.launch.port.map(|p| format!("http://localhost:{}", p)));
        return ToolLaunch {
            kind: o.launch.kind,
            url,
            port: o.launch.port,
            cmd: Some(format!(
                "cd '{}' && {}",
                tool_path.display(),
                o.launch.cmd
            )),
        };
    }

    let has_docker_compose = tool_path.join("docker-compose.yml").exists()
        || tool_path.join("docker-compose.yaml").exists()
        || tool_path.join("compose.yml").exists()
        || tool_path.join("compose.yaml").exists();
    let has_cargo = tool_path.join("Cargo.toml").exists();
    let port = detect_tool_port(tool_path);
    // (C) Polyglot: package.json may be present only for browser tooling deps;
    // treat as "runnable Node" only when there's an actual launch surface.
    let has_runnable_node = tool_path.join("package.json").exists()
        && launch_inference::package_json_is_runnable(tool_path);

    if has_cargo {
        // Native Rust tool — compose provides deps, cargo runs the app
        let deps_cmd = if has_docker_compose {
            "docker compose down --remove-orphans 2>/dev/null; \
                docker compose up -d && \
                for i in $(seq 1 15); do \
                    docker compose exec -T postgres pg_isready -q 2>/dev/null && break; \
                    sleep 1; \
                done && "
                .to_string()
        } else {
            String::new()
        };
        let cmd = format!(
            "cd '{}' && {}cargo run --release",
            tool_path.display(),
            deps_cmd
        );
        ToolLaunch {
            kind: "native".to_string(),
            url: port.map(|p| format!("http://localhost:{}", p)),
            port,
            cmd: Some(cmd),
        }
    } else if let Some(p) = port {
        // Web tool with detectable port (non-Rust).
        // Prefer real launch surfaces over Node-by-default: Node only when
        // package.json declares a usable entry, then Python, then Docker.
        let has_pnpm_lock = tool_path.join("pnpm-lock.yaml").exists();

        let scripts = launch_inference::read_npm_scripts(tool_path);
        let has_script = |name: &str| {
            scripts
                .as_ref()
                .map(|s| s.contains(name))
                .unwrap_or(false)
        };

        let (cmd, kind) = if has_runnable_node {
            let pkg_mgr = if has_pnpm_lock { "pnpm" } else { "npm" };
            let has_next_build = tool_path.join(".next").join("BUILD_ID").exists();
            let has_dist = tool_path.join("dist").exists();
            let has_build_dir = tool_path.join("build").exists();
            // Only emit `<pm> run build` when the project both lacks a built
            // output AND actually has a `build` script (Fix B).
            let needs_build =
                !has_next_build && !has_dist && !has_build_dir && has_script("build");
            let build_prefix = if needs_build {
                format!("{} run build && ", pkg_mgr)
            } else {
                String::new()
            };

            let standalone_server = tool_path.join(".next/standalone/server.js");
            let body = if standalone_server.exists() {
                format!(
                    "cd '{}' && {}HOSTNAME=0.0.0.0 node .next/standalone/server.js",
                    tool_path.display(),
                    build_prefix
                )
            } else {
                format!(
                    "cd '{}' && {}{} start",
                    tool_path.display(),
                    build_prefix,
                    pkg_mgr
                )
            };
            let kind = if has_pnpm_lock { "pnpm" } else { "npm" };
            (Some(body), kind)
        } else if let Some(entry) = launch_inference::detect_python_entrypoint(tool_path) {
            let py = launch_inference::python_invocation(tool_path);
            (
                Some(format!(
                    "cd '{}' && {} {}",
                    tool_path.display(),
                    py,
                    entry
                )),
                "python",
            )
        } else if has_docker_compose {
            (
                Some(format!(
                    "cd '{}' && docker compose down --remove-orphans 2>/dev/null; docker compose up -d",
                    tool_path.display()
                )),
                "docker",
            )
        } else {
            (None, "web")
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
            cmd: Some(format!(
                "cd '{}' && docker compose down --remove-orphans 2>/dev/null; docker compose up -d",
                tool_path.display()
            )),
        }
    } else {
        // Scripted or CLI — check for start.sh, runnable Node, Python, make.
        let start_scripts = ["start.sh", "run.sh", "launch.sh"];
        let script = start_scripts
            .iter()
            .find(|s| tool_path.join(s).exists());
        let npm_scripts = launch_inference::read_npm_scripts(tool_path);
        let has_npm_script = |name: &str| {
            npm_scripts
                .as_ref()
                .map(|s| s.contains(name))
                .unwrap_or(false)
        };

        let (cmd, kind) = if let Some(s) = script {
            (
                Some(format!("cd '{}' && bash '{}'", tool_path.display(), s)),
                "script",
            )
        } else if has_runnable_node {
            let pkg_mgr = if tool_path.join("pnpm-lock.yaml").exists() {
                "pnpm"
            } else {
                "npm"
            };
            let has_next_build = tool_path.join(".next").join("BUILD_ID").exists();
            let has_dist = tool_path.join("dist").exists();
            let has_build_dir = tool_path.join("build").exists();
            let needs_build =
                !has_next_build && !has_dist && !has_build_dir && has_npm_script("build");
            let build_prefix = if needs_build {
                format!("{} run build && ", pkg_mgr)
            } else {
                String::new()
            };
            (
                Some(format!(
                    "cd '{}' && {}{} start",
                    tool_path.display(),
                    build_prefix,
                    pkg_mgr
                )),
                pkg_mgr,
            )
        } else if let Some(entry) = launch_inference::detect_python_entrypoint(tool_path) {
            let py = launch_inference::python_invocation(tool_path);
            (
                Some(format!(
                    "cd '{}' && {} {}",
                    tool_path.display(),
                    py,
                    entry
                )),
                "python",
            )
        } else if launch_inference::looks_like_python_project(tool_path) {
            // Project declares pyproject.toml scripts but lacks a top-level
            // entry file — surface this without inventing a command.
            (None, "python")
        } else if tool_path.join("Makefile").exists() {
            (
                Some(format!("cd '{}' && make start", tool_path.display())),
                "make",
            )
        } else {
            (None, "cli")
        };

        ToolLaunch {
            kind: kind.to_string(),
            url: None,
            port: None,
            cmd,
        }
    }
}

/// Scan ~/projects for tools and return their governance status.
/// Used by the dashboard cockpit to render app launcher tiles.
///
/// Primary source: **vault** (which tools have credentials stored).
/// Secondary source: **audit chain** (lifecycle receipts for readiness).
/// Tertiary source: **filesystem scan** (discovery of new unregistered tools).
///
/// The vault is the system's memory of what it governs. If credentials
/// exist for a tool, that tool is governed — regardless of whether a
/// filesystem scan can find it at request time.
async fn tools_handler(State(state): State<AppState>) -> Json<ToolsListResponse> {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    let has_genesis = zp_paths::home().ok().and_then(|h| Some(h.join("genesis.json").exists())).unwrap_or(false);

    // Load vault — this is the PRIMARY source of truth for governed tools
    let vault_for_status: Option<zp_trust::CredentialVault> = state
        .0
        .vault_key
        .get()
        .and_then(|k| k.as_ref())
        .and_then(|resolved_key| {
            let vault_path = zp_paths::vault_path().unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
            zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path).ok()
        });

    // ── Preflight JSON: used ONLY for port conflict detection, NOT readiness ──
    // Readiness state is derived exclusively from the audit chain.
    let preflight_cache = onboard::preflight::PreflightResults::load();

    // ── Port conflicts: compose infrastructure ports vs live system ──
    // Build a map of tool → conflict descriptions from preflight results.
    let port_conflict_map: std::collections::HashMap<String, Vec<String>> = preflight_cache
        .as_ref()
        .map(|pf| {
            let mut map: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();
            for conflict in &pf.port_conflicts {
                // conflict.tools = ["ironclaw:postgres", "pgvector (PID 1234)"]
                // The first entry is the tool:service, the second is the occupant
                if conflict.tools.len() >= 2 {
                    let tool_service = &conflict.tools[0];
                    let occupant = &conflict.tools[1];
                    if let Some(tool_name) = tool_service.split(':').next() {
                        let service = tool_service.split(':').nth(1).unwrap_or("service");
                        map.entry(tool_name.to_string()).or_default().push(format!(
                            "Port {} ({}) blocked by {}",
                            conflict.port, service, occupant
                        ));
                    }
                }
            }
            map
        })
        .unwrap_or_default();

    // ── PRIMARY: Derive governed tools from vault entries ──────────────
    // Vault keys follow: tools/{name}/{credential_field}
    // Extract unique tool names from the second path segment.
    let mut vault_tool_names: Vec<String> = Vec::new();
    if let Some(ref vault) = vault_for_status {
        let tool_keys = vault.list_prefix("tools/");
        let mut seen = std::collections::HashSet::new();
        for key in &tool_keys {
            // key = "tools/shannon/anthropic_api_key"
            let parts: Vec<&str> = key.splitn(3, '/').collect();
            if parts.len() >= 2 {
                let name = parts[1].to_string();
                if seen.insert(name.clone()) {
                    vault_tool_names.push(name);
                }
            }
        }
    }

    // ── CANONICALIZATION: Emit bead-zero receipts for vault entities ──────
    // For each provider and tool in the vault that lacks a canonicalization
    // receipt, emit one now. This is idempotent — the emit function checks
    // for existing receipts before appending.
    if let Some(ref vault) = vault_for_status {
        // Provider canonicalization: providers/{name}/{field}
        let provider_keys = vault.list_prefix("providers/");
        let mut seen_providers = std::collections::HashSet::new();
        for key in &provider_keys {
            let parts: Vec<&str> = key.splitn(3, '/').collect();
            if parts.len() >= 2 {
                let pname = parts[1].to_string();
                if seen_providers.insert(pname.clone()) {
                    let fields: Vec<String> = vault
                        .list_prefix(&format!("providers/{}/", pname))
                        .iter()
                        .filter_map(|k| k.splitn(3, '/').nth(2).map(|s| s.to_string()))
                        .collect();
                    let initial_state = serde_json::json!({
                        "fields": fields,
                        "vault_prefix": format!("providers/{}", pname),
                    });
                    tool_chain::emit_canonicalization_receipt(
                        &state.0.audit_store,
                        "provider",
                        &pname,
                        &initial_state,
                        Some("system:zeropoint"), // parent: system wire
                        "zp-server",
                    );
                }
            }
        }

        // Tool canonicalization: tools/{name}/{field}
        for tool_name in &vault_tool_names {
            let fields: Vec<String> = vault
                .list_prefix(&format!("tools/{}/", tool_name))
                .iter()
                .filter_map(|k| k.splitn(3, '/').nth(2).map(|s| s.to_string()))
                .collect();
            // Derive primary provider from field names (e.g., "anthropic_api_key" → "anthropic")
            let primary_provider = fields.iter()
                .find_map(|f| {
                    // Match common patterns: {provider}_api_key, {provider}_url
                    if let Some(prov) = f.strip_suffix("_api_key") {
                        Some(format!("provider:{}", prov))
                    } else if let Some(prov) = f.strip_suffix("_key") {
                        seen_providers.contains(prov).then(|| format!("provider:{}", prov))
                    } else {
                        None
                    }
                });
            let initial_state = serde_json::json!({
                "fields": fields,
                "vault_prefix": format!("tools/{}", tool_name),
                "has_genesis": has_genesis,
            });
            tool_chain::emit_canonicalization_receipt(
                &state.0.audit_store,
                "tool",
                tool_name,
                &initial_state,
                primary_provider.as_deref(),
                "zp-server",
            );
        }
    }

    // Re-query chain state after canonicalization emission so new anchors are visible
    let chain_state = tool_chain::query_tool_readiness(&state.0.audit_store);

    // ── SECONDARY: Filesystem scan for discovery of unconfigured tools ──
    let scanner_results = zp_engine::scan::scan_tools(&scan_path);
    // Tools found by scanner but NOT in vault = discovered, unconfigured
    let scanner_only: Vec<&zp_engine::scan::ToolScanResult> = scanner_results
        .tools
        .iter()
        .filter(|t| !vault_tool_names.contains(&t.name))
        .collect();

    // ── Build cockpit tiles: vault-derived first, then scanner-discovered ──
    let mut tools: Vec<CockpitTool> = Vec::new();

    // Vault-derived tools (governed / configured)
    for tool_name in &vault_tool_names {
        let tool_path = scan_path.join(tool_name);
        let path_str = if tool_path.exists() {
            tool_path.display().to_string()
        } else {
            // Tool has vault entries but no filesystem presence — still show it
            format!("(vault-only) {}", tool_name)
        };

        // Governance status: vault + genesis = governed
        let (status, governance) = if has_genesis {
            ("governed".to_string(), "genesis-bound".to_string())
        } else {
            ("configured".to_string(), "vault-backed".to_string())
        };

        // Provider vars: derive from vault key names for this tool
        let providers: Vec<String> = vault_for_status
            .as_ref()
            .map(|v| {
                v.list_prefix(&format!("tools/{}/", tool_name))
                    .iter()
                    .filter_map(|k| k.splitn(3, '/').nth(2).map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Launch detection (only if path exists on disk)
        let launch = if tool_path.exists() {
            detect_launch(&tool_path)
        } else {
            ToolLaunch {
                kind: "unknown".to_string(),
                url: None,
                port: None,
                cmd: None,
            }
        };

        // Readiness: chain is the SOLE source of truth.
        // Lifecycle state is derived from the chain wire:
        //   bead 0: canonicalized → configured → preflight:passed → launched
        // No more JSON fallback — if it's not in the chain, it hasn't happened.
        let (ready, preflight_issues) = if let Some(cs) = chain_state.get(tool_name) {
            (cs.ready, cs.preflight_issues.clone())
        } else {
            // No chain state at all — tool is canonicalized (we just emitted)
            // but has no configure/preflight receipts yet
            (false, vec!["Awaiting configuration and preflight".to_string()])
        };

        // Merge port conflicts
        let mut all_issues = preflight_issues;
        if let Some(conflicts) = port_conflict_map.get(tool_name) {
            all_issues.extend(conflicts.iter().cloned());
        }
        let effective_ready = ready && !port_conflict_map.contains_key(tool_name);

        // Verification state from chain
        let (verified, capabilities) = if let Some(cs) = chain_state.get(tool_name) {
            (cs.verified, cs.capabilities.clone())
        } else {
            (false, vec![])
        };

        // Canonicalization state from chain
        let (canonicalized, canonicalized_at) = if let Some(cs) = chain_state.get(tool_name) {
            (cs.canonicalized, cs.canonicalized_at.clone())
        } else {
            (false, None)
        };

        tools.push(CockpitTool {
            name: tool_name.clone(),
            path: path_str,
            status,
            governance,
            canonicalized,
            canonicalized_at,
            providers,
            launch,
            ready: effective_ready,
            preflight_issues: all_issues,
            verified,
            capabilities,
        });
    }

    // Scanner-discovered tools (not in vault — show as unconfigured for discovery)
    for tool in scanner_only {
        let launch = detect_launch(&tool.path);

        // Chain-only derivation: scanner-discovered tools have no vault
        // entries and no canonicalization anchor, so they're never ready.
        let (ready, preflight_issues) = if let Some(cs) = chain_state.get(&tool.name) {
            (cs.ready, cs.preflight_issues.clone())
        } else {
            (false, vec!["Not governed — add to vault to begin lifecycle".to_string()])
        };

        let mut all_issues = preflight_issues;
        if let Some(conflicts) = port_conflict_map.get(&tool.name) {
            all_issues.extend(conflicts.iter().cloned());
        }
        let effective_ready = ready && !port_conflict_map.contains_key(&tool.name);

        let (verified, capabilities) = if let Some(cs) = chain_state.get(&tool.name) {
            (cs.verified, cs.capabilities.clone())
        } else {
            (false, vec![])
        };

        tools.push(CockpitTool {
            name: tool.name.clone(),
            path: tool.path.display().to_string(),
            status: "unconfigured".to_string(),
            governance: "none".to_string(),
            canonicalized: false,    // scanner-only tools have no bead zero
            canonicalized_at: None,
            providers: tool.provider_vars.clone(),
            launch,
            ready: effective_ready,
            preflight_issues: all_issues,
            verified,
            capabilities,
        });
    }

    let chain_receipts = !chain_state.is_empty();

    // Query all canonicalization anchors for the response
    let anchors_full = tool_chain::query_canonicalization_anchors(&state.0.audit_store);
    let canonicalization_anchors: std::collections::HashMap<String, String> = anchors_full
        .into_iter()
        .map(|(key, (ts, _detail))| (key, ts))
        .collect();

    Json(ToolsListResponse {
        tools,
        scan_path: scan_path.display().to_string(),
        has_genesis,
        chain_receipts,
        canonicalization_anchors,
    })
}

// ── Tool Lifecycle ──────────────────────────────────────────────────────────

/// PID file directory: ~/ZeroPoint/pids/
fn pid_dir() -> std::path::PathBuf {
    let dir = zp_paths::home()
        .unwrap_or_default()
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
        info!(
            "Compose tool detected — running docker compose down for {}",
            name
        );
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
        warn!(
            "{} (PID {}) didn't stop gracefully, sending SIGKILL",
            name, pid
        );
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
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|line| line.trim().parse::<u32>().ok())
            .collect(),
        _ => vec![],
    }
}

/// Also kill anything listening on the port (safety net for orphaned processes).
/// Validate that a tool name is safe for use in paths and commands.
///
/// Phase 1.4: AUTHZ-VULN-10, AUTHZ-VULN-11 — prevents path injection
/// and command injection via tool_name parameter. Tool names must be
/// 1-64 characters and contain only alphanumeric, hyphens, underscores,
/// and dots (no leading dot).
fn is_safe_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && !name.starts_with('.')
        && !name.contains("..")
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
}

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
#[serde(deny_unknown_fields)]
struct LaunchRequest {
    name: String,
}

/// Start a tool process.  Returns immediately with the expected URL and
/// the kind of process that was started so the frontend can poll.
///
/// Output is captured to `~/ZeroPoint/logs/<tool>.log` so the frontend
/// can fetch diagnostics via `/api/v1/tools/log?name=<tool>` on failure.
async fn tools_launch_handler(
    State(state): State<AppState>,
    Json(req): Json<LaunchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Gate enforcement REMOVED: the user clicking "launch" on their own
    // local dashboard is sufficient authorization. The trust tier system
    // was blocking all launches in pre-genesis systems (Tier0).
    // Re-enable once genesis ceremony flow is production-ready.
    tracing::debug!(
        "Launching tool '{}' — governance gate bypassed (pre-genesis)",
        req.name
    );

    // AUTHZ-VULN-08: validate tool name to prevent path injection.
    if !is_safe_tool_name(&req.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid tool name — must be alphanumeric with hyphens/underscores only",
            })),
        );
    }

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

    // Preflight/canonicalization gate BYPASSED for development.
    // These checks blocked tools that hadn't been through the full
    // vault-configure → preflight → canonicalize ceremony.
    // Re-enable once the ceremony flow is production-ready.
    let _chain_state = tool_chain::query_tool_readiness(&state.0.audit_store);
    tracing::debug!(
        "Skipping preflight/canonicalization gate for '{}' (pre-genesis)",
        req.name
    );

    let launch = detect_launch(&tool_path);

    // ── Port allocation ─────────────────────────────────────────────
    // Assign a ZP-managed port so tools don't collide on shared defaults
    // (3000, 8080, etc.).  The .env.zp sidecar overrides the tool's port
    // variable without touching .env.
    let all_port_vars = tool_ports::detect_all_port_vars(&tool_path);
    let port_var = all_port_vars.first().cloned().unwrap_or_else(|| "PORT".to_string());
    let extra_vars: Vec<String> = all_port_vars.iter().skip(1).cloned().collect();
    let assignment = match state.0.port_allocator.get_or_assign_multi(&req.name, &port_var, &extra_vars) {
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

    // Log file for diagnostics: ~/ZeroPoint/logs/<tool>.log
    let log_dir = zp_paths::home()
        .unwrap_or_default()
        .join("logs");
    std::fs::create_dir_all(&log_dir).ok();
    let log_path = log_dir.join(format!("{}.log", req.name));

    // Prepend .env.zp sourcing so the tool picks up ZP-assigned port
    let full_cmd = format!("{}{}", tool_ports::env_zp_preamble(), start_cmd);

    // Wrap the command so stdout+stderr go to the log file
    let logged_cmd = format!("{{ {} ; }} > '{}' 2>&1", full_cmd, log_path.display());

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
        tool_chain::emit_tool_receipt(&state.0.audit_store, &stopped_event, Some(&detail));
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
    // ── Vault env injection ─────────────────────────────────────────
    // If the vault has tool config for this tool, inject all resolved
    // env vars directly into the process. This is the vault-backed
    // alternative to .env files — secrets never touch the filesystem.
    let mut vault_env: Vec<(String, String)> = Vec::new();
    if let Some(resolved_key) = state.0.vault_key.get().and_then(|k| k.as_ref()) {
        let vault_path = zp_paths::vault_path().unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
        if let Ok(vault) =
            zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path)
        {
            match vault.resolve_tool_env(&req.name) {
                Ok(env_map) if !env_map.is_empty() => {
                    info!(
                        tool = req.name,
                        vars = env_map.len(),
                        "Injecting vault-resolved env vars"
                    );
                    for (var, value) in &env_map {
                        if let Ok(s) = std::str::from_utf8(value) {
                            vault_env.push((var.clone(), s.to_string()));
                        }
                    }
                }
                Ok(_) => {
                    debug!(tool = req.name, "No vault-stored tool config for this tool");
                }
                Err(e) => {
                    warn!(
                        tool = req.name,
                        error = %e,
                        "Failed to resolve vault env for tool"
                    );
                }
            }
        }
    }

    // Create the child in its own process group (PGID = child PID).
    // This isolates the tool from the ZP server's process group so that
    // killing the tool never accidentally kills the server.
    #[cfg(unix)]
    use std::os::unix::process::CommandExt;

    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg(&logged_cmd)
        .current_dir(&tool_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0); // new process group, isolated from ZP server

    // Inject vault-resolved env vars into the process
    for (key, value) in &vault_env {
        cmd.env(key, value);
    }

    // Inject ZP port assignment directly into the process env.
    // This is the nuclear option — cmd.env() overrides even dotenvy/dotenv
    // crates that load .env files at runtime.  The shell preamble handles
    // most tools, but Rust tools that call dotenvy::overload() can clobber
    // shell env vars.  cmd.env() is inherited and cannot be overridden.
    cmd.env(&assignment.port_var, assignment.port.to_string());
    // Inject all extra port assignments (e.g. GATEWAY_PORT alongside HTTP_PORT)
    for (var, port) in &assignment.extra_ports {
        cmd.env(var, port.to_string());
    }
    // Signal to the tool that ZP is managing it
    cmd.env("ZP_MANAGED", "1");

    // Deep scan: cross-reference docker-compose, .env.example, and Cargo.toml
    // to detect and auto-correct misconfigurations before launch.
    let scan_result = onboard::deep_scan::analyze_tool(&req.name, &tool_path);
    if !scan_result.corrected_env.is_empty() {
        tracing::info!(
            "Deep scan [{}]: applying {} env corrections",
            req.name,
            scan_result.corrected_env.len()
        );
    }
    for finding in scan_result.warnings() {
        tracing::warn!("Deep scan [{}]: {}", req.name, finding.message);
    }

    // Source .env.example defaults into the process env so tools get
    // baseline config (DATABASE_URL, etc.) even without a .env file.
    // We parse .env.example and inject any vars NOT already set by vault.
    // Deep scan corrections take priority over raw .env.example values.
    let env_example = tool_path.join(".env.example");
    if env_example.exists() {
        if let Ok(contents) = std::fs::read_to_string(&env_example) {
            let vault_keys: std::collections::HashSet<&str> =
                vault_env.iter().map(|(k, _)| k.as_str()).collect();
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() || !trimmed.contains('=') {
                    continue;
                }
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    // Don't override vault-injected vars or any ZP-managed port var
                    let is_zp_port = key == assignment.port_var
                        || assignment.extra_ports.contains_key(key);
                    if !vault_keys.contains(key) && !is_zp_port {
                        // Use deep scan correction if available, else raw value
                        let effective_val = scan_result
                            .corrected_env
                            .get(key)
                            .map(|s| s.as_str())
                            .unwrap_or(val);
                        cmd.env(key, effective_val);
                    }
                }
            }
        }
    }

    // Inject any deep scan corrections for vars NOT in .env.example
    // (e.g. synthesized DATABASE_URL when none was declared)
    {
        let vault_keys: std::collections::HashSet<&str> =
            vault_env.iter().map(|(k, _)| k.as_str()).collect();
        for (key, val) in &scan_result.corrected_env {
            let is_zp_port = key == &assignment.port_var
                || assignment.extra_ports.contains_key(key.as_str());
            if !vault_keys.contains(key.as_str()) && !is_zp_port {
                cmd.env(key, val);
            }
        }
    }

    let spawn_result = cmd.spawn();

    match spawn_result {
        Ok(child) => {
            // Track the PID so we can stop it later
            write_pid_file(&req.name, child.id());
            // Emit port assignment receipt
            let port_event = tool_state::events::port_assigned(&req.name, assignment.port);
            let port_detail = format!("var={}", assignment.port_var);
            tool_chain::emit_tool_receipt(&state.0.audit_store, &port_event, Some(&port_detail));

            // Emit launched receipt into the chain
            let event = tool_chain::ToolEvent::launched(&req.name);
            let launch_detail = format!("cmd={} port={}", full_cmd, assignment.port);
            tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&launch_detail));

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
                                    vname,
                                    verification.delay_secs
                                );
                                let result = onboard::verify::verify_tool_capabilities(
                                    &vname,
                                    vport,
                                    &vmanifest,
                                    &verification,
                                    &vstate.0.audit_store,
                                    Some(&vstate.0.internal_auth),
                                )
                                .await;
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
                Json(serde_json::to_value(ToolLaunchResponse {
                    status: if restarted { "restarting" } else { "starting" }.to_string(),
                    name: req.name.clone(),
                    cmd: full_cmd.clone(),
                    url: proxy_url,
                    raw_url,
                    port: assignment.port,
                    kind: launch.kind.clone(),
                    pid: child.id(),
                    log_path: log_path.display().to_string(),
                }).unwrap_or_default()),
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

// ── Tool registration / unregistration ─────────────────────────────
// POST /api/v1/tools/register inspects a path for ecosystem markers, env
// state, launch profile, and required providers, returning detection JSON
// the dashboard's Add-Tool flow renders. Persistent governance begins when
// vault entries are written via the configure path. POST /api/v1/tools/
// :tool_name/unregister removes all tools/{name}/* entries from the vault.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterToolRequest {
    path: String,
}

async fn tools_register_handler(
    Json(req): Json<RegisterToolRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let raw_path = req.path.trim();
    if raw_path.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "path is required"})),
        );
    }

    // Tilde expansion (the dashboard accepts ~/projects/foo style).
    let expanded = if let Some(stripped) = raw_path.strip_prefix("~/") {
        dirs::home_dir()
            .map(|h| h.join(stripped))
            .unwrap_or_else(|| std::path::PathBuf::from(raw_path))
    } else if raw_path == "~" {
        dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from(raw_path))
    } else {
        std::path::PathBuf::from(raw_path)
    };

    let canonical = match expanded.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Path does not exist: {}", e)})),
            )
        }
    };
    if !canonical.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Path is not a directory"})),
        );
    }

    let name: String = canonical
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    if !is_safe_tool_name(&name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Directory name must be alphanumeric (hyphens, underscores, dots permitted)"
            })),
        );
    }

    // Detection: presence of common ecosystem files.
    let exists = |f: &str| canonical.join(f).exists();
    let docker_compose = exists("docker-compose.yml")
        || exists("docker-compose.yaml")
        || exists("compose.yml")
        || exists("compose.yaml");
    let makefile = exists("Makefile") || exists("makefile");
    let env_example = exists(".env.example");
    let env_present = exists(".env");
    let detection = serde_json::json!({
        "package_json": exists("package.json"),
        "cargo_toml": exists("Cargo.toml"),
        "docker_compose": docker_compose,
        "dockerfile": exists("Dockerfile"),
        "requirements_txt": exists("requirements.txt"),
        "pyproject_toml": exists("pyproject.toml"),
        "go_mod": exists("go.mod"),
        "makefile": makefile,
        "env_example": env_example,
        "env": env_present,
    });

    let ecosystem = if exists("Cargo.toml") {
        "rust"
    } else if exists("go.mod") {
        "go"
    } else if exists("package.json") {
        if exists("pnpm-lock.yaml") {
            "node-pnpm"
        } else if exists("yarn.lock") {
            "node-yarn"
        } else if exists("package-lock.json") {
            "node-npm"
        } else {
            "node"
        }
    } else if exists("pyproject.toml") || exists("requirements.txt") {
        "python"
    } else if exists("Dockerfile") || docker_compose {
        "docker"
    } else {
        "unknown"
    };

    let launch = detect_launch(&canonical);

    // Provider extraction from .env.example via the canonical catalog.
    let mut providers: Vec<String> = Vec::new();
    if env_example {
        if let Ok(content) = std::fs::read_to_string(canonical.join(".env.example")) {
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(eq) = line.find('=') {
                    let key = line[..eq].trim();
                    let key = key.strip_prefix("export ").unwrap_or(key).trim();
                    if let Some(provider) = zp_engine::providers::detect_provider(key) {
                        if seen.insert(provider.clone()) {
                            providers.push(provider);
                        }
                    }
                }
            }
        }
    }

    let status = if env_present && env_example {
        "configured"
    } else if env_present {
        "has_env"
    } else if env_example {
        "unconfigured"
    } else {
        "no_env_template"
    };
    let needs_config = status == "unconfigured";

    // Symlink check on the pre-canonicalized path so we report whether the
    // user's input was a symlink (e.g., something linked into ~/projects/).
    let symlinked = std::fs::symlink_metadata(&expanded)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    info!(
        "Registered tool scan: name={} path={} ecosystem={} status={}",
        name,
        canonical.display(),
        ecosystem,
        status
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tool": {
                "name": name,
                "path": canonical.to_string_lossy(),
                "ecosystem": ecosystem,
                "launch": launch,
                "status": status,
                "needs_config": needs_config,
                "providers": providers,
                "symlinked": symlinked,
            },
            "detection": detection,
        })),
    )
}

async fn tools_unregister_handler(
    State(state): State<AppState>,
    AxumPath(tool_name): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid tool name"})),
        );
    }

    let resolved_key = match state.0.vault_key.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Vault key unavailable"})),
            )
        }
    };

    let vault_path = zp_paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));

    let mut vault = match zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path)
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to load vault: {}", e)})),
            )
        }
    };

    let removed_count = vault.remove_tool(&tool_name);
    if let Err(e) = vault.save(&vault_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to save vault: {}", e)})),
        );
    }

    info!(
        "Unregistered tool '{}' — {} vault entries removed",
        tool_name, removed_count
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "removed": true,
            "tool": tool_name,
            "entries_removed": removed_count,
        })),
    )
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ResolveToolRequest {
    /// Optional absolute path to the tool directory. Defaults to ~/projects/<name>.
    path: Option<String>,
}

/// Resolve a tool's `.env.example` template against the vault.
///
/// Wraps `zp_configure::resolve_tool` — the same orchestration `zp configure
/// tool` uses, but returns structured JSON instead of printing. Writes
/// `tools/{name}/*` entries into the vault, persists, and archives any
/// pre-vault `.env` to `.env.pre-vault`.
async fn tools_resolve_handler(
    State(state): State<AppState>,
    AxumPath(tool_name): AxumPath<String>,
    body: Option<Json<ResolveToolRequest>>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid tool name"})),
        );
    }

    let req = body.map(|Json(r)| r).unwrap_or_default();

    // Resolve tool path. Explicit override from the body, else ~/projects/<name>.
    let tool_path = match req.path.as_deref() {
        Some(p) if !p.trim().is_empty() => {
            let raw = p.trim();
            let expanded = if let Some(stripped) = raw.strip_prefix("~/") {
                dirs::home_dir()
                    .map(|h| h.join(stripped))
                    .unwrap_or_else(|| std::path::PathBuf::from(raw))
            } else {
                std::path::PathBuf::from(raw)
            };
            expanded
        }
        _ => dirs::home_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("projects")
            .join(&tool_name),
    };

    if !tool_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Tool path does not exist: {}", tool_path.display()),
            })),
        );
    }
    if !tool_path.is_dir() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Tool path is not a directory"})),
        );
    }

    let resolved_key = match state.0.vault_key.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Vault key unavailable"})),
            )
        }
    };

    let vault_path = zp_paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));

    let mut vault = match zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path)
    {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to load vault: {}", e)})),
            )
        }
    };

    match zp_configure::resolve_tool(&tool_path, &tool_name, &mut vault, &vault_path) {
        Ok(summary) => {
            info!(
                "Resolved '{}' — refs={}, values={}, unresolved={}",
                summary.tool, summary.refs_stored, summary.values_stored, summary.unresolved,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "resolved": true,
                    "summary": summary,
                })),
            )
        }
        Err(e) => {
            warn!("Resolve failed for '{}': {}", tool_name, e);
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({
                    "resolved": false,
                    "error": e,
                })),
            )
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct CredentialsQuery {
    /// Defaults to "api_key" — the most common credential field.
    field: Option<String>,
}

/// GET /api/v1/credentials/:provider — return a vault-stored provider
/// credential for governed forwarders (the AG-UI proxy in particular).
///
/// Auth-gated like every other /api/v1/* route. The value is returned in the
/// JSON body — there's no plaintext on disk and nothing leaves the localhost
/// boundary unless the operator deliberately remote-binds the server.
async fn credentials_handler(
    State(state): State<AppState>,
    AxumPath(provider): AxumPath<String>,
    Query(q): Query<CredentialsQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if provider.is_empty()
        || provider.contains('/')
        || provider.contains("..")
        || provider.len() > 64
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid provider name"})),
        );
    }
    let field_str = q.field.as_deref().unwrap_or("api_key");
    if field_str.is_empty()
        || field_str.contains('/')
        || field_str.contains("..")
        || field_str.len() > 64
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid field name"})),
        );
    }

    let resolved_key = match state.0.vault_key.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Vault key unavailable"})),
            )
        }
    };
    let vault_path = zp_paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
    let vault = match zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to load vault: {}", e)})),
            )
        }
    };

    let key = format!("providers/{}/{}", provider, field_str);
    match vault.retrieve(&key) {
        Ok(bytes) => {
            let value = String::from_utf8_lossy(&bytes).to_string();
            info!(
                "Credential disclosed: provider={} field={} (length={})",
                provider,
                field_str,
                value.len()
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "provider": provider,
                    "field": field_str,
                    "value": value,
                })),
            )
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Credential not found: {}", key),
            })),
        ),
    }
}

/// Stop a running tool process.
async fn tools_stop_handler(
    State(state): State<AppState>,
    Json(req): Json<LaunchRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // AUTHZ-VULN-09: validate tool name.
    if !is_safe_tool_name(&req.name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid tool name — must be alphanumeric with hyphens/underscores only",
            })),
        );
    }

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
            tool_chain::emit_tool_receipt(&state.0.audit_store, &event, Some(&detail));

            (
                StatusCode::OK,
                Json(serde_json::to_value(ToolStopResponse {
                    status: "stopped".to_string(),
                    name: req.name.clone(),
                    pid: Some(pid),
                    killed: Some(killed),
                    message: None,
                }).unwrap_or_default()),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ToolStopResponse {
                status: "not_running".to_string(),
                name: req.name.clone(),
                pid: None,
                killed: None,
                message: Some(format!("No running process found for '{}'", req.name)),
            }).unwrap_or_default()),
        ),
    }
}

/// Return the last 50 lines of a tool's launch log for diagnostics.
async fn tools_log_handler(
    Query(params): Query<ToolLogQuery>,
) -> Json<ToolLogResponse> {
    let name = match params.name {
        Some(ref n) => n,
        None => return Json(ToolLogResponse {
            name: String::new(),
            log: None,
            lines: None,
            path: None,
            message: Some("Missing 'name' parameter".to_string()),
        }),
    };

    // P2-2: Validate the name before using it to construct a file path.
    // Without this, an attacker could use traversal sequences like
    // "../../etc/passwd" to read arbitrary files.
    if !is_safe_tool_name(name) {
        return Json(ToolLogResponse {
            name: name.clone(),
            log: None,
            lines: None,
            path: None,
            message: Some("Invalid tool name".to_string()),
        });
    }

    let log_path = zp_paths::home()
        .unwrap_or_default()
        .join("logs")
        .join(format!("{}.log", name));

    if !log_path.exists() {
        return Json(ToolLogResponse {
            name: name.clone(),
            log: None,
            lines: None,
            path: None,
            message: Some("No launch log found. Tool may not have been started from the cockpit.".to_string()),
        });
    }

    let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
    let lines: Vec<&str> = contents.lines().collect();
    let tail_n = params.tail.unwrap_or(50).min(200);
    let tail_start = lines.len().saturating_sub(tail_n);
    let tail: String = lines[tail_start..].join("\n");

    Json(ToolLogResponse {
        name: name.clone(),
        log: Some(tail),
        lines: Some(lines.len()),
        path: Some(log_path.display().to_string()),
        message: None,
    })
}

// ── Tool Preflight ──────────────────────────────────────────────────────────

/// Run preflight checks on all configured tools (POST).
/// This pulls docker images, installs deps, fixes permissions, etc.
async fn tools_preflight_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    // Detect which tools have vault-backed config
    let vault = state.0.vault_key.get()
        .and_then(|k| k.as_ref())
        .and_then(|resolved_key| {
            let vault_path = zp_paths::vault_path().unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
            zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path).ok()
        });
    let vault_tools = onboard::preflight::detect_vault_configured_tools(vault.as_ref());

    let (results, _events) = onboard::preflight::run_preflight(
        &scan_path,
        Some(&state.0.audit_store),
        &vault_tools,
        state.0.vault_key.get().and_then(|k| k.as_ref()),
    )
    .await;
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
    // P2-2: Validate tool_name before constructing a directory path.
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid tool name" })),
        );
    }

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

    let vault = state.0.vault_key.get()
        .and_then(|k| k.as_ref())
        .and_then(|resolved_key| {
            let vault_path = zp_paths::vault_path().unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
            zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path).ok()
        });
    let vault_tools = onboard::preflight::detect_vault_configured_tools(vault.as_ref());

    let (results, _events) = onboard::preflight::run_preflight_single(
        &scan_path,
        &tool_name,
        Some(&state.0.audit_store),
        &vault_tools,
        state.0.vault_key.get().and_then(|k| k.as_ref()),
    )
    .await;

    // Extract the single tool's result from the full results vec.
    let tool_result = results
        .tools
        .iter()
        .find(|t| t.name.eq_ignore_ascii_case(&tool_name));

    match tool_result {
        Some(result) => {
            let status = if result.ready {
                StatusCode::OK
            } else {
                StatusCode::CONFLICT
            };
            (
                status,
                Json(serde_json::json!({
                    "tool": result.name,
                    "ready": result.ready,
                    "launch_method": result.launch_method,
                    "checks": result.checks,
                    "auto_fixed": result.auto_fixed,
                })),
            )
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

/// Typed request body for POST /api/v1/tools/:tool_name/configure.
/// Phase 2.8 (P2-4): replaces loose `serde_json::Value` parsing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolConfigureRequest {
    /// The configure action to perform. Currently: "reassign_port".
    action: String,
}

/// Typed request body for POST /api/v1/tools/:tool_name/repair.
/// Phase 2.8 (P2-4): replaces loose `serde_json::Value` parsing.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolRepairRequest {
    /// The repair action to perform. Currently: "restart_compose".
    action: String,
}

/// POST /api/v1/tools/:tool_name/configure
///
/// Actions:
///   - `reassign_port`: Release the tool's current port assignment and
///     let the allocator pick a new one. Useful when a port is in use by
///     another process.
async fn tools_configure_handler(
    State(state): State<AppState>,
    axum::extract::Path(tool_name): axum::extract::Path<String>,
    Json(body): Json<ToolConfigureRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // AUTHZ-VULN-10: validate tool_name to prevent path injection.
    // Tool names must be alphanumeric with hyphens/underscores only.
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid tool name — must be alphanumeric with hyphens/underscores only",
            })),
        );
    }

    let action = body.action.as_str();

    match action {
        "reassign_port" => {
            // Release the old assignment
            state.0.port_allocator.release(&tool_name);

            // Detect the port var and tool path
            let scan_path = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("projects");
            let tool_path = scan_path.join(&tool_name);
            let all_port_vars = tool_ports::detect_all_port_vars(&tool_path);
            let port_var = all_port_vars.first().cloned().unwrap_or_else(|| "PORT".to_string());
            let extra_vars: Vec<String> = all_port_vars.iter().skip(1).cloned().collect();

            // Re-assign to next free port
            match state.0.port_allocator.get_or_assign_multi(&tool_name, &port_var, &extra_vars) {
                Ok(assignment) => {
                    // Re-write .env.zp with new port
                    if tool_path.exists() {
                        if let Err(e) =
                            tool_ports::write_env_zp(&tool_path, &tool_name, &assignment)
                        {
                            tracing::warn!("Failed to write .env.zp for {}: {}", tool_name, e);
                        }
                    }

                    tracing::info!("Reassigned {}: new port {}", tool_name, assignment.port);

                    // P6-1: emit ConfigurationClaim receipt for the port change
                    tool_chain::emit_configuration_receipt(
                        &state.0.audit_store,
                        &tool_name,
                        &port_var,
                        &serde_json::json!(assignment.port),
                        "runtime_change",
                        None,
                    );

                    (
                        StatusCode::OK,
                        Json(serde_json::to_value(ToolConfigureResponse {
                            ok: true,
                            tool: tool_name.clone(),
                            new_port: Some(assignment.port),
                            port_var: Some(port_var.clone()),
                        }).unwrap_or_default()),
                    )
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Port reassignment failed: {}", e),
                    })),
                ),
            }
        }
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Unknown configure action: '{}'", action),
                "valid_actions": ["reassign_port"],
            })),
        ),
    }
}

/// POST /api/v1/tools/:tool_name/repair
///
/// Actions:
///   - `restart_compose`: Restart the tool's Docker Compose stack.
///
/// Phase 1.4 (AUTHZ-VULN-11): removed `fix_docker_network` action which
/// allowed unauthenticated Docker network deletion. Repair now only supports
/// `restart_compose` which is a safe, non-destructive operation.
async fn tools_repair_handler(
    axum::extract::Path(tool_name): axum::extract::Path<String>,
    Json(body): Json<ToolRepairRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // AUTHZ-VULN-11: validate tool_name to prevent command injection.
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid tool name — must be alphanumeric with hyphens/underscores only",
            })),
        );
    }

    let action = body.action.as_str();

    match action {
        "restart_compose" => {
            // Safe restart: `docker compose restart` in the tool's directory.
            // This does NOT modify infrastructure (networks, volumes) —
            // it only restarts the existing containers.
            let scan_path = dirs::home_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("projects");
            let tool_path = scan_path.join(&tool_name);

            if !tool_path.exists() {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": format!("Tool directory not found: {}", tool_name),
                    })),
                );
            }

            let output = std::process::Command::new("docker")
                .args(["compose", "restart"])
                .current_dir(&tool_path)
                .output();

            match output {
                Ok(o) if o.status.success() => {
                    tracing::info!("Restarted Docker Compose for {}", tool_name);
                    (
                        StatusCode::OK,
                        Json(serde_json::to_value(ToolRepairResponse {
                            ok: true,
                            tool: tool_name.clone(),
                            action: "restart_compose".to_string(),
                            hint: Some("Run preflight again to verify the fix.".to_string()),
                        }).unwrap_or_default()),
                    )
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": format!("Docker Compose restart failed: {}", stderr.trim()),
                        })),
                    )
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("docker not available: {}", e),
                    })),
                ),
            }
        }
        // AUTHZ-VULN-11: "fix_docker_network" deliberately removed.
        // Direct network deletion is a destructive infrastructure
        // operation that should not be accessible via API.
        "fix_docker_network" => (
            StatusCode::GONE,
            Json(serde_json::json!({
                "error": "fix_docker_network has been removed for security reasons. Use restart_compose instead.",
                "valid_actions": ["restart_compose"],
            })),
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Unknown repair action: '{}'", action),
                "valid_actions": ["restart_compose"],
            })),
        ),
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
) -> Json<ToolReceiptResponse> {
    let event = format!("tool:{}:{}", body.event, body.name);
    let detail = body.detail.as_deref();

    match tool_chain::emit_tool_receipt(&state.0.audit_store, &event, detail) {
        Some(hash) => Json(ToolReceiptResponse {
            ok: true,
            event: Some(event),
            entry_hash: Some(hash),
            error: None,
        }),
        None => Json(ToolReceiptResponse {
            ok: false,
            event: None,
            entry_hash: None,
            error: Some("Failed to append to audit chain".to_string()),
        }),
    }
}

/// Return tool readiness state derived from the audit chain (GET).
///
/// This is the canonical view — the cockpit can call this to see
/// which lifecycle receipts exist for each tool.
async fn tools_chain_handler(State(state): State<AppState>) -> Json<ToolChainResponse> {
    let chain_state = tool_chain::query_tool_readiness(&state.0.audit_store);
    let tools: Vec<tool_chain::ToolChainState> = chain_state.into_values().collect();
    Json(ToolChainResponse {
        tools,
        source: "audit_chain".to_string(),
    })
}

// ── P6-3: Runtime reconfiguration with receipt chain audit trail ────────

/// Request body for POST /api/v1/tools/:tool_name/reconfigure.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconfigureRequest {
    /// Parameter to reconfigure (must match a ConfigurableParam name)
    parameter: String,
    /// New value to apply
    value: serde_json::Value,
}

/// POST /api/v1/tools/:tool_name/reconfigure
///
/// Reconfigure a tool parameter at runtime. Validates the parameter exists
/// in the tool's manifest, checks allowed_values if specified, emits a
/// ConfigurationClaim receipt with the previous value, and returns the
/// updated configuration.
async fn tools_reconfigure_handler(
    State(state): State<AppState>,
    axum::extract::Path(tool_name): axum::extract::Path<String>,
    Json(body): Json<ReconfigureRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid tool name — must be alphanumeric with hyphens/underscores only",
            })),
        );
    }

    // Locate the tool's manifest to validate the parameter
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");
    let manifest_path = scan_path.join(&tool_name).join(".zp-configure.toml");

    let manifest = match zp_engine::capability::load_manifest(&manifest_path) {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("No manifest found for tool '{}'", tool_name),
                    "hint": "Tool must have a .zp-configure.toml with configurable parameters",
                })),
            );
        }
    };

    // Find the configurable param
    let param = manifest.configurable.iter().find(|p| p.name == body.parameter);
    let param = match param {
        Some(p) => p,
        None => {
            let available: Vec<&str> = manifest.configurable.iter().map(|p| p.name.as_str()).collect();
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Parameter '{}' is not configurable for tool '{}'", body.parameter, tool_name),
                    "available_parameters": available,
                })),
            );
        }
    };

    // Validate allowed_values constraint
    if !param.allowed_values.is_empty() && !param.allowed_values.contains(&body.value) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("Value {:?} not in allowed_values for '{}'", body.value, body.parameter),
                "allowed_values": param.allowed_values,
            })),
        );
    }

    // Query the previous value from the configuration receipt chain
    let existing = tool_chain::query_tool_configuration(&state.0.audit_store, &tool_name);
    let previous = existing
        .iter()
        .find(|r| r.parameter == body.parameter)
        .and_then(|r| r.value.clone());

    // Emit ConfigurationClaim receipt with audit trail
    let entry_hash = tool_chain::emit_configuration_receipt(
        &state.0.audit_store,
        &tool_name,
        &body.parameter,
        &body.value,
        "runtime_change",
        previous.as_ref(),
    );

    // Also broadcast to SSE stream (P4-1)
    let event_name = tool_chain::ToolEvent::capability_configured(&tool_name, &body.parameter);
    {
        let summary = format!("{}.{} = {}", tool_name, body.parameter, body.value);
        let item = crate::events::EventStreamItem::system(&event_name, &summary);
        let _ = state.0.event_tx.send(item);
    }

    tracing::info!(
        "Reconfigured {}.{} = {:?} (was {:?})",
        tool_name,
        body.parameter,
        body.value,
        previous
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "tool": tool_name,
            "parameter": body.parameter,
            "value": body.value,
            "previous_value": previous,
            "entry_hash": entry_hash,
        })),
    )
}

// ── P6-2: Sidecar endpoint — tools query their own configuration receipts ──

/// GET /api/v1/tools/:tool_name/receipts/configured
///
/// Returns all configuration receipts for the given tool, one per parameter
/// (latest value only). Tools call this to discover their own configured
/// parameters without having to parse the audit chain directly.
async fn tools_configured_receipts_handler(
    State(state): State<AppState>,
    axum::extract::Path(tool_name): axum::extract::Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !is_safe_tool_name(&tool_name) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invalid tool name — must be alphanumeric with hyphens/underscores only",
            })),
        );
    }

    let receipts = tool_chain::query_tool_configuration(&state.0.audit_store, &tool_name);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tool": tool_name,
            "parameters": receipts,
            "count": receipts.len(),
        })),
    )
}

// ============================================================================
// Dashboard Handler (Verification Surface)
// ============================================================================

// Embedded fallbacks — used only if the on-disk file is missing.
// ─── Compiled-in assets ─────────────────────────────────────────────────────
// Everything below is baked into the binary at compile time.  No filesystem
// pipeline, no bootstrap, no staleness.  `cargo build && zp serve` just works.

const DASHBOARD_HTML: &str = include_str!("../assets/dashboard.html");
const ONBOARD_HTML: &str = include_str!("../assets/onboard.html");
const SPEAK_HTML: &str = include_str!("../assets/speak.html");
const ECOSYSTEM_HTML: &str = include_str!("../assets/ecosystem.html");

const ONBOARD_CSS: &str = include_str!("../assets/onboard.css");
const ONBOARD_JS: &str = include_str!("../assets/onboard.js");
const TTS_JS: &str = include_str!("../assets/tts.js");
const DASHBOARD_JS: &str = include_str!("../assets/dashboard.js");
const ECOSYSTEM_JS: &str = include_str!("../assets/ecosystem.js");
const SPEAK_JS: &str = include_str!("../assets/speak.js");

const VENDOR_XTERM_JS: &str = include_str!("../assets/vendor/xterm.min.js");
const VENDOR_XTERM_CSS: &str = include_str!("../assets/vendor/xterm.min.css");
const VENDOR_XTERM_FIT_JS: &str = include_str!("../assets/vendor/xterm-addon-fit.min.js");
const VENDOR_D3_JS: &str = include_str!("../assets/vendor/d3.min.js");

const FONTS_CSS: &str = include_str!("../assets/fonts/fonts.css");
const FONT_INTER: &[u8] = include_bytes!("../assets/fonts/inter-latin.woff2");
const FONT_JETBRAINS: &[u8] = include_bytes!("../assets/fonts/jetbrainsmono-latin.woff2");

/// Build a router that serves all assets from compiled-in memory.
/// No filesystem, no bootstrap, no staleness.
fn embedded_assets_router() -> axum::Router {
    use axum::response::IntoResponse;

    fn text_response(body: &'static str, content_type: &'static str) -> Response {
        ([(axum::http::header::CONTENT_TYPE, content_type)], body).into_response()
    }
    fn binary_response(body: &'static [u8], content_type: &'static str) -> Response {
        ([(axum::http::header::CONTENT_TYPE, content_type)], body).into_response()
    }

    axum::Router::new()
        // CSS
        .route("/onboard.css", get(|| async { text_response(ONBOARD_CSS, "text/css; charset=utf-8") }))
        .route("/vendor/xterm.min.css", get(|| async { text_response(VENDOR_XTERM_CSS, "text/css; charset=utf-8") }))
        .route("/fonts/fonts.css", get(|| async { text_response(FONTS_CSS, "text/css; charset=utf-8") }))
        // JS
        .route("/onboard.js", get(|| async { text_response(ONBOARD_JS, "application/javascript; charset=utf-8") }))
        .route("/tts.js", get(|| async { text_response(TTS_JS, "application/javascript; charset=utf-8") }))
        .route("/dashboard.js", get(|| async { text_response(DASHBOARD_JS, "application/javascript; charset=utf-8") }))
        .route("/ecosystem.js", get(|| async { text_response(ECOSYSTEM_JS, "application/javascript; charset=utf-8") }))
        .route("/speak.js", get(|| async { text_response(SPEAK_JS, "application/javascript; charset=utf-8") }))
        .route("/vendor/xterm.min.js", get(|| async { text_response(VENDOR_XTERM_JS, "application/javascript; charset=utf-8") }))
        .route("/vendor/xterm-addon-fit.min.js", get(|| async { text_response(VENDOR_XTERM_FIT_JS, "application/javascript; charset=utf-8") }))
        .route("/vendor/d3.min.js", get(|| async { text_response(VENDOR_D3_JS, "application/javascript; charset=utf-8") }))
        // Fonts
        .route("/fonts/inter-latin.woff2", get(|| async { binary_response(FONT_INTER, "font/woff2") }))
        .route("/fonts/jetbrainsmono-latin.woff2", get(|| async { binary_response(FONT_JETBRAINS, "font/woff2") }))
}

/// Root handler: redirect to /onboard if no genesis ceremony has been completed,
/// otherwise serve the dashboard.
async fn root_handler(State(state): State<AppState>) -> Response {
    let genesis_path = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
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

    // Set the session cookie on page loads so the dashboard's JS can call
    // authenticated API endpoints. The cookie is HttpOnly + SameSite=Strict
    // so it's invisible to JavaScript and immune to CSRF.
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );

    let mut resp = if has_complete_genesis {
        Html(DASHBOARD_HTML)
        .into_response()
    } else {
        // Pre-genesis: redirect to /onboard WITHOUT the setup token.
        // The token is never exposed in redirect headers — the operator
        // must use the full URL from the server console (AUTH-VULN-06).
        Redirect::temporary("/onboard").into_response()
    };
    resp.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

async fn dashboard_handler(State(state): State<AppState>) -> Response {
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(DASHBOARD_HTML).into_response();
    resp.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

/// Query parameters for the onboard page.
#[derive(Debug, Deserialize)]
struct OnboardQuery {
    token: Option<String>,
    /// When `?review=true`, serve onboarding post-genesis as a read-only
    /// reference instead of redirecting to the dashboard.
    review: Option<String>,
}

async fn onboard_page_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<OnboardQuery>,
) -> Response {
    // Post-genesis: redirect to dashboard unless ?review=true (read-only reference mode)
    let review_mode = query.review.as_deref() == Some("true");
    let genesis_path = zp_paths::home()
        .ok()
        .and_then(|h| Some(h.join("genesis.json")))
        .unwrap_or_default();
    if genesis_path.exists() && !review_mode {
        return axum::response::Redirect::to("/dashboard").into_response();
    }

    // AUTH-VULN-06: One-time setup token for network-facing deployments.
    //
    // Token lifecycle:
    //   1. Browser auto-opens `/onboard?token=<hex>` (token in URL once).
    //   2. Server validates, sets `zp_onboard` HttpOnly cookie, redirects
    //      to `/onboard` (strips token from URL bar + browser history).
    //   3. Subsequent page loads + WebSocket upgrades ride the cookie.
    //
    // On localhost (default): onboard_token is None — no gate at all.
    if let Some(ref expected) = state.0.onboard_token {
        let client_ip = client_ip_from_headers(&headers);

        // Rate-limit failed token attempts (reuses the auth rate limiter).
        if let Some(_retry_after) = state.0.rate_limiter.is_blocked(client_ip) {
            return (StatusCode::TOO_MANY_REQUESTS, "Too many attempts").into_response();
        }

        // Accept token from query param OR cookie.
        let from_query = query
            .token
            .as_deref()
            .map(|t| constant_time_eq(t, expected))
            .unwrap_or(false);
        let from_cookie = extract_onboard_cookie(&headers)
            .map(|t| constant_time_eq(&t, expected))
            .unwrap_or(false);

        if from_query {
            // Token in URL — exchange for cookie and redirect to clean URL.
            // This ensures the token never lingers in the URL bar, browser
            // history, or Referrer headers.
            // Path=/ so the cookie reaches both /onboard and /api/onboard/ws.
            let cookie_val = format!(
                "zp_onboard={}; HttpOnly; SameSite=Strict; Path=/",
                expected
            );
            let mut resp = Redirect::temporary("/onboard").into_response();
            if let Ok(hv) = cookie_val.parse() {
                resp.headers_mut().insert(axum::http::header::SET_COOKIE, hv);
            }
            return resp;
        } else if !from_cookie {
            let _ = state.0.rate_limiter.record_failure(client_ip);
            return (
                StatusCode::FORBIDDEN,
                "Setup token required. Check the server console for the onboard URL with token.",
            )
                .into_response();
        }
        // from_cookie == true — fall through to serve the page.
    }

    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );

    let html = ONBOARD_HTML.to_string();

    let mut resp = Html(html).into_response();
    resp.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

async fn speak_page_handler(State(state): State<AppState>) -> Response {
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(SPEAK_HTML).into_response();
    resp.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

async fn ecosystem_page_handler(State(state): State<AppState>) -> Response {
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(ECOSYSTEM_HTML).into_response();
    resp.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie
            .parse()
            .unwrap_or_else(|_| HeaderValue::from_static("")),
    );
    resp
}

// ============================================================================
// Genesis Record Handler
// ============================================================================

async fn genesis_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let genesis_path = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("genesis.json");
    let home = genesis_path.clone();

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
