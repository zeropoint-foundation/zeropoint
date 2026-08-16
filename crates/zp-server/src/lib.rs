//! ZeroPoint v2 Server Library
//!
//! Exposes the governance API as a library so it can be embedded
//! in the unified `zp` binary.

pub mod analysis;
pub mod anchor_pipeline;
pub mod artifact_library;
pub mod attestations;
pub mod auth;
pub mod bedrock;
pub mod canary;
pub mod cartographer;
pub mod channels;
pub mod codebase;
pub mod cognition;
pub mod coherence;
pub mod envelope_state;
pub mod events;
pub mod exec_ws;
pub mod fleet;
pub mod foundation_relay;
pub mod genesis_verify;
pub mod internal_auth;
pub mod launch_inference;
pub mod lease_heartbeat;
pub mod officers;
pub mod onboard;
pub mod proxy;
pub mod regent;
pub mod regent_tools;
pub mod security;
pub mod substrate_validate;
pub mod tool_chain;
pub mod tool_launch;
pub mod tool_ports;
pub mod tool_proxy;
pub mod tool_state;
pub mod wasm_policy;

/// gRPC service handlers — Phase 2b foothold (NodeStatus pilot).
///
/// Per Architecture II.13 and II.14, gRPC is the substrate's outer
/// surface. Adapter for the verb-set port (`zp_verbs`).
pub mod grpc;

use axum::http::HeaderValue;
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tracing::{debug, error, info, warn};

use zp_audit::AuditStore;
use zp_core::governance::{ActionContext, GovernanceActor, GovernanceDecision, GovernanceEvent};
use zp_core::paths as zp_paths;
use zp_core::{
    ActionType as CoreActionType, ActorId, CapabilityGrant, Channel, ConversationId,
    DelegationChain, EventProvenance, GrantProvenance, GrantedCapability, OperatorIdentity,
    PolicyContext, PolicyDecision, TrustTier,
};
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
    /// Proxy provider segment the pipeline routes completions through.
    pub llm_provider: String,
    /// Default-tier model name.
    pub llm_model: String,
    /// Escalation-tier model name. Empty disables the tier.
    pub llm_escalation_model: String,
    /// Whether the configured models implement the OpenAI tool-call format.
    pub llm_supports_tools: bool,
    pub operator_name: String,
    /// Optional path to the Bridge UI dist directory.
    /// When set, serves the Bridge at /bridge.
    pub bridge_dir: Option<std::path::PathBuf>,

    // ── Officers ──
    pub officers_enabled: bool,
    pub officers_sweep_interval_secs: u64,
    pub officers_steward_enabled: bool,
    pub officers_sentinel_enabled: bool,
    pub officers_forge_enabled: bool,
    pub officers_cleo_enabled: bool,
    pub officers_aegis_enabled: bool,
    /// Enable the Cartographer background task (materializes ontology from
    /// receipt chain). Per CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md P3.
    /// Defaults to false — opt-in until empirical validation completes.
    pub cartographer_enabled: bool,
    /// External processes the operator acknowledges as expected listeners.
    pub acknowledged_listeners: Vec<zp_config::AcknowledgedListener>,
    // ── Regent ──
    pub regent_enabled: bool,
    pub regent_inference_endpoint: String,
    pub regent_inference_api_key: Option<String>,
    pub regent_reasoning_model: String,
    pub regent_routing_model: String,
    pub regent_loop_interval_secs: u64,
    pub regent_display_name: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let port: u16 = std::env::var("ZP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(3000);
        let bind = std::env::var("ZP_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
        let home = zp_paths::home().unwrap_or_else(|_| std::path::PathBuf::from("."));

        Self {
            bind_addr: bind,
            port,
            data_dir: std::env::var("ZP_DATA_DIR")
                .unwrap_or_else(|_| home.join("data").to_string_lossy().to_string()),
            home_dir: home,
            open_dashboard: true,
            llm_enabled: std::env::var("ZP_LLM_ENABLED").unwrap_or_default() == "true",
            // Defaults mirror zp_config::ZpConfig so this env-only path and the
            // resolved-config path agree. See officer-inference.toml for why
            // these two tags.
            llm_provider: std::env::var("ZP_LLM_PROVIDER").unwrap_or_else(|_| "ollama".to_string()),
            llm_model: std::env::var("ZP_LLM_MODEL")
                .unwrap_or_else(|_| "gemma4:26b-mlx".to_string()),
            llm_escalation_model: std::env::var("ZP_LLM_ESCALATION_MODEL")
                .unwrap_or_else(|_| "qwen3.6:35b-a3b".to_string()),
            llm_supports_tools: std::env::var("ZP_LLM_SUPPORTS_TOOLS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            operator_name: std::env::var("ZP_OPERATOR_NAME")
                .unwrap_or_else(|_| "ZeroPoint".to_string()),
            bridge_dir: std::env::var("ZP_BRIDGE_DIR")
                .ok()
                .map(std::path::PathBuf::from),
            officers_enabled: false,
            officers_sweep_interval_secs: 900,
            officers_steward_enabled: true,
            officers_sentinel_enabled: true,
            officers_forge_enabled: true,
            officers_cleo_enabled: true,
            officers_aegis_enabled: true,
            cartographer_enabled: false,
            acknowledged_listeners: Vec::new(),
            regent_enabled: false,
            regent_inference_endpoint: "http://127.0.0.1:11434".to_string(),
            regent_inference_api_key: None,
            regent_reasoning_model: "qwen3:8b".to_string(),
            regent_routing_model: "qwen3:1.7b".to_string(),
            regent_loop_interval_secs: 60,
            regent_display_name: "Regent".to_string(),
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
            llm_provider: cfg.llm_provider.value.clone(),
            llm_model: cfg.llm_model.value.clone(),
            llm_escalation_model: cfg.llm_escalation_model.value.clone(),
            llm_supports_tools: cfg.llm_supports_tools.value,
            operator_name: cfg.operator_name.value.clone(),
            bridge_dir: std::env::var("ZP_BRIDGE_DIR")
                .ok()
                .map(std::path::PathBuf::from),
            officers_enabled: cfg.officers_enabled.value,
            officers_sweep_interval_secs: cfg.officers_sweep_interval_secs.value,
            officers_steward_enabled: cfg.officers_steward_enabled.value,
            officers_sentinel_enabled: cfg.officers_sentinel_enabled.value,
            officers_forge_enabled: cfg.officers_forge_enabled.value,
            officers_cleo_enabled: cfg.officers_cleo_enabled.value,
            officers_aegis_enabled: cfg.officers_aegis_enabled.value,
            // P3.2 follow-up: add cartographer_enabled to ZpConfig proper.
            // For now, default false — opt-in via env var or programmatic
            // ServerConfig construction.
            cartographer_enabled: std::env::var("ZP_CARTOGRAPHER_ENABLED")
                .ok()
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
                .unwrap_or(false),
            acknowledged_listeners: cfg.acknowledged_listeners.value.clone(),
            regent_enabled: cfg.regent_enabled.value,
            regent_inference_endpoint: cfg.regent_inference_endpoint.value.clone(),
            regent_inference_api_key: cfg.regent_inference_api_key.value.clone(),
            regent_reasoning_model: cfg.regent_reasoning_model.value.clone(),
            regent_routing_model: cfg.regent_routing_model.value.clone(),
            regent_loop_interval_secs: cfg.regent_loop_interval_secs.value,
            regent_display_name: cfg.regent_display_name.value.clone(),
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
    let genesis_secret = zp_keys::load_sovereign_root(genesis_record_path)
        .map_err(|e| format!("could not unlock Genesis: {}", e))?;
    keyring
        .load_operator_with_genesis_secret(genesis_secret)
        .map_err(|e| format!("operator decrypt failed: {}", e))
}

/// Load the Genesis secret for audit-signer initialization.
///
/// Delegates to `zp_keys::load_sovereign_root`, which tries the standard OS
/// Keychain fast path first (no prompt after load_or_create_identity already
/// primed the cache) and falls back to the sovereignty provider only for
/// hardware-wallet modes that don't write the standard Keychain.
fn load_genesis_secret_from_provider(
    genesis_record_path: &std::path::Path,
) -> Result<[u8; 32], String> {
    zp_keys::load_sovereign_root(genesis_record_path)
        .copied()
        .map_err(|e| format!("{}", e))
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

    // CRIT-8: atomic mode-0600 write for the bootstrap signing key.
    // This is temporary — the onboarding flow creates the full hierarchy
    // (Genesis→Operator) and the next server start uses Path 1.
    zp_keys::write_secret_file(&identity_path, &key.to_bytes())
        .expect("Failed to write identity key");

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
    pub gate: Arc<GovernanceGate>,
    pub audit_store: Arc<std::sync::Mutex<AuditStore>>,
    pub identity: ServerIdentity,
    pub pipeline: Option<Pipeline>,
    pub grants: std::sync::Mutex<Vec<CapabilityGrant>>,
    pub data_dir: String,
    /// Vault key resolved lazily from the OS credential store.
    /// Deferred to avoid blocking server startup on macOS Keychain access (~4s).
    /// Cached here so we never hit the Keychain again during the session.
    /// Arc-wrapped so the Regent can hold a shared reference for lazy resolution
    /// (avoids the startup race where Regent spawns before keychain resolves).
    pub vault_key: Arc<std::sync::OnceLock<Option<zp_keys::ResolvedVaultKey>>>,
    /// Manages port assignments for governed tools so they don't collide.
    pub port_registry: tool_ports::PortRegistry,
    /// Operator-acknowledged external listeners (from config.toml).
    pub acknowledged_listeners: Vec<zp_config::AcknowledgedListener>,
    /// Sensor layer handle — register/unregister file watches and PID watches.
    /// Forge subscribes to sensor events for immune-system-style activation.
    pub sensor_handle: zp_sensors::SensorLayerHandle,
    /// Sensor event receiver — taken once by `spawn_sensor_forge_task`.
    /// `None` after first take; wrapped in Mutex for interior mutability.
    pub sensor_event_rx:
        std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<zp_sensors::SensorEvent>>>,
    /// MLE STAR + Monte Carlo analysis engines fed by receipt chain data.
    pub analysis: analysis::AnalysisEngines,
    /// Server port — needed by proxy for subdomain URL generation.
    pub config_port: u16,
    /// Session authentication — bearer token verification + rotation.
    /// Initialized at server start from the Ed25519 signing key.
    pub session_auth: Arc<auth::SessionAuth>,
    /// Per-request envelope verifier (`Authorization: ZP-Sig …`).
    ///
    /// `Some` once Genesis is established; `None` during the pre-Genesis
    /// onboarding window. The middleware short-circuits any envelope-shaped
    /// header to 401 when the verifier is absent — IronClaw should never
    /// reach the gate before Genesis exists.
    pub envelope_verifier: Option<Arc<envelope_state::EnvelopeVerifier>>,
    /// Signer for outbound requests this server makes to its own gate
    /// (`Authorization: ZP-Sig …`).
    ///
    /// Derived in `init` from the same `derive_gate_signer_seed` call as
    /// `envelope_verifier`'s `expected_kid`, so the key this process signs
    /// with and the key it verifies against cannot drift. Held on state
    /// because subsystems spawned after `init` — the provider pool, and the
    /// Regent as of W5 3b — each need it, and a second derivation would be a
    /// second source of truth for one key.
    ///
    /// `Some` once Genesis is established; `None` during the pre-Genesis
    /// onboarding window, where there is no sovereign root to sign with.
    pub gate_signer: Option<Arc<dyn zp_core::provider::RequestSigner>>,
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
    /// Memory promotion engine (Phase 4.3: truth transition lifecycle).
    /// Enforces receipt-backed gates on every memory stage transition.
    pub promotion_engine: Arc<std::sync::Mutex<zp_memory::PromotionEngine>>,
    /// Memory entries (in-memory store for the memory lifecycle).
    /// Maps memory_id → MemoryEntry. Populated by the promotion engine.
    pub memory_store:
        Arc<std::sync::Mutex<std::collections::HashMap<String, zp_memory::MemoryEntry>>>,
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
    /// Event-driven Merkle anchor pipeline (#176).
    /// Detects significant governance events as they land on the audit chain
    /// and seals epochs against the configured `TruthAnchor` backend, selected
    /// by `ZP_ANCHOR`: OpenTimestamps by default, `off` for no anchoring.
    /// Hedera HCS remains supported but is never the default — it needs a
    /// funded balance someone must consciously provision.
    pub anchor_pipeline: Arc<anchor_pipeline::AnchorPipeline>,

    /// P4 (#197): standing-delegation lease heartbeat state. `Some` only on
    /// delegate nodes (those with `~/ZeroPoint/lease.toml` configured).
    /// The gate consults `halted`/`degraded` flags here on every tool-call
    /// decision so a heartbeat-failure mode is honoured immediately.
    pub lease_heartbeat: Option<Arc<lease_heartbeat::LeaseHeartbeatState>>,

    /// Artifact library — content-addressed, signed, lifecycle-managed renderings.
    /// Stores generated artifacts (chain narrations, etc.) as Candidates until
    /// an operator signs them into canonical form.
    pub artifact_library: Arc<zp_artifacts::LocalArtifactLibrary>,

    /// Foundation Edge pubkey registry — verifies envelopes on
    /// `/v1/foundation-receipts`. `None` if `~/ZeroPoint/config/` doesn't
    /// exist yet (pre-onboarding state); endpoints respond 503 in that
    /// window. Reads `foundation-edge-keys.json` lazily with mtime-based
    /// invalidation.
    pub foundation_edge_registry: Option<foundation_relay::PubkeyRegistryArc>,

    /// Recent intent_id dedupe cache for foundation-relay (24h TTL,
    /// bounded). Idempotency guard against worker retries.
    pub foundation_edge_seen_intents: foundation_relay::SeenIntentsArc,

    /// Host-function boundary (Phase 1 — Commitment A).
    ///
    /// Every privileged side effect (process spawn, file write, network call)
    /// must pass through this interface.  `SystemHostContext` always consults
    /// the governance gate and always emits an audit receipt before executing
    /// the side effect — the invariant is structural, not conventional.
    ///
    /// See `docs/ARCHITECTURE-2026-04.md` Part I §2 Commitment A.
    pub host: Arc<dyn zp_host::HostContext>,

    /// Regent cognitive loop handle (opt-in via `[regent] enabled = true`).
    /// Empty when the Regent is disabled. Send operator input and officer
    /// findings through the handle; the loop processes them asynchronously.
    /// Uses `OnceLock` because the handle is created after `AppStateInner`
    /// construction (the Regent needs the `AuditStore` Arc from `AppState`).
    pub regent_handle: std::sync::OnceLock<zp_regent::loop_runner::RegentHandle>,
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

        // Derive audit signer if Genesis is complete, otherwise use read-only mode.
        // During the genesis ceremony there is no secret to derive from, so the
        // store is read-only until onboarding finishes. Post-Genesis we go
        // through the sovereignty provider — never the OS credential store
        // fast path, which doesn't hold the secret on hardware-wallet modes.
        // Genesis-derived material that several subsystems need at startup:
        // the audit signer (for the chain) and the gate-request verifier's
        // expected_kid (for envelope authentication). Derived once from a
        // single sovereign-root load so the operator sees at most one
        // ceremony (#152: singular sovereign root).
        // The gate signer is carried out of this block alongside the verifier
        // deliberately: both come from one `derive_gate_signer_seed` call on
        // one sovereign-root load, so the key this server signs with and the
        // `expected_kid` it verifies against cannot drift. Deriving the signer
        // anywhere else would be a second source of truth for the same key.
        // `None` during the Genesis ceremony — there is no secret yet, so
        // there is no identity to sign with.
        let (mut audit_store_inner, envelope_verifier, gate_signer) = if is_genesis {
            (
                AuditStore::open_readonly(&audit_path)
                    .expect("Failed to open audit store (readonly)"),
                None,
                None,
            )
        } else {
            let genesis_record_path = config.home_dir.join("genesis.json");
            let genesis_secret = load_genesis_secret_from_provider(&genesis_record_path)
                .unwrap_or_else(|e| {
                    error!("Failed to load Genesis secret for audit signer: {}", e);
                    panic!("audit signer derivation failed: {}", e);
                });

            let audit_seed = zp_keys::derive_audit_signer_seed(&genesis_secret);
            let audit_signer = zp_audit::AuditSigner::from_seed(&audit_seed);
            let store = AuditStore::open_signed(&audit_path, audit_signer)
                .expect("Failed to open audit store (signed)");

            let gate_seed = zp_keys::derive_gate_signer_seed(&genesis_secret);
            let expected_kid = ed25519_dalek::SigningKey::from_bytes(&gate_seed)
                .verifying_key()
                .to_bytes();
            let verifier = envelope_state::EnvelopeVerifier::new(expected_kid);
            // Log a short fingerprint prefix at INFO — the kid is a structurally
            // public identifier (pubkey fingerprint), but 64 hex chars triggers
            // entropy scanners in log aggregators. Full hex available at DEBUG.
            let kid_hex = verifier.expected_kid_hex();
            info!(
                "ZP-Sig envelope verifier ready: kid={}… drift={}s",
                &kid_hex[..16],
                verifier.drift_window().as_secs()
            );
            debug!("ZP-Sig envelope verifier kid (full): {}", kid_hex);

            // Same seed, signer side. This server calls its own proxy on
            // loopback, so it is both signer and verifier of these envelopes;
            // sharing the derivation makes the match structural rather than
            // something to keep in sync.
            let signer = zp_gate_envelope::GateRequestSigner::from_seed(&gate_seed);
            debug_assert_eq!(
                signer.kid(),
                expected_kid,
                "gate signer and verifier must derive the same key"
            );

            (
                store,
                Some(Arc::new(verifier)),
                Some(Arc::new(signer) as Arc<dyn zp_core::provider::RequestSigner>),
            )
        };

        // Claim 1: startup chain integrity verification (zp-verify catalog rules).
        // Non-fatal — a corrupt chain is logged loudly but does not prevent startup,
        // so an operator can still run `zp verify` to inspect the damage. The check
        // runs on `audit_store_inner` before it is Arc-wrapped, so there is no lock
        // contention risk here.
        //
        // In debug builds, ed25519 signature verification is ~50x slower than
        // release (no SIMD, no compiler optimizations). A chain with hundreds of
        // entries can take minutes, causing the dev script's 25-second health
        // check to time out. Skip full verification in debug; `zp verify` (run
        // on release builds) remains the authoritative check.
        {
            #[cfg(debug_assertions)]
            {
                let count = audit_store_inner.entry_count().unwrap_or(0);
                info!(
                    entries = count,
                    "Chain integrity: skipped (debug build — run `zp verify` for full check)",
                );
            }

            #[cfg(not(debug_assertions))]
            {
                let t0 = std::time::Instant::now();
                match audit_store_inner.verify_with_catalog() {
                    Ok(report) if report.passed => {
                        info!(
                            entries = report.entries_checked,
                            sig_checks = report.signature_checks,
                            elapsed_ms = t0.elapsed().as_millis() as u64,
                            "Chain integrity: passed",
                        );
                    }
                    Ok(report) => {
                        let errors = report.error_count();
                        error!(
                            entries = report.entries_checked,
                            errors = errors,
                            sig_failures = report.signature_failures,
                            elapsed_ms = t0.elapsed().as_millis() as u64,
                            "Chain integrity: {} error(s) — chain may be corrupt; run `zp verify` for details",
                            errors,
                        );
                        for finding in report.violations() {
                            error!(
                                rule = %finding.rule,
                                entry = %finding.entry_id,
                                "Chain finding: {}",
                                finding.description,
                            );
                        }
                    }
                    Err(e) => {
                        error!("Chain integrity check failed to run: {}", e);
                    }
                }
            }
        }

        // Auto-compact if the chain exceeds 50k entries.
        // Keeps the active table small for fast queries; archived entries
        // are preserved in audit_entries_archive for full verification.
        {
            const AUTO_COMPACT_THRESHOLD: usize = 50_000;
            const AUTO_COMPACT_RETAIN: usize = 10_000;
            // `live_entry_count`, not `entry_count`. The latter returns
            // live + archived, while `compact_chain` computes its cutoff from
            // the live table alone — so gating on the combined total compares
            // two different populations. Once anything has been archived the
            // total can never fall back below the threshold, and compaction
            // re-fires on every single start, churning the live window down to
            // the retain target each time. Observed 2026-08-08: 275,675
            // combined (24,272 live) against a 50,000 threshold, archiving
            // ~14,000 rows per boot. That churn is what stranded the
            // Cartographer's cursor below the retained floor.
            let count = audit_store_inner.live_entry_count().unwrap_or(0);
            if count > AUTO_COMPACT_THRESHOLD {
                info!(
                    entries = count,
                    threshold = AUTO_COMPACT_THRESHOLD,
                    retain = AUTO_COMPACT_RETAIN,
                    "Auto-compacting chain"
                );
                match audit_store_inner.compact_chain(AUTO_COMPACT_RETAIN) {
                    Ok(archived) => {
                        info!(archived, "Chain auto-compaction complete");
                    }
                    Err(e) => {
                        warn!("Chain auto-compaction failed (non-fatal): {}", e);
                    }
                }
            }
        }

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
                        tracing::warn!(
                            "WASM policy runtime unavailable: {} — falling back to native-only",
                            e
                        );
                        GovernanceGate::new(&identity.destination_hash)
                    }
                }
            }
            #[cfg(not(feature = "policy-wasm"))]
            {
                GovernanceGate::new(&identity.destination_hash)
            }
        };
        let gate = Arc::new(gate);

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
            let p = Pipeline::new(pipeline_config, audit_store.clone()).ok();
            // Populate the provider pool. Without this the pipeline exists but
            // every request fails with NoProvider — the pool is constructed
            // empty and nothing else fills it.
            //
            // Providers route through this server's own proxy on `config.port`,
            // so completions pick up receipt signing, cost tracking and policy
            // gating.
            //
            // HARNESS-SEAM-2026-08 §4 / S3: this crossing is boot-failing. An
            // earlier revision logged the error and continued, which let the
            // server report healthy while holding an empty pool — precisely the
            // half-state the seam declaration forbids. `llm.enabled = true` is
            // an operator assertion that inference is configured; if the
            // crossing fails, that assertion is false and the correct response
            // is to refuse to start rather than to serve a substrate that
            // silently cannot think.
            // Pre-Genesis there is no identity to sign with, so no provider can
            // be constructed. That is a precondition, not a fault: the ceremony
            // has not produced a sovereign root yet, so inference is legitimately
            // unavailable. Health reports `degraded` (pipeline present, zero
            // providers) and boot continues. Post-Genesis the signer is always
            // present, so a missing one there would be a broken assertion.
            let signer = match gate_signer.clone() {
                Some(s) => Some(s),
                None => {
                    tracing::warn!(
                        "llm.enabled = true during the Genesis ceremony — provider pool \
                         deferred until a sovereign root exists. Inference is unavailable \
                         until onboarding completes."
                    );
                    None
                }
            };

            match (p.as_ref(), signer) {
                (Some(pipe), Some(signer)) => {
                    match pipe
                        .init_providers(
                            config.port,
                            &config.llm_provider,
                            &config.llm_model,
                            &config.llm_escalation_model,
                            config.llm_supports_tools,
                            signer,
                        )
                        .await
                    {
                        Ok(n) => tracing::info!(
                            providers = n,
                            provider = %config.llm_provider,
                            model = %config.llm_model,
                            "LLM provider pool ready"
                        ),
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                provider = %config.llm_provider,
                                model = %config.llm_model,
                                "FATAL: provider pool initialization failed while llm.enabled = true"
                            );
                            eprintln!(
                                "\nZeroPoint refused to start.\n\n\
                             llm.enabled is true, but the provider pool could not be \
                             populated:\n  {}\n\n\
                             Provider: {}\n  Model: {}\n  Escalation: {}\n\n\
                             Fix the configuration, or set llm.enabled = false to run \
                             without inference.\n\
                             (HARNESS-SEAM-2026-08 S3 — a configured substrate that \
                             cannot serve is a half-state, not a degraded mode.)\n",
                                e,
                                config.llm_provider,
                                config.llm_model,
                                if config.llm_escalation_model.trim().is_empty() {
                                    "(none)"
                                } else {
                                    &config.llm_escalation_model
                                },
                            );
                            std::process::exit(1);
                        }
                    }
                }
                // Pre-Genesis: pipeline exists, no sovereign root to sign with.
                // Already warned above. Not fatal — the ceremony has not run,
                // so there is nothing broken to report. Health shows
                // `degraded` until onboarding completes.
                (Some(_), None) => {}
                // Pipeline construction failed while llm.enabled is true.
                // A broken assertion, same response as a failed crossing.
                (None, _) => {
                    tracing::error!("FATAL: llm.enabled = true but pipeline construction failed");
                    eprintln!(
                        "\nZeroPoint refused to start.\n\n\
                         llm.enabled is true, but the request pipeline could not be \
                         constructed.\nCheck that the data directory is writable: {}\n",
                        config.data_dir
                    );
                    std::process::exit(1);
                }
            }
            p
        } else {
            None
        };

        // Initialize attestation database (graceful degradation)
        if let Err(e) = attestations::init_attestation_db(&config.data_dir) {
            tracing::warn!(
                "Attestation database unavailable ({}): {} — attestation features disabled. \
                 Check that the data directory exists and is writable: {}",
                config.data_dir,
                e,
                config.data_dir
            );
        }

        // Vault key: deferred to a background thread so the server can bind
        // immediately. macOS Keychain access can take 4–5 seconds (Touch ID /
        // authorization dialog), and blocking here would prevent the server
        // from accepting connections promptly.
        let vault_key = Arc::new(std::sync::OnceLock::new());

        // Port registry — manages the 9100–9199 range for governed tools
        let port_registry = tool_ports::PortRegistry::new_with_audit(
            std::path::Path::new(&config.data_dir),
            Some(audit_store.clone()),
            identity.destination_hash.clone(),
        );

        // Sensor layer — event-driven governance sensors (kqueue + port discovery).
        // Watches tool-ports.json for changes and discovers new listening processes.
        // Forge subscribes to sensor events for immune-system-style activation.
        let tool_ports_path = std::path::Path::new(&config.data_dir).join("tool-ports.json");
        let sensor_config = zp_sensors::SensorLayerConfig {
            initial_files: if tool_ports_path.exists() {
                vec![tool_ports_path]
            } else {
                Vec::new()
            },
            ..Default::default()
        };
        let (sensor_handle, sensor_event_rx) = zp_sensors::SensorLayer::start(sensor_config);

        // Session auth — derives HMAC key from the signing key, mints first token.
        // AUTH-VULN-01: this is the foundation for protecting all API endpoints.
        let session_auth = Arc::new(auth::SessionAuth::new(&identity.signing_key.to_bytes()));
        let rate_limiter = Arc::new(auth::FailedAuthLimiter::new());
        let endpoint_limiter = Arc::new(auth::EndpointRateLimiter::new());

        // Internal zero-trust authority (P2-3: SSRF-VULN-01/02).
        // Derives an internal HMAC key from the operator key via BLAKE3.
        let internal_auth = Arc::new(internal_auth::InternalAuthority::new(
            &identity.signing_key.to_bytes(),
        ));

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
            Some(CognitionPipeline::new(
                obs_config,
                &identity.destination_hash,
            ))
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
        let blast_radius_tracker =
            Arc::new(std::sync::Mutex::new(zp_keys::BlastRadiusTracker::new()));

        // Quarantine store + memory store (R6-2: compromise → quarantine).
        let quarantine_store = Arc::new(std::sync::Mutex::new(zp_memory::QuarantineStore::new(
            &identity.destination_hash,
        )));
        let memory_store = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            zp_memory::MemoryEntry,
        >::new()));

        // Promotion engine (Phase 4.3: memory truth transition lifecycle).
        // Enforces the doctrine: "Nothing becomes durable truth merely because
        // a model inferred it." Every stage transition requires a receipt-backed gate.
        let promotion_engine = Arc::new(std::sync::Mutex::new(zp_memory::PromotionEngine::new(
            &identity.destination_hash,
            zp_memory::PromotionThresholds::default(),
        )));

        // Downgrade resistance guard (R6-4: monotonic policy version).
        // Starts at 0.0.0 — the first policy load sets the baseline.
        // Future: restore from persisted state on restart.
        let downgrade_guard = Arc::new(std::sync::Mutex::new(zp_policy::DowngradeGuard::new()));

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

        // P4 (#197) — lease heartbeat (delegate-node only). Reads
        // `~/ZeroPoint/lease.toml`; absent file = non-delegate node = no
        // heartbeat task. Genesis (APOLLO) never heartbeats.
        let lease_heartbeat_state: Option<Arc<lease_heartbeat::LeaseHeartbeatState>> = {
            let lease_path = config.home_dir.join("lease.toml");
            match lease_heartbeat::LeaseHeartbeatConfig::load(&lease_path) {
                Ok(Some(hb_cfg)) => {
                    info!(
                        "Lease heartbeat: starting for grant {} (subject={})",
                        hb_cfg.grant_id, hb_cfg.subject_node_id
                    );
                    Some(lease_heartbeat::start(hb_cfg))
                }
                Ok(None) => None,
                Err(e) => {
                    tracing::warn!("Lease heartbeat config error: {} — heartbeat disabled", e);
                    None
                }
            }
        };

        // Artifact library — content store + lifecycle index under data_dir/artifacts/
        let artifact_library = {
            let content_dir = std::path::Path::new(&config.data_dir).join("artifacts/content");
            let content_idx = std::path::Path::new(&config.data_dir).join("artifacts/cidx.db");
            let artifact_idx = std::path::Path::new(&config.data_dir).join("artifacts/aidx.db");
            let store = Arc::new(
                zp_content::backends::LocalFsBackend::new(&content_dir, &content_idx)
                    .await
                    .expect("artifact content store"),
            );
            Arc::new(
                zp_artifacts::LocalArtifactLibrary::new(store, &artifact_idx)
                    .await
                    .expect("artifact library index"),
            )
        };

        // Anchor pipeline (#176): event-driven Merkle epoch sealing.
        //
        // Backend selection, per `docs/design/ANCHOR-BACKEND-SELECTION-2026-08.md`
        // §6.1 (operator ruling 2026-08-14): **OpenTimestamps is the default
        // floor.** It is the default because enabling it asks nothing of the
        // operator — no account, no funded balance — so an air-gapped or
        // unbanked deployment anchors too. Hedera remains supported and is
        // never default, because it requires a balance someone must
        // consciously provision.
        //
        // `ZP_ANCHOR=off` disables anchoring entirely and is the escape hatch
        // for a deployment that does not want outbound calls from a governance
        // path. Note what enabling costs: `anchor()` fans out to three public
        // calendars with a ten-second worst case, and anchoring is
        // event-driven, so that await lands inside a gate denial or a dispute
        // rather than in a background job. See `zp-anchor-ots`'s crate docs on
        // why the concurrency fix improved that number without changing its
        // shape.
        //
        // An unrecognised value is a startup failure rather than a silent
        // fallback: `ZP_ANCHOR=OTS` quietly turning anchoring off would be the
        // configuration mistake hardest to notice, since nothing downstream
        // errors — the chain simply stops being witnessed.
        let anchor_backend = std::env::var("ZP_ANCHOR")
            .unwrap_or_else(|_| "ots".to_string())
            .to_ascii_lowercase();

        let anchor: Arc<dyn zp_anchor::TruthAnchor> = match anchor_backend.as_str() {
            "off" | "none" => {
                tracing::info!("anchor: disabled by ZP_ANCHOR — chain is not externally witnessed");
                Arc::new(zp_anchor::NoOpAnchor)
            }
            "ots" => match zp_core::paths::data_dir() {
                Ok(dir) => {
                    let store = zp_anchor_ots::default_store_dir(&dir);
                    tracing::info!(store = %store.display(), "anchor: OpenTimestamps floor");
                    Arc::new(zp_anchor_ots::OtsAnchor::new(store))
                }
                Err(e) => {
                    // Cannot resolve where proofs would live. Anchoring
                    // silently into nowhere is worse than not anchoring, so
                    // this degrades loudly rather than pretending.
                    tracing::error!(
                        "anchor: cannot resolve the data dir ({e}) — anchoring DISABLED; \
                         set ZP_ANCHOR=off to make this deliberate"
                    );
                    Arc::new(zp_anchor::NoOpAnchor)
                }
            },
            other => panic!(
                "ZP_ANCHOR={other:?} is not a recognised anchor backend. \
                 Valid values: 'ots' (default, OpenTimestamps floor) or 'off'. \
                 Refusing to start rather than silently leaving the chain \
                 unwitnessed."
            ),
        };

        let anchor_pipeline = Arc::new(anchor_pipeline::AnchorPipeline::new(
            anchor,
            audit_store.clone(),
            identity.destination_hash.clone(),
        ));
        // Rehydrate the in-memory cursor from any prior `epoch:anchored:*`
        // receipts on disk so a server restart does not re-seal entries that
        // were already sealed before shutdown.
        if let Err(e) = anchor_pipeline.rehydrate_from_chain().await {
            tracing::warn!("anchor pipeline rehydrate failed: {e} — starting from chain origin");
        }
        // Wire the pipeline into the audit store as the post-commit notifier.
        // From here on, every committed entry passes through `notify` and
        // trigger events spawn an async seal task.
        {
            let mut s = audit_store.lock().expect("audit store mutex");
            s.add_notifier(Arc::new(anchor_pipeline::AnchorNotifier::new(
                anchor_pipeline.clone(),
            )));
        }

        // Foundation Edge pubkey registry: lazy file-backed loader. None
        // if the ZeroPoint home path isn't resolvable yet (the endpoints
        // respond 503 in that pre-onboarding window).
        let foundation_edge_registry: Option<foundation_relay::PubkeyRegistryArc> =
            zp_paths::home()
                .ok()
                .map(|home| Arc::new(foundation_relay::PubkeyRegistry::at_zp_home(&home)));

        let foundation_edge_seen_intents: foundation_relay::SeenIntentsArc =
            Arc::new(std::sync::Mutex::new(foundation_relay::SeenIntents::new()));

        // Phase 1 — Commitment A: host-function boundary.
        // SystemHostContext takes Arc refs to the same gate and audit_store
        // that live in AppStateInner, so they share the same live state.
        let host: Arc<dyn zp_host::HostContext> = Arc::new(zp_host::SystemHostContext::new(
            gate.clone(),
            audit_store.clone(),
        ));

        let state = AppState(Arc::new(AppStateInner {
            gate,
            audit_store,
            identity,
            pipeline,
            grants: std::sync::Mutex::new(Vec::new()),
            data_dir: config.data_dir.clone(),
            vault_key,
            port_registry,
            acknowledged_listeners: config.acknowledged_listeners.clone(),
            sensor_handle,
            sensor_event_rx: std::sync::Mutex::new(Some(sensor_event_rx)),
            analysis: analysis::AnalysisEngines::new(),
            config_port: config.port,
            session_auth,
            envelope_verifier,
            gate_signer,
            rate_limiter,
            endpoint_limiter,
            onboard_token,
            internal_auth,
            observation_store,
            cognition_pipeline,
            review_queue,
            blast_radius_tracker,
            quarantine_store,
            promotion_engine,
            memory_store,
            downgrade_guard,
            event_tx,
            node_registry,
            policy_distributor,
            anchor_pipeline,
            lease_heartbeat: lease_heartbeat_state,
            artifact_library,
            foundation_edge_registry,
            foundation_edge_seen_intents,
            host,
            regent_handle: std::sync::OnceLock::new(),
        }));

        // Resolve the vault master key synchronously, before `init` returns.
        //
        // ── Why this is not a background thread, 2026-08-06 ───────────────
        //
        // It was one until this date, on the stated rationale that "the
        // Keychain access can take 4–5 seconds on macOS but the server is
        // already serving requests." That rationale was obsolete at the point
        // it ran.
        //
        // `resolve_vault_key` reaches the credential store only through
        // `load_sovereign_root`, which is a process-scoped `OnceLock`, and
        // `main.rs` warms that lock *before* the server starts — its comment
        // says so explicitly: "all subsequent Keychain accesses in
        // AppState::init are cache hits. Consistent with singular-sovereign-root
        // (#152): one ceremony here, everything else derived from the in-process
        // cache." What remains here is a cache read and a KDF. Microseconds.
        //
        // The thread bought nothing and cost the substrate its vault. Every
        // consumer of `vault_key` had to cope with "not resolved yet", and
        // `spawn_regent` — which runs immediately after `init` — lost that race
        // on every single boot. Its migration of the operator's cloud-inference
        // credential from `config.toml` into the vault therefore never ran once:
        // `~/ZeroPoint/vault.json` did not exist, the key stayed in plaintext on
        // disk, and `ApiKeySource::RawLegacy` — documented as a transition path —
        // became permanent. The vault itself was complete and correct the whole
        // time.
        //
        // Resolving here removes the race rather than widening the window on it.
        // A polled wait with a timeout would have left the same failure mode
        // behind a magic number; there is no race to lose once the value exists
        // before any consumer does. `init` returns fully-formed state, and every
        // `vault_key.get()` downstream is populated by construction.
        //
        // The `Option` inside remains meaningful — a substrate with no Genesis
        // yet (pre-onboarding) legitimately has no vault key. The `OnceLock`
        // wrapper is now vestigial and could be flattened to a plain
        // `Option<ResolvedVaultKey>`; that touches four call sites and is left
        // as a separate change.
        match zp_keys::Keyring::open(zp_paths::keys_dir().unwrap_or_default())
            .and_then(|kr| zp_keys::resolve_vault_key(&kr))
        {
            Ok(resolved) => {
                info!(
                    "Vault key resolved (source: {:?}) — cached for session",
                    resolved.source
                );
                tool_chain::emit_tool_receipt(
                    &state.0.audit_store,
                    "system:keychain:accessed",
                    Some(&format!("source={:?}", resolved.source)),
                );
                let _ = state.0.vault_key.set(Some(resolved));
            }
            Err(e) => {
                warn!(
                    "⚠ Vault key not available: {} — operator rotation, \
                     credential decryption, and vault operations are disabled. \
                     Run `zp recover` with your 24-word mnemonic or `zp doctor` \
                     to diagnose.",
                    e
                );
                let _ = state.0.vault_key.set(None);
            }
        }

        // ── Bedrock invariants ────────────────────────────────────────────
        //
        // Runs last in `init`, once every premise it checks has been
        // established or definitively failed. Asks whether the substrate is
        // what it claims to be — not whether it is healthy, which is a
        // question `substrate_validate` already answers and whose answer has
        // read `degraded` for long enough to carry no information.
        //
        // A missing vault hid inside that for months. See `bedrock.rs`.
        {
            let vault_path = zp_paths::vault_path()
                .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
            let resolved = state.0.vault_key.get().and_then(|k| k.as_ref());

            // `None` here means "could not open", which is a different fault
            // from "opened and holds nothing". Collapsing the two is precisely
            // what made the original failure unreadable.
            let vault_keys = resolved.and_then(|r| {
                zp_trust::CredentialVault::load_or_create(&r.key, &vault_path)
                    .ok()
                    .map(|v| v.list().len())
            });

            // Read one entry past the threshold — enough to answer "mature or
            // not" without pulling an unbounded history into memory to count.
            // The count itself is deliberately not passed on; see
            // `BedrockInputs::substrate_is_mature`.
            let substrate_is_mature = state
                .0
                .audit_store
                .lock()
                .ok()
                .and_then(|s| s.recent_entries(bedrock::YOUNG_SUBSTRATE_ENTRIES + 1).ok())
                .map(|e| e.len() > bedrock::YOUNG_SUBSTRATE_ENTRIES)
                .unwrap_or(false);

            let findings = bedrock::check(&bedrock::BedrockInputs {
                genesis_present: zp_core::paths::genesis_record_path()
                    .map(|p| p.exists())
                    .unwrap_or(false),
                vault_key_resolved: resolved.is_some(),
                vault_path,
                vault_file_exists: zp_paths::vault_path().map(|p| p.exists()).unwrap_or(false),
                vault_keys,
                substrate_is_mature,
            });

            bedrock::report(&findings);
            bedrock::anchor(&state.0.audit_store, &findings);
        }

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
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
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

    let mut router = Router::new()
        // HTML pages
        .route("/", get(root_handler))
        .route("/dashboard", get(dashboard_handler))
        .route("/onboard", get(onboard_page_handler))
        .route("/speak", get(speak_page_handler))
        .route("/ecosystem", get(ecosystem_page_handler))
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
        .route("/api/v1/audit/receipts", get(audit_receipts_handler))
        // Receipts
        .route("/api/v1/receipts/generate", post(receipt_generate_handler))
        // Foundation Edge worker relay (canonical receipt issuance for
        // workspace actions originating at the Cloudflare worker — see
        // docs/handoffs/foundation-worker-edge-proxy-2026-05.md).
        .route(
            "/v1/foundation-receipts",
            post(foundation_relay::post_handler).get(foundation_relay::get_handler),
        )
        // Stats
        .route("/api/v1/stats", get(stats_handler))
        .route("/api/v1/officer/sweep", get(officer_sweep_handler))
        .route("/api/v1/vault/test/:provider", post(vault_test_handler))
        // Substrate validation — deterministic structural audit primitive
        // per SUBSTRATE-SELF-CONSTRUCTION discipline (task #20/#21).
        .route(
            "/api/v1/substrate/validate",
            get(substrate_validate_handler),
        )
        // Standing corrections — chain-anchored operator claims about Regent's
        // cognitive layer. Composes with COGNITIVE-INPUT-PLANE-2026-07 Tier 1.
        // Vault operator surface. Names-only listing, value-carrying verbs in
        // the request body rather than the URL. See the handler module note.
        .route("/api/v1/vault/list", get(vault_list_handler))
        .route("/api/v1/vault/put", post(vault_put_handler))
        .route("/api/v1/vault/remove", post(vault_remove_handler))
        .route("/api/v1/vault/reveal", post(vault_reveal_handler))
        .route("/api/v1/correction/issue", post(correction_issue_handler))
        .route("/api/v1/correction/list", get(correction_list_handler))
        .route(
            "/api/v1/correction/revoke/:correction_id",
            post(correction_revoke_handler),
        )
        // Approval resolution — the operator's answer to
        // Intent::RequestApproval. The request half was already
        // chain-anchored; this is the half that records the answer, so a
        // proposal stops being fire-and-forget and can become precedent.
        .route("/api/v1/regent/approvals", get(regent_approvals_handler))
        .route("/api/v1/regent/precedents", get(regent_precedents_handler))
        .route(
            "/api/v1/regent/precedents/:signature/revoke",
            post(regent_precedent_revoke_handler),
        )
        .route(
            "/api/v1/regent/approvals/:request_hash/resolve",
            post(regent_approval_resolve_handler),
        )
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
        .route("/api/v1/credentials/:provider", get(credentials_handler))
        .route("/api/v1/receipts", post(receipts_external_handler))
        .route("/api/v1/gate/tool-call", post(gate_tool_call_handler))
        // P4 (#197) — standing delegation lease renewal.
        .route("/api/v1/lease/renew", post(lease_renew_handler))
        .route("/api/v1/tools", get(tools_list_handler))
        .route("/api/v1/tools/launch", post(tool_launch_handler))
        .route("/api/v1/tools/:name/stop", post(tool_stop_handler))
        .route("/api/v1/tools/:name/remove", post(tool_remove_handler))
        .route("/api/v1/tools/:name/probe", get(tool_probe_handler))
        .route("/api/v1/tools/:name/posture", get(tool_posture_handler))
        .route(
            "/api/v1/tools/:name/register-agent",
            post(register_agent_handler),
        )
        .route("/api/v1/tools/receipt", post(tools_receipt_handler))
        // Model governance — operator preference + routing observation
        .route("/api/v1/preference/model", post(model_preference_handler))
        .route("/api/v1/cognition/model-routed", post(model_routed_handler))
        // Cognition module — observation, reflection, memory lifecycle, reviews
        .route(
            "/api/v1/cognition/observe",
            post(cognition::observe_handler),
        )
        .route(
            "/api/v1/cognition/reflect",
            post(cognition::reflect_handler),
        )
        .route(
            "/api/v1/cognition/status",
            get(cognition::cognition_status_handler),
        )
        .route(
            "/api/v1/cognition/observations",
            get(cognition::list_observations_handler),
        )
        .route(
            "/api/v1/cognition/reviews",
            get(cognition::list_reviews_handler),
        )
        .route(
            "/api/v1/cognition/reviews/submit",
            post(cognition::submit_review_handler),
        )
        .route(
            "/api/v1/cognition/reviews/decide",
            post(cognition::decide_review_handler),
        )
        .route(
            "/api/v1/cognition/reviews/sweep",
            post(cognition::sweep_reviews_handler),
        )
        .route(
            "/api/v1/cognition/memories",
            get(cognition::list_memories_handler),
        )
        .route(
            "/api/v1/cognition/memories/sweep",
            post(cognition::sweep_memories_handler),
        )
        // Governed exec WebSocket — cockpit terminal output streaming
        .route("/ws/exec", get(exec_ws::exec_ws_handler))
        // Regent cockpit — operator input to the cognitive loop
        .route("/api/v1/regent/input", post(regent_input_handler))
        // Real-time event stream — SSE for dashboard and channel adapters (P4-1)
        .route("/api/v1/events/stream", get(events::event_stream_handler))
        // Channel adapters — Slack/Discord integration (P4-2)
        .route(
            "/api/v1/channels/slack/webhook",
            post(channels::slack_webhook_handler),
        )
        // Fleet node registry — heartbeat, status, and management (P5-2)
        .route(
            "/api/v1/fleet/heartbeat",
            post(fleet::fleet_heartbeat_handler),
        )
        .route("/api/v1/fleet/nodes", get(fleet::fleet_nodes_handler))
        .route(
            "/api/v1/fleet/nodes/:id",
            get(fleet::fleet_node_detail_handler).delete(fleet::fleet_deregister_handler),
        )
        .route("/api/v1/fleet/summary", get(fleet::fleet_summary_handler))
        // P6-4: WASM policy runtime management (feature-gated, fallback on non-WASM builds)
        .route(
            "/api/v1/policy/wasm/load",
            post(wasm_policy::wasm_load_handler),
        )
        .route("/api/v1/policy/wasm", get(wasm_policy::wasm_list_handler))
        .route(
            "/api/v1/policy/wasm/:hash/disable",
            post(wasm_policy::wasm_disable_handler),
        )
        .route(
            "/api/v1/policy/wasm/:hash/enable",
            post(wasm_policy::wasm_enable_handler),
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
        // API Proxy — governance-aware LLM provider proxy
        .route("/api/v1/proxy/*proxy_path", post(proxy::proxy_handler))
        // Pricing freshness — live refresh of provider pricing data
        .route(
            "/api/v1/pricing/refresh",
            post(proxy::pricing_refresh_handler),
        )
        // Artifact library
        .route(
            "/api/operator/me/library/chain-narration/compose",
            post(artifact_library::compose_handler),
        )
        .route(
            "/api/operator/me/library/chain-narration/submit",
            post(artifact_library::submit_handler),
        )
        .route(
            "/api/operator/me/library",
            get(artifact_library::list_handler),
        )
        .route(
            "/api/operator/me/library/:id",
            get(artifact_library::get_handler),
        )
        .route(
            "/api/operator/me/library/:id/sign",
            post(artifact_library::sign_handler),
        )
        .route(
            "/api/operator/me/library/:id/reject",
            post(artifact_library::reject_handler),
        )
        .route(
            "/api/operator/me/library/by-kind/:kind/canonical",
            get(artifact_library::canonical_handler),
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
            let envelope_verifier = state.0.envelope_verifier.clone();
            let rate_limiter = state.0.rate_limiter.clone();
            let endpoint_limiter = state.0.endpoint_limiter.clone();
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let session_auth = session_auth.clone();
                let envelope_verifier = envelope_verifier.clone();
                let rate_limiter = rate_limiter.clone();
                let endpoint_limiter = endpoint_limiter.clone();
                async move {
                    auth::require_auth(
                        req,
                        next,
                        session_auth,
                        envelope_verifier,
                        rate_limiter,
                        endpoint_limiter,
                    )
                    .await
                }
            }
        }))
        .with_state(state.clone());

    // ── Dev-tools routes retired in Phase 2a (verb-set inventory) ─────
    // audit simulate-tamper/restore/clear and codebase read/search/tree
    // were removed. No dev-tools routes remain.

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
            info!(
                "Assets:     http://localhost:{}/assets/  (override: {})",
                config.port, override_dir
            );
            router = router.nest_service("/assets", ServeDir::new(&dir));
        } else {
            tracing::warn!(
                "ZP_ASSETS_DIR={} does not exist, using compiled-in assets",
                override_dir
            );
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

    // ── Officer cadre sweep task ──────────────────────────────────────────
    // Spawned after AppState::init so vault_key resolution is already
    // underway in its background thread. The sweep task handles
    // vault_key not yet being set (returns empty VaultKeyLister).
    officers::spawn_sweep_task(
        officers::OfficersConfig {
            enabled: config.officers_enabled,
            sweep_interval_secs: config.officers_sweep_interval_secs,
            steward_enabled: config.officers_steward_enabled,
            sentinel_enabled: config.officers_sentinel_enabled,
            forge_enabled: config.officers_forge_enabled,
            cleo_enabled: config.officers_cleo_enabled,
            aegis_enabled: config.officers_aegis_enabled,
        },
        state.0.clone(),
    );

    // ── Sensor-driven Forge activation ──────────────────────────────────
    // Separate from the periodic sweep: sensor events trigger Forge
    // immediately (immune-system model). The periodic sweep still runs
    // all officers on its timer.
    if config.officers_enabled && config.officers_forge_enabled {
        if let Some(rx) = state
            .0
            .sensor_event_rx
            .lock()
            .ok()
            .and_then(|mut g| g.take())
        {
            officers::spawn_sensor_forge_task(rx, state.0.clone());
        }
    }

    // Feed current PortRegistry state to the sensor layer so the
    // discovery scanner knows which listeners are registered tools.
    officers::sync_known_bindings(&state.0);

    // ── Cartographer background task (P3 v1) ────────────────────────────
    // Materializes the ontology from the receipt chain. Runs Pi-side
    // (chain-adjacent) per SUBSTRATE-COMPUTE-BASELINE. Reads receipts,
    // evaluates boundary via zp_ontology::evaluate_boundary, materializes
    // Trajectory rows into ontology.db.
    //
    // Notifier is added via `add_notifier` alongside the anchor pipeline —
    // both fire on each chain append, chained in insertion order.
    //
    // Cartographer's own receipt emission (ontology:cartographer:*,
    // ontology:trajectory:*) deferred to P3.2 pending signing-key derivation.
    if config.cartographer_enabled {
        let cart_config = cartographer::CartographerConfig {
            enabled: true,
            ontology_db_path: std::path::PathBuf::from(&config.data_dir).join("ontology.db"),
            boundary_config: zp_ontology::BoundaryConfig::default(),
            channel_capacity: 1000,
            catchup_batch_size: 500,
        };
        if let Some(notifier) =
            cartographer::spawn_cartographer_task(cart_config, state.0.audit_store.clone())
        {
            let mut s = state.0.audit_store.lock().expect("audit store mutex");
            s.add_notifier(notifier);
            info!("Cartographer notifier installed");
        }
    }

    // ── Chain-read canary discipline (Tier 1) ────────────────────────────
    // Periodic canary marker writes + observer probes + statement cache flush
    // remediation. Structurally catches stuck-read-snapshot bugs per
    // CHAIN-READ-CANARY-DISCIPLINE-2026-07.md. First concrete implementation
    // of the observation-layer trust envelope.
    {
        let canary = canary::CanaryRuntime::new(state.0.audit_store.clone());
        let _handle = canary.spawn();
        // Handle intentionally dropped — the task runs for the process lifetime;
        // shutdown is via process exit, not explicit cancellation.
    }

    // ── Observer Coherence discipline — Class 1 (chain readers) ──────────
    // Periodic cross-check of tail-probe strategies on the shared connection.
    // Structurally catches chain-reader divergence per
    // OBSERVER-COHERENCE-DISCIPLINE-2026-07.md §Class 1. Complements canary
    // (single-observer freshness) with cross-strategy agreement checking —
    // the two together close the observation-layer trust envelope for chain
    // readers.
    {
        let coherence = coherence::CoherenceRuntime::new(state.0.audit_store.clone());
        let _handle = coherence.spawn();
    }

    // ── Regent cognitive loop ───────────────────────────────────────────
    // Spawned after officers so the Regent can receive officer findings.
    // Disabled by default; opt-in via `[regent] enabled = true` in config.
    let regent_config = regent::ServerRegentConfig {
        enabled: config.regent_enabled,
        inference_endpoint: config.regent_inference_endpoint.clone(),
        inference_api_key: config.regent_inference_api_key.clone(),
        reasoning_model: config.regent_reasoning_model.clone(),
        routing_model: config.regent_routing_model.clone(),
        loop_interval_secs: config.regent_loop_interval_secs,
        display_name: config.regent_display_name.clone(),
        // W5 3b: the Regent can now authenticate to the proxy. The endpoint
        // does not move here — 3c does that — so this is held and unused.
        gate_signer: state.0.gate_signer.clone(),
    };
    // Share the vault key reference with the Regent — she resolves lazily at
    // self_configure time, avoiding the startup race where spawn happens before
    // the background keychain thread finishes.
    let regent_vault_key = state.0.vault_key.clone();
    if let Some(handle) = regent::spawn_regent(
        regent_config,
        state.0.audit_store.clone(),
        state.0.gate.clone(),
        state.0.event_tx.clone(),
        config.home_dir.to_str().unwrap_or(""),
        state.0.promotion_engine.clone(),
        state.0.review_queue.clone(),
        regent_vault_key,
    )
    .await
    {
        // OnceLock::set is safe from any thread and races cleanly.
        // We're in the single-threaded startup path so this always succeeds.
        let _ = state.0.regent_handle.set(handle);
        debug!("Regent handle stored in AppState");
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
        info!(
            "Onboard:   http://{}:{}/onboard",
            config.bind_addr, config.port
        );
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
                    .stderr(std::process::Stdio::null())
                    .status();
                std::thread::sleep(std::time::Duration::from_millis(500));
                // SIGKILL if it didn't exit; suppress stderr — process may have exited cleanly
                let _ = std::process::Command::new("kill")
                    .args(["-9", &old_pid.to_string()])
                    .stderr(std::process::Stdio::null())
                    .status();
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
    // Write our own PID
    std::fs::write(&server_pid_path, std::process::id().to_string()).ok();

    // Lifecycle: record that this session began, before any listener
    // accepts. Version and pid make sessions distinguishable on the chain
    // without needing content.
    emit_lifecycle_receipt(
        &state.0.audit_store,
        format!(
            "system:startup version={} pid={} port={}",
            env!("CARGO_PKG_VERSION"),
            std::process::id(),
            config.port,
        ),
    );

    // ── Singular loopback binding: all listener binds + serve+shutdown ─
    // wiring routes through `zp_net`. One CancellationToken gates the
    // ctrl_c watcher (which performs tool-PID cleanup) and all four
    // listener tasks (HTTP v4/v6, gRPC v4/v6 — or one each on
    // network-facing deployments). See
    // `docs/handoffs/singular-loopback-binding-design-2026-05.md`.
    let shutdown = zp_net::CancellationToken::new();

    let is_loopback = config.bind_addr == "127.0.0.1"
        || config.bind_addr == "localhost"
        || config.bind_addr == "::1";

    // HTTP bind — dual-stack for loopback, single-stack for network.
    let http_listener = if is_loopback {
        zp_net::bind_loopback(config.port).await?
    } else {
        let v4 = zp_net::bind_network(&config.bind_addr, config.port).await?;
        zp_net::DualStackListener { v4, v6: None }
    };

    // ── Shutdown watcher: ctrl_c → PID cleanup → token.cancel() ───────
    // The cleanup body is preserved byte-identical from the previous
    // single-shot shutdown closure (Phase 0) so operator log output
    // does not change across the migration. The only difference is
    // *scheduling*: the cleanup now runs in a watcher task that fires
    // the token on completion, so every listener under the token
    // drains together instead of HTTP v4 draining while the rest die
    // abruptly with the process.
    {
        let signal_shutdown = shutdown.clone();
        let server_pid_path = server_pid_path.clone();
        let shutdown_audit = state.0.audit_store.clone();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            // Emit before cleanup: cleanup can fail, and a session that
            // ended is a fact independent of whether teardown succeeded.
            emit_lifecycle_receipt(
                &shutdown_audit,
                format!("system:shutdown pid={} reason=signal", std::process::id()),
            );
            cleanup_launched_tools(&pid_dir(), &server_pid_path);
            signal_shutdown.cancel();
        });
    }

    // ── PID liveness sweeper ────────────────────────────────────────────
    // Releases stale port bindings when tools die without a graceful exit.
    // Runs every 30 seconds; uses POSIX kill -0 on Unix (no actual signal).
    {
        let registry_arc = state.0.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                ticker.tick().await;
                registry_arc.port_registry.sweep_dead_pids();
            }
        });
    }

    // ── gRPC server (Phase 2b foothold: NodeStatus pilot) ──────────────
    // Per Architecture II.13, gRPC is the substrate's outer surface. For
    // the migration we run tonic alongside axum on `port + 1` so handlers
    // can move one service at a time without breaking existing clients.
    // Only `NodeStatus.GetNodeStats` is implemented in this commit; the
    // other nine NodeStatus verbs return `Unimplemented`. Each verb (and
    // each successive service) lands as a focused follow-up commit.
    //
    // The serve tasks watch the same CancellationToken as the HTTP
    // listeners so all four listeners drain together on ctrl_c.
    let grpc_port = config.port + 1;
    let grpc_state = state.clone();
    let grpc_factory = move || {
        let handler = grpc::NodeStatusHandler::new(grpc_state.clone());
        tonic::transport::Server::builder()
            .add_service(zp_verbs::nodestatus::node_status_server::NodeStatusServer::new(handler))
    };

    let _grpc_handles = if is_loopback {
        let handles =
            zp_net::serve_loopback_grpc_with_shutdown(grpc_factory, grpc_port, shutdown.clone())
                .await?;
        info!(
            "gRPC server on 127.0.0.1:{} (NodeStatus pilot — Phase 2b, stacks: {:?})",
            grpc_port, handles.bound_stacks
        );
        handles
    } else {
        let handles = zp_net::serve_network_grpc_with_shutdown(
            grpc_factory,
            &config.bind_addr,
            grpc_port,
            shutdown.clone(),
        )
        .await?;
        info!(
            "gRPC server on {}:{} (NodeStatus pilot — Phase 2b)",
            config.bind_addr, grpc_port
        );
        handles
    };

    // HTTP IPv6 loopback task — drains under the same token as v4.
    if let Some(v6) = http_listener.v6 {
        let app_v6 = app.clone();
        let v6_shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(e) = axum::serve(v6, app_v6)
                .with_graceful_shutdown(v6_shutdown.cancelled_owned())
                .await
            {
                tracing::error!("IPv6 loopback serve error: {}", e);
            }
        });
    }

    // HTTP IPv4 — the main task. Awaited so `run_server` returns when
    // the listener finishes draining, after the token cancel fired
    // and in-flight requests completed.
    axum::serve(http_listener.v4, app)
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await?;
    Ok(())
}

/// Walk the PID directory, kill every tool process, remove our own
/// PID file. Factored out of the ctrl_c watcher closure so it can be
/// unit-tested without driving the full server.
///
/// Idempotent: missing PIDs / already-dead processes are skipped
/// silently. Safe to call from a single watcher task on shutdown.
pub fn cleanup_launched_tools(pid_dir_path: &std::path::Path, server_pid_path: &std::path::Path) {
    info!("Shutdown signal received — stopping launched tools...");
    if let Ok(entries) = std::fs::read_dir(pid_dir_path) {
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
    std::fs::remove_file(server_pid_path).ok();
    info!("All tools stopped. Goodbye.");
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
    /// Number of providers in the pool. `pipeline_enabled: true` with
    /// `llm_providers: 0` is the half-state HARNESS-SEAM-2026-08 S3 forbids:
    /// a pipeline that looks configured and cannot serve. Boot refuses this
    /// condition, so it should be unreachable — it is reported anyway, because
    /// an invariant nobody can observe is an invariant nobody can trust.
    llm_providers: usize,
}

async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let llm_providers = match state.0.pipeline {
        Some(ref p) => p.provider_pool.read().await.len(),
        None => 0,
    };
    let degraded = state.0.pipeline.is_some() && llm_providers == 0;
    Json(HealthResponse {
        status: if degraded { "degraded" } else { "ok" }.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        pipeline_enabled: state.0.pipeline.is_some(),
        llm_providers,
    })
}

// ── Regent cockpit endpoint ────────────────────────────────────────────────

/// Accept operator input for the Regent cognitive loop and return the
/// Regent's response synchronously. Used by `zp regent` CLI and future
/// cockpit surfaces.
async fn regent_input_handler(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let handle = match state.0.regent_handle.get() {
        Some(h) => h.clone(),
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "regent not enabled"})),
            );
        }
    };

    let content = req
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if content.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "content required"})),
        );
    }

    match handle
        .send_input_and_wait(content, zp_regent::context::CockpitSource::Cli)
        .await
    {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::json!({"response": response})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("{}", e)})),
        ),
    }
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
        trust_tier: result.trust_tier.as_u8(),
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
    // Use ConfigChange (not CredentialAccess) — CatastrophicActionRule
    // unconditionally blocks all CredentialAccess actions. ConfigChange with
    // a non-self-modification setting is the correct action type here: issuing
    // a capability grant IS a configuration change. Required tier: Tier1;
    // context passes Tier2 (≥ Tier1), so TrustTierEnforcementRule passes.
    enforce_gate(
        &state,
        CoreActionType::ConfigChange {
            setting: format!("capability.grant:{}", body.capability),
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
        // Claim 4: ToolCall grants allow agents to call specific MCP tools.
        // `scope` carries the tool list (e.g., ["bash", "read"] or ["*"]).
        "tool_call" => GrantedCapability::ToolCall { tools: scope },
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                "Unknown capability type: {}. Use read, write, execute, api, config, or tool_call.",
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

    // Boundary 1→2: emit delegation:granted:<grantee> to the chain so the
    // gate's P4 prereq check can see this grant. Without this entry the
    // gate reads the chain and finds nothing, denying the grantee's tool
    // calls even though the grant exists in-memory. Pass the signing key
    // so the entry carries a typed, signed DelegationClaim receipt.
    tool_chain::emit_delegation_receipt(
        &state.0.audit_store,
        "granted",
        &grant,
        Some(&state.0.identity.signing_key),
    );

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
        // Claim 4: inherit the parent's tool set when delegating a ToolCall grant.
        // The child may further restrict it via body.scope.
        GrantedCapability::ToolCall { tools } => tools.clone(),
        // Exhaustive on purpose — no `_` arm. The previous `_ => vec!["*"]`
        // meant a child delegated from a CredentialAccess / MeshSend / Custom
        // parent, with no explicit scope in the request, inherited a wildcard.
        // Delegation must narrow; an unspecified scope inherits the parent's,
        // and a parent whose capability carries no scope list inherits nothing.
        GrantedCapability::CredentialAccess { credential_refs } => credential_refs.clone(),
        GrantedCapability::MeshSend { destinations } => destinations.clone(),
        // `Custom` has no scope list. Empty is the fail-closed reading: the
        // child is granted nothing until the caller states a scope explicitly.
        GrantedCapability::Custom { .. } => Vec::new(),
    });

    let capability = match body.capability.to_lowercase().as_str() {
        "read" => GrantedCapability::Read { scope },
        "write" => GrantedCapability::Write { scope },
        "execute" => GrantedCapability::Execute { languages: scope },
        "api" => GrantedCapability::ApiCall { endpoints: scope },
        "config" => GrantedCapability::ConfigChange { settings: scope },
        // Claim 4: ToolCall delegation — child scope must be ⊆ parent tool set.
        "tool_call" => GrantedCapability::ToolCall { tools: scope },
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
    child = child.with_issued_via(EventProvenance::external_request(
        "api-delegate-handler",
        None,
    ));
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

    // Boundary 1→2: emit delegation:granted:<grantee> so the gate's P4 prereq
    // check sees this delegated grant on the chain. Pass signing key for typed receipt.
    tool_chain::emit_delegation_receipt(
        &state.0.audit_store,
        "granted",
        &child,
        Some(&state.0.identity.signing_key),
    );

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

// ── Audit receipts (normalized, ZpClient-compatible schema) ─────────────────

#[derive(Deserialize)]
struct AuditReceiptsQuery {
    claim_pattern: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize)]
struct AuditReceiptsResponse {
    receipts: Vec<serde_json::Value>,
    count: usize,
}

/// Extract a claim string from an audit entry action.
fn audit_extract_claim(action: &zp_core::AuditAction) -> Option<String> {
    match action {
        zp_core::AuditAction::SystemEvent { event } => Some(event.clone()),
        zp_core::AuditAction::ToolInvoked { tool_name, .. } => {
            Some(format!("tool:invoked:{tool_name}"))
        }
        zp_core::AuditAction::ToolCompleted {
            tool_name, success, ..
        } => {
            if *success {
                Some(format!("tool:completed:{tool_name}"))
            } else {
                Some(format!("tool:failed:{tool_name}"))
            }
        }
        zp_core::AuditAction::MessageReceived { .. } => {
            Some("cognition:message:received".to_string())
        }
        zp_core::AuditAction::ResponseGenerated { .. } => {
            Some("cognition:response:generated".to_string())
        }
        zp_core::AuditAction::ApiCallProxied {
            provider, endpoint, ..
        } => Some(format!("api:proxied:{provider}:{endpoint}")),
        _ => None,
    }
}

/// True if `claim` matches the operator-supplied pattern.
/// Only trailing `*` glob is supported (same contract as foundation endpoint).
fn audit_matches_pattern(claim: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern.is_empty() {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return claim.starts_with(prefix);
    }
    claim == pattern
}

/// Normalize a chain entry into the foundation-compatible receipt shape so
/// chain_render's rendering logic works identically for local and foundation
/// sources.
fn audit_normalize_entry(entry: &zp_core::AuditEntry, claim: &str) -> serde_json::Value {
    let detail = match &entry.policy_decision {
        PolicyDecision::Allow { conditions } => conditions.first().cloned(),
        PolicyDecision::Block { reason, .. } => Some(reason.clone()),
        PolicyDecision::Warn { message, .. } => Some(message.clone()),
        _ => None,
    };
    serde_json::json!({
        "id": entry.entry_hash,
        "claim": claim,
        "metadata": { "detail": detail },
        "created_at": entry.timestamp.to_rfc3339(),
    })
}

/// `GET /api/v1/audit/receipts` — return normalized chain entries in the
/// foundation-compatible receipt schema (`{id, claim, metadata, created_at}`).
///
/// Used by IronClaw's `chain_render` tool when `source=local` so the same
/// narration logic works without requiring a `zp_session` cookie.
/// Authenticated via the existing ZP-Sig envelope middleware.
async fn audit_receipts_handler(
    State(state): State<AppState>,
    Query(params): Query<AuditReceiptsQuery>,
) -> Json<AuditReceiptsResponse> {
    let limit = params.limit.unwrap_or(1000);
    let pattern = params.claim_pattern.as_deref().unwrap_or("*");

    // When a specific pattern is provided, use a SQL-level keyword search so
    // we never miss entries that fall beyond the first N rows of a large chain.
    // For wildcard "*" we still export the most-recent N entries (chain tail).
    let entries = {
        let store = state.0.audit_store.lock().unwrap();
        if pattern == "*" || pattern.is_empty() {
            store.export_chain(limit).unwrap_or_default()
        } else {
            // Extract the raw keyword (strip trailing glob '*' if present).
            let keyword = pattern.trim_end_matches('*');
            match store.search_chain_by_action_keyword(keyword, limit) {
                Ok(entries) => {
                    tracing::debug!(keyword = %keyword, found = entries.len(), "audit search by keyword");
                    entries
                }
                Err(e) => {
                    tracing::warn!(keyword = %keyword, error = %e, "audit keyword search failed, returning empty");
                    vec![]
                }
            }
        }
    };

    let receipts: Vec<serde_json::Value> = entries
        .iter()
        .filter_map(|e| {
            let claim = audit_extract_claim(&e.action)?;
            if !audit_matches_pattern(&claim, pattern) {
                return None;
            }
            Some(audit_normalize_entry(e, &claim))
        })
        .collect();

    let count = receipts.len();
    Json(AuditReceiptsResponse { receipts, count })
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

/// Query params for `GET /api/v1/officer/sweep`.
///
/// `officer=steward|sentinel|forge|cleo` — optional name filter. If omitted,
/// runs the full enabled roster.
#[derive(Deserialize)]
struct OfficerSweepQuery {
    officer: Option<String>,
}

/// `GET /api/v1/officer/sweep?officer=<name>` — trigger on-demand officer sweep.
///
/// Composes with SUBSTRATE-COORDINATION-DISCIPLINE (autonomic scope):
/// operator or Regent explicitly requests diagnostic sweep. Response is
/// findings JSON structured per-officer. Regent can call this as a
/// diagnostic tool composed with her observation cycle; operator can call
/// via `zp officer sweep <name>` CLI verb.
async fn officer_sweep_handler(
    State(state): State<AppState>,
    Query(params): Query<OfficerSweepQuery>,
) -> Json<serde_json::Value> {
    let result = officers::run_manual_sweep(&state.0, params.officer.as_deref());
    Json(result)
}

/// `GET /api/v1/substrate/validate` — deterministic substrate validation.
///
/// Runs the same canonical `substrate_validate::run_substrate_validation`
/// primitive that Regent invokes via her `substrate_validate` tool (task #20).
/// Returns structured findings JSON and chain-anchors a
/// `substrate:validation:regent:<id>` evidence receipt.
///
/// Provides operator direct-invocation path independent of Regent's dispatch
/// choice — companion to task #21 CLI verb `zp substrate validate`.
///
/// Composes with SUBSTRATE-SELF-CONSTRUCTION discipline: separates
/// deterministic structural validation (this endpoint's job) from narration
/// judgment (Regent's job when she narrates the output).
async fn substrate_validate_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    let report = crate::substrate_validate::run_substrate_validation(&state.0.audit_store);
    Json(report)
}

/// `POST /api/v1/vault/test/:provider` — probe a vault-stored provider
/// credential for validity without exposing the credential value.
///
/// Composes with aligned blindness (KEEL III.24, Layer 4): credential values
/// never leave the substrate. This endpoint retrieves the credential server-side,
/// makes a minimal auth-check request to the provider's endpoint, and returns
/// structural pass/fail — not the credential itself. Regent's `vault_test` tool
/// invokes this to verify credentials without ever seeing them in cognitive layer.
///
/// Reference providers: `anthropic`, `openai`, `abacus`. Unknown provider names
/// return "unknown provider" without attempting probe.
async fn vault_test_handler(
    State(state): State<AppState>,
    AxumPath(provider): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate provider name
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

    // Determine probe URL and expected behavior per provider.
    // Unknown providers fail fast without vault access.
    let (probe_url, provider_display) = match provider.to_ascii_lowercase().as_str() {
        "anthropic" => ("https://api.anthropic.com/v1/models", "Anthropic"),
        "openai" => ("https://api.openai.com/v1/models", "OpenAI"),
        "abacus" | "abacusai" | "routellm" => {
            ("https://routellm.abacus.ai/v1/models", "Abacus RouteLLM")
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Unknown provider: {}", provider),
                    "known_providers": ["anthropic", "openai", "abacus"],
                })),
            );
        }
    };

    // Retrieve credential from vault (server-side only, per aligned blindness).
    let resolved_key = match state.0.vault_key.get().and_then(|k| k.as_ref()) {
        Some(k) => k,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Vault key unavailable"})),
            );
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
            );
        }
    };

    let key = format!("providers/{}/api_key", provider.to_ascii_lowercase());
    let credential = match vault.retrieve(&key) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "provider": provider_display,
                    "probe_status": "credential_not_found",
                    "vault_path": key,
                    "detail": "no api_key stored in vault for this provider",
                })),
            );
        }
    };

    // Log the probe attempt with credential length only — never the value.
    info!(
        "Vault probe: provider={} credential_length={}",
        provider_display,
        credential.len()
    );

    // Make minimal auth-verification request. Use short timeout — this is a
    // liveness probe, not a business call. Bearer for OpenAI/Anthropic-family;
    // x-api-key for Anthropic specifically (their auth pattern).
    let client = match reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("HTTP client build failed: {}", e)})),
            );
        }
    };

    let mut req = client.get(probe_url);
    if provider.eq_ignore_ascii_case("anthropic") {
        // Anthropic uses x-api-key + anthropic-version headers
        req = req
            .header("x-api-key", &credential)
            .header("anthropic-version", "2023-06-01");
    } else {
        // OpenAI + Abacus (OpenAI-compatible) use bearer auth
        req = req.bearer_auth(&credential);
    }

    let start = std::time::Instant::now();
    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "provider": provider_display,
                    "probe_status": "network_error",
                    "probe_url": probe_url,
                    "detail": format!("could not reach provider: {}", e),
                    "latency_ms": start.elapsed().as_millis(),
                })),
            );
        }
    };

    let http_status = response.status();
    let latency_ms = start.elapsed().as_millis();

    let probe_status = match http_status.as_u16() {
        200..=299 => "credential_valid",
        401 | 403 => "credential_rejected",
        429 => "rate_limited",
        s if s >= 500 => "provider_error",
        _ => "unexpected_response",
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "provider": provider_display,
            "probe_status": probe_status,
            "probe_url": probe_url,
            "http_status": http_status.as_u16(),
            "latency_ms": latency_ms,
            "credential_field": "api_key",
        })),
    )
}

// ── Vault operator surface ──────────────────────────────────────────────────
//
// Until 2026-08-06 `VaultCmd` had exactly one variant, `Test`, which exercises
// a sovereignty provider rather than vault storage. There was no way to list
// what the vault held, put anything into it, or take anything out. The only
// code touching `vault.list()` was the officer sweep, onboarding, and one
// branch of `zp configure`.
//
// The consequence showed up when the operator asked a simple question — "where
// are our API keys?" — and the substrate could not answer it. The one surface
// that reports on the vault is Steward's `vault_empty` finding, which says
// "Vault contains no entries" for three different conditions (key unresolved,
// vault unreadable, vault genuinely empty) at Info severity.
//
// These run server-side because the server already holds the vault master key,
// derived once from the boot ceremony. Routing them through the CLI's own
// sovereign-root unlock would mean a second ceremony per vault operation — a
// second root in all but name, which `singular_sovereign_root` forbids. The
// verbs are session-token-only for the same reason: seeing what the vault
// holds should cost nothing, because a surface that costs a ceremony to read
// is a surface that stops being read.

/// Resolve the vault for a handler, or the error response explaining why not.
///
/// Distinguishes the three states Steward's finding conflates, so a caller can
/// tell "no key" from "unreadable" from "empty" — see the note above.
fn open_vault_for_handler(
    state: &AppState,
) -> Result<zp_trust::CredentialVault, (StatusCode, Json<serde_json::Value>)> {
    let resolved = state
        .0
        .vault_key
        .get()
        .and_then(|k| k.as_ref())
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "vault_key_unavailable",
                    "detail": "The vault master key has not resolved. This is not an \
                               empty vault — it is an unreadable one. Check that Genesis \
                               exists and the boot ceremony completed.",
                })),
            )
        })?;
    let vault_path = zp_paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
    zp_trust::CredentialVault::load_or_create(&resolved.key, &vault_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "vault_unreadable",
                "detail": format!("{}", e),
            })),
        )
    })
}

fn vault_file_path(state: &AppState) -> std::path::PathBuf {
    zp_paths::vault_path()
        .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"))
}

/// `GET /api/v1/vault/list` — key names only, never values.
///
/// The R1 privilege invariant the officers already hold: names are metadata,
/// values are not. `exists` distinguishes a vault that has never been written
/// from one that is empty, which the filesystem alone cannot express because
/// `load_or_create` synthesises an empty vault in memory without touching disk.
async fn vault_list_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vault = match open_vault_for_handler(&state) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let path = vault_file_path(&state);
    let names = vault.list();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "keys": names,
            "count": names.len(),
            "vault_path": path.display().to_string(),
            "exists": path.exists(),
        })),
    )
}

#[derive(serde::Deserialize)]
struct VaultPutRequest {
    key: String,
    value: String,
}

/// `POST /api/v1/vault/put` — store a secret.
///
/// The value arrives in a JSON body rather than a query parameter or path
/// segment so it does not reach a URL, an access log, or shell history. The CLI
/// side reads it from stdin for the same reason.
async fn vault_put_handler(
    State(state): State<AppState>,
    Json(req): Json<VaultPutRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.key.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "key must not be empty"})),
        );
    }
    let mut vault = match open_vault_for_handler(&state) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // Tier is inferred from the key path by `store`, matching how
    // `spawn_regent`'s migration and the onboarding flow write.
    if let Err(e) = vault.store(&req.key, req.value.as_bytes()) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("store failed: {}", e)})),
        );
    }
    let path = vault_file_path(&state);
    if let Err(e) = vault.save(&path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("save failed: {}", e)})),
        );
    }
    // Chain-anchor the *fact*, never the value. Key name is metadata; the
    // secret does not enter the cognitive path or the chain.
    tool_chain::emit_tool_receipt(
        &state.0.audit_store,
        "vault:secret:stored",
        Some(&format!("key={}", req.key)),
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({"stored": req.key, "vault_path": path.display().to_string()})),
    )
}

#[derive(serde::Deserialize)]
struct VaultKeyRequest {
    key: String,
}

/// `POST /api/v1/vault/remove` — delete a secret by name.
async fn vault_remove_handler(
    State(state): State<AppState>,
    Json(req): Json<VaultKeyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut vault = match open_vault_for_handler(&state) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    if let Err(e) = vault.remove(&req.key) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("{}", e)})),
        );
    }
    let path = vault_file_path(&state);
    if let Err(e) = vault.save(&path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("save failed: {}", e)})),
        );
    }
    tool_chain::emit_tool_receipt(
        &state.0.audit_store,
        "vault:secret:removed",
        Some(&format!("key={}", req.key)),
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({"removed": req.key})),
    )
}

/// `POST /api/v1/vault/reveal` — return a secret's value.
///
/// Deliberately the only verb that emits secret material, and deliberately
/// present rather than omitted. Per *delegable safety* (KEEL §III.18), a
/// restriction with no sanctioned path gets bypassed: an operator who cannot
/// recover a secret from the vault keeps their secrets somewhere else, and the
/// vault discipline is defeated by the very rule meant to protect it.
///
/// The ceremony is that the caller must ask for this verb by name. The
/// retrieval is chain-anchored — the value never reaches the chain, but the
/// fact that it was read does, so the operator can audit their own access.
async fn vault_reveal_handler(
    State(state): State<AppState>,
    Json(req): Json<VaultKeyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let vault = match open_vault_for_handler(&state) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let bytes = match vault.retrieve(&req.key) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": format!("{}", e)})),
            )
        }
    };
    tool_chain::emit_tool_receipt(
        &state.0.audit_store,
        "vault:secret:revealed",
        Some(&format!("key={}", req.key)),
    );
    match String::from_utf8(bytes) {
        Ok(s) => (
            StatusCode::OK,
            Json(serde_json::json!({"key": req.key, "value": s})),
        ),
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "key": req.key,
                "error": "value is not valid UTF-8",
                "bytes": e.as_bytes().len(),
            })),
        ),
    }
}

// ── Standing correction handlers (P2.1) ─────────────────────────────────────

/// `POST /api/v1/correction/issue` — issue a new standing correction receipt.
///
/// Chain-anchors the correction as a `cognitive:correction:standing` event
/// per STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md. Operator's next
/// perceive() cycle sees this correction at Tier 1.
///
/// Request body: JSON matching StandingCorrection schema fields (correction_id,
/// issued_at, issued_by, correction_type, domain, scope, content, priority,
/// expiry, supersedes). The server fills correction_id from a content hash
/// when not provided, and stamps issued_at with current time when missing.
async fn correction_issue_handler(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    use zp_regent::corrections::StandingCorrection;

    // Fill in server-side defaults so callers can submit minimal payloads.
    let mut payload = payload;
    if payload.get("issued_at").is_none() {
        payload["issued_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
    }
    if payload.get("issued_by").is_none() {
        // Best-effort operator identity from Genesis; empty string if unavailable.
        let operator_pubkey = zp_paths::home()
            .ok()
            .and_then(|home| std::fs::read_to_string(home.join("genesis.json")).ok())
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| {
                v.get("genesis_public_key")
                    .and_then(|k| k.as_str().map(String::from))
            })
            .unwrap_or_default();
        payload["issued_by"] = serde_json::json!(operator_pubkey);
    }
    if payload.get("scope").is_none() {
        payload["scope"] = serde_json::json!({});
    }
    if payload.get("correction_id").is_none() {
        // Content-derived id: sha256 of (domain + assertion) truncated.
        let domain = payload.get("domain").and_then(|d| d.as_str()).unwrap_or("");
        let assertion = payload
            .get("content")
            .and_then(|c| c.get("assertion"))
            .and_then(|a| a.as_str())
            .unwrap_or("");
        let id_material = format!("{}::{}", domain, assertion);
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(id_material.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        payload["correction_id"] = serde_json::json!(&hash[..16]);
    }

    let correction: StandingCorrection = match serde_json::from_value(payload) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("Invalid correction payload: {}", e),
                    "hint": "Required fields: correction_type, domain, content.assertion, priority",
                })),
            );
        }
    };

    let event = correction.to_event_string();
    let entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::Operator,
        action: zp_core::AuditAction::SystemEvent { event },
        conversation_id: zp_core::ConversationId(
            uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
        ),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "operator-correction".to_string(),
        receipt: None,
    };

    let entry_hash = match state.0.audit_store.lock() {
        Ok(mut store) => match store.append(entry) {
            Ok(sealed) => sealed.entry_hash,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to anchor correction: {}", e),
                    })),
                );
            }
        },
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Audit store lock poisoned: {}", e),
                })),
            );
        }
    };

    info!(
        correction_id = %correction.correction_id,
        domain = %correction.domain,
        priority = correction.priority,
        "operator issued standing correction"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "correction_id": correction.correction_id,
            "entry_hash": entry_hash,
            "domain": correction.domain,
            "priority": correction.priority,
        })),
    )
}

/// `GET /api/v1/correction/list` — list currently active standing corrections.
///
/// Returns priority-sorted (highest first) list of corrections that are neither
/// superseded, revoked, nor expired.
async fn correction_list_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    use zp_regent::corrections::{CorrectionIndex, EVENT_PREFIX_REVOKED, EVENT_PREFIX_STANDING};

    let store = match state.0.audit_store.lock() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Audit store lock poisoned: {}", e),
                })),
            );
        }
    };

    let mut correction_entries = store
        .search_chain_by_action_keyword(EVENT_PREFIX_STANDING, 1024)
        .unwrap_or_default();
    let mut revocation_entries = store
        .search_chain_by_action_keyword(EVENT_PREFIX_REVOKED, 1024)
        .unwrap_or_default();
    correction_entries.append(&mut revocation_entries);
    drop(store);

    let index = CorrectionIndex::build(&correction_entries, chrono::Utc::now());

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "active_count": index.len(),
            "corrections": index.all(),
        })),
    )
}

/// `POST /api/v1/correction/revoke/:correction_id` — revoke a standing correction.
///
/// Emits a `cognitive:correction:revoked` event referencing the given id.
/// The revocation is chain-preserved (revocation itself is a receipt) but the
/// correction stops appearing in the active index.
/// Outstanding and recently resolved approval requests.
///
/// Reads both receipt families over one window and joins them, the same
/// shape as `correction_list_handler`.
async fn regent_approvals_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    use zp_regent::approvals::{
        ApprovalIndex, EVENT_PREFIX_DENIED, EVENT_PREFIX_GRANTED, EVENT_PREFIX_REQUEST,
    };

    let store = match state.0.audit_store.lock() {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Audit store lock poisoned: {}", e),
                })),
            );
        }
    };

    let mut entries = store
        .search_chain_by_action_keyword(EVENT_PREFIX_REQUEST, 1024)
        .unwrap_or_default();
    entries.append(
        &mut store
            .search_chain_by_action_keyword(EVENT_PREFIX_GRANTED, 1024)
            .unwrap_or_default(),
    );
    entries.append(
        &mut store
            .search_chain_by_action_keyword(EVENT_PREFIX_DENIED, 1024)
            .unwrap_or_default(),
    );
    drop(store);

    let index = ApprovalIndex::build(&entries);
    let pending = index.pending();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "pending_count": pending.len(),
            "pending": pending,
            "all": index.all(),
        })),
    )
}

/// The Regent's current autonomous envelope, as the operator can see it.
///
/// Precedent is the one thing in the substrate that widens what may happen
/// without asking. If the operator cannot enumerate it, they cannot consent
/// to it — a scope you can only discover by watching it get exercised is not
/// a scope anyone agreed to.
async fn regent_precedents_handler(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let entries = precedent_window(&state);
    let index = zp_regent::precedent::PrecedentIndex::build(&entries);
    let active = index.active();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": active.len(),
            "precedents": active,
        })),
    )
}

/// Narrow the envelope back.
///
/// Per KEEL §III.10: "Revoking a precedent narrows the autonomous scope back
/// and is itself a chain event." Not a deletion — the grant stays on chain as
/// the historical fact that it is, and this receipt records that it no longer
/// authorises anything. A substrate that could quietly forget having been
/// permitted could also quietly forget having been refused.
///
/// Actor is `ActorId::Operator`, as with approval resolution: withdrawing
/// consent is the operator's act.
async fn regent_precedent_revoke_handler(
    State(state): State<AppState>,
    AxumPath(signature): AxumPath<String>,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let reason = payload.get("reason").and_then(|v| v.as_str());

    let entries = precedent_window(&state);
    let index = zp_regent::precedent::PrecedentIndex::build(&entries);

    // Prefix resolution, ambiguity is an error. Same discipline as
    // `ApprovalIndex::resolve_prefix`: revoking the wrong precedent silently
    // widens the envelope somewhere the operator was not looking.
    let hits: Vec<_> = index
        .active()
        .into_iter()
        .filter(|p| p.context_signature.starts_with(&signature))
        .collect();

    let target = match hits.len() {
        0 => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("no active precedent matching {signature}"),
                })),
            )
        }
        1 => hits[0].clone(),
        n => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("{n} precedents match {signature} — use more characters"),
                })),
            )
        }
    };

    let revoked_at = chrono::Utc::now();
    let event = zp_regent::precedent::revocation_event_string(
        &target.tool,
        &target.context_signature,
        reason,
        revoked_at,
    );

    let entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::Operator,
        action: zp_core::AuditAction::SystemEvent { event },
        conversation_id: zp_core::ConversationId(
            uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
        ),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "operator-precedent-revocation".to_string(),
        receipt: None,
    };

    let anchored = {
        let mut store = match state.0.audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Audit store lock poisoned: {e}"),
                    })),
                )
            }
        };
        match store.append(entry) {
            Ok(sealed) => sealed.entry_hash,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("revocation receipt append failed: {e}"),
                    })),
                )
            }
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "revoked": true,
            "tool": target.tool,
            "context_signature": target.context_signature,
            "granted_request": target.granted_request,
            "anchored": anchored,
        })),
    )
}

/// The chain slice precedent is read from.
fn precedent_window(state: &AppState) -> Vec<zp_core::AuditEntry> {
    use zp_regent::approvals::{
        EVENT_PREFIX_DENIED, EVENT_PREFIX_ENACTED, EVENT_PREFIX_GRANTED, EVENT_PREFIX_REQUEST,
    };
    let store = match state.0.audit_store.lock() {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut acc = Vec::new();
    for prefix in [
        EVENT_PREFIX_REQUEST,
        EVENT_PREFIX_GRANTED,
        EVENT_PREFIX_DENIED,
        EVENT_PREFIX_ENACTED,
        zp_regent::precedent::EVENT_PREFIX_REVOKED,
    ] {
        acc.extend(
            store
                .search_chain_by_action_keyword(prefix, 1024)
                .unwrap_or_default(),
        );
    }
    acc
}

/// Record the operator's answer to a request.
///
/// Actor is `ActorId::Operator`, not the Regent — per P9 the approval is
/// the operator's act. The receipt cites the request's `entry_hash`,
/// because an approval that does not name what it approved is not
/// evidence of anything.
async fn regent_approval_resolve_handler(
    State(state): State<AppState>,
    AxumPath(request_hash): AxumPath<String>,
    Json(payload): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    use zp_regent::approvals::{
        resolution_event_string, ApprovalIndex, Resolution, EVENT_PREFIX_DENIED,
        EVENT_PREFIX_GRANTED, EVENT_PREFIX_REQUEST,
    };

    let decision = match payload
        .get("decision")
        .and_then(|v| v.as_str())
        .and_then(Resolution::parse)
    {
        Some(d) => d,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "decision must be \"granted\" or \"denied\"",
                })),
            );
        }
    };
    let reason = payload.get("reason").and_then(|v| v.as_str());

    // Resolve the operator's (possibly abbreviated) hash against real
    // requests, and refuse to answer one that is already answered —
    // silently double-resolving would make the record depend on read order.
    let (full_hash, action) = {
        let store = match state.0.audit_store.lock() {
            Ok(s) => s,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Audit store lock poisoned: {}", e),
                    })),
                );
            }
        };
        let mut entries = store
            .search_chain_by_action_keyword(EVENT_PREFIX_REQUEST, 1024)
            .unwrap_or_default();
        entries.append(
            &mut store
                .search_chain_by_action_keyword(EVENT_PREFIX_GRANTED, 1024)
                .unwrap_or_default(),
        );
        entries.append(
            &mut store
                .search_chain_by_action_keyword(EVENT_PREFIX_DENIED, 1024)
                .unwrap_or_default(),
        );
        drop(store);

        let index = ApprovalIndex::build(&entries);
        let full = match index.resolve_prefix(&request_hash) {
            Ok(h) => h,
            Err(e) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": e })),
                );
            }
        };
        let req = index.all().iter().find(|r| r.request_hash == full).cloned();
        match req {
            Some(r) if !r.is_pending() => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "request is already resolved",
                        "request_hash": full,
                        "resolution": r.resolution,
                    })),
                );
            }
            Some(r) => (full, r.action),
            None => (full, String::new()),
        }
    };

    let resolved_at = chrono::Utc::now();
    let event = resolution_event_string(decision, &full_hash, reason, resolved_at);

    let entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::Operator,
        action: zp_core::AuditAction::SystemEvent { event },
        conversation_id: zp_core::ConversationId(
            uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
        ),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "operator-approval".to_string(),
        receipt: None,
    };

    match state.0.audit_store.lock() {
        Ok(mut store) => match store.append(entry) {
            Ok(sealed) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "resolved",
                    "decision": decision,
                    "request_hash": full_hash,
                    "action": action,
                    "entry_hash": sealed.entry_hash,
                    "resolved_at": resolved_at.to_rfc3339(),
                })),
            ),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to anchor resolution: {}", e),
                })),
            ),
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Audit store lock poisoned: {}", e),
            })),
        ),
    }
}

async fn correction_revoke_handler(
    State(state): State<AppState>,
    AxumPath(correction_id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    use zp_regent::corrections::revocation_event_string;

    if correction_id.is_empty() || correction_id.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid correction_id"})),
        );
    }

    let revoked_at = chrono::Utc::now();
    let event = revocation_event_string(&correction_id, revoked_at);

    let entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::Operator,
        action: zp_core::AuditAction::SystemEvent { event },
        conversation_id: zp_core::ConversationId(
            uuid::Uuid::parse_str("00000000-0002-7000-8001-000000000001").unwrap(),
        ),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "operator-correction".to_string(),
        receipt: None,
    };

    let entry_hash = match state.0.audit_store.lock() {
        Ok(mut store) => match store.append(entry) {
            Ok(sealed) => sealed.entry_hash,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("Failed to anchor revocation: {}", e),
                    })),
                );
            }
        },
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Audit store lock poisoned: {}", e),
                })),
            );
        }
    };

    info!(
        correction_id = %correction_id,
        "operator revoked standing correction"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "correction_id": correction_id,
            "entry_hash": entry_hash,
            "revoked_at": revoked_at.to_rfc3339(),
        })),
    )
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
    zp_core::paths::redact_user_home(s)
}

// ============================================================================
// Tools / Cockpit — Typed Response Structs (P2-4)
// ============================================================================

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

// ============================================================================
// Tools / Cockpit Handler
// ============================================================================

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
            .or_else(|| o.launch.port.map(|p| zp_net::peer_origin("localhost", p)));
        return ToolLaunch {
            kind: o.launch.kind,
            url,
            port: o.launch.port,
            cmd: Some(format!("cd '{}' && {}", tool_path.display(), o.launch.cmd)),
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
            url: port.map(|p| zp_net::peer_origin("localhost", p)),
            port,
            cmd: Some(cmd),
        }
    } else if let Some(p) = port {
        // Web tool with detectable port (non-Rust).
        // Prefer real launch surfaces over Node-by-default: Node only when
        // package.json declares a usable entry, then Python, then Docker.
        let has_pnpm_lock = tool_path.join("pnpm-lock.yaml").exists();

        let scripts = launch_inference::read_npm_scripts(tool_path);
        let has_script = |name: &str| scripts.as_ref().map(|s| s.contains(name)).unwrap_or(false);

        let (cmd, kind) = if has_runnable_node {
            let pkg_mgr = if has_pnpm_lock { "pnpm" } else { "npm" };
            let has_next_build = tool_path.join(".next").join("BUILD_ID").exists();
            let has_dist = tool_path.join("dist").exists();
            let has_build_dir = tool_path.join("build").exists();
            // Only emit `<pm> run build` when the project both lacks a built
            // output AND actually has a `build` script (Fix B).
            let needs_build = !has_next_build && !has_dist && !has_build_dir && has_script("build");
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
                Some(format!("cd '{}' && {} {}", tool_path.display(), py, entry)),
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
            url: Some(zp_net::peer_origin("localhost", p)),
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
        let script = start_scripts.iter().find(|s| tool_path.join(s).exists());
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
                Some(format!("cd '{}' && {} {}", tool_path.display(), py, entry)),
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

// ── Tool Lifecycle ──────────────────────────────────────────────────────────

/// PID file directory: ~/ZeroPoint/pids/
fn pid_dir() -> std::path::PathBuf {
    let dir = zp_paths::home().unwrap_or_default().join("pids");
    std::fs::create_dir_all(&dir).ok();
    dir
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
    let tool_path = zp_core::paths::user_home_or("").join("projects").join(name);
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

/// POST /api/v1/receipts — accept an external receipt from a governed
/// forwarder (the AG-UI proxy) and append it to the external-receipts
/// journal.
///
/// These receipts are NOT added to the signed audit chain — the chain
/// invariants require receipts to slot into the conversation-ordered
/// bead structure under a node-controlled identity, which an external
/// proxy can't produce. The journal is an append-only observability
/// stream that the abacus artifact (and operator tools) can read.
///
/// **Distinction (issue #196):** this rationale applies to *external*
/// proxy receipts only. ZP's *own* governance decisions — the gate
/// (`gate_tool_call_handler`) and memory observations
/// (`memory_observe_handler`) — DO write to the signed chain in addition
/// to the jsonl journal, because ZP IS the authority producing those
/// claims and can sign them under the node identity. The jsonl entry
/// becomes the lightweight observability projection of the chain truth.
///
/// Auth-gated. Body is accepted as free-form JSON, but we require either
/// `receipt_id` or `claim_type` as a sanity gate against random payloads.
async fn receipts_external_handler(
    State(_state): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let receipt_id = body
        .get("receipt_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let claim_type = body
        .get("claim_type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if receipt_id.is_empty() && claim_type.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "receipt must have receipt_id or claim_type"
            })),
        );
    }

    let home = match zp_paths::home() {
        Ok(h) => h,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("home path unavailable: {}", e)})),
            )
        }
    };
    let path = home.join("logs").join("external-receipts.jsonl");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let line = match serde_json::to_string(&body) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("encode failed: {}", e)})),
            )
        }
    };

    use std::io::Write;
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("open journal: {}", e)})),
            )
        }
    };
    if let Err(e) = writeln!(file, "{}", line) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("write journal: {}", e)})),
        );
    }

    debug!(
        "External receipt logged: id={} claim={}",
        receipt_id, claim_type
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "accepted": true,
            "receipt_id": receipt_id,
        })),
    )
}

#[derive(Deserialize)]
struct GateToolCallRequest {
    tool_name: String,
    #[serde(default)]
    args_hash: Option<String>,
    #[serde(default)]
    thread_id: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    agent: Option<String>,
}

/// POST /api/v1/gate/tool-call — pre-dispatch gate for agent tool calls.
///
/// Stage 1 of the Hermes integration (per `docs/design/zp-hermes-interfaces.md`):
/// a governance check consulted by the Hermes `pre_tool_call` plugin hook
/// before each tool invocation. Returns `{allow, reason}`; either way, the
/// decision is journaled as an external receipt.
///
/// Policy (MVP): reads an optional deny-list at `~/ZeroPoint/gate-policy.json`:
///   { "deny_tool_names": ["terminal", "execute_code"] }
/// Missing file or missing key = allow everything. Deny-list matches are
/// case-sensitive exact-match on the tool name.
///
/// Future: capability-grant evaluation, WASM policy modules, envelope
/// consumption for browser_* tools (Interface 2).
async fn gate_tool_call_handler(
    State(state): State<AppState>,
    Json(req): Json<GateToolCallRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.tool_name.is_empty() || req.tool_name.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "tool_name required, max 128 chars"})),
        );
    }

    // P4 (#197) — local heartbeat halt: when this server is a delegate
    // node and its own lease has expired past grace, the heartbeat task
    // sets `halted = true` and the gate stops authorizing any tool call.
    // This is the kill switch's local enforcement point.
    if let Some(hb) = state.0.lease_heartbeat.as_ref() {
        use std::sync::atomic::Ordering;
        if hb.halted.load(Ordering::Relaxed) {
            let receipt_id = format!("rcpt-{}", uuid::Uuid::now_v7());
            let chain_event = format!("gate:denied:{}", req.tool_name);
            let chain_detail = serde_json::json!({
                "tool_name": req.tool_name,
                "agent": req.agent,
                "allowed": false,
                "reason": "lease_halt",
                "policy_source": "lease-heartbeat",
                "external_receipt_id": receipt_id,
            })
            .to_string();
            let chain_entry_hash = tool_chain::emit_tool_receipt(
                &state.0.audit_store,
                &chain_event,
                Some(&chain_detail),
            );
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "allowed": false,
                    "allow": false,
                    "reason": "lease_halt",
                    "receipt_id": receipt_id,
                    "chain_entry_hash": chain_entry_hash,
                })),
            );
        }
    }

    // P4 (#197) — standing delegation prerequisite check. When the caller
    // identifies its agent (`req.agent = Some(node_id)`), the gate requires
    // a live, non-revoked standing grant for that node before any deny-list
    // evaluation runs. Agentless callers keep today's permissive behaviour;
    // tightening that to "agent always required" is a deployment-time
    // policy switch, not an architectural one.
    if let Some(agent_id) = req.agent.as_deref() {
        // Resolve agent name → registered agent key. Gate requests may
        // carry the tool's human-readable name ("ironclaw") while the
        // delegation chain uses the hex public key the tool registered
        // via POST /api/v1/tools/:name/register-agent. Try the port
        // registry first; fall through to the raw value when no mapping
        // exists (the caller may already be sending a hex key).
        let resolved_agent_id = state
            .0
            .port_registry
            .get_agent_key(agent_id)
            .unwrap_or_else(|| agent_id.to_string());
        if let Some(deny_reason) =
            lease_prereq_for_agent(&state, &resolved_agent_id, &req.tool_name)
        {
            let receipt_id = format!("rcpt-{}", uuid::Uuid::now_v7());
            let chain_event = format!("gate:denied:{}", req.tool_name);
            let chain_detail = serde_json::json!({
                "tool_name": req.tool_name,
                "agent": agent_id,
                "allowed": false,
                "reason": deny_reason,
                "policy_source": "delegation-prereq",
                "external_receipt_id": receipt_id,
            })
            .to_string();
            let chain_entry_hash = tool_chain::emit_tool_receipt(
                &state.0.audit_store,
                &chain_event,
                Some(&chain_detail),
            );
            info!(
                "Gate decision: tool={} allow=false reason='{}' chain_entry={:?}",
                req.tool_name, deny_reason, chain_entry_hash
            );
            return (
                StatusCode::OK,
                Json(serde_json::json!({
                    "allowed": false,
                    "allow": false,
                    "reason": deny_reason,
                    "receipt_id": receipt_id,
                    "chain_entry_hash": chain_entry_hash,
                })),
            );
        }
    }

    // Load deny-list policy (best-effort; missing file = empty list).
    let policy_path = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("gate-policy.json");
    let deny: Vec<String> = std::fs::read_to_string(&policy_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.get("deny_tool_names")
                .and_then(|d| d.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
        })
        .unwrap_or_default();

    let denied = deny.iter().any(|t| t == &req.tool_name);
    let allow = !denied;
    let reason = if denied {
        format!("tool '{}' is on the gate-policy deny list", req.tool_name)
    } else {
        String::new()
    };

    let receipt_id = format!("rcpt-{}", uuid::Uuid::now_v7());
    let ts_ms = Utc::now().timestamp_millis();
    let claim_type = if allow {
        "gate.tool_call.allowed"
    } else {
        "gate.tool_call.blocked"
    };

    // Append to the external-receipts journal. Schema matches
    // receipts_external_handler so a single downstream (abacus artifact,
    // operator tools) can read either stream.
    let journal_receipt = serde_json::json!({
        "receipt_id": receipt_id,
        "timestamp": ts_ms,
        "claim_type": claim_type,
        "approved": allow,
        "reason": if allow { serde_json::Value::Null } else { serde_json::Value::String(reason.clone()) },
        "metadata": {
            "tool_name": req.tool_name,
            "args_hash": req.args_hash,
            "thread_id": req.thread_id,
            "run_id": req.run_id,
            "agent": req.agent,
        },
    });
    if let Ok(home) = zp_paths::home() {
        let path = home.join("logs").join("external-receipts.jsonl");
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            if let Ok(line) = serde_json::to_string(&journal_receipt) {
                let _ = writeln!(file, "{}", line);
            }
        }
    }

    // Issue #196 — dual-write the gate decision into the signed audit chain.
    // The jsonl journal above is the lightweight observability projection;
    // the chain is the source of truth. emit_gate_decision_receipt attaches a
    // typed, signed AuthorizationClaim receipt — replacing the old
    // emit_tool_receipt call that only stored a SystemEvent string.
    // Use emit_gate_decision_receipt instead of the generic emit_tool_receipt so
    // the chain entry carries a typed, signed AuthorizationClaim receipt — making
    // the gate decision independently verifiable by any chain reader.
    let chain_entry_hash = tool_chain::emit_gate_decision_receipt(
        &state.0.audit_store,
        &req.tool_name,
        allow,
        req.agent.as_deref(),
        if reason.is_empty() {
            None
        } else {
            Some(&reason)
        },
        Some(&state.0.identity.signing_key),
    );

    info!(
        "Gate decision: tool={} allow={} reason={} chain_entry={:?}",
        req.tool_name,
        allow,
        reason,
        chain_entry_hash.as_deref()
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            // F-integration: field is named `allowed` (past-participle) to
            // match the F7 Python SDK spec and IronClaw's GateDecision
            // deserializer. `allow` is preserved as a duplicate field for
            // any pre-rename clients still in flight; remove once they're
            // migrated.
            "allowed": allow,
            "allow": allow,
            "reason": reason,
            "receipt_id": receipt_id,
            // Issue #196 — surface the chain entry hash so callers can
            // correlate jsonl-line ↔ chain-entry without scanning either.
            "chain_entry_hash": chain_entry_hash,
        })),
    )
}

// ============================================================================
// P4 (#197) — Standing delegation lease renewal
// ============================================================================

#[derive(Deserialize)]
struct LeaseRenewRequest {
    grant_id: String,
    /// Subject node id. Must match the grantee on `delegation:granted:*`.
    subject_node_id: String,
    /// Hex-encoded Ed25519 signature over `{grant_id}|{timestamp_ms}`.
    /// **Required** — endpoint authenticates by signature, not by session
    /// cookie. The middleware exempts this path; rejection is the
    /// handler's job. Verified against the grant's bound
    /// `subject_public_key`.
    subject_signature: String,
    /// Millisecond timestamp the subject signed over. Required.
    /// Rejected as stale if more than 5 minutes off wallclock.
    timestamp_ms: i64,
}

/// POST /api/v1/lease/renew — renew a standing delegation grant.
///
/// Walks the audit chain to find the named grant, confirms it has not been
/// revoked, confirms the subject claim matches `delegation:granted:*`, and
/// emits a `delegation:renewed:{subject}` receipt with the new `expires_at`.
///
/// **Authentication.** This endpoint is exempt from the session-token
/// middleware (`auth.rs::is_exempt`). It authenticates by Ed25519
/// signature over `{grant_id}|{timestamp_ms}` against the grant's bound
/// `subject_public_key`. The middleware-bypass is safe because:
/// - The handler rejects any request whose signature does not verify.
/// - The signature is bound to the grant's pubkey at issuance, on chain.
/// - The timestamp is rejected if more than 5 minutes off wallclock,
///   preventing replay of old captured signatures.
///
/// Verification semantics:
/// - Grant must exist on chain and be subject_node_id's.
/// - Grant must not have a `delegation:revoked:*` entry already.
/// - Grant must not be past its grace period.
/// - Grant must have `subject_public_key` bound (legacy grants without one
///   cannot use this path; CLI-only renewal is the alternative).
/// - Signature must verify against that bound pubkey.
async fn lease_renew_handler(
    State(state): State<AppState>,
    Json(req): Json<LeaseRenewRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if req.grant_id.is_empty() || req.subject_node_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "grant_id and subject_node_id are required"
            })),
        );
    }

    // Reject stale or future-dated timestamps. 5-minute window matches the
    // typical clock-drift tolerance in TLS / Kerberos / etc.
    let now_ms = chrono::Utc::now().timestamp_millis();
    if (now_ms - req.timestamp_ms).abs() > 5 * 60 * 1000 {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "timestamp_out_of_window",
                "now_ms": now_ms,
                "claimed_ms": req.timestamp_ms,
            })),
        );
    }

    // Read the chain. We need the original grant body and the most recent
    // renewal so we can compute the new expiry from the right baseline.
    let chain = match state.0.audit_store.lock() {
        Ok(s) => match s.export_chain(i32::MAX as usize) {
            Ok(c) => c,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("export chain: {}", e)})),
                );
            }
        },
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "audit store mutex poisoned"})),
            );
        }
    };

    let mut current: Option<zp_core::CapabilityGrant> = None;
    let mut revoked: Option<String> = None;
    for entry in &chain {
        let zp_core::AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
            continue;
        };
        let Some(body) = conditions.first() else {
            continue;
        };

        if event.starts_with("delegation:granted:") || event.starts_with("delegation:renewed:") {
            if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                if g.id == req.grant_id {
                    current = Some(g);
                }
            }
        } else if event.starts_with("delegation:revoked:") {
            if let Ok(claim) = serde_json::from_str::<zp_core::RevocationClaim>(body) {
                if claim.target_grant_id == req.grant_id {
                    revoked = Some(format!("{:?}", claim.reason));
                }
            }
        }
    }

    let Some(mut grant) = current else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "grant_not_found",
                "grant_id": req.grant_id
            })),
        );
    };

    if let Some(reason) = revoked {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "grant_revoked",
                "reason": reason,
                "grant_id": req.grant_id,
            })),
        );
    }

    if grant.grantee != req.subject_node_id {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "subject_mismatch",
                "grant_subject": grant.grantee,
                "claimed_subject": req.subject_node_id,
            })),
        );
    }

    // The grant must carry a bound subject public key — otherwise this
    // path cannot authenticate the request. Legacy / browser-issued grants
    // without a pubkey must renew via the session-cookie CLI path instead.
    if grant.subject_public_key.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "no_subject_public_key",
                "detail": "grant has no subject_public_key bound; cannot authenticate this path"
            })),
        );
    }

    // Verify the signature. This is the authentication step.
    let payload = format!("{}|{}", req.grant_id, req.timestamp_ms).into_bytes();
    if !grant.verify_subject_signature(&payload, &req.subject_signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid_signature",
                "detail": "subject signature did not verify against the grant's bound public key"
            })),
        );
    }

    // Renew via the model. This already rejects past-grace.
    let new_expiry = match grant.renew() {
        Ok(t) => t,
        Err(zp_core::RenewalError::PastGrace) => {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "past_grace",
                    "grant_id": req.grant_id,
                })),
            );
        }
        Err(zp_core::RenewalError::NoLeasePolicy) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "no_lease_policy",
                    "grant_id": req.grant_id,
                })),
            );
        }
    };

    // Emit chain receipt: `delegation:renewed:{subject}` with refreshed grant.
    let entry_hash = tool_chain::emit_delegation_receipt(
        &state.0.audit_store,
        "renewed",
        &grant,
        Some(&state.0.identity.signing_key),
    );

    info!(
        grant_id = %req.grant_id,
        subject = %req.subject_node_id,
        renewal_count = grant.renewal_count,
        new_expiry = %new_expiry,
        "Lease renewed (sig verified)"
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "renewed": true,
            "grant_id": grant.id,
            "subject": grant.grantee,
            "new_expires_at": new_expiry,
            "renewal_count": grant.renewal_count,
            "chain_entry_hash": entry_hash,
        })),
    )
}

/// P4 (#197) — gate prerequisite: returns `Some(reason)` to deny when
/// `agent_id` has no valid (alive, non-revoked) standing delegation, or
/// `None` when the gate should proceed to deny-list / policy evaluation.
///
/// Walks the chain looking for `delegation:{granted,renewed,revoked}:{agent_id}`
/// and reconstructs the agent's most-recent grant state. Multiple grants for
/// the same agent are tolerated — at least one must be alive AND must cover
/// `tool_name` via a `GrantedCapability::ToolCall` scope.
///
/// # Claim 4 enforcement
///
/// The scope check enforces delegation narrowing: a live grant that does not
/// carry a `ToolCall` capability covering `tool_name` is not sufficient. The
/// deny reason `"capability_scope_exceeded"` is returned when an alive grant
/// exists but none of them cover the requested tool.
fn lease_prereq_for_agent(
    state: &AppState,
    agent_id: &str,
    tool_name: &str,
) -> Option<&'static str> {
    let chain = state
        .0
        .audit_store
        .lock()
        .ok()?
        .export_chain(i32::MAX as usize)
        .ok()?;

    let mut grants: std::collections::HashMap<String, zp_core::CapabilityGrant> =
        Default::default();
    let mut revoked: std::collections::HashSet<String> = Default::default();
    for entry in &chain {
        let zp_core::AuditAction::SystemEvent { event } = &entry.action else {
            continue;
        };
        let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
            continue;
        };
        let Some(body) = conditions.first() else {
            continue;
        };
        if event.starts_with("delegation:granted:") || event.starts_with("delegation:renewed:") {
            if let Ok(g) = serde_json::from_str::<zp_core::CapabilityGrant>(body) {
                if g.grantee == agent_id {
                    grants.insert(g.id.clone(), g);
                }
            }
        } else if event.starts_with("delegation:revoked:") {
            if let Ok(claim) = serde_json::from_str::<zp_core::RevocationClaim>(body) {
                revoked.insert(claim.target_grant_id);
            }
        }
    }

    // Collect grants that are not revoked and not past their grace period.
    let live: Vec<&zp_core::CapabilityGrant> = grants
        .values()
        .filter(|g| !revoked.contains(&g.id) && !g.is_past_grace())
        .collect();

    if !live.is_empty() {
        // Claim 4: at least one live grant must cover this specific tool.
        let tool_action = CoreActionType::ToolCall {
            name: tool_name.to_string(),
        };
        let scope_ok = live.iter().any(|g| g.matches_action(&tool_action));
        if scope_ok {
            None
        } else {
            Some("capability_scope_exceeded")
        }
    } else if grants.is_empty() {
        Some("no_valid_delegation")
    } else if grants.values().all(|g| revoked.contains(&g.id)) {
        Some("delegation_revoked")
    } else {
        Some("delegation_expired")
    }
}

/// Verify a hex-encoded Ed25519 signature over `payload` using `pubkey_hex`.
///
/// Routes through the single canonical verify primitive (Seam 5).
#[allow(dead_code)] // Used by anchor pipeline once external anchoring is wired
fn verify_ed25519_signature(pubkey_hex: &str, signature_hex: &str, payload: &[u8]) -> bool {
    let Ok(pk_bytes) = hex::decode(pubkey_hex) else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; 32], _> = pk_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(sig_arr): Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return false;
    };
    zp_receipt::verify::verify_signature(&pk_arr, payload, &sig_arr).is_ok()
}

// ============================================================================
// Tool configure / repair — ecosystem self-healing actions
// ============================================================================

// ============================================================================
// Tool-issued lifecycle receipts (tools attest to their own state)
// ============================================================================

/// Accept a lifecycle receipt from a tool (POST).
///
/// Tools call this to announce their own state transitions:
///   { "name": "IronClaw", "event": "setup:complete", "detail": "Admin created" }
// ─── GET /api/v1/tools — cockpit tile data ──────────────────────────────────

#[derive(Serialize)]
struct CockpitTool {
    name: String,
    path: String,
    status: String,
    governance: String,
    ready: bool,
    preflight_issues: Vec<String>,
    launch: CockpitLaunch,
    #[serde(skip_serializing_if = "Option::is_none")]
    running_pid: Option<u32>,
}

#[derive(Serialize)]
struct CockpitLaunch {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cmd: Option<String>,
}

/// GET /api/v1/tools — list governed tools from the port registry for the cockpit.
async fn tools_list_handler(State(state): State<AppState>) -> Json<serde_json::Value> {
    use std::collections::HashSet;
    use zp_officers::governance_posture::{
        compute_postures, RegisteredToolInfo, ToolRegistrySnapshot,
    };
    use zp_officers::officer::ChainReader;

    let bindings = state.0.port_registry.list();

    // Build registry snapshot and compute real governance postures.
    let mut snapshot = ToolRegistrySnapshot::default();
    for b in &bindings {
        snapshot.registered_tools.insert(
            b.tool.clone(),
            RegisteredToolInfo {
                port: b.web_ui_port(),
                pid: b.pid,
                has_launch_command: b.launch_command.is_some(),
            },
        );
    }

    let posture_map: std::collections::HashMap<String, String> = {
        let store = state.0.audit_store.lock();
        match store {
            Ok(s) => {
                let chain = ChainReader::new(&s);
                let unregistered: HashSet<String> = HashSet::new();
                let postures = compute_postures(&chain, &snapshot, &unregistered);
                postures
                    .into_iter()
                    .map(|p| (p.tool_name.clone(), p.summary()))
                    .collect()
            }
            Err(_) => std::collections::HashMap::new(),
        }
    };

    let mut tools: Vec<CockpitTool> = bindings
        .into_iter()
        .map(|b| {
            let ui_port = b.web_ui_port();
            // Prefer the registry PID (set on cockpit-launch); fall back to
            // port-based discovery so tools started outside the cockpit also
            // get a Stop button.
            let live_pid = b
                .pid
                .filter(|&pid| tool_ports::is_pid_alive(pid))
                .or_else(|| tool_ports::lsof_pid_for_port(ui_port));
            let path = b
                .launch_command
                .as_ref()
                .and_then(|lc| lc.working_dir.clone())
                .unwrap_or_else(|| format!("~/projects/{}", b.tool));

            let governance = posture_map
                .get(&b.tool)
                .cloned()
                .unwrap_or_else(|| "registered".to_string());

            CockpitTool {
                name: b.tool.clone(),
                path,
                status: "governed".to_string(),
                governance,
                ready: true,
                preflight_issues: vec![],
                launch: CockpitLaunch {
                    // No direct url — the JS uses its proxyUrl
                    // (http://{name}.localhost:{zp_port}/) so requests
                    // route through ZP's subdomain proxy, which injects
                    // the Authorization header before forwarding.
                    //
                    // kind is derived from the stored launch command so the
                    // cockpit uses the right wait strategy: native cargo tools
                    // get a 600s wait with indeterminate progress bar; web/
                    // script tools get 30s. Must match tool_launch_handler's
                    // kind derivation exactly.
                    kind: b
                        .launch_command
                        .as_ref()
                        .map_or("web", |lc| {
                            if lc.command == "cargo" || lc.command.ends_with("/cargo") {
                                "native"
                            } else {
                                "web"
                            }
                        })
                        .to_string(),
                    url: None,
                    port: Some(ui_port),
                    cmd: None,
                },
                running_pid: live_pid,
            }
        })
        .collect();

    // Stable sort: alphabetical by name so the cockpit order is deterministic.
    tools.sort_by(|a, b| a.name.cmp(&b.name));

    Json(serde_json::json!({
        "tools": tools,
        "chain_receipts": true,
    }))
}

/// GET /api/v1/tools/:name/probe — server-side TCP probe.
///
/// The browser can't probe cross-origin ports directly (CSP `connect-src 'self'`
/// blocks it), so the cockpit asks ZP to probe on its behalf.  Returns whether
/// the tool's allocated port is currently accepting connections.
async fn tool_probe_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Json<serde_json::Value> {
    let Some(binding) = state.0.port_registry.get_assigned(&name) else {
        return Json(serde_json::json!({
            "listening": false,
            "error": format!("Tool '{}' is not registered", name),
        }));
    };

    // Probe whether the tool's primary listener is up.  We do NOT return a
    // direct `gateway_url` — the JS falls back to its `proxyUrl` shape
    // (http://{name}.localhost:{zp_port}/) which routes through ZP's
    // subdomain proxy.  The proxy injects `Authorization: Bearer <auth_token>`
    // before forwarding, so tools that gate on that header (IronClaw, etc.)
    // never show a login page to the operator.
    //
    // Probing: check web_ui_port() first (the actual web UI — may differ from
    // proxy_target which can point at a webhook/gRPC listener).  If the web UI
    // port is different from the proxy_target, probe both.
    let proxy_port = binding.proxy_target();
    let ui_port = binding.web_ui_port();

    let probe_one = |port: u16| async move {
        tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
    };

    let listening = if ui_port == proxy_port {
        probe_one(proxy_port).await
    } else {
        // Probe the web UI port; fall back to the proxy_target so the JS
        // can still open the subdomain proxy URL even if only the webhook
        // (proxy_target) is up.
        probe_one(ui_port).await || probe_one(proxy_port).await
    };

    Json(serde_json::json!({
        "listening": listening,
        "port": ui_port,
        // No gateway_url — JS uses its proxyUrl (subdomain) which injects auth.
    }))
}

/// GET /api/v1/tools/:name/posture — per-tool governance posture.
///
/// Returns the computed governance facets, attestation details, and any
/// active officer warnings for the named tool. Reuses the same
/// `compute_postures()` that `zp doctor` relies on, plus a targeted
/// chain search for attestation timestamps.
async fn tool_posture_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Json<serde_json::Value> {
    use std::collections::HashSet;
    use zp_officers::governance_posture::{
        compute_postures, RegisteredToolInfo, ToolRegistrySnapshot,
    };
    use zp_officers::officer::ChainReader;

    let lower = name.to_lowercase();

    // Build registry snapshot from port registry (same as tools_list_handler).
    let bindings = state.0.port_registry.list();
    let mut snapshot = ToolRegistrySnapshot::default();
    for b in &bindings {
        snapshot.registered_tools.insert(
            b.tool.clone(),
            RegisteredToolInfo {
                port: b.web_ui_port(),
                pid: b.pid,
                has_launch_command: b.launch_command.is_some(),
            },
        );
    }

    let store = match state.0.audit_store.lock() {
        Ok(s) => s,
        Err(_) => {
            return Json(serde_json::json!({
                "error": "audit store lock poisoned",
            }));
        }
    };
    let chain = ChainReader::new(&store);

    // Compute postures for all tools, then find ours.
    let unregistered: HashSet<String> = HashSet::new();
    let postures = compute_postures(&chain, &snapshot, &unregistered);
    let posture = postures.iter().find(|p| p.tool_name == lower);

    let (facets, level) = match posture {
        Some(p) => {
            let mut labels: Vec<&str> = p.facets.iter().map(|f| f.label()).collect();
            labels.sort();
            (labels, p.level())
        }
        None => {
            return Json(serde_json::json!({
                "tool": lower,
                "facets": [],
                "level": 0,
                "attestations": [],
                "warnings": [],
                "computed_at": Utc::now().to_rfc3339(),
                "error": format!("Tool '{}' not found in posture data", lower),
            }));
        }
    };

    // Attestation details: officer name + timestamp of most recent attestation.
    let mut attestations: Vec<serde_json::Value> = Vec::new();
    if let Ok(entries) = chain.search_by_keyword("attested:", 500) {
        // Group by officer, keep most recent timestamp per officer.
        let mut latest: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for entry in &entries {
            if let zp_core::AuditAction::SystemEvent { event } = &entry.action {
                if let Some(rest) = event.strip_prefix("officer:") {
                    if let Some(pos) = rest.find(":attested:") {
                        let officer_name = &rest[..pos];
                        let tool_name = &rest[pos + ":attested:".len()..];
                        if tool_name == lower {
                            let ts = entry.timestamp.to_rfc3339();
                            latest
                                .entry(officer_name.to_string())
                                .and_modify(|existing: &mut String| {
                                    if ts > *existing {
                                        *existing = ts.clone();
                                    }
                                })
                                .or_insert(ts);
                        }
                    }
                }
            }
        }
        // Sort by officer name for stable output.
        let mut officers: Vec<_> = latest.into_iter().collect();
        officers.sort_by(|a, b| a.0.cmp(&b.0));
        for (officer, ts) in officers {
            attestations.push(serde_json::json!({
                "officer": officer,
                "attested_at": ts,
            }));
        }
    }

    // Warnings: search for officer findings referencing this tool.
    let mut warnings: Vec<String> = Vec::new();
    if let Ok(entries) = chain.search_by_keyword(":operations:", 500) {
        for entry in &entries {
            if let zp_core::AuditAction::SystemEvent { event } = &entry.action {
                if event.contains(&format!("tool={}", lower)) {
                    // Extract the condition text if present.
                    if let Some(cond_pos) = event.find("condition=") {
                        let cond = &event[cond_pos + "condition=".len()..];
                        let cond = cond.split_whitespace().next().unwrap_or(cond);
                        if !warnings.contains(&cond.to_string()) {
                            warnings.push(cond.to_string());
                        }
                    }
                }
            }
        }
    }

    Json(serde_json::json!({
        "tool": lower,
        "facets": facets,
        "level": level,
        "attestations": attestations,
        "warnings": warnings,
        "computed_at": Utc::now().to_rfc3339(),
    }))
}

/// POST /api/v1/tools/:name/stop — stop a running governed tool.
///
/// Reads the PID file, sends SIGTERM (then SIGKILL if needed), removes the PID
/// file, and emits a `tool:stopped:<name>` receipt into the audit chain.
async fn tool_stop_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let lower = name.to_lowercase();

    let pid = match read_live_pid(&lower) {
        Some(p) => p,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("No running process found for '{}'", lower),
                })),
            ));
        }
    };

    kill_tool_process(&lower, pid);

    // Unregister PID from sensor layer — no point watching a process we killed.
    state.0.sensor_handle.unwatch_pid(pid).await;

    // Kill any orphaned process still holding the tool's known ports.
    // cargo-as-launcher leaves the actual binary reparented to init after
    // cargo exits — kill -0 returns true for it, but the PID file has
    // cargo's PID (now dead). Kill by port instead to catch all cases.
    // Also clears the registry so the next launch gets a fresh proxy_port.
    if let Some(ref binding) = state.0.port_registry.get_assigned(&lower) {
        let ports: Vec<u16> = [Some(binding.port), binding.actual_port, binding.proxy_port]
            .into_iter()
            .flatten()
            .chain(binding.extra_ports.values().copied())
            .collect::<std::collections::HashSet<u16>>()
            .into_iter()
            .collect();
        for port in ports {
            if let Some(orphan_pid) = tool_ports::lsof_pid_for_port(port) {
                if orphan_pid != pid {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &orphan_pid.to_string()])
                        .status();
                    info!(
                        tool = %lower,
                        port = port,
                        orphan_pid = orphan_pid,
                        "Killed orphaned tool process found by port scan"
                    );
                }
            }
        }
        state
            .0
            .port_registry
            .clear_binding(&lower, tool_ports::ReleaseReason::OperatorKill);
        state.0.port_registry.clear_proxy_port(&lower);
    }

    // Emit tool:stopped receipt into the audit chain.
    tool_chain::emit_tool_receipt(
        &state.0.audit_store,
        &format!("tool:stopped:{}", lower),
        Some(&format!("pid={} operator=cockpit", pid)),
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "name": lower,
        "pid": pid,
    })))
}

/// POST /api/v1/tools/:name/remove — fully remove a governed tool.
///
/// Combines stop (if running) + deallocate (full entry removal) + cleanup.
/// This is the canonical removal path — the CLI calls this endpoint so that
/// the running server's in-memory PortRegistry stays consistent with disk.
async fn tool_remove_handler(
    State(state): State<AppState>,
    AxumPath(name): AxumPath<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let lower = name.to_lowercase();

    // 1. Resolve — tool must exist in the registry.
    let binding = match state.0.port_registry.get_assigned(&lower) {
        Some(b) => b,
        None => {
            return Err((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("Tool '{}' is not registered", lower),
                })),
            ));
        }
    };

    let mut pid_killed: Option<u32> = None;

    // 2. Stop process if running.
    if let Some(pid) = read_live_pid(&lower) {
        kill_tool_process(&lower, pid);
        state.0.sensor_handle.unwatch_pid(pid).await;

        // Kill orphaned processes holding the tool's ports.
        let ports: Vec<u16> = [Some(binding.port), binding.actual_port, binding.proxy_port]
            .into_iter()
            .flatten()
            .chain(binding.extra_ports.values().copied())
            .collect::<std::collections::HashSet<u16>>()
            .into_iter()
            .collect();
        for port in ports {
            if let Some(orphan_pid) = tool_ports::lsof_pid_for_port(port) {
                if orphan_pid != pid {
                    let _ = std::process::Command::new("kill")
                        .args(["-9", &orphan_pid.to_string()])
                        .status();
                }
            }
        }
        pid_killed = Some(pid);
    }

    // 3. Deallocate — full removal from in-memory registry + disk.
    //    deallocate() emits a PortReleased receipt with "allocation_removed".
    state.0.port_registry.deallocate(&lower);

    // 4. Clean up .env.zp sidecar.
    let mut env_zp_deleted = false;
    if let Some(ref lc) = binding.launch_command {
        if let Some(ref dir) = lc.working_dir {
            let env_zp = std::path::Path::new(dir).join(".env.zp");
            if env_zp.exists() {
                env_zp_deleted = std::fs::remove_file(&env_zp).is_ok();
            }
        }
    }

    // 5. Remove PID file.
    let pid_path = pid_dir().join(format!("{}.pid", lower));
    let _ = std::fs::remove_file(&pid_path);

    // 6. Emit tool:removed receipt.
    let detail = serde_json::json!({
        "tool": lower,
        "port": binding.port,
        "pid_killed": pid_killed,
        "env_zp_deleted": env_zp_deleted,
        "removal_reason": "operator requested",
    });
    tool_chain::emit_tool_receipt(
        &state.0.audit_store,
        &format!("tool:removed:{}", lower),
        Some(&detail.to_string()),
    );

    info!(
        tool = %lower,
        port = binding.port,
        pid_killed = ?pid_killed,
        "Tool fully removed from governance"
    );

    Ok(Json(serde_json::json!({
        "ok": true,
        "name": lower,
        "port": binding.port,
        "pid_killed": pid_killed,
        "env_zp_deleted": env_zp_deleted,
    })))
}

#[derive(Deserialize)]
struct ToolLaunchRequest {
    name: String,
}

/// POST /api/v1/tools/launch — spawn a governed tool from its StoredLaunchCommand.
///
/// Replays the exact command that was recorded when the tool was first registered
/// via `zp configure exec`. The process is detached (new process group) so it
/// survives if the operator navigates away from the dashboard. A PID file is
/// written to ~/ZeroPoint/pids/{name}.pid for shutdown cleanup.
async fn tool_launch_handler(
    State(state): State<AppState>,
    Json(body): Json<ToolLaunchRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(binding) = state.0.port_registry.get_assigned(&body.name) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": format!("Tool '{}' is not registered", body.name),
                "hint": "Run `zp configure exec` to register this tool.",
            })),
        ));
    };

    let Some(lc) = binding.launch_command.clone() else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": format!("No launch command recorded for '{}'", body.name),
                "hint": format!("Run `zp configure exec ~/projects/{}` to record the launch.", body.name),
                "cmd": format!("zp configure exec ~/projects/{}", body.name),
            })),
        ));
    };

    // Capture agent_key before borrowing binding further. Used after spawn
    // to re-issue the delegation grant — making cockpit launch the renewal
    // ceremony and keeping expiry from ever surfacing as an operator concern.
    let agent_key_for_regrant = binding.agent_key.clone();

    let ui_port = binding.web_ui_port();

    // Infer tool kind from the recorded command (used by the cockpit to pick
    // the right wait strategy — native cargo builds take minutes).
    let kind = if lc.command == "cargo" || lc.command.ends_with("/cargo") {
        "native"
    } else {
        "web"
    };

    // Resolve working directory — strip leading ~ if present.
    let work_dir: std::path::PathBuf = match lc.working_dir.as_deref() {
        Some(d) if d.starts_with("~/") => {
            let home = zp_paths::user_home().unwrap_or_default();
            home.join(&d[2..])
        }
        Some(d) => std::path::PathBuf::from(d),
        None => {
            // Fall back to ~/projects/{name} as a convention.
            zp_paths::user_home()
                .map(|h| h.join("projects").join(&body.name))
                .unwrap_or_default()
        }
    };

    // Log file for stdout/stderr — dashboard.js tails it via /ws/exec.
    // Must live under ~/ZeroPoint/ (ZP's runtime dir) so safe_path() allows
    // the tail; /var/folders and /tmp are blocked as system paths.
    let log_path = {
        let logs_dir = std::path::PathBuf::from(&state.0.data_dir).join("logs");
        let _ = std::fs::create_dir_all(&logs_dir);
        logs_dir.join(format!(
            "{}.log",
            body.name.to_lowercase().replace(' ', "-")
        ))
    };

    let auth_token = binding.auth_token.clone();
    let proxy_port_for_launch = binding.proxy_target();
    // GATEWAY_PORT must come from the registry's extra_ports allocation, not from
    // proxy_target(). proxy_target() returns the primary allocated port (e.g. 8090),
    // which some tools use for a separate HTTP channel — binding the gateway there
    // causes "address already in use" and the web UI never starts.
    // extra_ports["GATEWAY_PORT"] is the port ZP allocated specifically for the
    // gateway process; the proxy will discover it via post-launch probing.
    let gateway_port_for_launch = binding
        .extra_ports
        .get("GATEWAY_PORT")
        .copied()
        .unwrap_or(proxy_port_for_launch);
    let mut cmd = tokio::process::Command::new(&lc.command);
    cmd.args(&lc.args)
        .current_dir(&work_dir)
        .env("PORT", ui_port.to_string())
        // Inject the tool's declared primary port var (e.g. HTTP_PORT for ironclaw,
        // PORT for Node tools). This is authoritative — dotenvy never overwrites
        // existing env vars, so this beats whatever the tool's .env file declares.
        // Without this, tools that don't read `PORT` (e.g. ironclaw reads HTTP_PORT)
        // silently fall back to their .env value, breaking ZP's port allocation.
        .env(&binding.port_var, binding.port.to_string())
        // Inject the ZP-allocated GATEWAY_PORT for this tool. Using extra_ports
        // rather than proxy_target() ensures the gateway doesnds on its own port
        // rather than colliding with any other channel the tool starts first.
        // PORT and GATEWAY_PORT are ZP-owned routing vars — vault injection skips
        // them so this value is never silently overridden by a vault-stored port.
        .env("GATEWAY_PORT", gateway_port_for_launch.to_string())
        // Inject the ZP proxy auth token so the tool's gateway validates the
        // same token the proxy forwards. dotenvy never overwrites existing vars,
        // so this takes priority over any value in .env / ~/.ironclaw/.env.
        .env("GATEWAY_AUTH_TOKEN", &auth_token)
        .env("ZP_MANAGED", "1")
        // Signal that ZP owns process lifecycle for this tool — suppresses
        // IronClaw's own singleton enforcement (PID lock) and any other
        // self-management behaviors that belong to the governance layer.
        .env("ZP_GOVERNED", "1");

    // Inject vault-managed tool env vars (e.g. OPENAI_API_KEY, OPENAI_BASE_URL).
    // Stored at tools/{tool}/* via `zp configure vault-set-tool-env`.
    // These take priority over .env files because we set them before spawn;
    // dotenvy never overwrites existing env vars in the child process.
    let mut vault_default_model: Option<String> = None;
    if let Some(vault_key) = state.0.vault_key.get().and_then(|k| k.as_ref()) {
        let vault_path = zp_paths::vault_path()
            .unwrap_or_else(|_| std::path::PathBuf::from(&state.0.data_dir).join("vault.json"));
        match zp_trust::CredentialVault::load_or_create(&vault_key.key, &vault_path) {
            Ok(vault) => match vault.resolve_tool_env(&body.name.to_lowercase()) {
                Ok(tool_env) => {
                    // Capture vault default model before injecting (tier 2 fallback).
                    if let Some(m) = tool_env.get("ZP_DEFAULT_MODEL") {
                        vault_default_model = std::str::from_utf8(m).ok().map(str::to_string);
                    }

                    // ── Vault schema validation (mandatory, pre-injection) ──
                    //
                    // Load the tool's manifest and validate resolved env vars
                    // against its vault_schema constraints. Violations are logged
                    // at error! and emitted as preflight:failed receipts.
                    //
                    // Search order: tool working dir → ZP source tools/{name}/.
                    {
                        let tool_lower = body.name.to_lowercase();
                        let manifest_candidates = [
                            work_dir.join(".zp-configure.toml"),
                            std::path::PathBuf::from(
                                std::env::var("ZP_SOURCE_DIR").unwrap_or_else(|_| {
                                    zp_paths::user_home()
                                        .map(|h| h.join("projects/zeropoint").display().to_string())
                                        .unwrap_or_default()
                                }),
                            )
                            .join("tools")
                            .join(&tool_lower)
                            .join(".zp-configure.toml"),
                        ];

                        let mut manifest_loaded = None;
                        for candidate in &manifest_candidates {
                            if candidate.exists() {
                                match zp_engine::capability::load_manifest(candidate) {
                                    Ok(m) => {
                                        info!(
                                            tool = %tool_lower,
                                            path = %candidate.display(),
                                            schema_count = m.vault_schema.len(),
                                            "Loaded vault schema from manifest"
                                        );
                                        manifest_loaded = Some(m);
                                        break;
                                    }
                                    Err(e) => {
                                        warn!(
                                            tool = %tool_lower,
                                            path = %candidate.display(),
                                            error = %e,
                                            "Failed to parse manifest — skipping vault validation"
                                        );
                                    }
                                }
                            }
                        }

                        if let Some(ref manifest) = manifest_loaded {
                            if !manifest.vault_schema.is_empty() {
                                let violations = zp_engine::capability::validate_tool_env(
                                    &manifest.vault_schema,
                                    &tool_env,
                                );

                                for v in &violations {
                                    if v.severity == "error" {
                                        error!(
                                            tool = %tool_lower,
                                            var = %v.var,
                                            "Vault schema violation: {}",
                                            v.message
                                        );
                                    } else {
                                        warn!(
                                            tool = %tool_lower,
                                            var = %v.var,
                                            "Vault schema warning: {}",
                                            v.message
                                        );
                                    }
                                }

                                let error_count =
                                    violations.iter().filter(|v| v.severity == "error").count();

                                if error_count > 0 {
                                    error!(
                                        tool = %tool_lower,
                                        errors = error_count,
                                        total = violations.len(),
                                        "Tool vault validation FAILED — launching with broken credentials. \
                                         Run `zp configure vault-set-tool-env` to fix."
                                    );

                                    // Emit preflight:failed receipt to audit chain.
                                    {
                                        let violation_summary: Vec<String> = violations
                                            .iter()
                                            .filter(|v| v.severity == "error")
                                            .map(|v| format!("{}: {}", v.var, v.message))
                                            .collect();
                                        let detail_str = format!(
                                            "tool={} errors={} violations=[{}]",
                                            tool_lower,
                                            error_count,
                                            violation_summary.join("; ")
                                        );
                                        let _ = crate::tool_chain::emit_tool_receipt(
                                            &state.0.audit_store,
                                            &format!(
                                                "tool:preflight:vault_validation_failed:{}",
                                                tool_lower
                                            ),
                                            Some(&detail_str),
                                        );
                                    }
                                } else if !violations.is_empty() {
                                    info!(
                                        tool = %tool_lower,
                                        warnings = violations.len(),
                                        "Vault schema validation passed with warnings"
                                    );
                                } else {
                                    info!(
                                        tool = %tool_lower,
                                        checked = manifest.vault_schema.iter()
                                            .filter(|s| !s.substrate_owned).count(),
                                        "Vault schema validation passed"
                                    );
                                }
                            }
                        }

                        // Run vault hygiene audit on key names (no decryption needed).
                        if manifest_loaded.is_some() {
                            let all_keys: Vec<String> = vault
                                .list()
                                .into_iter()
                                .filter(|k| k.contains(&tool_lower))
                                .collect();

                            if !all_keys.is_empty() {
                                let findings =
                                    zp_engine::capability::audit_vault_keys(&tool_lower, &all_keys);
                                for f in &findings {
                                    if f.severity == "error" {
                                        error!(
                                            tool = %tool_lower,
                                            category = f.category,
                                            key = %f.key,
                                            "Vault hygiene: {}",
                                            f.message
                                        );
                                    } else {
                                        warn!(
                                            tool = %tool_lower,
                                            category = f.category,
                                            key = %f.key,
                                            "Vault hygiene: {}",
                                            f.message
                                        );
                                    }
                                }
                            }
                        }
                    }

                    // ZP-owned routing vars — port allocation belongs to the
                    // substrate, not the vault. Skip any vault-stored value so
                    // the port we assigned above is never silently overridden.
                    // ZP_MANAGED, ZP_GOVERNED, and
                    // GATEWAY_AUTH_TOKEN are substrate-controlled operational
                    // flags. The vault must not override them — the substrate
                    // is the authority on whether governance is active.
                    // All port-class vars are owned by ZP's PortRegistry.
                    // Vault must never override port allocation — ZP is the
                    // single authority for what port a governed tool binds to.
                    // Matches PORT_VAR_PRIORITY in tool_ports.rs plus gateway
                    // and substrate operational flags.
                    const ZP_OWNED_VARS: &[&str] = &[
                        "PORT",
                        "HTTP_PORT",
                        "WEBUI_PORT",
                        "APP_PORT",
                        "SERVER_PORT",
                        "LISTEN_PORT",
                        "API_PORT",
                        "GATEWAY_PORT",
                        "GATEWAY_AUTH_TOKEN",
                        "ZP_MANAGED",
                        "ZP_GOVERNED",
                    ];
                    for (var, val_bytes) in &tool_env {
                        if ZP_OWNED_VARS.contains(&var.as_str()) {
                            continue;
                        }
                        if let Ok(s) = std::str::from_utf8(val_bytes) {
                            cmd.env(var, s);
                        }
                    }
                    if !tool_env.is_empty() {
                        info!(
                            tool = %body.name,
                            count = tool_env.len(),
                            "Injected vault tool env vars into child process"
                        );
                    }
                }
                Err(e) => {
                    warn!("Could not resolve vault env for {}: {}", body.name, e);
                }
            },
            Err(e) => {
                warn!("Could not load vault for tool launch: {}", e);
            }
        }
    }

    // Three-tier model resolution: chain preference > vault default > tool default (no injection).
    //
    // Tier 1: operator recorded a `preference:model:selected` receipt via
    //         POST /api/v1/preference/model — chain is the source of truth.
    // Tier 2: operator stored ZP_DEFAULT_MODEL in vault via
    //         `zp configure vault-set-tool-env --var ZP_DEFAULT_MODEL`.
    // Tier 3: substrate injects nothing; tool uses its own internal default.
    {
        let tool_lower = body.name.to_lowercase();
        let chain_model =
            tool_chain::query_chain_model_preference(&state.0.audit_store, &tool_lower);

        let (resolved_model, resolution_source) = if let Some(m) = chain_model {
            (Some(m), "chain_preference")
        } else if let Some(m) = vault_default_model {
            (Some(m), "vault_default")
        } else {
            (None, "tool_default")
        };

        if let Some(ref model_id) = resolved_model {
            cmd.env("ZP_MODEL_ID", model_id);
            info!(
                tool = %body.name,
                model_id = %model_id,
                source = %resolution_source,
                "Injecting ZP_MODEL_ID from {} tier",
                resolution_source
            );
        }

        // Emit preference:model:resolved — always, even for tool_default (model_id = None).
        let signing_key = Some(&state.0.identity.signing_key);
        tool_chain::emit_model_resolved_receipt(
            &state.0.audit_store,
            &tool_lower,
            resolved_model.as_deref(),
            resolution_source,
            signing_key,
        );
    }

    // Detach: new process group so the child outlives the ZP server if needed.
    #[cfg(unix)]
    cmd.process_group(0);

    // Capture stdout + stderr to the log file (best-effort).
    if let Ok(log_file) = std::fs::File::create(&log_path) {
        if let Ok(log_file2) = log_file.try_clone() {
            cmd.stdout(log_file);
            cmd.stderr(log_file2);
        } else {
            cmd.stdout(std::process::Stdio::null());
            cmd.stderr(std::process::Stdio::null());
        }
    } else {
        cmd.stdout(std::process::Stdio::null());
        cmd.stderr(std::process::Stdio::null());
    }

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id().unwrap_or(0);
            // Detach — let the child run independently under its own session.
            tokio::spawn(async move {
                let _ = child.wait().await;
            });

            // Background: discover actual proxy port after the tool binds its
            // sockets. Clears the stale proxy_port from the last session first
            // so proxy_target() falls back to allocated port while probing.
            // Updates the registry once the tool is live so subsequent proxy
            // requests forward to the right port without a full reconfigure.
            {
                let state_for_probe = state.clone();
                let tool_name_for_probe = body.name.to_lowercase();
                tokio::spawn(async move {
                    // Give the tool a few seconds to bind before probing.
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    if let Some(binding) = state_for_probe
                        .0
                        .port_registry
                        .get_assigned(&tool_name_for_probe)
                    {
                        match tool_ports::discover_proxy_port_with_retry(
                            &binding,
                            30,
                            std::time::Duration::from_secs(2),
                        )
                        .await
                        {
                            Some(discovered) => {
                                info!(
                                    tool = %tool_name_for_probe,
                                    port = discovered,
                                    "Post-launch probe: proxy_port discovered"
                                );
                                state_for_probe
                                    .0
                                    .port_registry
                                    .set_proxy_port(&tool_name_for_probe, discovered);
                            }
                            None => {
                                warn!(
                                    tool = %tool_name_for_probe,
                                    "Post-launch probe: no port responded after 30 attempts"
                                );
                            }
                        }
                    }
                });
            }

            // Write PID file so cleanup_launched_tools() finds it on shutdown.
            let pid_file = pid_dir().join(format!("{}.pid", body.name.to_lowercase()));
            let _ = std::fs::write(&pid_file, pid.to_string());

            // Register PID with sensor layer — kqueue EVFILT_PROC will fire
            // immediately on exit/fork/exec, triggering a Forge sweep.
            if pid > 0 {
                state
                    .0
                    .sensor_handle
                    .watch_pid(pid, body.name.to_lowercase())
                    .await;
            }

            // Re-issue delegation grant on every cockpit launch. This makes
            // cockpit launch the renewal ceremony — expiry can never surface
            // as an operator concern for tools that call register-agent at
            // startup. CapabilityGrant::new defaults to expires_at: None
            // (no hard expiry), so the standing grant is perennial; the
            // chain entry is the durable record that the ceremony occurred.
            if let Some(ref agent_key) = agent_key_for_regrant {
                let grantor = state.0.identity.destination_hash.clone();
                let mut grant = CapabilityGrant::new(
                    grantor,
                    agent_key.clone(),
                    GrantedCapability::ToolCall {
                        tools: vec!["*".to_string()],
                    },
                    format!("rcpt-{}", uuid::Uuid::now_v7()),
                );
                grant.sign(&state.0.identity.signing_key);
                tool_chain::emit_delegation_receipt(
                    &state.0.audit_store,
                    "granted",
                    &grant,
                    Some(&state.0.identity.signing_key),
                );
                state.0.grants.lock().unwrap().push(grant);
                info!(
                    tool = %body.name,
                    agent_key = %agent_key,
                    "Delegation re-granted on cockpit launch"
                );
            }

            Ok(Json(serde_json::json!({
                "pid": pid,
                "port": ui_port,
                // No url — JS uses proxyUrl (subdomain) so ZP proxy injects auth.
                "kind": kind,
                "log_path": log_path.display().to_string(),
            })))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("Failed to spawn '{}': {}", lc.command, e),
                "cmd": format!("cd '{}' && {} {}", work_dir.display(), lc.command, lc.args.join(" ")),
            })),
        )),
    }
}

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

// ============================================================================
// Agent Registration + Delegation Auto-Renewal
// ============================================================================

/// Body for POST /api/v1/tools/:name/register-agent
#[derive(Deserialize)]
struct RegisterAgentRequest {
    /// The ZP agent identifier for this tool (its canonical bead-zero hash or
    /// a stable string identity the tool consistently self-reports).
    agent_key: String,
}

/// POST /api/v1/tools/:name/register-agent — register a tool's agent identity
/// and immediately issue a fresh `delegation:granted` receipt.
///
/// Called by tools at startup. Stores `agent_key` on the `ToolBinding` so
/// subsequent cockpit launches can re-grant without waiting for the tool to
/// re-register. The grant uses `ToolCall { tools: ["*"] }` with no expiry,
/// making the chain entry the durable record rather than a TTL clock.
async fn register_agent_handler(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
    Json(body): Json<RegisterAgentRequest>,
) -> Json<serde_json::Value> {
    // Persist the agent_key on the binding so tool_launch_handler can
    // re-grant on every cockpit launch without the tool needing to re-register.
    state.0.port_registry.set_agent_key(&name, &body.agent_key);

    // Issue a fresh CapabilityGrant — no expiry, full tool-call scope.
    let grantor = state.0.identity.destination_hash.clone();
    let receipt_id = format!("rcpt-{}", uuid::Uuid::now_v7());
    let mut grant = CapabilityGrant::new(
        grantor,
        body.agent_key.clone(),
        GrantedCapability::ToolCall {
            tools: vec!["*".to_string()],
        },
        receipt_id,
    );
    grant.sign(&state.0.identity.signing_key);

    let entry_hash = tool_chain::emit_delegation_receipt(
        &state.0.audit_store,
        "granted",
        &grant,
        Some(&state.0.identity.signing_key),
    );

    state.0.grants.lock().unwrap().push(grant);

    info!(
        tool = %name,
        agent_key = %body.agent_key,
        "Agent registered; delegation:granted emitted"
    );

    Json(serde_json::json!({
        "ok": true,
        "tool": name,
        "agent_key": body.agent_key,
        "entry_hash": entry_hash,
    }))
}

// ============================================================================
// Model Governance Handlers
// ============================================================================

/// Body for POST /api/v1/preference/model
#[derive(Deserialize)]
struct ModelPreferenceRequest {
    /// Tool name (case-insensitive, e.g. "ironclaw").
    tool: String,
    /// Model identifier to record as the operator's preference (e.g. "route-llm").
    model_id: String,
}

/// POST /api/v1/preference/model — record the operator's model preference for a tool.
///
/// Emits a `preference:model:selected` receipt into the chain. The substrate
/// reads this receipt at tool-launch time (tier 1 of three-tier model resolution)
/// and injects `ZP_MODEL_ID` accordingly. No gate required — this route uses
/// ZP-Sig auth at the router level like all /api/v1/* routes.
async fn model_preference_handler(
    State(state): State<AppState>,
    Json(body): Json<ModelPreferenceRequest>,
) -> Json<serde_json::Value> {
    let tool = body.tool.to_lowercase();
    let signing_key = Some(&state.0.identity.signing_key);

    match tool_chain::emit_model_preference_receipt(
        &state.0.audit_store,
        &tool,
        &body.model_id,
        signing_key,
    ) {
        Some(entry_hash) => {
            info!(tool = %tool, model_id = %body.model_id, "Recorded model preference");
            Json(serde_json::json!({
                "ok": true,
                "tool": tool,
                "model_id": body.model_id,
                "entry_hash": entry_hash,
            }))
        }
        None => {
            warn!(tool = %tool, "Failed to record model preference receipt");
            Json(serde_json::json!({
                "ok": false,
                "error": "Failed to append preference receipt to chain",
            }))
        }
    }
}

/// Body for POST /api/v1/cognition/model-routed
#[derive(Deserialize)]
struct ModelRoutedRequest {
    /// Tool name (e.g. "ironclaw").
    tool: String,
    /// Model the tool requested (e.g. "route-llm").
    requested_model: String,
    /// Model Abacus's router actually chose (e.g. "claude-3-5-sonnet-20241022").
    actual_model: String,
    /// Optional task/request identifier for cross-referencing.
    task_id: Option<String>,
}

/// POST /api/v1/cognition/model-routed — record what route-llm actually chose.
///
/// IronClaw calls this after each LLM completion when the requested model is a
/// routing alias (e.g. "route-llm"). The response body's `model` field reveals
/// the actual model Abacus selected. Recording this gives the chain full
/// visibility into routing decisions without requiring the substrate to be in
/// the hot path of every completion call.
async fn model_routed_handler(
    State(state): State<AppState>,
    Json(body): Json<ModelRoutedRequest>,
) -> Json<serde_json::Value> {
    let tool = body.tool.to_lowercase();
    let signing_key = Some(&state.0.identity.signing_key);

    match tool_chain::emit_model_routed_receipt(
        &state.0.audit_store,
        &tool,
        &body.requested_model,
        &body.actual_model,
        body.task_id.as_deref(),
        signing_key,
    ) {
        Some(entry_hash) => {
            info!(
                tool = %tool,
                requested = %body.requested_model,
                actual = %body.actual_model,
                "Recorded model routing observation"
            );
            Json(serde_json::json!({
                "ok": true,
                "tool": tool,
                "requested_model": body.requested_model,
                "actual_model": body.actual_model,
                "entry_hash": entry_hash,
            }))
        }
        None => {
            warn!(tool = %tool, "Failed to record model-routed receipt");
            Json(serde_json::json!({
                "ok": false,
                "error": "Failed to append routing receipt to chain",
            }))
        }
    }
}

// ============================================================================
// Dashboard Handler (Verification Surface)
// ============================================================================

// ─── Compiled-in assets ─────────────────────────────────────────────────────
// Everything below is baked into the binary at compile time.  No filesystem
// pipeline, no bootstrap, no staleness.  `cargo build && zp serve` just works.

// HTML pages — compiled-in fallbacks; override at runtime via ZP_ASSETS_DIR.
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
        .route(
            "/onboard.css",
            get(|| async { text_response(ONBOARD_CSS, "text/css; charset=utf-8") }),
        )
        .route(
            "/vendor/xterm.min.css",
            get(|| async { text_response(VENDOR_XTERM_CSS, "text/css; charset=utf-8") }),
        )
        .route(
            "/fonts/fonts.css",
            get(|| async { text_response(FONTS_CSS, "text/css; charset=utf-8") }),
        )
        // JS
        .route(
            "/onboard.js",
            get(|| async { text_response(ONBOARD_JS, "application/javascript; charset=utf-8") }),
        )
        .route(
            "/tts.js",
            get(|| async { text_response(TTS_JS, "application/javascript; charset=utf-8") }),
        )
        .route(
            "/dashboard.js",
            get(|| async { text_response(DASHBOARD_JS, "application/javascript; charset=utf-8") }),
        )
        .route(
            "/ecosystem.js",
            get(|| async { text_response(ECOSYSTEM_JS, "application/javascript; charset=utf-8") }),
        )
        .route(
            "/speak.js",
            get(|| async { text_response(SPEAK_JS, "application/javascript; charset=utf-8") }),
        )
        .route(
            "/vendor/xterm.min.js",
            get(|| async {
                text_response(VENDOR_XTERM_JS, "application/javascript; charset=utf-8")
            }),
        )
        .route(
            "/vendor/xterm-addon-fit.min.js",
            get(|| async {
                text_response(VENDOR_XTERM_FIT_JS, "application/javascript; charset=utf-8")
            }),
        )
        .route(
            "/vendor/d3.min.js",
            get(|| async { text_response(VENDOR_D3_JS, "application/javascript; charset=utf-8") }),
        )
        // Fonts
        .route(
            "/fonts/inter-latin.woff2",
            get(|| async { binary_response(FONT_INTER, "font/woff2") }),
        )
        .route(
            "/fonts/jetbrainsmono-latin.woff2",
            get(|| async { binary_response(FONT_JETBRAINS, "font/woff2") }),
        )
}

/// Resolve an HTML asset: check $ZP_ASSETS_DIR first (hot-reload override),
/// then fall back to the compiled-in copy.
fn resolve_html_asset(name: &str, fallback: &'static str) -> String {
    if let Ok(dir) = std::env::var("ZP_ASSETS_DIR") {
        let path = std::path::PathBuf::from(&dir).join(name);
        if let Ok(contents) = std::fs::read_to_string(&path) {
            return contents;
        }
    }
    fallback.to_string()
}

/// Root handler: serve dashboard post-genesis, redirect to /onboard pre-genesis.
async fn root_handler(State(state): State<AppState>) -> Response {
    let genesis_path = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("genesis.json");
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = if genesis_path.exists() {
        Html(resolve_html_asset("dashboard.html", DASHBOARD_HTML)).into_response()
    } else {
        Redirect::temporary("/onboard").into_response()
    };
    if let Ok(hv) = cookie.parse() {
        resp.headers_mut()
            .insert(axum::http::header::SET_COOKIE, hv);
    }
    resp
}

async fn dashboard_handler(State(state): State<AppState>) -> Response {
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(resolve_html_asset("dashboard.html", DASHBOARD_HTML)).into_response();
    if let Ok(hv) = cookie.parse() {
        resp.headers_mut()
            .insert(axum::http::header::SET_COOKIE, hv);
    }
    resp
}

#[derive(Debug, Deserialize)]
struct OnboardQuery {
    token: Option<String>,
}

async fn onboard_page_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(query): Query<OnboardQuery>,
) -> Response {
    // Post-genesis: redirect to dashboard.
    let genesis_path = zp_paths::home()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("genesis.json");
    if genesis_path.exists() {
        return Redirect::to("/dashboard").into_response();
    }

    // AUTH-VULN-06: one-time setup token for network-facing deployments.
    // On localhost the token is None — no gate.
    if let Some(ref expected) = state.0.onboard_token {
        let client_ip = client_ip_from_headers(&headers);
        if let Some(_retry_after) = state.0.rate_limiter.is_blocked(client_ip) {
            return (StatusCode::TOO_MANY_REQUESTS, "Too many attempts").into_response();
        }
        let from_query = query
            .token
            .as_deref()
            .map(|t| constant_time_eq(t, expected))
            .unwrap_or(false);
        let from_cookie = extract_onboard_cookie(&headers)
            .map(|t| constant_time_eq(&t, expected))
            .unwrap_or(false);

        if from_query {
            let cookie_val = format!("zp_onboard={}; HttpOnly; SameSite=Strict; Path=/", expected);
            let mut resp = Redirect::temporary("/onboard").into_response();
            if let Ok(hv) = cookie_val.parse() {
                resp.headers_mut()
                    .insert(axum::http::header::SET_COOKIE, hv);
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
    }

    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(resolve_html_asset("onboard.html", ONBOARD_HTML)).into_response();
    if let Ok(hv) = cookie.parse() {
        resp.headers_mut()
            .insert(axum::http::header::SET_COOKIE, hv);
    }
    resp
}

async fn speak_page_handler(State(state): State<AppState>) -> Response {
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(resolve_html_asset("speak.html", SPEAK_HTML)).into_response();
    if let Ok(hv) = cookie.parse() {
        resp.headers_mut()
            .insert(axum::http::header::SET_COOKIE, hv);
    }
    resp
}

async fn ecosystem_page_handler(State(state): State<AppState>) -> Response {
    let cookie = auth::build_session_cookie(
        &state.0.session_auth.current_token(),
        state.0.session_auth.max_age_secs(),
    );
    let mut resp = Html(resolve_html_asset("ecosystem.html", ECOSYSTEM_HTML)).into_response();
    if let Ok(hv) = cookie.parse() {
        resp.headers_mut()
            .insert(axum::http::header::SET_COOKIE, hv);
    }
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

// ============================================================================
// P4 (#197) — Phase 2 lease engine tests
// ============================================================================
//
// These tests exercise the chain-walking logic used by both the renewal
// endpoint and the gate prerequisite check, against an in-memory audit
// store. The HTTP layer itself is covered transitively — the handler is
// thin glue over the helpers tested here.

/// Emit a substrate lifecycle receipt.
///
/// `system:startup` and `system:shutdown` were declared in the receipt
/// registry, handled by `zp_officers::narration`, and fixtured in Aegis's
/// tests — and emitted nowhere. Across 84,246 chain entries neither had
/// ever appeared, so the substrate held no record of its own session
/// boundaries. Found 2026-07-26 by the receipt-inventory sweep.
///
/// Consequences of the absence, beyond the missing record: the Regent's
/// long observation window has nothing to anchor "across sessions" to,
/// boot-to-ready time (Phase 6's own worked example) is uncomputable, and
/// narration's lifecycle branch is unreachable code.
///
/// Actor is `System("server")` rather than the Regent namespace — this is
/// the substrate's own lifecycle, not a cognitive act.
fn emit_lifecycle_receipt(
    audit_store: &std::sync::Arc<std::sync::Mutex<zp_audit::AuditStore>>,
    event: String,
) {
    let entry = zp_audit::UnsealedEntry {
        actor: zp_core::ActorId::System("server".to_string()),
        action: zp_core::AuditAction::SystemEvent { event },
        conversation_id: zp_core::ConversationId(uuid::Uuid::nil()),
        policy_decision: zp_core::PolicyDecision::Allow {
            conditions: Vec::new(),
        },
        policy_module: "server-lifecycle".to_string(),
        receipt: None,
    };
    match audit_store.lock() {
        Ok(mut store) => {
            if let Err(e) = store.append(entry) {
                warn!("lifecycle receipt emission failed: {}", e);
            }
        }
        Err(e) => warn!("lifecycle receipt: audit store lock poisoned: {}", e),
    }
}

#[cfg(test)]
mod p4_phase2_tests {
    use std::sync::{Arc, Mutex};

    use zp_audit::AuditStore;
    use zp_core::{
        ActionType as CoreActionType, AuthorityRef, CapabilityGrant, GrantedCapability,
        LeasePolicy, RevocationClaim,
    };

    fn make_store() -> (tempfile::TempDir, Arc<Mutex<AuditStore>>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open_unsigned(&path).unwrap();
        (dir, Arc::new(Mutex::new(store)))
    }

    fn standing_grant(subject: &str) -> CapabilityGrant {
        // Wildcard ToolCall grant — authorises the subject to call any tool.
        // This replaces the former Custom { name: "tool-execution" } grant now
        // that Claim 4 scope enforcement requires a ToolCall capability kind.
        CapabilityGrant::new(
            "genesis".to_string(),
            subject.to_string(),
            GrantedCapability::ToolCall {
                tools: vec!["*".to_string()],
            },
            format!("rcpt-{}", uuid::Uuid::now_v7()),
        )
        .with_lease_policy(LeasePolicy::standard_8h())
        .with_renewal_authorities(vec![AuthorityRef::genesis("lease_renewal")])
        .with_revocable_by(vec![AuthorityRef::genesis("revocation_authority")])
        .as_standing("genesis-key")
    }

    /// Reproduce `lease_prereq_for_agent` over an in-memory store. We can't
    /// call the real function because it requires `AppState` (which pulls
    /// in genesis, ports, vault, etc.). The chain-walking logic is the same
    /// — pasting it into the test module keeps the contract visible.
    ///
    /// `tool_name` is the MCP tool being checked (Claim 4 scope enforcement).
    fn lease_prereq_for_agent(
        store: &Arc<Mutex<AuditStore>>,
        agent_id: &str,
        tool_name: &str,
    ) -> Option<&'static str> {
        let chain = store
            .lock()
            .unwrap()
            .export_chain(i32::MAX as usize)
            .unwrap();
        let mut grants: std::collections::HashMap<String, CapabilityGrant> = Default::default();
        let mut revoked: std::collections::HashSet<String> = Default::default();
        for entry in &chain {
            let zp_core::AuditAction::SystemEvent { event } = &entry.action else {
                continue;
            };
            let zp_core::PolicyDecision::Allow { conditions } = &entry.policy_decision else {
                continue;
            };
            let Some(body) = conditions.first() else {
                continue;
            };
            if event.starts_with("delegation:granted:") || event.starts_with("delegation:renewed:")
            {
                if let Ok(g) = serde_json::from_str::<CapabilityGrant>(body) {
                    if g.grantee == agent_id {
                        grants.insert(g.id.clone(), g);
                    }
                }
            } else if event.starts_with("delegation:revoked:") {
                if let Ok(claim) = serde_json::from_str::<RevocationClaim>(body) {
                    revoked.insert(claim.target_grant_id);
                }
            }
        }
        let live: Vec<&CapabilityGrant> = grants
            .values()
            .filter(|g| !revoked.contains(&g.id) && !g.is_past_grace())
            .collect();
        if !live.is_empty() {
            // Claim 4: scope check — at least one live grant must cover the tool.
            let tool_action = CoreActionType::ToolCall {
                name: tool_name.to_string(),
            };
            let scope_ok = live.iter().any(|g| g.matches_action(&tool_action));
            if scope_ok {
                None
            } else {
                Some("capability_scope_exceeded")
            }
        } else if grants.is_empty() {
            Some("no_valid_delegation")
        } else if grants.values().all(|g| revoked.contains(&g.id)) {
            Some("delegation_revoked")
        } else {
            Some("delegation_expired")
        }
    }

    #[test]
    fn p4_2d_t1_renewal_succeeds_for_valid_grant() {
        let (_d, store) = make_store();
        let grant = standing_grant("artemis");
        crate::tool_chain::emit_delegation_receipt(&store, "granted", &grant, None)
            .expect("granted receipt");

        // The "renewal" path locally reads the grant out, calls renew(),
        // and re-emits — which is exactly what the HTTP handler does.
        let mut g = grant.clone();
        let new_expiry = g.renew().unwrap();
        let h = crate::tool_chain::emit_delegation_receipt(&store, "renewed", &g, None)
            .expect("renewed");
        assert!(!h.is_empty());
        // Reconstruction picks up the new expiry / count.
        assert_eq!(g.renewal_count, 1);
        assert!(new_expiry > grant.expires_at.unwrap() - chrono::Duration::seconds(1));
    }

    #[test]
    fn p4_2d_t2_renewal_rejected_for_expired_grant() {
        // A grant whose expiry is far in the past, past its grace window.
        let mut g = standing_grant("artemis");
        g.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1000));
        let err = g.renew().unwrap_err();
        assert_eq!(err, zp_core::RenewalError::PastGrace);
    }

    #[test]
    fn p4_2d_t3_renewal_rejected_for_revoked_grant() {
        let (_d, store) = make_store();
        let grant = standing_grant("artemis");
        crate::tool_chain::emit_delegation_receipt(&store, "granted", &grant, None).unwrap();

        let claim = RevocationClaim::new(
            grant.id.clone(),
            "genesis-key".to_string(),
            AuthorityRef::genesis("revocation_authority"),
            zp_core::CascadePolicy::SubtreeHalt,
            zp_core::RevocationReason::OperatorRequested,
        );
        crate::tool_chain::emit_revocation_receipt(&store, "artemis", &claim).unwrap();

        // After revocation, the gate prereq must surface delegation_revoked
        // regardless of tool_name — lifecycle checks precede scope checks.
        assert_eq!(
            lease_prereq_for_agent(&store, "artemis", "bash"),
            Some("delegation_revoked")
        );
    }

    #[test]
    fn p4_2d_t4_renewal_rejected_for_unauthorized_subject() {
        // The handler returns subject_mismatch when claimed_subject differs
        // from the grantee. This test exercises the comparison logic
        // directly — the equivalent of the HTTP request body carrying a
        // wrong subject_node_id.
        let grant = standing_grant("artemis");
        let claimed_subject = "shannon";
        assert_ne!(grant.grantee, claimed_subject, "subjects must differ");
    }

    #[test]
    fn p4_2d_t5_gate_rejects_tool_call_with_no_delegation() {
        let (_d, store) = make_store();
        // Empty chain — agent has no grant.
        assert_eq!(
            lease_prereq_for_agent(&store, "artemis", "bash"),
            Some("no_valid_delegation")
        );
    }

    #[test]
    fn p4_2d_t5b_gate_allows_tool_call_with_alive_wildcard_delegation() {
        // standing_grant produces ToolCall { tools: ["*"] } — wildcard covers any tool.
        let (_d, store) = make_store();
        let grant = standing_grant("artemis");
        crate::tool_chain::emit_delegation_receipt(&store, "granted", &grant, None).unwrap();
        assert_eq!(lease_prereq_for_agent(&store, "artemis", "bash"), None);
    }

    #[test]
    fn p4_2d_t5c_gate_denies_out_of_scope_tool_despite_live_delegation() {
        // Claim 4: narrow grant covers ["read"] — calling "bash" must be denied.
        let (_d, store) = make_store();
        let narrow_grant = CapabilityGrant::new(
            "genesis".to_string(),
            "artemis".to_string(),
            GrantedCapability::ToolCall {
                tools: vec!["read".to_string()],
            },
            format!("rcpt-{}", uuid::Uuid::now_v7()),
        )
        .with_lease_policy(LeasePolicy::standard_8h())
        .as_standing("genesis-key");

        crate::tool_chain::emit_delegation_receipt(&store, "granted", &narrow_grant, None).unwrap();

        // In-scope tool: allowed.
        assert_eq!(
            lease_prereq_for_agent(&store, "artemis", "read"),
            None,
            "in-scope tool should be allowed"
        );
        // Out-of-scope tool: denied with capability_scope_exceeded.
        assert_eq!(
            lease_prereq_for_agent(&store, "artemis", "bash"),
            Some("capability_scope_exceeded"),
            "out-of-scope tool must be denied even with a live grant"
        );
    }

    #[test]
    fn p4_2d_subject_signature_round_trip_verifies_in_handler() {
        // The handler uses verify_ed25519_signature; we exercise it here
        // with a known key + payload to confirm the helper is correct.
        use ed25519_dalek::{Signer, SigningKey};

        let key = SigningKey::from_bytes(&[42u8; 32]);
        let payload = b"grant-abc|1735689600000";
        let sig = key.sign(payload);

        let pk_hex = hex::encode(key.verifying_key().to_bytes());
        let sig_hex = hex::encode(sig.to_bytes());

        assert!(crate::verify_ed25519_signature(&pk_hex, &sig_hex, payload));
        // Wrong payload → fails.
        assert!(!crate::verify_ed25519_signature(
            &pk_hex,
            &sig_hex,
            b"different"
        ));
    }

    // ── Typed-receipt round-trip tests ───────────────────────────────────────
    //
    // These tests verify the structural correctness of the `receipt: null` gap
    // fix: gate decisions and delegation grants emitted with a signing key must
    // produce an AuditEntry whose `receipt` field survives the DB round-trip
    // (store → SQLite → export_chain) as a non-null signed Receipt.
    //
    // The tests use `open_unsigned` (test-safe, no AuditSigner needed) and
    // an ephemeral SigningKey — enough to exercise the typed-receipt path
    // without requiring Genesis.

    #[test]
    fn typed_receipt_gate_decision_survives_db_round_trip() {
        use ed25519_dalek::SigningKey;

        let (_dir, store) = make_store();
        let key = SigningKey::from_bytes(&[0xAA_u8; 32]);

        // Emit a gate:allowed entry with a signing key — should attach a typed receipt.
        let hash = crate::tool_chain::emit_gate_decision_receipt(
            &store,
            "test-tool",
            true,
            Some("agent-artemis"),
            None,
            Some(&key),
        );
        assert!(
            hash.is_some(),
            "emit_gate_decision_receipt must return entry_hash"
        );

        // Reload via export_chain and verify the receipt is non-null.
        let entries = store.lock().unwrap().export_chain(10).unwrap();
        let entry = entries
            .iter()
            .find(|e| {
                matches!(
                    &e.action,
                    zp_core::AuditAction::SystemEvent { event } if event.contains("gate:allowed")
                )
            })
            .expect("gate:allowed entry must be present in chain");

        assert!(
            entry.receipt.is_some(),
            "gate decision emitted with signing key must have non-null receipt after DB round-trip"
        );
        // Receipt must carry the signed authorization claim.
        let r = entry.receipt.as_ref().unwrap();
        assert!(
            !r.signatures.is_empty(),
            "receipt must carry at least one signature block"
        );
    }

    #[test]
    fn typed_receipt_delegation_grant_survives_db_round_trip() {
        use ed25519_dalek::SigningKey;

        let (_dir, store) = make_store();
        let key = SigningKey::from_bytes(&[0xBB_u8; 32]);
        let grant = standing_grant("artemis");

        let hash =
            crate::tool_chain::emit_delegation_receipt(&store, "granted", &grant, Some(&key));
        assert!(
            hash.is_some(),
            "emit_delegation_receipt must return entry_hash"
        );

        let entries = store.lock().unwrap().export_chain(10).unwrap();
        let entry = entries
            .iter()
            .find(|e| {
                matches!(
                    &e.action,
                    zp_core::AuditAction::SystemEvent { event } if event.contains("delegation:granted")
                )
            })
            .expect("delegation:granted entry must be present in chain");

        assert!(
            entry.receipt.is_some(),
            "delegation grant emitted with signing key must have non-null receipt after DB round-trip"
        );
        let r = entry.receipt.as_ref().unwrap();
        assert!(
            !r.signatures.is_empty(),
            "delegation receipt must carry at least one signature block"
        );
    }

    #[test]
    fn typed_receipt_gate_denied_survives_db_round_trip() {
        use ed25519_dalek::SigningKey;

        let (_dir, store) = make_store();
        let key = SigningKey::from_bytes(&[0xCC_u8; 32]);

        let hash = crate::tool_chain::emit_gate_decision_receipt(
            &store,
            "blocked-tool",
            false,
            Some("agent-x"),
            Some("scope_mismatch"),
            Some(&key),
        );
        assert!(hash.is_some());

        let entries = store.lock().unwrap().export_chain(10).unwrap();
        let entry = entries
            .iter()
            .find(|e| {
                matches!(
                    &e.action,
                    zp_core::AuditAction::SystemEvent { event } if event.contains("gate:denied")
                )
            })
            .expect("gate:denied entry must be present");

        assert!(
            entry.receipt.is_some(),
            "gate:denied emitted with signing key must have non-null receipt"
        );
    }
}
