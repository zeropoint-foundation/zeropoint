//! Capability-based resolution engine — the heart of MVC (Minimum Viable Credentials).
//!
//! Instead of matching raw env var names, this module thinks in abstract **capabilities**
//! that providers satisfy. A tool declares what capabilities it needs (via `.zp-configure.toml`),
//! and the engine resolves each one to whichever provider the user actually has keys for.
//!
//! ## Architecture
//!
//! ```text
//! .zp-configure.toml   →  ToolManifest (parsed)
//!                              ↓
//! CredentialVault       →  resolve_tool() → ResolvedTool
//! providers-default.toml       ↑               ↓
//!                        ProviderProfile    .env file
//! ```
//!
//! ## Confidence tiers
//!
//! - **High**: Manifest-declared capability, resolved to a provider with vault key
//! - **Medium**: Inferred capability or ambiguous provider selection
//! - **Low / NeedsAttention**: Engine hit its knowledge boundary — honest punt

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

// ============================================================================
// Capability enum
// ============================================================================

/// Abstract capability that a provider can satisfy.
///
/// The engine resolves tool requirements to providers by matching capabilities,
/// not env var names. This decouples "what does the tool need" from "how does
/// provider X expose its API key."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    // ── Language & Reasoning ─────────────────────────────────
    /// Frontier-class model for complex tasks
    ReasoningLlm,
    /// Lightweight model for high-volume, low-latency tasks
    FastLlm,
    /// Code-specialized model
    CodeLlm,
    /// 100K+ token context window
    LongContextLlm,

    // ── Vision & Image ───────────────────────────────────────
    /// Image understanding — OCR, scene description, visual Q&A
    Vision,
    /// Image creation from text prompts
    ImageGen,
    /// Inpainting, outpainting, style transfer on existing images
    ImageEdit,

    // ── Audio ────────────────────────────────────────────────
    /// Text-to-speech
    Tts,
    /// Automatic speech recognition / transcription
    Asr,
    /// Music and sound effect generation
    AudioGen,
    /// Voice cloning and custom voice synthesis
    VoiceClone,

    // ── Video & 3D ───────────────────────────────────────────
    /// Video generation from text or image prompts
    VideoGen,
    /// Video manipulation — trimming, compositing, style transfer
    VideoEdit,
    /// Video analysis — scene detection, temporal Q&A
    VideoUnderstanding,
    /// 3D model and scene generation
    #[serde(rename = "3d_gen")]
    ThreeDGen,

    // ── Retrieval & Search ───────────────────────────────────
    /// Vector embeddings for semantic search, RAG, clustering
    Embedding,
    /// Real-time web search
    WebSearch,
    /// Result reranking for improved retrieval precision
    Reranking,

    // ── Infrastructure ───────────────────────────────────────
    /// Relational database (PostgreSQL, MySQL, SQLite)
    Database,
    /// Vector database for embedding storage and ANN search
    VectorDb,
    /// Graph database for knowledge graphs and traversals
    GraphDb,
    /// In-memory cache (Redis, Valkey)
    Cache,
    /// Binary/file storage (S3, R2, GCS)
    ObjectStorage,
    /// Async message passing (RabbitMQ, Kafka, NATS)
    MessageQueue,

    // ── Observability & Auth ─────────────────────────────────
    /// LLM call tracing, cost tracking, prompt versioning
    Observability,
    /// OAuth2 social login
    AuthOauth,
    /// API authentication and key management
    AuthApi,

    // ── Specialized Agent Capabilities ───────────────────────
    /// Headless browser automation
    Browser,
    /// Sandboxed code execution
    CodeExecution,
    /// Document format conversion
    FileConversion,
    /// Email sending and receiving
    Email,
    /// Distributed ledger for receipts and attestation
    Ledger,

    // ── Messaging Channels ───────────────────────────────────
    /// Slack bot integration
    MessagingSlack,
    /// Telegram bot integration
    MessagingTelegram,
    /// Signal bot integration
    MessagingSignal,

    // ── Document Processing ──────────────────────────────────
    /// AI-powered PDF/document parsing and extraction
    PdfProcessing,
}

impl Capability {
    /// All known capabilities, for iteration.
    pub const ALL: &'static [Capability] = &[
        Self::ReasoningLlm,
        Self::FastLlm,
        Self::CodeLlm,
        Self::LongContextLlm,
        Self::Vision,
        Self::ImageGen,
        Self::ImageEdit,
        Self::Tts,
        Self::Asr,
        Self::AudioGen,
        Self::VoiceClone,
        Self::VideoGen,
        Self::VideoEdit,
        Self::VideoUnderstanding,
        Self::ThreeDGen,
        Self::Embedding,
        Self::WebSearch,
        Self::Reranking,
        Self::Database,
        Self::VectorDb,
        Self::GraphDb,
        Self::Cache,
        Self::ObjectStorage,
        Self::MessageQueue,
        Self::Observability,
        Self::AuthOauth,
        Self::AuthApi,
        Self::Browser,
        Self::CodeExecution,
        Self::FileConversion,
        Self::Email,
        Self::Ledger,
        Self::MessagingSlack,
        Self::MessagingTelegram,
        Self::MessagingSignal,
        Self::PdfProcessing,
    ];

    /// Returns the string slug as used in TOML files and manifests.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ReasoningLlm => "reasoning_llm",
            Self::FastLlm => "fast_llm",
            Self::CodeLlm => "code_llm",
            Self::LongContextLlm => "long_context_llm",
            Self::Vision => "vision",
            Self::ImageGen => "image_gen",
            Self::ImageEdit => "image_edit",
            Self::Tts => "tts",
            Self::Asr => "asr",
            Self::AudioGen => "audio_gen",
            Self::VoiceClone => "voice_clone",
            Self::VideoGen => "video_gen",
            Self::VideoEdit => "video_edit",
            Self::VideoUnderstanding => "video_understanding",
            Self::ThreeDGen => "3d_gen",
            Self::Embedding => "embedding",
            Self::WebSearch => "web_search",
            Self::Reranking => "reranking",
            Self::Database => "database",
            Self::VectorDb => "vector_db",
            Self::GraphDb => "graph_db",
            Self::Cache => "cache",
            Self::ObjectStorage => "object_storage",
            Self::MessageQueue => "message_queue",
            Self::Observability => "observability",
            Self::AuthOauth => "auth_oauth",
            Self::AuthApi => "auth_api",
            Self::Browser => "browser",
            Self::CodeExecution => "code_execution",
            Self::FileConversion => "file_conversion",
            Self::Email => "email",
            Self::Ledger => "ledger",
            Self::MessagingSlack => "messaging_slack",
            Self::MessagingTelegram => "messaging_telegram",
            Self::MessagingSignal => "messaging_signal",
            Self::PdfProcessing => "pdf_processing",
        }
    }

    /// Whether this is an LLM-class capability (may share providers).
    pub fn is_llm(&self) -> bool {
        matches!(
            self,
            Self::ReasoningLlm
                | Self::FastLlm
                | Self::CodeLlm
                | Self::LongContextLlm
                | Self::Vision
        )
    }

    /// Whether this capability typically requires external credentials.
    /// Local-only capabilities (database, code_execution) often don't.
    pub fn typically_needs_credentials(&self) -> bool {
        !matches!(
            self,
            Self::Database
                | Self::CodeExecution
                | Self::FileConversion
                | Self::Cache
                | Self::Browser
        )
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for Capability {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "reasoning_llm" => Ok(Self::ReasoningLlm),
            "fast_llm" => Ok(Self::FastLlm),
            "code_llm" => Ok(Self::CodeLlm),
            "long_context_llm" => Ok(Self::LongContextLlm),
            "vision" => Ok(Self::Vision),
            "image_gen" => Ok(Self::ImageGen),
            "image_edit" => Ok(Self::ImageEdit),
            "tts" => Ok(Self::Tts),
            "asr" => Ok(Self::Asr),
            "audio_gen" => Ok(Self::AudioGen),
            "voice_clone" => Ok(Self::VoiceClone),
            "video_gen" => Ok(Self::VideoGen),
            "video_edit" => Ok(Self::VideoEdit),
            "video_understanding" => Ok(Self::VideoUnderstanding),
            "3d_gen" => Ok(Self::ThreeDGen),
            "embedding" => Ok(Self::Embedding),
            "web_search" => Ok(Self::WebSearch),
            "reranking" => Ok(Self::Reranking),
            "database" => Ok(Self::Database),
            "vector_db" => Ok(Self::VectorDb),
            "graph_db" => Ok(Self::GraphDb),
            "cache" => Ok(Self::Cache),
            "object_storage" => Ok(Self::ObjectStorage),
            "message_queue" => Ok(Self::MessageQueue),
            "observability" => Ok(Self::Observability),
            "auth_oauth" => Ok(Self::AuthOauth),
            "auth_api" => Ok(Self::AuthApi),
            "browser" => Ok(Self::Browser),
            "code_execution" => Ok(Self::CodeExecution),
            "file_conversion" => Ok(Self::FileConversion),
            "email" => Ok(Self::Email),
            "ledger" => Ok(Self::Ledger),
            "messaging_slack" => Ok(Self::MessagingSlack),
            "messaging_telegram" => Ok(Self::MessagingTelegram),
            "messaging_signal" => Ok(Self::MessagingSignal),
            "pdf_processing" => Ok(Self::PdfProcessing),
            other => Err(format!("unknown capability: {other}")),
        }
    }
}

// ============================================================================
// Confidence
// ============================================================================

/// Resolution confidence tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Engine hit its knowledge boundary — needs human review
    Low,
    /// Inferred or partially ambiguous resolution
    Medium,
    /// Manifest-declared, resolved with vault key
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

// ============================================================================
// Tool Manifest (.zp-configure.toml)
// ============================================================================

/// Top-level `.zp-configure.toml` manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolManifest {
    /// Tool metadata
    pub tool: ToolMeta,

    /// Required capabilities — tool won't function without these
    #[serde(default)]
    pub required: Vec<CapabilityRequirement>,

    /// Optional capabilities — enhance the tool but aren't essential
    #[serde(default)]
    pub optional: Vec<CapabilityRequirement>,

    /// Secrets the engine should auto-generate (random passwords, salts)
    #[serde(default)]
    pub auto_generate: Option<AutoGenerate>,

    /// Aggregator deluxe mode preferences
    #[serde(default)]
    pub deluxe: Option<DeluxeConfig>,

    /// Provider-specific env var mappings
    #[serde(default)]
    pub provider_overrides: Vec<ProviderOverride>,

    /// Runtime capability verification — endpoints ZP probes after launch
    /// to confirm credentials are not just delivered but actually working.
    #[serde(default)]
    pub verification: Option<VerificationConfig>,

    /// Configurable parameters with defaults (P6-1: capability-configured receipts).
    /// When present, the configure path emits a ConfigurationClaim receipt for each
    /// parameter, recording the value applied (default or override).
    #[serde(default)]
    pub configurable: Vec<ConfigurableParam>,
}

/// A configurable parameter declared in the tool manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurableParam {
    /// Parameter name (e.g., "max_tokens", "temperature", "model")
    pub name: String,
    /// Human-readable description
    #[serde(default)]
    pub description: String,
    /// Default value (applied if operator doesn't override)
    pub default: serde_json::Value,
    /// Allowed values (empty = any value)
    #[serde(default)]
    pub allowed_values: Vec<serde_json::Value>,
    /// The env var this maps to (e.g., "MAX_TOKENS")
    #[serde(default)]
    pub env_var: Option<String>,
}

// ── Capability Verification ────────────────────────────────────────────

/// Runtime verification config — declares how ZP can probe the tool
/// after launch to confirm credentials made it through the tool's
/// internal resolution chain.
///
/// Three tiers of confidence:
///   Tier 0: `tool:configured` — .env exists (always available)
///   Tier 1: `providers_endpoint` — runtime loaded the providers
///   Tier 2: `endpoints` — per-capability auth actually works
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Endpoint that returns which providers loaded at runtime.
    /// Response should be a JSON object keyed by provider ID.
    /// Example: `/api/server-providers` → `{ "openai": { "models": [...] } }`
    #[serde(default)]
    pub providers_endpoint: Option<String>,

    /// Per-capability verify endpoints.
    /// Key = capability name (must match a `[[required]]` or `[[optional]]` entry).
    /// Value = path to probe (e.g., `/api/verify-model`).
    /// ZP sends a request and checks for 2xx.
    #[serde(default)]
    pub endpoints: HashMap<String, String>,

    /// Per-capability probe configuration (method, headers, body).
    /// Key = capability name. If absent, defaults to GET with no extra headers.
    #[serde(default)]
    pub probes: HashMap<String, ProbeConfig>,

    /// Max seconds to wait after health-up before running verification.
    /// Gives the tool time to finish internal init (DB migrations, etc.).
    /// Default: 5
    #[serde(default = "default_verify_delay")]
    pub delay_secs: u64,

    /// Number of retry attempts if a probe fails (network error or 5xx).
    /// Default: 3
    #[serde(default = "default_verify_retries")]
    pub retries: u32,
}

fn default_verify_delay() -> u64 {
    5
}
fn default_verify_retries() -> u32 {
    3
}

/// How to probe a specific capability's verify endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// HTTP method — `GET` or `POST`. Default: `GET`.
    #[serde(default = "default_probe_method")]
    pub method: String,

    /// Extra headers to send with the probe.
    #[serde(default)]
    pub headers: HashMap<String, String>,

    /// JSON body for POST probes.
    #[serde(default)]
    pub body: Option<String>,
}

fn default_probe_method() -> String {
    "GET".to_string()
}

/// Tool metadata from [tool] section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMeta {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
}

/// A single capability requirement (used for both required and optional).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    /// The abstract capability needed
    pub capability: String,

    /// Env vars this capability maps to in the tool
    #[serde(default)]
    pub env_vars: Vec<String>,

    /// Additional config vars set dynamically when this capability resolves
    /// (e.g., Agent Zero's `A0_SET_*` pattern)
    #[serde(default)]
    pub config_vars: HashMap<String, String>,

    /// Preferred providers, in priority order
    #[serde(default)]
    pub prefer: Vec<String>,

    /// If set, this capability can share a provider with another capability
    #[serde(default)]
    pub shared_with: Option<String>,

    /// Env var that holds the model name
    #[serde(default)]
    pub model_env: Option<String>,

    /// Default model when no preference is set
    #[serde(default)]
    pub model_default: Option<String>,

    /// Default values for env vars
    #[serde(default)]
    pub defaults: HashMap<String, String>,

    /// Flags needing human attention (OAuth flows, platform app creation, etc.)
    #[serde(default)]
    pub attention: Option<String>,

    /// Whether a local default is available (e.g., local PostgreSQL)
    #[serde(default)]
    pub local_default: bool,

    /// Human-readable notes
    #[serde(default)]
    pub notes: Option<String>,

    /// Backend groups — for tools using the backend selector pattern (e.g., IronClaw)
    #[serde(default)]
    pub backend_groups: Vec<BackendGroup>,

    /// Auto-generate credential for this capability's env vars
    #[serde(default)]
    pub auto_generate: Vec<String>,
}

/// Backend-specific variable group for the backend selector pattern.
///
/// When a tool uses `LLM_BACKEND=anthropic` to select its provider,
/// only that backend's env vars get populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendGroup {
    /// Backend identifier (matches a provider id or a meta-backend like "openai_compatible")
    pub backend: String,

    /// Env vars specific to this backend
    #[serde(default)]
    pub env_vars: Vec<String>,

    /// Default values for this backend's vars
    #[serde(default)]
    pub defaults: HashMap<String, String>,

    /// Flags needing human attention (OAuth flows, special setup, etc.)
    #[serde(default)]
    pub attention: Option<String>,

    /// Notes about this backend
    #[serde(default)]
    pub notes: Option<String>,
}

/// Auto-generatable secrets section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoGenerate {
    /// Env var names to fill with random secrets
    #[serde(default)]
    pub secrets: Vec<String>,
}

/// Aggregator deluxe mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeluxeConfig {
    /// Whether the tool benefits from aggregator routing
    #[serde(default)]
    pub prefer_aggregator: bool,

    /// Which backend to use for aggregator mode (for backend selector tools)
    #[serde(default)]
    pub aggregator_backend: Option<String>,

    /// Notes about deluxe mode behavior
    #[serde(default)]
    pub notes: Option<String>,
}

/// Provider-specific env var mappings.
///
/// When a capability resolves to provider X, this tells the engine exactly
/// which env vars to set and what values to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderOverride {
    /// Provider ID this override applies to
    pub provider: String,

    /// Env var → value mappings (may contain `${vault:provider/field}` references)
    #[serde(default)]
    pub env_map: HashMap<String, String>,

    /// Additional env vars to set alongside the env_map
    #[serde(default)]
    pub also_set: HashMap<String, String>,

    /// Capabilities that share this provider's key
    #[serde(default)]
    pub shares: Vec<String>,

    /// Custom base URL (for aggregators masquerading as OpenAI)
    #[serde(default)]
    pub custom_base_url: Option<String>,

    /// Notes
    #[serde(default)]
    pub notes: Option<String>,
}

// ============================================================================
// Manifest loading
// ============================================================================

/// Load and parse a `.zp-configure.toml` manifest from disk.
pub fn load_manifest(path: &Path) -> Result<ToolManifest, ManifestError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| ManifestError::Io(path.to_path_buf(), e))?;
    toml::from_str(&content).map_err(|e| ManifestError::Parse(path.to_path_buf(), e))
}

/// Errors from manifest loading.
#[derive(Debug)]
pub enum ManifestError {
    Io(std::path::PathBuf, std::io::Error),
    Parse(std::path::PathBuf, toml::de::Error),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(path, e) => write!(f, "cannot read {}: {}", path.display(), e),
            Self::Parse(path, e) => write!(f, "invalid manifest {}: {}", path.display(), e),
        }
    }
}

impl std::error::Error for ManifestError {}

// ============================================================================
// Resolution types
// ============================================================================

/// Result of resolving a single capability requirement.
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityResolution {
    /// The capability that was resolved
    pub capability: String,
    /// Whether it was required or optional
    pub required: bool,
    /// Resolution outcome
    pub status: ResolutionStatus,
    /// Confidence in this resolution
    pub confidence: Confidence,
    /// Env vars to write into the tool's .env
    pub env_vars: HashMap<String, String>,
    /// Notes or warnings for the user
    pub notes: Vec<String>,
}

/// Outcome of resolving a single capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionStatus {
    /// Resolved — provider found in vault, env vars populated
    Resolved { provider_id: String },
    /// Shared — reusing another capability's provider
    Shared {
        shared_with: String,
        provider_id: String,
    },
    /// Default — using local or built-in default (no vault key needed)
    DefaultLocal,
    /// Auto-generated — random secrets filled in
    AutoGenerated,
    /// Missing — no provider in vault satisfies this capability
    Missing,
    /// Needs attention — human review required (OAuth, platform setup, etc.)
    NeedsAttention { reason: String },
}

/// Complete resolution result for a tool.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedTool {
    /// Tool name from manifest
    pub name: String,
    /// Path to tool directory
    pub path: std::path::PathBuf,
    /// All capability resolutions (required + optional)
    pub capabilities: Vec<CapabilityResolution>,
    /// Whether the tool can function (all required capabilities resolved)
    pub ready: bool,
    /// Overall confidence (min of required capability confidences)
    pub confidence: Confidence,
    /// Whether deluxe/aggregator mode was applied
    pub deluxe_mode: bool,
    /// Missing required capabilities
    pub missing_required: Vec<String>,
    /// Capabilities flagged for attention
    pub needs_attention: Vec<String>,
    /// Complete env var map to write
    pub env_output: HashMap<String, String>,
}

// ============================================================================
// Provider resolution
// ============================================================================

/// Resolve a single capability against the provider catalog and vault.
///
/// The resolution algorithm:
/// 1. Check the requirement's `prefer` list in order
/// 2. For each preferred provider, check if the vault has a key
/// 3. Fall back to any provider with the capability and a vault key
/// 4. If `shared_with` is set, try reusing that capability's provider
/// 5. If `local_default` is set, use the default without credentials
/// 6. Return Missing if nothing works
pub fn resolve_capability(
    requirement: &CapabilityRequirement,
    catalog: &[super::providers::ProviderProfile],
    vault_providers: &[String],
    already_resolved: &HashMap<String, String>,
) -> CapabilityResolution {
    let capability_str = &requirement.capability;

    // Parse capability for matching against catalog
    let target_cap = capability_str.clone();

    // Check if this requires human attention
    if let Some(ref attention) = requirement.attention {
        return CapabilityResolution {
            capability: capability_str.clone(),
            required: true, // caller sets this
            status: ResolutionStatus::NeedsAttention {
                reason: attention.clone(),
            },
            confidence: Confidence::Low,
            env_vars: requirement.defaults.clone(),
            notes: vec![format!("Requires setup: {attention}")],
        };
    }

    // Check local defaults first (database, code_execution, etc.)
    if requirement.local_default {
        return CapabilityResolution {
            capability: capability_str.clone(),
            required: true,
            status: ResolutionStatus::DefaultLocal,
            confidence: Confidence::High,
            env_vars: requirement.defaults.clone(),
            notes: vec!["Using local default".into()],
        };
    }

    // Check shared_with — can we reuse another capability's provider?
    if let Some(ref shared) = requirement.shared_with {
        if let Some(provider_id) = already_resolved.get(shared) {
            if provider_has_capability(catalog, provider_id, &target_cap) {
                return CapabilityResolution {
                    capability: capability_str.clone(),
                    required: true,
                    status: ResolutionStatus::Shared {
                        shared_with: shared.clone(),
                        provider_id: provider_id.clone(),
                    },
                    confidence: Confidence::High,
                    env_vars: requirement.defaults.clone(),
                    notes: vec![format!("Sharing provider with {shared}")],
                };
            }
        }
    }

    // Try preferred providers in order
    for pref in &requirement.prefer {
        if vault_providers.contains(pref) && provider_has_capability(catalog, pref, &target_cap) {
            return CapabilityResolution {
                capability: capability_str.clone(),
                required: true,
                status: ResolutionStatus::Resolved {
                    provider_id: pref.clone(),
                },
                confidence: Confidence::High,
                env_vars: HashMap::new(), // caller applies provider_overrides
                notes: vec![format!("Resolved to preferred provider: {pref}")],
            };
        }
    }

    // Fall back to any provider with this capability and a vault key
    for provider in catalog {
        if vault_providers.contains(&provider.id)
            && provider_has_capability_profile(provider, &target_cap)
        {
            return CapabilityResolution {
                capability: capability_str.clone(),
                required: true,
                status: ResolutionStatus::Resolved {
                    provider_id: provider.id.clone(),
                },
                confidence: Confidence::Medium,
                env_vars: HashMap::new(),
                notes: vec![format!(
                    "Resolved to available provider: {} (not in prefer list)",
                    provider.id
                )],
            };
        }
    }

    // Nothing resolved
    CapabilityResolution {
        capability: capability_str.clone(),
        required: true,
        status: ResolutionStatus::Missing,
        confidence: Confidence::Low,
        env_vars: HashMap::new(),
        notes: vec![format!(
            "No provider in vault satisfies capability '{capability_str}'"
        )],
    }
}

/// Resolve an entire tool manifest against the vault.
///
/// This is the main entry point for MVC resolution. Given a manifest and
/// the user's vault contents, it returns a complete resolution plan.
pub fn resolve_tool(
    manifest: &ToolManifest,
    tool_path: &Path,
    catalog: &[super::providers::ProviderProfile],
    vault_providers: &[String],
) -> ResolvedTool {
    let mut capabilities = Vec::new();
    let mut already_resolved: HashMap<String, String> = HashMap::new();
    let mut env_output: HashMap<String, String> = HashMap::new();
    let mut missing_required = Vec::new();
    let mut needs_attention = Vec::new();
    let mut all_ready = true;
    let mut min_confidence = Confidence::High;

    // Resolve required capabilities
    for req in &manifest.required {
        let mut resolution = resolve_capability(req, catalog, vault_providers, &already_resolved);
        resolution.required = true;

        match &resolution.status {
            ResolutionStatus::Resolved { provider_id } => {
                already_resolved.insert(req.capability.clone(), provider_id.clone());
                // Apply provider overrides
                apply_provider_overrides(
                    &manifest.provider_overrides,
                    provider_id,
                    &mut env_output,
                );
            }
            ResolutionStatus::Shared { provider_id, .. } => {
                already_resolved.insert(req.capability.clone(), provider_id.clone());
            }
            ResolutionStatus::DefaultLocal => {
                env_output.extend(resolution.env_vars.clone());
            }
            ResolutionStatus::Missing => {
                all_ready = false;
                missing_required.push(req.capability.clone());
            }
            ResolutionStatus::NeedsAttention { reason } => {
                all_ready = false;
                needs_attention.push(format!("{}: {}", req.capability, reason));
                env_output.extend(resolution.env_vars.clone());
            }
            ResolutionStatus::AutoGenerated => {}
        }

        if resolution.confidence < min_confidence {
            min_confidence = resolution.confidence;
        }

        capabilities.push(resolution);
    }

    // Resolve optional capabilities
    for req in &manifest.optional {
        let mut resolution = resolve_capability(req, catalog, vault_providers, &already_resolved);
        resolution.required = false;

        match &resolution.status {
            ResolutionStatus::Resolved { provider_id } => {
                already_resolved.insert(req.capability.clone(), provider_id.clone());
                apply_provider_overrides(
                    &manifest.provider_overrides,
                    provider_id,
                    &mut env_output,
                );
            }
            ResolutionStatus::Shared { provider_id, .. } => {
                already_resolved.insert(req.capability.clone(), provider_id.clone());
            }
            ResolutionStatus::DefaultLocal => {
                env_output.extend(resolution.env_vars.clone());
            }
            ResolutionStatus::NeedsAttention { reason } => {
                needs_attention.push(format!("{}: {}", req.capability, reason));
                env_output.extend(resolution.env_vars.clone());
            }
            _ => {} // Optional missing is fine
        }

        capabilities.push(resolution);
    }

    // Apply auto-generated secrets
    if let Some(ref auto_gen) = manifest.auto_generate {
        for secret_var in &auto_gen.secrets {
            let value = generate_secret(32);
            env_output.insert(secret_var.clone(), value);
        }
    }

    // Apply static defaults from all resolved capabilities
    for req in manifest.required.iter().chain(manifest.optional.iter()) {
        for (k, v) in &req.defaults {
            env_output.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    ResolvedTool {
        name: manifest.tool.name.clone(),
        path: tool_path.to_path_buf(),
        capabilities,
        ready: all_ready,
        confidence: min_confidence,
        deluxe_mode: false, // set by caller after aggregator check
        missing_required,
        needs_attention,
        env_output,
    }
}

// ============================================================================
// Aggregator / Deluxe mode
// ============================================================================

/// Check if an aggregator can satisfy ≥80% of required capabilities,
/// making it worthwhile to use deluxe mode.
pub fn check_deluxe_mode(
    manifest: &ToolManifest,
    catalog: &[super::providers::ProviderProfile],
    vault_providers: &[String],
) -> Option<DeluxeCandidate> {
    let deluxe = manifest.deluxe.as_ref()?;
    if !deluxe.prefer_aggregator {
        return None;
    }

    // Find aggregators in vault
    let aggregators: Vec<&super::providers::ProviderProfile> = catalog
        .iter()
        .filter(|p| p.aggregator.unwrap_or(false) && vault_providers.contains(&p.id))
        .collect();

    for agg in aggregators {
        let caps = &agg.capabilities;
        let required_count = manifest.required.len();
        if required_count == 0 {
            continue;
        }

        let covered = manifest
            .required
            .iter()
            .filter(|req| caps.iter().any(|c| c == &req.capability))
            .count();

        let coverage = covered as f32 / required_count as f32;

        if coverage >= 0.8 {
            return Some(DeluxeCandidate {
                aggregator_id: agg.id.clone(),
                aggregator_name: agg.name.clone(),
                coverage_percent: (coverage * 100.0) as u8,
                covered_capabilities: manifest
                    .required
                    .iter()
                    .filter(|req| caps.iter().any(|c| c == &req.capability))
                    .map(|req| req.capability.clone())
                    .collect(),
                uncovered_capabilities: manifest
                    .required
                    .iter()
                    .filter(|req| !caps.iter().any(|c| c == &req.capability))
                    .map(|req| req.capability.clone())
                    .collect(),
            });
        }
    }

    None
}

/// A viable aggregator for deluxe mode.
#[derive(Debug, Clone, Serialize)]
pub struct DeluxeCandidate {
    pub aggregator_id: String,
    pub aggregator_name: String,
    pub coverage_percent: u8,
    pub covered_capabilities: Vec<String>,
    pub uncovered_capabilities: Vec<String>,
}

// ============================================================================
// Helpers
// ============================================================================

/// Check if a provider (by id) has a specific capability in the catalog.
fn provider_has_capability(
    catalog: &[super::providers::ProviderProfile],
    provider_id: &str,
    capability: &str,
) -> bool {
    catalog
        .iter()
        .find(|p| p.id == provider_id)
        .map(|p| p.capabilities.iter().any(|c| c == capability))
        .unwrap_or(false)
}

/// Check if a provider profile has a specific capability.
fn provider_has_capability_profile(
    provider: &super::providers::ProviderProfile,
    capability: &str,
) -> bool {
    provider.capabilities.iter().any(|c| c == capability)
}

/// Apply provider_overrides for a resolved provider.
fn apply_provider_overrides(
    overrides: &[ProviderOverride],
    provider_id: &str,
    env_output: &mut HashMap<String, String>,
) {
    for ov in overrides {
        if ov.provider == provider_id {
            for (k, v) in &ov.env_map {
                // Skip vault references — those are resolved at write time
                if !v.starts_with("${vault:") {
                    env_output.insert(k.clone(), v.clone());
                }
            }
            for (k, v) in &ov.also_set {
                env_output.insert(k.clone(), v.clone());
            }
        }
    }
}

/// Generate a cryptographically random secret (hex-encoded).
fn generate_secret(bytes: usize) -> String {
    use std::io::Read;
    let mut buf = vec![0u8; bytes];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_roundtrip() {
        for cap in Capability::ALL {
            let s = cap.as_str();
            let parsed: Capability = s.parse().unwrap();
            assert_eq!(*cap, parsed, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn capability_serde_roundtrip() {
        for cap in Capability::ALL {
            let json = serde_json::to_string(cap).unwrap();
            let parsed: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(*cap, parsed);
        }
    }

    #[test]
    fn unknown_capability_errors() {
        assert!("nonexistent_cap".parse::<Capability>().is_err());
    }

    #[test]
    fn confidence_ordering() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn parse_minimal_manifest() {
        let toml_str = r#"
            [tool]
            name = "test-tool"
            version = "0.1"
            description = "A test"

            [[required]]
            capability = "reasoning_llm"
            env_vars = ["OPENAI_API_KEY"]
            prefer = ["anthropic", "openai"]
        "#;

        let manifest: ToolManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.tool.name, "test-tool");
        assert_eq!(manifest.required.len(), 1);
        assert_eq!(manifest.required[0].capability, "reasoning_llm");
        assert_eq!(manifest.required[0].prefer, vec!["anthropic", "openai"]);
    }

    #[test]
    fn parse_manifest_with_all_sections() {
        let toml_str = r#"
            [tool]
            name = "full-tool"
            version = "0.1"
            description = "A full manifest"

            [[required]]
            capability = "reasoning_llm"
            env_vars = ["API_KEY"]
            prefer = ["anthropic"]
            model_env = "MODEL_NAME"
            model_default = "claude-sonnet-4-20250514"

            [[optional]]
            capability = "embedding"
            env_vars = []
            shared_with = "reasoning_llm"

            [[optional]]
            capability = "web_search"
            env_vars = ["TAVILY_API_KEY"]
            prefer = ["tavily"]

            [auto_generate]
            secrets = ["AUTH_SECRET", "ENCRYPTION_KEY"]

            [deluxe]
            prefer_aggregator = true

            [[provider_overrides]]
            provider = "anthropic"
            env_map = { API_KEY = "${vault:anthropic/api_key}" }
            also_set = { MODEL_NAME = "claude-sonnet-4-20250514" }

            [[provider_overrides]]
            provider = "openrouter"
            env_map = { API_KEY = "${vault:openrouter/api_key}" }
            shares = ["embedding"]
        "#;

        let manifest: ToolManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.tool.name, "full-tool");
        assert_eq!(manifest.required.len(), 1);
        assert_eq!(manifest.optional.len(), 2);
        assert_eq!(manifest.auto_generate.as_ref().unwrap().secrets.len(), 2);
        assert!(manifest.deluxe.as_ref().unwrap().prefer_aggregator);
        assert_eq!(manifest.provider_overrides.len(), 2);
        assert_eq!(manifest.provider_overrides[1].shares, vec!["embedding"]);
    }

    #[test]
    fn generate_secret_produces_correct_length() {
        let s = generate_secret(16);
        assert_eq!(s.len(), 32); // 16 bytes = 32 hex chars
    }
}
