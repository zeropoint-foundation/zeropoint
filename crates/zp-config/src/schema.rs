//! The unified configuration schema.
//!
//! Every field is a [`Sourced<T>`] so we track provenance. The TOML file
//! uses a flat-ish structure that mirrors the `zp config show` output.

use crate::provenance::Sourced;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ─── Regent inference endpoint — symbolic default (W5 3c) ────────────

/// Default value for `regent_inference_endpoint` when the operator has not
/// set one.
///
/// Not a URL — a proxy base is `http://127.0.0.1:{port}/api/v1/proxy/ollama`,
/// and the port is itself config, so a literal here would either hardcode a
/// port that drifts from whatever the operator actually runs on, or hardcode
/// the pre-W5-3c native Ollama address (`http://127.0.0.1:11434`), which is
/// exactly the address the governed path retires. This sentinel names
/// *intent* — route through this substrate's own proxy to local Ollama —
/// deliberately spelled so it cannot be mistaken for a resolvable address.
///
/// `zp_regent::inference::ProviderProfile::detect` never needs to special-
/// case it: with no API key present it already falls through to the
/// `ollama()` profile for any endpoint string that doesn't match a known
/// cloud provider or the `/api/v1/proxy/` prefix, and this sentinel matches
/// neither. The actual HTTP target is built separately at call time from
/// `InferenceBackend`'s `proxy_base` (the substrate's own address, supplied
/// by the server at construction) plus the detected provider's name — never
/// by resolving this string into a URL.
pub const REGENT_INFERENCE_ENDPOINT_SENTINEL: &str = "@proxy/ollama";

// ─── Node Role (derived from chain state) ────────────────────

/// The node's role in the trust topology, derived from chain state.
///
/// This is the authoritative role determination — it is NOT derived from
/// config.toml, which is treated as a "bootstrap hint" only.
///
/// Priority:
///   1. If a delegation receipt exists → Delegate (with upstream binding)
///   2. If genesis.json exists with valid transcript → Genesis
///   3. Otherwise → Standalone
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// This node performed the genesis ceremony and holds the root signing key.
    /// Evidence: genesis.json with valid signed transcript.
    Genesis,

    /// This node verifies against an upstream genesis authority.
    /// Evidence: a delegation receipt in the local chain binding this node
    /// to an upstream genesis public key.
    Delegate {
        upstream_addr: String,
        upstream_genesis_pubkey: String,
    },

    /// No genesis ceremony, no delegation receipt. Pre-init or standalone.
    Standalone,
}

impl NodeRole {
    /// Compare roles by variant only, ignoring field values.
    ///
    /// This is needed because `config_hint_role()` returns a `Delegate` with
    /// placeholder empty strings, while `derive_node_role()` returns a `Delegate`
    /// with actual upstream values from the delegation receipt. Standard `PartialEq`
    /// would say these differ; `same_variant` says they agree on the role itself.
    pub fn same_variant(&self, other: &NodeRole) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

// ─── Unified Config ──────────────────────────────────────────

/// The complete, resolved ZeroPoint configuration.
#[derive(Debug, Clone, Serialize)]
pub struct ZpConfig {
    // ── Server ──
    pub port: Sourced<u16>,
    pub bind: Sourced<String>,
    pub open_dashboard: Sourced<bool>,

    // ── Data ──
    pub data_dir: Sourced<PathBuf>,
    pub home_dir: Sourced<PathBuf>,

    // ── Identity ──
    pub operator_name: Sourced<String>,

    // ── LLM ──
    pub llm_enabled: Sourced<bool>,
    /// Proxy provider segment the pipeline routes completions through.
    /// Must be a key known to `zp_server::proxy::provider_base_url`.
    /// "ollama" is the local backend.
    pub llm_provider: Sourced<String>,
    /// Default-tier model name, passed through to the provider verbatim.
    pub llm_model: Sourced<String>,
    /// Escalation-tier model. Registered as a second pool provider with a
    /// higher declared strength so `ModelClass::Strong` / `RequireStrong` can
    /// select it. Empty string disables the escalation tier.
    pub llm_escalation_model: Sourced<String>,
    /// Whether the configured models implement the OpenAI tool-call format.
    /// The pipeline's tool-invocation loop never fires when this is false.
    pub llm_supports_tools: Sourced<bool>,

    // ── Node topology ──
    /// Node role: "genesis" (default) or "delegate".
    /// Genesis nodes verify their own local chain.
    /// Delegate nodes verify against their upstream authority.
    pub node_role: Sourced<String>,
    /// Upstream server address for delegate nodes (e.g., "192.168.1.199:17770").
    /// Ignored when node_role is "genesis".
    pub node_upstream: Sourced<Option<String>>,

    // ── Officers ──
    pub officers_enabled: Sourced<bool>,
    pub officers_sweep_interval_secs: Sourced<u64>,
    pub officers_steward_enabled: Sourced<bool>,
    pub officers_sentinel_enabled: Sourced<bool>,
    pub officers_forge_enabled: Sourced<bool>,
    pub officers_cleo_enabled: Sourced<bool>,
    pub officers_aegis_enabled: Sourced<bool>,

    /// External processes the operator acknowledges as expected listeners.
    pub acknowledged_listeners: Sourced<Vec<AcknowledgedListener>>,

    // ── Regent ──
    pub regent_enabled: Sourced<bool>,
    pub regent_inference_endpoint: Sourced<String>,
    pub regent_inference_api_key: Sourced<Option<String>>,
    pub regent_reasoning_model: Sourced<String>,
    pub regent_routing_model: Sourced<String>,
    pub regent_loop_interval_secs: Sourced<u64>,
    pub regent_display_name: Sourced<String>,

    // ── Server runtime paths (Seam 12-B) ──
    /// Optional override directory for HTML/CSS/JS assets the server
    /// serves. When set and present, takes precedence over the
    /// compiled-in assets — used by `zp-dev.sh html` for instant
    /// reload during development. When unset or missing, the server
    /// falls back to `include_str!()`-embedded assets.
    ///
    /// Env: `ZP_ASSETS_DIR` (path).
    pub assets_dir: Sourced<Option<PathBuf>>,
    /// Optional directory of bridge / cockpit-side scratch files.
    /// Resolved relative to `home_dir` if unset.
    ///
    /// Env: `ZP_BRIDGE_DIR` (path).
    pub bridge_dir: Sourced<Option<PathBuf>>,
}

impl Default for ZpConfig {
    fn default() -> Self {
        let home = zp_home();
        Self {
            port: Sourced::default_value(17770),
            bind: Sourced::default_value("0.0.0.0".into()),
            open_dashboard: Sourced::default_value(true),

            data_dir: Sourced::default_value(home.join("data")),
            home_dir: Sourced::default_value(home),

            operator_name: Sourced::default_value(whoami()),

            llm_enabled: Sourced::default_value(false),
            llm_provider: Sourced::default_value("ollama".into()),
            // Defaults mirror officer-inference.toml, which validated this
            // pair on APOLLO against the full bench matrix. Both tags must be
            // pulled locally (`ollama pull <tag>`) or the provider health
            // check fails at startup with a 404 from the backend.
            llm_model: Sourced::default_value("gemma4:26b-mlx".into()),
            llm_escalation_model: Sourced::default_value("qwen3.6:35b-a3b".into()),
            llm_supports_tools: Sourced::default_value(true),

            node_role: Sourced::default_value("genesis".into()),
            node_upstream: Sourced::default_value(None),

            officers_enabled: Sourced::default_value(false),
            officers_sweep_interval_secs: Sourced::default_value(900),
            officers_steward_enabled: Sourced::default_value(true),
            officers_sentinel_enabled: Sourced::default_value(true),
            officers_forge_enabled: Sourced::default_value(true),
            officers_cleo_enabled: Sourced::default_value(true),
            officers_aegis_enabled: Sourced::default_value(true),
            acknowledged_listeners: Sourced::default_value(Vec::new()),

            regent_enabled: Sourced::default_value(false),
            regent_inference_endpoint: Sourced::default_value(
                REGENT_INFERENCE_ENDPOINT_SENTINEL.into(),
            ),
            regent_inference_api_key: Sourced::default_value(None),
            regent_reasoning_model: Sourced::default_value("qwen3:8b".into()),
            regent_routing_model: Sourced::default_value("qwen3:1.7b".into()),
            regent_loop_interval_secs: Sourced::default_value(60),
            regent_display_name: Sourced::default_value("Regent".into()),

            assets_dir: Sourced::default_value(None),
            bridge_dir: Sourced::default_value(None),
        }
    }
}

impl ZpConfig {
    /// Print the startup provenance banner (logged by zp-server on boot).
    pub fn provenance_banner(&self) -> String {
        let mut lines = Vec::new();
        lines.push("ZeroPoint starting".into());
        lines.push(format!("  port: {}", self.port));
        lines.push(format!("  bind: {}", self.bind));
        lines.push(format!("  data_dir: {}", self.data_dir.value.display()));
        lines.push(format!("  operator: {}", self.operator_name));
        lines.push(format!("  llm: {}", self.llm_enabled));
        lines.join("\n")
    }

    /// Produce the `zp config show` output with provenance for every field.
    pub fn show(&self) -> String {
        let mut lines = Vec::new();
        lines.push("[server]".into());
        lines.push(format!(
            "  port = {}  # {}",
            self.port.value, self.port.source
        ));
        lines.push(format!(
            "  bind = \"{}\"  # {}",
            self.bind.value, self.bind.source
        ));
        lines.push(format!(
            "  open_dashboard = {}  # {}",
            self.open_dashboard.value, self.open_dashboard.source
        ));
        lines.push(String::new());

        lines.push("[data]".into());
        lines.push(format!(
            "  dir = \"{}\"  # {}",
            self.data_dir.value.display(),
            self.data_dir.source
        ));
        lines.push(format!(
            "  home = \"{}\"  # {}",
            self.home_dir.value.display(),
            self.home_dir.source
        ));
        lines.push(String::new());

        lines.push("[identity]".into());
        lines.push(format!(
            "  operator = \"{}\"  # {}",
            self.operator_name.value, self.operator_name.source
        ));
        lines.push(String::new());

        lines.push("[llm]".into());
        lines.push(format!(
            "  enabled = {}  # {}",
            self.llm_enabled.value, self.llm_enabled.source
        ));
        lines.push(format!(
            "  provider = \"{}\"  # {}",
            self.llm_provider.value, self.llm_provider.source
        ));
        lines.push(format!(
            "  model = \"{}\"  # {}",
            self.llm_model.value, self.llm_model.source
        ));
        lines.push(format!(
            "  escalation_model = \"{}\"  # {}",
            self.llm_escalation_model.value, self.llm_escalation_model.source
        ));
        lines.push(format!(
            "  supports_tools = {}  # {}",
            self.llm_supports_tools.value, self.llm_supports_tools.source
        ));
        lines.push(String::new());

        lines.push("[node]".into());
        lines.push(format!(
            "  role = \"{}\"  # {}",
            self.node_role.value, self.node_role.source
        ));
        if let Some(ref upstream) = self.node_upstream.value {
            lines.push(format!(
                "  upstream = \"{}\"  # {}",
                upstream, self.node_upstream.source
            ));
        }

        lines.push(String::new());
        lines.push("[officers]".into());
        lines.push(format!(
            "  enabled = {}  # {}",
            self.officers_enabled.value, self.officers_enabled.source
        ));
        lines.push(format!(
            "  sweep_interval_secs = {}  # {}",
            self.officers_sweep_interval_secs.value, self.officers_sweep_interval_secs.source
        ));
        lines.push(format!(
            "  steward_enabled = {}  # {}",
            self.officers_steward_enabled.value, self.officers_steward_enabled.source
        ));
        lines.push(format!(
            "  sentinel_enabled = {}  # {}",
            self.officers_sentinel_enabled.value, self.officers_sentinel_enabled.source
        ));
        lines.push(format!(
            "  forge_enabled = {}  # {}",
            self.officers_forge_enabled.value, self.officers_forge_enabled.source
        ));
        lines.push(format!(
            "  cleo_enabled = {}  # {}",
            self.officers_cleo_enabled.value, self.officers_cleo_enabled.source
        ));
        lines.push(format!(
            "  aegis_enabled = {}  # {}",
            self.officers_aegis_enabled.value, self.officers_aegis_enabled.source
        ));
        if !self.acknowledged_listeners.value.is_empty() {
            for ack in &self.acknowledged_listeners.value {
                lines.push(format!(
                    "  acknowledged_listener = {{ name = \"{}\", port = {} }}  # {}",
                    ack.name, ack.port, self.acknowledged_listeners.source
                ));
            }
        }

        lines.push(String::new());
        lines.push("[regent]".into());
        lines.push(format!(
            "  enabled = {}  # {}",
            self.regent_enabled.value, self.regent_enabled.source
        ));
        lines.push(format!(
            "  inference_endpoint = \"{}\"  # {}",
            self.regent_inference_endpoint.value, self.regent_inference_endpoint.source
        ));
        if let Some(ref _key) = self.regent_inference_api_key.value {
            lines.push(format!(
                "  inference_api_key = \"***\"  # {} (redacted)",
                self.regent_inference_api_key.source
            ));
        }
        lines.push(format!(
            "  reasoning_model = \"{}\"  # {}",
            self.regent_reasoning_model.value, self.regent_reasoning_model.source
        ));
        lines.push(format!(
            "  routing_model = \"{}\"  # {}",
            self.regent_routing_model.value, self.regent_routing_model.source
        ));
        lines.push(format!(
            "  loop_interval_secs = {}  # {}",
            self.regent_loop_interval_secs.value, self.regent_loop_interval_secs.source
        ));
        lines.push(format!(
            "  display_name = \"{}\"  # {}",
            self.regent_display_name.value, self.regent_display_name.source
        ));

        lines.join("\n")
    }

    /// Serialize to TOML for writing to config.toml (values only, no provenance).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        let file = ConfigFile::from(self);
        toml::to_string_pretty(&file)
    }
}

// ─── TOML file schema (for ser/deser) ────────────────────────

/// The on-disk TOML representation (no provenance — just values).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub data: DataSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub llm: LlmSection,
    #[serde(default)]
    pub node: NodeSection,
    #[serde(default)]
    pub officers: OfficersSection,
    #[serde(default)]
    pub regent: RegentSection,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub port: Option<u16>,
    pub bind: Option<String>,
    pub open_dashboard: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DataSection {
    pub dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentitySection {
    pub operator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LlmSection {
    pub enabled: Option<bool>,
    /// Proxy provider segment (must be known to the server's provider registry).
    pub provider: Option<String>,
    /// Default-tier model name.
    pub model: Option<String>,
    /// Escalation-tier model name. Empty string disables the tier.
    pub escalation_model: Option<String>,
    /// Whether these models implement the OpenAI tool-call format.
    pub supports_tools: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Node role in the trust topology: "genesis" (default) or "delegate".
    pub role: Option<String>,
    /// Upstream authority address for delegate nodes (e.g., "192.168.1.199:17770").
    pub upstream: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OfficersSection {
    /// Master switch for the officer cadre.
    pub enabled: Option<bool>,
    /// Seconds between sweep cycles (default: 900 = 15 minutes).
    pub sweep_interval_secs: Option<u64>,
    /// Enable the Steward (integrity) officer.
    pub steward_enabled: Option<bool>,
    /// Enable the Sentinel (security) officer.
    pub sentinel_enabled: Option<bool>,
    /// Enable the Forge (operations) officer.
    pub forge_enabled: Option<bool>,
    /// Enable the Cleo (governance) officer.
    pub cleo_enabled: Option<bool>,
    /// Enable the Aegis (trajectory) officer.
    pub aegis_enabled: Option<bool>,
    /// External processes the operator acknowledges as expected listeners.
    /// Each entry is a table: `{ name = "ollama", port = 11434 }`.
    /// Registered as KnownBindings so the Sentinel tracks them instead of
    /// alerting on them. If the process disappears, the Sentinel flags it
    /// as stale — visibility, not blindness.
    pub acknowledged_listeners: Option<Vec<AcknowledgedListener>>,
}

/// An external process the operator has explicitly acknowledged.
/// Registered with the sensor layer as a KnownBinding so the Sentinel
/// tracks it (reports if it disappears) rather than alerting on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcknowledgedListener {
    /// Human-readable name (e.g., "ollama", "comet-cdp").
    pub name: String,
    /// Expected port. The Sentinel flags if something else binds this port.
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RegentSection {
    /// Enable the Regent cognitive loop.
    pub enabled: Option<bool>,
    /// Inference endpoint (Ollama local or OpenAI-compatible cloud).
    pub inference_endpoint: Option<String>,
    /// API key for cloud inference. When set, uses OpenAI protocol.
    pub inference_api_key: Option<String>,
    /// Model for reasoning tasks.
    pub reasoning_model: Option<String>,
    /// Model for fast routing/classification.
    pub routing_model: Option<String>,
    /// Seconds between autonomous cognitive cycles (0 = disable autonomous wake).
    pub loop_interval_secs: Option<u64>,
    /// Display name for the Regent (operator-renameable via chain receipt).
    pub display_name: Option<String>,
}

impl From<&ZpConfig> for ConfigFile {
    fn from(cfg: &ZpConfig) -> Self {
        Self {
            server: ServerSection {
                port: Some(cfg.port.value),
                bind: Some(cfg.bind.value.clone()),
                open_dashboard: Some(cfg.open_dashboard.value),
            },
            data: DataSection {
                dir: Some(cfg.data_dir.value.to_string_lossy().into()),
            },
            identity: IdentitySection {
                operator: Some(cfg.operator_name.value.clone()),
            },
            llm: LlmSection {
                enabled: Some(cfg.llm_enabled.value),
                provider: Some(cfg.llm_provider.value.clone()),
                model: Some(cfg.llm_model.value.clone()),
                escalation_model: Some(cfg.llm_escalation_model.value.clone()),
                supports_tools: Some(cfg.llm_supports_tools.value),
            },
            node: NodeSection {
                role: Some(cfg.node_role.value.clone()),
                upstream: cfg.node_upstream.value.clone(),
            },
            officers: OfficersSection {
                enabled: Some(cfg.officers_enabled.value),
                sweep_interval_secs: Some(cfg.officers_sweep_interval_secs.value),
                steward_enabled: Some(cfg.officers_steward_enabled.value),
                sentinel_enabled: Some(cfg.officers_sentinel_enabled.value),
                forge_enabled: Some(cfg.officers_forge_enabled.value),
                cleo_enabled: Some(cfg.officers_cleo_enabled.value),
                aegis_enabled: Some(cfg.officers_aegis_enabled.value),
                acknowledged_listeners: if cfg.acknowledged_listeners.value.is_empty() {
                    None
                } else {
                    Some(cfg.acknowledged_listeners.value.clone())
                },
            },
            regent: RegentSection {
                enabled: Some(cfg.regent_enabled.value),
                inference_endpoint: Some(cfg.regent_inference_endpoint.value.clone()),
                inference_api_key: cfg.regent_inference_api_key.value.clone(),
                reasoning_model: Some(cfg.regent_reasoning_model.value.clone()),
                routing_model: Some(cfg.regent_routing_model.value.clone()),
                loop_interval_secs: Some(cfg.regent_loop_interval_secs.value),
                display_name: Some(cfg.regent_display_name.value.clone()),
            },
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Resolve the ZeroPoint home directory.
///
/// **Mirror of [`zp_core::paths::home`]** (Seam 19) — kept local instead
/// of depending on `zp-core` because `zp-config` is a bootstrap-layer
/// crate that needs to stay light on dependencies. If the resolution
/// rule in `zp_core::paths::home` ever changes, this function MUST be
/// updated to match. The two stay in sync by hand.
fn zp_home() -> PathBuf {
    if let Ok(h) = std::env::var("ZP_HOME") {
        return PathBuf::from(h);
    }
    dirs_home().join("ZeroPoint")
}

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "operator".into())
}
