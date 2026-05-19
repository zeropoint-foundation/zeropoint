//! The unified configuration schema.
//!
//! Every field is a [`Sourced<T>`] so we track provenance. The TOML file
//! uses a flat-ish structure that mirrors the `zp config show` output.

use crate::provenance::Sourced;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

    // ── Node topology ──
    /// Node role: "genesis" (default) or "delegate".
    /// Genesis nodes verify their own local chain.
    /// Delegate nodes verify against their upstream authority.
    pub node_role: Sourced<String>,
    /// Upstream server address for delegate nodes (e.g., "192.168.1.199:17770").
    /// Ignored when node_role is "genesis".
    pub node_upstream: Sourced<Option<String>>,

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

            node_role: Sourced::default_value("genesis".into()),
            node_upstream: Sourced::default_value(None),

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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Node role in the trust topology: "genesis" (default) or "delegate".
    pub role: Option<String>,
    /// Upstream authority address for delegate nodes (e.g., "192.168.1.199:17770").
    pub upstream: Option<String>,
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
            },
            node: NodeSection {
                role: Some(cfg.node_role.value.clone()),
                upstream: cfg.node_upstream.value.clone(),
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
