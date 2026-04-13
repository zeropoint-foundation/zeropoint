//! The unified configuration schema.
//!
//! Every field is a [`Sourced<T>`] so we track provenance. The TOML file
//! uses a flat-ish structure that mirrors the `zp config show` output.

use crate::provenance::{Source, Sourced};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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
    pub sovereignty_mode: Sourced<String>,

    // ── Governance ──
    pub posture: Sourced<String>,

    // ── LLM ──
    pub llm_enabled: Sourced<bool>,

    // ── Logging ──
    pub log_level: Sourced<String>,

    // ── Session / Auth ──
    pub session_max_age_s: Sourced<u64>,
    pub auth_rate_limit_per_min: Sourced<u32>,

    // ── Mesh (optional) ──
    pub mesh_enabled: Sourced<bool>,
    pub mesh_listen: Sourced<Option<String>>,
    pub mesh_peers: Sourced<Vec<String>>,

    // ── DLT (optional) ──
    pub dlt_enabled: Sourced<bool>,
    pub dlt_network: Sourced<String>,

    // ── Docker (optional) ──
    pub docker_enabled: Sourced<bool>,

    // ── Shell governance ──
    pub shell_hook_enabled: Sourced<bool>,
    pub shell_posture: Sourced<String>,

    // ── Filesystem monitoring ──
    pub fs_watch_enabled: Sourced<bool>,
    pub fs_watch_dirs: Sourced<Vec<String>>,
}

impl Default for ZpConfig {
    fn default() -> Self {
        let home = dirs_home().join(".zeropoint");
        Self {
            port: Sourced::default_value(3000),
            bind: Sourced::default_value("127.0.0.1".into()),
            open_dashboard: Sourced::default_value(true),

            data_dir: Sourced::default_value(home.join("data")),
            home_dir: Sourced::default_value(home),

            operator_name: Sourced::default_value(whoami()),
            sovereignty_mode: Sourced::default_value("auto".into()),

            posture: Sourced::default_value("balanced".into()),

            llm_enabled: Sourced::default_value(false),

            log_level: Sourced::default_value("info".into()),

            session_max_age_s: Sourced::default_value(28800), // 8 hours
            auth_rate_limit_per_min: Sourced::default_value(10),

            mesh_enabled: Sourced::default_value(false),
            mesh_listen: Sourced::default_value(None),
            mesh_peers: Sourced::default_value(vec![]),

            dlt_enabled: Sourced::default_value(false),
            dlt_network: Sourced::default_value("testnet".into()),

            docker_enabled: Sourced::default_value(false),

            shell_hook_enabled: Sourced::default_value(true),
            shell_posture: Sourced::default_value("balanced".into()),

            fs_watch_enabled: Sourced::default_value(false),
            fs_watch_dirs: Sourced::default_value(vec![]),
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
        lines.push(format!("  sovereignty: {}", self.sovereignty_mode));
        lines.push(format!("  posture: {}", self.posture));
        lines.push(format!("  llm: {}", self.llm_enabled));
        lines.push(format!("  log_level: {}", self.log_level));
        if self.mesh_enabled.value {
            lines.push(format!("  mesh: {:?}", self.mesh_listen));
        }
        if self.dlt_enabled.value {
            lines.push(format!("  dlt: {}", self.dlt_network));
        }
        lines.join("\n")
    }

    /// Produce the `zp config show` output with provenance for every field.
    pub fn show(&self) -> String {
        let mut lines = Vec::new();
        lines.push("[server]".into());
        lines.push(format!("  port = {}  # {}", self.port.value, self.port.source));
        lines.push(format!("  bind = \"{}\"  # {}", self.bind.value, self.bind.source));
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
        lines.push(format!(
            "  sovereignty = \"{}\"  # {}",
            self.sovereignty_mode.value, self.sovereignty_mode.source
        ));
        lines.push(String::new());

        lines.push("[governance]".into());
        lines.push(format!(
            "  posture = \"{}\"  # {}",
            self.posture.value, self.posture.source
        ));
        lines.push(String::new());

        lines.push("[llm]".into());
        lines.push(format!(
            "  enabled = {}  # {}",
            self.llm_enabled.value, self.llm_enabled.source
        ));
        lines.push(String::new());

        lines.push("[logging]".into());
        lines.push(format!(
            "  level = \"{}\"  # {}",
            self.log_level.value, self.log_level.source
        ));
        lines.push(String::new());

        lines.push("[session]".into());
        lines.push(format!(
            "  max_age_s = {}  # {}",
            self.session_max_age_s.value, self.session_max_age_s.source
        ));
        lines.push(format!(
            "  auth_rate_limit_per_min = {}  # {}",
            self.auth_rate_limit_per_min.value, self.auth_rate_limit_per_min.source
        ));
        lines.push(String::new());

        lines.push("[mesh]".into());
        lines.push(format!(
            "  enabled = {}  # {}",
            self.mesh_enabled.value, self.mesh_enabled.source
        ));
        if let Some(ref listen) = self.mesh_listen.value {
            lines.push(format!("  listen = \"{}\"  # {}", listen, self.mesh_listen.source));
        }
        if !self.mesh_peers.value.is_empty() {
            lines.push(format!(
                "  peers = {:?}  # {}",
                self.mesh_peers.value, self.mesh_peers.source
            ));
        }
        lines.push(String::new());

        lines.push("[dlt]".into());
        lines.push(format!(
            "  enabled = {}  # {}",
            self.dlt_enabled.value, self.dlt_enabled.source
        ));
        lines.push(format!(
            "  network = \"{}\"  # {}",
            self.dlt_network.value, self.dlt_network.source
        ));
        lines.push(String::new());

        lines.push("[shell]".into());
        lines.push(format!(
            "  hook_enabled = {}  # {}",
            self.shell_hook_enabled.value, self.shell_hook_enabled.source
        ));
        lines.push(format!(
            "  posture = \"{}\"  # {}",
            self.shell_posture.value, self.shell_posture.source
        ));
        lines.push(String::new());

        lines.push("[filesystem]".into());
        lines.push(format!(
            "  watch_enabled = {}  # {}",
            self.fs_watch_enabled.value, self.fs_watch_enabled.source
        ));
        if !self.fs_watch_dirs.value.is_empty() {
            lines.push(format!(
                "  watch_dirs = {:?}  # {}",
                self.fs_watch_dirs.value, self.fs_watch_dirs.source
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
pub struct ConfigFile {
    #[serde(default)]
    pub server: ServerSection,
    #[serde(default)]
    pub data: DataSection,
    #[serde(default)]
    pub identity: IdentitySection,
    #[serde(default)]
    pub governance: GovernanceSection,
    #[serde(default)]
    pub llm: LlmSection,
    #[serde(default)]
    pub logging: LoggingSection,
    #[serde(default)]
    pub session: SessionSection,
    #[serde(default)]
    pub mesh: MeshSection,
    #[serde(default)]
    pub dlt: DltSection,
    #[serde(default)]
    pub shell: ShellSection,
    #[serde(default)]
    pub filesystem: FilesystemSection,
    #[serde(default)]
    pub docker: DockerSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSection {
    pub port: Option<u16>,
    pub bind: Option<String>,
    pub open_dashboard: Option<bool>,
}

impl Default for ServerSection {
    fn default() -> Self {
        Self {
            port: None,
            bind: None,
            open_dashboard: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataSection {
    pub dir: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentitySection {
    pub operator: Option<String>,
    pub sovereignty_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceSection {
    pub posture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LlmSection {
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LoggingSection {
    pub level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SessionSection {
    pub max_age_s: Option<u64>,
    pub auth_rate_limit_per_min: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MeshSection {
    pub enabled: Option<bool>,
    pub listen: Option<String>,
    pub peers: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DltSection {
    pub enabled: Option<bool>,
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellSection {
    pub hook_enabled: Option<bool>,
    pub posture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemSection {
    pub watch_enabled: Option<bool>,
    pub watch_dirs: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DockerSection {
    pub enabled: Option<bool>,
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
                sovereignty_mode: Some(cfg.sovereignty_mode.value.clone()),
            },
            governance: GovernanceSection {
                posture: Some(cfg.posture.value.clone()),
            },
            llm: LlmSection {
                enabled: Some(cfg.llm_enabled.value),
            },
            logging: LoggingSection {
                level: Some(cfg.log_level.value.clone()),
            },
            session: SessionSection {
                max_age_s: Some(cfg.session_max_age_s.value),
                auth_rate_limit_per_min: Some(cfg.auth_rate_limit_per_min.value),
            },
            mesh: MeshSection {
                enabled: Some(cfg.mesh_enabled.value),
                listen: cfg.mesh_listen.value.clone(),
                peers: if cfg.mesh_peers.value.is_empty() {
                    None
                } else {
                    Some(cfg.mesh_peers.value.clone())
                },
            },
            dlt: DltSection {
                enabled: Some(cfg.dlt_enabled.value),
                network: Some(cfg.dlt_network.value.clone()),
            },
            shell: ShellSection {
                hook_enabled: Some(cfg.shell_hook_enabled.value),
                posture: Some(cfg.shell_posture.value.clone()),
            },
            filesystem: FilesystemSection {
                watch_enabled: Some(cfg.fs_watch_enabled.value),
                watch_dirs: if cfg.fs_watch_dirs.value.is_empty() {
                    None
                } else {
                    Some(cfg.fs_watch_dirs.value.clone())
                },
            },
            docker: DockerSection {
                enabled: Some(cfg.docker_enabled.value),
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

fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "operator".into())
}
