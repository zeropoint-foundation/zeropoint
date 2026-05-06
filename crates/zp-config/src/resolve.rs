//! Configuration resolver — layers sources by priority.
//!
//! Resolution order: defaults → system config → project config → env vars → CLI flags.

use crate::error::ConfigError;
use crate::provenance::Source;
use crate::schema::{ConfigFile, ZpConfig};
use std::path::{Path, PathBuf};

/// Builder that accumulates configuration layers and resolves them.
pub struct ConfigResolver {
    config: ZpConfig,
}

impl ConfigResolver {
    /// Start with compiled defaults.
    pub fn new() -> Self {
        Self {
            config: ZpConfig::default(),
        }
    }

    /// Layer 1: Load system config from `~/ZeroPoint/config.toml`.
    pub fn load_system_config(mut self) -> Self {
        let path = self.config.home_dir.value.join("config.toml");
        if path.exists() {
            if let Ok(file) = load_toml(&path) {
                self.apply_file(file, Source::SystemConfig);
            }
        }
        self
    }

    /// Layer 2: Load project config from `./zeropoint.toml` (walking up from cwd).
    pub fn load_project_config(mut self) -> Self {
        if let Some(path) = find_project_config() {
            if let Ok(file) = load_toml(&path) {
                self.apply_file(file, Source::ProjectConfig);
            }
        }
        self
    }

    /// Layer 3: Apply environment variable overrides.
    pub fn load_env_vars(mut self) -> Self {
        if let Ok(v) = std::env::var("ZP_PORT") {
            if let Ok(port) = v.parse::<u16>() {
                self.config
                    .port
                    .override_with(port, Source::EnvVar("ZP_PORT".into()));
            }
        }
        if let Ok(v) = std::env::var("ZP_BIND") {
            self.config
                .bind
                .override_with(v, Source::EnvVar("ZP_BIND".into()));
        }
        if let Ok(v) = std::env::var("ZP_DATA_DIR") {
            self.config
                .data_dir
                .override_with(PathBuf::from(v), Source::EnvVar("ZP_DATA_DIR".into()));
        }
        if let Ok(v) = std::env::var("ZP_HOME") {
            let home = PathBuf::from(&v);
            self.config
                .home_dir
                .override_with(home.clone(), Source::EnvVar("ZP_HOME".into()));
            // If data_dir hasn't been explicitly set, derive it from home
            if matches!(self.config.data_dir.source, Source::Default) {
                self.config
                    .data_dir
                    .override_with(home.join("data"), Source::EnvVar("ZP_HOME".into()));
            }
        }
        if let Ok(v) = std::env::var("ZP_LLM_ENABLED") {
            self.config.llm_enabled.override_with(
                v == "true" || v == "1",
                Source::EnvVar("ZP_LLM_ENABLED".into()),
            );
        }
        if let Ok(v) = std::env::var("ZP_OPERATOR_NAME") {
            self.config
                .operator_name
                .override_with(v, Source::EnvVar("ZP_OPERATOR_NAME".into()));
        }
        if let Ok(v) = std::env::var("ZP_NO_OPEN") {
            self.config.open_dashboard.override_with(
                !(v == "true" || v == "1"),
                Source::EnvVar("ZP_NO_OPEN".into()),
            );
        }
        if let Ok(v) = std::env::var("ZP_LOG_LEVEL") {
            self.config
                .log_level
                .override_with(v, Source::EnvVar("ZP_LOG_LEVEL".into()));
        }
        if let Ok(v) = std::env::var("ZP_SESSION_MAX_AGE_SECONDS") {
            if let Ok(secs) = v.parse::<u64>() {
                self.config
                    .session_max_age_s
                    .override_with(secs, Source::EnvVar("ZP_SESSION_MAX_AGE_SECONDS".into()));
            }
        }
        if let Ok(v) = std::env::var("ZP_AUTH_RATE_LIMIT_PER_MIN") {
            if let Ok(rate) = v.parse::<u32>() {
                self.config
                    .auth_rate_limit_per_min
                    .override_with(rate, Source::EnvVar("ZP_AUTH_RATE_LIMIT_PER_MIN".into()));
            }
        }
        // ZP_NODE_ROLE is NO LONGER HONORED — node role is derived from chain state (genesis.json
        // or delegation receipt), not from config or env vars. This is a critical security fix.
        // If someone sets ZP_NODE_ROLE, it is silently ignored. To override role in testing,
        // use --unsafe-allow-role-override on the CLI (future feature, T1 phase 2).
        if let Ok(_v) = std::env::var("ZP_NODE_ROLE") {
            tracing::warn!("ZP_NODE_ROLE environment variable is set but ignored. Node role is derived from chain state (genesis.json or delegation receipt). See T1 design spec.");
        }
        if let Ok(v) = std::env::var("ZP_NODE_UPSTREAM") {
            self.config
                .node_upstream
                .override_with(Some(v), Source::EnvVar("ZP_NODE_UPSTREAM".into()));
        }
        self
    }

    /// Layer 4: Apply CLI flag overrides.
    pub fn apply_cli_port(mut self, port: u16) -> Self {
        self.config
            .port
            .override_with(port, Source::CliFlag("port".into()));
        self
    }

    pub fn apply_cli_bind(mut self, bind: String) -> Self {
        self.config
            .bind
            .override_with(bind, Source::CliFlag("bind".into()));
        self
    }

    pub fn apply_cli_no_open(mut self) -> Self {
        self.config
            .open_dashboard
            .override_with(false, Source::CliFlag("no-open".into()));
        self
    }

    pub fn apply_cli_data_dir(mut self, dir: PathBuf) -> Self {
        self.config
            .data_dir
            .override_with(dir, Source::CliFlag("data-dir".into()));
        self
    }

    pub fn apply_cli_log_level(mut self, level: String) -> Self {
        self.config
            .log_level
            .override_with(level, Source::CliFlag("log-level".into()));
        self
    }

    /// Finalize and return the resolved configuration.
    pub fn resolve(self) -> ZpConfig {
        self.config
    }

    /// Standard resolution: defaults → system → project → env → (no CLI yet).
    /// CLI flags are applied by the caller after this.
    pub fn resolve_standard() -> ZpConfig {
        Self::new()
            .load_system_config()
            .load_project_config()
            .load_env_vars()
            .resolve()
    }

    // ── Internal ─────────────────────────────────────────────

    fn apply_file(&mut self, file: ConfigFile, source: Source) {
        // Server
        if let Some(v) = file.server.port {
            self.config.port.override_with(v, source.clone());
        }
        if let Some(v) = file.server.bind {
            self.config.bind.override_with(v, source.clone());
        }
        if let Some(v) = file.server.open_dashboard {
            self.config.open_dashboard.override_with(v, source.clone());
        }
        // Data
        if let Some(v) = file.data.dir {
            let path = expand_tilde(&v);
            self.config.data_dir.override_with(path, source.clone());
        }
        // Identity
        if let Some(v) = file.identity.operator {
            self.config.operator_name.override_with(v, source.clone());
        }
        if let Some(v) = file.identity.sovereignty_mode {
            self.config
                .sovereignty_mode
                .override_with(v, source.clone());
        }
        // Governance
        if let Some(v) = file.governance.posture {
            self.config.posture.override_with(v, source.clone());
        }
        // LLM
        if let Some(v) = file.llm.enabled {
            self.config.llm_enabled.override_with(v, source.clone());
        }
        // Logging
        if let Some(v) = file.logging.level {
            self.config.log_level.override_with(v, source.clone());
        }
        // Session
        if let Some(v) = file.session.max_age_s {
            self.config
                .session_max_age_s
                .override_with(v, source.clone());
        }
        if let Some(v) = file.session.auth_rate_limit_per_min {
            self.config
                .auth_rate_limit_per_min
                .override_with(v, source.clone());
        }
        // Mesh
        if let Some(v) = file.mesh.enabled {
            self.config.mesh_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.mesh.listen {
            self.config
                .mesh_listen
                .override_with(Some(v), source.clone());
        }
        if let Some(v) = file.mesh.peers {
            self.config.mesh_peers.override_with(v, source.clone());
        }
        // DLT
        if let Some(v) = file.dlt.enabled {
            self.config.dlt_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.dlt.network {
            self.config.dlt_network.override_with(v, source.clone());
        }
        // Shell
        if let Some(v) = file.shell.hook_enabled {
            self.config
                .shell_hook_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.shell.posture {
            self.config.shell_posture.override_with(v, source.clone());
        }
        // Filesystem
        if let Some(v) = file.filesystem.watch_enabled {
            self.config
                .fs_watch_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.filesystem.watch_dirs {
            self.config.fs_watch_dirs.override_with(v, source.clone());
        }
        // Docker
        if let Some(v) = file.docker.enabled {
            self.config.docker_enabled.override_with(v, source.clone());
        }
        // Node topology
        if let Some(v) = file.node.role {
            self.config.node_role.override_with(v, source.clone());
        }
        if let Some(v) = file.node.upstream {
            self.config
                .node_upstream
                .override_with(Some(v), source.clone());
        }
    }
}

impl Default for ConfigResolver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── File loading ────────────────────────────────────────────

fn load_toml(path: &Path) -> Result<ConfigFile, ConfigError> {
    let content = std::fs::read_to_string(path).map_err(|e| ConfigError::ParseError {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    toml::from_str(&content).map_err(|e| ConfigError::ParseError {
        path: path.display().to_string(),
        detail: e.to_string(),
    })
}

fn find_project_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join("zeropoint.toml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") || path == "~" {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(path.replacen('~', &home, 1))
    } else {
        PathBuf::from(path)
    }
}

// ─── Config writing (for `zp config set`) ────────────────────

/// Set a single key-value pair in ~/ZeroPoint/config.toml.
/// Reads the existing file, updates the value, and writes it back.
///
/// Path resolution mirrors [`zp_core::paths::home`] (Seam 19); see the
/// comment on `zp_home` in `schema.rs` for why `zp-config` keeps a
/// local copy instead of depending on `zp-core`.
pub fn config_set(key: &str, value: &str) -> Result<(), ConfigError> {
    let zp_home = if let Ok(h) = std::env::var("ZP_HOME") {
        PathBuf::from(h)
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join("ZeroPoint")
    };
    let config_path = zp_home.join("config.toml");

    // Load existing or create empty
    let mut file: ConfigFile = if config_path.exists() {
        load_toml(&config_path)?
    } else {
        ConfigFile::default()
    };

    // Apply the change
    match key {
        "port" | "server.port" => {
            let port: u16 = value.parse().map_err(|_| ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be a number between 1 and 65535".into(),
            })?;
            if port == 0 {
                return Err(ConfigError::InvalidValue {
                    key: key.into(),
                    reason: "port 0 is not valid".into(),
                });
            }
            file.server.port = Some(port);
        }
        "bind" | "server.bind" => {
            file.server.bind = Some(value.into());
        }
        "data.dir" | "data_dir" => {
            let path = expand_tilde(value);
            if !path.parent().map(|p| p.exists()).unwrap_or(true) {
                return Err(ConfigError::InvalidValue {
                    key: key.into(),
                    reason: format!("parent directory does not exist: {}", path.display()),
                });
            }
            file.data.dir = Some(value.into());
        }
        "posture" | "governance.posture" => {
            match value {
                "permissive" | "balanced" | "strict" => {}
                _ => {
                    return Err(ConfigError::InvalidValue {
                        key: key.into(),
                        reason: "must be one of: permissive, balanced, strict".into(),
                    })
                }
            }
            file.governance.posture = Some(value.into());
        }
        "log_level" | "logging.level" => {
            match value {
                "trace" | "debug" | "info" | "warn" | "error" => {}
                _ => {
                    return Err(ConfigError::InvalidValue {
                        key: key.into(),
                        reason: "must be one of: trace, debug, info, warn, error".into(),
                    })
                }
            }
            file.logging.level = Some(value.into());
        }
        "operator" | "identity.operator" => {
            file.identity.operator = Some(value.into());
        }
        "llm.enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.llm.enabled = Some(b);
        }
        "mesh.enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.mesh.enabled = Some(b);
        }
        "mesh.listen" => {
            file.mesh.listen = Some(value.into());
        }
        "dlt.enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.dlt.enabled = Some(b);
        }
        "dlt.network" => {
            match value {
                "mainnet" | "testnet" | "previewnet" => {}
                _ => {
                    return Err(ConfigError::InvalidValue {
                        key: key.into(),
                        reason: "must be one of: mainnet, testnet, previewnet".into(),
                    })
                }
            }
            file.dlt.network = Some(value.into());
        }
        "node.role" => {
            match value {
                "genesis" | "delegate" => {}
                _ => {
                    return Err(ConfigError::InvalidValue {
                        key: key.into(),
                        reason: "must be one of: genesis, delegate".into(),
                    })
                }
            }
            file.node.role = Some(value.into());
        }
        "node.upstream" => {
            file.node.upstream = Some(value.into());
        }
        _ => {
            return Err(ConfigError::InvalidValue {
                key: key.into(),
                reason: format!(
                    "unknown config key '{key}'. Run 'zp config show' to see available keys."
                ),
            })
        }
    }

    // Write back
    let toml_str = toml::to_string_pretty(&file).map_err(|e| ConfigError::ParseError {
        path: config_path.display().to_string(),
        detail: e.to_string(),
    })?;

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, toml_str)?;

    Ok(())
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}
