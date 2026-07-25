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
        if let Ok(v) = std::env::var("ZP_OFFICERS_ENABLED") {
            self.config.officers_enabled.override_with(
                v == "true" || v == "1",
                Source::EnvVar("ZP_OFFICERS_ENABLED".into()),
            );
        }
        if let Ok(v) = std::env::var("ZP_OFFICERS_SWEEP_INTERVAL") {
            if let Ok(secs) = v.parse::<u64>() {
                self.config.officers_sweep_interval_secs.override_with(
                    secs,
                    Source::EnvVar("ZP_OFFICERS_SWEEP_INTERVAL".into()),
                );
            }
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

    /// Finalize and return the resolved configuration.
    pub fn resolve(self) -> ZpConfig {
        self.config
    }

    /// Standard resolution with error propagation: defaults → system → project → env.
    /// Returns Err if any config file contains unknown sections or invalid TOML.
    pub fn resolve_standard() -> Result<ZpConfig, ConfigError> {
        let mut r = Self::new();

        let system_path = r.config.home_dir.value.join("config.toml");
        if system_path.exists() {
            let file = load_toml(&system_path)?;
            r.apply_file(file, Source::SystemConfig);
        }

        if let Some(project_path) = find_project_config() {
            let file = load_toml(&project_path)?;
            r.apply_file(file, Source::ProjectConfig);
        }

        Ok(r.load_env_vars().resolve())
    }

    /// Resolve standard config, or print a clear error and exit(1).
    /// Use this in CLI entry points; use resolve_standard() in tests.
    pub fn resolve_standard_or_exit() -> ZpConfig {
        match Self::resolve_standard() {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("\x1b[31m✗\x1b[0m  Config error: {e}");
                eprintln!("  Check your config file for unknown sections or typos.");
                eprintln!("  Run `zp config show` to see the active configuration.");
                std::process::exit(1);
            }
        }
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
        // LLM
        if let Some(v) = file.llm.enabled {
            self.config.llm_enabled.override_with(v, source.clone());
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
        // Officers
        if let Some(v) = file.officers.enabled {
            self.config.officers_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.sweep_interval_secs {
            self.config.officers_sweep_interval_secs.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.steward_enabled {
            self.config.officers_steward_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.sentinel_enabled {
            self.config.officers_sentinel_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.forge_enabled {
            self.config.officers_forge_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.cleo_enabled {
            self.config.officers_cleo_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.aegis_enabled {
            self.config.officers_aegis_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.officers.acknowledged_listeners {
            self.config.acknowledged_listeners.override_with(v, source.clone());
        }
        // Regent
        if let Some(v) = file.regent.enabled {
            self.config.regent_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.regent.inference_endpoint {
            self.config.regent_inference_endpoint.override_with(v, source.clone());
        }
        if let Some(v) = file.regent.inference_api_key {
            self.config.regent_inference_api_key.override_with(Some(v), source.clone());
        }
        if let Some(v) = file.regent.reasoning_model {
            self.config.regent_reasoning_model.override_with(v, source.clone());
        }
        if let Some(v) = file.regent.routing_model {
            self.config.regent_routing_model.override_with(v, source.clone());
        }
        if let Some(v) = file.regent.loop_interval_secs {
            self.config.regent_loop_interval_secs.override_with(v, source.clone());
        }
        if let Some(v) = file.regent.display_name {
            self.config.regent_display_name.override_with(v, source.clone());
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
        "officers.enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.officers.enabled = Some(b);
        }
        "officers.sweep_interval_secs" => {
            let n: u64 = value.parse().map_err(|_| ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be a positive integer (seconds)".into(),
            })?;
            file.officers.sweep_interval_secs = Some(n);
        }
        "officers.steward_enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.officers.steward_enabled = Some(b);
        }
        "officers.cleo_enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.officers.cleo_enabled = Some(b);
        }
        "officers.aegis_enabled" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.officers.aegis_enabled = Some(b);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_section_rejected() {
        let toml = r#"
[server]
port = 17010

[bogus]
foo = "bar"
"#;
        let result: Result<crate::schema::ConfigFile, _> = toml::from_str(toml);
        assert!(result.is_err(), "unknown section must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("bogus") || msg.contains("unknown"),
            "error must mention the unknown field: {msg}"
        );
    }

    #[test]
    fn known_sections_accepted() {
        let toml = r#"
[server]
port = 17010
bind = "127.0.0.1"

[identity]
operator = "testuser"
"#;
        let result: Result<crate::schema::ConfigFile, _> = toml::from_str(toml);
        assert!(result.is_ok(), "valid config must parse: {:?}", result.err());
    }
}
