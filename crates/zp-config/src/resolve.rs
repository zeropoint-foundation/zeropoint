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
        if let Ok(v) = std::env::var("ZP_LLM_PROVIDER") {
            self.config
                .llm_provider
                .override_with(v, Source::EnvVar("ZP_LLM_PROVIDER".into()));
        }
        if let Ok(v) = std::env::var("ZP_LLM_MODEL") {
            self.config
                .llm_model
                .override_with(v, Source::EnvVar("ZP_LLM_MODEL".into()));
        }
        if let Ok(v) = std::env::var("ZP_LLM_ESCALATION_MODEL") {
            self.config
                .llm_escalation_model
                .override_with(v, Source::EnvVar("ZP_LLM_ESCALATION_MODEL".into()));
        }
        if let Ok(v) = std::env::var("ZP_LLM_SUPPORTS_TOOLS") {
            self.config.llm_supports_tools.override_with(
                v == "true" || v == "1",
                Source::EnvVar("ZP_LLM_SUPPORTS_TOOLS".into()),
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
                self.config
                    .officers_sweep_interval_secs
                    .override_with(secs, Source::EnvVar("ZP_OFFICERS_SWEEP_INTERVAL".into()));
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

    /// HARNESS-SEAM-2026-08 §4 S5 ("no shadowed writes"), boot-time
    /// complement to W6's write-time refusal in `config_set`. `config_set`
    /// refuses (or warns) when a *write* would land in a layer already
    /// shadowed by something higher-priority; this asks the same question
    /// about the state the substrate is already running with, every boot
    /// -- not just at the moment of a `zp config set`.
    ///
    /// Deliberately non-fatal. Unlike S1-S3, a shadow found here does not
    /// refuse to boot -- see the W7 report for why: an env var legitimately
    /// shadowing a file value is common and often intentional (a CI job
    /// pinning `ZP_LLM_MODEL` for one run without touching the operator's
    /// `config.toml`, say), and refusing to start over it would be the
    /// wrong failure mode for a condition that is frequently correct.
    ///
    /// Reuses `ConfigResolver` twice rather than inventing a second
    /// resolution path: once for the real, full resolution (defaults ->
    /// system -> project -> env), once restricted to the file layers alone.
    /// The difference between the two, per key, is exactly "what a file
    /// declared" vs. "what actually won" -- the same comparison
    /// `config_set`'s shadow pre-check makes at write time, made here at
    /// load time instead.
    pub fn boot_shadow_findings() -> Result<Vec<ShadowedAtBoot>, ConfigError> {
        let mut file_only = Self::new();
        let system_path = file_only.config.home_dir.value.join("config.toml");
        if system_path.exists() {
            let file = load_toml(&system_path)?;
            file_only.apply_file(file, Source::SystemConfig);
        }
        if let Some(project_path) = find_project_config() {
            let file = load_toml(&project_path)?;
            file_only.apply_file(file, Source::ProjectConfig);
        }
        let file_only_cfg = file_only.resolve();
        let effective_cfg = Self::resolve_standard()?;
        Ok(shadow_findings_from(&file_only_cfg, &effective_cfg))
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
        if let Some(v) = file.llm.provider {
            self.config.llm_provider.override_with(v, source.clone());
        }
        if let Some(v) = file.llm.model {
            self.config.llm_model.override_with(v, source.clone());
        }
        if let Some(v) = file.llm.escalation_model {
            self.config
                .llm_escalation_model
                .override_with(v, source.clone());
        }
        if let Some(v) = file.llm.supports_tools {
            self.config
                .llm_supports_tools
                .override_with(v, source.clone());
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
            self.config
                .officers_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.sweep_interval_secs {
            self.config
                .officers_sweep_interval_secs
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.steward_enabled {
            self.config
                .officers_steward_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.sentinel_enabled {
            self.config
                .officers_sentinel_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.forge_enabled {
            self.config
                .officers_forge_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.cleo_enabled {
            self.config
                .officers_cleo_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.aegis_enabled {
            self.config
                .officers_aegis_enabled
                .override_with(v, source.clone());
        }
        if let Some(v) = file.officers.acknowledged_listeners {
            self.config
                .acknowledged_listeners
                .override_with(v, source.clone());
        }
        // Regent
        if let Some(v) = file.regent.enabled {
            self.config.regent_enabled.override_with(v, source.clone());
        }
        if let Some(v) = file.regent.inference_endpoint {
            self.config
                .regent_inference_endpoint
                .override_with(v, source.clone());
        }
        if let Some(v) = file.regent.inference_api_key {
            self.config
                .regent_inference_api_key
                .override_with(Some(v), source.clone());
        }
        if let Some(v) = file.regent.reasoning_model {
            self.config
                .regent_reasoning_model
                .override_with(v, source.clone());
        }
        if let Some(v) = file.regent.routing_model {
            self.config
                .regent_routing_model
                .override_with(v, source.clone());
        }
        if let Some(v) = file.regent.loop_interval_secs {
            self.config
                .regent_loop_interval_secs
                .override_with(v, source.clone());
        }
        if let Some(v) = file.regent.display_name {
            self.config
                .regent_display_name
                .override_with(v, source.clone());
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
/// Outcome of a successful [`config_set`] call. Distinguishes a clean
/// write from a `--force` write that remains shadowed at runtime, so the
/// CLI can print the right follow-up (W6 -- HARNESS-SEAM sensor S5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSetOutcome {
    /// The write took effect: the target layer now holds the value that
    /// also resolves.
    Written,
    /// The write happened (only possible via `force: true`) but a higher
    /// layer still shadows the key -- the file changed, the resolved
    /// value did not.
    WrittenButShadowed {
        shadow_layer: String,
        shadow_value: String,
    },
}

/// One S5 finding: a config key whose file-declared value is currently
/// shadowed by a higher-priority layer at boot. See
/// `ConfigResolver::boot_shadow_findings`.
#[derive(Debug, Clone)]
pub struct ShadowedAtBoot {
    pub key: &'static str,
    /// The value a file layer (system or project config) declares.
    pub file_value: String,
    pub file_source: Source,
    /// The value that actually won -- from a higher-priority layer.
    pub effective_value: String,
    pub effective_source: Source,
}

/// Keys `boot_shadow_findings` checks. Deliberately the same set
/// `resolved_field` understands, not a second list to drift from it --
/// walked through `resolved_field` itself below.
const SHADOW_CHECK_KEYS: &[&str] = &[
    "server.port",
    "server.bind",
    "data.dir",
    "identity.operator",
    "llm.enabled",
    "llm.provider",
    "llm.model",
    "llm.escalation_model",
    "llm.supports_tools",
    "node.role",
    "node.upstream",
    "officers.enabled",
    "officers.sweep_interval_secs",
    "officers.steward_enabled",
    "officers.cleo_enabled",
    "officers.aegis_enabled",
];

/// For a `config_set` key, the field's currently-resolved value (as
/// display text) and the layer it resolved from. Mirrors `config_set`'s
/// own key list field-for-field -- every key `config_set` can write, this
/// can look up. `None` means the key isn't one `config_set` recognizes;
/// the caller falls through to the existing "unknown key" error.
fn resolved_field(cfg: &ZpConfig, key: &str) -> Option<(String, Source)> {
    Some(match key {
        "port" | "server.port" => (cfg.port.value.to_string(), cfg.port.source.clone()),
        "bind" | "server.bind" => (cfg.bind.value.clone(), cfg.bind.source.clone()),
        "data.dir" | "data_dir" => (
            cfg.data_dir.value.display().to_string(),
            cfg.data_dir.source.clone(),
        ),
        "operator" | "identity.operator" => (
            cfg.operator_name.value.clone(),
            cfg.operator_name.source.clone(),
        ),
        "llm.enabled" => (
            cfg.llm_enabled.value.to_string(),
            cfg.llm_enabled.source.clone(),
        ),
        "llm.provider" => (
            cfg.llm_provider.value.clone(),
            cfg.llm_provider.source.clone(),
        ),
        "llm.model" => (cfg.llm_model.value.clone(), cfg.llm_model.source.clone()),
        "llm.escalation_model" => (
            cfg.llm_escalation_model.value.clone(),
            cfg.llm_escalation_model.source.clone(),
        ),
        "llm.supports_tools" => (
            cfg.llm_supports_tools.value.to_string(),
            cfg.llm_supports_tools.source.clone(),
        ),
        "node.role" => (cfg.node_role.value.clone(), cfg.node_role.source.clone()),
        "node.upstream" => (
            cfg.node_upstream
                .value
                .clone()
                .unwrap_or_else(|| "(not set)".to_string()),
            cfg.node_upstream.source.clone(),
        ),
        "officers.enabled" => (
            cfg.officers_enabled.value.to_string(),
            cfg.officers_enabled.source.clone(),
        ),
        "officers.sweep_interval_secs" => (
            cfg.officers_sweep_interval_secs.value.to_string(),
            cfg.officers_sweep_interval_secs.source.clone(),
        ),
        "officers.steward_enabled" => (
            cfg.officers_steward_enabled.value.to_string(),
            cfg.officers_steward_enabled.source.clone(),
        ),
        "officers.cleo_enabled" => (
            cfg.officers_cleo_enabled.value.to_string(),
            cfg.officers_cleo_enabled.source.clone(),
        ),
        "officers.aegis_enabled" => (
            cfg.officers_aegis_enabled.value.to_string(),
            cfg.officers_aegis_enabled.source.clone(),
        ),
        _ => return None,
    })
}

/// The comparison at the heart of S5, pulled out of
/// `ConfigResolver::boot_shadow_findings` so it is directly unit-testable
/// against synthetic `ZpConfig` values -- no environment variables, no
/// files, no process-global state to leak between tests. Given "what the
/// file layers alone resolved to" and "what actually won", returns every
/// key where a file's value is currently shadowed by something
/// higher-priority with a different value.
fn shadow_findings_from(file_only_cfg: &ZpConfig, effective_cfg: &ZpConfig) -> Vec<ShadowedAtBoot> {
    let mut findings = Vec::new();
    for key in SHADOW_CHECK_KEYS.iter().copied() {
        let (file_value, file_source) = match resolved_field(file_only_cfg, key) {
            Some(v) => v,
            None => continue,
        };
        // A file only "declared" this key if a file layer actually won it
        // here -- Default means neither file set it, so there is nothing
        // to shadow.
        if !matches!(file_source, Source::SystemConfig | Source::ProjectConfig) {
            continue;
        }
        let (effective_value, effective_source) = match resolved_field(effective_cfg, key) {
            Some(v) => v,
            None => continue,
        };
        // Shadowed only if something with higher priority than the file
        // layer actually won, AND it won with a different value. The same
        // file layer winning (nothing higher present), or an identical
        // value from a higher layer, is not a finding -- an operator would
        // notice neither.
        if effective_source.priority() > file_source.priority() && effective_value != file_value {
            findings.push(ShadowedAtBoot {
                key,
                file_value,
                file_source,
                effective_value,
                effective_source,
            });
        }
    }
    findings
}

/// Set a single key-value pair in ~/ZeroPoint/config.toml.
/// Reads the existing file, updates the value, and writes it back.
///
/// W6 (HARNESS-SEAM S5): before writing, resolves `key` across every
/// layer (defaults -> system -> project -> env) via the same path
/// `zp config show` uses, and refuses when the resolved value already
/// comes from a layer strictly higher-precedence than the system-config
/// layer this function writes -- the write would succeed on disk and be
/// silently shadowed at read time, which was the motivating defect
/// ("`zp config set` was observed reporting success while changing
/// nothing"). `force: true` writes anyway and reports the outcome as
/// [`ConfigSetOutcome::WrittenButShadowed`] instead of refusing.
pub fn config_set(key: &str, value: &str, force: bool) -> Result<ConfigSetOutcome, ConfigError> {
    let zp_home = if let Ok(h) = std::env::var("ZP_HOME") {
        PathBuf::from(h)
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(home).join("ZeroPoint")
    };
    let config_path = zp_home.join("config.toml");

    // Shadow check: resolve every layer, then compare the winning layer's
    // priority against the layer we are about to write (SystemConfig).
    // Strictly-higher means shadowed; equal (SystemConfig itself, i.e.
    // self-supersede) and lower (Default, i.e. nothing else has set it)
    // are both fine to write.
    let mut shadow: Option<(String, String)> = None; // (shadow_layer, shadow_value)
    let resolved = ConfigResolver::resolve_standard()?;
    if let Some((current_value, current_source)) = resolved_field(&resolved, key) {
        if current_source.priority() > Source::SystemConfig.priority() {
            if force {
                shadow = Some((current_source.to_string(), current_value));
            } else {
                return Err(ConfigError::Shadowed {
                    key: key.into(),
                    target_layer: Source::SystemConfig.to_string(),
                    target_value: value.into(),
                    shadow_layer: current_source.to_string(),
                    shadow_value: current_value,
                });
            }
        }
    }

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
        "llm.provider" => {
            if value.trim().is_empty() {
                return Err(ConfigError::InvalidValue {
                    key: key.into(),
                    reason: "must be a non-empty provider segment (e.g. ollama)".into(),
                });
            }
            file.llm.provider = Some(value.into());
        }
        "llm.model" => {
            if value.trim().is_empty() {
                return Err(ConfigError::InvalidValue {
                    key: key.into(),
                    reason: "must be a non-empty model name".into(),
                });
            }
            file.llm.model = Some(value.into());
        }
        // Empty is meaningful here: it disables the escalation tier.
        "llm.escalation_model" => {
            file.llm.escalation_model = Some(value.into());
        }
        "llm.supports_tools" => {
            let b = parse_bool(value).ok_or(ConfigError::InvalidValue {
                key: key.into(),
                reason: "must be true or false".into(),
            })?;
            file.llm.supports_tools = Some(b);
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

    Ok(match shadow {
        Some((shadow_layer, shadow_value)) => ConfigSetOutcome::WrittenButShadowed {
            shadow_layer,
            shadow_value,
        },
        None => ConfigSetOutcome::Written,
    })
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
        assert!(
            result.is_ok(),
            "valid config must parse: {:?}",
            result.err()
        );
    }

    /// HARNESS-SEAM-2026-08 S5 ("no shadowed writes"), W7. Prove the sensor
    /// is not lying, entirely in memory -- no env vars, no files, no
    /// process-global state, so this cannot leak into or be leaked into by
    /// any other test running concurrently in this binary.
    ///
    /// Synthetic violation: a "file-only" config where a system-config
    /// layer declares `llm.model`, alongside an "effective" config where a
    /// higher-priority layer (env var) declares a *different* value for the
    /// same key. Fix: the effective config's value is changed back to match
    /// the file's -- same layer priority relationship, no operator-visible
    /// surprise left -- and the finding must disappear.
    #[test]
    fn s5_shadow_findings_catches_synthetic_violation_and_clears_on_fix() {
        let mut file_only_cfg = ZpConfig::default();
        file_only_cfg
            .llm_model
            .override_with("file-declared-model".to_string(), Source::SystemConfig);

        let mut effective_cfg = file_only_cfg.clone();
        effective_cfg.llm_model.override_with(
            "env-declared-model".to_string(),
            Source::EnvVar("ZP_LLM_MODEL".to_string()),
        );

        // 1-3: shadowed -- must be caught.
        let findings = shadow_findings_from(&file_only_cfg, &effective_cfg);
        let found = findings.iter().find(|f| f.key == "llm.model");
        assert!(
            found.is_some(),
            "S5 must catch a file-declared llm.model shadowed by a higher layer"
        );
        let found = found.unwrap();
        assert_eq!(found.file_value, "file-declared-model");
        assert_eq!(found.effective_value, "env-declared-model");

        // 4: fix -- the higher layer now agrees with the file. No surprise
        // left for an operator to trip over.
        effective_cfg
            .llm_model
            .override_with(
                "file-declared-model".to_string(),
                Source::EnvVar("ZP_LLM_MODEL".to_string()),
            );

        // 5: clean -- must not report llm.model any more.
        let findings = shadow_findings_from(&file_only_cfg, &effective_cfg);
        assert!(
            findings.iter().all(|f| f.key != "llm.model"),
            "S5 must not flag agreement between layers as a shadow"
        );
    }

    /// A file layer that was never actually the winner for a key (nothing
    /// ever wrote to it -- still at `Source::Default`) has nothing to
    /// shadow. Distinguishing "no one set this" from "a file set this and
    /// something else overrode it" is the whole point of gating on
    /// `file_source` rather than just comparing values.
    #[test]
    fn s5_does_not_flag_keys_no_file_ever_declared() {
        let file_only_cfg = ZpConfig::default();
        let mut effective_cfg = file_only_cfg.clone();
        effective_cfg.llm_model.override_with(
            "env-only-model".to_string(),
            Source::EnvVar("ZP_LLM_MODEL".to_string()),
        );

        let findings = shadow_findings_from(&file_only_cfg, &effective_cfg);
        assert!(
            findings.iter().all(|f| f.key != "llm.model"),
            "an env-only value with no file declaration is not a shadow -- there is nothing underneath it to be surprised about"
        );
    }
}
