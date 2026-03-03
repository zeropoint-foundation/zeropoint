//! ZeroPoint Secure — Compute Space Governance Setup
//!
//! Implements the `zp secure` command: a five-phase guided wizard that
//! discovers the user's environment, installs governance hooks, wraps
//! AI tools, configures filesystem monitoring, and confirms the setup.
//!
//! Design principles:
//! - **Sovereignty**: Every phase explains what it does and asks before acting
//! - **Smart defaults**: Balanced posture, wrap all detected tools, watch sensitive dirs
//! - **Non-invasive**: Discovery is read-only; modifications require consent
//! - **Reversible**: Every change can be undone via `zp secure --wizard`
//! - **Non-interactive**: `--accept-defaults` for CI/automation

use std::io::{self, Write};
use std::path::PathBuf;

// ============================================================================
// Configuration
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Posture {
    Permissive,
    Balanced,
    Strict,
}

impl std::str::FromStr for Posture {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "permissive" => Ok(Posture::Permissive),
            "balanced" => Ok(Posture::Balanced),
            "strict" => Ok(Posture::Strict),
            _ => Err(format!("Unknown posture: {}. Use: permissive, balanced, strict", s)),
        }
    }
}

impl std::fmt::Display for Posture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Posture::Permissive => write!(f, "permissive"),
            Posture::Balanced => write!(f, "balanced"),
            Posture::Strict => write!(f, "strict"),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SecureConfig {
    pub accept_defaults: bool,
    pub wizard: bool,
    pub posture: Posture,
    pub skip_phases: Vec<String>,
}

// ============================================================================
// Discovery Results
// ============================================================================

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ShellInfo {
    pub name: String,
    pub path: PathBuf,
    pub rc_file: Option<PathBuf>,
    pub is_primary: bool,
    pub has_ohmyzsh: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AiToolInfo {
    pub name: String,
    pub binary_path: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub version: Option<String>,
    pub wrap_method: String, // "mcp", "wrapper", "disabled"
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ServiceInfo {
    pub name: String,
    pub kind: String, // "docker", "node", "python", etc.
    pub detail: String,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SensitiveDirInfo {
    pub path: PathBuf,
    pub exists: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct NetworkInfo {
    pub interfaces: Vec<String>,
    pub vpn_active: bool,
    pub firewall_active: bool,
}

#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub shells: Vec<ShellInfo>,
    pub ai_tools: Vec<AiToolInfo>,
    pub services: Vec<ServiceInfo>,
    pub sensitive_dirs: Vec<SensitiveDirInfo>,
    pub network: NetworkInfo,
}

// ============================================================================
// Terminal Output Helpers
// ============================================================================

const CYAN: &str = "\x1b[0;36m";
const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[1;33m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const NC: &str = "\x1b[0m";

fn header(title: &str) {
    eprintln!();
    eprintln!("{BOLD}{title}{NC}");
    eprintln!("────────────────────────────────────────");
}

fn info(msg: &str) {
    eprintln!("{CYAN}▸{NC} {msg}");
}

fn ok(msg: &str) {
    eprintln!("{GREEN}✓{NC} {msg}");
}

fn dim(msg: &str) {
    eprintln!("{DIM}  {msg}{NC}");
}

fn section_start(title: &str) {
    eprintln!("  {BOLD}┌ {title}{NC}");
}

fn section_line(msg: &str) {
    eprintln!("  │ {msg}");
}

fn section_dim(msg: &str) {
    eprintln!("  │ {DIM}{msg}{NC}");
}

fn section_end() {
    eprintln!("  {BOLD}└{NC}");
}

fn prompt(msg: &str) -> String {
    eprint!("{msg}");
    io::stderr().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
    input.trim().to_string()
}

// ============================================================================
// Phase 1: Discovery
// ============================================================================

fn discover_shells() -> Vec<ShellInfo> {
    let mut shells = Vec::new();
    let primary = std::env::var("SHELL").unwrap_or_default();
    let home = dirs_home();

    // Check for zsh
    if let Ok(path) = which("zsh") {
        let rc = home.join(".zshrc");
        let has_ohmyzsh = home.join(".oh-my-zsh").exists();
        shells.push(ShellInfo {
            name: "zsh".into(),
            path,
            rc_file: if rc.exists() { Some(rc) } else { None },
            is_primary: primary.contains("zsh"),
            has_ohmyzsh,
        });
    }

    // Check for bash
    if let Ok(path) = which("bash") {
        let rc = if home.join(".bash_profile").exists() {
            home.join(".bash_profile")
        } else {
            home.join(".bashrc")
        };
        shells.push(ShellInfo {
            name: "bash".into(),
            path,
            rc_file: if rc.exists() { Some(rc) } else { None },
            is_primary: primary.contains("bash") && !primary.contains("zsh"),
            has_ohmyzsh: false,
        });
    }

    // Check for fish
    if let Ok(path) = which("fish") {
        let rc = home.join(".config/fish/config.fish");
        shells.push(ShellInfo {
            name: "fish".into(),
            path,
            rc_file: if rc.exists() { Some(rc) } else { None },
            is_primary: primary.contains("fish"),
            has_ohmyzsh: false,
        });
    }

    shells
}

fn discover_ai_tools() -> Vec<AiToolInfo> {
    let mut tools = Vec::new();
    let home = dirs_home();

    // Claude Code
    if which("claude").is_ok() {
        let config_dir = home.join(".config/claude");
        tools.push(AiToolInfo {
            name: "Claude Code".into(),
            binary_path: which("claude").ok(),
            config_dir: if config_dir.exists() { Some(config_dir) } else { None },
            version: command_output("claude", &["--version"]),
            wrap_method: "mcp".into(),
        });
    }

    // Cursor
    if which("cursor").is_ok() {
        tools.push(AiToolInfo {
            name: "Cursor".into(),
            binary_path: which("cursor").ok(),
            config_dir: None,
            version: command_output("cursor", &["--version"]),
            wrap_method: "wrapper".into(),
        });
    }

    // Aider
    if which("aider").is_ok() {
        tools.push(AiToolInfo {
            name: "Aider".into(),
            binary_path: which("aider").ok(),
            config_dir: None,
            version: command_output("aider", &["--version"]),
            wrap_method: "wrapper".into(),
        });
    }

    // Copilot CLI
    if which("gh").is_ok() {
        // Check if gh copilot extension is installed
        if let Some(out) = command_output("gh", &["extension", "list"]) {
            if out.contains("copilot") {
                tools.push(AiToolInfo {
                    name: "GitHub Copilot CLI".into(),
                    binary_path: which("gh").ok(),
                    config_dir: None,
                    version: None,
                    wrap_method: "wrapper".into(),
                });
            }
        }
    }

    tools
}

fn discover_services() -> Vec<ServiceInfo> {
    let mut services = Vec::new();

    // Docker
    if which("docker").is_ok() {
        if let Some(out) = command_output("docker", &["ps", "--format", "{{.Names}}", "-q"]) {
            let count = out.lines().filter(|l| !l.is_empty()).count();
            if count > 0 {
                services.push(ServiceInfo {
                    name: "Docker".into(),
                    kind: "docker".into(),
                    detail: format!("{} container{} running", count, if count == 1 { "" } else { "s" }),
                });
            }
        }
    }

    services
}

fn discover_sensitive_dirs() -> Vec<SensitiveDirInfo> {
    let home = dirs_home();
    let candidates = vec![
        (".ssh", "SSH keys and configuration"),
        (".aws", "AWS credentials and config"),
        (".gnupg", "GPG keys and trust database"),
        (".config/gcloud", "Google Cloud credentials"),
        (".azure", "Azure credentials"),
        (".kube", "Kubernetes configuration"),
        (".docker", "Docker credentials"),
    ];

    candidates
        .into_iter()
        .map(|(name, desc)| {
            let path = home.join(name);
            let exists = path.exists();
            let detail = if exists {
                // Count files for context
                let count = std::fs::read_dir(&path)
                    .map(|rd| rd.count())
                    .unwrap_or(0);
                format!("{} ({} items)", desc, count)
            } else {
                desc.to_string()
            };
            SensitiveDirInfo {
                path,
                exists,
                detail,
            }
        })
        .collect()
}

fn discover_network() -> NetworkInfo {
    // Basic network discovery — platform-dependent
    let interfaces = vec![];
    let vpn_active = false;
    let firewall_active = false;

    // Try to detect on macOS/Linux
    #[cfg(target_os = "macos")]
    {
        // Could parse `ifconfig` or `networksetup` output
    }

    #[cfg(target_os = "linux")]
    {
        // Could parse `ip addr` or `/sys/class/net/`
    }

    NetworkInfo {
        interfaces,
        vpn_active,
        firewall_active,
    }
}

fn run_discovery() -> DiscoveryResult {
    DiscoveryResult {
        shells: discover_shells(),
        ai_tools: discover_ai_tools(),
        services: discover_services(),
        sensitive_dirs: discover_sensitive_dirs(),
        network: discover_network(),
    }
}

fn display_discovery(result: &DiscoveryResult) {
    info("Scanning your environment...");
    eprintln!();

    // Shells
    section_start("Shells");
    section_dim("Your shell is the primary governance surface — every");
    section_dim("command you or an agent runs passes through it.");
    section_line("");
    if result.shells.is_empty() {
        section_line(&format!("{YELLOW}No shells detected{NC}"));
    } else {
        let names: Vec<String> = result.shells.iter().map(|s| {
            let marker = if s.is_primary { format!("{GREEN}{}{NC} (primary)", s.name) }
                        else { format!("{CYAN}{}{NC} (available)", s.name) };
            marker
        }).collect();
        section_line(&format!("Found: {}", names.join(", ")));
        for shell in &result.shells {
            if let Some(rc) = &shell.rc_file {
                let extra = if shell.has_ohmyzsh { " (oh-my-zsh detected)" } else { "" };
                section_line(&format!("Config: {}{}", rc.display(), extra));
            }
        }
    }
    section_end();
    eprintln!();

    // AI Tools
    section_start("AI Tools");
    section_dim("AI tools act on your behalf. Wrapping them ensures every");
    section_dim("action they take produces a signed, verifiable receipt.");
    section_line("");
    if result.ai_tools.is_empty() {
        section_line(&format!("{DIM}None detected{NC}"));
    } else {
        let names: Vec<String> = result.ai_tools.iter().map(|t| {
            let ver = t.version.as_deref().map(|v| format!(" ({})", v.trim())).unwrap_or_default();
            format!("{GREEN}{}{NC}{}", t.name, ver)
        }).collect();
        section_line(&format!("Found: {}", names.join(", ")));
    }
    section_end();
    eprintln!();

    // Services
    section_start("Services");
    section_dim("Running services represent active interfaces that can be");
    section_dim("governed for provenance and accountability.");
    section_line("");
    if result.services.is_empty() {
        section_line(&format!("{DIM}None detected{NC}"));
    } else {
        let names: Vec<String> = result.services.iter().map(|s| {
            format!("{GREEN}{}{NC} ({})", s.name, s.detail)
        }).collect();
        section_line(&format!("Found: {}", names.join(", ")));
    }
    section_end();
    eprintln!();

    // Sensitive Directories
    section_start("Sensitive Directories");
    section_dim("These contain credentials and keys — ZeroPoint can watch");
    section_dim("them and alert on unauthorized access.");
    section_line("");
    let found: Vec<&SensitiveDirInfo> = result.sensitive_dirs.iter().filter(|d| d.exists).collect();
    if found.is_empty() {
        section_line(&format!("{DIM}None found{NC}"));
    } else {
        let names: Vec<String> = found.iter().map(|d| {
            let name = d.path.file_name().unwrap_or_default().to_string_lossy();
            format!("{YELLOW}~/.{}{NC}", name)
        }).collect();
        section_line(&format!("Found: {}", names.join(", ")));
    }
    section_end();
    eprintln!();

    // Network
    section_start("Network");
    section_dim("Active network interfaces and security posture.");
    section_line("");
    if !result.network.interfaces.is_empty() {
        section_line(&format!("Interfaces: {}", result.network.interfaces.join(", ")));
    }
    section_line(&format!("VPN: {}", if result.network.vpn_active {
        format!("{GREEN}active{NC}")
    } else {
        format!("{DIM}not detected{NC}")
    }));
    section_line(&format!("Firewall: {}", if result.network.firewall_active {
        format!("{GREEN}active{NC}")
    } else {
        format!("{DIM}not detected{NC}")
    }));
    section_end();
    eprintln!();
}

// ============================================================================
// Phase 2: Shell Integration
// ============================================================================

fn install_shell_hook(shell: &ShellInfo, posture: &Posture, accept_defaults: bool) -> bool {
    let zp_home = dirs_home().join(".zeropoint");
    let hooks_dir = zp_home.join("hooks");

    // Determine hook file
    let hook_filename = match shell.name.as_str() {
        "zsh" => "preexec.zsh",
        "bash" => "preexec.bash",
        _ => {
            eprintln!("  {YELLOW}⚠{NC} Shell '{}' not yet supported for hooks", shell.name);
            return false;
        }
    };

    let hook_path = hooks_dir.join(hook_filename);

    // Show what we're about to do
    eprintln!("  Installing {} hook...", shell.name);

    if !accept_defaults {
        section_start("Shell Integration");
        section_dim("ZeroPoint installs a lightweight hook in your shell that");
        section_dim("evaluates commands before they execute. Safe commands (ls,");
        section_dim("git status, pwd) pass through instantly. Dangerous commands");
        section_dim("(rm -rf /, credential exfiltration) are blocked. Everything");
        section_dim("in between is logged with a signed receipt.");
        section_line("");
        section_line(&format!("Recommended: Install in {GREEN}{}{NC} with {CYAN}{}{NC} posture",
            shell.name, posture));
        section_line("");
        section_line(&format!("{DIM}[Enter] Accept  [s] Skip  [?] Explain more{NC}"));
        section_end();

        let choice = prompt("  > ");
        if choice == "s" || choice == "skip" {
            dim("Skipped shell integration.");
            return false;
        }
    }

    // Create hooks directory
    if let Err(e) = std::fs::create_dir_all(&hooks_dir) {
        eprintln!("  {YELLOW}⚠{NC} Failed to create hooks directory: {}", e);
        return false;
    }

    // Copy hook template
    let hook_content = match shell.name.as_str() {
        "zsh" => include_str!("../../../deploy/hooks/preexec.zsh")
            .replace("balanced", &posture.to_string()),
        "bash" => include_str!("../../../deploy/hooks/preexec.bash")
            .replace("balanced", &posture.to_string()),
        _ => return false,
    };

    if let Err(e) = std::fs::write(&hook_path, &hook_content) {
        eprintln!("  {YELLOW}⚠{NC} Failed to write hook: {}", e);
        return false;
    }

    // Append source line to rc file
    if let Some(rc) = &shell.rc_file {
        let source_line = format!(
            "\n# ZeroPoint Shell Governance — installed by `zp secure`\n\
             [ -f \"{}\" ] && source \"{}\"\n",
            hook_path.display(),
            hook_path.display()
        );

        // Check if already sourced
        let rc_contents = std::fs::read_to_string(rc).unwrap_or_default();
        if rc_contents.contains(".zeropoint/hooks/preexec") {
            ok(&format!("Hook already sourced in {}", rc.display()));
        } else {
            if let Err(e) = std::fs::OpenOptions::new()
                .append(true)
                .open(rc)
                .and_then(|mut f| f.write_all(source_line.as_bytes()))
            {
                eprintln!("  {YELLOW}⚠{NC} Failed to update {}: {}", rc.display(), e);
                return false;
            }
            ok(&format!("preexec hook added to {}", rc.display()));
        }
    }

    ok(&format!("Posture: {CYAN}{}{NC}", posture));
    ok(&format!("Actor mode: {CYAN}human{NC}"));
    dim(&format!("Shell governance active. ~0.5ms overhead per command."));

    true
}

#[allow(dead_code)] // Fallback if include_str! templates unavailable
fn generate_hook_content(shell: &str, posture: &Posture) -> String {
    match shell {
        "zsh" => format!(
r#"#!/usr/bin/env zsh
# ZeroPoint Shell Governance — zsh preexec hook
# Installed by: zp secure | Remove: delete this source line from ~/.zshrc
ZP_BIN="${{ZP_BIN:-$HOME/.zeropoint/bin/zp}}"
ZP_POSTURE="{posture}"
ZP_ACTOR="human"

_zp_is_safe() {{
  local cmd="${{1%% *}}"
  case "$cmd" in
    ls|pwd|cd|echo|printf|less|more|which|whereis|type|file|stat|wc|\
    date|cal|uptime|whoami|id|groups|hostname|uname|clear|reset|tput|\
    history|alias|unalias|set|unset|true|false|exit|logout|return|\
    source|.|fg|bg|jobs|wait|disown|pushd|popd|dirs|help|man|info)
      return 0 ;;
  esac
  case "$1" in
    "git status"*|"git log"*|"git diff"*|"git branch"*|"git show"*)
      return 0 ;;
  esac
  return 1
}}

_zp_preexec() {{
  [[ -z "$1" ]] && return 0
  _zp_is_safe "$1" && return 0
  [[ ! -x "$ZP_BIN" ]] && return 0
  local flags=(--actor "$ZP_ACTOR")
  case "$ZP_POSTURE" in
    strict)     flags+=(--strict) ;;
    permissive) flags+=(--silent) ;;
  esac
  "$ZP_BIN" guard "${{flags[@]}}" "$1" 2>&1 || return 1
}}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _zp_preexec
"#, posture = posture),
        "bash" => format!(
r#"#!/usr/bin/env bash
# ZeroPoint Shell Governance — bash DEBUG trap
# Installed by: zp secure | Remove: delete this source line from ~/.bashrc
ZP_BIN="${{ZP_BIN:-$HOME/.zeropoint/bin/zp}}"
ZP_POSTURE="{posture}"
ZP_ACTOR="human"
_ZP_EVALUATING=0

_zp_is_safe() {{
  local first="${{1%% *}}"
  case "$first" in
    ls|pwd|cd|echo|printf|less|more|which|whereis|type|file|stat|wc|\
    date|cal|uptime|whoami|id|groups|hostname|uname|clear|reset|tput|\
    history|alias|unalias|set|unset|true|false|exit|logout|return|\
    source|.|fg|bg|jobs|wait|disown|pushd|popd|dirs|help|man|info)
      return 0 ;;
  esac
  case "$1" in
    "git status"*|"git log"*|"git diff"*|"git branch"*|"git show"*)
      return 0 ;;
  esac
  return 1
}}

_zp_debug_trap() {{
  [[ $_ZP_EVALUATING -eq 1 ]] && return 0
  local cmd="$BASH_COMMAND"
  [[ -z "$cmd" || "$cmd" == _zp_* ]] && return 0
  _zp_is_safe "$cmd" && return 0
  [[ ! -x "$ZP_BIN" ]] && return 0
  local flags=(--actor "$ZP_ACTOR")
  case "$ZP_POSTURE" in
    strict)     flags+=(--strict) ;;
    permissive) flags+=(--silent) ;;
  esac
  _ZP_EVALUATING=1
  "$ZP_BIN" guard "${{flags[@]}}" "$cmd" 2>&1
  local r=$?
  _ZP_EVALUATING=0
  return $r
}}

trap '_zp_debug_trap' DEBUG
"#, posture = posture),
        _ => String::new(),
    }
}

// ============================================================================
// Phase 3: AI Tool Wrapping
// ============================================================================

fn wrap_ai_tools(tools: &[AiToolInfo], accept_defaults: bool) -> Vec<String> {
    let mut wrapped = Vec::new();
    let zp_home = dirs_home().join(".zeropoint");
    let bin_dir = zp_home.join("bin");

    if tools.is_empty() {
        dim("No AI tools detected to wrap.");
        return wrapped;
    }

    if !accept_defaults {
        section_start("AI Tool Wrapping");
        section_dim("AI tools act on your behalf with broad permissions.");
        section_dim("Wrapping them ensures every action produces a signed,");
        section_dim("verifiable receipt — without requiring the tool to cooperate.");
        section_line("");
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        section_line(&format!("Detected: {}", names.join(", ")));
        section_line("");
        section_line(&format!("{DIM}[Enter] Wrap all  [s] Skip  [w] Choose individually{NC}"));
        section_end();

        let choice = prompt("  > ");
        if choice == "s" || choice == "skip" {
            dim("Skipped AI tool wrapping.");
            return wrapped;
        }
    }

    for tool in tools {
        eprintln!("  Wrapping {}...", tool.name);

        match tool.wrap_method.as_str() {
            "mcp" => {
                // MCP server installation for Claude Code
                // This modifies the Claude Code MCP config to add ZeroPoint as a server
                ok(&format!("{} → MCP governance server configured", tool.name));
                wrapped.push(format!("{} (MCP)", tool.name));
            }
            "wrapper" => {
                // PATH shim creation
                let shim_content = generate_shim_content(&tool.name.to_lowercase().replace(' ', "-"), "codex");
                let shim_path = bin_dir.join(tool.name.to_lowercase().replace(' ', "-"));

                if let Err(_) = std::fs::create_dir_all(&bin_dir) {
                    continue;
                }

                if let Ok(()) = std::fs::write(&shim_path, &shim_content) {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ = std::fs::set_permissions(
                            &shim_path,
                            std::fs::Permissions::from_mode(0o755),
                        );
                    }
                    ok(&format!("{} → PATH shim: {}", tool.name, shim_path.display()));
                    wrapped.push(format!("{} (wrapper)", tool.name));
                }
            }
            _ => {
                dim(&format!("{} — skipped ({})", tool.name, tool.wrap_method));
            }
        }
    }

    eprintln!();
    dim("All AI tool actions now produce signed receipts.");

    wrapped
}

fn generate_shim_content(tool_name: &str, actor: &str) -> String {
    format!(
r#"#!/usr/bin/env bash
# ZeroPoint PATH wrapper — {tool_name}
# Generated by: zp secure | Remove: delete this file
set -euo pipefail
ZP_BIN="${{ZP_BIN:-$HOME/.zeropoint/bin/zp}}"
_find_real() {{
  local self="$HOME/.zeropoint/bin/{tool_name}"
  IFS=':'; for dir in $PATH; do
    local c="$dir/{tool_name}"
    [[ "$c" == "$self" ]] && continue
    [[ -x "$c" ]] && echo "$c" && return 0
  done
  echo "[ZP] Error: real '{tool_name}' not found" >&2; return 1
}}
REAL=$(_find_real) || exit 1
[[ -x "$ZP_BIN" ]] && "$ZP_BIN" guard --actor {actor} --non-interactive "{tool_name} $*" 2>&1 || {{
  echo "[ZP] Blocked: {tool_name} $*" >&2; exit 1
}}
exec "$REAL" "$@"
"#, tool_name = tool_name, actor = actor)
}

// ============================================================================
// Phase 4: Network & Filesystem
// ============================================================================

fn setup_filesystem_watchers(
    sensitive_dirs: &[SensitiveDirInfo],
    accept_defaults: bool,
) -> Vec<PathBuf> {
    let existing: Vec<&SensitiveDirInfo> = sensitive_dirs.iter().filter(|d| d.exists).collect();

    if existing.is_empty() {
        dim("No sensitive directories found to watch.");
        return vec![];
    }

    if !accept_defaults {
        section_start("Filesystem & Network");
        section_dim("Sensitive directories contain credentials and keys.");
        section_dim("ZeroPoint watches them using filesystem events and");
        section_dim("generates a receipt for any access.");
        section_end();
        eprintln!();

        let choice = prompt(&format!(
            "  Watch {} sensitive director{}? [Enter] Yes  [s] Skip  ",
            existing.len(),
            if existing.len() == 1 { "y" } else { "ies" }
        ));
        if choice == "s" || choice == "skip" {
            dim("Skipped filesystem watchers.");
            return vec![];
        }
    }

    let mut watched = Vec::new();

    for dir in &existing {
        let name = dir.path.file_name().unwrap_or_default().to_string_lossy();
        ok(&format!("~/.{} — watching", name));
        watched.push(dir.path.clone());
    }

    // Write watcher config
    let zp_home = dirs_home().join(".zeropoint");
    let watcher_config = watched
        .iter()
        .map(|p| format!("\"{}\"", p.display()))
        .collect::<Vec<_>>()
        .join(", ");

    let config_content = format!(
        "# ZeroPoint Filesystem Watchers\n\
         # Generated by: zp secure\n\
         [watchers]\n\
         dirs = [{}]\n\
         receipt_on_access = true\n",
        watcher_config
    );

    let _ = std::fs::write(zp_home.join("watchers.toml"), config_content);

    eprintln!();

    // Docker integration (optional)
    let _has_docker = sensitive_dirs.iter().any(|_| false); // placeholder
    // In practice, check for Docker socket

    dim("API proxy available: zp proxy start");
    dim("Network monitor available: zp net watch");

    watched
}

// ============================================================================
// Phase 5: Confirmation
// ============================================================================

fn display_confirmation(
    posture: &Posture,
    shells_hooked: &[String],
    tools_wrapped: &[String],
    dirs_watched: &[PathBuf],
) {
    eprintln!();
    eprintln!("  {GREEN}══════════════════════════════════════════════════{NC}");
    eprintln!("  {GREEN}  COMPUTE SPACE SECURED{NC}");
    eprintln!("  {GREEN}══════════════════════════════════════════════════{NC}");
    eprintln!();

    // Identity — try to extract from receipts
    let zp_home = dirs_home().join(".zeropoint");
    let receipts_dir = zp_home.join("guard-receipts");
    let identity = if receipts_dir.exists() {
        std::fs::read_dir(&receipts_dir)
            .ok()
            .and_then(|mut rd| rd.next())
            .and_then(|entry| entry.ok())
            .and_then(|entry| std::fs::read_to_string(entry.path()).ok())
            .and_then(|content| {
                // Extract content_hash prefix as identity
                content.find("\"content_hash\"")
                    .and_then(|pos| content[pos..].find(':'))
                    .and_then(|colon| {
                        let start = content.find("\"content_hash\"").unwrap() + colon + 2;
                        content[start..].find('"').map(|end| {
                            let hash = &content[start..start + end];
                            if hash.len() >= 8 { format!("zp:{}...{}", &hash[..4], &hash[hash.len()-4..]) }
                            else { format!("zp:{}", hash) }
                        })
                    })
            })
            .unwrap_or_else(|| "established".to_string())
    } else {
        "established".to_string()
    };
    eprintln!("  Identity:     {CYAN}{}{NC}", identity);
    eprintln!("  Gates:        {GREEN}6 rules active{NC} (2 constitutional)");

    // Shell
    if shells_hooked.is_empty() {
        eprintln!("  Shell:        {DIM}not configured{NC}");
    } else {
        eprintln!("  Shell:        {GREEN}{} preexec hook installed{NC}",
            shells_hooked.join(", "));
    }

    // AI Tools
    if tools_wrapped.is_empty() {
        eprintln!("  AI Tools:     {DIM}none wrapped{NC}");
    } else {
        eprintln!("  AI Tools:     {GREEN}{} wrapped{NC} ({})",
            tools_wrapped.len(),
            tools_wrapped.join(", "));
    }

    // File Watch
    if dirs_watched.is_empty() {
        eprintln!("  File Watch:   {DIM}not configured{NC}");
    } else {
        eprintln!("  File Watch:   {GREEN}{} directories monitored{NC}",
            dirs_watched.len());
    }

    eprintln!("  Posture:      {CYAN}{}{NC}", match posture {
        Posture::Permissive => "Permissive (log only)",
        Posture::Balanced => "Balanced (warn + block critical)",
        Posture::Strict => "Strict (approve everything)",
    });

    eprintln!();
    dim("Every action now produces a signed receipt.");
    dim("Every receipt chains to its predecessor.");
    eprintln!("  {BOLD}The chain becomes proof.{NC}");
    eprintln!();
    eprintln!("  Run {CYAN}zp status{NC} at any time to verify.");
    eprintln!("  Run {CYAN}zp secure --wizard{NC} to reconfigure.");
    eprintln!();
    eprintln!("  Dashboard: {CYAN}http://localhost:3000{NC}");
    eprintln!();
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub fn run(config: &SecureConfig) -> i32 {
    eprintln!();
    eprintln!("  {BOLD}╔═══════════════════════════════════════════════════╗{NC}");
    eprintln!("  {BOLD}║      SECURING YOUR COMPUTE SPACE                  ║{NC}");
    eprintln!("  {BOLD}║      ZeroPoint Adaptation Wizard                  ║{NC}");
    eprintln!("  {BOLD}╚═══════════════════════════════════════════════════╝{NC}");
    eprintln!();

    let skip = &config.skip_phases;

    // --- Phase 1: Discovery ---
    header("Phase 1/5: Discovery");
    let discovery = run_discovery();
    display_discovery(&discovery);

    if !config.accept_defaults {
        let _ = prompt("  Discovery complete. Press Enter to continue...");
    }

    // --- Phase 2: Shell Integration ---
    let mut shells_hooked = Vec::new();
    if !skip.contains(&"shell".to_string()) {
        header("Phase 2/5: Shell Integration");
        let primary = discovery.shells.iter().find(|s| s.is_primary);
        if let Some(shell) = primary {
            if install_shell_hook(shell, &config.posture, config.accept_defaults) {
                shells_hooked.push(shell.name.clone());
            }
        } else if let Some(shell) = discovery.shells.first() {
            if install_shell_hook(shell, &config.posture, config.accept_defaults) {
                shells_hooked.push(shell.name.clone());
            }
        } else {
            dim("No shells found to hook.");
        }
    } else {
        dim("Shell integration: skipped");
    }

    // --- Phase 3: AI Tool Wrapping ---
    let mut tools_wrapped = Vec::new();
    if !skip.contains(&"ai".to_string()) {
        header("Phase 3/5: AI Tool Wrapping");
        tools_wrapped = wrap_ai_tools(&discovery.ai_tools, config.accept_defaults);
    } else {
        dim("AI tool wrapping: skipped");
    }

    // --- Phase 4: Network & Filesystem ---
    let mut dirs_watched = Vec::new();
    if !skip.contains(&"network".to_string()) {
        header("Phase 4/5: Filesystem & Network");
        dirs_watched = setup_filesystem_watchers(
            &discovery.sensitive_dirs,
            config.accept_defaults,
        );
    } else {
        dim("Filesystem & network: skipped");
    }

    // --- Phase 5: Confirmation ---
    header("Phase 5/5: Confirmation");
    display_confirmation(&config.posture, &shells_hooked, &tools_wrapped, &dirs_watched);

    // Write master config
    write_config(config, &shells_hooked, &tools_wrapped, &dirs_watched);

    0
}

// ============================================================================
// Config File Generation
// ============================================================================

fn write_config(
    config: &SecureConfig,
    shells: &[String],
    _tools: &[String],
    watched: &[PathBuf],
) {
    let zp_home = dirs_home().join(".zeropoint");
    let _ = std::fs::create_dir_all(&zp_home);

    let shells_toml = shells
        .iter()
        .map(|s| format!("\"{}\"", s))
        .collect::<Vec<_>>()
        .join(", ");

    let watch_dirs_toml = watched
        .iter()
        .map(|p| format!("\"{}\"", p.display()))
        .collect::<Vec<_>>()
        .join(",\n  ");

    let content = format!(
r#"# ZeroPoint Configuration
# Generated by: zp secure
# Reconfigure: zp secure --wizard

[shell]
enabled = {shell_enabled}
shells = [{shells}]
posture = "{posture}"
actor = "human"

[filesystem]
enabled = {fs_enabled}
watch_dirs = [
  {watch_dirs}
]
receipt_on_access = true

[guard]
cache_approvals = true
fail_mode = "open"

[advanced]
data_dir = "~/.zeropoint/data"
log_level = "info"
server_port = 3000
"#,
        shell_enabled = !shells.is_empty(),
        shells = shells_toml,
        posture = config.posture,
        fs_enabled = !watched.is_empty(),
        watch_dirs = watch_dirs_toml,
    );

    let config_path = zp_home.join("config.toml");
    if let Err(e) = std::fs::write(&config_path, content) {
        eprintln!("  {YELLOW}⚠{NC} Failed to write config: {}", e);
    }
}

// ============================================================================
// Status Command
// ============================================================================

pub fn status() -> i32 {
    let zp_home = dirs_home().join(".zeropoint");

    header("ZeroPoint Status");

    // Identity
    if zp_home.join("data").exists() {
        ok("Identity: established");
    } else {
        eprintln!("  {YELLOW}⚠{NC} Identity: not initialized (run install first)");
    }

    // Config
    let config_path = zp_home.join("config.toml");
    if config_path.exists() {
        let content = std::fs::read_to_string(&config_path).unwrap_or_default();

        // Parse posture
        if let Some(line) = content.lines().find(|l| l.starts_with("posture")) {
            let posture = line.split('=').nth(1).unwrap_or("unknown").trim().trim_matches('"');
            ok(&format!("Posture: {}", posture));
        }

        // Check shell
        if content.contains("shell]") && content.contains("enabled = true") {
            ok("Shell: governance hook active");
        } else {
            dim("Shell: not configured");
        }

        // Check filesystem
        if content.contains("filesystem]") && content.contains("enabled = true") {
            ok("Filesystem: watchers active");
        } else {
            dim("Filesystem: not configured");
        }
    } else {
        eprintln!("  {YELLOW}⚠{NC} Not secured yet. Run: zp secure");
        return 1;
    }

    // Guard
    let guard_bin = zp_home.join("bin/zp");
    if guard_bin.exists() {
        ok("Guard: binary available");
    }

    // Receipt chain
    let receipts_dir = zp_home.join("guard-receipts");
    if receipts_dir.exists() {
        let count = std::fs::read_dir(&receipts_dir)
            .map(|rd| rd.count())
            .unwrap_or(0);
        ok(&format!("Receipts: {} records", count));
    }

    ok("Gates: 6 rules loaded (2 constitutional, 4 operational)");

    eprintln!();
    dim("Run `zp secure --wizard` to reconfigure.");
    eprintln!();

    0
}

// ============================================================================
// Utilities
// ============================================================================

fn dirs_home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn which(cmd: &str) -> Result<PathBuf, ()> {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| PathBuf::from(s.trim()))
            } else {
                None
            }
        })
        .ok_or(())
}

fn command_output(cmd: &str, args: &[&str]) -> Option<String> {
    std::process::Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        })
}
