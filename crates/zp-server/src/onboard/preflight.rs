//! Preflight checks — validate and auto-fix tool launch readiness.
//!
//! Runs after `zp configure auto` to ensure every configured tool
//! can start with a single cockpit click. Checks:
//!   - Docker daemon availability
//!   - Compose file validation
//!   - Image pre-pull
//!   - Port conflict detection
//!   - Start script permissions
//!   - Node dependency installation
//!   - .env completeness
//!
//! Results are persisted to `~/.zeropoint/state/preflight.json`
//! so the cockpit knows which tools are launch-ready.

use super::{OnboardEvent, OnboardState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use zp_audit::AuditStore;

/// Result of preflight for a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPreflight {
    pub name: String,
    pub path: String,
    pub ready: bool,
    pub launch_method: String,  // "docker", "npm", "script", "make", "none"
    pub checks: Vec<PreflightCheck>,
    pub auto_fixed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub name: String,
    pub status: String,  // "pass", "fixed", "fail"
    pub detail: String,
}

/// Full preflight result set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightResults {
    pub tools: Vec<ToolPreflight>,
    pub docker_available: bool,
    pub port_conflicts: Vec<PortConflict>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortConflict {
    pub port: u16,
    pub tools: Vec<String>,
}

impl PreflightResults {
    pub fn ready_count(&self) -> usize {
        self.tools.iter().filter(|t| t.ready).count()
    }

    /// Persist to ~/.zeropoint/state/preflight.json
    pub fn save(&self) {
        let state_dir = dirs::home_dir()
            .unwrap_or_default()
            .join(".zeropoint")
            .join("state");
        std::fs::create_dir_all(&state_dir).ok();
        let path = state_dir.join("preflight.json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            std::fs::write(path, json).ok();
        }
    }

    /// Load from disk, if available.
    pub fn load() -> Option<Self> {
        let path = dirs::home_dir()?
            .join(".zeropoint")
            .join("state")
            .join("preflight.json");
        let contents = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&contents).ok()
    }
}

// ============================================================================
// Preflight Engine
// ============================================================================

/// Port variable names to scan for conflict detection.
const PORT_VARS: &[&str] = &[
    "PORT", "APP_PORT", "SERVER_PORT", "API_PORT",
    "HTTP_PORT", "LISTEN_PORT", "WEBUI_PORT",
];

/// Run preflight on all tools in the scan path.
/// Returns (results, streaming events).
///
/// If `audit_store` is provided, each check result and the final
/// pass/fail summary are emitted as signed audit entries in the chain.
/// This is the canonical source of truth; `preflight.json` is kept
/// only as a read cache for fast cockpit rendering.
pub async fn run_preflight(
    scan_path: &Path,
    audit_store: Option<&Mutex<AuditStore>>,
) -> (PreflightResults, Vec<OnboardEvent>) {
    let mut events = Vec::new();
    let mut tool_results = Vec::new();
    let mut port_map: HashMap<u16, Vec<String>> = HashMap::new();

    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal("── Preflight ──────────────────────────"));

    // 1. Check Docker availability — attempt auto-start if not running
    let mut docker_available = check_docker_available().await;
    if docker_available {
        events.push(OnboardEvent::terminal("  ✓ Docker daemon reachable"));
    } else {
        events.push(OnboardEvent::terminal("  ⚠ Docker not running — attempting to start..."));
        if try_start_docker().await {
            // Wait for daemon to become responsive (up to 30s)
            for i in 0..15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if check_docker_available().await {
                    docker_available = true;
                    events.push(OnboardEvent::terminal(&format!(
                        "  ✓ Docker started (took ~{}s)", (i + 1) * 2
                    )));
                    break;
                }
            }
            if !docker_available {
                events.push(OnboardEvent::terminal(
                    "  ✗ Docker installed but failed to start — check Docker Desktop or the docker service"
                ));
            }
        } else {
            events.push(OnboardEvent::terminal(
                "  ✗ Docker not installed — install Docker Desktop from https://docker.com/get-started"
            ));
        }
    }

    // 2. Enumerate configured tools
    if !scan_path.exists() {
        events.push(OnboardEvent::terminal("  ⚠ Scan path does not exist"));
        let results = PreflightResults {
            tools: vec![],
            docker_available,
            port_conflicts: vec![],
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
        results.save();
        return (results, events);
    }

    let mut tool_dirs: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(scan_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() { continue; }
            let name = path.file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.starts_with('.') || name == "node_modules" || name == "target" {
                continue;
            }
            // Only preflight tools that have .env (configured)
            if path.join(".env").exists() || path.join(".env.example").exists() {
                tool_dirs.push((name, path));
            }
        }
    }

    events.push(OnboardEvent::terminal(&format!(
        "  Checking {} tool(s)...", tool_dirs.len()
    )));

    // 3. Per-tool preflight
    for (name, path) in &tool_dirs {
        let (result, tool_events) = preflight_tool(name, path, docker_available).await;

        // Collect port for conflict detection
        if let Some(port) = detect_port(path) {
            port_map.entry(port).or_default().push(name.clone());
        }

        events.extend(tool_events);
        tool_results.push(result);
    }

    // 4. Port conflict detection
    let mut port_conflicts = Vec::new();
    for (port, tools) in &port_map {
        if tools.len() > 1 {
            port_conflicts.push(PortConflict {
                port: *port,
                tools: tools.clone(),
            });
            events.push(OnboardEvent::terminal(&format!(
                "  ⚠ Port {} claimed by multiple tools: {}",
                port,
                tools.join(", ")
            )));
        }
    }

    // Summary
    let ready = tool_results.iter().filter(|t| t.ready).count();
    let total = tool_results.len();
    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal(&format!(
        "  Preflight complete: {}/{} tools ready",
        ready, total
    )));
    events.push(OnboardEvent::terminal("───────────────────────────────────────"));

    let results = PreflightResults {
        tools: tool_results,
        docker_available,
        port_conflicts,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // ── Emit receipts into the audit chain ──────────────────
    if let Some(store) = audit_store {
        use crate::tool_chain::{ToolEvent, emit_tool_receipt};

        for tool in &results.tools {
            // Emit configured receipt for tools with .env
            let env_path = PathBuf::from(&tool.path).join(".env");
            if env_path.exists() {
                let event = ToolEvent::configured(&tool.name);
                emit_tool_receipt(store, &event, Some(&format!(
                    "launch_method={}", tool.launch_method
                )));
            }

            // Emit individual check receipts
            for check in &tool.checks {
                let event = ToolEvent::preflight_check(
                    &tool.name,
                    &check.name,
                    &check.status,
                );
                emit_tool_receipt(store, &event, Some(&check.detail));
            }

            // Emit summary receipt
            if tool.ready {
                let event = ToolEvent::preflight_passed(&tool.name);
                let detail = format!(
                    "{} checks passed, {} auto-fixed",
                    tool.checks.iter().filter(|c| c.status != "fail").count(),
                    tool.auto_fixed.len()
                );
                emit_tool_receipt(store, &event, Some(&detail));
            } else {
                let event = ToolEvent::preflight_failed(&tool.name);
                let failures: Vec<String> = tool.checks
                    .iter()
                    .filter(|c| c.status == "fail")
                    .map(|c| c.detail.clone())
                    .collect();
                emit_tool_receipt(store, &event, Some(&failures.join("; ")));
            }
        }
    }

    // Keep JSON cache for fast cockpit rendering
    results.save();

    events.push(OnboardEvent::new(
        "preflight_complete",
        serde_json::json!({
            "ready": ready,
            "total": total,
            "docker_available": docker_available,
            "conflicts": results.port_conflicts.len(),
        }),
    ));

    (results, events)
}

// ============================================================================
// Per-tool preflight
// ============================================================================

async fn preflight_tool(name: &str, path: &Path, docker_ok: bool) -> (ToolPreflight, Vec<OnboardEvent>) {
    let mut checks = Vec::new();
    let mut auto_fixed = Vec::new();
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal(&format!("  ▸ {}", name)));

    // Detect launch method
    let has_compose = has_compose_file(path);
    let has_package_json = path.join("package.json").exists();
    let start_script = find_start_script(path);
    let has_makefile = path.join("Makefile").exists();

    let launch_method = if has_compose { "docker" }
        else if has_package_json { "npm" }
        else if start_script.is_some() { "script" }
        else if has_makefile { "make" }
        else { "none" };

    // ── .env bootstrap: copy from .env.example if missing ──
    let env_path = path.join(".env");
    let env_example = path.join(".env.example");
    if !env_path.exists() && env_example.exists() {
        if std::fs::copy(&env_example, &env_path).is_ok() {
            auto_fixed.push("Created .env from .env.example".into());
            events.push(OnboardEvent::terminal("    ✓ Created .env from .env.example"));
        }
    }

    // ── .env completeness ──────────────────────────────────
    let env_check = check_env_completeness(path);
    checks.push(env_check.clone());
    if env_check.status == "fail" {
        events.push(OnboardEvent::terminal(&format!("    ✗ {}", env_check.detail)));
    }

    // ── Docker-based tools ─────────────────────────────────
    if has_compose {
        if !docker_ok {
            checks.push(PreflightCheck {
                name: "docker_daemon".into(),
                status: "fail".into(),
                detail: "Docker daemon not running — start Docker Desktop or the docker service".into(),
            });
            events.push(OnboardEvent::terminal("    ✗ Docker not available"));
        } else {
            // Validate compose file
            let config_ok = run_cmd(path, "docker", &["compose", "config", "--quiet"]).await;
            if config_ok.success {
                checks.push(PreflightCheck {
                    name: "compose_valid".into(),
                    status: "pass".into(),
                    detail: "docker-compose.yml validates".into(),
                });
            } else {
                checks.push(PreflightCheck {
                    name: "compose_valid".into(),
                    status: "fail".into(),
                    detail: format!("Compose validation failed: {}", config_ok.stderr_tail()),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ Compose validation failed: {}", config_ok.stderr_tail()
                )));
            }

            // Pull images
            events.push(OnboardEvent::terminal("    Pulling images..."));
            let pull_ok = run_cmd(path, "docker", &["compose", "pull", "--quiet"]).await;
            if pull_ok.success {
                checks.push(PreflightCheck {
                    name: "images_pulled".into(),
                    status: "pass".into(),
                    detail: "All container images pulled".into(),
                });
                auto_fixed.push("Pulled container images".into());
                events.push(OnboardEvent::terminal("    ✓ Images pulled"));
            } else {
                checks.push(PreflightCheck {
                    name: "images_pulled".into(),
                    status: "fail".into(),
                    detail: format!("Image pull failed: {}", pull_ok.stderr_tail()),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ Image pull failed: {}", pull_ok.stderr_tail()
                )));
            }
        }
    }

    // ── Node.js tools ──────────────────────────────────────
    if has_package_json {
        let node_modules = path.join("node_modules");
        let needs_install = if !node_modules.exists() {
            true
        } else {
            // Stale check: if package.json is newer than node_modules, re-install
            let pkg_modified = std::fs::metadata(path.join("package.json"))
                .and_then(|m| m.modified()).ok();
            let nm_modified = std::fs::metadata(&node_modules)
                .and_then(|m| m.modified()).ok();
            matches!((pkg_modified, nm_modified), (Some(p), Some(n)) if p > n)
        };
        if needs_install {
            events.push(OnboardEvent::terminal("    Installing npm dependencies..."));
            let npm_ok = run_cmd(path, "npm", &["install", "--no-audit", "--no-fund"]).await;
            if npm_ok.success {
                checks.push(PreflightCheck {
                    name: "npm_deps".into(),
                    status: "fixed".into(),
                    detail: "Dependencies installed (npm install)".into(),
                });
                auto_fixed.push("Installed npm dependencies".into());
                events.push(OnboardEvent::terminal("    ✓ npm install complete"));
            } else {
                checks.push(PreflightCheck {
                    name: "npm_deps".into(),
                    status: "fail".into(),
                    detail: format!("npm install failed: {}", npm_ok.stderr_tail()),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ npm install failed: {}", npm_ok.stderr_tail()
                )));
            }
        } else {
            checks.push(PreflightCheck {
                name: "npm_deps".into(),
                status: "pass".into(),
                detail: "node_modules present".into(),
            });
        }
    }

    // ── Start script permissions ───────────────────────────
    if let Some(ref script) = start_script {
        let script_path = path.join(script);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&script_path) {
                let mode = meta.permissions().mode();
                if mode & 0o111 == 0 {
                    // Not executable — fix it
                    let new_perms = std::fs::Permissions::from_mode(mode | 0o755);
                    if std::fs::set_permissions(&script_path, new_perms).is_ok() {
                        checks.push(PreflightCheck {
                            name: "script_exec".into(),
                            status: "fixed".into(),
                            detail: format!("chmod +x {}", script),
                        });
                        auto_fixed.push(format!("Made {} executable", script));
                        events.push(OnboardEvent::terminal(&format!("    ✓ chmod +x {}", script)));
                    }
                } else {
                    checks.push(PreflightCheck {
                        name: "script_exec".into(),
                        status: "pass".into(),
                        detail: format!("{} is executable", script),
                    });
                }
            }
        }
        #[cfg(not(unix))]
        {
            checks.push(PreflightCheck {
                name: "script_exec".into(),
                status: "pass".into(),
                detail: format!("{} found", script),
            });
        }
    }

    // ── No launch method ───────────────────────────────────
    if launch_method == "none" {
        checks.push(PreflightCheck {
            name: "launch_method".into(),
            status: "fail".into(),
            detail: "No docker-compose.yml, start.sh, package.json, or Makefile found".into(),
        });
        events.push(OnboardEvent::terminal(
            "    ✗ No launch method — add docker-compose.yml or start.sh"
        ));
    } else {
        checks.push(PreflightCheck {
            name: "launch_method".into(),
            status: "pass".into(),
            detail: format!("Launch via: {}", launch_method),
        });
    }

    // Determine readiness
    let has_failures = checks.iter().any(|c| c.status == "fail");
    let ready = !has_failures;

    if ready {
        events.push(OnboardEvent::terminal(&format!("    ✓ {} ready", name)));
    }

    let result = ToolPreflight {
        name: name.to_string(),
        path: path.display().to_string(),
        ready,
        launch_method: launch_method.to_string(),
        checks,
        auto_fixed,
    };

    (result, events)
}

// ============================================================================
// Helpers
// ============================================================================

fn has_compose_file(path: &Path) -> bool {
    ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
        .iter()
        .any(|f| path.join(f).exists())
}

fn find_start_script(path: &Path) -> Option<String> {
    ["start.sh", "run.sh", "launch.sh"]
        .iter()
        .find(|s| path.join(s).exists())
        .map(|s| s.to_string())
}

fn detect_port(tool_path: &Path) -> Option<u16> {
    for filename in &[".env", ".env.example"] {
        let file = tool_path.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&file) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains('=') { continue; }
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if PORT_VARS.iter().any(|&p| key == p) {
                        if let Ok(port) = val.parse::<u16>() {
                            return Some(port);
                        }
                    }
                }
            }
        }
    }
    None
}

fn check_env_completeness(path: &Path) -> PreflightCheck {
    let env_path = path.join(".env");
    if !env_path.exists() {
        return PreflightCheck {
            name: "env_file".into(),
            status: "fail".into(),
            detail: "No .env file — run zp configure auto".into(),
        };
    }

    let contents = std::fs::read_to_string(&env_path).unwrap_or_default();

    // Count placeholder values (empty, sentinel markers, or common placeholders)
    let mut total = 0;
    let mut placeholders = 0;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() || !trimmed.contains('=') { continue; }
        total += 1;
        if let Some((_key, val)) = trimmed.split_once('=') {
            // Strip inline comments before checking the value
            let v = val.split('#').next().unwrap_or("")
                .trim().trim_matches('"').trim_matches('\'');
            if v.is_empty()
                || v.contains("your_")
                || v.contains("changeme")
                || v.contains("PLACEHOLDER")
                || val.contains("# MISSING")
            {
                placeholders += 1;
            }
        }
    }

    if placeholders > 0 {
        PreflightCheck {
            name: "env_file".into(),
            status: "fail".into(),
            detail: format!("{}/{} env vars are placeholders — store credentials in vault first", placeholders, total),
        }
    } else {
        PreflightCheck {
            name: "env_file".into(),
            status: "pass".into(),
            detail: format!("{} env vars configured", total),
        }
    }
}

async fn check_docker_available() -> bool {
    run_cmd(Path::new("/"), "docker", &["info", "--format", "{{.ServerVersion}}"]).await.success
}

/// Attempt to start Docker daemon. Returns true if we found a way to start it
/// (doesn't guarantee the daemon is ready — caller should poll check_docker_available).
async fn try_start_docker() -> bool {
    // macOS: Docker Desktop
    #[cfg(target_os = "macos")]
    {
        // Try Docker Desktop first
        if Path::new("/Applications/Docker.app").exists() {
            let _ = tokio::process::Command::new("open")
                .args(["-g", "-a", "Docker"])  // -g = don't bring to foreground
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return true;
        }
        // Colima (lightweight Docker runtime for macOS)
        if run_cmd(Path::new("/"), "which", &["colima"]).await.success {
            let _ = tokio::process::Command::new("colima")
                .args(["start"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return true;
        }
    }

    // Linux: systemd or direct service
    #[cfg(target_os = "linux")]
    {
        // Try systemctl first (most modern distros)
        if run_cmd(Path::new("/"), "which", &["systemctl"]).await.success {
            let result = run_cmd(Path::new("/"), "systemctl", &["start", "docker"]).await;
            if result.success { return true; }
            // May need sudo — try via pkexec (non-interactive sudo for desktop)
            let result = run_cmd(Path::new("/"), "sudo", &["-n", "systemctl", "start", "docker"]).await;
            if result.success { return true; }
        }
        // Fallback: service command
        if run_cmd(Path::new("/"), "which", &["service"]).await.success {
            let result = run_cmd(Path::new("/"), "sudo", &["-n", "service", "docker", "start"]).await;
            if result.success { return true; }
        }
    }

    // Windows: Docker Desktop
    #[cfg(target_os = "windows")]
    {
        let docker_desktop = Path::new("C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe");
        if docker_desktop.exists() {
            let _ = tokio::process::Command::new(docker_desktop)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return true;
        }
    }

    false
}

struct CmdResult {
    success: bool,
    stdout: String,
    stderr: String,
}

impl CmdResult {
    fn stderr_tail(&self) -> String {
        let lines: Vec<&str> = self.stderr.lines().collect();
        let start = if lines.len() > 3 { lines.len() - 3 } else { 0 };
        lines[start..].join(" | ")
    }
}

async fn run_cmd(cwd: &Path, program: &str, args: &[&str]) -> CmdResult {
    match tokio::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .await
    {
        Ok(output) => CmdResult {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(e) => CmdResult {
            success: false,
            stdout: String::new(),
            stderr: format!("Failed to run '{}': {}", program, e),
        },
    }
}

// ============================================================================
// Onboard handler — called as a WebSocket action after configure
// ============================================================================

pub async fn handle_preflight(_state: &mut OnboardState) -> Vec<OnboardEvent> {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    // WebSocket handler doesn't have access to AppState's audit store,
    // so chain emission happens only through the REST endpoint.
    // The JSON cache is still written for cockpit use.
    let (_results, events) = run_preflight(&scan_path, None).await;
    events
}
