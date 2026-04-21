//! Preflight checks — validate and auto-fix tool launch readiness.
//!
//! Runs after `zp configure auto` to ensure every configured tool
//! can start with a single cockpit click. Checks:
//!   - Vault configuration (credentials encrypted, injected at launch)
//!   - Docker daemon availability
//!   - Compose file validation
//!   - Image pre-pull
//!   - Port conflict detection
//!   - Start script permissions
//!   - Node dependency installation
//!
//! Tools without vault config are auto-resolved via `zp configure tool`.
//! No `.env` files are read or written — the vault is the sole authority.
//!
//! Results are persisted to `~/ZeroPoint/state/preflight.json`
//! so the cockpit knows which tools are launch-ready.

use super::{OnboardEvent, OnboardState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use zp_audit::AuditStore;
use zp_core::paths as zp_paths;

/// Result of preflight for a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPreflight {
    pub name: String,
    pub path: String,
    pub ready: bool,
    pub launch_method: String, // "native", "pnpm", "npm", "docker", "script", "make", "none"
    pub checks: Vec<PreflightCheck>,
    pub auto_fixed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightCheck {
    pub name: String,
    pub status: String, // "pass", "fixed", "fail"
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

    /// Persist to ~/ZeroPoint/state/preflight.json
    pub fn save(&self) {
        let state_dir = zp_paths::home()
            .unwrap_or_default()
            .join("state");
        std::fs::create_dir_all(&state_dir).ok();
        let path = state_dir.join("preflight.json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            std::fs::write(path, json).ok();
        }
    }

    /// Load from disk, if available.
    pub fn load() -> Option<Self> {
        let path = zp_paths::home()
            .ok()?
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
    "PORT",
    "APP_PORT",
    "SERVER_PORT",
    "API_PORT",
    "HTTP_PORT",
    "LISTEN_PORT",
    "WEBUI_PORT",
];

/// How recently a tool must have passed preflight for us to skip re-checking.
/// Receipts older than this are considered stale.
const PREFLIGHT_FRESH_SECS: i64 = 3600; // 1 hour

/// Set of tool names that have vault-backed configuration.
/// Preflight uses this to skip `.env` completeness checks for vault-configured tools.
pub type VaultConfiguredTools = std::collections::HashSet<String>;

/// Build the set of vault-configured tool names from the vault.
/// Returns an empty set if the vault can't be loaded.
pub fn detect_vault_configured_tools(
    vault_key: Option<&zp_trust::vault::CredentialVault>,
) -> VaultConfiguredTools {
    let mut set = VaultConfiguredTools::new();
    if let Some(vault) = vault_key {
        for entry in vault.list_prefix("tools/") {
            // entries are "tools/{name}/{VAR}" — extract the tool name
            if let Some(name) = entry.strip_prefix("tools/") {
                if let Some(tool_name) = name.split('/').next() {
                    set.insert(tool_name.to_string());
                }
            }
        }
    }
    set
}

/// Run preflight on all tools in the scan path.
/// Returns (results, streaming events).
///
/// If `audit_store` is provided, each check result and the final
/// pass/fail summary are emitted as signed audit entries in the chain.
/// This is the canonical source of truth; `preflight.json` is kept
/// only as a read cache for fast cockpit rendering.
///
/// **Idempotent**: tools with a `tool:preflight:passed:{name}` receipt
/// less than `PREFLIGHT_FRESH_SECS` old are skipped unless `force` is true.
pub(crate) async fn run_preflight(
    scan_path: &Path,
    audit_store: Option<&Arc<Mutex<AuditStore>>>,
    vault_tools: &VaultConfiguredTools,
) -> (PreflightResults, Vec<OnboardEvent>) {
    run_preflight_inner(scan_path, audit_store, false, None, vault_tools).await
}

/// Force a full re-run of all tools, ignoring fresh chain receipts.
#[allow(dead_code)]
pub(crate) async fn run_preflight_force(
    scan_path: &Path,
    audit_store: Option<&Arc<Mutex<AuditStore>>>,
    vault_tools: &VaultConfiguredTools,
) -> (PreflightResults, Vec<OnboardEvent>) {
    run_preflight_inner(scan_path, audit_store, true, None, vault_tools).await
}

/// Run preflight scoped to a single tool. Other tools are skipped.
/// Always forces a fresh run (never skips based on chain freshness).
pub(crate) async fn run_preflight_single(
    scan_path: &Path,
    tool_name: &str,
    audit_store: Option<&Arc<Mutex<AuditStore>>>,
    vault_tools: &VaultConfiguredTools,
) -> (PreflightResults, Vec<OnboardEvent>) {
    run_preflight_inner(scan_path, audit_store, true, Some(tool_name), vault_tools).await
}

async fn run_preflight_inner(
    scan_path: &Path,
    audit_store: Option<&Arc<Mutex<AuditStore>>>,
    force: bool,
    only_tool: Option<&str>,
    vault_tools: &VaultConfiguredTools,
) -> (PreflightResults, Vec<OnboardEvent>) {
    let mut events = Vec::new();
    let mut tool_results = Vec::new();
    let mut port_map: HashMap<u16, Vec<String>> = HashMap::new();

    // Build set of tools that recently passed preflight (idempotent skip).
    let fresh_tools: std::collections::HashSet<String> = if force {
        std::collections::HashSet::new()
    } else if let Some(store) = audit_store {
        fresh_preflight_tools(store)
    } else {
        std::collections::HashSet::new()
    };

    events.push(OnboardEvent::terminal(""));
    events.push(OnboardEvent::terminal(
        "── Preflight ──────────────────────────",
    ));

    // 1. Check Docker availability — attempt auto-start if not running
    let mut docker_available = check_docker_available().await;
    if docker_available {
        events.push(OnboardEvent::terminal("  ✓ Docker daemon reachable"));
    } else {
        events.push(OnboardEvent::terminal(
            "  ⚠ Docker not running — attempting to start...",
        ));
        if try_start_docker().await {
            // Wait for daemon to become responsive (up to 30s)
            for i in 0..15 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if check_docker_available().await {
                    docker_available = true;
                    events.push(OnboardEvent::terminal(&format!(
                        "  ✓ Docker started (took ~{}s)",
                        (i + 1) * 2
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
            if !path.is_dir() {
                continue;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if name.starts_with('.') || name == "node_modules" || name == "target" {
                continue;
            }
            // Preflight tools that are configured (vault) or discoverable (template)
            if vault_tools.contains(&name) || path.join(".env.example").exists() {
                tool_dirs.push((name, path));
            }
        }
    }

    events.push(OnboardEvent::terminal(&format!(
        "  Checking {} tool(s)...",
        tool_dirs.len()
    )));

    // 3. Per-tool preflight
    for (name, path) in &tool_dirs {
        // Single-tool scope: skip everything except the requested tool.
        if let Some(target) = only_tool {
            if !name.eq_ignore_ascii_case(target) {
                continue;
            }
        }

        // Idempotent: skip tools with a fresh passing receipt.
        if fresh_tools.contains(name.as_str()) {
            events.push(OnboardEvent::terminal(&format!(
                "  ▸ {} — recently passed, skipping (use force to re-check)",
                name
            )));
            // Synthesize a passing result so the summary counts are correct.
            tool_results.push(ToolPreflight {
                name: name.clone(),
                path: path.display().to_string(),
                ready: true,
                launch_method: "cached".to_string(),
                checks: vec![PreflightCheck {
                    name: "chain_fresh".into(),
                    status: "pass".into(),
                    detail: "Passed within the last hour — skipped".into(),
                }],
                auto_fixed: vec![],
            });
            continue;
        }

        let is_vault_configured = vault_tools.contains(name.as_str());
        let (result, tool_events) = preflight_tool(name, path, docker_available, is_vault_configured).await;

        // Collect port for conflict detection
        if let Some(port) = detect_port(path) {
            port_map.entry(port).or_default().push(name.clone());
        }

        events.extend(tool_events);
        tool_results.push(result);
    }

    // 4. Port conflict detection — app ports AND compose infrastructure ports
    let mut port_conflicts = Vec::new();

    // 4a. Check for tools claiming the same app port
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

    // 4b. Check compose infrastructure ports against the live system.
    //     This catches the buried failure: tool A's postgres on 5432
    //     collides with tool B's postgres already running on 5432.
    //     Only applies to tools that actually launch via Docker compose.
    //     Tools running via pnpm/npm/native may have a compose file for
    //     dev purposes but don't use it at runtime.
    let docker_launched: std::collections::HashSet<String> = tool_results
        .iter()
        .filter(|t| t.launch_method == "docker")
        .map(|t| t.name.clone())
        .collect();
    if docker_available {
        for (name, path) in &tool_dirs {
            if !docker_launched.contains(name.as_str()) {
                continue;
            }
            let compose_ports = extract_compose_ports(path);
            for (host_port, service) in &compose_ports {
                if let Some(occupant) = check_port_in_use(*host_port).await {
                    // Is it occupied by THIS tool's own compose stack? That's fine.
                    let own_container = occupant.to_lowercase().contains(&name.to_lowercase());
                    if !own_container {
                        port_conflicts.push(PortConflict {
                            port: *host_port,
                            tools: vec![format!("{}:{}", name, service), occupant.clone()],
                        });
                        events.push(OnboardEvent::terminal(&format!(
                            "  ⚠ {}'s {} needs port {} — already held by {}",
                            name, service, host_port, occupant
                        )));

                        // Emit dep receipt — this is a blocking conflict
                        if let Some(store) = audit_store {
                            use crate::tool_chain::emit_tool_receipt;
                            use crate::tool_state::events as te;
                            let event =
                                te::dep(te::DEP_FAILED, name, &format!("port:{}", host_port));
                            emit_tool_receipt(
                                store,
                                &event,
                                Some(&format!("service={} occupant={}", service, occupant)),
                            );
                        }
                    }
                }
            }
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
    events.push(OnboardEvent::terminal(
        "───────────────────────────────────────",
    ));

    let results = PreflightResults {
        tools: tool_results,
        docker_available,
        port_conflicts,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // ── Emit receipts into the audit chain ──────────────────
    if let Some(store) = audit_store {
        use crate::tool_chain::{emit_tool_receipt, ToolEvent};
        use crate::tool_state::events as te;

        for tool in &results.tools {
            // Emit configured receipt for vault-configured tools
            if vault_tools.contains(&tool.name) {
                let event = ToolEvent::configured(&tool.name);
                emit_tool_receipt(
                    store,
                    &event,
                    Some(&format!("launch_method={} storage=vault", tool.launch_method)),
                );
            }

            // P6-1: emit ConfigurationClaim receipts for manifest configurable params
            {
                let tool_path = std::path::PathBuf::from(&tool.path);
                let manifest_path = tool_path.join(".zp-configure.toml");
                if let Ok(manifest) = zp_engine::capability::load_manifest(&manifest_path) {
                    for param in &manifest.configurable {
                        crate::tool_chain::emit_configuration_receipt(
                            store,
                            &tool.name,
                            &param.name,
                            &param.default,
                            "manifest_default",
                            None,
                        );
                    }
                }
            }

            // Emit individual check receipts
            for check in &tool.checks {
                let event = ToolEvent::preflight_check(&tool.name, &check.name, &check.status);
                emit_tool_receipt(store, &event, Some(&check.detail));
            }

            // ── Dependency receipts ─────────────────────────────
            // Infer dependencies from the tool's .env.example template
            // (source of truth for what services a tool needs).
            let tool_path = PathBuf::from(&tool.path);

            // Docker daemon dependency
            if tool.launch_method == "docker" || has_compose_file(&tool_path) {
                let event = if docker_available {
                    te::dep(te::DEP_SATISFIED, &tool.name, "docker")
                } else {
                    te::dep(te::DEP_NEEDED, &tool.name, "docker")
                };
                emit_tool_receipt(store, &event, None);
            }

            // Database dependency: infer from .env.example template
            let template_path = tool_path.join(".env.example");
            if let Ok(template_contents) = std::fs::read_to_string(&template_path) {
                // Postgres
                if template_contents.contains("DATABASE_URL")
                    || template_contents.contains("POSTGRES_")
                    || template_contents.contains("PG_")
                {
                    let compose_ok = tool
                        .checks
                        .iter()
                        .any(|c| c.name == "compose_valid" && c.status == "pass");
                    let event = if compose_ok || docker_available {
                        te::dep(te::DEP_SATISFIED, &tool.name, "postgres")
                    } else {
                        te::dep(te::DEP_NEEDED, &tool.name, "postgres")
                    };
                    emit_tool_receipt(store, &event, None);
                }

                // Redis
                if template_contents.contains("REDIS_URL") || template_contents.contains("REDIS_HOST") {
                    let event = if docker_available {
                        te::dep(te::DEP_SATISFIED, &tool.name, "redis")
                    } else {
                        te::dep(te::DEP_NEEDED, &tool.name, "redis")
                    };
                    emit_tool_receipt(store, &event, None);
                }
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
                let failures: Vec<String> = tool
                    .checks
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

async fn preflight_tool(
    name: &str,
    path: &Path,
    docker_ok: bool,
    vault_configured: bool,
) -> (ToolPreflight, Vec<OnboardEvent>) {
    let mut checks = Vec::new();
    let mut auto_fixed = Vec::new();
    let mut events = Vec::new();

    events.push(OnboardEvent::terminal(&format!("  ▸ {}", name)));

    // Detect launch method
    let has_cargo = path.join("Cargo.toml").exists();
    let has_compose = has_compose_file(path);
    let has_package_json = path.join("package.json").exists();
    let has_pnpm_lock = path.join("pnpm-lock.yaml").exists();
    let has_npm_lock = path.join("package-lock.json").exists();
    let start_script = find_start_script(path);
    let has_makefile = path.join("Makefile").exists();

    // Priority: native > local package manager (pnpm > npm) > docker > script > make
    // Local-first: prefer pnpm/npm over Docker when lockfile present
    let launch_method = if has_cargo {
        "native"
    } else if has_package_json && has_pnpm_lock {
        "pnpm"
    } else if has_package_json && has_npm_lock {
        "npm"
    } else if has_compose {
        "docker"
    } else if has_package_json {
        "npm"
    } else if start_script.is_some() {
        "script"
    } else if has_makefile {
        "make"
    } else {
        "none"
    };

    // ── Configuration check: vault-backed or .env ──────────
    let env_check = if vault_configured {
        // Tool has vault config — .env is not needed. Secrets are injected
        // at launch time via Command::env(). No plaintext on disk.
        events.push(OnboardEvent::terminal(
            "    ✓ Vault-configured (credentials encrypted, injected at launch)",
        ));
        PreflightCheck {
            name: "env_config".into(),
            status: "pass".into(),
            detail: "Vault-backed configuration — zero plaintext on disk".into(),
        }
    } else {
        // No vault config — attempt vault auto-resolution.
        events.push(OnboardEvent::terminal(
            "    ⚠ Not vault-configured — attempting auto-resolve...",
        ));

        let configure_result = run_cmd(
            path,
            "zp",
            &[
                "configure",
                "tool",
                "--path",
                &path.display().to_string(),
                "--name",
                name,
            ],
        )
        .await;

        if configure_result.success {
            auto_fixed.push("Resolved credentials into vault".into());
            events.push(OnboardEvent::terminal(
                "    ✓ Credentials resolved into vault",
            ));
            PreflightCheck {
                name: "env_config".into(),
                status: "pass".into(),
                detail: "Credentials auto-resolved into vault".into(),
            }
        } else {
            events.push(OnboardEvent::terminal(
                "    ✗ Vault auto-resolve failed",
            ));
            events.push(OnboardEvent::terminal(
                "    → Store credentials: zp configure vault-add --provider <name> --field api_key"
            ));
            PreflightCheck {
                name: "env_config".into(),
                status: "fail".into(),
                detail: "No vault configuration — run `zp configure tool` or `zp configure vault-add`".into(),
            }
        }
    };
    checks.push(env_check.clone());

    // ── Docker-based tools ─────────────────────────────────
    if has_compose {
        if !docker_ok {
            checks.push(PreflightCheck {
                name: "docker_daemon".into(),
                status: "fail".into(),
                detail: "Docker daemon not running — start Docker Desktop or the docker service"
                    .into(),
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
                    "    ✗ Compose validation failed: {}",
                    config_ok.stderr_tail()
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
                    "    ✗ Image pull failed: {}",
                    pull_ok.stderr_tail()
                )));
            }
        }
    }

    // ── Node.js tools ──────────────────────────────────────
    if has_package_json {
        // Detect package manager: pnpm (pnpm-lock.yaml) > npm (default)
        let use_pnpm = path.join("pnpm-lock.yaml").exists();
        let pkg_mgr = if use_pnpm { "pnpm" } else { "npm" };

        let node_modules = path.join("node_modules");
        let needs_install = if !node_modules.exists() {
            true
        } else {
            // Stale check: if package.json is newer than node_modules, re-install
            let pkg_modified = std::fs::metadata(path.join("package.json"))
                .and_then(|m| m.modified())
                .ok();
            let nm_modified = std::fs::metadata(&node_modules)
                .and_then(|m| m.modified())
                .ok();
            matches!((pkg_modified, nm_modified), (Some(p), Some(n)) if p > n)
        };
        if needs_install {
            events.push(OnboardEvent::terminal(&format!(
                "    Installing {} dependencies...",
                pkg_mgr
            )));
            let install_args: Vec<&str> = if use_pnpm {
                vec!["install"]
            } else {
                vec!["install", "--no-audit", "--no-fund"]
            };
            let install_ok = run_cmd(path, pkg_mgr, &install_args).await;
            if install_ok.success {
                checks.push(PreflightCheck {
                    name: "node_deps".into(),
                    status: "fixed".into(),
                    detail: format!("Dependencies installed ({} install)", pkg_mgr),
                });
                auto_fixed.push(format!("Installed {} dependencies", pkg_mgr));
                events.push(OnboardEvent::terminal(&format!(
                    "    ✓ {} install complete",
                    pkg_mgr
                )));
            } else {
                checks.push(PreflightCheck {
                    name: "node_deps".into(),
                    status: "fail".into(),
                    detail: format!("{} install failed: {}", pkg_mgr, install_ok.stderr_tail()),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ {} install failed: {}",
                    pkg_mgr,
                    install_ok.stderr_tail()
                )));
            }
        } else {
            checks.push(PreflightCheck {
                name: "node_deps".into(),
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
                        events.push(OnboardEvent::terminal(&format!(
                            "    ✓ chmod +x {}",
                            script
                        )));
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
            "    ✗ No launch method — add docker-compose.yml or start.sh",
        ));
    } else {
        checks.push(PreflightCheck {
            name: "launch_method".into(),
            status: "pass".into(),
            detail: format!("Launch via: {}", launch_method),
        });
    }

    // ── Zombie container detection ────────────────────────
    // If compose is present, check for orphan containers from a previous
    // launch that might be holding ports or database locks.
    if has_compose && docker_ok {
        let ps_result = run_cmd(path, "docker", &["compose", "ps", "-q"]).await;
        if ps_result.success && !ps_result.stdout.trim().is_empty() {
            let container_count = ps_result.stdout.lines().count();
            // Try to bring them down cleanly
            let down_result =
                run_cmd(path, "docker", &["compose", "down", "--remove-orphans"]).await;
            if down_result.success {
                checks.push(PreflightCheck {
                    name: "zombie_containers".into(),
                    status: "fixed".into(),
                    detail: format!(
                        "Cleaned up {} orphan container(s) from previous run",
                        container_count
                    ),
                });
                auto_fixed.push(format!("Removed {} zombie containers", container_count));
                events.push(OnboardEvent::terminal(&format!(
                    "    ✓ Cleaned {} orphan container(s)",
                    container_count
                )));
            } else {
                checks.push(PreflightCheck {
                    name: "zombie_containers".into(),
                    status: "fail".into(),
                    detail: format!(
                        "Found {} running container(s) that could not be stopped",
                        container_count
                    ),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ {} zombie container(s) — try: docker compose down",
                    container_count
                )));
            }
        }
    }

    // ── Stale PID file detection ──────────────────────────
    // Native tools often write PID files (e.g., ~/.ironclaw/ironclaw.pid).
    // A leftover PID file from a crash prevents the next startup.
    if has_cargo {
        let pid_dirs = [
            // ~/.{toolname}/{toolname}.pid
            dirs::home_dir().map(|h| h.join(format!(".{}", name))),
            // ./tmp/{toolname}.pid
            Some(path.join("tmp")),
        ];
        for dir in pid_dirs.iter().flatten() {
            let pid_file = dir.join(format!("{}.pid", name));
            if pid_file.exists() {
                // Read PID and check if process is still running
                let pid_content = std::fs::read_to_string(&pid_file).unwrap_or_default();
                let pid_str = pid_content.trim();
                let process_alive = if let Ok(pid) = pid_str.parse::<u32>() {
                    // kill -0 checks existence without sending a signal
                    run_cmd(Path::new("/"), "kill", &["-0", &pid.to_string()])
                        .await
                        .success
                } else {
                    false
                };

                if !process_alive {
                    // Stale PID — remove it
                    if std::fs::remove_file(&pid_file).is_ok() {
                        checks.push(PreflightCheck {
                            name: "stale_pid".into(),
                            status: "fixed".into(),
                            detail: format!("Removed stale PID file: {}", pid_file.display()),
                        });
                        auto_fixed.push(format!("Removed stale {}.pid", name));
                        events.push(OnboardEvent::terminal(&format!(
                            "    ✓ Removed stale PID file ({})",
                            pid_str
                        )));
                    }
                }
            }
        }
    }

    // ── Native binary pre-build check ────────────────────
    // cargo run --release on a fresh clone takes 5–10 minutes.
    // Detect whether the release binary exists so the cockpit can
    // warn the user or pre-build.
    if has_cargo {
        // Detect the binary name from Cargo.toml
        let binary_name = detect_cargo_binary(path).unwrap_or_else(|| name.to_string());
        let release_binary = path.join("target").join("release").join(&binary_name);

        if release_binary.exists() {
            checks.push(PreflightCheck {
                name: "native_binary".into(),
                status: "pass".into(),
                detail: format!("Release binary found: target/release/{}", binary_name),
            });
        } else {
            // Not a hard failure — it'll just take a while on first launch
            checks.push(PreflightCheck {
                name: "native_binary".into(),
                status: "pass".into(), // warn, not fail
                detail: format!(
                    "No release binary yet — first launch will compile (3–10 min). \
                     Pre-build with: cd {} && cargo build --release",
                    path.display()
                ),
            });
            events.push(OnboardEvent::terminal(&format!(
                "    ⚠ No release binary — first launch will compile ({} min)",
                "3–10"
            )));
        }
    }

    // ── Database connectivity smoke test ──────────────────
    // If the tool uses compose with postgres/redis, verify the
    // services can actually accept connections after `docker compose up -d`.
    // This catches: wrong credentials, missing init scripts, volume
    // permission issues — things image-pull alone can't detect.
    if has_compose && docker_ok {
        let compose_ports = extract_compose_ports(path);
        let has_db_service =
            compose_ports.iter().any(|(p, _)| *p == 5432 || *p == 5433) || env_mentions_db(path);

        if has_db_service {
            // Quick up → wait → check → down cycle
            let up = run_cmd(path, "docker", &["compose", "up", "-d"]).await;
            if up.success {
                // Give services a few seconds to initialize
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;

                // Try pg_isready against the compose network
                let pg_check = run_cmd(
                    path,
                    "docker",
                    &[
                        "compose",
                        "exec",
                        "-T",
                        "db",
                        "pg_isready",
                        "-U",
                        "postgres",
                    ],
                )
                .await;

                // Also try the service named "postgres" if "db" didn't work
                let pg_ok = if pg_check.success {
                    true
                } else {
                    run_cmd(
                        path,
                        "docker",
                        &[
                            "compose",
                            "exec",
                            "-T",
                            "postgres",
                            "pg_isready",
                            "-U",
                            "postgres",
                        ],
                    )
                    .await
                    .success
                };

                // Clean up — don't leave containers running after preflight
                let _ = run_cmd(path, "docker", &["compose", "down"]).await;

                if pg_ok {
                    checks.push(PreflightCheck {
                        name: "db_connectivity".into(),
                        status: "pass".into(),
                        detail: "Postgres accepts connections".into(),
                    });
                    events.push(OnboardEvent::terminal(
                        "    ✓ Database connectivity verified",
                    ));
                } else {
                    checks.push(PreflightCheck {
                        name: "db_connectivity".into(),
                        status: "fail".into(),
                        detail: "Postgres container started but pg_isready failed — check credentials or init scripts".into(),
                    });
                    events.push(OnboardEvent::terminal(
                        "    ✗ Database not accepting connections — check compose logs",
                    ));
                }
            } else {
                checks.push(PreflightCheck {
                    name: "db_connectivity".into(),
                    status: "fail".into(),
                    detail: format!("docker compose up failed: {}", up.stderr_tail()),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ Compose up failed: {}",
                    up.stderr_tail()
                )));
            }
        }
    }

    // ── Deep scan: cross-reference config files ─────────
    let scan_result = super::deep_scan::analyze_tool(name, path);
    events.push(OnboardEvent::terminal(&format!(
        "    ▸ Deep scan: {} ({})",
        scan_result.archetype,
        if scan_result.findings.len() == 1 {
            "1 finding".to_string()
        } else {
            format!("{} findings", scan_result.findings.len())
        }
    )));

    for finding in &scan_result.findings {
        match finding.severity {
            super::deep_scan::FindingSeverity::Error => {
                checks.push(PreflightCheck {
                    name: format!("deep_scan:{}", finding.category),
                    status: "fail".into(),
                    detail: finding.message.clone(),
                });
                events.push(OnboardEvent::terminal(&format!(
                    "    ✗ {}",
                    finding.message
                )));
            }
            super::deep_scan::FindingSeverity::Warning => {
                checks.push(PreflightCheck {
                    name: format!("deep_scan:{}", finding.category),
                    status: "pass".into(), // warnings don't block launch
                    detail: finding.message.clone(),
                });
                if finding.correction.is_some() {
                    events.push(OnboardEvent::terminal(&format!(
                        "    ⚠ {} (auto-corrected)",
                        finding.category
                    )));
                    auto_fixed.push(format!("Deep scan: {}", finding.category));
                } else {
                    events.push(OnboardEvent::terminal(&format!(
                        "    ⚠ {}",
                        finding.message
                    )));
                }
            }
            super::deep_scan::FindingSeverity::Info => {
                // Info findings are logged but don't produce PreflightChecks
                debug!("Deep scan [{}]: {}", name, finding.message);
            }
        }
    }

    if !scan_result.corrected_env.is_empty() {
        let corrections: Vec<String> = scan_result.corrected_env.keys().cloned().collect();
        checks.push(PreflightCheck {
            name: "deep_scan:corrections".into(),
            status: "fixed".into(),
            detail: format!(
                "Auto-corrected env vars from config cross-reference: {}",
                corrections.join(", ")
            ),
        });
        auto_fixed.push(format!("Deep scan corrected: {}", corrections.join(", ")));
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
    [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ]
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
    // .env.zp is the ZP-assigned override and takes highest priority.
    // It's sourced at launch via the preamble, so preflight must respect it too.
    for filename in &[".env.zp", ".env", ".env.example"] {
        let file = tool_path.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&file) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains('=') {
                    continue;
                }
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if PORT_VARS.contains(&key) {
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

/// Extract host port mappings from docker-compose.yml.
///
/// Parses the `ports:` section of each service for host:container port
/// mappings.  Returns a vec of (host_port, service_name) pairs.
///
/// Handles formats:
///   - "5432:5432"
///   - "127.0.0.1:5432:5432"
///   - "8080:80"
///   - `5432` (short form — host=container)
fn extract_compose_ports(tool_path: &Path) -> Vec<(u16, String)> {
    let compose_files = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ];
    let compose_path = compose_files
        .iter()
        .map(|f| tool_path.join(f))
        .find(|p| p.exists());

    let contents = match compose_path.and_then(|p| std::fs::read_to_string(&p).ok()) {
        Some(c) => c,
        None => return vec![],
    };

    let mut results = Vec::new();
    let mut current_service: Option<String> = None;
    let mut in_ports = false;

    for line in contents.lines() {
        let trimmed = line.trim();

        // Skip comments and empty
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Detect service name (top-level key under services:, 2-space indent)
        // Simple YAML parsing — works for standard compose files
        let indent = line.len() - line.trim_start().len();

        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
            current_service = Some(trimmed.trim_end_matches(':').to_string());
            in_ports = false;
        }

        // Detect ports: section
        if trimmed == "ports:" && current_service.is_some() {
            in_ports = true;
            continue;
        }

        // Non-list line at same or lower indent ends the ports section
        if in_ports && !trimmed.starts_with('-') && indent <= 4 {
            in_ports = false;
        }

        // Parse port entries
        if in_ports && trimmed.starts_with('-') {
            let port_spec = trimmed
                .trim_start_matches('-')
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if let Some(host_port) = parse_host_port(port_spec) {
                let service = current_service.clone().unwrap_or_default();
                results.push((host_port, service));
            }
        }
    }

    results
}

/// Parse a Docker port mapping string and return the host port.
///
/// Formats: "5432:5432", "127.0.0.1:5432:5432", "8080:80", "5432"
fn parse_host_port(spec: &str) -> Option<u16> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        1 => parts[0].split('/').next()?.parse().ok(), // "5432" or "5432/tcp"
        2 => parts[0].parse().ok(),                    // "5432:5432"
        3 => parts[1].parse().ok(),                    // "127.0.0.1:5432:5432"
        _ => None,
    }
}

/// Detect the binary name from a Cargo.toml.
///
/// Checks in priority order:
///   1. `[[bin]]` sections — returns the first `name` found
///   2. `[package]` section — returns the `name` field
///   3. Falls back to `None` (caller uses directory name)
///
/// This is a lightweight parse — we don't pull in `cargo_toml` crate
/// since we only need the binary name for a readiness check.
fn detect_cargo_binary(tool_path: &Path) -> Option<String> {
    let cargo_toml = tool_path.join("Cargo.toml");
    let contents = std::fs::read_to_string(&cargo_toml).ok()?;

    // Pass 1: look for [[bin]] name = "..."
    let mut in_bin_section = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[[bin]]" {
            in_bin_section = true;
            continue;
        }
        // Any other section header ends [[bin]]
        if trimmed.starts_with('[') {
            in_bin_section = false;
        }
        if in_bin_section {
            if let Some(name) = parse_toml_string_value(trimmed, "name") {
                return Some(name);
            }
        }
    }

    // Pass 2: fall back to [package] name
    let mut in_package = false;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed == "[package]" {
            in_package = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_package = false;
        }
        if in_package {
            if let Some(name) = parse_toml_string_value(trimmed, "name") {
                return Some(name);
            }
        }
    }

    None
}

/// Extract a string value from a TOML key = "value" line.
fn parse_toml_string_value(line: &str, key: &str) -> Option<String> {
    let trimmed = line.trim();
    if let Some(rest) = trimmed.strip_prefix(key) {
        let rest = rest.trim();
        if let Some(rest) = rest.strip_prefix('=') {
            let val = rest.trim().trim_matches('"').trim_matches('\'');
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

/// Check if a tool's .env references database variables.
fn env_mentions_db(tool_path: &Path) -> bool {
    let env_path = tool_path.join(".env");
    if let Ok(contents) = std::fs::read_to_string(&env_path) {
        return contents.contains("DATABASE_URL")
            || contents.contains("POSTGRES_")
            || contents.contains("PG_HOST")
            || contents.contains("PG_PORT");
    }
    false
}

/// Check if a port is in use on the system.
/// Returns Some(description) if occupied, None if free.
async fn check_port_in_use(port: u16) -> Option<String> {
    // Try lsof first (macOS + Linux)
    let result = run_cmd(
        Path::new("/"),
        "lsof",
        &["-i", &format!(":{}", port), "-sTCP:LISTEN", "-P", "-n"],
    )
    .await;

    if result.success && !result.stdout.trim().is_empty() {
        // Parse lsof output for process name
        let lines: Vec<&str> = result.stdout.lines().collect();
        if lines.len() > 1 {
            let fields: Vec<&str> = lines[1].split_whitespace().collect();
            let process = fields.first().unwrap_or(&"unknown");
            let pid = fields.get(1).unwrap_or(&"?");
            return Some(format!("{} (PID {})", process, pid));
        }
        return Some("unknown process".to_string());
    }

    // Also check docker containers
    let docker_result = run_cmd(
        Path::new("/"),
        "docker",
        &[
            "ps",
            "--format",
            "{{.Names}} {{.Ports}}",
            "--filter",
            &format!("publish={}", port),
        ],
    )
    .await;

    if docker_result.success && !docker_result.stdout.trim().is_empty() {
        let container = docker_result
            .stdout
            .lines()
            .next()
            .unwrap_or("unknown container");
        return Some(format!("container: {}", container.trim()));
    }

    None
}

async fn check_docker_available() -> bool {
    run_cmd(
        Path::new("/"),
        "docker",
        &["info", "--format", "{{.ServerVersion}}"],
    )
    .await
    .success
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
                .args(["-g", "-a", "Docker"]) // -g = don't bring to foreground
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
        if run_cmd(Path::new("/"), "which", &["systemctl"])
            .await
            .success
        {
            let result = run_cmd(Path::new("/"), "systemctl", &["start", "docker"]).await;
            if result.success {
                return true;
            }
            // May need sudo — try via pkexec (non-interactive sudo for desktop)
            let result = run_cmd(
                Path::new("/"),
                "sudo",
                &["-n", "systemctl", "start", "docker"],
            )
            .await;
            if result.success {
                return true;
            }
        }
        // Fallback: service command
        if run_cmd(Path::new("/"), "which", &["service"]).await.success {
            let result = run_cmd(
                Path::new("/"),
                "sudo",
                &["-n", "service", "docker", "start"],
            )
            .await;
            if result.success {
                return true;
            }
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

/// Default timeout for quick probes (docker info, lsof, kill -0, etc.)
const CMD_TIMEOUT_PROBE: std::time::Duration = std::time::Duration::from_secs(30);

/// Extended timeout for heavy operations (docker pull, npm install, cargo build).
const CMD_TIMEOUT_HEAVY: std::time::Duration = std::time::Duration::from_secs(300);

/// Programs that get the extended 5-minute timeout.
const HEAVY_PROGRAMS: &[&str] = &["pnpm", "npm", "yarn", "cargo"];
/// Args that upgrade docker to the heavy timeout.
const HEAVY_DOCKER_ARGS: &[&str] = &["pull", "build", "up", "install"];

async fn run_cmd(cwd: &Path, program: &str, args: &[&str]) -> CmdResult {
    run_cmd_with_timeout(cwd, program, args, None).await
}

async fn run_cmd_with_timeout(
    cwd: &Path,
    program: &str,
    args: &[&str],
    timeout_override: Option<std::time::Duration>,
) -> CmdResult {
    // Pick timeout: explicit override > heavy heuristic > default probe
    let timeout = timeout_override.unwrap_or_else(|| {
        if HEAVY_PROGRAMS.contains(&program) {
            return CMD_TIMEOUT_HEAVY;
        }
        if (program == "docker" || program == "docker-compose")
            && args.iter().any(|a| HEAVY_DOCKER_ARGS.contains(a))
        {
            return CMD_TIMEOUT_HEAVY;
        }
        CMD_TIMEOUT_PROBE
    });

    let child_future = tokio::process::Command::new(program)
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();

    match tokio::time::timeout(timeout, child_future).await {
        Ok(Ok(output)) => CmdResult {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Ok(Err(e)) => CmdResult {
            success: false,
            stdout: String::new(),
            stderr: format!("Failed to run '{}': {}", program, e),
        },
        Err(_) => CmdResult {
            success: false,
            stdout: String::new(),
            stderr: format!(
                "Command '{}' timed out after {}s",
                program,
                timeout.as_secs()
            ),
        },
    }
}

// ============================================================================
// Chain-based freshness check
// ============================================================================

/// Scan the audit chain for `tool:preflight:passed:{name}` receipts
/// that are less than `PREFLIGHT_FRESH_SECS` old.
fn fresh_preflight_tools(
    audit_store: &Arc<Mutex<AuditStore>>,
) -> std::collections::HashSet<String> {
    use crate::tool_chain::tool_lifecycle_conv_id;
    use zp_core::AuditAction;

    let mut fresh = std::collections::HashSet::new();
    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return fresh,
    };

    let entries = match store.get_entries(tool_lifecycle_conv_id(), 500) {
        Ok(e) => e,
        Err(_) => return fresh,
    };

    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(PREFLIGHT_FRESH_SECS);

    for entry in &entries {
        if let AuditAction::SystemEvent { event } = &entry.action {
            // Match "tool:preflight:passed:{name}"
            if let Some(rest) = event.strip_prefix("tool:preflight:passed:") {
                if entry.timestamp >= cutoff {
                    fresh.insert(rest.to_string());
                }
            }
        }
    }

    fresh
}

// ============================================================================
// Onboard handler — called as a WebSocket action after configure
// ============================================================================

pub(crate) async fn handle_preflight(
    _state: &mut OnboardState,
    app_state: &crate::AppState,
) -> Vec<OnboardEvent> {
    let scan_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("projects");

    // Pass the audit store so preflight receipts are emitted into the
    // canonical chain — not just the JSON cache.  Without this, tools
    // preflighted during onboarding show "awaiting preflight" on the
    // dashboard because chain-based readiness finds no entries.
    // Detect vault-configured tools for the preflight
    let vault = app_state.0.vault_key.get()
        .and_then(|k| k.as_ref())
        .and_then(|resolved_key| {
            let vault_path = std::path::PathBuf::from(&app_state.0.data_dir).join("vault.json");
            zp_trust::CredentialVault::load_or_create(&resolved_key.key, &vault_path).ok()
        });
    let vault_tools = detect_vault_configured_tools(vault.as_ref());

    let (_results, events) = run_preflight(&scan_path, Some(&app_state.0.audit_store), &vault_tools).await;
    events
}
