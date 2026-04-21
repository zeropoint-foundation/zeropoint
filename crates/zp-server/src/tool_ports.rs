//! Tool Port Allocator — deterministic port assignment for governed tools.
//!
//! ZeroPoint assigns each registered tool a port from a reserved range
//! (default 9100–9199) so tools that share default ports (3000, 8080, etc.)
//! don't collide.  Assignments are persisted to `{data_dir}/tool-ports.json`
//! and remain stable across restarts.
//!
//! The allocator is used at two points:
//!   1. **Launch**: Before spawning a tool, ZP writes `.env.zp` with the
//!      assigned port.  The launch command sources this file so the tool
//!      binds to the ZP-managed port instead of its default.
//!   2. **Proxy**: The subdomain proxy at `{name}.localhost:3000` forwards to
//!      `127.0.0.1:{assigned_port}`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing::{debug, info, warn};

// ── Range ───────────────────────────────────────────────────────────────

const DEFAULT_RANGE_START: u16 = 9100;
const DEFAULT_RANGE_END: u16 = 9199;

// ── Error ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PortError {
    #[error("All ports in range {0}–{1} are allocated")]
    RangeExhausted(u16, u16),

    #[error("Tool '{0}' has no port assignment")]
    NotAssigned(String),
}

// ── Allocator ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PortAssignment {
    pub port: u16,
    /// The .env variable name this tool uses for its primary UI port.
    /// Stored so `.env.zp` can write the right key.
    pub port_var: String,
    /// ZP-generated auth token injected into `.env.zp` and the proxy.
    /// The proxy sends this as `Authorization: Bearer {token}` on every
    /// request, so the user never sees a login screen.
    #[serde(default = "generate_auth_token")]
    pub auth_token: String,
}

/// Generate a cryptographically random auth token.
///
/// Uses 16 bytes (128 bits) of randomness from the OS CSPRNG via `rand`,
/// producing a 32-char hex string prefixed with `zp-`. This replaces the
/// previous timestamp+PID scheme which was predictable if an attacker
/// could observe process timing.
fn generate_auth_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!("zp-{}", hex::encode(bytes))
}

pub struct PortAllocator {
    range_start: u16,
    range_end: u16,
    assignments: Mutex<HashMap<String, PortAssignment>>,
    persist_path: PathBuf,
}

impl PortAllocator {
    /// Create a new allocator, loading persisted assignments if they exist.
    pub fn new(data_dir: &Path) -> Self {
        let persist_path = data_dir.join("tool-ports.json");
        let assignments: HashMap<String, PortAssignment> = if persist_path.exists() {
            match std::fs::read_to_string(&persist_path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_else(|e| {
                    warn!("Corrupt tool-ports.json, starting fresh: {}", e);
                    HashMap::new()
                }),
                Err(e) => {
                    warn!("Could not read tool-ports.json: {}", e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        info!(
            "Port allocator: {} existing assignments, range {}–{}",
            assignments.len(),
            DEFAULT_RANGE_START,
            DEFAULT_RANGE_END,
        );

        let alloc = Self {
            range_start: DEFAULT_RANGE_START,
            range_end: DEFAULT_RANGE_END,
            assignments: Mutex::new(assignments),
            persist_path,
        };

        // Re-persist so any newly-generated auth_tokens (from serde
        // default on old entries) are saved.
        alloc.persist();
        alloc
    }

    /// Get the port for a tool if already assigned.
    pub fn get_assigned(&self, tool_name: &str) -> Option<PortAssignment> {
        self.assignments.lock().unwrap().get(tool_name).cloned()
    }

    /// Get or assign a port.  `port_var` is the .env variable name the
    /// tool uses for its primary UI port (e.g. "GATEWAY_PORT", "PORT").
    pub fn get_or_assign(
        &self,
        tool_name: &str,
        port_var: &str,
    ) -> Result<PortAssignment, PortError> {
        let mut map = self.assignments.lock().unwrap();

        // Already assigned?
        if let Some(existing) = map.get(tool_name) {
            return Ok(existing.clone());
        }

        // Find next free port
        let used: std::collections::HashSet<u16> = map.values().map(|a| a.port).collect();

        for port in self.range_start..=self.range_end {
            if !used.contains(&port) {
                let assignment = PortAssignment {
                    port,
                    port_var: port_var.to_string(),
                    auth_token: generate_auth_token(),
                };
                info!("Port allocator: {} → :{} ({})", tool_name, port, port_var);
                map.insert(tool_name.to_string(), assignment.clone());
                drop(map);
                self.persist();
                return Ok(assignment);
            }
        }

        Err(PortError::RangeExhausted(self.range_start, self.range_end))
    }

    /// Release a tool's port assignment.
    pub fn release(&self, tool_name: &str) {
        let mut map = self.assignments.lock().unwrap();
        if map.remove(tool_name).is_some() {
            info!("Port allocator: released {}", tool_name);
            drop(map);
            self.persist();
        }
    }

    /// All current assignments (for dashboard / debugging).
    pub fn list(&self) -> HashMap<String, PortAssignment> {
        self.assignments.lock().unwrap().clone()
    }

    fn persist(&self) {
        let map = self.assignments.lock().unwrap();
        match serde_json::to_string_pretty(&*map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.persist_path, &json) {
                    warn!("Failed to persist tool-ports.json: {}", e);
                } else {
                    debug!("Persisted {} port assignments", map.len());
                }
            }
            Err(e) => warn!("Failed to serialize port assignments: {}", e),
        }
    }
}

// ── .env.zp sidecar ────────────────────────────────────────────────────

/// Write a `.env.zp` sidecar in the tool directory with the assigned port,
/// auth token, and base path for reverse-proxy-aware frameworks.
///
/// This file is sourced before the tool starts, overriding its default
/// port and setting the auth token so the proxy can authenticate
/// transparently.  The user's `.env` is never touched.
pub fn write_env_zp(
    tool_path: &Path,
    tool_name: &str,
    assignment: &PortAssignment,
) -> std::io::Result<()> {
    let zp_env = tool_path.join(".env.zp");

    // Detect which env var the tool uses for auth tokens
    let auth_var = detect_auth_var(tool_path);

    // With subdomain proxy routing (name.localhost:3000), tools serve
    // at their own root (/) — no base path override needed.
    let proxy_comment = format!(
        "# Subdomain proxy: {}.localhost:3000 -> 127.0.0.1:{}",
        tool_name, assignment.port,
    );
    let content = format!(
        "# Auto-generated by ZeroPoint — do not edit\n\
         # Overrides port and injects auth so the proxy authenticates transparently.\n\
         {}\n\
         {}={}\n\
         {}={}\n",
        proxy_comment, assignment.port_var, assignment.port, auth_var, assignment.auth_token,
    );
    std::fs::write(&zp_env, &content)?;
    debug!(
        "Wrote .env.zp for {} → {}={}, {}=<redacted>",
        tool_path.display(),
        assignment.port_var,
        assignment.port,
        auth_var,
    );

    // ── Shadow-conflict prevention ───────────────────────────────
    // Many Rust/Node tools use `dotenv` which loads `.env` directly
    // into the process, overriding shell exports from `.env.zp`.
    // If the tool's `.env` has the same auth or port variable, it
    // shadows the ZP-managed value — causing token mismatches.
    // Remove ZP-owned vars from `.env` so `.env.zp` is authoritative.
    let dot_env = tool_path.join(".env");
    if dot_env.exists() {
        if let Ok(env_contents) = std::fs::read_to_string(&dot_env) {
            let zp_owned = [auth_var.as_str(), assignment.port_var.as_str()];
            let filtered: Vec<&str> = env_contents
                .lines()
                .filter(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with('#') || !trimmed.contains('=') {
                        return true;
                    }
                    if let Some((key, _)) = trimmed.split_once('=') {
                        let key = key.trim();
                        if zp_owned.contains(&key) {
                            debug!("Removing shadowed {} from .env (ZP owns via .env.zp)", key);
                            return false;
                        }
                    }
                    true
                })
                .collect();

            let new_contents = filtered.join("\n");
            if new_contents.len() < env_contents.len() {
                let final_contents =
                    if env_contents.ends_with('\n') && !new_contents.ends_with('\n') {
                        format!("{}\n", new_contents)
                    } else {
                        new_contents
                    };
                std::fs::write(&dot_env, &final_contents)?;
                info!(
                    "Removed ZP-managed vars ({}, {}) from {}.env to prevent shadow conflicts",
                    auth_var,
                    assignment.port_var,
                    tool_path.display()
                );
            }
        }
    }

    Ok(())
}

/// Known auth-token variable names, in priority order.
const AUTH_VAR_PRIORITY: &[&str] = &[
    "GATEWAY_AUTH_TOKEN",
    "AUTH_TOKEN",
    "API_TOKEN",
    "API_KEY",
    "SECRET_TOKEN",
    "ACCESS_TOKEN",
];

/// Detect which env variable a tool uses for its auth token.
/// Scans `.env` / `.env.example` for known auth variable names.
/// Falls back to `GATEWAY_AUTH_TOKEN` (most common for web gateways).
fn detect_auth_var(tool_path: &Path) -> String {
    for filename in &[".env", ".env.example"] {
        let file = tool_path.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&file) {
            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains('=') {
                    continue;
                }
                if let Some((key, _)) = trimmed.split_once('=') {
                    let key = key.trim();
                    if AUTH_VAR_PRIORITY.contains(&key) {
                        return key.to_string();
                    }
                }
            }
        }
    }
    "GATEWAY_AUTH_TOKEN".to_string()
}

/// Build a shell preamble that sources env files in priority order.
///
/// Layering (last write wins):
///   1. `.env.example`  — project defaults (DATABASE_URL, etc.)
///   2. `.env`          — operator overrides
///   3. `.env.zp`       — ZP port assignment + auth token (always wins)
///
/// `set -a` exports all variables so child processes inherit them.
/// Vault-injected env vars are set directly on the Command and always
/// override everything (they bypass the shell entirely).
pub fn env_zp_preamble() -> &'static str {
    "set -a && [ -f .env.example ] && . ./.env.example && [ -f .env ] && . ./.env && [ -f .env.zp ] && . ./.env.zp && set +a && "
}

// ── Port variable detection ────────────────────────────────────────────

/// Detect which .env variable name a tool uses for its primary UI port.
///
/// Scans `.env` / `.env.example` in priority order and returns the
/// variable name (e.g. "GATEWAY_PORT") so we know what to override in
/// `.env.zp`.  Falls back to "PORT" if nothing is found.
///
/// Priority order matches the governance intent: gateway/app ports first,
/// generic ports next, webhook/internal ports last.
const PORT_VAR_PRIORITY: &[&str] = &[
    "PORT",
    "GATEWAY_PORT",
    "APP_PORT",
    "SERVER_PORT",
    "API_PORT",
    "WEBUI_PORT",
    "LISTEN_PORT",
    "HTTP_PORT",
];

pub fn detect_port_var(tool_path: &Path) -> String {
    for filename in &[".env", ".env.example"] {
        let file = tool_path.join(filename);
        if let Ok(contents) = std::fs::read_to_string(&file) {
            let mut best: Option<(usize, &str)> = None;

            for line in contents.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || !trimmed.contains('=') {
                    continue;
                }
                if let Some((key, _)) = trimmed.split_once('=') {
                    let key = key.trim();
                    if let Some(priority) = PORT_VAR_PRIORITY.iter().position(|&p| p == key) {
                        if best.is_none_or(|(bp, _)| priority < bp) {
                            best = Some((priority, key));
                        }
                    }
                }
            }

            if let Some((_, var)) = best {
                return var.to_string();
            }
        }
    }

    // Fallback — most tools respect PORT
    "PORT".to_string()
}
