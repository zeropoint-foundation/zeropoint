//! Tool Port Allocator — deterministic port assignment for governed tools.
//!
//! ZeroPoint assigns each registered tool a port from a reserved range
//! (default 9100–9199) so tools that share default ports (8080, etc.)
//! don't collide.  Assignments are persisted to `{data_dir}/tool-ports.json`
//! and remain stable across restarts.
//!
//! The allocator is used at two points:
//!   1. **Launch**: Before spawning a tool, ZP writes `.env.zp` with the
//!      assigned port.  The launch command sources this file so the tool
//!      binds to the ZP-managed port instead of its default.
//!   2. **Proxy**: The subdomain proxy at `{name}.localhost:17770` forwards to
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
    /// Additional port vars the tool declares (e.g. GATEWAY_PORT alongside
    /// HTTP_PORT).  Each gets its own ZP-assigned port so nothing collides.
    #[serde(default)]
    pub extra_ports: HashMap<String, u16>,
    /// Discovered proxy port — the port that actually serves a web UI.
    ///
    /// After launch, ZP probes all assigned ports (primary + extras) with
    /// a GET / request.  The first port that responds with HTTP 200 is
    /// stored here.  The subdomain proxy uses this port instead of
    /// `port`, so multi-port tools (webhook + gateway, API + dashboard)
    /// route correctly without any tool-side configuration.
    ///
    /// `None` means probing hasn't run yet or no port responded — the
    /// proxy falls back to `port`.
    #[serde(default)]
    pub proxy_port: Option<u16>,
}

impl PortAssignment {
    /// Return the port the subdomain proxy should forward to.
    ///
    /// Prefers the discovered `proxy_port` (from post-launch probing),
    /// falling back to the statically-assigned primary `port`.
    pub fn proxy_target(&self) -> u16 {
        self.proxy_port.unwrap_or(self.port)
    }
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
        self.get_or_assign_multi(tool_name, port_var, &[])
    }

    /// Get or assign ports for a tool.  `primary_var` is the main port
    /// (used by the subdomain proxy).  `extra_vars` are additional port
    /// variables the tool declares — each gets its own ZP-assigned port.
    pub fn get_or_assign_multi(
        &self,
        tool_name: &str,
        primary_var: &str,
        extra_vars: &[String],
    ) -> Result<PortAssignment, PortError> {
        let mut map = self.assignments.lock().unwrap();

        // Already assigned?  Reconcile extra_ports if new vars appeared.
        if let Some(existing) = map.get(tool_name) {
            let mut updated = existing.clone();
            let mut changed = false;
            let all_used: std::collections::HashSet<u16> =
                map.values().flat_map(|a| {
                    std::iter::once(a.port).chain(a.extra_ports.values().copied())
                }).collect();
            let mut next_port = self.range_start;
            for var in extra_vars {
                if !updated.extra_ports.contains_key(var.as_str()) {
                    // Allocate a new port for this var
                    while next_port <= self.range_end && all_used.contains(&next_port) {
                        next_port += 1;
                    }
                    if next_port > self.range_end {
                        return Err(PortError::RangeExhausted(self.range_start, self.range_end));
                    }
                    info!("Port allocator: {} → :{} ({}, extra)", tool_name, next_port, var);
                    updated.extra_ports.insert(var.clone(), next_port);
                    next_port += 1;
                    changed = true;
                }
            }
            if changed {
                map.insert(tool_name.to_string(), updated.clone());
                drop(map);
                self.persist();
            }
            return Ok(updated);
        }

        // Find next free port for primary
        let all_used: std::collections::HashSet<u16> =
            map.values().flat_map(|a| {
                std::iter::once(a.port).chain(a.extra_ports.values().copied())
            }).collect();

        let mut next_free = self.range_start;
        while next_free <= self.range_end && all_used.contains(&next_free) {
            next_free += 1;
        }
        if next_free > self.range_end {
            return Err(PortError::RangeExhausted(self.range_start, self.range_end));
        }
        let primary_port = next_free;
        next_free += 1;

        // Allocate extra ports
        let mut extra_ports = HashMap::new();
        for var in extra_vars {
            while next_free <= self.range_end
                && (all_used.contains(&next_free) || next_free == primary_port)
            {
                next_free += 1;
            }
            if next_free > self.range_end {
                return Err(PortError::RangeExhausted(self.range_start, self.range_end));
            }
            info!("Port allocator: {} → :{} ({}, extra)", tool_name, next_free, var);
            extra_ports.insert(var.clone(), next_free);
            next_free += 1;
        }

        let assignment = PortAssignment {
            port: primary_port,
            port_var: primary_var.to_string(),
            auth_token: generate_auth_token(),
            extra_ports,
            proxy_port: None,
        };
        info!("Port allocator: {} → :{} ({})", tool_name, primary_port, primary_var);
        map.insert(tool_name.to_string(), assignment.clone());
        drop(map);
        self.persist();
        Ok(assignment)
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

    /// Update the discovered proxy port for a tool and persist.
    ///
    /// Called after post-launch probing identifies which port serves
    /// the web UI.
    pub fn set_proxy_port(&self, tool_name: &str, proxy_port: u16) {
        let mut map = self.assignments.lock().unwrap();
        if let Some(assignment) = map.get_mut(tool_name) {
            if assignment.proxy_port != Some(proxy_port) {
                info!(
                    "Port allocator: {} proxy_port discovered → :{}",
                    tool_name, proxy_port
                );
                assignment.proxy_port = Some(proxy_port);
                drop(map);
                self.persist();
            }
        }
    }

    /// Clear a previously discovered proxy port so re-discovery can run
    /// fresh after a tool relaunch (prevents stale routing).
    pub fn clear_proxy_port(&self, tool_name: &str) {
        let mut map = self.assignments.lock().unwrap();
        if let Some(assignment) = map.get_mut(tool_name) {
            if assignment.proxy_port.is_some() {
                debug!(
                    "Port allocator: {} proxy_port cleared for re-discovery",
                    tool_name
                );
                assignment.proxy_port = None;
                drop(map);
                self.persist();
            }
        }
    }
}

// ── Post-launch proxy port discovery ──────────────────────────────────

/// Probe all assigned ports for a tool and return the first one that
/// responds to `GET /` with HTTP 200.
///
/// This discovers which port actually serves a web UI, so the subdomain
/// proxy routes to the right place regardless of how the tool names its
/// port variables.  Probes are sent with a short timeout and the tool's
/// auth token, mirroring what the proxy itself would send.
///
/// Returns `None` if no port responds within the deadline.
pub async fn discover_proxy_port(assignment: &PortAssignment) -> Option<u16> {
    let mut candidates: Vec<u16> = vec![assignment.port];
    // Add extra ports — these might be the actual web UI
    candidates.extend(assignment.extra_ports.values());

    // Single-port tools don't need probing — the only port is the proxy target.
    if candidates.len() <= 1 {
        return None;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    // Two-pass probe: first look for HTML (definitive web UI signal),
    // then fall back to any 200 response.  This handles tools where
    // both ports return 200 — an API returns application/json while
    // a web UI returns text/html.
    let mut first_200: Option<u16> = None;

    for &port in &candidates {
        let url = format!("http://127.0.0.1:{}/", port);
        let result = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", assignment.auth_token))
            .send()
            .await;
        match result {
            Ok(resp) if resp.status().as_u16() == 200 => {
                let content_type = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();

                if content_type.contains("text/html") {
                    debug!("Proxy port probe: :{} → 200 text/html (selected)", port);
                    return Some(port);
                }

                debug!(
                    "Proxy port probe: :{} → 200 {} (candidate, not html)",
                    port, content_type
                );
                if first_200.is_none() {
                    first_200 = Some(port);
                }
            }
            Ok(resp) => {
                debug!(
                    "Proxy port probe: :{} → {} (skipped)",
                    port,
                    resp.status().as_u16()
                );
            }
            Err(e) => {
                debug!("Proxy port probe: :{} → error: {} (skipped)", port, e);
            }
        }
    }

    // No HTML port found — fall back to first 200, or None.
    if let Some(port) = first_200 {
        debug!(
            "Proxy port probe: no text/html port, using first 200 → :{}",
            port
        );
    } else {
        warn!("Proxy port probe: no port returned 200, falling back to primary");
    }
    first_200
}

/// Probe ports with retries, waiting for the tool to finish starting.
///
/// Tools need time to bind their ports after launch.  This retries the
/// probe up to `max_attempts` times with `interval` between attempts.
/// Used by the launch flow to discover the proxy port asynchronously
/// without blocking the launch response.
pub async fn discover_proxy_port_with_retry(
    assignment: &PortAssignment,
    max_attempts: u32,
    interval: std::time::Duration,
) -> Option<u16> {
    for attempt in 1..=max_attempts {
        if let Some(port) = discover_proxy_port(assignment).await {
            return Some(port);
        }
        if attempt < max_attempts {
            debug!(
                "Proxy port probe attempt {}/{} — retrying in {:?}",
                attempt, max_attempts, interval
            );
            tokio::time::sleep(interval).await;
        }
    }
    None
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

    // With subdomain proxy routing (name.localhost:17770), tools serve
    // at their own root (/) — no base path override needed.
    let proxy_comment = format!(
        "# Subdomain proxy: {}.localhost:17770 -> 127.0.0.1:{}",
        tool_name, assignment.port,
    );
    let mut content = format!(
        "# Auto-generated by ZeroPoint — do not edit\n\
         # Overrides port(s) and injects auth so the proxy authenticates transparently.\n\
         {}\n\
         {}={}\n",
        proxy_comment, assignment.port_var, assignment.port,
    );
    // Write extra port assignments
    for (var, port) in &assignment.extra_ports {
        content.push_str(&format!("{}={}\n", var, port));
    }
    content.push_str(&format!("{}={}\n", auth_var, assignment.auth_token));
    // Signal to the tool that ZP is managing it
    content.push_str("ZP_MANAGED=1\n");

    std::fs::write(&zp_env, &content)?;
    debug!(
        "Wrote .env.zp for {} → {}={}{}, {}=<redacted>",
        tool_path.display(),
        assignment.port_var,
        assignment.port,
        if assignment.extra_ports.is_empty() {
            String::new()
        } else {
            format!(" +{} extra", assignment.extra_ports.len())
        },
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
            let mut zp_owned: Vec<&str> = vec![auth_var.as_str(), assignment.port_var.as_str(), "ZP_MANAGED"];
            for var in assignment.extra_ports.keys() {
                zp_owned.push(var.as_str());
            }
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
                    "Removed ZP-managed vars ({}) from {}.env to prevent shadow conflicts",
                    zp_owned.join(", "),
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
/// Each file is optional — a missing `.env` must not prevent `.env.zp`
/// from being sourced. We use semicolons between file blocks so each
/// `[ -f X ] && . ./X` is an independent statement whose exit code
/// doesn't short-circuit the rest of the preamble.
///
/// `set -a` exports all variables so child processes inherit them.
/// Vault-injected env vars are set directly on the Command and always
/// override everything (they bypass the shell entirely).
pub fn env_zp_preamble() -> &'static str {
    "set -a; [ -f .env.example ] && . ./.env.example; [ -f .env ] && . ./.env; [ -f .env.zp ] && . ./.env.zp; set +a && "
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
    "HTTP_PORT",
    "WEBUI_PORT",
    "APP_PORT",
    "SERVER_PORT",
    "LISTEN_PORT",
    "API_PORT",
    "GATEWAY_PORT",
];

pub fn detect_port_var(tool_path: &Path) -> String {
    let all = detect_all_port_vars(tool_path);
    all.into_iter().next().unwrap_or_else(|| "PORT".to_string())
}

/// Detect ALL port variable names a tool declares, ordered by priority.
///
/// Returns a vec where the first element is the primary (proxy) port var
/// and the rest are secondary ports that also need ZP-assigned values.
pub fn detect_all_port_vars(tool_path: &Path) -> Vec<String> {
    let mut found: Vec<(usize, String)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

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
                    if let Some(priority) = PORT_VAR_PRIORITY.iter().position(|&p| p == key) {
                        if seen.insert(key.to_string()) {
                            found.push((priority, key.to_string()));
                        }
                    }
                }
            }
        }
    }

    found.sort_by_key(|(p, _)| *p);
    found.into_iter().map(|(_, v)| v).collect()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preamble_uses_semicolons_not_and_chains() {
        let preamble = env_zp_preamble();
        // Each file block should be separated by semicolons so missing
        // files don't short-circuit the chain.
        assert!(
            preamble.contains("; [ -f .env ] && . ./.env;"),
            "Preamble should use semicolons between file blocks, got: {}",
            preamble,
        );
        // .env.zp must always be sourced last (highest priority)
        assert!(
            preamble.contains("; [ -f .env.zp ] && . ./.env.zp;"),
            "Preamble should source .env.zp with semicolons, got: {}",
            preamble,
        );
        // Must NOT contain the fragile `&& [ -f .env ]` pattern
        assert!(
            !preamble.contains("&& [ -f .env ]"),
            "Preamble must not chain file tests with &&, got: {}",
            preamble,
        );
    }

    #[test]
    fn proxy_target_prefers_proxy_port() {
        let assignment = PortAssignment {
            port: 9100,
            port_var: "HTTP_PORT".to_string(),
            auth_token: "zp-test".to_string(),
            extra_ports: HashMap::from([("GATEWAY_PORT".to_string(), 9101)]),
            proxy_port: Some(9101),
        };
        assert_eq!(assignment.proxy_target(), 9101);
    }

    #[test]
    fn proxy_target_falls_back_to_primary() {
        let assignment = PortAssignment {
            port: 9100,
            port_var: "HTTP_PORT".to_string(),
            auth_token: "zp-test".to_string(),
            extra_ports: HashMap::new(),
            proxy_port: None,
        };
        assert_eq!(assignment.proxy_target(), 9100);
    }

    #[test]
    fn proxy_port_serde_default_is_none() {
        // Existing persisted assignments (pre-proxy_port) should
        // deserialize with proxy_port: None thanks to #[serde(default)].
        let json = r#"{
            "port": 9100,
            "port_var": "HTTP_PORT",
            "auth_token": "zp-test",
            "extra_ports": {}
        }"#;
        let assignment: PortAssignment = serde_json::from_str(json).unwrap();
        assert_eq!(assignment.proxy_port, None);
        assert_eq!(assignment.proxy_target(), 9100);
    }

    #[test]
    fn proxy_port_serde_round_trip() {
        let assignment = PortAssignment {
            port: 9100,
            port_var: "HTTP_PORT".to_string(),
            auth_token: "zp-test".to_string(),
            extra_ports: HashMap::from([("GATEWAY_PORT".to_string(), 9101)]),
            proxy_port: Some(9101),
        };
        let json = serde_json::to_string(&assignment).unwrap();
        let deserialized: PortAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.proxy_port, Some(9101));
        assert_eq!(deserialized.proxy_target(), 9101);
    }

    #[test]
    fn detect_port_vars_from_env_example() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env.example"),
            "HTTP_PORT=8080\nGATEWAY_PORT=3000\n",
        )
        .unwrap();

        let vars = detect_all_port_vars(dir.path());
        assert_eq!(vars, vec!["HTTP_PORT", "GATEWAY_PORT"]);

        // Primary is first in priority order
        let primary = detect_port_var(dir.path());
        assert_eq!(primary, "HTTP_PORT");
    }

    #[tokio::test]
    async fn discover_skips_single_port_tools() {
        // Single-port tools shouldn't waste time probing
        let assignment = PortAssignment {
            port: 9100,
            port_var: "PORT".to_string(),
            auth_token: "zp-test".to_string(),
            extra_ports: HashMap::new(),
            proxy_port: None,
        };
        let result = discover_proxy_port(&assignment).await;
        assert_eq!(result, None);
    }
}
