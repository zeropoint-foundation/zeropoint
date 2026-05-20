//! Tool Port Registry — deterministic port assignment for governed tools.
//!
//! ZeroPoint assigns each registered tool a port from a reserved range
//! (default 9100–9199) so tools that share default ports (8080, etc.)
//! don't collide.  Assignments are persisted to `{data_dir}/tool-ports.json`
//! and remain stable across restarts.
//!
//! The registry is used at two points:
//!   1. **Launch**: Before spawning a tool, ZP writes `.env.zp` with the
//!      assigned port.  The launch command sources this file so the tool
//!      binds to the ZP-managed port instead of its default.
//!   2. **Proxy**: The subdomain proxy at `{name}.localhost:17770` forwards to
//!      `127.0.0.1:{assigned_port}`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};
use zp_audit::chain::UnsealedEntry;
use zp_core::{ActorId, AuditAction, ConversationId, PolicyDecision};
use zp_receipt::{ReceiptBuilder, ReceiptType, Status, TrustGrade};

// ── Range ───────────────────────────────────────────────────────────────

const DEFAULT_RANGE_START: u16 = 9100;
const DEFAULT_RANGE_END: u16 = 9199;

// ── Error ───────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("All ports in range {0}–{1} are allocated")]
    RangeExhausted(u16, u16),

    #[error("Port {port} is already owned by '{owner}'")]
    Conflict { port: u16, owner: String },

    #[error("Tool '{0}' has no port assignment")]
    NotAssigned(String),

    #[error("Chain append failed: {0}")]
    ChainAppend(String),
}

// Backward compat alias
pub use RegistryError as PortError;

// ── PreferenceSource ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceSource {
    Manifest,
    Env,
    #[default]
    Default,
    /// Actual port observed via lsof after launch; overrides allocation intent.
    PostLaunchObservation,
}

// ── ReleaseReason ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseReason {
    GracefulExit,
    PidDead,
    OperatorKill,
    Reconciliation,
}

// ── ToolBinding (replaces PortAssignment) ───────────────────────────────

/// A tool's full port binding record.
///
/// `PortAssignment` is kept as a type alias for backward compat with any
/// existing callers that still use the old name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolBinding {
    pub tool: String,
    /// Allocated port preference (ZP-managed, stable across restarts).
    pub port: u16,
    /// The .env variable name this tool uses for its primary UI port.
    pub port_var: String,
    /// ZP-generated auth token injected into `.env.zp` and the proxy.
    #[serde(default = "generate_auth_token")]
    pub auth_token: String,
    /// Allocated extra port vars (stable across restarts).
    #[serde(default)]
    pub extra_ports: HashMap<String, u16>,
    /// Discovered proxy port after post-launch probing.
    #[serde(default)]
    pub proxy_port: Option<u16>,
    /// Actual port the tool bound after launch (may differ from `port` if the
    /// tool ignored the env var). Cleared on binding-clear event.
    #[serde(default)]
    pub actual_port: Option<u16>,
    /// Actual extra ports the tool bound (post-reconciliation, per port_var).
    #[serde(default)]
    pub actual_extra_ports: HashMap<String, u16>,
    /// OS PID of the running tool process (None if not tracked).
    #[serde(default)]
    pub pid: Option<u32>,
    /// Receipt ID emitted when this binding was created.
    #[serde(default)]
    pub allocated_receipt_id: String,
    /// Where the port preference originated.
    #[serde(default)]
    pub preference_source: PreferenceSource,
}

// Backward compat alias
pub type PortAssignment = ToolBinding;

impl ToolBinding {
    /// Return the port the subdomain proxy should forward to.
    ///
    /// Priority: `proxy_port` (HTTP probe) → `actual_port` (lsof reconcile) → `port` (allocated).
    pub fn proxy_target(&self) -> u16 {
        self.proxy_port
            .or(self.actual_port)
            .unwrap_or(self.port)
    }
}

/// Generate a cryptographically random auth token.
fn generate_auth_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    format!("zp-{}", hex::encode(bytes))
}

// ── PortRegistry ────────────────────────────────────────────────────────

pub struct PortRegistry {
    range_start: u16,
    range_end: u16,
    bindings: Mutex<HashMap<String, ToolBinding>>,
    persist_path: PathBuf,
    audit_store: Option<Arc<std::sync::Mutex<zp_audit::AuditStore>>>,
    executor_id: String,
}

// Backward compat alias — all existing `PortAllocator` references still compile.
pub type PortAllocator = PortRegistry;

impl PortRegistry {
    /// Create a new registry without chain backing (test / CLI contexts).
    pub fn new(data_dir: &Path) -> Self {
        Self::new_with_audit(data_dir, None, String::new())
    }

    /// Create a registry wired into the audit chain.
    pub fn new_with_audit(
        data_dir: &Path,
        audit_store: Option<Arc<std::sync::Mutex<zp_audit::AuditStore>>>,
        executor_id: String,
    ) -> Self {
        let persist_path = data_dir.join("tool-ports.json");

        // Load persisted bindings — try new ToolBinding format first,
        // fall back to old PortAssignment JSON (migration path).
        let bindings: HashMap<String, ToolBinding> = if persist_path.exists() {
            match std::fs::read_to_string(&persist_path) {
                Ok(data) => {
                    // Try new format (has "tool" field)
                    if let Ok(map) = serde_json::from_str::<HashMap<String, ToolBinding>>(&data) {
                        map
                    } else {
                        // Fall back to old PortAssignment — migrate in place
                        serde_json::from_str::<HashMap<String, serde_json::Value>>(&data)
                            .unwrap_or_default()
                            .into_iter()
                            .filter_map(|(tool_name, v)| {
                                let port = v.get("port")?.as_u64()? as u16;
                                let port_var = v
                                    .get("port_var")?
                                    .as_str()?
                                    .to_string();
                                let auth_token = v
                                    .get("auth_token")
                                    .and_then(|t| t.as_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(generate_auth_token);
                                let extra_ports: HashMap<String, u16> = v
                                    .get("extra_ports")
                                    .and_then(|e| serde_json::from_value(e.clone()).ok())
                                    .unwrap_or_default();
                                let proxy_port = v
                                    .get("proxy_port")
                                    .and_then(|p| p.as_u64())
                                    .map(|p| p as u16);
                                Some((
                                    tool_name.clone(),
                                    ToolBinding {
                                        tool: tool_name,
                                        port,
                                        port_var,
                                        auth_token,
                                        extra_ports,
                                        proxy_port,
                                        actual_port: None,
                                        actual_extra_ports: HashMap::new(),
                                        pid: None,
                                        allocated_receipt_id: "legacy".to_string(),
                                        preference_source: PreferenceSource::Default,
                                    },
                                ))
                            })
                            .collect()
                    }
                }
                Err(e) => {
                    warn!("Could not read tool-ports.json: {}", e);
                    HashMap::new()
                }
            }
        } else {
            HashMap::new()
        };

        info!(
            "Port registry: {} existing bindings, range {}–{}",
            bindings.len(),
            DEFAULT_RANGE_START,
            DEFAULT_RANGE_END,
        );

        let registry = Self {
            range_start: DEFAULT_RANGE_START,
            range_end: DEFAULT_RANGE_END,
            bindings: Mutex::new(bindings),
            persist_path,
            audit_store,
            executor_id,
        };

        // Re-persist to flush any migrated entries.
        registry.persist();
        registry
    }

    // ── Allocation ────────────────────────────────────────────────────

    /// Allocate a port for `tool`, or return the existing binding.
    ///
    /// Primary API for all new callers. `pid` tracks the process for
    /// liveness sweeping. `preferred` requests a specific port (conflict
    /// returns `RegistryError::Conflict`).
    pub fn allocate_or_existing(
        &self,
        tool: &str,
        pid: u32,
        primary_var: &str,
        extra_vars: &[String],
        preferred: Option<u16>,
        preference_source: PreferenceSource,
    ) -> Result<ToolBinding, RegistryError> {
        let mut map = self.bindings.lock().unwrap();

        // Already assigned — reconcile extra_ports / update pid.
        if let Some(existing) = map.get(tool) {
            let mut updated = existing.clone();
            let pid_changed = updated.pid != Some(pid);
            updated.pid = Some(pid);
            let mut changed = pid_changed;

            let all_used: std::collections::HashSet<u16> = map
                .values()
                .flat_map(|b| {
                    std::iter::once(b.port).chain(b.extra_ports.values().copied())
                })
                .collect();
            let mut next_port = self.range_start;
            for var in extra_vars {
                if !updated.extra_ports.contains_key(var.as_str()) {
                    while next_port <= self.range_end && all_used.contains(&next_port) {
                        next_port += 1;
                    }
                    if next_port > self.range_end {
                        return Err(RegistryError::RangeExhausted(
                            self.range_start,
                            self.range_end,
                        ));
                    }
                    updated.extra_ports.insert(var.clone(), next_port);
                    next_port += 1;
                    changed = true;
                }
            }
            if changed {
                map.insert(tool.to_string(), updated.clone());
                drop(map);
                self.persist();
            }
            return Ok(updated);
        }

        // Conflict check for preferred port.
        if let Some(pref) = preferred {
            if let Some(owner) = map.values().find(|b| {
                b.port == pref || b.extra_ports.values().any(|&p| p == pref)
            }) {
                return Err(RegistryError::Conflict {
                    port: pref,
                    owner: owner.tool.clone(),
                });
            }
        }

        // Find primary port.
        let all_used: std::collections::HashSet<u16> = map
            .values()
            .flat_map(|b| std::iter::once(b.port).chain(b.extra_ports.values().copied()))
            .collect();

        let primary_port = if let Some(pref) = preferred {
            pref
        } else {
            let mut next = self.range_start;
            while next <= self.range_end && all_used.contains(&next) {
                next += 1;
            }
            if next > self.range_end {
                return Err(RegistryError::RangeExhausted(
                    self.range_start,
                    self.range_end,
                ));
            }
            next
        };

        // Extra ports.
        let mut extra_ports = HashMap::new();
        let mut next_free = primary_port + 1;
        for var in extra_vars {
            while next_free <= self.range_end
                && (all_used.contains(&next_free) || next_free == primary_port)
            {
                next_free += 1;
            }
            if next_free > self.range_end {
                return Err(RegistryError::RangeExhausted(
                    self.range_start,
                    self.range_end,
                ));
            }
            extra_ports.insert(var.clone(), next_free);
            next_free += 1;
        }

        let receipt_id = self.emit_allocate_receipt(
            tool,
            primary_port,
            primary_var,
            pid,
            &extra_ports,
            preference_source,
        );

        let binding = ToolBinding {
            tool: tool.to_string(),
            port: primary_port,
            port_var: primary_var.to_string(),
            auth_token: generate_auth_token(),
            extra_ports,
            proxy_port: None,
            actual_port: None,
            actual_extra_ports: HashMap::new(),
            pid: Some(pid),
            allocated_receipt_id: receipt_id,
            preference_source,
        };
        info!("Port registry: {} → :{} ({})", tool, primary_port, primary_var);
        map.insert(tool.to_string(), binding.clone());
        drop(map);
        self.persist();
        Ok(binding)
    }

    /// Backward-compat wrapper — no pid, no preferred port.
    pub fn get_or_assign_multi(
        &self,
        tool_name: &str,
        primary_var: &str,
        extra_vars: &[String],
    ) -> Result<ToolBinding, RegistryError> {
        self.allocate_or_existing(
            tool_name,
            0,
            primary_var,
            extra_vars,
            None,
            PreferenceSource::Default,
        )
    }

    /// Backward-compat single-port wrapper.
    pub fn get_or_assign(
        &self,
        tool_name: &str,
        port_var: &str,
    ) -> Result<ToolBinding, RegistryError> {
        self.get_or_assign_multi(tool_name, port_var, &[])
    }

    // ── Release / clear binding / deallocate ──────────────────────────

    /// Clear the runtime binding (PID, actual ports) while preserving the allocation.
    ///
    /// This is the correct action on process death (kill, crash, sweeper).
    /// The operator's port preferences (allocated port, auth_token, port_var,
    /// extra_ports) survive so the next launch inherits the same configuration.
    ///
    /// Emits `PortReleased` with `event_type = "binding_cleared"`.
    pub fn clear_binding(&self, tool: &str, reason: ReleaseReason) {
        let mut map = self.bindings.lock().unwrap();
        if let Some(binding) = map.get_mut(tool) {
            let port = binding.port;
            let pid = binding.pid;
            binding.pid = None;
            binding.actual_port = None;
            binding.actual_extra_ports.clear();
            info!(
                "Port registry: cleared binding for {} (port {}, reason: {:?})",
                tool, port, reason
            );
            drop(map);
            self.emit_release_receipt(tool, port, pid, reason, "binding_cleared");
            self.persist();
        }
    }

    /// Backward-compat wrapper — routes to `clear_binding`.
    ///
    /// All existing call sites (sweeper, restart) get correct binding-clear
    /// semantics without requiring immediate call-site changes.
    pub fn release(&self, tool: &str, reason: ReleaseReason) {
        self.clear_binding(tool, reason);
    }

    /// Fully remove a tool's allocation from the registry.
    ///
    /// Unlike `clear_binding`, this removes the entire entry — port, auth_token,
    /// extra_ports, and all.  Use only for explicit deallocation (future
    /// `zp port deallocate <tool>` verb). Do not call on process death.
    ///
    /// Emits `PortReleased` with `event_type = "allocation_removed"`.
    pub fn deallocate(&self, tool: &str) {
        let mut map = self.bindings.lock().unwrap();
        if let Some(binding) = map.remove(tool) {
            info!(
                "Port registry: deallocated {} (port {})",
                tool, binding.port
            );
            drop(map);
            self.emit_release_receipt(
                tool,
                binding.port,
                binding.pid,
                ReleaseReason::OperatorKill,
                "allocation_removed",
            );
            self.persist();
        }
    }

    // ── Query ─────────────────────────────────────────────────────────

    /// Get the binding for a specific tool, if present.
    pub fn get_assigned(&self, tool_name: &str) -> Option<ToolBinding> {
        self.bindings.lock().unwrap().get(tool_name).cloned()
    }

    /// Return the binding that owns `port` (primary or extra), if any.
    pub fn owner(&self, port: u16) -> Option<ToolBinding> {
        self.bindings
            .lock()
            .unwrap()
            .values()
            .find(|b| b.port == port || b.extra_ports.values().any(|&p| p == port))
            .cloned()
    }

    /// All current bindings as a Vec (primary API for dashboards / CLI).
    pub fn list(&self) -> Vec<ToolBinding> {
        self.bindings.lock().unwrap().values().cloned().collect()
    }

    /// All current bindings as a HashMap (legacy API for tool_proxy.rs).
    pub fn list_map(&self) -> HashMap<String, ToolBinding> {
        self.bindings.lock().unwrap().clone()
    }

    // ── Proxy port management ─────────────────────────────────────────

    /// Update the discovered proxy port for a tool and persist.
    pub fn set_proxy_port(&self, tool_name: &str, proxy_port: u16) {
        let mut map = self.bindings.lock().unwrap();
        if let Some(binding) = map.get_mut(tool_name) {
            if binding.proxy_port != Some(proxy_port) {
                info!(
                    "Port registry: {} proxy_port discovered → :{}",
                    tool_name, proxy_port
                );
                binding.proxy_port = Some(proxy_port);
                drop(map);
                self.persist();
            }
        }
    }

    /// Clear a previously discovered proxy port for re-discovery after relaunch.
    pub fn clear_proxy_port(&self, tool_name: &str) {
        let mut map = self.bindings.lock().unwrap();
        if let Some(binding) = map.get_mut(tool_name) {
            if binding.proxy_port.is_some() {
                debug!(
                    "Port registry: {} proxy_port cleared for re-discovery",
                    tool_name
                );
                binding.proxy_port = None;
                drop(map);
                self.persist();
            }
        }
    }

    // ── PID liveness sweeper ──────────────────────────────────────────

    /// Release bindings for tools whose recorded PIDs are no longer alive.
    ///
    /// Called periodically by the background sweeper task. Uses POSIX
    /// `kill -0` on Unix; degrades gracefully on non-Unix (no releases).
    pub fn sweep_dead_pids(&self) {
        let snapshot: Vec<ToolBinding> = self
            .bindings
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for binding in snapshot {
            if let Some(pid) = binding.pid {
                if !is_pid_alive(pid) {
                    debug!(
                        "Port registry: pid {} for {} is dead, releasing",
                        pid, binding.tool
                    );
                    self.release(&binding.tool, ReleaseReason::PidDead);
                }
            }
        }
    }

    // ── Chain receipt helpers ─────────────────────────────────────────

    fn emit_allocate_receipt(
        &self,
        tool: &str,
        port: u16,
        port_var: &str,
        pid: u32,
        extra_ports: &HashMap<String, u16>,
        preference_source: PreferenceSource,
    ) -> String {
        let receipt = ReceiptBuilder::new(ReceiptType::PortAllocated, &self.executor_id)
            .status(Status::Success)
            .trust_grade(TrustGrade::D)
            .extension(
                "zp.port.lifecycle",
                serde_json::json!({
                    "tool": tool,
                    "port": port,
                    "port_var": port_var,
                    "pid": pid,
                    "extra_ports": extra_ports,
                    "preference_source": preference_source,
                }),
            )
            .finalize();
        let receipt_id = receipt.id.clone();
        self.append_to_chain(receipt);
        receipt_id
    }

    fn emit_release_receipt(
        &self,
        tool: &str,
        port: u16,
        pid: Option<u32>,
        reason: ReleaseReason,
        event_type: &str,
    ) {
        let receipt = ReceiptBuilder::new(ReceiptType::PortReleased, &self.executor_id)
            .status(Status::Success)
            .trust_grade(TrustGrade::D)
            .extension(
                "zp.port.lifecycle",
                serde_json::json!({
                    "tool": tool,
                    "port": port,
                    "pid": pid,
                    "reason": reason,
                    "event_type": event_type,
                }),
            )
            .finalize();
        self.append_to_chain(receipt);
    }

    fn append_to_chain(&self, receipt: zp_receipt::Receipt) {
        let Some(ref audit_arc) = self.audit_store else {
            return;
        };
        let unsealed = UnsealedEntry::new(
            ActorId::System("port_registry".to_string()),
            AuditAction::SystemEvent {
                event: format!("port:lifecycle:{}", receipt.receipt_type.id_prefix()),
            },
            ConversationId::new(),
            PolicyDecision::Allow {
                conditions: Vec::new(),
            },
            "port_registry",
        )
        .with_receipt(receipt);
        match audit_arc.lock() {
            Ok(mut store) => {
                if let Err(e) = store.append(unsealed) {
                    warn!("Port registry: failed to append receipt to chain: {}", e);
                }
            }
            Err(e) => warn!("Port registry: audit store lock poisoned: {}", e),
        }
    }

    // ── Persistence ───────────────────────────────────────────────────

    fn persist(&self) {
        let map = self.bindings.lock().unwrap();
        match serde_json::to_string_pretty(&*map) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.persist_path, &json) {
                    warn!("Failed to persist tool-ports.json: {}", e);
                } else {
                    debug!("Persisted {} port bindings", map.len());
                }
            }
            Err(e) => warn!("Failed to serialize port bindings: {}", e),
        }
    }

    // ── Wire 1: PID capture ───────────────────────────────────────────

    /// Record the OS PID of a running tool without changing its port allocation.
    ///
    /// Called from `zp configure exec` after `Command::spawn()` succeeds.
    /// Index-only update — no new receipt; the allocation receipt is unchanged.
    pub fn update_pid(&self, tool: &str, pid: u32) -> Result<(), RegistryError> {
        let mut map = self.bindings.lock().unwrap();
        match map.get_mut(tool) {
            Some(binding) => {
                binding.pid = Some(pid);
                drop(map);
                self.persist();
                Ok(())
            }
            None => Err(RegistryError::NotAssigned(tool.to_string())),
        }
    }

    // ── Wire 2: post-launch port reconciliation ───────────────────────

    /// Reconcile the registry against ports the tool actually bound.
    ///
    /// `actual_ports` comes from `lsof_tcp_listen_ports` after the tool has had
    /// time to start.  If the allocated primary port is absent from `actual_ports`,
    /// emits a `port:release` for the stale port and a `port:allocate` for the
    /// first actual port (tagged `PostLaunchObservation`), then updates the binding.
    ///
    /// Returns 0 (no mismatch or empty actuals) or 2 (release + allocate pair).
    pub fn reconcile_ports(&self, tool: &str, pid: u32, actual_ports: &[u16]) -> usize {
        if actual_ports.is_empty() {
            return 0;
        }
        let binding = match self.get_assigned(tool) {
            Some(b) => b,
            None => return 0,
        };
        let allocated_port = binding.port;
        if actual_ports.contains(&allocated_port) {
            return 0;
        }
        let actual_primary = actual_ports[0];
        debug!(
            "Port registry: reconcile '{}' allocated={} actual={}",
            tool, allocated_port, actual_primary
        );
        self.emit_release_receipt(
            tool,
            allocated_port,
            Some(pid),
            ReleaseReason::Reconciliation,
            "reconciliation",
        );
        self.emit_allocate_receipt(
            tool,
            actual_primary,
            &binding.port_var,
            pid,
            &HashMap::new(),
            PreferenceSource::PostLaunchObservation,
        );
        let mut map = self.bindings.lock().unwrap();
        if let Some(b) = map.get_mut(tool) {
            // Write actual_port — `port` (allocated preference) stays unchanged.
            b.actual_port = Some(actual_primary);
        }
        drop(map);
        self.persist();
        2
    }
}

// ── Post-launch port discovery via lsof ───────────────────────────────

/// Return the set of TCP ports a PID is currently listening on.
///
/// Runs `lsof -p <pid> -i -n -P` and parses LISTEN entries.  Best-effort:
/// returns an empty Vec on lsof errors, permission failures, or parse failures.
/// On non-Unix targets always returns empty Vec (reconciliation degrades gracefully).
pub fn lsof_tcp_listen_ports(pid: u32) -> Vec<u16> {
    #[cfg(unix)]
    {
        let output = std::process::Command::new("lsof")
            .args(["-p", &pid.to_string(), "-i", "-n", "-P"])
            .output();
        match output {
            Ok(o) if o.status.success() || !o.stdout.is_empty() => {
                parse_lsof_listen_ports(&String::from_utf8_lossy(&o.stdout))
            }
            _ => Vec::new(),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Vec::new()
    }
}

/// Parse TCP LISTEN port numbers from `lsof -i -n -P` output.
///
/// Expects lines like:
///   `ironclaw 1234 user 17u IPv4 0x... 0t0 TCP *:3000 (LISTEN)`
/// Finds the address token immediately before "(LISTEN)" and extracts the
/// port from after the last ":".
pub(crate) fn parse_lsof_listen_ports(lsof_output: &str) -> Vec<u16> {
    let mut ports: Vec<u16> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for line in lsof_output.lines() {
        if !line.contains("(LISTEN)") {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (i, tok) in tokens.iter().enumerate() {
            if *tok == "(LISTEN)" && i > 0 {
                // token before "(LISTEN)" is the address, e.g. "*:3000"
                if let Some(port_str) = tokens[i - 1].rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        if seen.insert(port) {
                            ports.push(port);
                        }
                    }
                }
            }
        }
    }
    ports
}

// ── PID liveness check ─────────────────────────────────────────────────

/// Returns true if the given PID is alive and signal-accessible.
///
/// Uses POSIX `kill -0` on Unix (no actual signal sent, just existence check).
/// Non-Unix builds always return `true` (sweeper degrades gracefully).
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
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
pub async fn discover_proxy_port(assignment: &ToolBinding) -> Option<u16> {
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
    assignment: &ToolBinding,
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
    assignment: &ToolBinding,
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
            let mut zp_owned: Vec<&str> =
                vec![auth_var.as_str(), assignment.port_var.as_str(), "ZP_MANAGED"];
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
                            debug!(
                                "Removing shadowed {} from .env (ZP owns via .env.zp)",
                                key
                            );
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
// `env_zp_preamble` was the shell-sourced preamble for the historical
// `Command::new("sh").arg("-c")` launch flow. It built a string like
// `set -a; [ -f .env.example ] && . ./.env.example; ...` that was
// prepended to the start command. Removed in Seam 9a (May 2026):
// argv-form launch parses `.env` files in Rust via
// `crate::tool_launch::load_dotenv_layered`, which has clearer
// priority semantics and no shell-injection surface. See
// `docs/STRUCTURAL-AUDIT-2026-05.md` Seam 9 for the full rationale.

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

    // `preamble_uses_semicolons_not_and_chains` removed in Seam 9a —
    // the shell preamble it tested is gone. See
    // `crate::tool_launch::tests::load_dotenv_layered_priority` for
    // the equivalent test of the new in-Rust .env layering.

    fn make_binding(port: u16) -> ToolBinding {
        ToolBinding {
            tool: "test-tool".to_string(),
            port,
            port_var: "HTTP_PORT".to_string(),
            auth_token: "zp-test".to_string(),
            extra_ports: HashMap::new(),
            proxy_port: None,
            actual_port: None,
            actual_extra_ports: HashMap::new(),
            pid: None,
            allocated_receipt_id: String::new(),
            preference_source: PreferenceSource::Default,
        }
    }

    #[test]
    fn proxy_target_prefers_proxy_port() {
        let mut b = make_binding(9100);
        b.extra_ports = HashMap::from([("GATEWAY_PORT".to_string(), 9101)]);
        b.proxy_port = Some(9101);
        assert_eq!(b.proxy_target(), 9101);
    }

    #[test]
    fn proxy_target_prefers_actual_over_allocated() {
        let mut b = make_binding(9100);
        b.actual_port = Some(3000);
        assert_eq!(b.proxy_target(), 3000, "actual_port beats allocated");
    }

    #[test]
    fn proxy_target_proxy_port_beats_actual() {
        let mut b = make_binding(9100);
        b.actual_port = Some(3000);
        b.proxy_port = Some(8080);
        assert_eq!(b.proxy_target(), 8080, "proxy_port beats actual_port");
    }

    #[test]
    fn proxy_target_falls_back_to_primary() {
        let b = make_binding(9100);
        assert_eq!(b.proxy_target(), 9100);
    }

    #[test]
    fn proxy_port_serde_default_is_none() {
        // Old PortAssignment JSON (without new fields) should deserialize
        // with defaults thanks to #[serde(default)] on the new fields.
        let json = r#"{
            "tool": "test-tool",
            "port": 9100,
            "port_var": "HTTP_PORT",
            "auth_token": "zp-test",
            "extra_ports": {}
        }"#;
        let binding: ToolBinding = serde_json::from_str(json).unwrap();
        assert_eq!(binding.proxy_port, None);
        assert_eq!(binding.proxy_target(), 9100);
    }

    #[test]
    fn proxy_port_serde_round_trip() {
        let binding = ToolBinding {
            tool: "test-tool".to_string(),
            port: 9100,
            port_var: "HTTP_PORT".to_string(),
            auth_token: "zp-test".to_string(),
            extra_ports: HashMap::from([("GATEWAY_PORT".to_string(), 9101)]),
            proxy_port: Some(9101),
            actual_port: Some(3000),
            actual_extra_ports: HashMap::from([("GATEWAY_PORT".to_string(), 8090)]),
            pid: Some(12345),
            allocated_receipt_id: "port-abc123".to_string(),
            preference_source: PreferenceSource::Manifest,
        };
        let json = serde_json::to_string(&binding).unwrap();
        let deserialized: ToolBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.proxy_port, Some(9101));
        assert_eq!(deserialized.proxy_target(), 9101, "proxy_port wins");
        assert_eq!(deserialized.actual_port, Some(3000));
        assert_eq!(deserialized.pid, Some(12345));
        assert_eq!(deserialized.preference_source, PreferenceSource::Manifest);
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
        let binding = make_binding(9100);
        let result = discover_proxy_port(&binding).await;
        assert_eq!(result, None);
    }

    // ── PortRegistry unit tests ──────────────────────────────────────

    fn make_registry() -> (PortRegistry, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let reg = PortRegistry::new(dir.path());
        // Return dir so the caller keeps it alive for the test duration.
        (reg, dir)
    }

    #[test]
    fn registry_allocate_returns_binding() {
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing(
                "tool-a",
                1000,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("allocate");
        assert_eq!(b.tool, "tool-a");
        assert_eq!(b.port_var, "PORT");
        assert!(b.port >= 9100 && b.port <= 9199);
        assert_eq!(b.pid, Some(1000));
    }

    #[test]
    fn registry_release_clears_binding_preserves_allocation() {
        let (reg, _dir) = make_registry();
        reg.allocate_or_existing(
            "tool-b",
            2000,
            "PORT",
            &[],
            None,
            PreferenceSource::Default,
        )
        .expect("allocate");
        let allocated_port = reg.get_assigned("tool-b").unwrap().port;
        reg.release("tool-b", ReleaseReason::GracefulExit);
        // Entry preserved — allocation survives process death.
        let binding = reg.get_assigned("tool-b").expect("allocation preserved");
        assert_eq!(binding.port, allocated_port, "allocated port unchanged");
        assert_eq!(binding.pid, None, "pid cleared");
        assert_eq!(binding.actual_port, None, "actual_port cleared");
    }

    #[test]
    fn registry_owner_returns_holder() {
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing(
                "tool-c",
                3000,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("allocate");
        let owner = reg.owner(b.port).expect("owner");
        assert_eq!(owner.tool, "tool-c");
    }

    #[test]
    fn registry_owner_still_finds_after_release() {
        // After clear_binding, the allocation persists — owner() still finds
        // the allocated port so conflict detection works.
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing(
                "tool-d",
                4000,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("allocate");
        let port = b.port;
        reg.release("tool-d", ReleaseReason::GracefulExit);
        // Allocation persists — allocated port is still "owned"
        assert!(reg.owner(port).is_some(), "owner still holds allocated port");
    }

    #[test]
    fn deallocate_removes_entry() {
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing(
                "tool-dealloc",
                5555,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("allocate");
        let port = b.port;
        reg.deallocate("tool-dealloc");
        assert!(reg.get_assigned("tool-dealloc").is_none(), "entry removed");
        assert!(reg.owner(port).is_none(), "port freed after deallocation");
    }

    #[test]
    fn registry_conflict_returns_conflict_error() {
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing(
                "tool-e",
                5000,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("allocate first");
        // Attempt to allocate a different tool on the same port
        let err = reg
            .allocate_or_existing(
                "tool-f",
                6000,
                "PORT",
                &[],
                Some(b.port),
                PreferenceSource::Default,
            )
            .expect_err("should conflict");
        assert!(matches!(err, RegistryError::Conflict { .. }));
    }

    #[test]
    fn registry_allocate_or_existing_idempotent() {
        let (reg, _dir) = make_registry();
        let b1 = reg
            .allocate_or_existing(
                "tool-g",
                7000,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("first");
        let b2 = reg
            .allocate_or_existing(
                "tool-g",
                7001,
                "PORT",
                &[],
                None,
                PreferenceSource::Default,
            )
            .expect("second (idempotent)");
        // Same port returned
        assert_eq!(b1.port, b2.port);
        // PID updated
        assert_eq!(b2.pid, Some(7001));
    }

    #[test]
    fn sweep_dead_pids_clears_binding_preserves_allocation() {
        let (reg, _dir) = make_registry();
        // u32::MAX is virtually guaranteed to not be a live PID
        reg.allocate_or_existing(
            "dead-tool",
            u32::MAX,
            "PORT",
            &[],
            None,
            PreferenceSource::Default,
        )
        .expect("allocate");
        let allocated_port = reg.get_assigned("dead-tool").unwrap().port;
        reg.sweep_dead_pids();
        // Allocation preserved — only runtime binding cleared.
        let binding = reg.get_assigned("dead-tool").expect("allocation preserved");
        assert_eq!(binding.port, allocated_port);
        assert_eq!(binding.pid, None, "pid cleared by sweeper");
    }

    #[test]
    fn sweep_skips_live_pids() {
        let (reg, _dir) = make_registry();
        let own_pid = std::process::id();
        reg.allocate_or_existing(
            "live-tool",
            own_pid,
            "PORT",
            &[],
            None,
            PreferenceSource::Default,
        )
        .expect("allocate");
        reg.sweep_dead_pids();
        // Own PID is alive — binding must still be present
        assert!(reg.get_assigned("live-tool").is_some());
    }

    // ── Wire 1 tests ─────────────────────────────────────────────────

    #[test]
    fn update_pid_records_correctly() {
        let (reg, _dir) = make_registry();
        reg.allocate_or_existing("pid-tool", 0, "PORT", &[], None, PreferenceSource::Default)
            .expect("allocate");
        assert_eq!(reg.get_assigned("pid-tool").unwrap().pid, Some(0));

        reg.update_pid("pid-tool", 42424).expect("update_pid");
        let binding = reg.get_assigned("pid-tool").unwrap();
        assert_eq!(binding.pid, Some(42424));
        // Port and other fields unchanged
        assert!(binding.port >= 9100 && binding.port <= 9199);
    }

    #[test]
    fn update_pid_returns_err_for_unknown_tool() {
        let (reg, _dir) = make_registry();
        let err = reg.update_pid("no-such-tool", 999).unwrap_err();
        assert!(matches!(err, RegistryError::NotAssigned(_)));
    }

    #[test]
    fn clear_binding_zeroes_pid_and_actuals() {
        let (reg, _dir) = make_registry();
        reg.allocate_or_existing("cb-tool", 9999, "PORT", &[], None, PreferenceSource::Default)
            .expect("allocate");
        reg.update_pid("cb-tool", 9999).expect("update_pid");
        // Manually set actual_port by doing a reconciliation
        let b = reg.get_assigned("cb-tool").unwrap();
        reg.reconcile_ports("cb-tool", 9999, &[b.port + 1]);

        reg.clear_binding("cb-tool", ReleaseReason::GracefulExit);
        let after = reg.get_assigned("cb-tool").expect("allocation preserved");
        assert_eq!(after.pid, None);
        assert_eq!(after.actual_port, None);
        assert!(after.actual_extra_ports.is_empty());
        // Allocated port stays
        assert_eq!(after.port, b.port);
    }

    #[test]
    fn clear_binding_preserves_auth_token_and_port_var() {
        let (reg, _dir) = make_registry();
        reg.allocate_or_existing("auth-tool", 1111, "MY_PORT", &[], None, PreferenceSource::Default)
            .expect("allocate");
        let original = reg.get_assigned("auth-tool").unwrap();
        reg.clear_binding("auth-tool", ReleaseReason::PidDead);
        let after = reg.get_assigned("auth-tool").unwrap();
        assert_eq!(after.port_var, "MY_PORT");
        assert_eq!(after.auth_token, original.auth_token);
        assert_eq!(after.port, original.port);
    }

    // ── Wire 2 tests ─────────────────────────────────────────────────

    #[test]
    fn post_launch_reconciliation_detects_port_mismatch() {
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing("recon-tool", 1234, "PORT", &[], None, PreferenceSource::Default)
            .expect("allocate");
        let allocated = b.port;

        // Simulate tool bound to a different port than allocated
        let actual_ports = vec![allocated + 50];
        let receipts = reg.reconcile_ports("recon-tool", 1234, &actual_ports);
        assert_eq!(receipts, 2, "should emit release + allocate receipt pair");

        let updated = reg.get_assigned("recon-tool").unwrap();
        // Allocated port is UNCHANGED — actual_port carries the observation.
        assert_eq!(updated.port, allocated, "allocated port unchanged");
        assert_eq!(
            updated.actual_port,
            Some(allocated + 50),
            "actual_port reflects observation"
        );
        // preference_source tracks the allocation, not the observation
        assert_eq!(updated.preference_source, PreferenceSource::Default);
    }

    #[test]
    fn post_launch_reconciliation_no_mismatch_no_receipts() {
        let (reg, _dir) = make_registry();
        let b = reg
            .allocate_or_existing("match-tool", 5678, "PORT", &[], None, PreferenceSource::Default)
            .expect("allocate");

        // Tool bound exactly to its allocated port — no mismatch
        let actual_ports = vec![b.port];
        let receipts = reg.reconcile_ports("match-tool", 5678, &actual_ports);
        assert_eq!(receipts, 0, "no receipts when ports match");

        let unchanged = reg.get_assigned("match-tool").unwrap();
        assert_eq!(unchanged.port, b.port);
        assert_eq!(unchanged.preference_source, PreferenceSource::Default);
    }

    #[test]
    fn reconcile_empty_actual_ports_is_noop() {
        let (reg, _dir) = make_registry();
        reg.allocate_or_existing("crash-tool", 999, "PORT", &[], None, PreferenceSource::Default)
            .expect("allocate");
        // Empty actuals = tool crashed before binding; sweeper will clean up
        let receipts = reg.reconcile_ports("crash-tool", 999, &[]);
        assert_eq!(receipts, 0);
        assert!(reg.get_assigned("crash-tool").is_some(), "binding preserved");
    }

    // ── lsof parser tests ─────────────────────────────────────────────

    #[test]
    fn parse_lsof_listen_ports_extracts_ports() {
        let sample = "\
COMMAND    PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\n\
ironclaw 1234 user   17u  IPv4 0xabc       0t0  TCP *:3000 (LISTEN)\n\
ironclaw 1234 user   18u  IPv4 0xdef       0t0  TCP *:8090 (LISTEN)\n\
ironclaw 1234 user   19u  IPv4 0x123       0t0  TCP 127.0.0.1:50051 (LISTEN)\n\
ironclaw 1234 user   20u  IPv4 0x456       0t0  TCP 127.0.0.1:50051 (ESTABLISHED)\n";
        let ports = parse_lsof_listen_ports(sample);
        assert_eq!(ports, vec![3000, 8090, 50051]);
    }

    #[test]
    fn parse_lsof_listen_ports_deduplicates() {
        let sample = "\
tool 1 u  TCP *:9100 (LISTEN)\n\
tool 1 u  TCP *:9100 (LISTEN)\n";
        let ports = parse_lsof_listen_ports(sample);
        assert_eq!(ports, vec![9100], "duplicates collapsed");
    }

    #[test]
    fn parse_lsof_listen_ports_empty_on_no_listen() {
        let sample = "tool 1 u  TCP *:9100 (ESTABLISHED)\n";
        let ports = parse_lsof_listen_ports(sample);
        assert!(ports.is_empty(), "ESTABLISHED not included");
    }
}
