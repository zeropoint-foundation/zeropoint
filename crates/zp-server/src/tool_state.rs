//! Tool State Engine — derives system state from the receipt chain.
//!
//! ZeroPoint's core insight: **state is never stored, only derived**.
//! There is no `tool_status` field in a database that gets stale.
//! Instead, state is a pure function over the receipt chain:
//!
//!   `current_state(tool) = reduce(receipts_for(tool))`
//!
//! Any observer with access to the chain independently derives the same
//! state.  The chain is the single source of truth.  This makes state
//! **portable** — an agent, a dashboard, a remote auditor all compute
//! identical conclusions.
//!
//! ## Receipt taxonomy
//!
//! ```text
//! LIFECYCLE (explicit events — emitted by ZP orchestration)
//!   tool:configured:{name}            .env written, credentials resolved
//!   tool:preflight:passed:{name}      all infra checks green
//!   tool:preflight:failed:{name}      one or more checks failed
//!   tool:launched:{name}              process spawned
//!   tool:stopped:{name}               graceful shutdown
//!   tool:crashed:{name}               non-zero exit or OOM
//!   tool:setup:complete:{name}        tool's own first-run finished
//!
//! HEALTH (derived from proxy traffic — emitted by ZP proxy)
//!   tool:health:up:{name}             proxy got 2xx/3xx from tool
//!   tool:health:down:{name}           proxy got connection refused / timeout
//!   tool:health:degraded:{name}       proxy got 5xx from tool
//!
//! DEPENDENCY (inferred from launch failures & config)
//!   tool:dep:needed:{name}:{dep}      tool needs {dep} to start
//!   tool:dep:satisfied:{name}:{dep}   dependency confirmed available
//!   tool:dep:failed:{name}:{dep}      dependency could not be started
//!
//! PORT (managed by PortAllocator)
//!   tool:port:assigned:{name}:{port}  ZP assigned port from range
//!   tool:port:released:{name}         port returned to pool
//!
//! GOVERNANCE (proxy-observed traffic patterns)
//!   tool:traffic:request:{name}       proxied request (sampled, not every one)
//!   tool:traffic:error:{name}         proxied request returned error
//!   tool:governance:violation:{name}  policy violation detected in traffic
//!
//! VERIFICATION (probed after health:up — closes the configure-to-consumption gap)
//!   tool:providers:resolved:{name}              Tier 1: tool runtime loaded configured providers
//!   tool:capability:verified:{name}:{cap}       Tier 2: capability's verify endpoint returned 2xx
//!   tool:capability:degraded:{name}:{cap}       Tier 2: optional capability probe failed
//!   tool:capability:failed:{name}:{cap}         Tier 2: required capability probe failed
//! ```
//!
//! ## State machine
//!
//! ```text
//!                    ┌──────────────────────────────────────────────────┐
//!                    │                                                  │
//!  ┌─────────┐  configured  ┌────────────┐  preflight   ┌──────────┐  │
//!  │ Unknown ├────────────►│ Configured ├──────────────►│ Ready    │  │
//!  └─────────┘             └────────────┘  :passed      └────┬─────┘  │
//!                    ▲            │                           │        │
//!                    │            │ preflight:failed    launched       │
//!                    │            ▼                           │        │
//!                    │     ┌────────────┐              ┌─────▼─────┐  │
//!                    │     │ Blocked    │              │ Starting  │  │
//!                    │     └────────────┘              └─────┬─────┘  │
//!                    │                                       │        │
//!                    │                              health:up│        │
//!                    │                                       ▼        │
//!                    │  stopped/crashed             ┌────────────┐   │
//!                    └─────────────────────────────┤  Running    │   │
//!                                                  └──────┬─────┘   │
//!                                                         │         │
//!                                               health:down│        │
//!                                                         ▼         │
//!                                                  ┌────────────┐   │
//!                                                  │  Down      ├───┘
//!                                                  └────────────┘
//!                                                   (auto-relaunch?)
//! ```

use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;

use zp_audit::AuditStore;
use zp_core::{AuditAction, PolicyDecision};

// ── Receipt event constants ─────────────────────────────────────────────

/// Receipt event namespace for tool lifecycle.
pub mod events {
    // Lifecycle
    pub const CONFIGURED: &str = "tool:configured";
    pub const PREFLIGHT_PASSED: &str = "tool:preflight:passed";
    pub const PREFLIGHT_FAILED: &str = "tool:preflight:failed";
    pub const LAUNCHED: &str = "tool:launched";
    pub const STOPPED: &str = "tool:stopped";
    pub const CRASHED: &str = "tool:crashed";
    pub const SETUP_COMPLETE: &str = "tool:setup:complete";

    // Health (emitted by proxy)
    pub const HEALTH_UP: &str = "tool:health:up";
    pub const HEALTH_DOWN: &str = "tool:health:down";
    pub const HEALTH_DEGRADED: &str = "tool:health:degraded";

    // Dependencies
    pub const DEP_NEEDED: &str = "tool:dep:needed";
    pub const DEP_SATISFIED: &str = "tool:dep:satisfied";
    pub const DEP_FAILED: &str = "tool:dep:failed";

    // Port management
    pub const PORT_ASSIGNED: &str = "tool:port:assigned";
    pub const PORT_RELEASED: &str = "tool:port:released";

    // Traffic (sampled)
    pub const TRAFFIC_REQUEST: &str = "tool:traffic:request";
    pub const TRAFFIC_ERROR: &str = "tool:traffic:error";

    // Capability verification (Tier 1 + Tier 2)
    //
    // Tier 1: Runtime provider resolution — did the tool load the keys ZP wrote?
    pub const PROVIDERS_RESOLVED: &str = "tool:providers:resolved";
    // Tier 2: Per-capability auth verification — do the keys actually work?
    pub const CAPABILITY_VERIFIED: &str = "tool:capability:verified";
    pub const CAPABILITY_DEGRADED: &str = "tool:capability:degraded";
    pub const CAPABILITY_FAILED: &str = "tool:capability:failed";

    /// Build a namespaced event string: `tool:health:up:ironclaw`
    pub fn for_tool(event: &str, tool_name: &str) -> String {
        format!("{}:{}", event, tool_name)
    }

    /// Build a dependency event: `tool:dep:needed:ironclaw:postgres`
    pub fn dep(event: &str, tool_name: &str, dep_name: &str) -> String {
        format!("{}:{}:{}", event, tool_name, dep_name)
    }

    /// Build a port event: `tool:port:assigned:ironclaw:9101`
    pub fn port_assigned(tool_name: &str, port: u16) -> String {
        format!("{}:{}:{}", PORT_ASSIGNED, tool_name, port)
    }

    /// Build a capability event: `tool:capability:verified:ember:reasoning_llm`
    pub fn capability(event: &str, tool_name: &str, capability: &str) -> String {
        format!("{}:{}:{}", event, tool_name, capability)
    }
}

// ── Derived state ───────────────────────────────────────────────────────

/// The lifecycle phase of a tool, derived purely from receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolPhase {
    /// No receipts at all — tool is known but never configured.
    Unknown,
    /// `.env` written and credentials resolved, but not preflighted.
    Configured,
    /// Preflight failed — something is blocking launch.
    Blocked,
    /// Preflight passed — ready to launch.
    Ready,
    /// Launch command issued, waiting for health check.
    Starting,
    /// Proxy confirmed the tool is responding.
    Running,
    /// Tool was responding but is now unreachable.
    Down,
    /// Tool is responding but returning errors.
    Degraded,
    /// Gracefully stopped.
    Stopped,
    /// Exited abnormally.
    Crashed,
}

impl ToolPhase {
    /// Is this a "live" state where the tool is expected to serve traffic?
    pub fn is_live(&self) -> bool {
        matches!(self, ToolPhase::Running | ToolPhase::Degraded)
    }

    /// Should ZP attempt automatic recovery?
    pub fn should_auto_recover(&self) -> bool {
        matches!(self, ToolPhase::Down | ToolPhase::Crashed)
    }
}

/// Complete derived state for a tool, computed from the receipt chain.
#[derive(Debug, Clone, Serialize)]
pub struct ToolState {
    pub name: String,
    pub phase: ToolPhase,

    // Timestamps of last state-relevant events
    pub configured_at: Option<DateTime<Utc>>,
    pub preflight_at: Option<DateTime<Utc>>,
    pub launched_at: Option<DateTime<Utc>>,
    pub last_healthy_at: Option<DateTime<Utc>>,
    pub last_unhealthy_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,

    // Preflight details
    pub preflight_passed: bool,
    pub preflight_issues: Vec<String>,

    // Port
    pub assigned_port: Option<u16>,

    // Dependencies
    pub dependencies: Vec<DepState>,

    // Traffic stats (from sampled receipts)
    pub total_requests: u64,
    pub total_errors: u64,
    pub last_request_at: Option<DateTime<Utc>>,

    // Health
    /// How long ago was the last health receipt?
    pub health_age_secs: Option<i64>,
    /// Is the health stale (no receipt in the last N seconds)?
    pub health_stale: bool,
}

/// State of a single dependency.
#[derive(Debug, Clone, Serialize)]
pub struct DepState {
    pub name: String,
    pub satisfied: bool,
    pub last_checked_at: Option<DateTime<Utc>>,
}

// ── State derivation engine ─────────────────────────────────────────────

/// Maximum age of a health receipt before we consider it stale.
/// If a tool hasn't had proxy traffic in this window, its health
/// is unknown (not the same as down — it might just be idle).
const HEALTH_STALE_SECS: i64 = 120; // 2 minutes

/// Derive the complete state of all tools from the receipt chain.
///
/// This is a pure function: same chain → same output.
/// It can be called by dashboards, agents, CLIs, or remote auditors.
pub fn derive_system_state(
    audit_store: &Mutex<AuditStore>,
) -> SystemState {
    let now = Utc::now();

    let store = match audit_store.lock() {
        Ok(s) => s,
        Err(_) => return SystemState::empty(),
    };

    // Get all tool lifecycle entries (most recent first, generous limit)
    let conv_id = super::tool_chain::tool_lifecycle_conv_id();
    let entries = match store.get_entries(conv_id, 2000) {
        Ok(e) => e,
        Err(_) => return SystemState::empty(),
    };

    // Parse all events into a per-tool timeline
    let mut tools: HashMap<String, ToolStateBuilder> = HashMap::new();

    // Walk from most recent to oldest — first occurrence of each event
    // type per tool wins (it's the latest).
    for entry in &entries {
        if let AuditAction::SystemEvent { event } = &entry.action {
            if !event.starts_with("tool:") {
                continue;
            }

            let ts = entry.timestamp;
            let detail = match &entry.policy_decision {
                PolicyDecision::Allow { conditions } => conditions.clone(),
                _ => vec![],
            };

            // Parse: tool:{category}:{sub}:{name}[:{extra}]
            let parts: Vec<&str> = event.splitn(5, ':').collect();
            if parts.len() < 3 {
                continue;
            }

            // Route by category
            match parts[1] {
                "configured" => {
                    if parts.len() >= 3 {
                        let name = parts[2];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        if b.configured_at.is_none() {
                            b.configured_at = Some(ts);
                        }
                    }
                }
                "preflight" => {
                    if parts.len() >= 4 {
                        let sub = parts[2];
                        let name = parts[3];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        match sub {
                            "passed" => {
                                if b.preflight_at.is_none() {
                                    b.preflight_at = Some(ts);
                                    b.preflight_passed = true;
                                }
                            }
                            "failed" => {
                                if b.preflight_at.is_none() {
                                    b.preflight_at = Some(ts);
                                    b.preflight_passed = false;
                                    b.preflight_issues = detail;
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "launched" => {
                    if parts.len() >= 3 {
                        let name = parts[2];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        if b.launched_at.is_none() {
                            b.launched_at = Some(ts);
                        }
                    }
                }
                "stopped" => {
                    if parts.len() >= 3 {
                        let name = parts[2];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        if b.stopped_at.is_none() {
                            b.stopped_at = Some(ts);
                        }
                    }
                }
                "crashed" => {
                    if parts.len() >= 3 {
                        let name = parts[2];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        if b.crashed_at.is_none() {
                            b.crashed_at = Some(ts);
                        }
                    }
                }
                "setup" => {
                    if parts.len() >= 4 && parts[2] == "complete" {
                        let name = parts[3];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        if b.setup_at.is_none() {
                            b.setup_at = Some(ts);
                        }
                    }
                }
                "health" => {
                    if parts.len() >= 4 {
                        let sub = parts[2]; // up, down, degraded
                        let name = parts[3];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        match sub {
                            "up" => {
                                if b.last_healthy_at.is_none() {
                                    b.last_healthy_at = Some(ts);
                                }
                            }
                            "down" => {
                                if b.last_unhealthy_at.is_none() {
                                    b.last_unhealthy_at = Some(ts);
                                    b.last_unhealthy_reason = Some("unreachable".to_string());
                                }
                            }
                            "degraded" => {
                                if b.last_degraded_at.is_none() {
                                    b.last_degraded_at = Some(ts);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "dep" => {
                    // tool:dep:{needed|satisfied|failed}:{tool}:{dep}
                    if parts.len() >= 5 {
                        let sub = parts[2];
                        let name = parts[3];
                        let dep = parts[4];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        let d = b.deps.entry(dep.to_string()).or_insert_with(|| DepStateBuilder {
                            satisfied: false,
                            last_checked_at: None,
                        });
                        match sub {
                            "satisfied" => {
                                if d.last_checked_at.is_none() {
                                    d.satisfied = true;
                                    d.last_checked_at = Some(ts);
                                }
                            }
                            "failed" | "needed" => {
                                if d.last_checked_at.is_none() {
                                    d.satisfied = false;
                                    d.last_checked_at = Some(ts);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                "port" => {
                    if parts.len() >= 4 {
                        let sub = parts[2]; // assigned, released
                        let name = parts[3];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        if sub == "assigned" && parts.len() >= 5 {
                            if b.assigned_port.is_none() {
                                b.assigned_port = parts[4].parse().ok();
                            }
                        } else if sub == "released" {
                            // Most recent event wins — if released is newer than assigned,
                            // port is None.  But we're walking newest-first, so if we
                            // haven't seen an assigned yet, leave it None.
                        }
                    }
                }
                "traffic" => {
                    if parts.len() >= 4 {
                        let sub = parts[2];
                        let name = parts[3];
                        let b = tools.entry(name.to_string()).or_insert_with(|| ToolStateBuilder::new(name));
                        match sub {
                            "request" => {
                                b.total_requests += 1;
                                if b.last_request_at.is_none() {
                                    b.last_request_at = Some(ts);
                                }
                            }
                            "error" => {
                                b.total_errors += 1;
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    // Reduce each builder into a final ToolState
    let tool_states: HashMap<String, ToolState> = tools
        .into_iter()
        .map(|(name, b)| (name, b.finalize(now)))
        .collect();

    SystemState {
        timestamp: now,
        tools: tool_states,
    }
}

// ── Builder (internal) ──────────────────────────────────────────────────

#[derive(Debug)]
struct DepStateBuilder {
    satisfied: bool,
    last_checked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct ToolStateBuilder {
    name: String,
    configured_at: Option<DateTime<Utc>>,
    preflight_at: Option<DateTime<Utc>>,
    preflight_passed: bool,
    preflight_issues: Vec<String>,
    launched_at: Option<DateTime<Utc>>,
    stopped_at: Option<DateTime<Utc>>,
    crashed_at: Option<DateTime<Utc>>,
    setup_at: Option<DateTime<Utc>>,
    last_healthy_at: Option<DateTime<Utc>>,
    last_unhealthy_at: Option<DateTime<Utc>>,
    last_unhealthy_reason: Option<String>,
    last_degraded_at: Option<DateTime<Utc>>,
    assigned_port: Option<u16>,
    deps: HashMap<String, DepStateBuilder>,
    total_requests: u64,
    total_errors: u64,
    last_request_at: Option<DateTime<Utc>>,
}

impl ToolStateBuilder {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            configured_at: None,
            preflight_at: None,
            preflight_passed: false,
            preflight_issues: vec![],
            launched_at: None,
            stopped_at: None,
            crashed_at: None,
            setup_at: None,
            last_healthy_at: None,
            last_unhealthy_at: None,
            last_unhealthy_reason: None,
            last_degraded_at: None,
            assigned_port: None,
            deps: HashMap::new(),
            total_requests: 0,
            total_errors: 0,
            last_request_at: None,
        }
    }

    /// The state machine: derive the current phase from the receipt timeline.
    ///
    /// The key insight is that we compare timestamps of the *most recent*
    /// event of each type.  The newest event wins.
    ///
    /// Example timeline (newest first):
    ///   health:up     @ 14:05  ← this wins → Running
    ///   launched      @ 14:00
    ///   preflight:ok  @ 13:59
    ///   configured    @ 13:55
    ///
    /// Another example:
    ///   health:down   @ 14:10  ← this wins → Down
    ///   health:up     @ 14:05
    ///   launched      @ 14:00
    fn derive_phase(&self, now: DateTime<Utc>) -> ToolPhase {
        // Collect all state-relevant timestamps into a sortable list.
        // The most recent event determines the phase.
        let mut events: Vec<(DateTime<Utc>, &str)> = Vec::new();

        if let Some(t) = self.configured_at { events.push((t, "configured")); }
        if let Some(t) = self.preflight_at {
            if self.preflight_passed {
                events.push((t, "preflight_passed"));
            } else {
                events.push((t, "preflight_failed"));
            }
        }
        if let Some(t) = self.launched_at { events.push((t, "launched")); }
        if let Some(t) = self.stopped_at { events.push((t, "stopped")); }
        if let Some(t) = self.crashed_at { events.push((t, "crashed")); }
        if let Some(t) = self.last_healthy_at { events.push((t, "healthy")); }
        if let Some(t) = self.last_unhealthy_at { events.push((t, "unhealthy")); }
        if let Some(t) = self.last_degraded_at { events.push((t, "degraded")); }

        if events.is_empty() {
            return ToolPhase::Unknown;
        }

        // Sort by timestamp descending — newest first
        events.sort_by(|a, b| b.0.cmp(&a.0));

        // The newest event determines the base phase
        let (newest_ts, newest_event) = events[0];
        let base_phase = match newest_event {
            "configured" => ToolPhase::Configured,
            "preflight_passed" => ToolPhase::Ready,
            "preflight_failed" => ToolPhase::Blocked,
            "launched" => {
                // Launched but no health receipt yet — still starting
                ToolPhase::Starting
            }
            "healthy" => {
                // But is it stale?
                let age = (now - newest_ts).num_seconds();
                if age > HEALTH_STALE_SECS {
                    // Health receipt is old — tool might be idle or dead.
                    // If we also have a recent launched, it's still "Running"
                    // with stale health.  If not, mark as Down.
                    if self.launched_at.map_or(false, |l| (now - l).num_seconds() < HEALTH_STALE_SECS * 5) {
                        ToolPhase::Running // benefit of the doubt
                    } else {
                        ToolPhase::Down
                    }
                } else {
                    ToolPhase::Running
                }
            }
            "unhealthy" => ToolPhase::Down,
            "degraded" => ToolPhase::Degraded,
            "stopped" => ToolPhase::Stopped,
            "crashed" => ToolPhase::Crashed,
            _ => ToolPhase::Unknown,
        };

        base_phase
    }

    fn finalize(self, now: DateTime<Utc>) -> ToolState {
        let phase = self.derive_phase(now);

        let health_age_secs = self.last_healthy_at
            .or(self.last_unhealthy_at)
            .map(|t| (now - t).num_seconds());

        let health_stale = health_age_secs
            .map_or(true, |age| age > HEALTH_STALE_SECS);

        let dependencies: Vec<DepState> = self.deps
            .into_iter()
            .map(|(name, d)| DepState {
                name,
                satisfied: d.satisfied,
                last_checked_at: d.last_checked_at,
            })
            .collect();

        ToolState {
            name: self.name,
            phase,
            configured_at: self.configured_at,
            preflight_at: self.preflight_at,
            launched_at: self.launched_at,
            last_healthy_at: self.last_healthy_at,
            last_unhealthy_at: self.last_unhealthy_at,
            stopped_at: self.stopped_at,
            preflight_passed: self.preflight_passed,
            preflight_issues: self.preflight_issues,
            assigned_port: self.assigned_port,
            dependencies,
            total_requests: self.total_requests,
            total_errors: self.total_errors,
            last_request_at: self.last_request_at,
            health_age_secs,
            health_stale,
        }
    }
}

// ── System-wide state ───────────────────────────────────────────────────

/// Complete system state — every tool's derived state at a point in time.
///
/// This is the object that dashboards render, agents query, and auditors
/// verify.  It's ephemeral — recomputed on demand from the chain.
#[derive(Debug, Clone, Serialize)]
pub struct SystemState {
    pub timestamp: DateTime<Utc>,
    pub tools: HashMap<String, ToolState>,
}

impl SystemState {
    pub fn empty() -> Self {
        Self {
            timestamp: Utc::now(),
            tools: HashMap::new(),
        }
    }

    /// How many tools are in each phase?
    pub fn phase_summary(&self) -> HashMap<ToolPhase, usize> {
        let mut counts: HashMap<ToolPhase, usize> = HashMap::new();
        for tool in self.tools.values() {
            *counts.entry(tool.phase).or_insert(0) += 1;
        }
        counts
    }

    /// Tools that are live (Running or Degraded).
    pub fn live_tools(&self) -> Vec<&ToolState> {
        self.tools.values().filter(|t| t.phase.is_live()).collect()
    }

    /// Tools that need attention (Down, Crashed, Blocked).
    pub fn attention_needed(&self) -> Vec<&ToolState> {
        self.tools.values().filter(|t| {
            matches!(t.phase, ToolPhase::Down | ToolPhase::Crashed | ToolPhase::Blocked)
        }).collect()
    }

    /// Tools eligible for automatic recovery.
    pub fn recoverable(&self) -> Vec<&ToolState> {
        self.tools.values().filter(|t| t.phase.should_auto_recover()).collect()
    }

    /// Check if a dependency is satisfied across the system.
    /// E.g., "is postgres running?" — look for any tool named "postgres"
    /// or any tool that provides that service.
    pub fn is_service_available(&self, service: &str) -> bool {
        let service_lower = service.to_lowercase();
        self.tools.values().any(|t| {
            t.name.to_lowercase().contains(&service_lower) && t.phase.is_live()
        })
    }

    /// Pre-launch dependency check: given a tool's dependency list,
    /// which deps are satisfied and which are missing?
    pub fn check_dependencies(&self, tool_name: &str) -> Option<(Vec<String>, Vec<String>)> {
        let tool = self.tools.get(tool_name)?;
        let mut satisfied = Vec::new();
        let mut missing = Vec::new();

        for dep in &tool.dependencies {
            if dep.satisfied {
                satisfied.push(dep.name.clone());
            } else {
                missing.push(dep.name.clone());
            }
        }

        Some((satisfied, missing))
    }
}

// ── Dependency graph (inferred from receipts) ───────────────────────────

/// The dependency graph is not configured — it's *learned* from receipts.
///
/// When IronClaw fails because Postgres isn't running, the preflight
/// emits `tool:dep:needed:ironclaw:postgres`.  When Postgres comes up
/// and preflight re-runs, it emits `tool:dep:satisfied:ironclaw:postgres`.
///
/// Over time, ZP builds a dependency graph purely from observations:
///
/// ```text
///   ironclaw ──needs──► postgres
///   pentagi  ──needs──► postgres
///   pentagi  ──needs──► redis
/// ```
///
/// This graph enables:
///   - Smart launch ordering (start deps before dependents)
///   - Cascade detection (postgres down → ironclaw + pentagi affected)
///   - Recovery prioritization (restart the root cause first)
pub fn derive_dependency_graph(
    state: &SystemState,
) -> HashMap<String, Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();

    for tool in state.tools.values() {
        let deps: Vec<String> = tool.dependencies
            .iter()
            .map(|d| d.name.clone())
            .collect();
        if !deps.is_empty() {
            graph.insert(tool.name.clone(), deps);
        }
    }

    graph
}

/// Compute the optimal launch order given the dependency graph.
///
/// Returns a topologically sorted list: start the first tool first,
/// then the next, etc.  Tools with no dependencies can start in parallel.
pub fn launch_order(graph: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    // Collect all nodes
    let mut all_nodes: std::collections::HashSet<String> = graph.keys().cloned().collect();
    for deps in graph.values() {
        for d in deps {
            all_nodes.insert(d.clone());
        }
    }

    let mut remaining = graph.clone();
    let mut order: Vec<Vec<String>> = Vec::new();

    loop {
        // Find nodes with no remaining dependencies
        let ready: Vec<String> = all_nodes.iter()
            .filter(|n| {
                remaining.get(*n).map_or(true, |deps| deps.is_empty())
            })
            .cloned()
            .collect();

        if ready.is_empty() {
            if !all_nodes.is_empty() {
                // Circular dependency — dump remaining as a final batch
                order.push(all_nodes.into_iter().collect());
            }
            break;
        }

        // Remove these nodes from the graph
        for node in &ready {
            all_nodes.remove(node);
            remaining.remove(node);
        }
        // Remove resolved deps from remaining entries
        for deps in remaining.values_mut() {
            deps.retain(|d| !ready.contains(d));
        }

        order.push(ready);
    }

    order
}

// ── REST endpoint ───────────────────────────────────────────────────────

/// GET /api/v1/system/state — full system state derived from the chain.
pub async fn system_state_handler(
    axum::extract::State(state): axum::extract::State<crate::AppState>,
) -> impl axum::response::IntoResponse {
    let system = derive_system_state(&state.0.audit_store);

    let graph = derive_dependency_graph(&system);
    let order = launch_order(&graph);
    let summary = system.phase_summary();
    let attention = system.attention_needed();

    axum::Json(serde_json::json!({
        "timestamp": system.timestamp,
        "tools": system.tools,
        "summary": {
            "total": system.tools.len(),
            "running": summary.get(&ToolPhase::Running).unwrap_or(&0),
            "degraded": summary.get(&ToolPhase::Degraded).unwrap_or(&0),
            "down": summary.get(&ToolPhase::Down).unwrap_or(&0),
            "starting": summary.get(&ToolPhase::Starting).unwrap_or(&0),
            "ready": summary.get(&ToolPhase::Ready).unwrap_or(&0),
            "blocked": summary.get(&ToolPhase::Blocked).unwrap_or(&0),
            "stopped": summary.get(&ToolPhase::Stopped).unwrap_or(&0),
            "crashed": summary.get(&ToolPhase::Crashed).unwrap_or(&0),
        },
        "attention_needed": attention.iter().map(|t| &t.name).collect::<Vec<_>>(),
        "dependency_graph": graph,
        "launch_order": order,
    }))
}
