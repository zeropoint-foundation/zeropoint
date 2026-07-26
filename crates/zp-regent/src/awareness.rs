//! System awareness — the Regent's view of the compute surface.
//!
//! The Regent actively maintains system harmony. This module provides
//! the instruments: memory pressure, loaded models, and background task
//! tracking. The Regent perceives this state each cycle and makes
//! resource decisions — deferring background work under pressure,
//! unloading idle models when memory is tight, yielding to operator
//! activity.
//!
//! Zero new dependencies: memory stats via macOS sysctl / Linux procfs,
//! model inventory via Ollama /api/ps (reqwest already available).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::sync::Mutex;
use tracing::debug;

use crate::context::{
    BackgroundTaskKind, BackgroundTaskStatus, LoadedModel, MemoryPressure,
    PressureLevel, SystemAwareness,
};
use crate::error::RegentError;
use crate::inference::InferenceBackend;

// ── Background task tracking ──────────────────────────────────────────

/// A handle to a running background task with its cancel flag.
pub struct BackgroundTask {
    pub kind: BackgroundTaskKind,
    pub started_at: DateTime<Utc>,
    pub cancel: Arc<AtomicBool>,
    pub join_handle: tokio::task::JoinHandle<()>,
}

impl BackgroundTask {
    /// Cancel this task. The task checks the flag between work units.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Whether the task has finished (joined or cancelled).
    pub fn is_finished(&self) -> bool {
        self.join_handle.is_finished()
    }

    /// Build a status snapshot for the cognitive context.
    pub fn status(&self) -> BackgroundTaskStatus {
        BackgroundTaskStatus {
            kind: self.kind.clone(),
            started_at: self.started_at,
            progress: if self.is_finished() {
                Some("completed".to_string())
            } else {
                Some("running".to_string())
            },
        }
    }
}

/// Manages the Regent's background tasks and system awareness.
///
/// Lives in the loop runner's spawned task. Tracks idle time, manages
/// background work, assembles SystemAwareness snapshots for the
/// cognitive context.
/// How many cycles the medium window retains.
///
/// Phase 6's own worked example is "over the last 20 cycles."
const TREND_WINDOW: usize = 20;

/// Below this many samples a delta is noise rather than drift, and the
/// window reports nothing rather than reporting confidently from two
/// points.
const MIN_TREND_SAMPLES: usize = 3;

/// One cycle's scalars, retained for trend computation.
///
/// Deliberately not a `SystemAwareness` — that type now carries the
/// trends themselves, so retaining it would nest each window inside the
/// next. It also allocates two `Vec`s per snapshot, which is real cost
/// to hold twenty of for no gain.
#[derive(Debug, Clone, Copy)]
struct Sample {
    usage_fraction: f64,
    loaded_models: usize,
    active_tasks: usize,
}

pub struct SystemMonitor {
    /// When the operator last sent input.
    last_operator_input: Instant,
    /// Active background tasks.
    tasks: Vec<BackgroundTask>,
    /// Reference to the inference backend for Ollama queries.
    inference: Arc<InferenceBackend>,
    /// Medium window — rolling samples across recent cycles.
    history: std::collections::VecDeque<Sample>,
}

impl SystemMonitor {
    pub fn new(inference: Arc<InferenceBackend>) -> Self {
        Self {
            last_operator_input: Instant::now(),
            tasks: Vec::new(),
            inference,
            history: std::collections::VecDeque::with_capacity(TREND_WINDOW),
        }
    }

    /// Record that the operator just interacted.
    /// Also cancels any running background tasks — operator has priority.
    pub fn operator_active(&mut self) {
        self.last_operator_input = Instant::now();
        // Cancel all background tasks — operator attention takes priority.
        for task in &self.tasks {
            if !task.is_finished() {
                debug!(kind = ?task.kind, "cancelling background task — operator active");
                task.cancel();
            }
        }
    }

    /// Seconds since last operator interaction.
    pub fn idle_secs(&self) -> u64 {
        self.last_operator_input.elapsed().as_secs()
    }

    /// Register a new background task.
    pub fn register_task(&mut self, task: BackgroundTask) {
        // Clean up finished tasks first.
        self.tasks.retain(|t| !t.is_finished());
        self.tasks.push(task);
    }

    /// Whether any background task of the given kind is currently running.
    pub fn has_active_task(&self, kind: &BackgroundTaskKind) -> bool {
        self.tasks.iter().any(|t| &t.kind == kind && !t.is_finished())
    }

    /// Cancel all background tasks.
    pub fn cancel_all(&mut self) {
        for task in &self.tasks {
            task.cancel();
        }
    }

    /// Assemble a full SystemAwareness snapshot for the cognitive context.
    pub async fn snapshot(&mut self) -> SystemAwareness {
        // Clean up finished tasks.
        self.tasks.retain(|t| !t.is_finished());

        let memory = read_memory_pressure();
        let loaded_models = query_loaded_models(&self.inference).await;

        let active_tasks: Vec<BackgroundTaskStatus> = self
            .tasks
            .iter()
            .filter(|t| !t.is_finished())
            .map(|t| t.status())
            .collect();

        // Record this cycle before computing the window, so the trend
        // includes the sample it is reported alongside.
        self.history.push_back(Sample {
            usage_fraction: memory.usage_fraction,
            loaded_models: loaded_models.len(),
            active_tasks: active_tasks.len(),
        });
        while self.history.len() > TREND_WINDOW {
            self.history.pop_front();
        }
        let trends = self.compute_trends();

        SystemAwareness {
            idle_secs: self.idle_secs(),
            memory,
            loaded_models,
            active_tasks,
            trends,
        }
    }

    /// Aggregate the medium window. `None` until enough samples exist.
    ///
    /// Simple statistics only — delta and monotonicity — per Phase 6's
    /// implementation note that the aggregation "is simple statistics
    /// (mean, delta, monotonicity), not inference."
    fn compute_trends(&self) -> Option<crate::context::SystemTrends> {
        if self.history.len() < MIN_TREND_SAMPLES {
            return None;
        }
        let first = self.history.front()?;
        let last = self.history.back()?;

        let monotonic_rising = self
            .history
            .iter()
            .zip(self.history.iter().skip(1))
            .all(|(a, b)| b.usage_fraction >= a.usage_fraction);

        Some(crate::context::SystemTrends {
            samples: self.history.len(),
            memory_usage_delta: last.usage_fraction - first.usage_fraction,
            memory_monotonic_rising: monotonic_rising,
            loaded_model_delta: last.loaded_models as i64 - first.loaded_models as i64,
            active_task_delta: last.active_tasks as i64 - first.active_tasks as i64,
        })
    }

    /// Create a new cancel flag for a background task.
    pub fn new_cancel_flag(&self) -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }
}

// ── System memory reading ─────────────────────────────────────────────

/// Read system memory pressure without external crate dependencies.
///
/// macOS: `sysctl hw.memsize` + `vm_stat`
/// Linux: `/proc/meminfo`
/// Fallback: unknown pressure (won't block decisions).
fn read_memory_pressure() -> MemoryPressure {
    #[cfg(target_os = "macos")]
    {
        read_memory_macos()
    }
    #[cfg(target_os = "linux")]
    {
        read_memory_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        MemoryPressure {
            total_bytes: 0,
            available_bytes: 0,
            usage_fraction: 0.0,
            level: PressureLevel::Low,
        }
    }
}

#[cfg(target_os = "macos")]
fn read_memory_macos() -> MemoryPressure {
    use std::process::Command;

    // Total memory via sysctl.
    let total_bytes = Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    // Page size and free/inactive pages via vm_stat.
    let vm_stat = Command::new("vm_stat")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    let page_size: u64 = 16384; // Apple Silicon default
    let mut free_pages: u64 = 0;
    let mut inactive_pages: u64 = 0;
    let mut purgeable_pages: u64 = 0;

    for line in vm_stat.lines() {
        if line.starts_with("Pages free:") {
            free_pages = parse_vm_stat_value(line);
        } else if line.starts_with("Pages inactive:") {
            inactive_pages = parse_vm_stat_value(line);
        } else if line.starts_with("Pages purgeable:") {
            purgeable_pages = parse_vm_stat_value(line);
        }
    }

    let available_bytes = (free_pages + inactive_pages + purgeable_pages) * page_size;
    let usage_fraction = if total_bytes > 0 {
        1.0 - (available_bytes as f64 / total_bytes as f64)
    } else {
        0.0
    };

    let level = if usage_fraction > 0.90 {
        PressureLevel::Critical
    } else if usage_fraction > 0.80 {
        PressureLevel::High
    } else if usage_fraction > 0.60 {
        PressureLevel::Moderate
    } else {
        PressureLevel::Low
    };

    MemoryPressure {
        total_bytes,
        available_bytes,
        usage_fraction,
        level,
    }
}

#[cfg(target_os = "macos")]
fn parse_vm_stat_value(line: &str) -> u64 {
    line.split(':')
        .nth(1)
        .and_then(|v| v.trim().trim_end_matches('.').parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
fn read_memory_linux() -> MemoryPressure {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();

    let mut total_kb: u64 = 0;
    let mut available_kb: u64 = 0;

    for line in meminfo.lines() {
        if line.starts_with("MemTotal:") {
            total_kb = parse_meminfo_value(line);
        } else if line.starts_with("MemAvailable:") {
            available_kb = parse_meminfo_value(line);
        }
    }

    let total_bytes = total_kb * 1024;
    let available_bytes = available_kb * 1024;
    let usage_fraction = if total_bytes > 0 {
        1.0 - (available_bytes as f64 / total_bytes as f64)
    } else {
        0.0
    };

    let level = if usage_fraction > 0.90 {
        PressureLevel::Critical
    } else if usage_fraction > 0.80 {
        PressureLevel::High
    } else if usage_fraction > 0.60 {
        PressureLevel::Moderate
    } else {
        PressureLevel::Low
    };

    MemoryPressure {
        total_bytes,
        available_bytes,
        usage_fraction,
        level,
    }
}

#[cfg(target_os = "linux")]
fn parse_meminfo_value(line: &str) -> u64 {
    line.split_whitespace()
        .nth(1)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

// ── Ollama model inventory ────────────────────────────────────────────

/// Query Ollama /api/ps for currently loaded models.
async fn query_loaded_models(backend: &InferenceBackend) -> Vec<LoadedModel> {
    let client = reqwest::Client::new();
    let url = format!("{}/api/ps", backend.endpoint());

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            debug!("awareness: Ollama /api/ps unreachable: {}", e);
            return vec![];
        }
    };

    if !resp.status().is_success() {
        return vec![];
    }

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(_) => return vec![],
    };

    body["models"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    let name = m["name"].as_str()?.to_string();
                    let size_bytes = m["size"].as_u64().unwrap_or(0);
                    let expires_at = m["expires_at"].as_str().map(|s| s.to_string());
                    Some(LoadedModel {
                        name,
                        size_bytes,
                        expires_at,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

// ── System status tool dispatch ───────────────────────────────────────

/// Build a system_status response for the Regent's tool dispatch.
///
/// This is what the Regent sees when she calls system_status() —
/// a structured view of the system she governs.
pub async fn dispatch_system_status(
    monitor: &Mutex<SystemMonitor>,
) -> Result<serde_json::Value, RegentError> {
    let mut mon = monitor.lock().await;
    let awareness = mon.snapshot().await;

    let models: Vec<serde_json::Value> = awareness
        .loaded_models
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "size_mb": m.size_bytes / (1024 * 1024),
                "expires_at": m.expires_at,
            })
        })
        .collect();

    let tasks: Vec<serde_json::Value> = awareness
        .active_tasks
        .iter()
        .map(|t| {
            serde_json::json!({
                "kind": format!("{:?}", t.kind),
                "started_at": t.started_at.to_rfc3339(),
                "progress": t.progress,
            })
        })
        .collect();

    Ok(serde_json::json!({
        "idle_secs": awareness.idle_secs,
        "memory": {
            "total_gb": awareness.memory.total_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            "available_gb": awareness.memory.available_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            "usage_percent": (awareness.memory.usage_fraction * 100.0).round(),
            "pressure": format!("{:?}", awareness.memory.level),
        },
        "loaded_models": models,
        "background_tasks": tasks,
    }))
}
