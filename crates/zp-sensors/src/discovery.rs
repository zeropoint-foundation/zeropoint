//! Port discovery via the `listeners` crate.
//!
//! Periodic scan (~5min default) that calls `listeners::get_all()` to
//! map all listening processes to their ports. Diffs against a known
//! set (from the port registry) and emits events for:
//!
//! - New unregistered processes binding ports
//! - Registered tools whose actual ports don't match the registry
//! - Registered tools whose PIDs have disappeared

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::Utc;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::event::{DiscoveredPort, SensorEvent};
use crate::process::gather_process_context;

/// Known tool binding — what the port registry says should be true.
#[derive(Debug, Clone)]
pub struct KnownBinding {
    pub tool_name: String,
    pub pid: Option<u32>,
    pub port: u16,
    pub extra_ports: Vec<u16>,
}

/// Configuration for the discovery scanner.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to run the full scan. Default: 5 minutes.
    pub interval: Duration,
    /// PIDs to ignore (system services, ZP's own server, etc.).
    pub ignore_pids: HashSet<u32>,
    /// Process names to ignore (launchd, kernel_task, etc.).
    pub ignore_names: HashSet<String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        let mut ignore_names = HashSet::new();
        // System daemons that always show up but aren't governed.
        for name in &[
            "launchd",
            "configd",
            "syslogd",
            "mDNSResponder",
            "airportd",
            "kdc",
            "netbiosd",
            "rapportd",
            "ARDAgent",
            "ControlCenter",
            "kernel_task",
            "WindowServer",
        ] {
            ignore_names.insert(name.to_string());
        }

        Self {
            interval: Duration::from_secs(300),
            ignore_pids: HashSet::new(),
            ignore_names,
        }
    }
}

/// Run the periodic discovery scanner.
///
/// Calls `listeners::get_all()` on `config.interval`, diffs against
/// `known_bindings`, and emits sensor events for anything unexpected.
///
/// This function runs until the channel is closed.
pub async fn run_discovery(
    config: DiscoveryConfig,
    tx: mpsc::Sender<SensorEvent>,
    known_rx: tokio::sync::watch::Receiver<Vec<KnownBinding>>,
) {
    let mut interval = tokio::time::interval(config.interval);
    // Don't burst on startup — wait one full interval before first scan.
    interval.tick().await;

    loop {
        interval.tick().await;

        let known_bindings = known_rx.borrow().clone();

        match scan_and_diff(&config, &known_bindings) {
            Ok(events) => {
                for event in events {
                    debug!(kind = event.kind_label(), "Discovery event");
                    if tx.send(event).await.is_err() {
                        debug!("Sensor event channel closed, stopping discovery");
                        return;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Discovery scan failed");
            }
        }
    }
}

/// Run one scan cycle: call `listeners::get_all()` and diff against known bindings.
fn scan_and_diff(
    config: &DiscoveryConfig,
    known_bindings: &[KnownBinding],
) -> Result<Vec<SensorEvent>, String> {
    let entries = listeners::get_all().map_err(|e| format!("listeners::get_all() failed: {e}"))?;

    trace!(entries = entries.len(), "listeners scan complete");

    // Group by PID.
    let mut by_pid: HashMap<u32, (String, Vec<DiscoveredPort>)> = HashMap::new();
    for entry in &entries {
        let pid = entry.process.pid;
        let e = by_pid
            .entry(pid)
            .or_insert_with(|| (entry.process.name.clone(), Vec::new()));
        e.1.push(DiscoveredPort {
            port: entry.socket.port(),
            protocol: format!("{:?}", entry.protocol),
            socket: format!("{}", entry.socket),
        });
    }

    // Build lookup from known bindings.
    let known_by_pid: HashMap<u32, &KnownBinding> = known_bindings
        .iter()
        .filter_map(|b| b.pid.map(|pid| (pid, b)))
        .collect();

    let known_ports: HashSet<u16> = known_bindings
        .iter()
        .flat_map(|b| {
            let mut ports = vec![b.port];
            ports.extend(&b.extra_ports);
            ports
        })
        .collect();

    let mut events = Vec::new();
    let now = Utc::now();

    // Self-exemption: never flag our own process as an unknown listener.
    let self_pid = std::process::id();

    for (pid, (name, ports)) in &by_pid {
        // Skip ignored and self.
        if *pid == self_pid || config.ignore_pids.contains(pid) || config.ignore_names.contains(name) {
            continue;
        }

        if let Some(known) = known_by_pid.get(pid) {
            // Known tool — check for port mismatches.
            let expected: HashSet<u16> = {
                let mut s = HashSet::new();
                s.insert(known.port);
                s.extend(&known.extra_ports);
                s
            };
            let actual: Vec<u16> = ports.iter().map(|p| p.port).collect();
            let actual_set: HashSet<u16> = actual.iter().copied().collect();

            if !expected.is_subset(&actual_set) || !actual_set.is_subset(&expected) {
                events.push(SensorEvent::PortMismatch {
                    tool_name: known.tool_name.clone(),
                    pid: *pid,
                    expected_port: known.port,
                    actual_ports: actual,
                    timestamp: now,
                });
            }
        } else {
            // Unknown PID — check if any of its ports overlap with known ports.
            // If not, it's a genuinely new listener.
            let listener_ports: Vec<u16> = ports.iter().map(|p| p.port).collect();
            let overlaps_known = listener_ports.iter().any(|p| known_ports.contains(p));

            if !overlaps_known {
                let context = gather_process_context(*pid, name);
                events.push(SensorEvent::NewListenerDiscovered {
                    pid: *pid,
                    process_name: name.clone(),
                    ports: ports.clone(),
                    context,
                    timestamp: now,
                });
            }
        }
    }

    // Check for stale registry entries — known PIDs that no longer appear in scan.
    for binding in known_bindings {
        if let Some(pid) = binding.pid {
            if !by_pid.contains_key(&pid) {
                events.push(SensorEvent::RegistryStale {
                    tool_name: binding.tool_name.clone(),
                    expected_pid: pid,
                    timestamp: now,
                });
            }
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_system_ignores() {
        let config = DiscoveryConfig::default();
        assert!(config.ignore_names.contains("launchd"));
        assert!(config.ignore_names.contains("mDNSResponder"));
        assert_eq!(config.interval, Duration::from_secs(300));
    }

    #[test]
    fn scan_and_diff_runs_without_root() {
        // This test validates that listeners::get_all() works unprivileged.
        // The specific events depend on what's running, so we just check
        // it doesn't error.
        let config = DiscoveryConfig::default();
        let known: Vec<KnownBinding> = Vec::new();
        let result = scan_and_diff(&config, &known);
        assert!(result.is_ok(), "scan_and_diff failed: {:?}", result.err());
    }
}
