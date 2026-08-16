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

    // Listeners already reported as new, carried across scans.
    //
    // Without this the scan is edge-blind: `scan_and_diff` diffs against the
    // *port registry*, so "new" means "unregistered", not "not seen before",
    // and every unregistered listener re-fires on every cycle. Observed
    // 2026-08-06: five `officer:sen:security:unauthorized_listener` findings at
    // 15:15:4x and five more at 15:20:4x — the same processes, 300 seconds
    // apart, at Warning severity. Sixty security findings an hour describing a
    // machine state that had not changed, and `officer:sen:` accounting for
    // roughly a fifth of all receipts in the inventory window.
    //
    // Per KEEL §III.25, a finding that fires on unchanged state is a runaway
    // alarm: it forces operator attention onto routine flow and buries real
    // signal. Findings are edge-triggered; heartbeats already carry the
    // level-triggered "still here" story.
    //
    // Keyed on `(pid, process_name)` rather than pid alone so a recycled PID
    // running a different binary reads as new. Entries for listeners that have
    // gone away are dropped each cycle, so a process that exits and returns is
    // correctly reported again.
    let mut reported: HashSet<(u32, String)> = HashSet::new();

    loop {
        interval.tick().await;

        let known_bindings = known_rx.borrow().clone();

        match scan_and_diff(&config, &known_bindings, &mut reported) {
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
///
/// `reported` carries the set of unregistered listeners already announced, so
/// `NewListenerDiscovered` is edge-triggered. It is replaced each cycle with
/// the listeners seen *this* scan, which both suppresses repeats and lets a
/// listener that disappears and returns be reported again.
fn scan_and_diff(
    config: &DiscoveryConfig,
    known_bindings: &[KnownBinding],
    reported: &mut HashSet<(u32, String)>,
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

    // Unregistered listeners observed this cycle. Becomes `reported` at the
    // end, so departures drop out and can be announced again if they return.
    let mut still_present: HashSet<(u32, String)> = HashSet::new();

    for (pid, (name, ports)) in &by_pid {
        // Skip ignored and self.
        if *pid == self_pid
            || config.ignore_pids.contains(pid)
            || config.ignore_names.contains(name)
        {
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
                let key = (*pid, name.clone());
                // Every candidate joins the current set whether or not it is
                // announced — that is what makes the next cycle quiet.
                still_present.insert(key.clone());
                if !reported.contains(&key) {
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

    // Swap in this cycle's set. Departures drop out here, which is what lets a
    // listener that exits and returns be announced a second time.
    *reported = still_present;

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
        let mut reported = HashSet::new();
        let result = scan_and_diff(&config, &known, &mut reported);
        assert!(result.is_ok(), "scan_and_diff failed: {:?}", result.err());
    }

    /// The defect this guards against: `NewListenerDiscovered` firing again for
    /// a listener already announced.
    ///
    /// Before edge-triggering, the diff ran against the port registry alone, so
    /// an unregistered listener re-fired every cycle — five Warning-severity
    /// security findings per scan, 300 seconds apart, for a host whose state
    /// was not changing.
    ///
    /// Uses the live host rather than a fixture because `scan_and_diff` calls
    /// `listeners::get_all()` directly. That makes the first count
    /// environment-dependent, so the assertion is about the *second* scan: no
    /// listener announced twice from unchanged state. On a host with no
    /// unregistered listeners both counts are zero and the test is vacuous but
    /// still correct.
    #[test]
    fn second_scan_is_quiet_for_unchanged_listeners() {
        let config = DiscoveryConfig::default();
        let known: Vec<KnownBinding> = Vec::new();
        let mut reported = HashSet::new();

        let first = scan_and_diff(&config, &known, &mut reported).expect("first scan");
        let first_new = first
            .iter()
            .filter(|e| matches!(e, SensorEvent::NewListenerDiscovered { .. }))
            .count();

        // Snapshot before the second scan replaces it. Comparing against the
        // post-scan `reported` would match every event, since each candidate
        // joins the set whether or not it was announced.
        let seen_in_first = reported.clone();

        let second = scan_and_diff(&config, &known, &mut reported).expect("second scan");
        let repeats: Vec<_> = second
            .iter()
            .filter_map(|e| match e {
                SensorEvent::NewListenerDiscovered { pid, process_name, .. }
                    // Only a listener present in the first scan is a repeat; one
                    // that appeared between the two scans is a genuine discovery
                    // and must still be announced.
                    if seen_in_first.contains(&(*pid, process_name.clone())) =>
                {
                    Some(format!("{} (pid {})", process_name, pid))
                }
                _ => None,
            })
            .collect();

        assert!(
            repeats.is_empty(),
            "listeners re-announced from unchanged state after {} initial discoveries: {:?}",
            first_new,
            repeats
        );
    }
}
