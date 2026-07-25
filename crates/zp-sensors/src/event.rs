//! Sensor events — the unit of sensor output.
//!
//! Each variant carries enough context for Forge to decide whether to
//! activate and what to check. Events are cheap value types — the sensor
//! layer produces them, Forge consumes them.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::process::ProcessContext;

/// An event emitted by the sensor layer.
///
/// Forge subscribes to these. Each event type maps to a specific Forge
/// check method (see design doc §3 activation table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensorEvent {
    /// A watched file was modified, renamed, or deleted.
    ///
    /// Covers `tool-ports.json`, `.zp-configure.toml`, and any other
    /// governance-relevant files registered with the sensor layer.
    FileChanged {
        path: PathBuf,
        timestamp: DateTime<Utc>,
    },

    /// A watched process exited, was signaled, forked, or exec'd.
    ///
    /// The PID was registered when the tool entered the port registry.
    /// This covers governed tools whose PIDs we already know.
    ProcessEvent {
        pid: u32,
        tool_name: String,
        kind: ProcessEventKind,
        timestamp: DateTime<Utc>,
    },

    /// A new listening process was discovered that isn't in the port registry.
    ///
    /// Emitted by the periodic `listeners` scan when it finds a process
    /// binding a port that no registered tool owns. Includes enriched
    /// process context for human-readable identification.
    NewListenerDiscovered {
        pid: u32,
        process_name: String,
        ports: Vec<DiscoveredPort>,
        /// Enriched process metadata — binary path, command line, user,
        /// parent process, start time. Best-effort; fields may be `None`.
        context: ProcessContext,
        timestamp: DateTime<Utc>,
    },

    /// A registered tool's port binding changed — it's listening on a
    /// different port than the registry expects.
    PortMismatch {
        tool_name: String,
        pid: u32,
        expected_port: u16,
        actual_ports: Vec<u16>,
        timestamp: DateTime<Utc>,
    },

    /// A registered tool's process disappeared — PID no longer in
    /// the process table, but the registry still has a binding.
    RegistryStale {
        tool_name: String,
        expected_pid: u32,
        timestamp: DateTime<Utc>,
    },
}

/// What happened to a watched process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessEventKind {
    /// Process exited (normal or crash).
    Exit,
    /// Process forked a child.
    Fork,
    /// Process called exec (replaced its image).
    Exec,
    /// Process received a signal.
    Signal,
}

/// A port discovered by the `listeners` crate scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPort {
    pub port: u16,
    pub protocol: String,
    pub socket: String,
}

impl SensorEvent {
    /// Short label for logging/receipts.
    pub fn kind_label(&self) -> &'static str {
        match self {
            Self::FileChanged { .. } => "file_changed",
            Self::ProcessEvent { .. } => "process_event",
            Self::NewListenerDiscovered { .. } => "new_listener",
            Self::PortMismatch { .. } => "port_mismatch",
            Self::RegistryStale { .. } => "registry_stale",
        }
    }

    /// Extract the tool name associated with this event, if known.
    ///
    /// Returns `None` for events that aren't tool-specific (e.g.
    /// `FileChanged` on `tool-ports.json` affects all tools).
    /// Used by the Forge deactivation logic to decide whether a
    /// dormant tool should be reactivated.
    pub fn tool_name(&self) -> Option<&str> {
        match self {
            Self::ProcessEvent { tool_name, .. } => Some(tool_name.as_str()),
            Self::PortMismatch { tool_name, .. } => Some(tool_name.as_str()),
            Self::RegistryStale { tool_name, .. } => Some(tool_name.as_str()),
            Self::FileChanged { .. } | Self::NewListenerDiscovered { .. } => None,
        }
    }
}
