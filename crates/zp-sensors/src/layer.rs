//! Sensor layer — the unified interface that Forge subscribes to.
//!
//! Composes the kqueue sensor and discovery scanner behind a single
//! event stream. Forge calls `SensorLayer::start()` to get a handle
//! and a receiver, then selects on the receiver alongside its chain
//! subscription.

use std::path::{Path, PathBuf};

use tokio::sync::mpsc;
use tracing::info;

use crate::discovery::{DiscoveryConfig, KnownBinding};
use crate::event::SensorEvent;

/// Configuration for the sensor layer.
#[derive(Debug, Clone)]
pub struct SensorLayerConfig {
    /// Files to watch on startup (e.g., tool-ports.json path).
    pub initial_files: Vec<PathBuf>,
    /// Discovery scanner config.
    pub discovery: DiscoveryConfig,
    /// Channel buffer size for sensor events.
    pub event_buffer: usize,
}

impl Default for SensorLayerConfig {
    fn default() -> Self {
        Self {
            initial_files: Vec::new(),
            discovery: DiscoveryConfig::default(),
            event_buffer: 64,
        }
    }
}

/// Handle for interacting with a running sensor layer.
///
/// Cloneable. Used by:
/// - `zp-server` to register/unregister PIDs and files as tools come and go
/// - The discovery scanner gets binding updates through this handle
#[derive(Clone)]
pub struct SensorLayerHandle {
    /// Send kqueue commands (file/pid watch registration).
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    kq_cmd_tx: mpsc::Sender<crate::kqueue::KqueueCommand>,

    /// Update known bindings for the discovery scanner.
    known_tx: tokio::sync::watch::Sender<Vec<KnownBinding>>,
}

/// The sensor layer — owns the kqueue sensor and discovery scanner.
///
/// Start with [`SensorLayer::start`], which spawns background tasks and
/// returns a handle + event receiver.
pub struct SensorLayer;

impl SensorLayer {
    /// Start the sensor layer as background tokio tasks.
    ///
    /// Returns a handle for dynamic registration and a receiver for
    /// consuming sensor events.
    pub fn start(config: SensorLayerConfig) -> (SensorLayerHandle, mpsc::Receiver<SensorEvent>) {
        let (event_tx, event_rx) = mpsc::channel(config.event_buffer);
        let (known_tx, known_rx) = tokio::sync::watch::channel(Vec::<KnownBinding>::new());

        // Spawn the kqueue sensor task (macOS/FreeBSD only).
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let kq_cmd_tx = {
            let (cmd_tx, cmd_rx) = mpsc::channel(32);
            let kq_event_tx = event_tx.clone();
            let initial_files = config.initial_files.clone();

            tokio::spawn(async move {
                crate::kqueue::run_kqueue_sensor(initial_files, cmd_rx, kq_event_tx).await;
            });

            info!(files = config.initial_files.len(), "kqueue sensor started");
            cmd_tx
        };

        // Spawn the discovery scanner task.
        let disc_event_tx = event_tx;
        let disc_config = config.discovery;
        tokio::spawn(async move {
            info!("Discovery scanner starting");
            crate::discovery::run_discovery(disc_config, disc_event_tx, known_rx).await;
        });

        let handle = SensorLayerHandle {
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            kq_cmd_tx,
            known_tx,
        };

        (handle, event_rx)
    }
}

impl SensorLayerHandle {
    /// Register a file for change notifications.
    pub async fn watch_file(&self, path: impl AsRef<Path>) {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            use crate::kqueue::KqueueCommand;
            let _ = self
                .kq_cmd_tx
                .send(KqueueCommand::WatchFile(path.as_ref().to_path_buf()))
                .await;
        }
    }

    /// Stop watching a file.
    pub async fn unwatch_file(&self, path: impl AsRef<Path>) {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            use crate::kqueue::KqueueCommand;
            let _ = self
                .kq_cmd_tx
                .send(KqueueCommand::UnwatchFile(path.as_ref().to_path_buf()))
                .await;
        }
    }

    /// Register a tool's PID for process lifecycle notifications.
    pub async fn watch_pid(&self, pid: u32, tool_name: String) {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            use crate::kqueue::KqueueCommand;
            let _ = self
                .kq_cmd_tx
                .send(KqueueCommand::WatchPid { pid, tool_name })
                .await;
        }
    }

    /// Stop watching a process.
    pub async fn unwatch_pid(&self, pid: u32) {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            use crate::kqueue::KqueueCommand;
            let _ = self.kq_cmd_tx.send(KqueueCommand::UnwatchPid(pid)).await;
        }
    }

    /// Update the set of known bindings used by the discovery scanner.
    ///
    /// Call this whenever the port registry changes so the scanner knows
    /// which processes are already governed.
    pub fn update_known_bindings(&self, bindings: Vec<KnownBinding>) {
        let _ = self.known_tx.send(bindings);
    }
}
