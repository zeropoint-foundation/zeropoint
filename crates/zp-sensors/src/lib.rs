//! Event-driven sensor layer for ZeroPoint governance.
//!
//! Three sensor mechanisms, all unprivileged:
//!
//! - **kqueue `EVFILT_VNODE`** — file change notifications for governance files
//!   (`tool-ports.json`, `.zp-configure.toml`).
//! - **kqueue `EVFILT_PROC`** — process lifecycle events (exit, fork, exec) for
//!   known tool PIDs.
//! - **`listeners` crate** — periodic port scan (~1ms) for discovering new
//!   unregistered processes.
//!
//! The sensor layer emits [`SensorEvent`]s through a tokio broadcast channel.
//! Forge subscribes and activates only when an event fires — immune system
//! model, not cardiac.

pub mod discovery;
pub mod event;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub mod kqueue;
pub mod layer;

pub use discovery::{DiscoveryConfig, KnownBinding};
pub use event::{ProcessEventKind, SensorEvent};
pub use layer::{SensorLayer, SensorLayerConfig, SensorLayerHandle};
