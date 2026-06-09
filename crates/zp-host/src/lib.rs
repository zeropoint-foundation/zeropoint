//! `zp-host` — the host-function boundary for ZeroPoint's WASM trust layer.
//!
//! ## What this crate is
//!
//! Every privileged side effect (process spawn, file write, network call)
//! must pass through a [`HostContext`] implementation.  The type system makes
//! ambient authority unrepresentable in production call paths:
//!
//! - There is no `Command::new` accessible to callers of this crate's public
//!   API.  The only spawn path is `HostContext::spawn_process`.
//! - `SystemHostContext` always consults the governance gate and always emits
//!   an audit receipt — these invariants hold by construction, not by
//!   convention.
//!
//! ## Architecture reference
//!
//! See `docs/ARCHITECTURE-2026-04.md` Part I §2 Commitment A and Part II
//! §Phase 1.  This crate is the Phase 1 deliverable: the host-function trait
//! and its first canonical implementation.
//!
//! ## Extension pattern
//!
//! To port a new privileged action:
//!
//! 1. Add a method to [`HostContext`] in `context.rs`.
//! 2. Implement it in [`SystemHostContext`] following the gate-receipt-exec
//!    pattern in `system.rs`.
//! 3. Replace the direct syscall at the call site with `host.<new_method>()`.
//!
//! Each new method reduces the ambient-authority surface by one more class of
//! side effect.

pub mod context;
pub mod error;
pub mod system;
pub mod types;

pub use context::HostContext;
pub use error::HostError;
pub use system::SystemHostContext;
pub use types::{HttpMethod, HttpRequest, HttpResult, SpawnRequest, SpawnResult, WriteMode, WriteRequest, WriteResult};
