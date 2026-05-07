//! ZeroPoint × Cloudflare adapter layer.
//!
//! # The wire
//!
//! This crate is the **only** place in the ZeroPoint workspace allowed
//! to import Cloudflare-specific Rust types — `worker::*`,
//! `cloudflare::*`, `cf_workers_*`, etc. The boundary is mechanically
//! enforced by the discipline pin
//! `no_cloudflare_imports_in_zp_crates` (see
//! `crates/zp-discipline/tests/no_cloudflare_imports_in_zp_crates.rs`).
//!
//! Every other `zp-*` crate is pure ZeroPoint: it defines port traits
//! and wire types, and it never knows what platform implements them.
//! This crate is the bridge.
//!
//! # Layout
//!
//! ```text
//! crates/zp-cloudflare/
//! ├── src/
//! │   ├── lib.rs          (this file — module declarations + docs)
//! │   ├── wire/           (cross-boundary types: pure Rust, no CF deps)
//! │   │   └── mod.rs
//! │   └── adapter/        (impls of ZP ports using CF primitives)
//! │       └── mod.rs
//! └── Cargo.toml
//! ```
//!
//! # Boundary rules
//!
//! Three rules govern this crate. They are also documented in
//! `docs/STACK-CLOUDFLARE-2026-05.md` ("Boundaries: ports, adapters,
//! wires"):
//!
//! 1. **No Cloudflare types upstream of this crate.** The `zp-*` crates
//!    in `crates/` (other than this one) must not reference any
//!    Cloudflare types. The discipline pin enforces this.
//!
//! 2. **All ZP↔CF transitions emit receipts.** Every adapter method
//!    that crosses the boundary emits an audit-chain receipt
//!    describing the call: which port, which adapter, the canonical
//!    hash of the request and response. The adapter is a trust-
//!    boundary crossing; receipts are the wire.
//!
//! 3. **Adapters are substitutable.** Every adapter has at least one
//!    fallback implementation documented (self-hosted or another
//!    vendor). The fallback need not be production-ready today, but
//!    the *port* must be defined such that a fallback adapter is a
//!    finite engineering project, not a rewrite.
//!
//! # Status
//!
//! Phase 1.0 — scaffold only. No adapter implementations yet. Each
//! later phase in `docs/STACK-CLOUDFLARE-2026-05.md` adds an adapter:
//!
//! - Phase 1.2 — `WorkersAIInferenceAdapter` (Inference port)
//! - Phase 2.1 — `VectorizeIndexAdapter` (VectorIndex port)
//! - Phase 2.2 — `CfQueueFleetBusAdapter` (FleetBus port)
//! - Phase 2.3 — `CfWorkflowAdapter` (GovernedWorkflow port)
//! - (Future) — `D1AuditStoreAdapter` (AuditStore port)

pub mod wire;
pub mod adapter;
