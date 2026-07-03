//! System Officer Cadre — dormant integrity/security/operations/governance monitors.
//!
//! Four officers — Steward, Sentinel, Forge, Cleo — activate on chain events
//! or periodic sweeps to check system health and narrate authority flow.
//! They are read-only observers: their only write path is appending finding
//! receipts to the chain.
//!
//! - **Steward** (`std`): integrity — chain hash integrity, vault coherence.
//! - **Sentinel** (`sen`): security — identity anomalies, credential drift.
//! - **Forge** (`forge`): operations — tool/process health.
//! - **Cleo** (`cleo`): governance — delegation lifecycle, gate decisions, authority chains.
//!
//! See `docs/design/SYSTEM-OFFICER-CADRE-2026-06.md` and
//! `docs/design/CHAIN-STORYTELLING-AND-CLEO-2026-06.md` for full specs.

pub mod cleo;
pub mod finding;
pub mod forge;
pub mod narration;
pub mod officer;
pub mod posture;
pub mod sentinel;
pub mod steward;
pub mod sweep;
