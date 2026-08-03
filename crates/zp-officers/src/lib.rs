//! System Officer Cadre — dormant integrity/security/operations/governance/trajectory monitors.
//!
//! Five officers — Steward, Sentinel, Forge, Cleo, Aegis — activate on chain
//! events or periodic sweeps to check system health, narrate authority flow,
//! and monitor trajectory-level substrate coherence. They are read-only
//! observers: their only write path is appending finding receipts to the chain.
//!
//! - **Steward** (`std`): integrity — chain hash integrity, vault coherence.
//! - **Sentinel** (`sen`): security — identity anomalies, credential drift.
//! - **Forge** (`forge`): operations — tool/process health.
//! - **Cleo** (`cleo`): governance — delegation lifecycle, gate decisions, authority chains.
//! - **Aegis** (`aegis`): trajectory — constitutional-trajectory monitoring;
//!   best-effort detection of misaligned trajectories. Advisory, not enforcement.
//!
//! See `docs/design/SYSTEM-OFFICER-CADRE-2026-06.md`,
//! `docs/design/CHAIN-STORYTELLING-AND-CLEO-2026-06.md`,
//! `docs/design/TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md`,
//! and `docs/design/OFFICER-LENS-DECLARATIONS-2026-07.md` for full specs.

pub mod aegis;
pub mod chain_reads;
pub mod cleo;
pub mod finding;
pub mod forge;
pub mod governance_posture;
pub mod narration;
pub mod officer;
pub mod posture;
pub mod proposal;
pub mod request;
pub mod sentinel;
pub mod steward;
pub mod sweep;
