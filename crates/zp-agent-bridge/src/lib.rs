//! # zp-agent-bridge — Connects agent-zp to ZeroPoint native infrastructure
//!
//! This crate provides the concrete adapters that bridge agent-zp's abstract
//! traits (`AuditSink`, `SovereigntyBridge`) to ZeroPoint's actual implementations
//! (`AuditStore`, `SovereigntyProvider`).
//!
//! ## Architecture
//!
//! ```text
//! agent-zp (claw-code-rust)          zp-agent-bridge          ZeroPoint
//! ┌─────────────────────┐    ┌────────────────────────┐    ┌──────────────────┐
//! │ AuditSink trait      │───▶│ ZpAuditSink            │───▶│ AuditStore       │
//! │ SovereigntyBridge    │───▶│ ZpSovereigntyBridge    │───▶│ SovereigntyProvider │
//! │ DelegationPolicy     │───▶│ ZpDelegationPolicy     │───▶│ DelegationChain  │
//! │ QuorumPolicy         │───▶│ ZpQuorumPolicy         │───▶│ ConsensusCoord.  │
//! │ MeshTransport        │───▶│ ZpMeshTransport        │───▶│ MeshNode         │
//! └─────────────────────┘    └────────────────────────┘    └──────────────────┘
//! ```

mod audit_bridge;
mod delegation_bridge;
mod mesh_bridge;
mod quorum_bridge;
mod sovereignty_bridge;

pub use audit_bridge::*;
pub use delegation_bridge::*;
pub use mesh_bridge::*;
pub use quorum_bridge::*;
pub use sovereignty_bridge::*;
