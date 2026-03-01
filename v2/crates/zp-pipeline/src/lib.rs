//! ZeroPoint Request Pipeline
//!
//! The central orchestrator that connects policy, skills, audit, and LLM components.
//! This module implements the core message handling flow as defined in ARCHITECTURE-V2.md §7.2.
//!
//! Phase 4 adds mesh integration: the pipeline can optionally forward receipts
//! and audit entries to mesh peers after each request completes.

pub mod config;
pub mod mesh_bridge;
pub mod pipeline;

pub use config::{MeshConfig, PipelineConfig};
pub use mesh_bridge::{MeshBridge, MeshBridgeConfig, PeerTrustSnapshot, ReceivedReceipt};
pub use pipeline::Pipeline;
