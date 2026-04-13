//! ZeroPoint Policy Engine — native Rust rules + optional WASM policy modules.
//!
//! This crate provides the policy evaluation engine that determines what actions
//! an AI operator can perform. It evaluates requests against a set of policy rules
//! and returns graduated PolicyDecision results (Block > Review > Warn > Sanitize > Allow).
//!
//! The native Rust rules (constitutional + operational) are always available.
//! WASM policy module loading via wasmtime is optional — enable with:
//! `cargo build --features policy-wasm`

pub mod engine;
pub mod gate;
pub mod rules;

#[cfg(feature = "policy-wasm")]
pub mod policy_registry;
#[cfg(feature = "policy-wasm")]
pub mod wasm_runtime;

// Re-export commonly used types — always available
pub use engine::PolicyEngine;
pub use gate::{GateResult, GovernanceGate};
pub use rules::{PolicyRule, ReputationGateRule, ReputationThresholds};

// WASM types — only available with policy-wasm feature
#[cfg(feature = "policy-wasm")]
pub use policy_registry::{ModuleStatus, PolicyModuleRegistry};
#[cfg(feature = "policy-wasm")]
pub use wasm_runtime::{WasmModuleMetadata, WasmPolicyError, WasmPolicyModule, WasmRuntime};
