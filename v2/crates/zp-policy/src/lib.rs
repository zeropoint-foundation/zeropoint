//! ZeroPoint Policy Engine — native Rust rules + WASM policy modules.
//!
//! This crate provides the policy evaluation engine that determines what actions
//! an AI operator can perform. It evaluates requests against a set of policy rules
//! and returns graduated PolicyDecision results (Block > Review > Warn > Sanitize > Allow).
//!
//! Phase 1 provides native Rust rules (constitutional + operational).
//! Phase 2 adds WASM policy module loading via wasmtime, enabling user-defined
//! and governance-signed policy modules to be loaded at runtime.

pub mod engine;
pub mod gate;
pub mod policy_registry;
pub mod rules;
pub mod wasm_runtime;

// Re-export commonly used types
pub use engine::PolicyEngine;
pub use gate::{GateResult, GovernanceGate};
pub use policy_registry::{ModuleStatus, PolicyModuleRegistry};
pub use rules::{PolicyRule, ReputationGateRule, ReputationThresholds};
pub use wasm_runtime::{WasmModuleMetadata, WasmPolicyError, WasmPolicyModule, WasmRuntime};
