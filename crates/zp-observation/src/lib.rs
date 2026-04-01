//! Receipt-backed Observational Memory for ZeroPoint agents.
//!
//! Adapts the Observational Memory pattern (Observer → Reflector → Actor) to
//! leverage ZeroPoint's Blake3 hash-chained, Ed25519-signed receipt system.
//!
//! Observations are themselves receipts that cryptographically reference the
//! source receipt range they were distilled from. This means any observation
//! can be verified against the raw chain, and the observation chain itself is
//! tamper-evident.

pub mod config;
pub mod observer;
pub mod reflector;
pub mod store;
pub mod types;

pub use config::*;
pub use observer::{build_observer_prompt, parse_observer_output, OBSERVER_SYSTEM_PROMPT};
pub use reflector::{
    apply_reflector_actions, build_reflector_prompt, parse_reflector_output,
    REFLECTOR_SYSTEM_PROMPT,
};
pub use store::*;
pub use types::*;
