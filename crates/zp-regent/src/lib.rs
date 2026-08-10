//! The Regent — ZeroPoint's apex cognitive entity.
//!
//! The Regent is the operator's primary agent: a persistent cognitive
//! presence that governs on behalf of the sovereign. It perceives the
//! substrate's state through the audit chain and officer findings,
//! reasons about what matters, delegates to sub-agents for execution,
//! and presents results through cockpit surfaces (regent chat, CLI, visual).
//!
//! The Regent is not the operator. The operator signs; the Regent acts.
//! Every action the Regent takes is chain-anchored and officer-observed.
//! The Regent's authority is always delegated, never inherent.
//!
//! The title "Regent" is deliberately temporary — the operator can rename
//! their cognitive entity via a `regent:named` receipt at any time.
//!
//! See `docs/ARCHITECTURE-2026-07.md` Part II for the full cognitive
//! architecture specification.

pub mod approvals;
pub mod awareness;
pub mod cognitive_observer;
pub mod cognitive_observer_semantic;
pub mod config;
pub mod context;
pub mod corrections;
pub mod error;
pub mod evaluation;
pub mod events;
pub mod inference;
pub mod inference_classifier;
pub mod intent;
pub mod loop_runner;
pub mod memory;
pub mod persona;
pub mod precedent;
pub mod regent;
pub mod routing;
pub mod shadow_validation;
pub mod text;
pub mod tools;

// Re-export key types for ergonomic access from downstream crates.
pub use regent::{OperatorModelPin, PinStatus, ShadowCandidate, ShadowCandidateState};
pub use shadow_validation::{EvaluationTier, ShadowBatteryResult, ShadowCheckResult};
