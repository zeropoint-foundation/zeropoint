//! ZeroPoint v2 Skills — skill registry and matching system.
//!
//! This crate provides:
//! - **SkillRegistry**: A central registry for managing registered skills with their metadata, statistics, and enabled/disabled states.
//! - **SkillMatcher**: A matching engine that finds relevant skills for a given request based on keyword overlap.
//!
//! Phase 1 uses simple keyword matching. Semantic matching will be added in later phases.

pub mod matcher;
pub mod registry;

// Re-export main types for convenience
pub use matcher::SkillMatcher;
pub use registry::{RegisteredSkill, SkillRegistry};

pub use zp_core::{SkillId, SkillManifest, SkillOrigin, SkillStats};
