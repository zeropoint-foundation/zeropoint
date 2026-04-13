//! Memory promotion engine for ZeroPoint's cognition plane.
//!
//! Phase 4.3: Implements the doctrine's truth transition lifecycle.
//! Nothing becomes durable truth merely because a model inferred it.
//!
//! The promotion lifecycle maps epistemic stages to receipt-backed gates:
//!
//! | Stage          | Source                      | Receipt Type           |
//! |----------------|-----------------------------|------------------------|
//! | Transient      | Raw receipt chain output    | —                      |
//! | Observed       | Observer agent distillation | ObservationClaim       |
//! | Interpreted    | Reflector consolidation     | ReflectionClaim        |
//! | Trusted        | Policy gate + evidence      | PolicyClaim            |
//! | Remembered     | Promotion engine approval   | MemoryPromotionClaim   |
//! | IdentityBearing| Human review + signing      | MemoryPromotionClaim   |

pub mod promotion;
pub mod types;

pub use promotion::PromotionEngine;
pub use types::*;
