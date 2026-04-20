//! ZeroPoint v2 Core — shared types, traits, and error definitions.
//!
//! This crate is the foundation that all other ZeroPoint crates depend on.
//! It defines the vocabulary types used across the system: requests, responses,
//! capabilities, policy decisions, audit entries, and the trait interfaces
//! that the deterministic core enforces.

pub mod audit;
pub mod capability;
pub mod capability_grant;
pub mod delegation_chain;
pub mod episode;
pub mod epistemic;
pub mod error;
pub mod governance;
pub mod internal_token;
pub mod paths;
pub mod policy;
pub mod provider;
pub mod receipt_emission;
pub mod skill;
pub mod types;

// Re-export commonly used types at crate root
pub use audit::{ActorId, AuditAction, AuditEntry, AuditId};
pub use capability::{Capability, ModelClass, ModelPreference, PipelineResult, ToolDefinition};
pub use capability_grant::{
    CapabilityGrant, Constraint, ConstraintContext, ConstraintViolation, DelegationError,
    GrantProvenance, GrantedCapability, IssuanceError,
};
pub use delegation_chain::{ChainError, DelegationChain};
pub use episode::{Episode, EpisodeId, Feedback, FeedbackRating, Outcome, Pattern};
pub use epistemic::{Epistemic, EpistemicError, EpistemicStatus, StatusTransition};
pub use error::ZpError;
pub use governance::{
    ConsensusThreshold, EventOrigin, EventProvenance, GovernanceActor, GovernanceDecision,
    GovernanceEvent, GovernanceEventType,
};
pub use internal_token::{
    InternalCapabilityToken, InternalScope, InternalTokenAuthority, TokenError,
};
pub use policy::{
    ActionType, FileOperation, MeshAction, MeshPeerContext, PolicyMetadata, ReviewTarget,
    RiskLevel, SanitizePattern,
};
pub use policy::{PolicyContext, PolicyDecision, TrustTier};
pub use provider::{ProviderCapabilities, ProviderHealth, ProviderId};
pub use receipt_emission::{emit_authorization_receipt, emit_delegation_receipt, emit_revocation_receipt};
pub use skill::{CandidateStatus, SkillCandidate, SkillId, SkillManifest, SkillOrigin, SkillStats};
pub use types::*;
