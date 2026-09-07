//! ZeroPoint ontology layer + Cartographer materialization.
//!
//! Derived object graph over the receipt chain. Cartographer materializes
//! Trajectories, Decisions, Insights, Artifacts, Frictions from chain-anchored
//! receipts; officers, Regent, and dashboards query the ontology via
//! `OntologyReader` snapshots.
//!
//! ## Design docs
//!
//! - `docs/design/ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` — parent what-spec
//! - `docs/design/CARTOGRAPHER-IMPLEMENTATION-DESIGN-2026-07.md` — how-spec
//!
//! ## Phase status (2026-07-25)
//!
//! - **P0 (scaffolding + schema + meta)**: this crate's landing point
//! - **P1 (object CRUD)**: pending
//! - **P2 (Tier 1 boundary detection: S1, S2, S5)**: pending
//! - **P3 (Cartographer background task in zp-server)**: pending
//! - **P4 (full 5-signal boundary detection + resumption)**: pending
//! - **P5 (OntologyReader + officer integration)**: pending
//! - **P6 (operator correction CLI verbs)**: pending
//! - **P7 (Aegis v2 integration)**: pending

pub mod boundary;
pub mod error;
pub mod id;
pub mod objects;
pub mod relationships;
pub mod store;

pub use boundary::{
    canonicalize_boundary_signals, classify_explicit_marker, evaluate_boundary,
    signal_conversation_continuity, signal_explicit_marker, signal_time_gap, BoundaryConfig,
    BoundaryDecision, BoundaryInput, BoundaryReason, BoundarySignals, ExplicitMarkerKind,
    TrajectoryContext,
};
pub use error::{ReadError, StoreError};
pub use id::{
    derive_object_id, derive_relationship_id, derive_trajectory_id, ObjectId, ObjectType,
};
pub use objects::{
    Artifact, ArtifactStatus, ArtifactType, Decision, DecisionStatus, Friction, FrictionSeverity,
    FrictionStatus, Insight, OntologyObject, Trajectory, TrajectoryStatus,
};
pub use relationships::{ObjectRef, Relationship, RelationshipKind};
pub use store::{meta_keys, OntologyStore};
