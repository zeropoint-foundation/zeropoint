//! ZeroPoint artifact library — content-addressed, signed, lifecycle-managed renderings.
//!
//! The artifact library is the "editorial layer" of the substrate:
//! - Receipts are facts (signed, chain-anchored data)
//! - Artifacts are renderings of facts (cached, content-addressed, optionally signed)
//! - Signed artifacts are decisions (operator-endorsed canonical references)
//!
//! ## Lifecycle
//!
//! ```text
//! Candidate (auto-generated) → Signed (operator-approved) → Superseded (replaced)
//!                           ↘ Rejected (operator-declined, kept for audit)
//! ```
//!
//! ## Storage
//!
//! Artifact bytes are stored in `zp_content::ContentStore`. Lifecycle state and
//! metadata are tracked in a separate SQLite index. The `ArtifactId` (semantic
//! identity) and the `ContentId` of the stored blob are intentionally distinct.

pub mod artifact;
pub mod index;
pub mod kinds;
pub mod library;
pub mod local;

pub use artifact::{
    ArtifactId, ArtifactKind, ArtifactContent, ArtifactSignature, Artifact, LifecycleState,
    LibraryError, LibraryFilter, LibraryStateFilter, RenderConfig, SourceManifest,
    compute_artifact_id,
};
pub use library::Library;
pub use local::LocalArtifactLibrary;
