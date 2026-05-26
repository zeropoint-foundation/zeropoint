//! The `Library` trait — the singular substrate primitive for artifact lifecycle management.

use async_trait::async_trait;
use ed25519_dalek::SigningKey;

use crate::artifact::{Artifact, ArtifactId, ArtifactKind, LibraryError, LibraryFilter};

/// The singular substrate primitive for content-addressed, signed artifact lifecycle management.
///
/// Implementors: `LocalArtifactLibrary` (this crate); cloud-backed libraries via `zp-cloudflare`.
///
/// No direct R2/D1/KV calls. Backed by `zp_content::ContentStore` for byte storage;
/// SQLite for lifecycle state and metadata queries.
#[async_trait]
pub trait Library: Send + Sync {
    /// Store a candidate artifact. Returns its `ArtifactId`.
    ///
    /// Idempotent: storing the same artifact_id again is a no-op if already present.
    async fn store_candidate(&self, artifact: &Artifact) -> Result<ArtifactId, LibraryError>;

    /// Fetch an artifact by id. Returns `None` if not present.
    async fn get(&self, id: &ArtifactId) -> Result<Option<Artifact>, LibraryError>;

    /// Sign a candidate — attaches Ed25519 signature and transitions to `Signed`.
    ///
    /// If `artifact.supersedes` is set, the prior artifact transitions to `Superseded`.
    /// Emitting the `ArtifactSignedClaim` receipt is the caller's responsibility.
    async fn sign(
        &self,
        id: &ArtifactId,
        signing_key: &SigningKey,
        signer_pubkey: [u8; 32],
    ) -> Result<(), LibraryError>;

    /// Reject a candidate — transitions to `Rejected`, kept for audit.
    async fn reject(&self, id: &ArtifactId) -> Result<(), LibraryError>;

    /// List artifact ids matching `filter`.
    async fn list(&self, filter: &LibraryFilter) -> Result<Vec<ArtifactId>, LibraryError>;

    /// Latest signed artifact of a given kind for an operator. Returns `None` if none exist.
    async fn latest_signed(
        &self,
        kind: &ArtifactKind,
        operator_id: &str,
    ) -> Result<Option<Artifact>, LibraryError>;
}
