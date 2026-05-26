//! Core artifact types for the ZeroPoint artifact library.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zp_content::ContentId;

/// Semantic identity of an artifact — BLAKE3 of (source_manifest_bytes || render_config_bytes).
///
/// Newtype over `ContentId` rather than a type alias: the artifact_id/content_store_id
/// distinction is load-bearing (same semantic artifact, different storage blobs as state
/// transitions occur). A type alias lets the compiler silently accept the wrong id;
/// a newtype forces explicit conversion at every boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactId(pub ContentId);

impl ArtifactId {
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    pub fn from_hex(s: &str) -> Result<Self, zp_content::ContentError> {
        ContentId::from_hex(s).map(ArtifactId)
    }

    pub fn content_id(&self) -> &ContentId {
        &self.0
    }
}

impl std::fmt::Display for ArtifactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Compute the artifact_id from a source manifest and render config.
///
/// `artifact_id = BLAKE3(sorted_json(manifest) || json(config))`
///
/// Callers must provide `receipt_ids` in stable (sorted) order so the
/// identity is deterministic across generators.
pub fn compute_artifact_id(manifest: &SourceManifest, config: &RenderConfig) -> ArtifactId {
    let mut sorted = manifest.clone();
    sorted.receipt_ids.sort();
    let mut bytes = serde_json::to_vec(&sorted).expect("manifest serialization is infallible");
    bytes.extend_from_slice(&serde_json::to_vec(config).expect("config serialization is infallible"));
    ArtifactId(ContentId::from_bytes(&bytes))
}

/// The artifact kinds supported by the library.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ChainNarration,
    // Calendar, Timeline, Digest — v0.1 kinds
}

impl ArtifactKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ArtifactKind::ChainNarration => "chain_narration",
        }
    }
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Lifecycle state of an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LifecycleState {
    Candidate,
    Signed,
    /// The artifact has been superseded by a newer signed artifact.
    Superseded {
        /// hex ArtifactId of the artifact that superseded this one.
        by: String,
    },
    Rejected,
}

/// The exact set of receipts (and chain head) that contributed to an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceManifest {
    /// Receipt ids that contributed, in sorted order (caller must sort).
    pub receipt_ids: Vec<String>,
    /// Chain head — the latest receipt_id at generation time.
    pub chain_head: String,
}

/// Versioned rendering configuration — changes here produce new artifact_ids.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderConfig {
    pub composition_rules_version: u32,
    pub voice_anchor_version: u32,
    pub render_function_version: u32,
    pub llm_provider: String,
    pub llm_model: String,
    /// hex BLAKE3 of serialized LLM params (temperature, top_p, etc.)
    pub llm_params_hash: String,
}

/// The rendered bytes and their format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactContent {
    /// MIME type: "text/markdown", "text/html", "audio/mpeg", …
    pub mime_type: String,
    /// Raw rendered bytes (text or binary).
    pub body: Vec<u8>,
}

/// Ed25519 signature attached when an operator promotes a candidate to signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSignature {
    /// hex 32-byte Ed25519 verifying key (operator's Genesis-derived key).
    pub signer_pubkey: String,
    pub signed_at: DateTime<Utc>,
    /// hex 64-byte Ed25519 signature over canonical(artifact_for_signing).
    pub sig: String,
    /// Receipt id that recorded this signing event (filled by HTTP handler).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_receipt_id: Option<String>,
}

/// A content-addressed, lifecycle-managed rendering of substrate receipts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Semantic identity: BLAKE3(manifest || config). Stable across state transitions.
    pub artifact_id: String, // hex ArtifactId
    pub kind: ArtifactKind,
    pub source_manifest: SourceManifest,
    pub render_config: RenderConfig,
    pub content: ArtifactContent,
    /// Operator public key hex (identifies which operator this artifact belongs to).
    pub operator_id: String,
    pub generated_at: DateTime<Utc>,
    /// hex ArtifactId of the prior signed artifact of the same kind this replaces, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    pub lifecycle: LifecycleState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ArtifactSignature>,
}

impl Artifact {
    /// Serialize the artifact in canonical form for signing.
    ///
    /// Excludes `lifecycle` and `signature` so the signature is stable
    /// across state transitions (candidate → signed, signed → superseded).
    pub fn canonical_bytes_for_signing(&self) -> Vec<u8> {
        // Only the immutable fields participate in the signature.
        let signable = SignableArtifact {
            artifact_id: &self.artifact_id,
            kind: &self.kind,
            source_manifest: &self.source_manifest,
            render_config: &self.render_config,
            content_mime_type: &self.content.mime_type,
            content_body: &self.content.body,
            operator_id: &self.operator_id,
            generated_at: self.generated_at,
            supersedes: self.supersedes.as_deref(),
        };
        serde_json::to_vec(&signable).expect("signable artifact serialization is infallible")
    }
}

/// Internal: the immutable fields that participate in the Ed25519 signature.
/// Excludes `lifecycle` and `signature` fields.
#[derive(Serialize)]
struct SignableArtifact<'a> {
    artifact_id: &'a str,
    kind: &'a ArtifactKind,
    source_manifest: &'a SourceManifest,
    render_config: &'a RenderConfig,
    content_mime_type: &'a str,
    content_body: &'a Vec<u8>,
    operator_id: &'a str,
    generated_at: DateTime<Utc>,
    supersedes: Option<&'a str>,
}

/// Errors returned by Library operations.
#[derive(Debug, thiserror::Error)]
pub enum LibraryError {
    #[error("storage: {0}")]
    Storage(#[from] zp_content::ContentError),
    #[error("index: {0}")]
    Index(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("wrong lifecycle state for this operation: {0}")]
    WrongState(String),
    #[error("signing: {0}")]
    Signing(String),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Filter for `Library::list`.
#[derive(Debug, Clone, Default)]
pub struct LibraryFilter {
    pub kind: Option<ArtifactKind>,
    pub state: Option<LibraryStateFilter>,
    pub operator_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    /// Max results. Backends treat 0 as "use default" (100).
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibraryStateFilter {
    Candidate,
    Signed,
    Superseded,
    Rejected,
}

impl LibraryStateFilter {
    pub fn as_str(&self) -> &'static str {
        match self {
            LibraryStateFilter::Candidate => "candidate",
            LibraryStateFilter::Signed => "signed",
            LibraryStateFilter::Superseded => "superseded",
            LibraryStateFilter::Rejected => "rejected",
        }
    }
}
