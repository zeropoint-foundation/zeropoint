//! Local artifact library: ContentStore-backed bytes + SQLite lifecycle index.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::Signer as _;
use tracing::debug;
use zp_content::{ContentMeta, ContentStore};

use crate::artifact::{
    Artifact, ArtifactId, ArtifactKind, ArtifactSignature, LibraryError, LibraryFilter,
    LifecycleState,
};
use crate::index::{ArtifactIndex, IndexRow};
use crate::library::Library;

pub struct LocalArtifactLibrary {
    store: Arc<dyn ContentStore>,
    index: ArtifactIndex,
}

impl LocalArtifactLibrary {
    /// Create a library backed by `store`, with a SQLite index at `index_path`.
    pub async fn new(
        store: Arc<dyn ContentStore>,
        index_path: &Path,
    ) -> Result<Self, LibraryError> {
        if let Some(parent) = index_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| LibraryError::Index(e.to_string()))?;
        }
        let index = ArtifactIndex::open(index_path)?;
        Ok(Self { store, index })
    }

    /// Convenience constructor using default paths under `$ZP_DATA_DIR`.
    pub async fn default_local(store: Arc<dyn ContentStore>) -> Result<Self, LibraryError> {
        let base = std::env::var("ZP_DATA_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| "/tmp/ZeroPoint".into());
        let index_path = std::env::var("ZP_ARTIFACT_INDEX")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| base.join("artifact-index.db"));
        Self::new(store, &index_path).await
    }

    /// Store artifact bytes in the content store; return the content_store_id.
    async fn put_artifact_bytes(&self, artifact: &Artifact) -> Result<String, LibraryError> {
        let bytes = serde_json::to_vec(artifact)?;
        let meta = ContentMeta {
            kind: format!("artifact.{}.v0", artifact.kind.as_str()),
            created_at: artifact.generated_at,
            size_bytes: bytes.len() as u64,
            extensions: None,
        };
        let content_id = self.store.put(&bytes, meta).await?;
        Ok(content_id.to_hex())
    }

    /// Load artifact from content store by content_store_id hex.
    async fn load_artifact_bytes(&self, content_store_id: &str) -> Result<Artifact, LibraryError> {
        let cid = zp_content::ContentId::from_hex(content_store_id)?;
        let bytes = self.store.get(&cid).await?.ok_or_else(|| {
            LibraryError::NotFound(format!("content_store_id {content_store_id}"))
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

#[async_trait]
impl Library for LocalArtifactLibrary {
    async fn store_candidate(&self, artifact: &Artifact) -> Result<ArtifactId, LibraryError> {
        let artifact_id = ArtifactId::from_hex(&artifact.artifact_id)?;

        // Idempotent: if already present, return existing id
        if self.index.get(&artifact.artifact_id)?.is_some() {
            return Ok(artifact_id);
        }

        let content_store_id = self.put_artifact_bytes(artifact).await?;
        let row = IndexRow {
            artifact_id: artifact.artifact_id.clone(),
            content_store_id,
            operator_id: artifact.operator_id.clone(),
            kind: artifact.kind.as_str().to_string(),
            state: "candidate".to_string(),
            supersedes: artifact.supersedes.clone(),
            created_at_ms: artifact.generated_at.timestamp_millis(),
        };
        self.index.insert(&row)?;
        debug!("candidate stored: {}", artifact.artifact_id);
        Ok(artifact_id)
    }

    async fn get(&self, id: &ArtifactId) -> Result<Option<Artifact>, LibraryError> {
        let row = match self.index.get(&id.to_hex())? {
            Some(r) => r,
            None => return Ok(None),
        };
        let artifact = self.load_artifact_bytes(&row.content_store_id).await?;
        Ok(Some(artifact))
    }

    async fn sign(
        &self,
        id: &ArtifactId,
        signing_key: &ed25519_dalek::SigningKey,
        signer_pubkey: [u8; 32],
    ) -> Result<(), LibraryError> {
        let row = self.index.get(&id.to_hex())?.ok_or_else(|| {
            LibraryError::NotFound(id.to_hex())
        })?;

        if row.state != "candidate" {
            return Err(LibraryError::WrongState(format!(
                "expected candidate, found {}",
                row.state
            )));
        }

        let mut artifact = self.load_artifact_bytes(&row.content_store_id).await?;

        // Sign the canonical (immutable) bytes — excludes lifecycle + signature fields.
        let canonical = artifact.canonical_bytes_for_signing();
        let sig_bytes = signing_key.sign(&canonical);

        artifact.signature = Some(ArtifactSignature {
            signer_pubkey: hex::encode(signer_pubkey),
            signed_at: Utc::now(),
            sig: hex::encode(sig_bytes.to_bytes()),
            signing_receipt_id: None,
        });
        artifact.lifecycle = LifecycleState::Signed;

        // Re-store with signature attached; index points to new blob.
        let new_cid = self.put_artifact_bytes(&artifact).await?;
        self.index.update_state(&id.to_hex(), &new_cid, "signed")?;

        // Mark prior artifact as superseded if applicable.
        if let Some(prior_hex) = &artifact.supersedes {
            if let Some(prior_row) = self.index.get(prior_hex)? {
                // Load prior, update its lifecycle, re-store, update index.
                let mut prior = self.load_artifact_bytes(&prior_row.content_store_id).await?;
                prior.lifecycle = LifecycleState::Superseded { by: id.to_hex() };
                let prior_cid = self.put_artifact_bytes(&prior).await?;
                self.index.update_state(prior_hex, &prior_cid, "superseded")?;
            }
        }

        debug!("artifact signed: {}", id);
        Ok(())
    }

    async fn reject(&self, id: &ArtifactId) -> Result<(), LibraryError> {
        let row = self.index.get(&id.to_hex())?.ok_or_else(|| {
            LibraryError::NotFound(id.to_hex())
        })?;
        if row.state != "candidate" {
            return Err(LibraryError::WrongState(format!(
                "can only reject candidates, found {}",
                row.state
            )));
        }
        // Load + update state + re-store
        let mut artifact = self.load_artifact_bytes(&row.content_store_id).await?;
        artifact.lifecycle = LifecycleState::Rejected;
        let new_cid = self.put_artifact_bytes(&artifact).await?;
        self.index.update_state(&id.to_hex(), &new_cid, "rejected")?;
        Ok(())
    }

    async fn list(&self, filter: &LibraryFilter) -> Result<Vec<ArtifactId>, LibraryError> {
        let rows = self.index.list(filter)?;
        rows.iter()
            .map(|(id_hex, _)| ArtifactId::from_hex(id_hex).map_err(LibraryError::from))
            .collect()
    }

    async fn latest_signed(
        &self,
        kind: &ArtifactKind,
        operator_id: &str,
    ) -> Result<Option<Artifact>, LibraryError> {
        let Some((_, cid)) = self.index.latest_signed(kind, operator_id)? else {
            return Ok(None);
        };
        let artifact = self.load_artifact_bytes(&cid).await?;
        Ok(Some(artifact))
    }
}
