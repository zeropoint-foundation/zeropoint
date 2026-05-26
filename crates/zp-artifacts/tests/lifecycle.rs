//! Lifecycle state machine tests.

use std::sync::Arc;
use tempfile::TempDir;
use zp_artifacts::{ArtifactKind, Library, LibraryFilter, LibraryStateFilter, LocalArtifactLibrary};
use zp_artifacts::artifact::{Artifact, ArtifactContent, LifecycleState, RenderConfig, SourceManifest};
use zp_content::backends::LocalFsBackend;
use chrono::Utc;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

async fn make_library(tmp: &TempDir) -> LocalArtifactLibrary {
    let content_dir = tmp.path().join("content");
    let index_path = tmp.path().join("content-index.db");
    let store = Arc::new(LocalFsBackend::new(&content_dir, &index_path).await.unwrap());
    let artifact_index = tmp.path().join("artifact-index.db");
    LocalArtifactLibrary::new(store, &artifact_index).await.unwrap()
}

fn make_candidate(id_hex: Option<&str>) -> Artifact {
    let manifest = SourceManifest {
        receipt_ids: vec!["rcpt-001".into()],
        chain_head: "rcpt-001".into(),
    };
    let config = RenderConfig {
        composition_rules_version: 1,
        voice_anchor_version: 1,
        render_function_version: 1,
        llm_provider: "openai".into(),
        llm_model: "gpt-4o".into(),
        llm_params_hash: "abc".into(),
    };
    let artifact_id = id_hex
        .map(|s| s.to_string())
        .unwrap_or_else(|| zp_artifacts::compute_artifact_id(&manifest, &config).to_hex());

    Artifact {
        artifact_id,
        kind: ArtifactKind::ChainNarration,
        source_manifest: manifest,
        render_config: config,
        content: ArtifactContent {
            mime_type: "text/markdown".into(),
            body: b"Test narration body".to_vec(),
        },
        operator_id: "op-test".into(),
        generated_at: Utc::now(),
        supersedes: None,
        lifecycle: LifecycleState::Candidate,
        signature: None,
    }
}

#[tokio::test]
async fn candidate_store_and_retrieve() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();
    let fetched = lib.get(&id).await.unwrap().unwrap();
    assert_eq!(fetched.artifact_id, art.artifact_id);
    assert!(matches!(fetched.lifecycle, LifecycleState::Candidate));
}

#[tokio::test]
async fn store_candidate_idempotent() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id1 = lib.store_candidate(&art).await.unwrap();
    let id2 = lib.store_candidate(&art).await.unwrap();
    assert_eq!(id1, id2);
}

#[tokio::test]
async fn candidate_to_signed() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();

    let signing_key = SigningKey::generate(&mut OsRng);
    let pubkey = signing_key.verifying_key().to_bytes();
    lib.sign(&id, &signing_key, pubkey).await.unwrap();

    let signed = lib.get(&id).await.unwrap().unwrap();
    assert!(matches!(signed.lifecycle, LifecycleState::Signed));
    assert!(signed.signature.is_some());
}

#[tokio::test]
async fn sign_non_candidate_returns_wrong_state() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();

    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();

    lib.sign(&id, &sk, pk).await.unwrap();
    let err = lib.sign(&id, &sk, pk).await.unwrap_err();
    assert!(matches!(err, zp_artifacts::LibraryError::WrongState(_)));
}

#[tokio::test]
async fn candidate_to_rejected() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();
    lib.reject(&id).await.unwrap();
    let rejected = lib.get(&id).await.unwrap().unwrap();
    assert!(matches!(rejected.lifecycle, LifecycleState::Rejected));
}

#[tokio::test]
async fn reject_signed_returns_wrong_state() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    lib.sign(&id, &sk, sk.verifying_key().to_bytes()).await.unwrap();
    let err = lib.reject(&id).await.unwrap_err();
    assert!(matches!(err, zp_artifacts::LibraryError::WrongState(_)));
}

#[tokio::test]
async fn sign_supersedes_prior() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;

    let prior = make_candidate(None);
    let prior_id = lib.store_candidate(&prior).await.unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    lib.sign(&prior_id, &sk, sk.verifying_key().to_bytes()).await.unwrap();

    // Create a new candidate that supersedes the prior
    let manifest2 = SourceManifest {
        receipt_ids: vec!["rcpt-001".into(), "rcpt-002".into()],
        chain_head: "rcpt-002".into(),
    };
    let config2 = RenderConfig {
        composition_rules_version: 1,
        voice_anchor_version: 1,
        render_function_version: 1,
        llm_provider: "openai".into(),
        llm_model: "gpt-4o".into(),
        llm_params_hash: "abc".into(),
    };
    let new_id = zp_artifacts::compute_artifact_id(&manifest2, &config2);
    let mut art2 = make_candidate(None);
    art2.artifact_id = new_id.to_hex();
    art2.source_manifest = manifest2;
    art2.render_config = config2;
    art2.supersedes = Some(prior_id.to_hex());
    let id2 = lib.store_candidate(&art2).await.unwrap();
    lib.sign(&id2, &sk, sk.verifying_key().to_bytes()).await.unwrap();

    let prior_now = lib.get(&prior_id).await.unwrap().unwrap();
    assert!(matches!(prior_now.lifecycle, LifecycleState::Superseded { .. }));
}

#[tokio::test]
async fn list_by_state_filter() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();

    let candidates = lib
        .list(&LibraryFilter {
            state: Some(LibraryStateFilter::Candidate),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(candidates.contains(&id));

    let signed = lib
        .list(&LibraryFilter {
            state: Some(LibraryStateFilter::Signed),
            limit: 10,
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(!signed.contains(&id));
}

#[tokio::test]
async fn latest_signed_returns_none_when_empty() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let result = lib.latest_signed(&ArtifactKind::ChainNarration, "op-test").await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn latest_signed_returns_after_sign() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_candidate(None);
    let id = lib.store_candidate(&art).await.unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    lib.sign(&id, &sk, sk.verifying_key().to_bytes()).await.unwrap();
    let latest = lib.latest_signed(&ArtifactKind::ChainNarration, "op-test").await.unwrap();
    assert!(latest.is_some());
}
