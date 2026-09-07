//! Signing round-trip verification tests.

use chrono::Utc;
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::sync::Arc;
use tempfile::TempDir;
use zp_artifacts::artifact::{
    Artifact, ArtifactContent, ArtifactKind, LifecycleState, RenderConfig, SourceManifest,
};
use zp_artifacts::{compute_artifact_id, Library, LocalArtifactLibrary};
use zp_content::backends::LocalFsBackend;

async fn make_library(tmp: &TempDir) -> LocalArtifactLibrary {
    let store = Arc::new(
        LocalFsBackend::new(&tmp.path().join("content"), &tmp.path().join("cidx.db"))
            .await
            .unwrap(),
    );
    LocalArtifactLibrary::new(store, &tmp.path().join("aidx.db"))
        .await
        .unwrap()
}

fn make_artifact() -> Artifact {
    let manifest = SourceManifest {
        receipt_ids: vec!["r-001".into(), "r-002".into()],
        chain_head: "r-002".into(),
    };
    let config = RenderConfig {
        composition_rules_version: 1,
        voice_anchor_version: 1,
        render_function_version: 1,
        llm_provider: "anthropic".into(),
        llm_model: "claude-3-5-sonnet".into(),
        llm_params_hash: "deadbeef".into(),
    };
    let artifact_id = compute_artifact_id(&manifest, &config);
    Artifact {
        artifact_id: artifact_id.to_hex(),
        kind: ArtifactKind::ChainNarration,
        source_manifest: manifest,
        render_config: config,
        content: ArtifactContent {
            mime_type: "text/markdown".into(),
            body: b"May 14: operator onboarded.\n\nMay 15: first gate call.".to_vec(),
        },
        operator_id: "op-roundtrip-test".into(),
        generated_at: Utc::now(),
        supersedes: None,
        lifecycle: LifecycleState::Candidate,
        signature: None,
    }
}

#[tokio::test]
async fn sign_and_verify_signature() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_artifact();
    let canonical = art.canonical_bytes_for_signing();

    let id = lib.store_candidate(&art).await.unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    lib.sign(&id, &sk, pk).await.unwrap();

    let signed = lib.get(&id).await.unwrap().unwrap();
    let sig_info = signed.signature.as_ref().unwrap();

    let sig_bytes = hex::decode(&sig_info.sig).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
    let vk = VerifyingKey::from_bytes(&pk).unwrap();
    vk.verify(&canonical, &sig).expect("signature must verify");
}

#[tokio::test]
async fn mutated_content_fails_verification() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_artifact();
    let id = lib.store_candidate(&art).await.unwrap();
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key().to_bytes();
    lib.sign(&id, &sk, pk).await.unwrap();

    let signed = lib.get(&id).await.unwrap().unwrap();
    let sig_info = signed.signature.as_ref().unwrap();
    let sig_bytes = hex::decode(&sig_info.sig).unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());
    let vk = VerifyingKey::from_bytes(&pk).unwrap();

    // Mutate the canonical bytes
    let mut tampered = signed.canonical_bytes_for_signing();
    tampered[10] ^= 0xFF;
    assert!(
        vk.verify(&tampered, &sig).is_err(),
        "tampered bytes must not verify"
    );
}

#[tokio::test]
async fn artifact_id_stable_across_state_transitions() {
    let tmp = TempDir::new().unwrap();
    let lib = make_library(&tmp).await;
    let art = make_artifact();
    let original_id = art.artifact_id.clone();

    let id = lib.store_candidate(&art).await.unwrap();
    assert_eq!(id.to_hex(), original_id);

    let sk = SigningKey::generate(&mut OsRng);
    lib.sign(&id, &sk, sk.verifying_key().to_bytes())
        .await
        .unwrap();

    let signed = lib.get(&id).await.unwrap().unwrap();
    assert_eq!(
        signed.artifact_id, original_id,
        "artifact_id must not change on sign"
    );
}

#[tokio::test]
async fn artifact_id_deterministic_same_inputs() {
    let manifest = SourceManifest {
        receipt_ids: vec!["r1".into(), "r2".into()],
        chain_head: "r2".into(),
    };
    let config = RenderConfig {
        composition_rules_version: 1,
        voice_anchor_version: 1,
        render_function_version: 1,
        llm_provider: "openai".into(),
        llm_model: "gpt-4o".into(),
        llm_params_hash: "ff".into(),
    };
    let id1 = compute_artifact_id(&manifest, &config);
    let id2 = compute_artifact_id(&manifest, &config);
    assert_eq!(id1, id2);
}

#[tokio::test]
async fn artifact_id_changes_on_config_bump() {
    let manifest = SourceManifest {
        receipt_ids: vec!["r1".into()],
        chain_head: "r1".into(),
    };
    let config_v1 = RenderConfig {
        composition_rules_version: 1,
        voice_anchor_version: 1,
        render_function_version: 1,
        llm_provider: "openai".into(),
        llm_model: "gpt-4o".into(),
        llm_params_hash: "aa".into(),
    };
    let mut config_v2 = config_v1.clone();
    config_v2.composition_rules_version = 2;
    let id1 = compute_artifact_id(&manifest, &config_v1);
    let id2 = compute_artifact_id(&manifest, &config_v2);
    assert_ne!(id1, id2);
}
