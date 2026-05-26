//! Backend conformance test suite.
//!
//! Every `ContentStore` implementation must pass this suite. Add new backends
//! to the `conformance_suite!` invocations at the bottom of this file; CI
//! fails if a new backend is absent from the suite.

use chrono::Utc;
use tempfile::TempDir;
use zp_content::{
    ContentFilter, ContentMeta, ContentStore,
    backends::{LocalFsBackend, MemoryBackend},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn meta(kind: &str) -> ContentMeta {
    ContentMeta {
        kind: kind.to_string(),
        created_at: Utc::now(),
        size_bytes: 0, // overwritten by backends that track size
        extensions: None,
    }
}

// ---------------------------------------------------------------------------
// Conformance macro — parametrised over a store factory expression
// ---------------------------------------------------------------------------

macro_rules! conformance_suite {
    ($mod_name:ident, $make_store:expr) => {
        mod $mod_name {
            use super::*;

            async fn make() -> (impl ContentStore, Option<TempDir>) {
                $make_store
            }

            #[tokio::test]
            async fn put_returns_consistent_id() {
                let (store, _tmp) = make().await;
                let content = b"hello conformance";
                let id1 = store.put(content, meta("test.v1")).await.unwrap();
                let id2 = store.put(content, meta("test.v1")).await.unwrap();
                assert_eq!(id1, id2, "same bytes must produce same ContentId");
            }

            #[tokio::test]
            async fn content_id_is_blake3() {
                let (store, _tmp) = make().await;
                let content = b"blake3 check";
                let id = store.put(content, meta("test.v1")).await.unwrap();
                let expected = zp_content::ContentId::from_bytes(content);
                assert_eq!(id, expected, "ContentId must equal BLAKE3 of content bytes");
            }

            #[tokio::test]
            async fn put_idempotent() {
                let (store, _tmp) = make().await;
                let content = b"idempotent";
                let id1 = store.put(content, meta("test.v1")).await.unwrap();
                let id2 = store.put(content, meta("test.v1")).await.unwrap();
                assert_eq!(id1, id2);
                // get should still return the content after two puts
                let fetched = store.get(&id1).await.unwrap();
                assert!(fetched.is_some());
            }

            #[tokio::test]
            async fn get_roundtrip() {
                let (store, _tmp) = make().await;
                let content = b"round trip content bytes";
                let id = store.put(content, meta("test.v1")).await.unwrap();
                let fetched = store.get(&id).await.unwrap().expect("should be present");
                assert_eq!(fetched.as_ref(), content);
            }

            #[tokio::test]
            async fn get_missing_returns_none() {
                let (store, _tmp) = make().await;
                let absent = zp_content::ContentId::from_bytes(b"not stored");
                let result = store.get(&absent).await.unwrap();
                assert!(result.is_none(), "absent id should return None");
            }

            #[tokio::test]
            async fn has_present() {
                let (store, _tmp) = make().await;
                let content = b"has test";
                let id = store.put(content, meta("test.v1")).await.unwrap();
                assert!(store.has(&id).await.unwrap());
            }

            #[tokio::test]
            async fn has_absent() {
                let (store, _tmp) = make().await;
                let absent = zp_content::ContentId::from_bytes(b"also not stored");
                assert!(!store.has(&absent).await.unwrap());
            }

            #[tokio::test]
            async fn list_by_kind() {
                let (store, _tmp) = make().await;
                let id1 = store.put(b"a", meta("artifact.calendar.v1")).await.unwrap();
                let _id2 = store.put(b"b", meta("artifact.kanban.v1")).await.unwrap();
                let ids = store
                    .list(&ContentFilter {
                        kind: Some("artifact.calendar.v1".into()),
                        limit: 10,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert!(ids.contains(&id1), "kind filter should include matching id");
                for id in &ids {
                    // All returned ids should be the calendar kind
                    // (we can verify via meta)
                    let m = store.meta(id).await.unwrap().unwrap();
                    assert_eq!(m.kind, "artifact.calendar.v1");
                }
            }

            #[tokio::test]
            async fn list_limit_respected() {
                let (store, _tmp) = make().await;
                for i in 0u8..10 {
                    store
                        .put(&[i], meta("limit.test.v1"))
                        .await
                        .unwrap();
                }
                let ids = store
                    .list(&ContentFilter {
                        kind: Some("limit.test.v1".into()),
                        limit: 3,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert!(
                    ids.len() <= 3,
                    "list must honour the limit: got {}",
                    ids.len()
                );
            }

            #[tokio::test]
            async fn list_created_after_filter() {
                let (store, _tmp) = make().await;
                let before = Utc::now();
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let id = store.put(b"after timestamp", meta("ts.test.v1")).await.unwrap();

                let ids = store
                    .list(&ContentFilter {
                        created_after: Some(before),
                        limit: 10,
                        ..Default::default()
                    })
                    .await
                    .unwrap();
                assert!(ids.contains(&id), "created_after filter should include recently stored id");
            }

            #[tokio::test]
            async fn meta_roundtrip() {
                let (store, _tmp) = make().await;
                let m = ContentMeta {
                    kind: "meta.roundtrip.v1".into(),
                    created_at: Utc::now(),
                    size_bytes: 42,
                    extensions: None,
                };
                let id = store.put(b"meta content", m.clone()).await.unwrap();
                let fetched = store.meta(&id).await.unwrap().expect("meta should be present");
                assert_eq!(fetched.kind, m.kind);
            }

            #[tokio::test]
            async fn meta_missing_returns_none() {
                let (store, _tmp) = make().await;
                let absent = zp_content::ContentId::from_bytes(b"no meta here");
                let result = store.meta(&absent).await.unwrap();
                assert!(result.is_none());
            }

            #[tokio::test]
            async fn different_content_different_ids() {
                let (store, _tmp) = make().await;
                let id1 = store.put(b"content A", meta("test.v1")).await.unwrap();
                let id2 = store.put(b"content B", meta("test.v1")).await.unwrap();
                assert_ne!(id1, id2, "different bytes must produce different ContentIds");
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Backend registrations — add new backends here; CI enforces this list grows
// ---------------------------------------------------------------------------

conformance_suite!(memory, {
    let store = MemoryBackend::new();
    (store, None)
});

conformance_suite!(local_fs, {
    let tmp = TempDir::new().unwrap();
    let content_dir = tmp.path().join("content");
    let index_path = tmp.path().join("content-index.db");
    let store = LocalFsBackend::new(&content_dir, &index_path).await.unwrap();
    (store, Some(tmp))
});

// v0.1 — add when zp-cloudflare R2/D1 backends land:
// conformance_suite!(r2, { ... });
// conformance_suite!(d1, { ... });
