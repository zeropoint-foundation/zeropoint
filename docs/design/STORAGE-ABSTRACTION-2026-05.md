> **Promoted from `docs/handoffs/` on 2026-07-29.** This document is the cited
> rationale for 1 shipped discipline pin — `no_raw_storage_calls_outside_zp_content` — which fail the
> build when violated. `docs/handoffs/` is excluded by `.gitignore`, and the corpus
> convention adopted 2026-07-27 classifies handoffs as local notes rather than corpus,
> so until this promotion the rule travelled with the repo and the reason for it did
> not. Content is unchanged from the handoff original, which remains in place locally
> as the working copy. References below to companion *investigation* documents still
> point into `docs/handoffs/` and are still local-only: those are working notes, and
> deliberately not promoted.

**Document type:** Design record, 2026-05-25. **Status:** Implemented — `crates/zp-content/` shipped; `no_raw_storage_calls_outside_zp_content` enforces it. Layout described below is the May proposal; the pin landed as a test file, not `src/pins/`.

# Design — Substrate storage abstraction (`zp-content`)

*2026-05-25. Sonnet tier — substrate-layer architecture design.*
*Upstream: `docs/handoffs/storage-abstraction-investigation-2026-05.md`*
*Deliverable: `crates/zp-content/` (implementation arc, not this doc)*

---

## Seven open questions — decided

### Q1 · Content-addressed identity

**Decision: BLAKE3 hash IS the `ContentId`. No separate namespace.**

Content identity is `blake3(content_bytes)` — deterministic, reproducible, backend-independent. Renaming a signed artifact is itself a chain event ("supersedes X with Y"); the store doesn't model rename. A separate UUID namespace buys nothing here and adds a join that has no canonical authority (the hash is always authoritative; the UUID isn't).

Consequence for receipts: `ContentId([u8; 32])` becomes the canonical cross-crate type for referencing stored content. When a receipt references a stored artifact, it carries a `ContentId`, not a URL or opaque string.

### Q2 · Lookup index location

**Decision: local SQLite as a separate DB (`~/ZeroPoint/content-index.db`).**

The audit chain's SQLite has its own integrity semantics (append-only, hash-chained, signed). Adding content-index tables muddies that. The content index is a derived cache — rebuildable by walking the backend; the audit chain is canonical and non-rebuildable. Different lifecycles, different trust properties, separate databases.

The index stores `(content_id BLOB, kind TEXT, created_at INTEGER, size_bytes INTEGER)` and is the primary path for `list()` queries. On first run against an existing `LocalFsBackend`, the index is rebuilt by walking `$ZP_CONTENT_DIR`.

### Q3 · Versioning / supersession

**Decision: chain only. Store is immutable.**

Supersession is a signed relationship between two `ContentId`s expressed as a chain receipt (`artifact:supersedes`, linking `new_id` and `prior_id`). The store holds bytes; the chain holds relationships. Storing a supersession pointer in the content backend would create a mutable field on an otherwise immutable, content-addressed record — a structural contradiction. Chain-only supersession keeps the store pure; the audit trail of "what replaced what, when, signed by whom" lives where audit trails belong.

### Q4 · v0 backends

**Decision: `LocalFsBackend` + `MemoryBackend` only for v0. Cloud-specific backends live in cloud-specific crates, not in `zp-content`.**

v0 makes the abstraction real and concrete with cloud-neutral backends. Cloud-specific backends (R2, D1, future S3, GCS, etc.) ship in cloud-specific crates that depend on `zp-content` — they are NOT feature-gated additions inside `zp-content`. This preserves the substrate boundary: `zp-content` defines the trait; `zp-cloudflare` (existing crate, governed by `no_cloudflare_imports_in_zp_crates` discipline pin) implements `ContentStore` for R2 and D1; a hypothetical future `zp-aws` would implement it for S3.

v0.1 wiring of R2/D1 backends in `zp-cloudflare` proves the abstraction abstracts. Shipping cloud backends in v0 before any consumer exists creates churn risk regardless of which crate hosts them.

### Q5 · Local-fs file layout

**Decision: two-level shard by hash prefix.**

```
$ZP_CONTENT_DIR/
  aa/
    bb/
      aabb<remaining 60 hex chars>
  ...
```

First 2 hex chars → first directory level; next 2 hex chars → second directory level; full hash as filename. Standard pattern (Git objects, IPFS). Avoids directory-size limits at scale. Kind belongs in the index, not in the file path — kind can be reinterpreted; the hash cannot.

### Q6 · Encryption

**Decision: plaintext-only. No encryption opt-in in the trait.**

Signed content is signed-not-secret. Encryption is the vault's concern (different threat model). If a future artifact kind needs at-rest encryption, that's a separate primitive layered on top of `ContentStore`, not a flag in the trait. Keeping the trait plaintext-only preserves the abstraction's simplicity and its composability with the vault.

### Q7 · Deletion semantics

**Decision: no `delete` in the trait. Maintenance sweep is a separate concern.**

The trait is pure read/put. Operators who need to expire content for compliance invoke a maintenance sweep (separate tool, not part of the trait) that walks the chain for expired/revoked receipts and removes the referenced content. The sweep is operational tooling; the trait is the substrate primitive.

---

## Final trait definition

```rust
// crates/zp-content/src/lib.rs

#[async_trait]
pub trait ContentStore: Send + Sync {
    /// Store content; return its content-addressed id.
    /// Idempotent: same bytes → same id, no duplicate write.
    async fn put(&self, content: &[u8], meta: ContentMeta)
        -> Result<ContentId, ContentError>;

    /// Fetch by content id. `None` if not present.
    async fn get(&self, id: &ContentId)
        -> Result<Option<bytes::Bytes>, ContentError>;

    /// Whether content is present without fetching it.
    async fn has(&self, id: &ContentId) -> Result<bool, ContentError>;

    /// List content ids matching a filter (always bounded by `filter.limit`).
    async fn list(&self, filter: &ContentFilter)
        -> Result<Vec<ContentId>, ContentError>;

    /// Metadata for a content id. `None` if not present.
    async fn meta(&self, id: &ContentId)
        -> Result<Option<ContentMeta>, ContentError>;
}
```

Deliberately absent: `delete`, `update`, `encrypt`. Rationale for each: see Q7, Q3, Q6 above.

---

## Final types

```rust
/// BLAKE3 hash of content bytes — the canonical identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ContentId(pub [u8; 32]);

impl ContentId {
    pub fn from_bytes(content: &[u8]) -> Self {
        Self(*blake3::hash(content).as_bytes())
    }
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
    pub fn from_hex(s: &str) -> Result<Self, ContentError> { ... }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContentMeta {
    /// Reverse-DNS kind string, e.g. "artifact.calendar.v1"
    pub kind: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub size_bytes: u64,
    /// Arbitrary caller-defined extensions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Default)]
pub struct ContentFilter {
    pub kind: Option<String>,
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
    /// Hard cap — callers must always set this. Default: 100.
    pub limit: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ContentError {
    #[error("backend I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("index error: {0}")]
    Index(String),
    #[error("content id parse error: {0}")]
    IdParse(String),
    #[error("backend error: {0}")]
    Backend(String),
}
```

---

## Crate layout

```
crates/zp-content/
  Cargo.toml                 — deps: async-trait, blake3, bytes, chrono,
                               hex, rusqlite, serde, serde_json, thiserror, tokio
  src/
    lib.rs                   — pub trait ContentStore + pub types
    index.rs                 — LocalIndex (SQLite); used by LocalFsBackend
    backends/
      mod.rs                 — pub use local_fs::LocalFsBackend;
                               pub use memory::MemoryBackend;
      local_fs.rs            — sharded filesystem backend + LocalIndex
      memory.rs              — BTreeMap<ContentId, (Bytes, ContentMeta)>
                               behind an Arc<RwLock<...>>; index is in-memory
```

**No cloud-specific feature flags in `zp-content`.** Cloud backends live in cloud-specific crates that depend on `zp-content`:

- `crates/zp-cloudflare/` (existing) gains `R2Backend` and `D1Backend` implementations of `ContentStore` in v0.1. Governed by the existing `no_cloudflare_imports_in_zp_crates` discipline pin — Cloudflare deps stay confined to `zp-cloudflare`.
- A future `crates/zp-aws/` (if needed) would host `S3Backend`.
- Adopters choose which backend crate to depend on based on their cloud target. The substrate stays cloud-neutral.

---

## Commit sequence

### Commit 1 — crate skeleton + trait + types

```
feat(zp-content): crate skeleton, ContentStore trait, types

New crate crates/zp-content/ with ContentStore trait,
ContentId (BLAKE3), ContentMeta, ContentFilter, ContentError.
No backends yet. Workspace Cargo.toml updated.

Discipline: establishes the abstraction. Cloud-specific backend
crates (zp-cloudflare, future zp-aws, etc.) implement the trait
against their respective backends; the discipline pin (Commit 4)
forbids raw content storage outside this set of allowed crates.
```

Files: `crates/zp-content/Cargo.toml`, `crates/zp-content/src/lib.rs`

### Commit 2 — LocalFsBackend + LocalIndex

```
feat(zp-content): LocalFsBackend + LocalIndex (SQLite)

Two-level sharded file layout under $ZP_CONTENT_DIR
(default ~/ZeroPoint/content/). LocalIndex uses a separate
SQLite at ~/ZeroPoint/content-index.db. Both put() and list()
keep index in sync. Index rebuild from backend on startup if
index is absent.
```

Files: `crates/zp-content/src/index.rs`, `crates/zp-content/src/backends/local_fs.rs`

### Commit 3 — MemoryBackend + conformance test suite

```
test(zp-content): MemoryBackend + backend conformance tests

MemoryBackend (Arc<RwLock<BTreeMap>>) for tests. Conformance
test suite in tests/conformance.rs parametrized over both
backends; any future backend must pass the same suite.
```

Files: `crates/zp-content/src/backends/memory.rs`, `crates/zp-content/tests/conformance.rs`

### Commit 4 — discipline pin

```
feat(zp-discipline): no_raw_storage_calls_outside_zp_content

Pin forbids raw filesystem-for-content calls outside
crates/zp-content/. Cloud-specific backend crates (zp-cloudflare,
future zp-aws, etc.) implement ContentStore against R2/D1/S3/etc.
and are allowlisted here — they are the trait's implementations,
not bypasses of it. Other allowlist entries: probes, tests, audit
store, vault, config stores (different storage concerns with
their own primitives).

Composes with existing no_cloudflare_imports_in_zp_crates pin —
Cloudflare deps confined to zp-cloudflare; ContentStore impls
in zp-cloudflare are the legitimate consumer of those deps.
```

Files: `crates/zp-discipline/tests/no_raw_storage_calls_outside_zp_content.rs` *(landed 2026-05 as a test file; this section proposed `src/pins/`, which is not how the discipline framework was built)*

---

## Test plan

### Conformance test suite

`tests/conformance.rs` (not yet written) — parametrized macro expands one test body for each backend. Any backend added in v0.1+ must be added to the macro; CI fails if a new backend isn't in the conformance suite.

```rust
macro_rules! conformance_suite {
    ($name:ident, $make_store:expr) => {
        mod $name {
            use super::*;
            use crate::make_store_fn;

            #[tokio::test] async fn test_put_returns_consistent_id() { ... }
            #[tokio::test] async fn test_put_idempotent() { ... }
            #[tokio::test] async fn test_get_roundtrip() { ... }
            #[tokio::test] async fn test_get_missing_returns_none() { ... }
            #[tokio::test] async fn test_has_present() { ... }
            #[tokio::test] async fn test_has_absent() { ... }
            #[tokio::test] async fn test_list_by_kind() { ... }
            #[tokio::test] async fn test_list_limit_respected() { ... }
            #[tokio::test] async fn test_list_created_after_filter() { ... }
            #[tokio::test] async fn test_meta_roundtrip() { ... }
            #[tokio::test] async fn test_meta_missing_returns_none() { ... }
            #[tokio::test] async fn test_content_id_is_blake3_of_bytes() { ... }
            #[tokio::test] async fn test_different_content_different_ids() { ... }
        }
    }
}

conformance_suite!(local_fs, make_local_fs_backend());
conformance_suite!(memory, make_memory_backend());
// v0.1: conformance_suite!(r2, make_r2_backend());
```

### Unit tests (per-backend)

`LocalFsBackend`: shard path computation, index rebuild from existing content dir, concurrent put/get under Tokio tasks.

`MemoryBackend`: list filter correctness, limit boundary.

`LocalIndex`: schema migration idempotence, `list()` SQL correctness.

### Integration smoke test

`tests/integration.rs` (not yet written) — artifact library's intended usage pattern:

```rust
let store = LocalFsBackend::new(tmp_dir).await?;
let content = b"calendar artifact bytes";
let meta = ContentMeta { kind: "artifact.calendar.v1".into(), ... };
let id = store.put(content, meta).await?;
assert!(store.has(&id).await?);
let retrieved = store.get(&id).await?.unwrap();
assert_eq!(retrieved.as_ref(), content);
let listed = store.list(&ContentFilter { kind: Some("artifact.calendar.v1".into()), limit: 10, ..Default::default() }).await?;
assert!(listed.contains(&id));
```

---

## Surprises from the audit

1. **No existing `pub trait` in `zp-audit` or `zp-trust` to reuse or extend.** The only trait found was `AppendNotifier` in `zp-audit/src/notify.rs` — a narrow notification hook, not a general store abstraction. The new crate really is additive; there's nothing to refactor.

2. **`Receipt.content_hash: String` at line 38 of `zp-receipt/src/types.rs` is the receipt's *own* hash, not a reference to stored content.** No artifact-id field exists yet in receipt types. When the artifact library ships, a new `artifact_id: Option<ContentId>` field on the relevant receipt types will be the integration point — a small, targeted addition, not a schema migration.

3. **Foundation worker already has both cloud backends in wrangler.toml** — `D1` binding `DB` (database "zpmail") and R2 bucket `zp-storage`. These are the physical targets for the v0.1 `D1Backend` and `R2Backend` implementations of `ContentStore`. Per the correction noted above, those implementations live in `zp-cloudflare` (not in `zp-content`), so the substrate's storage abstraction stays cloud-neutral while the foundation deployment gets working backends via the Cloudflare-specific crate.

---

*Singular trait. Two v0 backends. Conformance gate for every future backend. Artifact library consumes `ContentStore`, not R2.*
