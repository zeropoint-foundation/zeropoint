# Audit Subsystem Architecture

Status: **canonical** (post AUDIT-03 recanonicalization, April 2026)
Scope: the identity-grade chain that records every policy decision and
governed action. *Not* the pedagogical `zp-receipt` chain, and *not* the
cross-agent collective-audit protocol — those are peer subsystems with
their own hash functions and are listed in §6.

This doc is the answer to "who owns the audit chain and where can I
look it up?" after the Stage 0–5 work that followed the discovery of 4
concurrent-append forks in the historical `~/.zeropoint/data/audit.db`.
It should be read alongside `audit-invariant.md`, which states the
formal invariant this architecture is trying to preserve.

---

## 1. The single-ownership diagram

```
                    ┌──────────────────────────────────┐
                    │        docs/audit-invariant.md   │
                    │  (∀ e: prev_hash = prior entry,  │
                    │   entry_hash = seal_entry(...))  │
                    └──────────────┬───────────────────┘
                                   │ pins
                                   ▼
  UnsealedEntry ──► AuditStore::append ──► audit_entries table
                    (BEGIN IMMEDIATE)      (schema v2, Stage 4)
                                   │
                                   ├─► seal_entry / compute_entry_hash   (Stage 2, the one and only app hash fn)
                                   │
                                   └─► Verifier / verify_with_catalog    (Stage 5, strict P1/P2/P3/P4)
```

There is exactly one of each of the following per process. Any second
instance is a bug and is treated as an integrity regression, not a
configuration choice.

| Role                       | Owner                                                      | Where                                |
| -------------------------- | ---------------------------------------------------------- | ------------------------------------ |
| Chain storage              | `AuditStore` (one `Arc<Mutex<_>>`)                         | `crates/zp-audit/src/store.rs`       |
| Writer                     | `AuditStore::append(UnsealedEntry) -> AuditEntry`          | same                                 |
| Chain head / `prev_hash`   | `MAX(rowid)` in `audit_entries`, read inside `BEGIN IMMEDIATE` | same                             |
| Hash function              | `seal_entry` / `compute_entry_hash`                        | `crates/zp-audit/src/chain.rs`       |
| Round-trip (inverse hash)  | `recompute_entry_hash`                                     | same                                 |
| Strict verifier            | `verify_with_catalog` (P1 linkage, P2 content, P3 unique parent, P4 monotonic) | `crates/zp-audit/src/catalog_verify.rs` + `zp-verify` |
| Schema definition          | `AuditStore::init`, `SCHEMA_VERSION = 2`                   | `crates/zp-audit/src/store.rs`       |
| Invariant statement        | `docs/audit-invariant.md`                                  | this repo                            |

The pipeline's `Pipeline::audit_store` and the server's
`AppStateInner.audit_store` are both `Arc<Mutex<AuditStore>>` pointing
at the same instance. `Pipeline::new(config, audit_store)` and
`AppState::init` enforce this by construction: `Pipeline::new` takes
the store as an argument rather than opening one itself (Stage 3).

## 2. Lifecycle of a single audit entry

1. A caller — proxy handler, playground handler, pipeline step,
   governance gate — constructs an `UnsealedEntry` via
   `UnsealedEntry::new(actor, action, conversation_id, policy_decision,
   policy_module)`. Callers must **not** assign `id`, `timestamp`,
   `prev_hash`, or `entry_hash`. Those fields do not exist on the
   unsealed type.
2. The caller acquires the shared store: `let mut store =
   state.audit_store.lock().unwrap()` (or, inside the pipeline, `self
   .audit_store.lock()`).
3. The caller invokes `store.append(unsealed)`. Inside that call,
   `AuditStore` opens a `BEGIN IMMEDIATE` transaction (which takes
   SQLite's RESERVED lock — a *file-level* lock that serializes writers
   across every in-process handle and every OS process), reads
   `MAX(rowid)` to get the chain tip, allocates a v7 UUID id and a
   timestamp, calls `seal_entry` to compute the hash, inserts the row,
   and commits. The returned `AuditEntry` is fully sealed.
4. Downstream code may inspect the sealed entry but must not try to
   rewrite any of its four store-assigned fields.

## 3. The canonical hash preimage

`compute_entry_hash` builds a `serde_json` object with the following
keys, in this exact order, then hashes `serde_json::to_vec(..)` with
blake3:

```
{ id, timestamp, prev_hash, actor, action, conversation_id,
  policy_decision, policy_module, receipt, signature }
```

Notes:

- `actor`, `action`, `policy_decision`, and `receipt` are `serde_json::to_value`
  of the typed enum. **Never** `format!("{:?}", ...)` — that was AUDIT-02.
- `conversation_id` and `id` are the UUIDs in hyphenated Display form,
  which is what the read path (`get_entries`) uses too. That's the
  round-trip property the Stage 5 test pins.
- `timestamp` is RFC 3339 via `chrono::DateTime::to_rfc3339`.
- `signature` is always hashed as JSON `null`. Signatures, when they
  exist, sign the `entry_hash`, so the hash must be well-defined before
  any signature does.

`recompute_entry_hash` is the inverse operation on a fully-sealed
`AuditEntry`: it rebuilds an `UnsealedEntry` from the stored fields and
calls `compute_entry_hash` with the stored `prev_hash`, `id`, and
`timestamp`. Strict P2 in `catalog_verify.rs` asserts that for every
row, `recompute_entry_hash(e) == e.entry_hash`.

## 4. Schema v2 (Stage 4)

`audit_entries` columns:

| column           | type    | notes                                                        |
| ---------------- | ------- | ------------------------------------------------------------ |
| `id`             | TEXT PK | hyphenated UUID                                              |
| `timestamp`      | TEXT    | RFC 3339                                                     |
| `prev_hash`      | TEXT    | blake3 hex; participates in the partial UNIQUE index below   |
| `entry_hash`     | TEXT    | blake3 hex of the preimage in §3                             |
| `actor`          | TEXT    | JSON of `zp_core::ActorId`                                   |
| `action`         | TEXT    | JSON of `zp_core::AuditAction`                               |
| `conversation_id`| TEXT    | hyphenated UUID                                              |
| `policy_decision`| TEXT    | JSON of `zp_core::PolicyDecision`                            |
| `policy_module`  | TEXT    | short string                                                 |
| `receipt`        | TEXT    | optional JSON of `zp_core::Receipt`                          |
| `signature`      | TEXT    | optional hex                                                 |

Indexes:

- `idx_conversation_id(conversation_id)`
- `idx_timestamp(timestamp)`
- `idx_unique_prev_hash(prev_hash) WHERE prev_hash != '<genesis>'`
  — Stage 4 belt-and-suspenders. A second row claiming the same parent
  fails at the storage layer, independently of `BEGIN IMMEDIATE`.

Pragmas: `journal_mode = WAL`, `synchronous = NORMAL`,
`user_version = 2`. Opening a DB with any other `user_version` returns
`StoreError::SchemaMismatch`. The existing v0 database must be
recanonicalized: run `security/pentest-2026-04-06/forensic-dump-audit-03.sh`
to preserve the historical 4 forks as forensic evidence, then delete
`audit.db` and let the server recreate it.

## 5. Back doors (there is one, narrow)

The old `AuditStore::execute_raw(sql: &str)` SQL back door is **gone**.
Stage 4 replaced it with exactly two parameterized, feature-gated
methods used only by the pentest/demo UI:

- `AuditStore::tamper_entry_hash(id, new_hash)`
- `AuditStore::restore_entry_hash(id, original_hash)`

Both are behind `#[cfg(feature = "pentest-demo")]`. The server crate's
`pentest-demo` feature (default on in dev, off for production builds)
forwards to `zp-audit/pentest-demo` and also gates the
`/api/v1/audit/simulate-tamper` and `/api/v1/audit/restore` handlers;
the non-feature build compiles stub handlers that return 404.

`cargo check -p zp-server --no-default-features` proves that dropping
the feature really does strip every line of tamper code. See Stage 4 in
`audit-invariant.md` §Back doors.

## 6. Every `compute_hash` function in the tree

The ripple audit (Stage 0) identified six functions that compute a
hash. Only **one** of them — `zp-audit::chain::compute_entry_hash` —
operates on the audit chain described in this document. The rest are
listed here so that a future reader who finds `compute_hash` in grep
output does not mistake them for a second audit-chain hash.

| # | Function                                                          | File                                            | What it hashes                                                                                               |
| - | ----------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1 | `zp_audit::chain::compute_entry_hash`                             | `crates/zp-audit/src/chain.rs`                  | **The** audit chain. Canonical. Everything in §1–§4 refers to this.                                          |
| 2 | `zp_audit::collective_audit::CompactAuditEntry::compute_hash`     | `crates/zp-audit/src/collective_audit.rs`       | A compact transport-hash over a peer's audit-entry summary, exchanged in the mesh's cross-agent challenge/response protocol. Derived from the canonical `entry_hash` but not a second chain. |
| 3 | `zp_receipt::chain::compute_entry_hash`                           | `crates/zp-receipt/src/chain.rs`                | The pedagogical receipt-chain's entry hash. Not the audit chain. See R3 in `security/pentest-2026-04-06/RIPPLE-AUDIT.md` — kept for course examples. Has its own `"genesis"` literal and `blake3("prev:content")` formula. |
| 4 | `zp_receipt::hasher::canonical_hash`                              | `crates/zp-receipt/src/hasher.rs`               | Content hash of a `Receipt` value, used by `zp-verify`'s `ChainEntry::content_hash_valid` for *receipts*, not audit entries. |
| 5 | `zp_core::governance::GovernanceEvent::compute_hash`              | `crates/zp-core/src/governance.rs`              | Hash of a governance-event record (a separate cross-agent coordination object). Not on the audit chain.      |
| 6 | `execution_engine::receipt::compute_hash`                         | `crates/execution-engine/src/receipt.rs`        | Hash of an execution-engine run receipt. Fed into the audit chain *as* the `receipt` field of an `UnsealedEntry`, but computed by the execution-engine, not by the audit store. |

**Sweep 1 (2026-04-07) — canonicality and verify-on-read audit.** All
six functions have been audited. Findings:

- Rows 1, 2, 4, 5: already canonical JSON, already verified on read.
- Row 3 (`zp_receipt::chain::compute_entry_hash`): kept as pedagogical
  (see R3 below and the crate-level doc comment in
  `crates/zp-receipt/src/chain.rs`). Not used outside
  `course-examples`.
- Row 6 (`execution_engine::receipt::compute_hash`): **rewritten** to
  canonical JSON via `serde_json::json!`, replacing the previous
  ad-hoc format-string preimage. `ExecutionReceipt::verify_hash()`
  added. Round-trip regression test added.
- Rows 2 and 5: **`verify_hash()` added** to
  `PeerAuditAttestation` and `GovernanceEvent`. Both hashes were
  previously write-only (computed on construction, never re-verified
  on read) — the same class of bug that bit us in AUDIT-02.

If a seventh `compute_hash` appears in the tree, it must either (a) be
added to this table with a clear non-overlap argument plus a
canonical-JSON preimage, a `verify_hash()` method, and a round-trip
test, or (b) be deleted.

**Sweep 5 (2026-04-07) — R2 closed.** `zp-receipt::epoch::compact()`
operates on `ChainEntry` (the pedagogical type from row 3 / row 4),
**not** on `zp_audit::AuditEntry`. There are zero `use zp_audit`
references in `crates/zp-receipt/src/epoch.rs`. The canonical
`AuditStore` is append-only and does not compact. Therefore epoch
compaction cannot interact with strict P2 enforcement on the canonical
chain — R2 is a non-issue and is formally closed. The pedagogical
status is already documented by the crate-level guard added in Sweep 2
(`crates/zp-receipt/src/chain.rs`).

## 7. Ripple findings R3/R4/R5 (cross-references)

See `security/pentest-2026-04-06/RIPPLE-AUDIT.md` for the full ripple
audit. The items that landed in this document:

- **R3 — pedagogical `ReceiptChain` in `zp-receipt`.** Not the audit
  chain. Row 3 of §6. It keeps its own `"genesis"` literal and a
  `blake3("prev:content")` formula. Kept because the course examples
  use it to teach hash chains without dragging in the full audit store.
  Do not route real audit data through it.

- **R4 — `execute_raw` SQL back door.** Removed in Stage 4. Replaced by
  the narrow, feature-gated methods in §5. Historical CVE-shaped bug;
  the grep pattern to watch for is `execute_raw\|execute_batch(&format!`.

- **R5 — six `compute_hash` functions.** Enumerated in §6. The point of
  that table is discoverability: anyone who finds one of these in code
  review can confirm in one step which chain, if any, it belongs to.

## 8. Verifier obligations, by rule ID

`verify_with_catalog` wraps each `AuditEntry` as an `AuditChainEntry`
and runs the catalog grammar from `zp-verify`. As of Stage 5:

| Rule | Description                                                       | Status   |
| ---- | ----------------------------------------------------------------- | -------- |
| P1   | `prev_hash` of entry *n* equals `entry_hash` of entry *n-1*       | Strict   |
| P2   | `entry_hash == recompute_entry_hash(entry)`                       | Strict (Stage 5) |
| P3   | `prev_hash` is unique among non-genesis entries                   | Enforced at storage layer by `idx_unique_prev_hash` (Stage 4); surfaced as a violation by the verifier via duplicate-detection in `ChainEntry::parent_link` |
| P4   | `timestamp` is non-decreasing along the chain                     | Strict (M4)      |

## 9. Writing code that touches the audit chain

Checklist for any PR that touches `zp-audit`, `zp-policy`, `zp-pipeline`,
or `zp-server` around audit entries:

1. Is there only one `AuditStore::open` call in the new code path?
   There should be zero — the store is handed to you as
   `Arc<Mutex<AuditStore>>`.
2. Are you constructing `UnsealedEntry` and handing it to
   `AuditStore::append`? You should not be touching `AuditEntry` fields
   directly, and you should not be reading `get_latest_hash` to compute
   a `prev_hash` yourself.
3. Are you hashing anything related to audit identity via
   `format!("{:?}", ...)`? Stop. AUDIT-02.
4. Are you adding a `compute_hash` function? If yes, add a row to §6
   with an explicit non-overlap argument, or reuse an existing hash.
5. Are you adding a new SQL statement inside `zp-audit`? It must be
   parameterized (`params![...]`), never `format!`.
6. Does it still pass `cargo test -p zp-audit` and
   `cargo test -p zp-pipeline --test integration test_stage3_shared_audit_store_no_forks_under_load`?

## 10. History

- 2026-04-06 — AUDIT-03 discovered: 4 P1 fork rows at rowids
  8214/8217/8223/8228. Root cause: two `AuditStore` handles on the same
  DB file, each with a private `Mutex`.
- 2026-04-06/07 — Stages 0–5 recanonicalization. See this document, the
  Stage commit history, and `audit-invariant.md` for the details.
- 2026-04-07 — Sweeps 1–4 (post-recanonicalization hardening):
  - **Sweep 1** — audited and remediated the five non-canonical
    `compute_hash` functions. `ExecutionReceipt` rewritten to canonical
    JSON. `verify_hash()` added to `ExecutionReceipt`,
    `GovernanceEvent`, and `PeerAuditAttestation`. Round-trip regression
    tests added to all three. All hashes in the tree are now
    canonical-JSON + verify-on-read.
  - **Sweep 2** — R3 pedagogical `ReceiptChain` confirmed to have zero
    non-test consumers outside `course-examples`. Retained with a
    crate-level doc comment flagging pedagogical-only status. R5 closed
    by Sweep 1 (all six functions now audited).
  - **Sweep 3** — `OnboardEvent` visibility fixed: `run_preflight`,
    `run_preflight_force`, `run_preflight_single`, and `handle_preflight`
    narrowed from `pub` to `pub(crate)` to match the private return type.
    Stale warnings cleared (`AsyncWriteExt` unused import,
    `method = "unknown"` unused assignment, `hmac_key` dead-code).
  - **Sweep 4** — `test_sweep4_full_construction_end_to_end_coherence`
    added to `zp-pipeline/tests/integration.rs`. This test walks the
    exact production construction path (`PipelineConfig` →
    `AuditStore::open` → `Arc<Mutex<_>>` → `Pipeline::new`), asserts
    `Arc::ptr_eq` between the pipeline's handle and the server-side
    clone, runs 200 concurrent appends across both sides, and verifies
    with catalog under strict P2. Pins the full end-to-end coherence
    invariant at the pipeline layer.
