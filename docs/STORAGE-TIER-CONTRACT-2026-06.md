# Storage Tier Contract — What a Chain-Persistence Backend Must, May, and Must Not Do

*Dated 2026-06. The runtime-neutral contract between the Storage tier and
the Operator substrate's Chain sub-layer. Names which affordances a
chain-persistence implementation MUST have, which it MAY have, and which
it MUST NOT have, so that affordance gaps are classifiable without re-
deriving from structural first principles each time.*

*Updates to this doc are architectural acts and should be treated as such.*

---

## 1. What this doc is

This is the Storage tier contract — the operational complement to
`docs/audit-architecture.md` and `docs/audit-invariant.md` at the
persistence-backend boundary. Where those documents name the invariant the
substrate is trying to preserve and the recanonicalization story that restored
it after it was broken, this document names what makes a persistence-backend
implementation conformant in the first place: the append, read, durability,
concurrency, and integrity semantics a storage backend must provide to host
the substrate's chain correctly.

The contract is runtime-neutral and backend-neutral by construction. SQLite
with WAL mode and `BEGIN IMMEDIATE` transactions is the current
implementation; PostgreSQL with Serializable isolation, RocksDB in single-
writer mode, or any other transactional backend that satisfies the Required
affordances is equally conformant. The contract names the semantics the
backend must provide; which backend provides them is an operator deployment
decision.

This document is the spoke for Tier 7 in
`docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`. The Storage tier covers
persistence-backend conformance alone — append semantics, read semantics,
durability, concurrency control, and integrity primitives. It does not cover
the chain hash function (Operator substrate Chain sub-layer), receipt body
canonicalization (Operator substrate Receipt sub-layer), receipt signing
(Operator substrate Identity binding sub-layer), or verifier obligations
(Verifier tier). The boundary between the Storage tier and the Operator
substrate's Chain sub-layer is `AuditStore::append`: what the Storage tier
provides to that boundary is what this contract names; what the Chain sub-
layer requires at that boundary is named in
`docs/OPERATOR-SUBSTRATE-CONTRACT-2026-06.md` §3 Chain.

---

## 2. The category statement

The Storage tier hosts the substrate's chain. That chain is append-only,
content-addressed, hash-linked, crash-safe, and single-writer — a hash-
linked sequence of sealed entries in which every entry's `prev_hash` equals
the prior entry's `entry_hash`, every `entry_hash` is a BLAKE3 hash over a
deterministic canonical preimage, and no entry may be mutated after insertion.
The storage backend is the layer that makes those properties *durable*: it
provides the transactional primitives, the uniqueness constraints, the crash-
recovery guarantees, and the schema discipline that allow the chain layer
above it to maintain those properties across restarts, concurrent callers,
schema migrations, and hardware failures.

The storage backend is not the chain. The chain is a structural commitment
expressed in the substrate's grammar; the storage backend is the persistence
substrate underneath that commitment. An `AuditStore` that reads `MAX(rowid)`
inside a `BEGIN IMMEDIATE` transaction, calls `seal_entry`, and inserts the
sealed row is using its storage backend correctly; a storage backend that
allows two writers to race on `MAX(rowid)` has failed the `AuditStore`
regardless of how correct the higher layers are. The Storage tier's Required
affordances are exactly the properties the `AuditStore` relies on from the
backend; its Forbidden affordances are the uses that would break those
properties from within.

---

## 3. Required affordances

An implementation lacking any of these cannot serve as a conformant chain-
persistence backend. The fallback when a non-conformant backend is used is
not graceful degradation — it is chain corruption of the kind AUDIT-03
produced: hash-link forks that make Claim 1 false at affected positions. The
substrate's chain either has the Required affordances underneath it or it does
not have integrity guarantees.

**1. Atomic append.** The chain insertion path must execute as a single
serializable transaction encompassing all of: reading the current chain tip,
assigning the new entry's `id`, `timestamp`, and `prev_hash`, sealing the
entry (computing its `entry_hash`), and inserting the row. No other writer
may observe an intermediate state between tip-read and row-insertion. In
SQLite, this is `BEGIN IMMEDIATE`, which takes the RESERVED file-level lock
and serializes writers across both in-process handles and OS processes. In
PostgreSQL, this is Serializable isolation with a transaction lock covering
the tip-read and insert. In RocksDB, this is an atomic write batch with a
write barrier. The specific primitive varies by backend; the invariant —
tip-read and insert are a single, uninterruptible unit — does not. **P1,
Claim 1.**

**2. UNIQUE constraint on `prev_hash` excluding the genesis sentinel.**
A partial unique index on `prev_hash` where `prev_hash != '<genesis>'` (or
the backend's equivalent partial-index construct) must ensure that no two
entries claim the same parent. This is a belt-and-suspenders constraint
alongside the transactional append: if two writers somehow race past the
transaction lock, the storage layer rejects the second insertion independently.
In SQLite this is `idx_unique_prev_hash(prev_hash) WHERE prev_hash != '<genesis>'`,
enforced by the schema at `AuditStore::init`. **P1, Claim 1.**

**3. Append-only storage.** The persistence backend must not provide any
code path — migration, repair tool, administrative API, or otherwise — that
mutates existing chain entries' identity-bearing fields: `id`, `timestamp`,
`prev_hash`, `entry_hash`, or any canonical-body input field. Schema
migrations may add new columns or indexes but must leave all existing rows'
identity fields unchanged. An identity-bearing field that can be mutated
after insertion makes the chain's integrity guarantee contingent on the
discipline of every code path with database access, which is not a structural
guarantee. **P1, M3.**

**4. Single-writer ownership.** Exactly one `AuditStore` instance (or its
equivalent in an alternative implementation) may hold a write handle to the
chain database per process. All in-process consumers receive a shared
`Arc<Mutex<AuditStore>>` handle to the same instance; `AuditStore::open` is
called exactly once per process. The AUDIT-03 root cause was precisely this
property's violation: two `AuditStore` handles on the same database file,
each with its own private `Mutex`, each believing it was the sole writer.
The single-writer commitment is enforced by construction at Stage 3 of the
recanonicalization work: `Pipeline::new` receives the `AuditStore` handle as
an argument rather than opening its own. **P8.**

**5. Crash-safe durability.** The backend must provide durability guarantees
that survive process crashes and OS-level interruption without leaving the
chain in a state that the next startup cannot recover from coherently. A
transaction that was committed before the crash must be durably on-disk at
next startup; a transaction that was in-flight at the time of crash must be
either fully committed or fully absent, never partially written. In SQLite
this is WAL mode with `synchronous = NORMAL`, which provides durability with
acceptable write latency. In PostgreSQL this is fsync-on-commit. The specific
mechanism varies; the invariant — a committed chain entry is permanent — does
not. **P5.**

**6. Content-addressed point read by entry id.** The backend must support
reading a single entry by its `id`, returning the canonical body that
produces the same `entry_hash` on recomputation. Read-after-write coherence
must hold within the same process: a caller that appended an entry and
immediately reads it by id must receive that entry. Without this, the chain-
walk machinery cannot fetch specific entries for verification, and the surface
layer's chain-read endpoint cannot serve the signed entries the verifier needs.
**P1, Claim 2.**

**7. Ordered range read by insertion order for chain walk.** The backend must
support reading entries ordered by insertion sequence — by `rowid` or an
equivalent insertion-order column — so that the full chain can be walked from
Genesis to the current tip in the order entries were inserted. The chain walk
is the mechanism that makes Claim 2 testable (present state compresses full
history because the full history is re-derivable in order from Genesis); an
unordered read interface makes that walk impossible. **P5, Claim 2.**

**8. Schema versioning with strict mismatch behavior.** The backend must
record its own schema version (SQLite `user_version = 2`) and refuse to open
a database whose recorded version does not match the implementation's expected
version, returning a hard error (`StoreError::SchemaMismatch` or equivalent)
rather than silently migrating or silently proceeding. Schema migration is an
explicit operation through a dedicated API with explicit operator authorization.
Opening with an unexpected version means the database state may not match
what the current implementation expects; the correct response is to surface
the mismatch so the operator can act, not to paper over it. **M2.**

---

## 4. Optional affordances

Each optional affordance improves the deployment's operational characteristics
without affecting the chain's structural integrity.

**Specific storage backend.** SQLite is the current implementation. PostgreSQL,
RocksDB, FoundationDB, or any other transactional backend whose primitives
satisfy the eight Required affordances above is conformant. The contract names
semantics; the backend is operator choice. Different backends make different
trade-offs — SQLite is embedded and file-local; PostgreSQL supports multi-
process access with network-accessible durability; RocksDB offers higher
write throughput at the cost of operational complexity — but these are
deployment trade-offs, not conformance distinctions.

**Compaction strategies.** Epoch snapshots and content-addressed segment
archives that reduce chain-walk cost for Claim 2 verification are optional
space-management mechanisms. Any compaction strategy must preserve re-
derivability from Genesis — typically by producing a signed checkpoint that
can substitute for chain replay up to the checkpoint position, with the full
chain retained as an archive. The canonical `AuditStore` is append-only by
the storage invariant; compaction operates on archived representations, not
on the live chain.

**Replication.** Replicating the chain — or chain digests — to additional
storage for backup, geographic redundancy, or peer-attestation support is
optional. Replication is orthogonal to per-process append semantics: the
primary chain retains single-writer semantics; replicas are read-side
projections or backup artifacts, not writers.

**Read-side indexing on application-level fields.** Indexes on `conversation_id`,
`timestamp`, `actor`, or other non-identity fields are optional query-
performance optimizations. The Required indexes are those that enforce
structural invariants: the `UNIQUE(prev_hash)` partial index. Additional
indexes for query convenience are implementation choice.

**In-process read caches.** Caching recently-appended entries for read-after-
write optimization is optional, provided the cache is invalidated correctly
on every append and never serves a stale entry after a chain insertion
modified the tip. The Required affordance is read-after-write coherence;
how the implementation achieves it is up to the backend.

**Scrubbing.** Periodic integrity scans that walk the full chain from Genesis
and recompute every `entry_hash` are an optional capability that detects
storage-layer corruption — bit rot, partial writes, silent hardware failure —
that per-append verification does not catch. `crates/zp-audit/src/scrub.rs`
is the current implementation. Scrubbing is deployment-stratified: it is
recommended for long-running production deployments where hardware failure
or filesystem corruption is a realistic concern, but the substrate is correct
without it. Per-append hash verification (Required affordance #1's atomic seal)
catches logical corruption at write time; scrubbing catches physical corruption
after the fact. Both are valuable; only the former is Required.

**Reconstitution tooling.** Mechanisms that rebuild derived state — a
revocation index, a capability table, in-memory caches — from chain replay are
optional. `crates/zp-audit/src/reconstitute.rs` provides this for disaster
recovery and verifier-side state rebuilding. Like scrubbing, reconstitution is
deployment-stratified: operationally important for production deployments that
need to recover from data corruption or state loss, but not a substrate-
correctness requirement. The chain itself is always the source from which
derived state can be rebuilt; the tooling speeds up that rebuilding.

**Forensic back-door write methods (feature-gated).** The two parameterized
tamper hooks used for pentest demonstrations — `AuditStore::tamper_entry_hash`
and `AuditStore::restore_entry_hash` — are optional and must be compiled out
of production builds via `#[cfg(feature = "pentest-demo")]`. The compile-time
exclusion is the load-bearing property; `cargo check -p zp-server --no-default-features`
must produce a build with zero tamper code reachable. The existence of these
methods in the development build is what makes the chain-viz tamper
demonstration possible; their absence in production is what makes the
substrate trustworthy.

---

## 5. Forbidden affordances

The Forbidden category at the Storage tier is calibrated against a specific
empirical failure shape: AUDIT-03. In April 2026, four concurrent-append
forks appeared at rowids 8214, 8217, 8223, and 8228 in `audit.db`. The root
cause was two `AuditStore` handles open on the same database file simultaneously,
each holding its own private `Mutex` and each reading `MAX(rowid)` without
serialization against the other. The result was four entries sharing `prev_hash`
values with prior entries that other concurrently-appended entries already
claimed — four broken hash links at the positions where the two writers
interleaved. Claim 1 was false at each of those positions.

The ten entries below name storage-tier uses that either reproduce the AUDIT-03
failure mode directly, or produce equivalent chain-corruption failure modes by
different paths. The substrate uses transactions, mutations, and ad-hoc SQL
foundationally in many places; the Forbidden entries name the specific *chain-
layer uses* that escape the structural commitments the chain rests on.

**1. Non-atomic append.** Any append path that allows the chain-tip read,
`entry_hash` computation, and row insertion to interleave with another writer's
identical sequence produces the AUDIT-03 failure mode: two entries with the
same `prev_hash`, breaking hash-link integrity at the insertion point. The
specific mechanism — two in-process handles without a shared lock, two OS
processes without a file-level lock, or any other interleaving path — is
irrelevant; the result is the same. **P1, Claim 1.**

**2. Mutation of existing entries' identity-bearing fields.** Any code path
that modifies `id`, `timestamp`, `prev_hash`, `entry_hash`, or canonical-body
input fields of an entry already in the chain retroactively breaks the hash-
link structure: every subsequent entry's `prev_hash` was computed against the
original value, and the mutation produces a mismatch that the verifier will
detect as a P2 violation. The chain is append-only as a structural commitment,
not a convention. **P1, M3.**

**3. Caller-supplied chain-position fields.** Callers must not be able to
supply `id`, `timestamp`, `prev_hash`, or `entry_hash` to the append API.
These fields are assigned exclusively by the storage backend within the atomic
append transaction; they are computed from the chain's current state and from
the `seal_entry` function's output, not from the caller's input. The
`UnsealedEntry` type enforces this in the current implementation — those
fields do not exist on the unsealed type and callers cannot reach them. An
append API that accepts caller-supplied chain-position fields allows any caller
to forge hash links. **P1.**

**4. In-memory chain head caches across transactions.** Any in-memory
structure that tracks "the current chain tip" outside the database transaction
— a `Mutex<String>` chain-head field, a `RefCell<String>` cursor, an
`AtomicU64`-plus-a-hash, a `Gate::audit_chain_head` field — is forbidden.
The pre-recanonicalization `zp_policy::Gate::audit_chain_head` was precisely
this pattern: an in-memory cursor that diverged from `MAX(rowid)` under
concurrent writers. The chain head must always be read as `MAX(rowid)` (or
the backend's equivalent insertion-order maximum) inside the atomic append
transaction. Reading it outside the transaction, caching it across calls, or
maintaining it in memory alongside the database are all the AUDIT-03 failure
mode by a slightly different path. **M3, Claim 1.**

**5. Second chain hash function.** The storage backend must not provide or
define a separate hash function that operates on audit chain entries. The one
canonical hash function for chain entries is `zp_audit::chain::compute_entry_hash`
in `crates/zp-audit/src/chain.rs`. The storage backend invokes this function
but does not replace or supplement it. The six-function ripple audit (Sweep 1,
April 2026) identified and audited every `compute_hash` function in the tree;
a seventh that operates on audit chain entries would violate the single-hash-
function commitment and could produce entries that verify under one function
but not the other. **P8.**

**6. Unparameterized SQL back-door writes.** An `execute_raw(sql: &str)` method,
batch updates constructed with `format!()`, or any code path that bypasses the
parameterized append API and writes directly to `audit_entries` with ad-hoc SQL
is forbidden. The `execute_raw` back door was R4 from the pentest ripple audit
and was removed in Stage 4 of the recanonicalization. It was replaced by the
narrow, parameterized, feature-gated tamper methods described in Optional #8.
The distinction is: parameterized, auditable, compile-out-in-production is
conformant; ad-hoc string-interpolated SQL is not. **M3.**

**7. Multiple `open()` calls per process per database file.** Opening a second
`AuditStore` handle to the same database file within the same process — whether
in production code, in tests, or in any other context — is the AUDIT-03 root
cause expressed directly. Each handle has its own lock and its own view of the
chain tip; two handles inevitably race. The pattern is: `AuditStore::open()` is
called once, the resulting instance is wrapped in `Arc<Mutex<AuditStore>>`, and
all consumers receive a clone of the `Arc`. Tests that need a chain backend
create a fresh database at a distinct path, not a second handle to a shared
file. **P8.**

**8. Silent schema upgrade on version mismatch.** Opening a database whose
recorded `user_version` does not match the implementation's expected version
and silently migrating or silently proceeding — rather than returning
`StoreError::SchemaMismatch` — is forbidden. A schema mismatch means the
database was either created by a different implementation version or has been
manually modified; silent upgrade or silent proceed hides that fact and may
produce entries that were sealed under one schema version but are stored under
the metadata of another. Schema migration is an explicit operation with explicit
operator authorization. **M2.**

**9. `format!("{:?}", ...)` for any identity-bearing field.** Using Rust's
debug-format string representation as the canonical serialization of any field
that feeds into an `entry_hash` computation, an `id` derivation, a map key,
or a database column is forbidden. Debug format is not stable across Rust
compiler versions; AUDIT-02 was exactly this failure: a hash-preimage computed
from `format!("{:?}", ...)` of a typed enum diverged from the hash-preimage
computed by a conformant verifier using the stable JSON representation. Canonical
serialization for identity-bearing fields uses `serde_json::to_value`, `Display`,
RFC 3339 for timestamps, or a purpose-built versioned serialization function
with round-trip tests. **P4.**

**10. Eventually-consistent storage semantics for the canonical write path.**
Storage backends that do not provide serializable atomic-append semantics —
because they are eventually consistent, because they allow concurrent writers
without serialization, or because they have no concept of transaction isolation
— are not conformant for hosting the canonical chain. Replication to eventually-
consistent replicas is permitted (Optional #3) provided the primary write path
retains strong consistency. A chain hosted on an eventually-consistent backend
will produce the AUDIT-03 failure mode under any concurrent-write workload;
Claim 1 cannot hold without the atomic-append guarantee the backend provides.
M3 (hash-chain continuity) is the structural rule the eventually-consistent
backend most directly breaks — concurrent writes that observe the same
chain tip produce duplicate or missing prev-hash links, falsifying the
continuity invariant.
**P1, M3, Claim 1.**

---

## 6. Composition with principles

The Storage tier is one of the places where four principles simultaneously
do load-bearing work, because the chain's integrity properties depend on the
persistence layer being structurally honest in four distinct ways at once.

**P1 (signing is gravity) is the primary principle for Required affordances
#1, #2, #3, #6, and for Forbidden entries #1, #2, #3, #10.** Signed entries
become durable at the storage layer; if the storage layer can corrupt, reorder,
or fork the chain, signed entries lose their structural meaning. A signature
attests to a canonical body at a specific chain position; a storage backend
that allows the position to fork or the body to mutate retroactively invalidates
the attestation. Claim 1 (each step conditioned on full prior context) is what
P1 makes testable; the Required affordances are the primitives that make the
claim durable.

**P4 (every bit counts) is the structural basis for Forbidden entries #2, #5,
and #9.** Mutation of identity-bearing fields is a P4 violation because the
mutated field is no longer what was signed — it is a bit that changed without
earning its place through cryptographic necessity. A second hash function is
a P4 violation because it creates a parallel encoding of chain entry identity
with no cryptographic purpose. Debug-format serialization is a P4 violation
because it introduces platform-dependent bits into the hash preimage, producing
non-determinism where the canonical body requires determinism.

**P5 (store-and-forward is primary) is the structural basis for Required
affordances #5, #7, and the Optional scrubbing and reconstitution affordances.**
The chain survives outages because the storage backend provides crash-safe
durability. The chain is walkable from Genesis without a live substrate because
the storage backend provides ordered range reads. The substrate does not ask
"is the system healthy right now?" — it reads the chain. P5 is why crash-safe
durability is Required rather than Optional: without it, an outage is a chain
gap, and the chain-as-primary-record breaks.

**P8 (one canonical path per substrate concern) is the structural basis for
Required affordance #4 (single-writer ownership) and Forbidden entries #5
and #7.** There is one canonical chain, written by one writer, using one hash
function, with one database handle per process. Each of these singularities
is an expression of P8 at the storage layer. AUDIT-03 was a P8 violation: two
writers for one chain. The second-hash-function prohibition is P8 for the hash
computation. The multiple-`open()`-calls prohibition is P8 for the handle
lifecycle. The pattern is consistent: wherever the storage tier names one
canonical thing, a second instance of that thing is forbidden.

**Claim 1 is made durably testable by this tier's conformance.** The Storage
tier is the layer where Claim 1's structural support — hash-linked, atomic-
append, single-writer — becomes a property of on-disk state rather than of
in-memory invariants. An implementation that satisfies the Required affordances
provides the persistence foundation that allows Claim 1 to hold across
restarts, concurrent callers, and hardware interruptions. An implementation
that violates any Forbidden affordance falsifies Claim 1 at the affected chain
positions, as AUDIT-03 demonstrated empirically.

---

## 7. Portability sketches

The contract is backend-agnostic. These four sketches demonstrate that the
Required affordances are achievable with meaningfully different storage
architectures.

**SQLite (current implementation).** WAL journal mode, `synchronous = NORMAL`,
`BEGIN IMMEDIATE` transactions for atomic append, `UNIQUE` partial index on
`prev_hash` excluding the genesis sentinel, `user_version = 2` schema versioning.
Embedded, single-file, zero network dependency. All eight Required affordances
are satisfied: the `BEGIN IMMEDIATE` lock provides atomic append (#1); the
partial index provides the UNIQUE constraint (#2); the schema design forbids
UPDATE on identity fields (#3); `AuditStore::open` is called once (#4); WAL
with `synchronous = NORMAL` provides crash-safe durability (#5); indexed reads
by `id` provide point-read coherence (#6); rowid ordering provides chain-walk
range reads (#7); `user_version` check provides schema mismatch detection (#8).

**PostgreSQL.** Serializable isolation replaces `BEGIN IMMEDIATE`; a unique
partial index on `prev_hash` where `prev_hash != '<genesis>'` replaces the
SQLite partial index; `fsync = on` provides crash-safe durability; a single
application-level connection owner (equivalent to `Arc<Mutex<AuditStore>>`)
provides single-writer semantics across network clients. PostgreSQL enables
multi-process deployments — operators can run separate `zp-server` processes
and a separate verifier process against the same chain database — provided
the single-writer constraint is enforced at the application level (one writer
at a time, not one writer per process). All eight Required affordances are
achievable; the trade-off is operational complexity versus multi-process
flexibility.

**RocksDB.** Single-writer mode with atomic write batches provides the
equivalent of `BEGIN IMMEDIATE`. A separate column family for `prev_hash →
rowid` mappings enforces the UNIQUE constraint by making duplicate-parent
writes detectable at insert time. Write-ahead log provides crash-safe
durability. Content-addressed point reads by entry id are a natural key-value
lookup. Ordered range reads require a rowid-keyed secondary column family.
Schema versioning is tracked in a dedicated metadata key. RocksDB is a good
fit for high-throughput chain writes with embedded deployment; the operational
trade-off is a more complex schema design and less mature tooling for SQL-
style forensic queries.

**In-memory with journal replay (test and development scope).** An ephemeral
backend that holds entries in a `Vec` with a journal file for crash recovery
is conformant within its deployment scope if: the in-memory append is
serialized by a `Mutex` (Required #4), a UNIQUE check on `prev_hash` is
enforced in the append path (Required #2), the journal file is fsynced on
commit (Required #5 within the journal's durability scope), and the schema
version is tracked and enforced on journal replay (Required #8). This backend
is appropriate for integration tests and development iteration; it is not
appropriate for production deployments where hardware failure is a realistic
concern. The Optional scrubbing and reconstitution affordances are not present
in this configuration; that is acceptable for the test scope.

---

## 8. Autoregressive update triggers

1. **A new storage backend is adopted.** If the substrate ships a new chain-
   persistence backend — FoundationDB, a WASM-hosted SQLite, a custom
   append-log format — this doc should be updated with a new portability
   sketch naming the specific primitives that satisfy the Required affordances
   and any operational considerations. The contract itself should not change;
   the new sketch demonstrates the contract's backend-agnosticism.

2. **A new chain primitive requires new storage semantics.** If the substrate
   introduces epoch boundaries with stronger consistency requirements at epoch
   transitions, or if a new receipt type requires a storage-level uniqueness
   constraint not covered by the current Required affordances, the Required
   affordances should be updated to name the new semantic. The update is a
   Required affordance addition, not a relaxation.

3. **A Required affordance proves hard to implement portably.** If "UNIQUE
   constraint on `prev_hash`" turns out to be unavailable in a storage backend
   worth supporting — perhaps a backend where constraint enforcement must be
   application-level rather than storage-level — the question is whether to
   relax the Required affordance (accept application-level enforcement for this
   backend) or accept that the backend is out of scope for conformant chain
   hosting. Either answer belongs in this doc.

4. **A Forbidden affordance is proposed for relaxation.** If someone proposes
   "allow mutation of existing entries for recanonicalization purposes," this
   doc is what the proposal must justify against. The default answer is no;
   AUDIT-03 is the empirical evidence for why mutation paths produce chain
   corruption even when the intent is repair.

5. **A storage-layer integrity incident of the AUDIT-03 shape.** If a future
   incident surfaces a new class of chain corruption — a forbidden affordance
   not yet named here — this doc should be updated with a new Forbidden entry
   calibrated against that incident's failure shape. The Forbidden category is
   where empirical incidents become structural prohibitions.

6. **A new principle is added to Architecture Part V½.** Each new principle
   may make existing Optional affordances Required or add new Forbidden entries
   where a storage-level use would violate the new principle.

---

## 9. Refs

- `docs/handoffs/storage-tier-affordance-pass-2026-06.md` — the
  architectural-decisions source; the Required / Optional / Forbidden partition
  and the AUDIT-03 mapping this contract synthesizes
- `docs/audit-architecture.md` — the canonical post-AUDIT-03 reference; §§1,
  2, 3, 4, 5 carry the substantive content the contract's Required affordances
  derive from; §§6, 9, 10 carry the incident history and dev checklist
- `docs/audit-invariant.md` — the formal chain invariant and non-negotiables;
  the invariant statement is the structural commitment the Storage tier hosts
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` — the hub contract;
  §4 Tier 7 entry ("Storage tier"); §5 contract template; §5.c tier-scoping
  discipline
- `docs/OPERATOR-SUBSTRATE-CONTRACT-2026-06.md` — the Operator substrate tier
  contract; the Chain sub-layer's Required affordances name what it requires
  from the Storage tier at the `AuditStore::append` boundary
- `docs/EDGE-TIER-CONTRACT-2026-06.md` — the template exemplar; the
  Required / Optional / Forbidden structure and composition-with-principles
  section this doc follows
- `docs/ARCHITECTURE-2026-04.md` Part I §2 — the four claims; Claim 1
  (each step conditioned on full prior context) is the primary claim the
  Storage tier makes testable; Claim 2 (present state compresses full history)
  depends on the ordered-range-read Required affordance
- `docs/ARCHITECTURE-2026-04.md` Part V½ — the eight design principles;
  P1, P4, P5, P8 all carry load-bearing weight at this tier simultaneously
- `crates/zp-audit/src/store.rs` — the `AuditStore` implementation; the
  primary Storage tier implementation site
- `crates/zp-audit/src/recovery.rs` — crash recovery implementation
- `crates/zp-audit/src/scrub.rs` — scrubbing implementation (Optional #6)
- `crates/zp-audit/src/reconstitute.rs` — reconstitution tooling (Optional #7)
