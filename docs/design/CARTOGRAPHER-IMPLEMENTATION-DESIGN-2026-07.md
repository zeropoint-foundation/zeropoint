# Cartographer — Implementation Design

**Document type:** Tier 2 canonical elaboration — implementation-design layer over `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md`. Elaborates KEEL §II.7 (Cartographer as infrastructure), §II.9 (Layer A/B split), §II.13 P3 (there is no center) + P4 (every bit counts) + P5 (store-and-forward is primary) + P9 (system acts; operator signs), Part IV (ontology definitions), Part V (composition contract). Where the parent spec defines *what* the ontology and Cartographer are, this doc defines *how* they get built.

**Author:** Ken Romero (2026-07-25). Synthesis assistance from Claude.

**Status:** Implementation-design pass. Ready to inform code work in `zp-ontology` crate + Cartographer background task in `zp-server`. Composes with SUBSTRATE-COMPUTE-BASELINE (APOLLO-tier where appropriate; Pi-side where required), SUBSTRATE-TABULAR-CLASSIFIER (ontology attribution joins feature projection), AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL (primary consumer via OntologyReader), LENS-DISCIPLINE (Cartographer materializes lens ontology from lens receipts), and the officer cadre (secondary consumers).

---

## Framing

`ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` defines a coherent design: five object types (Trajectory, Decision, Insight, Artifact, Friction), typed relationships, SQLite-backed derived storage, Cartographer as first-class actor emitting receipts for its own actions, five-phase implementation plan. The spec is design-complete at the "what" level.

This doc fills the implementation-design gap between the what-spec and actual code. It resolves the questions a Rust engineer needs answered before writing a line: the boundary-detection algorithm shape, storage schema DDL, runtime lifecycle, object identity semantics, query API concurrency model, receipt payload shapes, composition points with newer specs, testing strategy, and concrete phased milestones.

The single hardest problem is boundary detection — the parent spec calls it "the core research problem of the entire design." Section 1 gives it the largest treatment. Everything else is engineering.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`.

- **`lens_id`**: `cartographer_implementation`
- **`focus`**: how the Cartographer materializes chain-anchored ontology objects deterministically, incrementally, and rebuild-consistently — with confidence-scored boundary detection, chain-anchored receipts for its own actions, and clean query surface for downstream consumers (officers, Regent, dashboards, Aegis v2)
- **`dimensions`**: boundary-detection algorithm (five-signal confidence fusion), object identity (deterministic content-address), storage schema (SQLite tables + indexes + WAL), runtime lifecycle (startup / notifier / shutdown / crash recovery), query API concurrency (RwLock + snapshot semantics), receipt schemas (ontology:* payload shapes), rebuild determinism, testing strategy (golden corpus + property + rebuild-diff)
- **`keyword_composition`**: [Cartographer, ontology, trajectory, boundary detection, confidence scoring, materialization, rebuild determinism, chain replay, high-water mark, notifier, incremental, OntologyStore, OntologyReader, SQLite, WAL, snapshot, object identity, content-address, receipt schema, cartographer receipt, ontology correction, golden corpus test, property test]
- **`transformation_question`**: *"how does the Cartographer materialize chain-anchored understanding deterministically and incrementally, such that officers, Regent, and dashboards can query it as though it were substrate ground truth, while the chain remains the sole source of truth?"*
- **`cross_references`**: `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (parent what-spec), `SUBSTRATE-COMPUTE-BASELINE-2026-07.md` (compute placement), `SUBSTRATE-TABULAR-CLASSIFIER-2026-07.md` (feature-projection composition), `AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL-2026-07.md` (primary consumer), `LENS-DISCIPLINE-2026-07.md` (lens receipt ingestion), `OBSERVER-COHERENCE-DISCIPLINE-2026-07.md` (Class 2 ontology queriers coherence class), `CHAIN-READ-CANARY-DISCIPLINE-2026-07.md` (Cartographer is a chain reader; participates in canary discipline)

Directional: **inside-out** (substrate self-observation via materialized ontology from its own chain).

---

## Section 1 — Boundary detection algorithm

**The core problem.** Given a stream of chain receipts, determine which receipts belong to which Trajectory. Trajectories emerge from activity; the Cartographer materializes them from structural signals.

### Signal set (five deterministic signals)

Each signal produces a per-receipt-transition **boundary score** in `[-1.0, +1.0]`. Positive scores argue *for* a new trajectory boundary (this receipt starts a new trajectory relative to the prior one); negative scores argue *against* (this receipt continues the existing trajectory). Signals combine into a weighted sum; when the sum crosses a threshold, a boundary is declared.

#### Signal S1 — Conversation continuity

Compare `receipt.conversation_id` to the trajectory's dominant `conversation_id` (or the immediately-preceding receipt in the trajectory candidate).

| Condition | Boundary score contribution |
|---|---|
| Same `conversation_id` as trajectory's dominant | **-0.6** (strong continuity signal) |
| Different `conversation_id`, but trajectory has multi-conversation history | **-0.2** (weak continuity) |
| Different `conversation_id`, trajectory is single-conversation to date | **+0.3** (weak boundary signal) |
| Never-before-seen `conversation_id` and trajectory is at capacity threshold | **+0.5** (medium boundary signal) |

Rationale: `conversation_id` is the strongest structural continuity marker available. Two receipts sharing a conversation-id are almost certainly part of the same working session.

#### Signal S2 — Time gap

Compare `receipt.timestamp` to the trajectory's `last_active` timestamp.

| Gap | Boundary score contribution |
|---|---|
| < 5 min | **-0.4** (recent-activity continuity) |
| 5 min – 1 hr | **-0.1** (weak continuity) |
| 1 hr – 4 hr | **0.0** (neutral — trajectory naturally has gaps) |
| 4 hr – 24 hr | **+0.2** (weak boundary signal) |
| 24 hr – 7 days | **+0.4** (medium boundary — trajectory likely dormant, this is resumption or new work) |
| > 7 days | **+0.6** (strong boundary — extended dormancy suggests new arc) |

Config default: `time_gap_short_threshold_secs = 300`, `time_gap_medium_threshold_secs = 14400`, `time_gap_long_threshold_secs = 86400`. Operator-tunable.

Note: gap signal is *directional but not decisive*. An operator picking up a dormant trajectory after 10 days should not be split from the prior trajectory if other signals (conversation, actor, domain) strongly argue continuity. That's the point of confidence fusion.

#### Signal S3 — Actor transition

Compare `receipt.actor` to the trajectory's dominant primary actor.

| Condition | Boundary score contribution |
|---|---|
| Same actor as dominant | **-0.2** (weak continuity) |
| Different actor, but is officer/tool acting within operator's trajectory (structural pattern) | **-0.1** (officers act within trajectories, not beside them) |
| Different operator actor | **+0.3** (medium boundary — different operator = different trajectory in multi-operator households per SOVEREIGN-KINSHIP-PRIMITIVES) |
| Different Regent instance | **+0.5** (strong boundary — different Regent = different agent trajectory) |

Rationale: actor changes are boundary-suggestive but require care. Steward emitting a finding *during* a trajectory is not a boundary; a different operator picking up work *is*.

#### Signal S4 — Domain clustering

Compare `receipt.event_prefix` (first 2 colon-separated segments of the event string) to the trajectory's dominant domain prefix distribution.

| Condition | Boundary score contribution |
|---|---|
| Exact match with dominant prefix | **-0.3** (strong continuity) |
| Match with any prefix in trajectory's top-3 distribution | **-0.1** (weak continuity) |
| Different prefix, but same top-level namespace (e.g. both `officer:*`) | **0.0** (neutral) |
| Different top-level namespace than any in trajectory's distribution | **+0.4** (medium boundary — domain shift) |

Rationale: trajectories have coherent domain distributions. A run of `officer:*` receipts followed by a run of `regent:tool:*` receipts often but not always represents two trajectories.

#### Signal S5 — Explicit markers

Operator or cockpit-emitted `ontology:trajectory:started` / `ontology:trajectory:ended` receipts are **definitive**.

| Condition | Boundary score contribution |
|---|---|
| `ontology:trajectory:started:*` receipt | **+1.0** (definitive boundary — new trajectory begins here) |
| `ontology:trajectory:ended:*` receipt | **+1.0** (definitive boundary — current trajectory ends here) |
| `ontology:trajectory:continued:*` receipt (operator-signed marker of continuity across ambiguous gap) | **-1.0** (definitive continuity — Cartographer must not split here) |

The `-1.0` case veto-overrides all other signals: if operator has explicitly declared continuity, boundary detection respects it. This is the operator's final-authority path per parent spec §Governance.

### Confidence fusion

For each candidate boundary decision, compute:

```
raw_score = sum(signal_scores[S1..S5])
```

Because operator-explicit markers can veto (±1.0), check for those first:

```
if any signal == +1.0: declare_boundary(confidence=1.0, reason="explicit_start_or_end_marker")
if any signal == -1.0: declare_continuity(confidence=1.0, reason="explicit_continuity_marker")
```

Otherwise, apply threshold + confidence formula:

```
BOUNDARY_THRESHOLD = 0.5  // configurable
CONFIDENCE_SCALE = 1.5    // divides raw_score to produce 0.0-1.0 confidence

if raw_score >= BOUNDARY_THRESHOLD:
    boundary = true
    confidence = min(raw_score / CONFIDENCE_SCALE, 1.0)
else:
    boundary = false
    confidence = 1.0 - min(raw_score / CONFIDENCE_SCALE, 1.0)  // confidence in continuity
```

Confidence is emitted as a first-class field on `Trajectory.boundary_confidence` and in the `ontology:trajectory:created:*` receipt. Officers and dashboards can surface low-confidence trajectories for operator review per the parent spec's Tier-1 mitigation strategy.

### Default to over-splitting

Per parent spec §"Mitigation strategy for Tier 1": when uncertain, split rather than merge. The threshold above (`0.5`) is deliberately conservative — moderate signals produce boundaries. Operators merge two trajectories that should be one via `zp trajectory merge` more easily than untangling one that should be two.

### Streaming forward-pass algorithm

The Cartographer processes chain receipts sequentially (in `rowid` order, since chain is append-only). Each receipt is either:

1. **Assigned to the currently-active trajectory** (no boundary declared)
2. **Starts a new trajectory** (boundary declared)
3. **Resumes a dormant trajectory** (special case — matched against dormant trajectories by conversation-id, dominant actor, domain — if match confidence exceeds `RESUMPTION_THRESHOLD = 0.6`, assign to resumed trajectory rather than creating new)

Pseudo-code:

```
fn process_receipt(receipt, current_trajectory, dormant_trajectories, config):
    // Step 1: check for explicit markers first (definitive)
    if is_explicit_start_marker(receipt): return NewTrajectory { confidence: 1.0 }
    if is_explicit_continuity_marker(receipt): return AssignTo(current_trajectory, confidence: 1.0)

    // Step 2: score against current trajectory
    scores = [s1(receipt, current), s2(receipt, current), s3(receipt, current), s4(receipt, current)]
    raw = sum(scores)

    // Step 3: check resumption candidates (dormant trajectories)
    for dormant in dormant_trajectories:
        resumption_score = evaluate_resumption_match(receipt, dormant)
        if resumption_score >= RESUMPTION_THRESHOLD:
            return ResumeTrajectory(dormant, confidence: resumption_score)

    // Step 4: normal boundary decision
    if raw >= BOUNDARY_THRESHOLD:
        return NewTrajectory { confidence: min(raw / CONFIDENCE_SCALE, 1.0) }
    else:
        return AssignTo(current_trajectory, confidence: 1.0 - min(raw / CONFIDENCE_SCALE, 1.0))
```

Complexity: O(N × D) where N is receipt count and D is dormant-trajectory count. D is bounded (default 50 dormant trajectories cached before eviction to persistent-only storage). N is amortized across incremental processing (typically one receipt per notifier tick).

### Determinism

Given the same chain input and the same config, the algorithm produces the same trajectory assignment. This is load-bearing for rebuild consistency (§Testing strategy) and content-addressed IDs (§Section 4).

Deterministic requirements:
- Signal scoring is pure over `(receipt, trajectory_state)`
- Signal order is fixed
- Dormant-trajectory eviction policy is deterministic (LRU by `last_active`)
- No wall-clock decisions except comparing receipt timestamps to each other

---

## Section 2 — Storage schema

### Database layout

`~/ZeroPoint/data/ontology.db` — SQLite, WAL journal mode, foreign keys enabled.

### Tables

```sql
-- Metadata / high-water mark
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
) WITHOUT ROWID;

-- Objects (Trajectory, Decision, Insight, Artifact, Friction)
CREATE TABLE objects (
    id BLOB PRIMARY KEY,                    -- 16-byte content-addressed hash
    object_type TEXT NOT NULL CHECK (object_type IN
        ('trajectory', 'decision', 'insight', 'artifact', 'friction')),
    trajectory_id BLOB,                      -- FK to objects(id) where type='trajectory', NULL for Trajectory rows
    status TEXT NOT NULL,                    -- e.g. 'active', 'dormant', 'superseded'
    title TEXT NOT NULL,                     -- derived name for display
    payload BLOB NOT NULL,                   -- serde_json serialization of full object
    boundary_confidence REAL,                -- present only on trajectory rows; NULL otherwise
    created_at TEXT NOT NULL,                -- RFC3339
    last_active TEXT NOT NULL,               -- RFC3339
    FOREIGN KEY (trajectory_id) REFERENCES objects(id)
);

CREATE INDEX idx_objects_type_status ON objects(object_type, status);
CREATE INDEX idx_objects_trajectory ON objects(trajectory_id) WHERE trajectory_id IS NOT NULL;
CREATE INDEX idx_objects_last_active ON objects(last_active);
CREATE INDEX idx_objects_type_active ON objects(object_type, last_active DESC);

-- Relationships (typed, directional)
CREATE TABLE relationships (
    id BLOB PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_id BLOB NOT NULL,
    target_type TEXT NOT NULL,
    target_id BLOB NOT NULL,
    kind TEXT NOT NULL,                      -- 'contributes_to', 'belongs_to', etc.
    created_at TEXT NOT NULL,
    payload BLOB NOT NULL,                   -- serde_json serialization of full Relationship
    UNIQUE (source_type, source_id, target_type, target_id, kind)
);

CREATE INDEX idx_rel_source ON relationships(source_type, source_id);
CREATE INDEX idx_rel_target ON relationships(target_type, target_id);
CREATE INDEX idx_rel_kind ON relationships(kind);

-- Receipt references (many-to-many between objects/relationships and audit entries)
CREATE TABLE object_receipts (
    object_id BLOB NOT NULL,
    audit_id BLOB NOT NULL,                  -- AuditId from chain
    role TEXT,                                -- optional: 'origin', 'evidence', 'update'
    PRIMARY KEY (object_id, audit_id)
);

CREATE INDEX idx_object_receipts_audit ON object_receipts(audit_id);

CREATE TABLE relationship_receipts (
    relationship_id BLOB NOT NULL,
    audit_id BLOB NOT NULL,
    PRIMARY KEY (relationship_id, audit_id)
);
```

### Meta keys (v1)

- `last_processed_sequence` — highest audit rowid Cartographer has processed
- `last_processed_at` — RFC3339 timestamp of last processed receipt
- `cartographer_version` — Cartographer implementation version (semver)
- `schema_version` — ontology schema version (integer)
- `boundary_config` — JSON-serialized config used for the most recent processing pass (allows detecting config changes that require rebuild)
- `rebuild_in_progress` — presence indicates ongoing rebuild; enables crash-recovery to resume

### Concurrency

- **Journal mode:** WAL — enables one writer + many readers concurrently without blocking.
- **Writer:** Cartographer background task holds exclusive access via `Arc<Mutex<Connection>>` internally, serializes writes.
- **Readers:** `OntologyReader` instances acquire read connections from a pool; readers do not block writer, writer does not block readers (WAL semantics).
- **Crash safety:** SQLite WAL provides atomicity per transaction. Cartographer wraps each `process_receipt` result in a single transaction that (a) inserts/updates objects, (b) inserts relationships, (c) inserts object_receipts entries, (d) updates `last_processed_sequence` in meta. Either the entire per-receipt result commits or nothing does.

### Migrations

Version-in-meta with hand-written migration scripts (`migrations/schema-v1-to-v2.sql`). No `sqlx-migrate` or heavy migration framework needed at Phase 1 scale. Migration runs at Cartographer startup if `schema_version` in meta < compiled-in version; runs to completion or refuses to start (fail-loud, no half-migrated states).

---

## Section 3 — Runtime lifecycle

### Startup sequence

```
1. Open ontology.db (create + apply schema if not present)
2. Migrate schema if version mismatch
3. Read meta:last_processed_sequence
4. Check chain.get_max_sequence() vs last_processed
5. If chain.max > last_processed:
     Launch catchup loop:
       Fetch batches of receipts (rowid > last_processed_sequence)
       Process each receipt via boundary-detection algorithm
       Commit per-receipt transaction
       Update meta:last_processed_sequence at end of batch
6. When caught up: register notifier hook with AuditStore
7. Enter steady-state loop:
     Wait for notifier signal (new receipt appended)
     Fetch new receipt via chain.get_by_sequence
     Process
     Commit
```

Catchup batch size default: 1000 receipts. At 6K chain, initial catchup completes in seconds. At 100K, tens of seconds. Reported to operator via startup log lines.

### Notifier hook

`zp_audit::AuditStore::set_notifier(fn(rowid: i64))` invokes Cartographer's notification handler when a new receipt is appended. Handler enqueues the rowid to Cartographer's processing channel (`tokio::sync::mpsc`). Cartographer background task processes from the channel.

### Backpressure

Bounded channel (default capacity 1000). If Cartographer falls behind (rare — processing is millisecond-per-receipt on APOLLO), channel fills; append operations continue (chain is authoritative), but Cartographer's next batch is enqueued when channel drains.

If the channel would overflow: Cartographer emits `ontology:cartographer:backpressure_signaled` receipt and enters catch-up mode (drops the notifier subscription, resumes fetching from `last_processed_sequence` in batches until caught up, then re-subscribes). Prevents unbounded memory growth under pathological chain-write bursts.

### Shutdown

Graceful drain:
1. Drop notifier subscription
2. Drain processing channel
3. Commit final `last_processed_sequence`
4. Emit `ontology:cartographer:shutdown:graceful` receipt
5. Close SQLite connection

If shutdown times out (default 30s), emit `ontology:cartographer:shutdown:forced` and exit. On next startup, catchup handles any un-processed receipts.

### Crash recovery

Idempotency is the primary defense. Reprocessing a receipt produces the same result given deterministic boundary detection. On startup, Cartographer catches up from `last_processed_sequence` regardless of the reason for the gap (crash, forced shutdown, missed notifier).

If `rebuild_in_progress` is set in meta (from a prior interrupted rebuild), Cartographer resumes the rebuild before entering steady state.

### Compute placement per SUBSTRATE-COMPUTE-BASELINE

Cartographer runs **Pi-side** in the canonical composition. It's a chain reader; the chain lives on the sovereignty anchor. The processing itself is lightweight (structural pattern matching, no ML inference), well within Pi 5 capacity.

Heavier ontology *queries* (e.g. Aegis v2 trajectory scoring across large observation windows, dashboard rendering with joins) may rally to APOLLO for compute. The rally reads the ontology snapshot; queries execute APOLLO-side; results return.

---

## Section 4 — Object identity and CREATE/UPDATE semantics

### Deterministic IDs

Object IDs are content-addressed for rebuild determinism. Given identical chain input + identical config, rebuild produces identical IDs.

**Trajectory ID:**
```
trajectory_id = sha256("trajectory:" + first_receipt.entry_hash + ":" + boundary_signals_json)[..16]
```
Where `boundary_signals_json` is the deterministic JSON serialization of the S1-S5 scores that triggered the boundary. This ensures ID stability across rebuilds while remaining unique per boundary decision.

**Decision/Insight/Artifact/Friction ID:**
```
object_id = sha256("<object_type>:" + originating_receipt.entry_hash + ":" + object_class_discriminator)[..16]
```
Where `object_class_discriminator` is the object-type-specific field that distinguishes multiple objects that could be derived from the same receipt (e.g., for Decisions, the specific decision predicate that triggered materialization).

**Relationship ID:**
```
relationship_id = sha256("rel:" + source_id + ":" + target_id + ":" + kind)[..16]
```
Deterministic on `(source, target, kind)` — the same relationship is not materialized twice.

### CREATE vs UPDATE

Cartographer processing a new receipt does one of:

- **CREATE new object** — receipt matches materialization rules for a not-yet-existing object. Insert row.
- **UPDATE existing object** — receipt provides additional evidence for or state transition of an existing object. Update `payload`, `status`, `last_active`; append to `object_receipts`.
- **CREATE relationship** — receipt establishes a new typed edge between objects. Insert relationship row + relationship_receipts entries.
- **UPDATE relationship** — receipt reinforces an existing relationship (add to `receipt_refs`). Update `payload`, append to `relationship_receipts`.
- **No action** — receipt does not affect ontology (many receipts have no direct ontology impact — e.g., canary receipts, most heartbeats).

The materialization-rule set is Layer B canonical. Each rule maps a receipt-pattern to an object-materialization action. Rules ship compiled-in for v1; extensible via canonicalization ceremony.

### Object lifecycle state transitions

Trajectories:
- `active` → `dormant`: no activity for `dormant_threshold_secs` (default 604800 = 7 days)
- `dormant` → `active`: resumption via new receipt with sufficient match score (per §Section 1)
- `active` / `dormant` → `completed`: operator emits `ontology:trajectory:completed:*` receipt
- `dormant` → `abandoned`: extended dormancy past `abandonment_threshold_secs` (default 2592000 = 30 days) without resumption

Decisions:
- `active` → `superseded`: newer decision receipt references this one as superseded
- `active` → `reverted`: operator emits `ontology:decision:reverted:*` receipt

Frictions:
- `active` → `mitigated`: workaround identified (operator or Regent emits marker)
- `active` / `mitigated` → `resolved`: operator emits resolution marker

State transitions themselves emit `ontology:object:updated:*` receipts.

---

## Section 5 — Query API detail

### `OntologyStore` (writer-side, Cartographer-only)

```rust
pub struct OntologyStore {
    conn: Arc<Mutex<Connection>>,  // WAL-mode SQLite
    config: BoundaryConfig,
}

impl OntologyStore {
    pub fn open(path: impl AsRef<Path>, config: BoundaryConfig) -> Result<Self, StoreError>;
    pub fn last_processed_sequence(&self) -> Result<Option<i64>, StoreError>;
    pub fn process_receipt(&self, receipt: &AuditEntry) -> Result<ProcessResult, StoreError>;
    pub fn commit_batch(&self, results: &[ProcessResult]) -> Result<(), StoreError>;
    pub fn reader(&self) -> OntologyReader<'_>;
}

pub enum ProcessResult {
    NoAction,
    CreatedObject { id: ObjectId, object_type: ObjectType, boundary_confidence: Option<f32> },
    UpdatedObject { id: ObjectId },
    CreatedRelationship { id: RelationshipId, kind: RelationshipKind },
    UpdatedRelationship { id: RelationshipId },
    OperatorCorrection { id: ObjectId, correction_type: CorrectionType },
}
```

### `OntologyReader` (read-only, many concurrent instances)

```rust
pub struct OntologyReader<'a> {
    conn: PooledConn,               // read-connection from pool
    snapshot_seq: i64,               // last_processed_sequence at reader-open time
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> OntologyReader<'a> {
    // Trajectory queries
    pub fn active_trajectories(&self) -> Result<Vec<Trajectory>, ReadError>;
    pub fn dormant_trajectories(&self) -> Result<Vec<Trajectory>, ReadError>;
    pub fn trajectory_by_id(&self, id: &TrajectoryId) -> Result<Option<Trajectory>, ReadError>;
    pub fn trajectories_by_actor(&self, actor: &ActorId) -> Result<Vec<Trajectory>, ReadError>;
    pub fn trajectories_touching_receipt(&self, hash: &str) -> Result<Vec<TrajectoryId>, ReadError>;

    // Sub-object queries
    pub fn decisions_for(&self, traj: &TrajectoryId) -> Result<Vec<Decision>, ReadError>;
    pub fn insights_for(&self, traj: &TrajectoryId) -> Result<Vec<Insight>, ReadError>;
    pub fn artifacts_for(&self, traj: &TrajectoryId) -> Result<Vec<Artifact>, ReadError>;
    pub fn frictions_for(&self, traj: &TrajectoryId) -> Result<Vec<Friction>, ReadError>;

    // Relationship queries
    pub fn relationships_from(&self, obj: &ObjectRef) -> Result<Vec<Relationship>, ReadError>;
    pub fn relationships_to(&self, obj: &ObjectRef) -> Result<Vec<Relationship>, ReadError>;

    // Freshness metadata
    pub fn snapshot_sequence(&self) -> i64;
    pub fn snapshot_age_secs(&self, now: DateTime<Utc>) -> i64;
}
```

### Staleness semantics

Each `OntologyReader` captures `snapshot_sequence` at open time. Reader queries reflect ontology state at that sequence. If Cartographer has processed new receipts since reader was opened, the reader does NOT see them — this is snapshot isolation, prevents flickering results within a single query cycle.

Callers who need fresh reads open a new reader. Cheap operation (pool checkout + one meta query).

### Errors

```rust
pub enum ReadError {
    ConnectionPool(String),
    Query(rusqlite::Error),
    Deserialization(serde_json::Error),
    ObjectNotFound(ObjectId),
    SnapshotStale { snapshot_seq: i64, current_seq: i64 },  // opt-in strict-freshness mode
}
```

### Composition with OBSERVER-COHERENCE-DISCIPLINE Class 2

`OntologyReader` is a Class 2 (ontology queriers) member per OBSERVER-COHERENCE-DISCIPLINE. Multiple substrate paths querying the ontology should produce coherent views on the same snapshot sequence. Coherence probe: fetch object-count summary + last-canonicalization hash per member; disagreement flags either stale Cartographer materialization or corrupted read path.

---

## Section 6 — Cartographer receipt schemas

Cartographer emits chain receipts for its own actions per KEEL §II.7 (Cartographer as first-class actor). All receipts signed with Cartographer's Genesis-derived signing key.

### `ontology:cartographer:startup`
```json
{
  "cartographer_version": "0.1.0",
  "schema_version": 1,
  "resumed_from_sequence": 12345,
  "chain_max_sequence": 12500,
  "catchup_needed": 155,
  "boundary_config_hash": "sha256:..."
}
```

### `ontology:cartographer:shutdown:graceful` / `:forced`
```json
{
  "last_processed_sequence": 12500,
  "reason": "signal_term" | "config_reload" | "operator_stop",
  "receipts_processed_this_session": 155,
  "graceful": true
}
```

### `ontology:trajectory:created:<trajectory_id>`
```json
{
  "trajectory_id": "<16-byte-hex>",
  "title": "<derived-from-dominant-signals>",
  "originating_receipt_hash": "<receipt-that-triggered-boundary>",
  "boundary_confidence": 0.85,
  "boundary_signals": {
    "conversation": 0.3,
    "time_gap": 0.2,
    "actor": 0.0,
    "domain": 0.4,
    "explicit_marker": null
  },
  "dominant_conversation_id": "<uuid>",
  "dominant_actor": "<actor-id>",
  "dominant_event_prefix": "delegation:*"
}
```

### `ontology:trajectory:updated:<trajectory_id>`
```json
{
  "trajectory_id": "<hex>",
  "receipt_added": "<hash>",
  "state_transition": null | "active_to_dormant" | "dormant_to_active" | ...,
  "last_active": "<rfc3339>",
  "total_receipts_now": 42
}
```

### `ontology:object:created:<type>:<id>`
Generic form for Decision, Insight, Artifact, Friction:
```json
{
  "object_type": "decision" | "insight" | "artifact" | "friction",
  "object_id": "<hex>",
  "trajectory_id": "<hex>",
  "originating_receipt_hash": "<hash>",
  "title": "<derived>",
  "materialization_rule": "<layer-b-rule-id>"
}
```

### `ontology:relationship:created:<source_type>:<target_type>:<kind>`
```json
{
  "relationship_id": "<hex>",
  "source": {"type": "trajectory", "id": "<hex>"},
  "target": {"type": "decision", "id": "<hex>"},
  "kind": "contains",
  "receipt_refs": ["<hash1>", "<hash2>"]
}
```

### `ontology:correction:auto:<object_id>`
Cartographer's self-correction when it detects structural inconsistency (e.g., an object whose receipt refs no longer support its state):
```json
{
  "object_id": "<hex>",
  "correction_type": "receipt_ref_invalidated" | "supersession_detected" | "orphaned",
  "prior_state_hash": "<sha256>",
  "new_state_hash": "<sha256>",
  "rationale": "<short-machine-readable>"
}
```

### `ontology:correction:operator:<object_id>`
Emitted when operator signs a correction (e.g., `zp trajectory merge`):
```json
{
  "object_id": "<hex>",
  "correction_type": "merge" | "split" | "reclassify" | "supersede",
  "operator_intent": "<short-rationale>",
  "related_object_ids": ["<hex>", ...]  // e.g., for merge, the merged-away trajectory
}
```

### `ontology:cartographer:backpressure_signaled`
```json
{
  "channel_capacity": 1000,
  "queued_count": 987,
  "action": "catchup_mode_engaged",
  "resume_estimate_secs": 12
}
```

---

## Section 7 — Composition with newer specs

### With SUBSTRATE-COMPUTE-BASELINE

Cartographer runs Pi-side (chain-local). Heavy ontology queries rally to APOLLO. Two-tier compute placement:
- **Materialization** (Cartographer's writer path): Pi-side, chain-adjacent
- **Query** (OntologyReader consumers): reader can be either Pi-side (for lightweight queries) or APOLLO-side via rally (for heavy joins, Aegis v2 scoring, dashboard rendering)

### With SUBSTRATE-TABULAR-CLASSIFIER

Ontology attribution becomes a feature-projection input. When the classifier scores a receipt, it can join against `object_receipts` table to add trajectory-attribution features:
- `trajectory_id` (categorical, high-cardinality — bucket to top-N)
- `trajectory_status` (categorical)
- `trajectory_boundary_confidence` (numerical)
- `trajectory_size` (numerical — receipt count so far)
- `trajectory_age_hours` (numerical)

Feature-projection extension per SUBSTRATE-TABULAR-CLASSIFIER §Feature engineering (Layer B). Composes cleanly — no schema conflict.

### With AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL

**Primary consumer.** Aegis v2's per-trajectory scoring path:
```
Aegis observation cycle:
  reader = ontology.reader()
  for traj in reader.active_trajectories():
    receipts = reader.receipts_in_trajectory(traj.id)
    features = feature_projection.project(receipts, traj)
    scores = classifier.predict(features)
    emit_aegis_finding(traj, scores)
```

Aegis is the load-bearing consumer that motivates Cartographer's implementation urgency (per Gate 1 of REGENT-SELF-BUILDOUT-TRAJECTORY).

### With LENS-DISCIPLINE

Cartographer materializes lens ontology from `lens:declared:*`, `lens:applied:*`, `lens:composed:*`, `lens:conflicts:*` receipts.

Lens-as-object schema addition (future):
```rust
pub struct Lens {
    pub id: LensId,
    pub focus: String,
    pub dimensions: Vec<String>,
    pub keyword_composition: Vec<String>,
    pub transformation_question: String,
    pub cross_references: Vec<String>,
    pub declaration_receipt_hash: String,
    pub applications_count: u64,
    pub last_applied: Option<DateTime<Utc>>,
    pub silent_since: Option<Duration>,  // detects silent-lens-over-long-window
}
```

Lens is an ontology object class in its own right (not a Trajectory sub-object). Adding Lens materialization is a Phase 2+ extension per parent spec's phase model.

### With OBSERVER-COHERENCE-DISCIPLINE

Cartographer participates as the only writer to Class 2 (ontology queriers) coherence class. Coherence discipline probes multiple ontology readers against a shared snapshot; disagreement signals reader-path corruption or stale materialization. Cartographer's `snapshot_sequence` metadata surface is the coherence-probe hook.

### With CHAIN-READ-CANARY-DISCIPLINE

Cartographer is a chain reader; its read path participates in the canary discipline. If Cartographer's chain reads go stale (rare — same-process notifier hook usually delivers), canary detection triggers Cartographer restart per the canary Tier-3 remediation ladder.

---

## Section 8 — Testing strategy

### Golden corpus tests

Curated sequences of chain receipts with expected ontology outcomes. Located in `zp-ontology/tests/golden/`:

```
tests/golden/
  ├── single_trajectory/
  │   ├── input_chain.jsonl        # ordered receipt sequence
  │   └── expected_ontology.json   # expected trajectories, objects, relationships
  ├── boundary_time_gap/
  ├── boundary_conversation_change/
  ├── explicit_marker_override/
  ├── resumption_after_dormancy/
  ├── multi_actor_within_trajectory/
  └── operator_correction_merge/
```

Test runner: load `input_chain.jsonl`, feed to Cartographer, dump ontology, diff against `expected_ontology.json`. Any diff fails the test.

### Property-based tests

Using `proptest` or `quickcheck`. Invariants:
- **Receipt-assignment completeness:** Every receipt processed is assigned to exactly one Trajectory (except no-action receipts, which are unassigned).
- **Trajectory non-overlap:** No two Trajectories share receipts (partition property).
- **ID stability across rebuild:** For any receipt sequence, running Cartographer twice from scratch produces identical Trajectory IDs.
- **Explicit-marker respect:** `ontology:trajectory:started` receipt always produces a new Trajectory boundary; `ontology:trajectory:continued` never produces one.
- **Determinism:** Same input + same config = same output.

### Rebuild-diff test

The most load-bearing correctness test. Sequence:
1. Populate substrate with realistic chain (mix of officer heartbeats, delegations, tool events, corrections, ~5000 receipts).
2. Cartographer materializes ontology.
3. Dump `ontology.db` to canonical JSON.
4. Delete `ontology.db`.
5. Restart Cartographer.
6. Cartographer rebuilds from scratch.
7. Dump the rebuilt ontology to canonical JSON.
8. Diff step 3 and step 7. Should be empty.

If diff is non-empty, either boundary detection is non-deterministic, ID derivation is non-deterministic, or ordering of processing differs across runs.

### Notifier integration test

- Cartographer running, chain empty, ontology empty
- Append receipts via AuditStore
- Assert Cartographer processes them within notifier-latency budget
- Assert ontology state updates observable via OntologyReader

### Concurrent-read stress test

- Cartographer processing incrementally in background
- Many concurrent `OntologyReader` instances querying
- Assert no reader observes torn writes (snapshot isolation holds)
- Assert readers see monotonically-non-decreasing `snapshot_sequence`

### Test fixtures shared with Aegis v2

Aegis v2's trajectory-scoring tests will need materialized ontologies as input. Golden-corpus test fixtures are shareable — Aegis test suite reuses Cartographer's `expected_ontology.json` outputs as inputs.

---

## Section 9 — Phased implementation plan

### P0 — Scaffolding (small, contained)

- Create `crates/zp-ontology` crate with dependencies (rusqlite, chrono, serde, sha2, thiserror)
- Schema DDL in `crates/zp-ontology/migrations/schema-v1.sql`
- `OntologyStore::open()` skeleton — creates tables, applies migrations, returns handle
- Meta table read/write
- Golden-corpus test infrastructure (loader, differ, harness)

**Definition of done:** `cargo test -p zp-ontology` runs with harness in place; one trivial "empty chain produces empty ontology" test passes.

### P1 — Object types + basic CRUD

- Trajectory, Decision, Insight, Artifact, Friction Rust structs per parent spec's Phase 1 shapes
- Content-addressed ID derivation
- `OntologyStore::process_receipt` for simplest cases (single-trajectory chains, no boundaries)
- Insert / update paths
- Object-receipt linkage

**Definition of done:** Cartographer materializes a single Trajectory from a simple chain; ontology.db contains the expected rows.

### P2 — Tier 1 boundary detection (narrow signal set)

- Signals S1 (conversation continuity), S2 (time gap), S5 (explicit markers) implemented
- Confidence fusion with defaults from Section 1
- Boundary emission (`ontology:trajectory:created` receipts)

**Definition of done:** Golden-corpus tests for `single_trajectory`, `boundary_time_gap`, `boundary_conversation_change`, `explicit_marker_override` all pass.

### P3 — Cartographer background task in zp-server

- Tokio task with startup + catchup + notifier + steady-state loop
- AuditStore notifier hook integration
- Backpressure handling
- Graceful shutdown + crash recovery (idempotent replay)
- Startup / shutdown receipt emission

**Definition of done:** Cartographer runs live alongside officer cadre; can be observed emitting materialization receipts as chain grows during normal substrate operation.

### P4 — Full 5-signal boundary detection + resumption

- Signals S3 (actor transition), S4 (domain clustering) added
- Dormant-trajectory tracking + resumption matching
- Boundary confidence calibration against a representative chain corpus (empirical tuning of thresholds)

**Definition of done:** All golden-corpus tests pass; property tests pass; rebuild-diff test passes on a 5000-receipt corpus.

### P5 — OntologyReader + officer integration

- `OntologyReader` implementation with snapshot semantics
- Officer sweep pipeline extended: each officer's sweep receives both `ChainReader` and `OntologyReader`
- Cleo enhanced to query ontology for governance narration
- Steward enhanced to verify structural consistency of ontology objects

**Definition of done:** Officers query ontology in production sweeps; `substrate_validate` reports ontology-query health as a new check class.

### P6 — Operator correction CLI verbs

- `zp trajectory merge <traj_a> <traj_b>`
- `zp trajectory split <traj_id> <split_point>`
- `zp trajectory reclassify <traj_id> <new_title>`
- `zp trajectories` (list active/dormant with confidence)
- Each verb requires operator signature; emits `ontology:correction:operator:*` receipt
- Cartographer re-processes affected receipts after correction

**Definition of done:** Operator can round-trip an incorrect trajectory materialization: view via `zp trajectories`, correct via `zp trajectory merge`, verify correction on chain, observe corrected state on next `zp trajectories`.

### P7 — Aegis v2 integration point

- Aegis's `evaluate_cadence` extended (or v2 method added) to query `OntologyReader::active_trajectories`
- Per-trajectory feature projection call to substrate tabular classifier
- New Aegis receipt emission: `officer:aegis:trajectory:scored:*` per AEGIS-V2 proposal

**Definition of done:** Aegis emits `trajectory:scored` receipts alongside its cadence heartbeats; substrate_validate accepts the new receipt class as known.

### P8+ — Deferred to later canonicalization ceremonies

- Lens materialization (LENS ontology objects per §Section 7)
- Cockpit-emitted context receipt consumption (per parent spec Open Question 1)
- Inference-assisted refinement (parent spec Phase 4 — depends on local inference infrastructure)
- Cross-sovereign trajectory federation (per SOVEREIGN-KINSHIP-PRIMITIVES — probably never; kinship trajectories stay per-sovereign)

---

## Non-goals

- **Not a general-purpose graph database.** SQLite storage is deliberately narrow — objects + relationships + receipt-refs. Not designed to answer arbitrary graph queries; designed to answer trajectory-scope questions officers and dashboards actually ask.
- **Not inference-based in v1.** All boundary detection, materialization, correction is deterministic string/pattern processing. Inference-assisted refinement is Phase 4 per parent spec, and requires local-inference infrastructure that doesn't exist yet.
- **Not for external chain consumption.** Cartographer processes the operator's own chain, not chains of other sovereigns. Cross-sovereign observation would violate coordination-not-oversight (KEEL III.23).
- **Not a substitute for chain integrity discipline.** Ontology is a derived cache; chain is truth. Chain-integrity failure (per Steward) invalidates ontology derivations — Cartographer should stop materialization and defer to reset ceremony.
- **Not a real-time query surface.** Ontology reads have snapshot-consistency semantics — fresh reads require new reader. Real-time streams are chain-notifier territory, not ontology-query territory.

---

## Open positions

- **Boundary threshold empirical tuning.** Defaults in Section 1 are proposals. Real substrate chains will reveal calibration needs. Recommend: land defaults, log per-boundary raw scores + confidence, adjust after ~1000 boundaries of observed data.
- **Dormant-trajectory cache size.** Default 50 dormant trajectories in memory before eviction to persistent-only. Trade-off: memory vs resumption-lookup cost. Empirical.
- **Materialization-rule extensibility ceremony.** How does an operator add a new materialization rule (mapping receipt-pattern → object-materialization)? Prefer Layer B canonicalization ceremony analogous to Standing Correction ceremony.
- **Backpressure threshold behavior.** When channel fills, current design switches to catchup mode. Alternative: block the chain writer temporarily. Prefer non-blocking — chain must never wait on Cartographer.
- **Lens object materialization timing.** Should lens objects materialize immediately as `lens:declared` receipts land, or is Phase 2+? Prefer immediate for LENS-DISCIPLINE observability, but non-blocking (defer if Phase 1 timeline compresses).
- **Operator-correction propagation cost.** A `zp trajectory merge` requires re-processing all receipts in the merged-away trajectory to reassign them. For long-lived trajectories with many receipts, this could be slow. Acceptable at Phase 1 scale; may need incremental / lazy re-processing at larger scale.
- **Multi-conversation trajectory support.** Current design allows a trajectory to span multiple conversations (via S1's multi-conversation continuity signal). Empirical validation needed — do real substrate chains benefit from this, or is single-conversation-per-trajectory a cleaner boundary rule?

---

## What composes from here

Immediate:
1. `zp-ontology` crate scaffold + P0/P1 landing.
2. Golden-corpus test infrastructure alongside implementation.
3. Cartographer signing-key derivation (adds to VAULT-KEY-SOVEREIGNTY-COMPOSITION's canonical loader).

Near-term:
1. Boundary-detection empirical tuning phase (log scores in real substrate, adjust defaults).
2. Officer integration via OntologyReader.
3. Aegis v2 wiring against materialized trajectories.

Longer:
1. Lens ontology materialization (Phase 2+).
2. Dashboard widget queries backed by ontology (per DASHBOARD-CONNECTORS-STACK-DECISION).
3. Regent cognitive input plane Tier 2 pulling ontology summaries into cognitive context.

---

## Framing note

The parent spec is a mature what-spec — it names the objects, the storage, the composition. This doc is the how-spec. Together they should be sufficient for implementation to proceed without further design work at the substrate-cognitive layer.

The single hard problem (boundary detection) is now specified concretely. The remaining engineering — storage, lifecycle, query API, receipts, testing, phasing — is workmanlike but not novel.

The whole arc should fit within the runway that opened when Pi 5 hardware setbacks delayed physical assembly. Boundary-detection tuning specifically benefits from empirical exposure to a real substrate chain, which requires the substrate to be running long enough to accumulate representative activity — that argument favors landing P0/P1/P2 quickly, then letting the substrate run for a period of days with score-logging enabled, then tuning thresholds against the observed data.

Cartographer's arrival unblocks Aegis v2, which contributes to Gate 4 of the Regent Self-Buildout Trajectory. That in turn unblocks the tabular-classifier-fed anomaly detection that reframes the "TabFM/tree-search" strategic question we resolved earlier today. The whole arc composes: this doc is the load-bearing implementation-design that makes the rest tractable.
