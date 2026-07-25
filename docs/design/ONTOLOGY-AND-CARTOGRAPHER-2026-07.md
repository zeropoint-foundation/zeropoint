# Ontology Layer & The Cartographer

*2026-07-01. A structured understanding layer over the receipt chain.*

## Problem

Officers currently scan raw chain entries. Cleo pattern-matches on `delegation:granted:*` and `gate:denied:*`. Steward counts unsigned entries and measures chain silence gaps. This works for Tier 1 structural checks, but it has a ceiling: raw entries carry no semantic context. An officer can count delegation grants but can't answer "what is the operator working on, and does the governance posture fit?"

The chain is also operationally dense. 6,000+ entries accumulate from normal substrate activity — tool lifecycle, gate evaluations, policy interactions, epoch anchoring, officer heartbeats. When the operator returns to work, there's no way to ask "what matters right now?" without wading through raw logs or depending on a cockpit agent to interpret them.

The gap is a missing layer: structured objects with typed relationships, derived from the chain, rebuildable from the chain, queryable by officers and cockpits alike.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    Cockpits                          │
│              (the Regent, CLI, future UIs)                 │
│                  query ontology                      │
└──────────────────────┬───────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────┐
│              Officer Cadre                           │
│     Steward · Sentinel · Forge · Cleo                │
│     sweep ontology objects, emit findings            │
└──────────────────────┬───────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────┐
│              Ontology                                │
│     Trajectories · Decisions · Insights              │
│     Artifacts · Frictions                            │
│     + typed relationships between them               │
└──────────────────────┬───────────────────────────────┘
                       │ materialized by
┌──────────────────────▼───────────────────────────────┐
│              Cartographer                            │
│     reads new receipts → creates/updates objects     │
│     maintains relationships                          │
│     emits ontology:* receipts for its own actions    │
└──────────────────────┬───────────────────────────────┘
                       │ reads from
┌──────────────────────▼───────────────────────────────┐
│              Receipt Chain                           │
│     immutable, signed, hash-linked                   │
│     source of truth                                  │
└──────────────────────────────────────────────────────┘
```

The chain stays immutable and structureless. The ontology is a derived, rebuildable projection. Restart the Cartographer and it reconstitutes from the chain — same guarantee as cockpits reconstituting affordances from chain state.

The circular flow: the Cartographer reads chain entries and materializes ontology objects. Officers sweep the ontology and emit findings as new chain receipts. The Cartographer reads those receipts on the next pass. Everything stays grounded in the chain.

## The Cartographer

### What it actually is

The Cartographer is not a dumb index. Calling it "infrastructure" would be dishonest about the work it's doing.

It decides what constitutes a Trajectory. It decides when one arc of work ends and another begins. It decides what's a Decision versus routine activity. These are ontological judgments — high-leverage interpretive acts that shape how the entire system understands reality. If the Cartographer gets them wrong, the ontology is garbage and every officer querying it inherits that garbage.

So: the Cartographer is a first-class actor in the system. It has a chain identity (`ActorId::System("cartographer")`), it emits signed receipts when it creates or updates important objects (`ontology:trajectory:created`, `ontology:object:updated`, `ontology:correction:applied`), and its actions are auditable on the chain like any other actor's. Officers can read its receipts and verify its work. The operator can see what the Cartographer did and override it.

It is not an officer. Officers police; the Cartographer materializes. Officers have sweep cycles and emit findings about system health. The Cartographer has a continuous read loop and emits facts about what it understood. Different job, different cadence, different output type. But it's an actor with real authority over how the system represents reality, and the design needs to be honest about that.

Name rationale: "Cartographer" tells the operator what the system is doing without jargon. There's something in here reading what happened and drawing a map of it. Replaces the prior working name "Dreaming."

### The hard problem: trajectory boundary detection

This is the single hardest problem in the entire design. Everything else — object types, relationships, importance scores, officer queries — is secondary. If the Cartographer can't reliably detect trajectory boundaries, the ontology is useless.

The question: given a stream of chain entries, when does one arc of work end and another begin?

**Why this is genuinely difficult:**

An operator might work on three different things in one session, interleaving freely. A thread might go dormant for a week and then resume seamlessly. Two apparently separate threads might turn out to be the same trajectory viewed from different angles. The Cartographer has to get this right — or at least get it wrong in detectable, correctable ways — using only chain receipts as input.

**What we can actually detect with deterministic rules (Tier 1):**

1. **Conversation continuity.** Entries sharing a `conversation_id` belong to the same session. This is the strongest structural signal but only covers within-session grouping — it says nothing about cross-session trajectory continuity.

2. **Time gaps.** A gap of N hours between entries from the same actor is a candidate boundary. The threshold needs tuning — 4 hours might be right for some operators, 24 for others. Configurable, with a sensible default (8 hours).

3. **Actor transitions.** When the primary actor changes (operator → officer → tool → different operator), that's a candidate boundary. But officers and tools act *within* an operator's trajectory, not beside it, so this needs care.

4. **Domain clustering.** A run of governance events (`delegation:*`, `gate:*`) is structurally distinct from a run of tool lifecycle events (`tool:started:*`, `tool:stopped:*`). Domain boundaries are trajectory boundary candidates.

5. **Explicit markers.** If the operator or a cockpit emits an `ontology:trajectory:started` or `ontology:trajectory:ended` receipt, that's a definitive boundary. This is the escape hatch for when deterministic detection fails — the operator can always tell the system "no, this is a new thing."

**What these rules will get wrong:**

- An operator working on two interleaved things in one session. Conversation continuity says "one trajectory," reality says "two." Tier 1 will merge them incorrectly.
- A thread that resumes after 10 days of dormancy. The time gap rule says "new trajectory," but the operator picks up exactly where they left off. Tier 1 will split them incorrectly.
- Work that crosses domains — governance decisions driven by operational friction. Domain clustering says "two trajectories," reality says "one."

**The honest assessment:** Tier 1 rules will produce a trajectory map that's roughly 60-70% correct. The remaining 30-40% will be merge errors (things that should be separate) and split errors (things that should be connected). This is good enough to be useful — a rough map is better than no map — but the system needs to make its uncertainty visible and the operator's correction path frictionless.

**Tier 2 (inference-assisted) would help with:** cross-session continuity detection (does this new session's activity pattern match a dormant trajectory?), interleave detection (are these entries within one session actually two distinct threads?), and domain-crossing recognition. But Tier 2 depends on local inference infrastructure that doesn't exist yet. The Tier 1 rules must be strong enough to stand alone for months.

**Mitigation strategy for Tier 1:**

- Default to over-splitting rather than over-merging. It's easier for the operator to merge two trajectories that should be one (`zp trajectory merge`) than to untangle one trajectory that should be two.
- Make the Cartographer's confidence visible. Each Trajectory gets a `boundary_confidence` score: high when multiple signals agree (time gap + domain shift + actor change), low when only one signal fired. Officers and cockpits can surface low-confidence trajectories for operator review.
- Emit `ontology:trajectory:created` receipts with the structural signals that triggered the boundary. The operator can read why the Cartographer split here and decide if it was right.

### Operational posture

- Runs as a background task within `zp-server`, parallel to the officer sweep timer.
- Fires on new chain entries (event-driven via `AuditStore::set_notifier`) or on a periodic timer as fallback.
- Maintains a high-water mark (last processed sequence number) persisted to disk. On restart, replays from the mark.
- Full rebuild from scratch is always possible: delete the ontology store, restart, the Cartographer replays the entire chain. Slow but correct.
- Emits `ontology:*` receipts to the chain for significant actions (trajectory creation, object updates, contradiction detection, correction application). These receipts make the Cartographer's work auditable.

## Core Object Types

Five object types. Each carries a stable `id`, a `created_at` timestamp derived from the originating receipt, and `receipt_refs` tracing it back to the chain entries that produced it.

The structs below are Phase 1 shapes — deliberately minimal. Fields like `importance`, `momentum`, `pros`/`cons`, and `intent` are Phase 2+ concerns that depend on scoring logic and inference that doesn't exist yet. They're noted in comments but not part of the initial implementation. Ship what you can populate from deterministic rules; add the rest when the machinery to fill them exists.

### 1. Trajectory

The central primitive. A Trajectory is a living arc of work or thinking that emerges from activity — not declared top-down. It can nest (sub-trajectories), fork, go dormant, resume. It spans sessions, conversations, and projects.

```rust
pub struct Trajectory {
    pub id: TrajectoryId,
    pub title: String,                // derived from dominant activity, or "Untitled"
    pub status: TrajectoryStatus,     // Active, Dormant, Completed, Abandoned
    pub boundary_confidence: f32,     // 0.0–1.0: how confident the boundary detection was
    pub parent_id: Option<TrajectoryId>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_active: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,   // chain entries assigned to this trajectory

    // Phase 2+:
    // pub intent: Option<String>,
    // pub importance: u8,
    // pub momentum: Momentum,
}

pub enum TrajectoryStatus {
    Active,
    Dormant,     // no activity for a configurable threshold
    Completed,   // operator marked done
    Abandoned,   // dormant beyond a second threshold, no resolution
}
```

Why Trajectory and not Project: a project is something you declare. A Trajectory is something that emerges from what you actually did. Some of the most important work doesn't fit in a project folder but clearly has a trajectory — a direction, a lineage, decisions that built on each other. Projects and sessions become secondary concepts, derivable from Trajectory groupings when needed.

### 2. Decision

A meaningful choice made within a Trajectory. Decisions change direction, close options, open new ones. They can be superseded by later Decisions.

```rust
pub struct Decision {
    pub id: DecisionId,
    pub trajectory_id: TrajectoryId,
    pub title: String,
    pub description: String,
    pub status: DecisionStatus,      // Active, Superseded, Reverted
    pub superseded_by: Option<DecisionId>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,

    // Phase 2+:
    // pub confidence: u8,
    // pub outcome: Outcome,
    // pub pros: Vec<String>,
    // pub cons: Vec<String>,
}

pub enum DecisionStatus { Active, Superseded, Reverted }
```

Phase 1 can detect Decisions from structural chain signals: `delegation:granted:*` is a decision (authority was granted). `preference:*:selected` is a decision. Gate overrides are decisions. The richer fields (pros, cons, outcome tracking) require either inference or operator annotation — that's Phase 2+.

### 3. Insight

A key realization or observation within a Trajectory. Insights carry implications — downstream consequences that may affect other Trajectories.

```rust
pub struct Insight {
    pub id: InsightId,
    pub trajectory_id: TrajectoryId,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,

    // Phase 2+:
    // pub importance: u8,
    // pub confidence: u8,
    // pub implications: Vec<String>,
}
```

Insights are the hardest object type to materialize deterministically. Most insights are embedded in conversation context, not in chain receipts. Phase 1 will catch officer findings (a Steward finding about unsigned entry ratio *is* an insight about chain health), but the richer "key realization" sense of Insight depends on inference or operator annotation.

### 4. Artifact

Created work — code, documents, designs, specs. Artifacts are linked to the Trajectory and Decision that produced them.

```rust
pub struct Artifact {
    pub id: ArtifactId,
    pub trajectory_id: TrajectoryId,
    pub title: String,
    pub artifact_type: ArtifactType,  // Code, Document, Design, Spec, Config
    pub location: String,             // file path or receipt range
    pub author: ActorId,
    pub status: ArtifactStatus,       // Current, Superseded, Deprecated
    pub related_decision: Option<DecisionId>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

pub enum ArtifactType { Code, Document, Design, Spec, Config }
pub enum ArtifactStatus { Current, Superseded, Deprecated }
```

### 5. Friction

A blocker or recurring problem within a Trajectory. Frictions are the system's memory for pain — they enable pattern detection across time ("this is the third time we've hit this").

```rust
pub struct Friction {
    pub id: FrictionId,
    pub trajectory_id: TrajectoryId,
    pub title: String,
    pub description: String,
    pub severity: FrictionSeverity,   // Low, Medium, High, Critical
    pub status: FrictionStatus,       // Active, Mitigated, Resolved
    pub occurrences: u32,             // how many times this has come up
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub workaround: Option<String>,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,
}

pub enum FrictionSeverity { Low, Medium, High, Critical }
pub enum FrictionStatus { Active, Mitigated, Resolved }
```

Frictions are the most naturally materializable object type. Officer findings with severity ≥ Warning map directly. Repeated gate denials for the same capability map directly. The chain has strong structural signals for "something went wrong here."

## Relationships

The ontology's value lives in the edges, not just the nodes. Relationships are first-class, typed, and directional.

```rust
pub struct Relationship {
    pub id: RelationshipId,
    pub source: ObjectRef,            // (object_type, object_id)
    pub target: ObjectRef,
    pub kind: RelationshipKind,
    pub created_at: DateTime<Utc>,
    pub receipt_refs: Vec<AuditId>,   // chain evidence for this relationship
}

pub enum RelationshipKind {
    // Trajectory relationships
    ContributesTo,    // Artifact → Trajectory
    BelongsTo,        // Decision, Insight, Friction → Trajectory
    SubTrajectoryOf,  // Trajectory → parent Trajectory

    // Decision relationships
    SupersededBy,     // Decision → newer Decision
    InfluencedBy,     // Decision → prior Decision or Insight
    AuthorizedBy,     // gate decision → Delegation (Decision)

    // Friction relationships
    BlockedBy,        // Trajectory → Friction
    MitigatedBy,      // Friction → Decision that addressed it
    RelatedTo,        // Friction → Insight that explains it

    // Artifact relationships
    ProducedBy,       // Artifact → Decision that led to its creation
    DependsOn,        // Artifact → other Artifact
}
```

Every relationship traces back to chain entries via `receipt_refs`. The relationship exists because specific receipts justify it — not because an inference model guessed.

## Storage

The ontology is stored separately from the chain — a derived database, not chain entries. SQLite alongside `audit.db` in the data directory.

```
~/ZeroPoint/data/
├── audit.db          # immutable receipt chain
└── ontology.db       # derived, rebuildable
```

The ontology database is explicitly disposable. Delete it and the Cartographer rebuilds it from the chain. This is the operational guarantee that keeps the chain as the single source of truth — the ontology is a cache of understanding, not an independent store.

Schema considerations:
- Objects stored as JSON blobs with indexed columns for `id`, `trajectory_id`, `status`, `last_active`. Avoids rigid schema migrations as the object types evolve in early phases.
- Relationships stored in a separate table with indexed `source` and `target` columns for graph traversal.
- High-water mark stored in a metadata table: `last_processed_sequence`, `last_processed_at`.
- Cartographer confidence metadata stored per-object so officers and cockpits can surface low-confidence materializations.

## Officer Integration

Officers currently read the chain directly via `ChainReader`. With the ontology, officers gain a second read handle: `OntologyReader`.

```rust
pub struct OntologyReader<'a> {
    // ... reference to ontology store
}

impl<'a> OntologyReader<'a> {
    pub fn active_trajectories(&self) -> Vec<&Trajectory>;
    pub fn decisions_for(&self, traj: &TrajectoryId) -> Vec<&Decision>;
    pub fn frictions_for(&self, traj: &TrajectoryId) -> Vec<&Friction>;
    pub fn relationships_from(&self, obj: &ObjectRef) -> Vec<&Relationship>;
}
```

Officers don't abandon the chain — they still need it for structural checks (hash integrity, signature coverage). But for semantic checks, they query the ontology. Cleo's sweep becomes richer: instead of counting delegation events, she can ask "which Trajectories have active Frictions with no corresponding Decisions to address them?" That's a governance gap that raw chain scanning can't express.

The sweep pipeline becomes: Cartographer materializes → officers query ontology → officers emit findings → findings land on chain → Cartographer reads them on the next pass. Findings about the ontology itself (a Trajectory drifting without decisions, a Friction recurring without resolution) become first-class chain entries.

## Operator Experience

What the system should eventually be able to produce — this is aspirational, not Phase 1 output:

```
Active Trajectories (3)

1. Officer Cadre & Chain Storytelling          last active: 2 hours ago
   Recent: Cleo officer implemented and verified on live chain.
   Friction: audit log showed head-of-chain instead of tail (resolved).

2. Local Inference Infrastructure              last active: 4 hours ago
   Recent: Decided on local-by-default for officer inference.
   Friction: local model list stale, not optimally quantized.

3. Foundation Onboarding Prep                  last active: 2 days ago
   the Regent identity files updated. USER.md template ready.
```

Phase 1 output will be rougher. The `zp trajectories` CLI verb targets this output shape:

```
Trajectories (5 active, 2 dormant)

  Active:
  [T-0042] Governance activity cluster         confidence: 0.85  last: 2h ago
           14 receipts · 1 decision · 2 frictions (1 resolved)
           Dominant: delegation:*, gate:*, officer:cleo:*

  [T-0041] Tool lifecycle cluster              confidence: 0.72  last: 4h ago
           31 receipts · 0 decisions · 0 frictions
           Dominant: tool:started:*, tool:stopped:*

  [T-0039] Chain maintenance                   confidence: 0.91  last: 6h ago
           8 receipts · 1 decision · 1 friction (resolved)
           Dominant: epoch:*, anchor:*

  ...

  Dormant:
  [T-0033] (unnamed)                           confidence: 0.58  last: 3d ago
           6 receipts · 0 decisions · 0 frictions
```

Titles will be generic ("Governance activity cluster" derived from the dominant receipt type prefix), confidence scores will be visible, and some trajectories will be incorrectly split or merged. That's fine. A rough map with visible confidence is better than no map, and operator corrections improve it over time.

`zp trajectories` is a substrate-tier command, no cockpit required. Cockpits (the Regent) can add interpretation and conversational interaction on top.

## Governance

The ontology is a derived projection, not a source of truth. But projections can drift — classification errors, stale objects, relationships that should have been updated. Three governance mechanisms:

**The Cartographer polices itself.** When it detects clear contradictions — an object whose receipt refs point to entries that no longer support its state, a relationship between objects that have both been superseded — it emits `ontology:correction:auto` receipts and updates the ontology. This is not governance judgment; it's structural consistency maintenance. The receipt makes the correction auditable.

**Officers police the ontology's meaning.** Steward can verify structural consistency: do receipt refs exist, does the object state match what the receipts say? Cleo can verify governance coherence: are Trajectories with governance-significant Decisions properly tracked? These are the same kinds of checks they already do on the chain, applied to the ontology layer.

**The operator has final authority.** The operator can override any Cartographer classification. "This isn't a separate Trajectory, merge it with that one." "This Decision was reverted." Corrections are chain receipts (`ontology:correction:operator`), which the Cartographer reads and applies. The correction is auditable — the chain records what was changed and who changed it. The operator's correction path must be low-friction, because they'll need to use it — especially in early phases when Tier 1 boundary detection is getting 30-40% of trajectories wrong.

## Implementation Plan

### Phase 1: Storage, Cartographer, and boundary detection
- Create `zp-ontology` crate with the five object types (minimal Phase 1 shapes) and Relationship.
- Implement `OntologyStore` backed by SQLite (`ontology.db`).
- Implement Cartographer as a background task in `zp-server`.
- **Spend the majority of Phase 1 effort on boundary detection rules.** The five deterministic signals (conversation continuity, time gaps, actor transitions, domain clustering, explicit markers) need careful threshold tuning and confidence scoring. This is the core research problem of the entire design.
- Default to over-splitting. Ship `zp trajectory merge` before `zp trajectory split`.
- Emit `ontology:trajectory:created` receipts with boundary signals and confidence.
- High-water mark persistence and chain replay on startup.

### Phase 2: Officer integration and operator correction
- Add `OntologyReader` to the officer sweep pipeline alongside `ChainReader`.
- Implement operator correction receipts and CLI verbs (`zp trajectory merge`, `zp trajectory reclassify`).
- Add `zp trajectories` CLI verb.
- Surface low-confidence trajectories for operator review.
- Iterate on boundary detection thresholds based on real correction patterns.

### Phase 3: Richer object population
- Add importance scoring (rule-based: recency, activity density, friction count).
- Add momentum detection (activity rate trend over a sliding window).
- Populate Decision fields that require cross-referencing (superseded_by, confidence).
- Populate Insight objects from officer findings and chain patterns.
- Expose ontology query API for cockpit consumption (`/api/v1/ontology/trajectories`).

### Phase 4: Inference-assisted refinement
- Wire local model inference for trajectory boundary edge cases (cross-session continuity, interleave detection).
- Wire intent extraction for Trajectory objects.
- This phase depends on local inference infrastructure being operational and governed. It is explicitly not a prerequisite for a useful ontology — Phases 1–3 must stand alone.

### Phase 5: Cockpit integration
- Regent integration: ontology-grounded briefings on session start.
- Conversational trajectory management ("what am I working on?" answered from the ontology, not re-derived).
- Artifact library integration: ontology objects as candidates for signed artifacts.

## Design Principles Engaged

- **Store-and-forward is primary (P5).** The chain survives; the ontology rebuilds. Delete `ontology.db` and nothing is lost — just understanding, temporarily.
- **There is no center (P3).** The ontology is local. No remote service materializes your work into objects for you.
- **Every bit counts (P4).** Objects are reference-based — they point to receipts, not duplicate them. The ontology is lightweight because the chain carries the weight.
- **A tool is intent, crystallized (P6).** The five object types aren't arbitrary categories — they're the vocabulary of how work actually happens: direction (Trajectory), choices (Decision), understanding (Insight), output (Artifact), resistance (Friction).
- **Signing is gravity (P1).** The Cartographer emits receipts for its materializations. Ontology objects themselves are unsigned projections — they become load-bearing only when the operator promotes them to signed artifacts. The Cartographer proposes; the operator signs.

## Open Questions

1. **Should the Cartographer consume cockpit-side context?** Chain receipts don't capture everything — conversation content, reasoning, informal decisions made in chat. If the Cartographer only reads the chain, it misses context that would improve boundary detection and object population. But if it reads cockpit data, it couples to a specific cockpit implementation. The chain-only constraint keeps the ontology cockpit-independent, which is probably the right tradeoff even though it limits quality.

   **Resolution path (Phase 5):** The cockpit emits structured receipts for context it decides is worth persisting — `context:decision:recorded`, `context:insight:captured`, `context:trajectory:annotated`. The cockpit owns the judgment of what's worth persisting; the Cartographer consumes these receipts like any other chain entry. No direct read of workspace memory, no cockpit dependency in the ontology layer. The chain remains the interface between cockpit and ontology — cockpits write to it, the Cartographer reads from it. This closes the context gap without coupling.

2. **How do Trajectories relate to the IronClaw workspace memory?** IronClaw/the Regent has its own memory system (workspace, AGENTS.md, USER.md). Trajectories are a substrate concept; workspace memory is a cockpit concept. They'll need to reference each other without creating a dependency. The cockpit should read the ontology; the ontology should not read the cockpit's memory.

3. **What's the rebuild cost?** A full chain replay to rebuild `ontology.db` from scratch needs to be fast enough to be practical. At 6,000+ entries growing, this is fine. At 100,000+, it might need batching or checkpointing. Worth measuring early.
