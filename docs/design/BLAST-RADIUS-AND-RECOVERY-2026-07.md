# Blast Radius and Recovery

**Tier 2 canonical elaboration.** Elaborates the operational discipline that `CIRCUIT-BREAKER-2026-07.md` declares. Where the circuit breaker doc specifies *what* the breaker does at a boundary, this doc specifies *how* the response actually happens — termination mechanics, escalation ladder, blast radius containment, and the recovery model. Canonical claims live in KEEL.

Draft — 2026-07-10 — internal audience only. Companion to `CIRCUIT-BREAKER-2026-07.md`, `QUARANTINE-PLANE-2026-07.md`, `COGNITIVE-INPUT-PLANE-2026-07.md`, `OBSERVATION-PLANE-2026-07.md`.

## Framing

Emergency response is not one primitive. It's a discipline with five interlocking concerns:

1. **Termination semantics** — how a circuit actually gets cut, per class of thing being cut
2. **Scope of arrest** — what gets terminated when a scope is tripped
3. **Escalation ladder** — graduated response levels, not binary trip
4. **Blast radius containment** — response itself has consequences that must be bounded
5. **Recovery** — how the substrate returns to healthy operation after remediation

The naive model treats these as invisible implementation details. That naive model fails because each concern has real trade-offs that need explicit discipline. This doc makes each explicit.

The load-bearing architectural claim of this doc: **recovery in a chain-anchored substrate is fundamentally forward-only.** The chain is truth; the chain is append-only; you do not roll back truth. What CAN be recovered is derived state — the Cartographer's ontology, runtime caches, computed views. Recovery means recomputing derived state from a known-good checkpoint forward, preserving the full chain record of the emergency as audit trail. This inverts the traditional "rollback" model of most systems.

## Section 1 — Termination Semantics

"Cut the circuit" is a promise about specific behaviors, not a single primitive. Different substrate concerns need different termination discipline. Getting this wrong leaves state inconsistent, corrupts held resources, or wastes work that could have completed safely.

### In-flight actions past the gate

An action that passed the gate and started execution but hasn't completed when the breaker trips. Three termination options per action class, declared in Layer B:

- **Complete-in-flight**: let the action finish. Only future actions blocked. Applies to actions with no ongoing effect (already-committed side effect, remaining work is cleanup). Emit `action:completed_during_arrest` receipt so audit trail shows the action ran with breaker context.
- **Interrupt at safe checkpoint**: signal the action to abort at its next declared checkpoint boundary. Actions declare their own checkpoints (before I/O, between transactions, at emission boundaries). If checkpoint is reached within timeout, clean stop. If not, escalate to hard-kill.
- **Hard-kill**: force termination without waiting. Corrupts state; use only when the action itself is the threat.

Default per class:
- Read-only actions: complete-in-flight (no state to corrupt)
- Deterministic actions (KEEL determinism principle): interrupt at safe checkpoint
- Actions with side effects on external systems: complete-in-flight if less than N seconds remaining, otherwise interrupt at safe checkpoint
- Actions modifying chain state: interrupt at safe checkpoint (never hard-kill mid-append)

### WASM module executing

An extension currently running when scope is tripped. Cooperative termination first:

1. Host signals module via reserved host function (`substrate.arrest_signal()`)
2. Module has up to N milliseconds (Layer B configured, default 100ms) to yield cleanly
3. Yield = module returns from current host call; substrate observes yield and marks module as arrested
4. If module doesn't yield in time, WASM instance is destroyed (safe — WASM sandbox contains any damage)

Module state (linear memory, tables) is either preserved for post-mortem analysis or discarded per module's declared state discipline. Emit `wasm:arrested:<module_hash>` with yield status and any state hash preserved.

### Async tasks (tokio futures)

Substrate is Rust; async runtime is tokio. Cancellation via `CancellationToken`, never via `JoinHandle::abort()` which drops state without cleanup.

Task lifecycle discipline: every task at potentially-arrestable scope registers with its scope's cancellation token. When scope is tripped, token is cancelled; tasks observe cancellation at their next await point and clean up per their declared discipline.

Tasks that don't have cancellation points (compute-bound loops) declare max-loop-time per iteration; if exceeded, panic-arrest is acceptable but noted in receipt.

### HTTP requests in flight

Outbound requests to APIs (inference calls, external tool dispatches, peer messages). Abort at TCP level immediately. Emit `http:aborted_by_breaker:<request_id>` receipt with:
- Endpoint
- Bytes sent
- Bytes received before abort
- Whether response was in flight

For inference calls specifically (Regent's model calls): if response headers indicate the inference already started, we've been billed regardless — emit `inference:aborted_by_breaker:<call_id>` with token counts and provider so dashboard can attribute cost.

### Held locks and mutexes

Locks held by arrested code paths must be released, otherwise substrate deadlocks. Discipline:

1. All arrestable code paths hold locks via typed guards that emit `lock:acquired:<lock_id>:<task_id>` receipts
2. When task is arrested, host runtime observes the guard drop and emits `lock:released_by_arrest`
3. If guard destructor doesn't fire (task hard-killed mid-guard), host applies `lock:force_released` with poison flag — the lock is released but marked; next acquirer sees the poison and can decide whether to trust prior state

Poison flag is standard Rust discipline; applying it structurally to arrests keeps state consistency reasonable even under force-termination.

### Buffered data (writes not yet flushed)

Chain-anchored writes: flush before terminating. Chain integrity depends on receipts being durable; arrest during in-flight append is not allowed to lose the receipt.

Non-chain writes (log buffers, metric aggregations, in-memory caches): declared per buffer whether to flush or discard on arrest. Default: flush if buffer contains uncommitted work, discard if buffer contains only cached derived state.

### Regent cognitive cycle mid-inference

Special class because inference is expensive and interrupting mid-cycle is often wasteful. Discipline:

- If Regent's cycle is mid-inference call to model provider: check `time_remaining_estimate` against `cycle_arrest_urgency`
- If arrest is urgent (Sentinel-detected key exfiltration in progress) and Regent's scope is implicated: abort the inference call immediately, mark cycle as `regent:cycle:arrested_urgent`
- If arrest is not urgent (threshold breach, cognitive-observer sustained finding): let inference complete, arrest the response handling. Cycle emits `regent:cycle:arrested_after_inference` with cost accounted for
- If Regent is mid-tool-dispatch (post-inference, executing a tool call): arrest the tool dispatch, mark cycle as `regent:cycle:arrested_mid_tool_dispatch`

Different states, different termination costs, different discipline. Get this wrong and Regent's arrests either waste money (aborting inferences we've already been billed for) or fail to arrest fast enough (waiting for slow inference to complete during active security event).

## Section 2 — Scope of Arrest

Beyond the plane-level scope (see CIRCUIT-BREAKER-2026-07.md §"Trip scopes"), the actual set of things that get terminated needs to be enumerated at trip time. Not "arrest scope X" abstractly but "arrest these specific N items" concretely.

Trip receipt includes an arrest manifest:

```
circuit:tripped:<source>:<scope> {
  trigger_source: "sentinel",
  scope: "extension:abc123",
  arrest_manifest: {
    running_tasks: [task_id_1, task_id_2, ...],
    active_delegations: [delegation_id_1, ...],
    pending_admissions: [admission_ceremony_id_1, ...],
    held_locks: [lock_id_1, lock_id_2, ...],
    queued_operations: [queue_entry_id_1, ...],
    cached_state_keys: [cache_key_1, ...],
    outbound_http: [request_id_1, ...],
    regent_cycles_at_scope: [cycle_id_1, ...],
  }
}
```

Concrete enumeration. When operator reviews for reset, they see exactly what was arrested — not "extension X was tripped" but "extension X had 3 running tasks, 2 active delegations, 1 pending admission ceremony, 4 held locks..."

Enumeration is Layer A responsibility — the runtime knows what's active at each scope. Layer B declares what classes get enumerated per trip.

## Section 3 — Escalation Ladder

Emergency response is not binary — trigger fires, breaker trips. Graduated response with declared levels lets the substrate respond proportionally to evidence and buys time for operator diagnosis without giving up safety.

### The five levels

**L1 — Elevated attention**

Suspicious pattern noted; increase surveillance without changing operational behavior.

- Officer sweep frequency at scope: 15min → 1min
- Cognitive observer at scope: subscribe intensely
- Detailed context logging: enabled
- Threshold monitoring: reduced trip threshold (edge of concern → concerning)
- Chain-anchored `circuit:escalation:1:<scope>` receipt

Operations continue normally. No user-facing effect. This is "watch closely."

**L2 — Rate limit**

Suspicious pattern sustained; throttle without arresting.

- Actions at scope: rate limited (declared per scope in Layer B)
- New delegations at scope: manual review required (bypasses normal auto-admission of precedent-approved patterns)
- Regent's tool dispatch at scope: rate limited to defined pace
- Chain-anchored `circuit:escalation:2:<scope>` receipt

User-facing effect: things slow down at scope. Operator sees noticeable throttle. Buys time for diagnosis.

**L3 — Soft arrest**

Pattern serious; contain existing operations, block new operations.

- New actions at scope: blocked (gate fail-closed)
- New admissions at scope: quarantine plane refuses new intake
- Running operations at scope: allowed to complete-in-flight; no new starts
- Observation at scope: continues (need to see what's happening)
- Chain-anchored `circuit:escalation:3:<scope>` receipt

User-facing effect: scope becomes read-only. Existing work drains. New work blocked. Operator has clean state to diagnose from.

**L4 — Hard trip**

Pattern critical; full circuit breaker as specified in CIRCUIT-BREAKER-2026-07.md.

- All operations at scope arrested per Section 1 termination semantics
- All planes propagate the trip (observation refuses, quarantine holds, cognitive input strips scope + injects notice)
- Full arrest manifest emitted
- Chain-anchored `circuit:tripped:<source>:<scope>` receipt

User-facing effect: scope is dark. Nothing at scope operates. Chain still records the emergency (arrest actions, refused operations).

**L5 — Substrate-wide graduated response**

Pattern indicates systemic compromise; cascade to related scopes.

- Trip all scopes dependent on the compromised scope
- Notify peers if operator opted in
- Reduce substrate operations to identity + minimal chain writes
- Chain-anchored `circuit:escalation:5:<scope>` receipt with cascade manifest

User-facing effect: substrate enters minimal-operations state. Only identity, chain reads, essential outputs. Operator must actively work through the emergency; no automatic recovery.

### Escalation dynamics

Escalation is **monotonic** by default — level increases as evidence accumulates. De-escalation is **asymmetric** — requires explicit operator ceremony, same principle as trip/reset in CIRCUIT-BREAKER-2026-07.md.

Multiple trigger sources can vote for escalation. Layer B declares escalation thresholds:

- Operator manual: can push to any level immediately
- Sentinel + Steward concurrent findings: escalate two levels at once
- Sustained findings over N cycles: escalate one level per N cycles
- Threshold breach: escalate one level, hold at that level for cooldown

Chain-anchored escalation receipts document every level transition. Operator can review the escalation history and see what happened at each level.

### The point of graduated response

Real emergencies rarely arrive at "fully compromised" state cleanly. They usually manifest as anomalies that could be benign or malicious. Binary trip forces the substrate to choose between over-reaction (false alarms trip everything, mechanism gets bypassed) and under-reaction (waits for clear evidence, arrives too late).

Graduated response lets each level be a checkpoint — the substrate responds proportionally, buys time for operator input, and can de-escalate cleanly if evidence turns out to be benign. Same discipline as how humans handle emergencies. Not "slam the emergency stop" — "increase attention, then slow down, then contain, THEN cut power, then cascade."

## Section 4 — Blast Radius Containment

The response itself has consequences. Cutting scope X can cascade if X is depended on by other operations. Interrupting a cognitive cycle mid-inference wastes tokens for no output. Force-releasing locks can corrupt state. Response has to be scope-aware in two directions: what's IN the arrested scope, and what OTHER scopes depend on this scope.

### Scope dependency graph

Layer B declares a dependency graph:

```
scope: "extension:abc123"
depends_on: []                    # what this scope needs to operate
depended_on_by: [                 # what needs this scope to operate
  "regent:tool:analyze_dataset",  # Regent uses this extension's verb
  "cognitive_input_matrix:tier_2", # matrix pulls from extension's ontology
]
```

When arresting extension:abc123 at L3+ soft-arrest or L4 hard-trip:

- Enumerate dependent scopes (regent:tool:analyze_dataset, cognitive_input_matrix:tier_2)
- Choose cascade discipline per dependent:
  - **Degrade gracefully** — the dependent scope loses functionality but keeps operating (regent's analyze_dataset verb becomes unavailable; other Regent tools still work)
  - **Cascade arrest** — the dependent scope is also arrested (only if the arrested scope is load-bearing for the dependent's core function)
  - **Continue with warning** — the dependent scope continues but emits a `dependent_scope_arrested:<upstream>` observation so consumers know something upstream is degraded

Default: degrade gracefully. Cascade arrest is opt-in per scope, declared in Layer B.

### Safe interruption points

Termination discipline (Section 1) preferred stopping at declared boundaries:

- **Transaction boundaries** — SQLite commit/rollback points
- **Cognitive cycle boundaries** — between Regent cycles, not mid-inference
- **Receipt emission boundaries** — after chain append is durable, before the next
- **Officer sweep boundaries** — between sweeps, not mid-sweep
- **HTTP request boundaries** — between requests, not mid-response

Layer B declares safe checkpoints per operation class. Arresters prefer stopping at checkpoint; hard-stop only when checkpoint isn't reached within timeout.

### The arrest itself must not cascade damage

Response actions have their own blast radius:

- **Force-releasing locks** — mark with poison flag, allow next acquirer to decide
- **Killing tokio tasks** — cancellation tokens preferred over abort; abort last resort
- **Aborting HTTP requests** — TCP-level abort, mark receipt, do not retry automatically
- **Discarding buffered data** — declared per buffer; default to flush uncommitted, discard cached derived
- **Terminating WASM modules** — sandbox contains damage; memory freed cleanly

The pattern: response actions are themselves chain-anchored, structurally bounded, and preserve as much state as safely possible. The chain has receipts for every arrest action so post-hoc reconstruction is possible.

## Section 5 — Forward-Only Recovery

Here is the strong architectural claim: **in a chain-anchored substrate, recovery is fundamentally forward-only.**

The chain is append-only, hash-linked, signed. You do not roll back truth. What happened, happened. During the emergency, the chain kept recording — arrest receipts, refused operations, remediation actions, reset ceremony. All of it is part of the substrate's permanent record.

What CAN be recovered is **derived state**:
- Cartographer's ontology (materialized from chain)
- Runtime caches (delegation cache, observation cache, tool dispatch cache)
- Port registry (persisted; can be reconstructed from chain)
- Vault runtime cache (in-memory; can be reloaded from vault.json)
- Substrate state snapshot (composed from live substrate state)

Derived state can be discarded and recomputed. That's the recovery model.

### Checkpoint receipts

Substrate periodically emits `checkpoint:derived_state:<name>` receipts declaring:
- Timestamp
- Chain rowid at checkpoint (anchoring point)
- Named subsystems and their state hashes at that moment

Examples:
- `checkpoint:derived_state:ontology` — Cartographer's ontology hash at this chain rowid
- `checkpoint:derived_state:port_registry` — port registry hash
- `checkpoint:derived_state:vault_cache` — vault cache hash
- `checkpoint:derived_state:delegation_cache` — active delegation set hash

Checkpoint frequency: Layer B configured. Default: every N chain entries or every T minutes, whichever comes first.

Purpose: known-good anchors that substrate can recompute from. Not necessary during normal operation — just quiet chain-anchored save points.

### Recovery ceremony (post-reset)

After operator has reviewed the emergency and signed circuit reset (per CIRCUIT-BREAKER-2026-07.md §"The reset ceremony"), operator can optionally trigger derived-state recovery:

**Step 1 — Select checkpoint**

Operator (or Regent under operator direction) reviews `checkpoint:derived_state:*` receipts and picks a known-good checkpoint. Typically: the most recent checkpoint before the emergency began.

**Step 2 — Sign recovery ceremony**

Operator emits `recovery:derived_state_from_checkpoint:<checkpoint_id>` receipt declaring intent to recompute derived state from that checkpoint forward.

**Step 3 — Substrate recomputation**

Layer A observes recovery receipt and executes:
- Discard runtime derived state (ontology, caches)
- Replay chain from checkpoint rowid forward
- Emit `recovery:progress` receipts as each subsystem is reconstructed
- On completion, emit `recovery:completed:<checkpoint_id>` with final state hashes

**Step 4 — Verification**

Substrate verifies the reconstructed state:
- Ontology hash matches the deterministic computation from chain-replay
- Cache state consistent
- No inconsistencies detected

Emit `recovery:verified` on pass. If verification fails, emit `recovery:verification_failed` and pause for operator intervention.

### What the emergency record preserves

The chain still contains:
- `circuit:escalation:*` and `circuit:tripped:*` receipts documenting the response
- `action:arrested_by_breaker:*` receipts documenting what was blocked
- `wasm:arrested:*`, `http:aborted_by_breaker:*`, `regent:cycle:arrested:*` documenting terminations
- `circuit:reset:*` documenting the reset ceremony
- `recovery:derived_state_from_checkpoint:*` documenting the recovery decision

None of this is erased. The substrate's memory of the emergency is complete. What's recomputed is only the derived interpretation of substrate state going forward.

### Why forward-only vs rollback

Most systems' recovery model: "roll back to before the bad thing happened, discard the record."

Chain-anchored substrate's recovery model: "chain is truth; roll forward from a known-good derivation checkpoint, recomputing derived state. The chain preserves everything that happened during the emergency."

The inversion matters for four reasons:

1. **Audit trail preservation** — the emergency and response are permanent record. Future analysis, forensics, learning-from-precedent all benefit from full history.
2. **Chain integrity preservation** — rollback would break hash-linkage. Forward-recovery preserves the append-only property that everything else in the substrate depends on.
3. **Truth over convenience** — the chain says what happened. Rollback would delete truth for convenience. That's the wrong trade.
4. **Precedent generation** — the emergency and its resolution become chain-anchored precedent for how future similar events should be handled (per act-on-precedent, escalate-on-novelty heuristic).

## Composition with the nine design principles

- **P1 (Signing is gravity)** — recovery preserves signed record; rollback would destroy signed truth
- **P3 (There is no center)** — recovery is local computation from chain, no external authority coordinating
- **P4 (Every bit counts)** — chain has no redundant records; recovery replays without duplication
- **P5 (Store-and-forward is primary)** — the chain survives; derivations recompute
- **P7 (Contact does not commit)** — extended: contact doesn't commit AND emergency recovery preserves record
- **P8 (One canonical path)** — one canonical response mechanism (escalation → arrest → reset → recovery), not scattered emergency code
- **P9 (System acts; operator signs)** — trip is system action; reset and recovery ceremony are operator sign

## Composition with the substrate architecture

- **Circuit Breaker** — this doc covers the operational side of what breaker declares
- **Quarantine Plane** — arrested artifacts return to quarantine; recovery re-admits with possibly modified delegation
- **Cognitive Input Plane** — recovery state is a top-tier input for Regent's context during and after emergency
- **Observation Plane** — every arrest action, every recovery step is observed and receipt-anchored
- **Substrate Form** — checkpoint discipline appropriate per Form; Sovereign Form has full-state checkpoints; Companion Form has subset available under vendor permissions
- **Genesis** — recovery ceremony is Genesis-signed; forward-only property inherits chain's Genesis-rooted signature discipline

## Attack model

- **Attacker triggers unnecessary escalation to disable substrate**: escalation requires officer signature or operator command; single spurious trigger only advances one level; sustained triggering requires sustained officer findings which require actually manipulating officer state (bigger emergency)
- **Attacker hides emergency by manipulating recovery**: recovery ceremony is chain-anchored, Genesis-signed, and preserves the emergency chain record; there's no "hide it" path
- **Attacker corrupts checkpoint receipts**: checkpoints are chain-anchored and hash-linked like any receipt; corruption is chain-integrity violation, detected structurally
- **Attacker forces recovery to a compromised checkpoint**: recovery ceremony requires operator ceremony; operator sees which checkpoint is being used; a compromised checkpoint would show inconsistencies during verification step
- **Attacker uses forward-only recovery to launder bad state into legitimate state**: chain record shows the emergency and remediation; state going forward is consistent with chain; laundering isn't possible without breaking chain integrity

## Non-goals

- **Not a rollback mechanism.** Chain is truth; there is no rollback. Explicitly.
- **Not automatic recovery.** Reset and recovery are operator ceremonies. Silent auto-recovery would defeat the discipline.
- **Not a replacement for the underlying substrate integrity.** If chain integrity is genuinely violated (not just Steward's earlier false positives), this doc doesn't cover that — that's a KEEL-level emergency requiring different response.
- **Not distributed recovery coordination.** Each sovereign's recovery is local. Peer notification is optional per operator; peer-driven recovery isn't implied.

## Open positions

- **Checkpoint frequency defaults** — how often to emit `checkpoint:derived_state:*` receipts. Trade-off: chain size vs recovery granularity. Empirical work.
- **Rate limit values** — L2 escalation rate-limits. What starting numbers? Depend on scope class.
- **Cascade discipline defaults** — degrade-gracefully vs cascade-arrest. Currently degrade default; watch for cases requiring different.
- **Timing budgets** — WASM yield timeout, tokio cancellation propagation, HTTP abort timeout. Values need calibration.
- **Recovery UX** — operator ceremony flow. Dashboard panel showing checkpoint options with substrate-state summaries? Regent-narrated? Both?
- **Multi-scope recovery** — if emergency affected multiple scopes with cascading arrests, is recovery scoped per-checkpoint per subsystem, or unified? Prefer unified for simplicity; watch for cases requiring per-subsystem.
- **Recovery precedent** — after operator has recovered from a specific pattern several times, can that pattern trigger auto-recovery-suggestion? Not auto-execute — suggestion only. Composes with act-on-precedent heuristic.

## What composes from here

Immediate design work:

1. **Arrest manifest schema** — Layer B canonical spec for the manifest that trip receipts include
2. **Escalation-level schemas** — receipt shapes per level, transition rules
3. **Termination discipline per action class** — declared per class of thing being arrested
4. **Checkpoint receipt schema** — subsystem naming, state hash format
5. **Recovery ceremony flow** — operator UX for checkpoint selection and recovery execution
6. **Verification checks** — post-recovery consistency checks per subsystem

Near-term implementation:

1. Layer A arrest primitives per class (WASM yield, tokio cancellation, HTTP abort, lock poisoning)
2. Escalation-level runtime — moves substrate between levels based on trigger receipts
3. Scope dependency graph — Layer B declarations of what depends on what
4. Cascade discipline runtime — applies degrade-gracefully or cascade-arrest per declared rule
5. Checkpoint emitter — periodic background task emitting derived-state checkpoint receipts
6. Recovery ceremony CLI verb — `zp recovery from-checkpoint <id>` interactive with review + sign
7. Dashboard integration — escalation level prominent, arrest manifest browsable, recovery panel available

## Framing note

This doc completes the emergency response envelope. CIRCUIT-BREAKER-2026-07 declares what the breaker does; this doc specifies how the response actually happens — termination mechanics, escalation ladder, blast radius containment, and forward-only recovery.

The load-bearing architectural insight is the recovery inversion: chain-anchored substrates recover FORWARD from a known-good derivation checkpoint, not BACKWARD by rolling back truth. Chain is preserved; derived state is recomputed. Truth is preserved; convenience is not the trade.

Combined with the three planes (observation, quarantine, cognitive input), the extension surface (Task #46), the two observer patterns (hardware self-observer, cognitive self-observer), the delegable-safety heuristic, and the circuit breaker itself, the substrate now has full structural discipline for its trust boundaries under all three temporal scales — normal operations via planes, deliberate admission via ceremony, emergency response with graduated escalation and forward-only recovery. One canonical discipline; three time scales; every boundary chain-anchored, Genesis-derived, structurally enforced.
