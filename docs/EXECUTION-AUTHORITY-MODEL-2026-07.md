# Execution Authority Model

**Status:** Accepted  
**Date:** 2026-07-04  
**Scope:** All deterministic code execution in the ZeroPoint substrate  
**Companion to:** `ARCHITECTURE-2026-07.md` (nine design principles, four claims), `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` (eleven cognitive principles), `REGENT-PHASE-0-1-DESIGN-2026-07.md` (Phase 0–1 implementation)

---

## Decision

All deterministic code execution in the ZeroPoint substrate traces to one of exactly two execution authorities:

1. **Regent** — cognitive authority. Decides *what* the substrate should attend to, *when* to act, and *why*. Reasoning, perception, operator interaction, tool dispatch, cloud escalation, self-improvement proposals.

2. **Forge** — operational authority. Decides *how* infrastructure maintains itself. Process lifecycle, hardening actions, port management, service health, configuration enforcement.

Everything else — officer sweeps, sensor reactions, anchor pipeline seals, HTTP handler side effects, discovery scans — is **infrastructure that one of these two authorities directs**. Infrastructure does not initiate; it executes on behalf of an authority.

The distinction is not "who wrote the code" but "who decided this code should run right now." A timer tick is infrastructure. The decision that the timer should exist, at what interval, checking what condition — that traces to Forge (operational) or Regent (cognitive).

---

## Context: Why This Decision

### The Three-Authority Problem

The substrate currently has three execution authorities:

| Authority | Examples | Decides to run because... |
|-----------|----------|--------------------------|
| Regent | `zp regent "hello"`, cognitive loop tick | Operator input or autonomous wake timer |
| Forge | Hardening sweep after `NewListenerDiscovered` | Sensor event triggers Forge assessment |
| **Nobody** | Officer cadre sweep (900s timer), discovery scanner (90s cycle), anchor seal (30s tick), `security::assess()` on HTTP GET, auto-compaction at startup | A timer fired, an HTTP request arrived, or startup code ran |

The "nobody" category is the problem. These code paths hold the same `audit_store` lock as the Regent, contend for the same resources, produce chain receipts with the same authority as governed actions, and run at cadences no authority chose. The 13-second perceive latency, the tenant sensor cascade, the Steward full-chain verify on every security posture request — all are symptoms of code that runs because a timer said so, not because an authority decided it should.

### Motivating Evidence

**Lock contention from autonomous subsystems.** The `std::sync::Mutex<AuditStore>` is shared across officer sweeps, sensors, anchor pipeline, regent, and HTTP handlers. Steward's `check_chain_integrity()` runs `verify_with_report()` on the entire chain (736k entries at peak) during its autonomous 900-second sweep. This holds the lock for seconds, during which the Regent's `perceive()` blocks. The Regent didn't ask for this verification. No authority did. A timer fired.

**Sensor cascade producing Forge thrashing.** The discovery scanner re-discovers a governed tool's port every scan cycle (~90s), emitting `NewListenerDiscovered` each time. This triggers a Forge sweep → hardening assessment → dormancy → reactivation loop. Forge is an authority, but it's being *triggered* by infrastructure that no authority is directing. The scan interval, the dedup gap, the decision to scan at all — these are unowned.

**Security posture endpoint as unbounded chain verify.** `GET /api/v1/security/posture` calls `security::assess()` which runs `verify_with_report()` on the full chain. If any dashboard auto-refreshes, this holds the lock repeatedly at whatever cadence the client chooses. The HTTP handler is infrastructure; the decision to verify the full chain on every GET is not governed by any authority.

**Auto-compaction at startup with no authority.** The startup block checks `entry_count > 50_000` and compacts. This is a reasonable operation, but it's initiated by startup code, not by an authority that decided "now is the right time to compact." It runs regardless of what the Regent or Forge think about chain length.

### The Structural Diagnosis

The pattern across all these cases: **infrastructure that should be directed is instead self-directing.** The timer, the HTTP handler, the startup block — each makes an implicit decision ("it's time to sweep," "I should verify the full chain," "50k is too many entries") that properly belongs to an execution authority.

This is the same shape as the "when two reasonable architectural models conflict" heuristic in CLAUDE.md: the substrate is half-governed, half-autonomous, and the half-state produces rotating failures (lock contention this restart, sensor cascade that restart, security posture timeout the next).

---

## Target State

### Two Authorities, One Infrastructure Layer

```
┌─────────────────────────────────────────────────┐
│                   Operator                       │
│              (sovereign, signs)                   │
└──────────┬──────────────────────┬────────────────┘
           │                      │
    ┌──────▼──────┐        ┌──────▼──────┐
    │   Regent    │        │    Forge    │
    │ (cognitive) │◄──────►│(operational)│
    │             │ coord  │             │
    └──────┬──────┘        └──────┬──────┘
           │                      │
    ┌──────▼──────────────────────▼──────┐
    │         Infrastructure Layer        │
    │                                     │
    │  Officers    Sensors    Anchor      │
    │  Handlers    Timers     Compaction  │
    │                                     │
    │  (executes at authority direction)  │
    └─────────────────────────────────────┘
```

**Regent directs:**
- When and how often to perceive chain state (replaces fixed cognitive loop timer)
- When to run officer sweeps and which officers to wake (replaces fixed 900s cadence)
- When chain integrity verification is needed (replaces unconditional verify on every sweep)
- When to compact the chain (replaces startup auto-compact)
- Cloud inference escalation (via CloudMandate)
- Agent swarm dispatch (future: multiple parallel inference tasks)
- Self-improvement proposals (future: reads own source, proposes changes)

**Forge directs:**
- Sensor scan intervals and which sensors are active (replaces fixed 90s discovery cycle)
- Hardening responses to sensor events (already partially true, but Forge should control the trigger cadence, not react to every scan)
- Process lifecycle: start, stop, health-check intervals for governed tools
- Port allocation, auth token rotation, `.env` sidecar writes
- Anchor pipeline seal timing (replaces fixed 30s tick)

**Neither authority owns:**
- HTTP request handling (infrastructure: serves requests, but side effects like full-chain verify require authority direction)
- Chain append (infrastructure: the append primitive is available to both authorities)
- Receipt signing (infrastructure: signing is gravity — it happens when an authority produces something worth signing)

### The Authority Contract

Every `tokio::spawn` that runs a loop or periodic task must satisfy one of:

1. **Authority-directed**: The task's wake condition, cadence, and scope are set by Regent or Forge, and can be changed at runtime via chain receipts.
2. **Request-scoped**: The task serves a single incoming request and terminates (HTTP handlers, CLI commands).
3. **Startup-only**: The task runs once during initialization and does not recur.

Category 1 is the new requirement. Currently, officer sweeps (category 1 work) run as category 3 (startup spawns a loop with a hardcoded interval). The migration path: Regent emits a `regent:directive:officer_sweep` receipt specifying interval and scope; the officer runner reads this directive and adjusts.

### Sentinel's Elevation Authority

Sentinel is not a third execution authority. It does not direct code execution. But it has something the other officers lack: **elevation authority** — the ability to preempt the normal wake cadence of Regent and Forge when a security-critical condition demands immediate response.

Normal finding flow: Sentinel emits findings during its sweep → Regent reads them at next cognitive cycle → Regent or Forge acts. This is fine for routine posture assessment. It is not fine for an active intrusion, a key compromise, or a suspect process.

Elevation flow: Sentinel emits a `sentinel:escalation:critical` receipt. This receipt preempts normal scheduling — Forge wakes immediately for operational response (kill process, lock port, revoke delegation), Regent wakes immediately for cognitive response (assess scope, decide next steps, notify operator). The execution still traces to Forge or Regent. The *urgency* traces to Sentinel.

The distinction matters: Sentinel rings the alarm. Forge and Regent respond. Sentinel never touches the kill switch directly. This keeps the execution authority surface to two, which keeps the audit trail legible — every action traces to a cognitive or operational decision, never to "the security system did it autonomously."

A security-related *code change* (patching a vulnerability, hardening a prompt) is Regent territory — cognitive work. Sentinel's elevation ensures the Regent sees it immediately rather than at the next scheduled wake, but the Regent still reasons about and directs the change.

Receipt chain for an escalation:

```
sentinel:escalation:critical          severity=critical, finding="suspect process on port 9101"
forge:wake:escalation                 trigger=sentinel:escalation:critical
forge:action:process_kill             pid=12345, port=9101, reason="sentinel escalation"
regent:wake:escalation                trigger=sentinel:escalation:critical
regent:intent:respond                 "Sentinel flagged a suspect process. Forge killed it. Assessing scope..."
```

### Coordination Between Authorities

Regent and Forge are peers, not hierarchy. Neither directs the other. They coordinate through the chain:

- Forge emits operational findings (port conflict, process death, hardening gap). Regent reads these in its cognitive context and decides whether to act.
- Regent emits cognitive directives (change sweep interval, enable/disable sensor, compact chain). Forge reads these and adjusts operational behavior.
- Sentinel elevates security-critical findings that preempt normal wake cadence for both authorities.
- Conflicts (Regent wants sensor off, Forge sees active threat) are surfaced to the operator via competing chain receipts. The operator decides.

This is Cognitive Design Principle #6 (peer windows are autonomous; they dialogue, they don't merge) applied to the execution layer.

---

## Migration Path

### Phase 0: Decontention

No authority model change. Eliminate the acute symptoms:

1. **Chain compaction succeeds** — trigger fix already in code (DROP/CREATE within transaction). Reduces chain from 736k to 10k entries. Makes Steward verify sub-second.
2. **Security posture endpoint uses cached posture** — don't run `verify_with_report()` on every GET. Serve the posture score from the last officer sweep. The sweep is the authority-directed verification; the HTTP endpoint is a read.
3. **Discovery scanner dedup** — don't emit `NewListenerDiscovered` for already-known ports. Eliminates the tenant-tool cascade.

### Phase 1: Regent Gets Hands

As specified in the companion design doc. The Regent gains tool dispatch through the gate, multi-turn reasoning, and a receipt trail for every action. This gives the Regent the ability to *do* things — prerequisite for directing infrastructure.

### Phase 2: Cloud Inference + Sovereign Identity

Wire `CloudMandate` to an inference backend. The Regent can now use cloud models when local inference is insufficient. Simultaneously, inject sovereign identity (Genesis pubkey, operator name) into `CognitiveContext` so the Regent knows who it serves.

This phase also moves system prompts from string literals in Rust to `.md` files in `crates/zp-regent/prompts/`, loaded via `include_str!()` with override dir for hot-reload. Response contract enforcement: parse model output into typed enum (`Respond | Execute | Observe | Confused`).

### Phase 3: Regent Directs Officers

The Regent gains authority over officer sweep timing and scope:

- `regent:directive:officer_sweep { interval_secs, officers, scope }` receipt
- Officer runner reads the latest directive from chain state at each wake
- Regent can say "run Steward verify now" or "skip Steward verify for the next 3 cycles" or "change sweep interval to 300s"
- Default directive emitted at startup if none exists on chain

This is where "nobody" starts shrinking. The officer cadre loop still runs, but its cadence and scope are chain-configured by the Regent.

### Phase 4: Forge Directs Sensors + Anchor

Same pattern for Forge:

- `forge:directive:sensor_scan { interval_secs, sensors, targets }` receipt
- `forge:directive:anchor_seal { interval_secs }` receipt
- Sensor runner and anchor pipeline read directives from chain state
- Forge can respond to threat posture changes by increasing scan frequency, or dial back during quiet periods

### Phase 5: Agent Swarms and Self-Configuration

The Regent can now:

- Spawn parallel inference tasks (agent swarms), each scoped with prompt, model, budget, reply channel
- Change its own inference model by emitting a `regent:config:model` receipt
- Read its own source (prompt files, not Rust), propose improvements as unsigned artifacts
- Operator reviews and signs; the signed artifact becomes the new prompt

This is "the substrate proposes; operators sign" applied to the Regent's own cognitive configuration.

#### The Model-Prompt Coupling Invariant

A model and its prompt set are an **atomic pair**. Changing one without the other is a half-state that produces a class of bugs where the prompt's assumptions about model behavior no longer hold — JSON output format compliance, instruction-following fidelity, structured output syntax, chain-of-thought suppression, context window usage patterns. These bugs are invisible at the architecture level (the code is correct) and only surface empirically when a specific model misinterprets a specific prompt. The invariant eliminates the class structurally.

**Prompt resolution order:**

```
prompts/{model_family}/unified_system.md    ← most specific
prompts/base/unified_system.md              ← default fallback
prompts/unified_system.md                   ← compiled-in (current)
```

Model family is derived from the model name: `qwen3:8b` → `qwen3`, `gemma4:27b-mlx` → `gemma4`, `claude-sonnet-4-20250514` → `claude`. The resolution is the same pattern as the asset architecture (override → compiled-in), extended with a model-family tier.

**When the Regent changes its own model, the change is atomic:**

```
regent:config:inference {
    model: "gemma4:27b-mlx",
    prompt_variant: "gemma4",           // which prompt family to use
    validation_result: "5/5 intents parsed correctly",  // self-test
}
```

The Regent does not emit this receipt until it has validated the new model against its prompt set — run a few canonical inputs, confirm structured output parses correctly. If validation fails, the Regent proposes the model change *with* prompt modifications as a paired artifact. The operator signs the pair, not the parts independently.

**What this eliminates:** the class of bugs where a model swap (or Ollama update, or quantization change) silently degrades intent parsing, JSON compliance, or response quality. Every model transition is validated before it becomes operative, and every validation result is on chain. If a model starts failing after an external update (Ollama pulls a new quant), the Regent detects it on the next cycle's parse failures and proposes a rollback or prompt adaptation — again, as a paired change.

**Diagnostic discipline: prompt failure looks like model failure.** When a model ignores a system prompt instruction, the instinct is to blame the model tier — "1.7b can't do this, escalate to 8b." But prompt structure determines whether the instruction is legible to the model at all. A sovereign identity line jammed mid-sentence with no delimiter (`...this substrate.You serve operator kenrom...`) is structurally invisible to a small model even though the information is present in the context window. The same information on its own line with a clear prefix (`IDENTITY: You serve operator kenrom...`) works immediately at the same model tier.

The diagnostic order is: (1) check prompt structure — is the instruction isolated, labeled, and unambiguous? (2) check inference hygiene — is the model serving stale KV cache from a prior session? (3) only then blame the model tier. Steps 1 and 2 are free; step 3 costs 4–16x the memory and latency. The validation battery (Phase 5) should test prompt legibility explicitly: a canonical "who do I serve?" probe that fails if the sovereign line isn't being used, catching structural prompt regressions before they reach the operator.

**Inference hygiene at startup.** Models pinned with `keep_alive: -1` survive ZP restarts. The KV cache from the previous session's system prompt persists in Ollama's memory, and the new binary's compiled-in prompts never reach the model until it's evicted and reloaded. The startup sequence must be: unload all loaded models → preload configured models fresh → start cognitive loop. Without this, prompt changes only take effect after Ollama itself restarts or the model's keep-alive expires — which, at `-1`, is never.

#### Model Dossiers

Before a model enters the validation gate, it must be characterized. A **model dossier** (`models/{family}/model_dossier.toml`) is the substrate's structured assessment of a model family — combining researched knowledge (published quirks, architecture notes, community findings) with empirical measurements (bench results, prompt compatibility testing).

The dossier serves three roles:

1. **Characterization input.** The Regent reads the dossier to know *what to test for* during validation. A model with a known context-dump quirk gets tested for context dumps; a model with a known thinking-mode interaction gets tested with thinking on and off. The validation battery is dossier-informed, not generic. The think suppression profile — which of `think: false`, `think` omitted, or `/no_think` token actually suppresses chain-of-thought for a given variant — is itself a characterization dimension. Different variants of the same model family (e.g., qwen3:8b vs qwen3:1.7b) may respond to different suppression mechanisms. The evaluation battery probes all three and records which ones are effective, so the inference layer can use the right mechanism per variant rather than assuming one approach works for all.

2. **Deployment gate.** A model with `suitability = "blocked"` on a tier cannot be deployed to that tier regardless of validation results. The dossier records *why* — the blocking quirk, the incompatible prompt mode, the empirical evidence. This prevents the substrate from repeatedly re-discovering the same failure.

3. **Operational memory.** When a model update arrives (Ollama pulls a new quantization, a point release changes behavior), the dossier is the structured record of what was true before. Delta-testing against the dossier catches regressions that a generic self-test would miss.

The dossier is code — reviewed, versioned, checked into the repo alongside the model's prompt variants. The chain records which dossier version was active when validation passed. Together: dossier captures knowledge, bench captures measurement, chain captures operational truth.

See `models/README.md` for the lifecycle and `models/qwen3/model_dossier.toml` for the canonical schema.

##### Emission-coherence characterization (amended 2026-07-18)

Following SLM failure-mode analysis (Liquid AI LFM 2/2.5) and the REGENT-DOOM-LOOP-DETECTION-2026-07.md discipline, the dossier's `suitability` block extends to include emission-coherence fields. These are populated empirically from chain-anchored detection events; they are not researcher-declared claims. Fields:

- **`doom_loop_rate_per_1k_responses`** — rolling measurement of `regent:emission:doom_loop_confirmed` receipts per 1000 responses, computed over the last N cycles (default N=1000). Updated per dossier-refresh ceremony. A model whose rate exceeds an operator-declared threshold (typically 1–2%) is auto-flagged `suitability = "restricted"` and requires operator ceremony to remain in Regent tier.
- **`entropy_baseline`** — mean per-token entropy across a curated baseline evaluation battery. Reference value used by Heuristic 3 (entropy anomaly). Absence of this field means Heuristic 3 is skipped for this model; substrate emits a `substrate:degraded:entropy_baseline_missing` receipt at boot per SUBSTRATE-READINESS-CONTRACT-2026-07.md.
- **`reasoning_step_parseable`** — boolean; whether the model's reasoning-mode output contains structurally parseable step markers (`<thinking>`, `<step>`, numeric enumeration, etc.). If true, Heuristic 5 (reasoning-step stagnation) applies. If false, Heuristic 5 is skipped. Model-family-declared based on prompt-mode characterization.
- **`known_doom_loop_triggers`** — array of `task_class` identifiers empirically prone to doom-loop this model. Populated from accumulated chain evidence per task_class × model. Used by INFERENCE-ROUTING-DISCIPLINE's precedent bright-line to preemptively escalate this task_class to fallback tier without waiting for detection to fire on this cycle.
- **`emission_coherence_verified_at_commit`** — git SHA of the substrate build against which the fields above were measured. Delta-testing against this baseline catches emission-coherence regressions when either the model or the substrate detection logic changes.

The composed effect: the dossier's `suitability` becomes evidence-backed rather than claim-based. Adding a new model to Regent's tier under SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md Phase B2 requires these fields to be present; boot ceremony refuses substrates whose active model dossier is missing detection-parameter fields.

Chain composition: emission-coherence measurements land as `dossier:emission_coherence:measured` receipts per rolling window; these compose into the dossier's `verification_hash` per the composition matrix for `inference_provider`. Amending emission-coherence fields via ceremony produces `dossier:emission_coherence:amended` receipts that flow through SUPERSESSION-FRAMEWORK-2026-07.md.

Connects to *every bit counts* (no silent degradation from mismatched pairs), *signing is gravity* (the model-prompt pair is signed as a unit; unsigned pairs have no authority), and the balanced loop heuristic (the validation step IS the smallest end-to-end test before the configuration change takes effect).

### Phase 6: Nested Observer Windows

The deterministic system awareness snapshot (Phase 0) answers "what does the system look like right now?" This is necessary but insufficient — it catches current state, not trajectory. A model whose inference latency increases 5% per cycle, a memory leak from background tasks, an officer sweep whose receipt frequency is climbing — each individual snapshot is within tolerance. The trend is the problem, and no single snapshot catches a trend.

The nested observer pattern adds temporal depth to the Regent's self-awareness:

**Short window (per-cycle):** The existing deterministic snapshot. Raw readings of memory pressure, loaded models, active tasks, idle duration. This is the input layer.

**Medium window (per-session):** Rolling aggregation across cycles within a session. The Regent maintains a sliding window of prior system states (last N cycles, configurable) and computes deltas: latency trends, memory growth rate, model accuracy drift, officer finding frequency. This is where operational drift becomes visible — "inference latency for qwen3:1.7b has increased 40% over the last 20 cycles" or "Sentinel unauthorized_listener alerts have doubled since startup."

**Long window (across sessions):** Cross-session comparison anchored to chain receipts. Each session's medium-window summary is emitted as a `regent:awareness:session_profile` receipt at shutdown. On startup, the Regent reads prior session profiles from chain and compares: "system boot-to-ready time is 3x what it was last epoch" or "this model's routing accuracy has degraded since the last model dossier evaluation." This is where structural drift — invisible within any single session — becomes detectable.

The scope is Regent-internal, not officer-level. Officers observe the *substrate*; the Regent observes *herself operating within the substrate*. The officers watch what's happening; the observer windows watch whether the Regent's own perception and action quality is changing.

**Prerequisites:** Stable baseline from empirical operation of the core cycle. Adding observation windows before normal behavior is characterized means observing noise. The right sequence: stabilize the cycle → establish what "normal" looks like empirically → add medium window to detect deviation from that baseline → add long window after enough sessions to compare.

**Implementation shape:** The medium window is a `Vec<SystemAwareness>` ring buffer in the Regent struct, with a `compute_trends()` method that produces a `SystemTrends` struct (latency_delta, memory_delta, accuracy_delta) injected into the cognitive context alongside the raw snapshot. The long window is chain-read at startup + chain-write at shutdown. Both are lightweight — the aggregation is simple statistics (mean, delta, monotonicity), not inference.

Connects to Cognitive Principle #6 (peer windows — the Regent's observer windows are their own peer windows for self-monitoring) and the balanced loop heuristic (each observation cycle is itself a smallest end-to-end test of the Regent's own operational health).

### Phase 7: Autonomous Remediation via Precedent

The Regent should not wait for the operator to ask about problems the officers have already detected. They should act within their delegated authority on known patterns and escalate only when the situation is genuinely novel — when they would be setting new precedent in a new context.

#### The Three-Part Autonomous Action Test

Before acting on an officer finding without operator input, the Regent evaluates:

1. **Authority gate.** Does the proposed action fall within their active delegation scope? This is the existing gate mechanism — if the delegation doesn't cover the action, stop. No escalation, no proposal. The gate is the hard boundary.

2. **Pattern precedent.** Has the Regent performed this class of remediation before, and was the outcome operator-approved? They query the chain for prior `regent:remediation:*` receipts matching the same (finding_type, remediation_verb) pair. An operator-signed precedent receipt means: "this pattern has been tried, the operator approved the result, do it again." No precedent → this is a new class of action → escalate.

3. **Context novelty.** Even if the pattern is known, is the current environmental context materially different from prior precedent? Two signals make a context novel: (a) co-occurring findings that weren't present before (e.g., unsigned entries + chain integrity break simultaneously), (b) the remediation would affect chain state that's structurally different from prior instances (e.g., entries in a compacted segment vs. a live segment). Known pattern + novel context = new precedent → escalate.

All three pass → **act autonomously**. Emit a `regent:remediation:{verb}` receipt documenting: what was done, which officer finding triggered it, which precedent receipt authorized the pattern, and what changed. The operator sees this in the chain as a fait accompli with full audit trail.

Any test fails → **escalate**. Surface the proposed remediation to the operator as a `regent:proposal:{verb}` receipt containing: the finding, the proposed action, why the Regent can't act autonomously (no authority / no precedent / novel context), and the expected outcome. The operator reviews and signs or rejects. A signed approval becomes the new precedent receipt for that (finding_type, remediation_verb, context_signature) tuple.

#### Remediation Receipt Schema

```
regent:remediation:{verb}
  triggered_by: finding_id          # the officer finding that caused this
  finding_type: string              # e.g. "unsigned_entries", "chain_link_broken"
  remediation_verb: string          # e.g. "batch_sign", "integrity_repair"
  precedent_receipt: receipt_id     # the prior approval that established this pattern
  context_signature: string         # hash of co-occurring findings + env state
  entries_affected: u64             # scope of what changed
  outcome: string                   # what happened
```

```
regent:proposal:{verb}
  triggered_by: finding_id
  finding_type: string
  proposed_verb: string
  escalation_reason: enum           # NoAuthority | NoPrecedent | NovelContext
  context_signature: string
  expected_outcome: string
  # Unsigned until operator approves. Operator signature = precedent creation.
```

#### The Chain as Trust Corpus

The precedent mechanism is self-teaching. The chain accumulates remediation receipts over time. Each operator-approved escalation expands the Regent's autonomous action envelope. The corpus grows from operational reality, not from a predefined policy.

This means:
- A fresh substrate has zero precedent → the Regent escalates everything → the operator approves the first instances of each pattern → precedent accumulates.
- A mature substrate has deep precedent → the Regent handles routine remediation silently → the operator only sees escalations for genuinely novel situations.
- The trust relationship between operator and Regent is *empirically grounded* in the chain, not declared in config.

The operator can audit the precedent corpus at any time: `zp chain query "regent:remediation"` shows every autonomous action; `zp chain query "regent:proposal"` shows every escalation. If the operator disagrees with an established precedent, they emit a `regent:precedent:revoked` receipt — the Regent loses that autonomous pattern and escalates it next time.

#### Immune System Analogy

- **Innate immunity** (officers): detect threats through sweeps. Pattern-matching against known anomaly types. Always active, no learning required.
- **Adaptive immunity** (Regent + enriched prompts): interpret what threats mean in substrate context. Reason about severity, co-occurrence, and implications.
- **Immune response** (autonomous remediation): act on detected threats within established precedent. The chain is the immune memory — prior successful remediations are remembered and replicated.
- **Immune escalation** (operator approval): novel pathogens (unprecedented findings) are escalated to the operator. The operator's approval trains the immune system for next time.

The set point for escalation is novelty, not permission. The Regent is not hamstrung by uncertainty about whether they have a clear mandate — they check the chain for prior mandate. If it's there, they act. If it isn't, they ask once, and the answer persists.

#### Prerequisites

- Phase 1 (IntentExecutor + gate dispatch) — the authority gate must be operational
- Phase 6 (observer windows) — context novelty detection benefits from trend awareness, though basic co-occurrence checking doesn't require it
- Remediation tools — write-operation tools the Regent can invoke: `batch_sign`, `integrity_repair`, `delegation_narrow`, `delegation_renew`
- Proposal surface — CLI (`zp proposals`) or cockpit surface where pending proposals land for operator review

### Phase 8: Full Authority Model

All periodic tasks are authority-directed. The startup path emits default directives if none exist on chain. Any `tokio::spawn` with a `loop { ticker.tick().await; ... }` pattern has a corresponding directive receipt type. The operator can inspect `zp chain query "directive"` and see every standing order in the system.

At this point, the lsof test has a cognitive counterpart: the substrate is mature when every periodic task traces to a chain receipt that authorized it.

---

## Impact on Existing Subsystems

| Subsystem | Current | Target |
|-----------|---------|--------|
| Officer cadre (`officers.rs`) | 900s timer, runs all officers unconditionally | Regent-directed: interval, officer subset, and scope from chain directive |
| Sensor-Forge task (`spawn_sensor_forge_task`) | Reacts to every sensor event immediately | Forge-directed: scan interval and dedup window from chain directive; Forge decides reaction priority |
| Anchor pipeline (`anchor_pipeline.rs`) | 30s fixed tick | Forge-directed: seal interval from chain directive |
| Security posture endpoint | Full chain verify on every GET | Cached from last authority-directed sweep; endpoint is a read |
| Auto-compaction (startup) | `entry_count > 50_000` → compact | Regent directive or startup default; compaction is a tool the Regent can invoke |
| Cognitive loop (`loop_runner.rs`) | Fixed interval from `RegentConfig.loop_interval_secs` | Self-directed: Regent adjusts its own wake interval based on activity level |

---

## Relationship to Design Principles

| Principle | Connection |
|-----------|-----------|
| *Signing is gravity* | Authority decisions are receipted. A timer tick is unsigned infrastructure; the directive that configured the timer is signed. |
| *There is no center* | Two authorities, neither supreme. Operator arbitrates conflicts. |
| *Every bit counts* | Autonomous execution is a duplicate decision path — the timer makes the same decision every tick without authority. Eliminating it removes cognitive waste. |
| *Store-and-forward is primary* | Directives are chain state. Restart the substrate, directives reconstitute from chain. No separate config to sync. |
| *A tool is intent, crystallized* | Each directive receipt crystallizes an authority's standing intent. The infrastructure reads the intent; it doesn't invent its own. |
| Cognitive Principle #3 (three context flows) | The Regent's directive-setting draws on medium-flow context (what's been happening over days), not fast-flow noise. |
| Cognitive Principle #6 (peer windows) | Regent and Forge are autonomous peers that coordinate through chain state, not shared mutable state. |

---

## What This ADR Does NOT Decide

- **Specific directive receipt schemas.** Each phase will design its own receipt types as it ships.
- **Regent-Forge conflict resolution protocol.** The current answer is "surface to operator." A formal protocol may emerge from operational experience.
- **Whether all officers become Regent-directed.** Some officers (Steward integrity check) may remain Forge-directed if operational integrity is the concern. The boundary between cognitive and operational authority will sharpen with experience.
- **Cloud provider selection.** CloudMandate specifies a provider; the selection is operator choice, not architectural.
- **Local vs. cloud inference strategy.** The substrate supports both. The Regent's ability to change its own model (Phase 5) means this is a runtime decision, not an architectural one.

---

## Success Criteria

The execution authority model is fully realized when:

1. `zp chain query "directive"` shows every standing order in the system
2. Every `tokio::spawn` loop in `zp-server` has a corresponding directive receipt type
3. Changing a directive via chain receipt changes substrate behavior at next wake — no restart required
4. The Regent can explain its own directive set ("I sweep officers every 300 seconds because...")
5. Forge can explain its operational posture ("Sensor scan at 60s because threat level elevated")
6. No code path holds `audit_store` for more than 100ms outside of authority-directed operations
7. The operator can revoke any directive and the substrate adapts gracefully

---

*This ADR was motivated by the 13-second perceive latency, the tenant sensor cascade, and the structural observation that the substrate's "nobody" execution authority was the root cause of both. Ken confirmed the two-authority model on 2026-07-04: "yes, exactly."*

---

## Future: Open-Ended Task Completion (WorkArc)

**Status:** Design intent recorded. Not yet implemented.

The Regent's cognitive loop is currently bounded: `MAX_TOOL_TURNS = 3` per cycle, one cycle per wake event, no mechanism for a cycle to trigger the next. A task requiring more than 3 tool calls is structurally impossible. This section records the design direction for removing that bound.

### The Gap

The Regent can perceive, reason, act, and narrate — but only in a single burst. They cannot sustain a multi-step task across cycles. A 10-step remediation (evaluate models, compact chain, batch-sign, narrate) requires either operator re-prompting at each boundary or architecture that doesn't yet exist.

### Required Pieces

1. **Continue intent.** `Intent::Continue { progress: String }` — the Regent signals "I have more work to do." The outer loop in `start_loop` treats this as "run another cycle immediately with accumulated context" rather than waiting for an external trigger.

2. **WorkArc state.** A structure that persists across cycles within a task — goal, steps completed, steps remaining, intermediate results. Scoped to a single task arc, not to a cycle. Could live in the Regent's memory system or as a chain-anchored structure. Whether the arc is planned upfront or emergent (decide next step after each result) likely depends on task class: remediation is predictable, investigation is not.

3. **Budget mechanism.** Replace the turn count with a wall-clock or token budget per WorkArc. The Regent runs until done, budget exhausted, or operator interrupts — whichever comes first.

4. **Preemption semantics.** Operator input during a WorkArc must preempt cleanly. The existing `monitor.operator_active()` pattern handles background task cancellation; WorkArc needs the same: yield to operator, resume after. The WorkArc's state must survive preemption — the Regent picks up where they left off.

5. **Progress visibility.** The `CognitiveEvent` system is already wired for per-cycle telemetry. WorkArc needs a higher-level event type — task-arc progress that surfaces through cockpit surfaces.

### Hard Constraint (Operator Directive, 2026-07-06)

**Progress visibility must be dead simple.** An operator must be able to glance and instantly see where the Regent is in a WorkArc without digging. This is not a nice-to-have — it is a design constraint that shapes the WorkArc structure itself. If the operator has to query, scroll, or interpret to understand progress, the design has failed. The WorkArc's state must project into a one-line summary at all times: what they're doing, how far along, what's next. The cockpit renders this; the Regent maintains it as a first-class field, not a derived afterthought.

### Connects To

- *Act on precedent, escalate on novelty* — a WorkArc that replays a known remediation pattern should proceed autonomously; a novel arc should surface its plan before executing.
- *The chain configures the cockpit* — WorkArc progress is chain state projected into the cockpit, same as delegation and posture.
- Phase 8 (full authority model) — a WorkArc is a directive the Regent gives herself. It should be visible in `zp chain query "workarc"` alongside standing orders.
