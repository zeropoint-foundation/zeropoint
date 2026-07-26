# Regent Doom-Loop Detection

**Document type:** Tier 2 canonical elaboration.
**Elaborates:** KEEL §II.17 (cognitive discipline sandwich), §III.19 (detectability — silence-is-the-enemy applied to cognitive emissions), §III.20 (forward-only recovery), §III.22 (evidence-based ceremony). Companion to `COGNITIVE-SELF-OBSERVER-2026-07.md` — this document **proposes** a new class for the observer's verification catalog (proposed Class 8: Emission Coherence). CSO ships Classes 1–7 today; integration of Class 8 is pending and lands via follow-up work.
**Date:** 2026-07-18. Motivated by SLM failure-mode analysis (Liquid AI LFM 2/2.5 talk by Maxime Labonne) and the observation that the substrate's Regent tier — currently qwen3:8b — is exactly the class of model that hits doom loops under load without any substrate mechanism noticing.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Living discipline. Ships as instrumentation, not remediation — the substrate first observes and chain-anchors evidence; escalation policy per class lands via follow-up work.

---

## Part I — What this addresses

Small language models exhibit a specific failure mode absent from frontier models at scale: **doom loops.** The model gets stuck emitting repetitive token sequences — same phrase over and over, cycling through near-identical variants, degenerating to minimum-entropy output — usually under one of three conditions:

1. **Task complexity exceeds capacity.** Model asked to reason about something beyond its intrinsic capability; instead of failing gracefully, it collapses to repetitive filler.
2. **Cold-start / RL-brittle domains.** Task class absent from supervised-fine-tuning distribution; model has no scaffold to fall back on.
3. **Sampling pathology.** Temperature-zero decoding on a distribution with a strong repetitive attractor; even competent models can hit this.

Doom loops are qualitatively different from ordinary poor output. Ordinary bad output is wrong-but-varied; doom-looped output collapses the response distribution. It's the cognitive equivalent of a stuck record.

Current substrate state: **no mechanism catches this.** The Regent's emission goes through Cognitive Self-Observer for standing-correction verification and (eventually) through Claim Verifier for capability claims. Neither detects doom-loop signatures. If qwen3:8b (or any future SLM in Regent seat) hits a doom loop tonight, the substrate would happily chain-anchor the resulting `regent:intent:respond` receipt with 4KB of repeated tokens and treat it as valid cognitive output. Operator would see the collapse and know something's wrong. Chain evidence would show nothing structurally wrong.

**This spec closes that gap** by adding doom-loop detection as a first-class substrate discipline — the same shape as chain-integrity discipline (Steward), coherence discipline (Observer Coherence), and canary discipline (Chain-Read Canary), but for cognitive emissions rather than substrate state.

---

## Part II — Detection heuristics

Layered, cheap-to-run, composable. No single heuristic is authoritative; the composed signal is what triggers detection.

### Heuristic 1 — N-gram repetition density

**What:** count occurrences of each n-gram (n ∈ {3, 5, 8}) in the response body; flag if any single n-gram appears more than a threshold count relative to response length.

**Concrete:** for a response of L tokens, if any 3-gram appears more than `max(4, L/20)` times, or any 5-gram more than `max(2, L/40)` times, or any 8-gram more than `1`, mark the response as doom-loop-suspected.

**Rationale:** doom loops manifest as bounded token sequences repeating. Natural language has repetition too, but bounded (an operator's name appears often; a technical term appears often); doom-loop repetition is on longer sequences that would not naturally repeat.

**Cost:** O(L·n) per response, negligible.

### Heuristic 2 — Response length distribution collapse across cycles

**What:** track Regent response length over a rolling window of N cycles (default N = 20). If the coefficient of variation collapses below a threshold (default 0.15) AND the mean approaches either the minimum-token floor OR a highly-round number (100, 200, 500, 1000, 2048), flag the window.

**Rationale:** healthy Regent cycles produce variable-length responses matched to prompt complexity. Doom-looped cycles produce either "shortest thing possible" or "hit the response cap." Collapse to either pole is signal.

**Cost:** O(N) per cycle for rolling stats.

### Heuristic 3 — Token entropy anomaly

**What:** if the inference backend exposes per-token log-probabilities (Ollama and most local backends do), compute mean token-entropy across the response. Compare against a rolling baseline for this model. If entropy collapses more than 2σ below baseline, flag.

**Rationale:** doom-looped output has near-deterministic per-token distributions — the model is very confident about the next repetition. Healthy output has higher variance.

**Cost:** O(L) per response; only when log-probs are available (baseline collection required — dossier field).

### Heuristic 4 — Precedent-context degeneration

**What:** compare response semantic embedding against the response from the same cycle's prior invocation (if this is a retry) or against the mean embedding of last N responses in the same conversation. If cosine similarity exceeds 0.98 across distinct prompts, flag.

**Rationale:** doom-loop responses tend to be indistinguishable regardless of prompt. Semantic sameness across genuinely distinct inputs is a stronger signal than any single response's shape.

**Cost:** requires embedding pass; expensive. Run only when Heuristics 1–3 already flag.

### Heuristic 5 — Reasoning-step stagnation (for reasoning-mode responses)

**What:** for models emitting `<thinking>` blocks or equivalent, count distinct intermediate states in the reasoning trace. If the trace has ≥ K tokens but < J distinct intermediate assertions, flag.

**Rationale:** reasoning-mode doom loops are the worst class — the model appears to reason but the reasoning is circular. Frontier reasoning models mostly don't hit this; SLMs in reasoning mode hit it constantly on hard tasks.

**Cost:** O(K) if reasoning trace parsing is cheap; expensive otherwise. Model-dossier-declared whether applicable.

### Composed signal

Detection fires when:
- Heuristics 1 OR 2 OR 3 flag on the current response, OR
- Heuristics 4 OR 5 flag over a window of responses, OR
- Any combination of two heuristics at any severity flags simultaneously.

Chain-anchored `regent:emission:doom_loop_suspected` receipt with heuristic evidence per flag.

---

### Chronic-drift heuristics (pre-runtime formalization, 2026-07-24 addendum)

Heuristics 1–5 catch **acute** doom-loop signatures — a specific response or short window that flags as failure. Heuristics 6–8 catch **chronic drift** — slow textual and structural quality degradation across many cycles that individually would not flag as failure but in aggregate signals the Regent's output quality is declining. Distinct failure modes; distinct response profile (see updated Composed signal below).

Chronic-drift heuristics require Cartographer materialization + officer runtime + baseline-collection cycles to compute against. **Formalized here now as observables for the empirical program to track once the runtime is live** (see `EMPIRICAL-PROGRAM-2026-07.md` §REGENT-CHRONIC-DRIFT-INVESTIGATION); they do not ship with fixed thresholds because thresholds require per-model empirical calibration that only runtime data produces.

### Heuristic 6 — Lexical diversity drop

**What:** track type-token ratio (TTR) — unique tokens over total tokens — per Regent response. Also track moving-average TTR (MATTR) across a sliding sub-window to mitigate length-sensitivity. Compute per-response value and per-cycle-window trend across a rolling window of N cycles (default N = 30, empirical calibration pending). Flag if per-window MATTR trends monotonically downward across ≥K cycles (default K = 10, pending) OR drops below an absolute floor (per-model baseline − 2σ).

**Rationale:** healthy Regent output shows lexical variety appropriate to the diversity of prompts she is responding to. Chronic drift toward a smaller working vocabulary — "vocab collapse" — is an early signal of model degradation, over-conditioning, or training-signal starvation. Distinct from Heuristic 1 (n-gram repetition density is *within-response* burst repetition; lexical diversity drop is *cross-response* vocabulary shrinkage).

**Cost:** O(L) per response for TTR; O(W·L) per cycle for MATTR window; both cheap. Baseline MATTR per (model, prompt-class) pair needs collection before flagging.

**Cartographer dependency:** requires an ontology object (name TBD — see §Ontology gap below) materializing per-emission Regent-response data with lexical statistics so window trends can be queried; officer runtime to run the trend detection sweep.

### Heuristic 7 — Structural variance collapse

**What:** extract structural features of each Regent response — paragraph count, sentence-count-per-paragraph distribution, section-header presence and depth, opening-phrase-shape hash, closing-phrase-shape hash, enumeration-template presence (e.g., "First,... Second,... Finally,..."), question-vs-statement ratio. Represent as a compact structural fingerprint per response. Track fingerprint diversity (unique fingerprint count / total responses) across a rolling window of N cycles (default N = 30, empirical calibration pending). Flag if fingerprint diversity collapses below threshold across genuinely distinct prompts.

**Rationale:** response length distribution collapse (Heuristic 2) catches acute length-uniformity. Structural variance collapse catches the chronic case where responses are *shape-identical* even though length and token content vary — the Regent has fallen into a single response template. Distinct prompts should elicit distinct structures; if they don't, the model has flattened into a mold. Empirically observed as a precursor to full doom-loop in SLM tuning arcs (LFM 2/2.5 analysis).

**Cost:** O(L) for feature extraction; O(W) for window variance. Fingerprint scheme is Layer B canonicalizable — start with simple counts + template pattern hashes; refine as empirical data informs which structural features carry the most signal.

**Cartographer dependency:** requires an ontology object (name TBD — see §Ontology gap below) materializing per-emission Regent-response data with structural fingerprints stored; officer runtime for window trend queries.

### Heuristic 8 — Boilerplate creep

**What:** maintain a Layer B canonical catalog of **boilerplate phrases** — stock phrases indicating template-language drift. Count boilerplate phrase occurrences per response (raw count and rate-per-hundred-tokens). Track per-window trend across a rolling window of N cycles (default N = 30, empirical calibration pending). Flag if per-response rate exceeds threshold OR per-window trend shows monotonic increase across ≥K cycles.

**Nominated initial catalog** (Layer B, extensible via canonicalization ceremony as operators observe new boilerplate patterns from live substrate use):

- Deferral / self-reference templates: *"As an AI assistant, I..."*, *"I'm just an AI..."*, *"I don't have access to..."*
- Hedge and softener clusters: *"It's important to note that..."*, *"Please note that..."*, *"It depends on..."*, *"Generally speaking..."*
- Closing platitudes: *"I hope this helps"*, *"Let me know if you have any questions"*, *"Feel free to ask..."*
- Enumeration templates: *"First,... Second,... Third,... Finally,..."* skeleton without content-specific bridging
- Formulaic transitions: *"Moving on to..."*, *"In summary..."*, *"To conclude..."*
- Non-committal opening: *"That's a great question."*, *"There are several factors to consider."*

**Rationale:** chronic quality degradation manifests as increased reliance on safe, generic filler. Boilerplate creep is a canary for the *training-signal starvation* failure mode — when the model can no longer produce sharp contextual response, it retreats to phrases it has been strongly reinforced on across pre-training. Distinct from Heuristic 4 (semantic sameness across distinct prompts is about *response semantics* collapsing; boilerplate creep is about *filler phrases within otherwise-varied response* accumulating).

**Cost:** O(L·|catalog|) per response — matches against boilerplate catalog with fast substring / regex matching. Catalog size bounded (Layer B enforces size cap; operators nominate additions via ceremony, do not bulk-add).

**Cartographer dependency:** an ontology object (name TBD — see §Ontology gap below) materializing per-emission Regent-response data with boilerplate-hit counts and rates stored; officer runtime for window trend queries.

**Model-specific catalogs:** different inference providers produce different boilerplate signatures. Model dossier gains a `known_boilerplate_signatures` field (per SUBSTRATE-BOOT-INVARIANT-CEREMONY B2 model-dossier requirements) that Heuristic 8 composes with the global catalog when scanning that model's emissions. Baseline drift-rate per model per prompt-class is empirical.

### Ontology gap

The chronic-drift heuristics require per-Regent-emission data to be queryable across a rolling window — a persistent materialization of Regent's response history with statistical fields (lexical counts, structural fingerprints, boilerplate hit counts). `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` currently declares five core object types (Trajectory, Decision, Insight, Artifact, Friction); none is a natural fit for per-emission observation records at the granularity these heuristics need.

The gap has two candidate resolutions, both pre-runtime and both requiring Cartographer amendment:

- **Option A — extend Artifact.** A specialization: `Artifact.kind = regent_emission` with per-emission statistical fields. Uses existing infrastructure; may stretch Artifact's semantics (artifacts are currently signed canonical renderings, not observational records — semantic drift risk).
- **Option B — new object type.** Introduce a sixth core object (working name `RegentEmission` or similar). Cleaner semantics; requires Cartographer ceremony to add.

Recommendation: **Option B.** The semantic separation (Regent emissions are *observational data*, not *signed decisions*) is worth the object-type addition. The formal decision belongs to a Cartographer amendment ceremony, not this doc.

Coordinated with `EMPIRICAL-PROGRAM-2026-07.md §REGENT-CHRONIC-DRIFT-INVESTIGATION`: the investigation's Phase 1 precondition includes Cartographer materialization of the chosen object type. Whichever option lands, the empirical-program dependency chain names it before the investigation activates.

### Updated Composed signal — acute vs chronic

Detection now distinguishes two response profiles:

**Acute doom-loop signal** (existing R0/R1/R2 response classes):
- Heuristics 1 OR 2 OR 3 flag on the current response, OR
- Heuristics 4 OR 5 flag over a window of responses, OR
- Any two of {1,2,3,4,5} flagging simultaneously.
- Chain-anchored `regent:emission:doom_loop_suspected` receipt; runtime response per Part III (log/retry/escalate).

**Chronic-drift signal** (new response profile, not runtime-blocking):
- Heuristics 6 OR 7 OR 8 flag on window trend across N ≥ 30 cycles, OR
- Any two of {6, 7, 8} flag simultaneously on window trend.
- Chain-anchored `regent:emission:chronic_drift_suspected` receipt with per-heuristic evidence and the window range covered.
- **Does not trigger R1/R2 retry cycles** — chronic drift is not fixed by re-sampling one response.
- Surfaces to Cleo for narration ("your Regent's lexical diversity has declined 30% over the last 60 cycles; you may want to review the current model or its prompt configuration"); surfaces to operator dashboard.
- Composes with operator's model-swap or model-tuning decision, not with Regent's autonomous runtime action.
- Feeds SHADOW-EVALUATION-PRIMITIVE Context 1 (inference paths) via SHADOW-INFERENCE-COMPARISON Trigger 1 (novel-model served) and Trigger 2 (dossier drift suspected); also feeds SHADOW-MODEL-SWITCHING's 5-check validation battery. In each case the candidate model's chronic-drift baseline (once accumulated) is compared against the current-model baseline as an additional dimension of shadow evaluation.

---

## Part III — Response classes

Detection is one thing; the substrate's response to detection is another. Three classes, per severity:

### Class R0 — Log and continue

**When:** single-heuristic flag on a single response, no window-level pattern.

**Substrate response:**
- Emit `regent:emission:doom_loop_flagged` receipt with heuristic evidence.
- Deliver the response to the operator surface (do NOT withhold — false-positive risk).
- Continue Regent cycles normally.

**Rationale:** first flag is investigation-worthy but not action-worthy. False positives happen; withholding responses on single flags produces its own trust degradation.

### Class R1 — Retry with adjusted sampling

**When:** two-heuristic composed signal on a single response, OR single-heuristic flag on a window pattern.

**Substrate response:**
- Do NOT deliver the flagged response.
- Chain-anchor `regent:emission:doom_loop_suspected` with evidence.
- Retry the cycle with `temperature += 0.15`, `top_p += 0.05`, and n-gram-repetition penalty enabled at the sampling layer (most backends support this).
- Chain-anchor `regent:emission:retry_adjusted_sampling` with the adjusted parameters.
- Deliver the retry response (subject to its own detection pass — if it also flags, escalate to R2).

**Rationale:** the LFM approach's insight — doom loops respond to sampling adjustment. Verifiable-reward RL and DPO reduce the frequency; at inference time, sampling parameters are the operator's remaining lever.

### Class R2 — Escalate

**When:** R1 retry also flagged, OR two-heuristic composed signal across a window pattern, OR reasoning-step-stagnation flag.

**Substrate response:**
- Do NOT deliver either response.
- Chain-anchor `regent:emission:doom_loop_confirmed` with all evidence.
- Emit substrate-visible event: `substrate:degraded:regent_cognitive_capability` per SUBSTRATE-READINESS-CONTRACT `no_silent_degradation` discipline.
- Options for operator surface (per operator preference — chain-anchored preference receipt determines default):
  - **Fallback tier:** if inference-routing has a fallback tier declared (e.g., LLM cloud mandate), route the cycle to fallback. Chain-anchor `regent:cognitive:fallback_engaged`.
  - **Operator escalation:** surface the situation to operator explicitly, propose either fallback or "I don't know how to answer this at my current capacity" response.
  - **Refuse-and-narrate:** Regent emits a chain-anchored refusal with the specific failure mode named (per aligned-blindness heuristic applied to cognitive limits).

**Rationale:** confirmed doom loop means the current model tier can't handle the current task. Silently retrying forever wastes cycles and produces the "stuck substrate" failure mode. Substrate is honest about its limits; operator's preference determines the escape.

---

## Part IV — Chain-anchored evidence schema

Every detection produces structured chain evidence. Not just for accountability — this corpus becomes the eval battery + training signal for eventual substrate-specific fine-tuning.

**Per-flag receipt:**

```
regent:emission:doom_loop_flagged
  cycle_id: uuid
  response_receipt_id: string      # cites the regent:intent:respond receipt
  model: string                    # e.g., "qwen3:8b"
  sampling_params: {temperature, top_p, seed?}
  heuristics_fired: [
    {
      name: string                 # "n_gram_repetition_density" | ...
      severity: enum               # Warning | Critical
      evidence: {                  # heuristic-specific
        ...
      }
    }
  ]
  response_hash: sha256            # of the flagged response body
  response_length: u32
```

**Retry adjustment receipt:**

```
regent:emission:retry_adjusted_sampling
  cycle_id: uuid
  original_flag_receipt: string
  original_params: {...}
  adjusted_params: {...}
  n_gram_penalty_enabled: bool
```

**Confirmed doom loop receipt:**

```
regent:emission:doom_loop_confirmed
  cycle_id: uuid
  attempt_receipts: [<flag_receipt_ids>]
  model: string
  task_class: string               # inferred from cognitive input (per Cognitive Input Plane)
  escalation_taken: enum           # fallback_tier | operator_escalation | refuse_and_narrate
  operator_preference_receipt: string?  # cites the operator-signed preference
```

**Substrate-visible degradation:**

```
substrate:degraded:regent_cognitive_capability
  cycle_id: uuid
  confirmed_receipt: string
  degraded_capability: "cognitive_response_for_task_class"
  task_class: string
  fallback_engaged: bool
  operator_notified: bool
```

**Chronic-drift receipt (new, 2026-07-24 addendum — Heuristics 6/7/8):**

```
regent:emission:chronic_drift_suspected
  window_start_cycle: string        # first cycle_id in the trend window
  window_end_cycle: string          # last cycle_id in the trend window (exclusive)
  window_cycle_count: u32
  model: string
  heuristics_fired: [
    {
      name: enum                    # "lexical_diversity_drop" | "structural_variance_collapse" | "boilerplate_creep"
      trend_direction: enum         # "monotonic_decline" | "threshold_breach" | "monotonic_increase"
      trend_magnitude: f64          # heuristic-specific quantification
      cycles_over_threshold: u32    # how many cycles in the window flagged
      baseline_reference: string?   # cites the baseline receipt this compared against
      evidence_sample_receipt_ids: [<up to 5 example flagged emission receipts>]
    }
  ]
  operator_advisory: string?        # Cleo-generated narration line, optional
  # Deliberately does NOT include: retry_taken, fallback_engaged, or degradation flags —
  # chronic drift does not trigger runtime response; it feeds operator decisions.
```

Emission cadence: at most one `chronic_drift_suspected` receipt per (model, heuristic-name) per rolling window duration. Avoids chain-bloat from stable-trend re-emission. Layer B threshold configurable.

---

## Part V — Composition with existing disciplines

**COGNITIVE-SELF-OBSERVER-2026-07.md** — this document proposes to extend the observer's verification catalog. CSO today ships Classes 1–7 (Chain-state, Diagnosis, Interpretation, Precedent, Commitment, Self-state, Capability). Doom-loop detection is proposed as an additional Class 8: Emission Coherence. Same infrastructure: post-emission verification, pattern-match extraction, chain-anchored findings. Different signal. **Integration status:** Class 8 is not yet in CSO's shipped catalog; picked up in follow-up work when doom-loop instrumentation lands.

**MODEL-DOSSIER-2026-07** (via EXECUTION-AUTHORITY-MODEL Phase 5) — dossier's `suitability` field extends to include:
- `doom_loop_rate_per_1k_responses` — chain-anchored measurement over rolling window
- `entropy_baseline` — for Heuristic 3
- `reasoning_step_parseable` — bool, whether Heuristic 5 applies
- `known_doom_loop_triggers` — task classes empirically prone to doom loops for this model

The dossier becomes evidence-backed; measurements derive from chain-anchored detection events.

**SHADOW-EVALUATION-PRIMITIVE-2026-07.md** — shadow inference comparison can now compare candidate models on doom-loop rate. Not just "candidate produces same output as control"; also "candidate has lower doom-loop rate on this task class." Chain-anchored evidence enables provider comparison structurally.

**SUBSTRATE-READINESS-CONTRACT-2026-07.md** — the `no_silent_degradation` discipline pin applies. Class R2 escalation emits `substrate:degraded:regent_cognitive_capability` — not a WARN log, a chain receipt. `zp doctor` reads it as substrate state; `zp regent` surfaces the degradation to operator per Class R2 escape.

**SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md** — Phase B2 (composition proof) verifies that Regent's active model has a populated dossier with detection-parameter fields present. Adding a new model to Regent's tier fails CI until dossier fields are populated. This makes Regent-tier changes evidence-based rather than assumption-based.

**INFERENCE-ROUTING-DISCIPLINE-2026-07.md** — Class R2 fallback tier engagement is a Layer 2 routing event; chain-anchored `regent:inference:routed` per that discipline captures which fallback was engaged and why (with the confirmed doom-loop receipt as motivation).

**ACT-ON-PRECEDENT** heuristic — the corpus of chain-anchored doom-loop evidence per task class becomes precedent. Regent (or a future substrate discipline) can preemptively check: "is this task class known to doom-loop this model?" and route to fallback tier proactively without waiting for detection to fire.

---

## Part VI — What this generates as substrate benefit

Beyond catching immediate failures:

**Substrate-specific eval battery.** Chain-anchored doom-loop events across models and task classes become a structured evaluation battery — the substrate's own benchmark of which models handle which task classes cleanly. External benchmarks (GPQA, BFCL, IF-Bench) don't measure what actually matters for Regent operation; substrate-anchored measurements do.

**Training signal for fine-tuning.** When the substrate-specific fine-tuning path becomes viable (per this session's SLM analysis), the corpus of `regent:emission:doom_loop_confirmed` events with task_class + response_hash + heuristic_evidence is training signal — specifically, negative examples for DPO-style preference alignment. "Do not emit responses like this on prompts like this." No synthetic dataset needed; the substrate's own operation produces it.

**Evidence-based routing.** Once enough events accumulate per task_class × model, routing can be proactive: "for task class X, model Y has a 12% doom-loop rate; route to model Z or fallback." Chain-anchored evidence, not vendor claims.

**Operator understanding of capability limits.** Currently the substrate is opaque about its cognitive limits — operator learns them through surprise. With doom-loop detection surfaced honestly, operator sees "Regent is struggling with this class of task on this model" as chain evidence, not silent degradation.

**Model-provider evaluation.** When comparing SLM candidates for Regent tier (qwen3, LFM 2.5, Gemma 3, BitNet variants), doom-loop rate becomes a first-class metric. Composes with SHADOW-INFERENCE-COMPARISON for empirical head-to-head.

---

## Part VII — What this does NOT cover

- **Semantic hallucination detection.** Doom loops are structural (repetitive tokens); hallucinations are semantic (wrong content, confidently stated). Different failure mode; different detection stack (Claim Verifier is the primary discipline there).
- **Model-quality degradation over time.** If qwen3:8b silently gets worse for reasons unrelated to doom loops, this discipline won't catch it. That's SHADOW-MODEL-SWITCHING territory.
- **Prompt engineering to avoid doom loops.** This discipline detects and responds to them; the Cognitive Input Plane's matrix (which prompts the Regent sees) is the upstream lever.
- **Reasoning-mode-specific analysis.** Heuristic 5 is placeholder; a full reasoning-trace analysis discipline is its own arc (composes with REGENT-ORCHESTRATION-ARCHITECTURE).
- **Cross-model doom-loop correlation.** If both qwen3:8b and Gemma 3 doom-loop on the same task class, that says something about the task class (maybe about the Cognitive Input Plane matrix). This spec doesn't diagnose that; it produces the evidence that would enable diagnosis.

---

## Part VIII — Implementation seed

Concrete first-pass placement in the codebase:

- **New module:** `crates/zp-regent/src/emission_coherence.rs` — parallel to `cognitive_observer.rs`. Contains Heuristics 1–5, detection composition, receipt schema.
- **Integration point:** invoked in `crates/zp-regent/src/loop_runner.rs` immediately after `intent` is produced but before delivery — same slot Cognitive Self-Observer occupies.
- **Configuration:** thresholds default in code, overridable via `zp_config` schema additions (`[regent.emission_coherence]` section — but defaults produce a functional substrate per SUBSTRATE-READINESS-CONTRACT §Surface 3).
- **Chain emission:** existing audit-store append path (through the intent executor).
- **Retry loop:** requires small change to `IntentExecutor::execute` to accept a retry-with-adjusted-sampling path. Non-trivial but bounded.
- **Fallback tier engagement:** requires INFERENCE-ROUTING-DISCIPLINE's routing surface to expose a `route_to_fallback(&self, reason: FallbackReason)` verb. Straightforward composition.

Total scope: ~600 lines of Rust for detection + retry, plus dossier field additions, plus configuration schema additions. Bounded work; can land in one focused PR after this spec is agreed.

---

## Part IX — Verifiable outcomes

Testable claims that must hold post-implementation:

**Claim DL1:** every Regent response is inspected by all applicable heuristics (per model dossier). No response bypasses detection.

**Claim DL2:** every flag produces a chain-anchored receipt. No silent flags.

**Claim DL3:** confirmed doom loops produce a `substrate:degraded:regent_cognitive_capability` receipt visible to `zp doctor` and readable by any operator surface.

**Claim DL4:** retry loop terminates. Under any inputs, the retry-adjustment sequence bounds at N attempts (default N=2), then escalates. No infinite retry loop.

**Claim DL5:** chain evidence from doom-loop events over T time forms a queryable corpus (`zp chain query "regent:emission:doom_loop_confirmed"`) with per-model, per-task-class aggregation available.

**Claim DL6:** false-positive rate on curated adversarial content is measurable and stays below 1% for Class R1 escalation, 5% for Class R0 flag. Chain-anchored eval battery lands with this spec.

**Claim DL7:** the discipline itself is chain-anchorable — heuristic thresholds and detection code are versioned; changes flow through SUPERSESSION-FRAMEWORK.

---

## Part X — Follow-up work

**Immediate (blocks first-shipping instrumentation):**
- Implement `emission_coherence.rs` module with Heuristics 1–3 (n-gram, length collapse, entropy).
- Add dossier field schema for `doom_loop_rate_per_1k_responses`, `entropy_baseline`.
- Wire Class R0 (log and continue) response.

**Near-term:**
- Implement Heuristic 4 (semantic embedding) — requires embedding endpoint on the running inference backend.
- Implement Heuristic 5 (reasoning-step stagnation) — requires reasoning-trace parsing per model.
- Implement Class R1 retry with sampling adjustment.
- Populate dossier fields from initial deployment observation.

**Longer-term:**
- Implement Class R2 with fallback-tier engagement (requires INFERENCE-ROUTING-DISCIPLINE fallback verb).
- Amend EXECUTION-AUTHORITY-MODEL Phase 5 (model evaluation) to include doom-loop rate as first-class metric.
- Amend INFERENCE-ROUTING-DISCIPLINE with the SLM-vs-LLM routing bright line: precedent → SLM, novelty → LLM.
- Feedback loop: chain-anchored doom-loop corpus feeds SHADOW-EVALUATION-PRIMITIVE for provider comparison.
- Feedback loop: chain-anchored doom-loop corpus becomes training signal for eventual substrate-specific fine-tuning.

**Chronic-drift heuristic implementation (blocked on Cartographer + officer runtime; formalized 2026-07-24 for the empirical program to track once runtime is live):**
- Implement Heuristic 6 (lexical diversity drop) — TTR / MATTR per emission, window-trend detection. Blocked on: `RegentEmission` ontology object materialization by the Cartographer with per-emission lexical statistics.
- Implement Heuristic 7 (structural variance collapse) — response-shape fingerprinting, window-diversity trend. Blocked on: `RegentEmission` ontology object with structural-fingerprint field; Layer B fingerprint scheme canonicalization.
- Implement Heuristic 8 (boilerplate creep) — Layer B canonical boilerplate catalog + per-emission match count + window trend. Blocked on: initial catalog canonicalization ceremony; per-model dossier field `known_boilerplate_signatures`; officer runtime for trend queries.
- Populate baseline data per (model, prompt-class) before flagging fires — needs the runtime running long enough to establish baselines. See `EMPIRICAL-PROGRAM-2026-07.md §REGENT-CHRONIC-DRIFT-INVESTIGATION` for the empirical validation arc.

---

## Composes with / connects to

- **COGNITIVE-SELF-OBSERVER-2026-07.md** — this document proposes Class 8 (Emission Coherence) as an extension to the observer's verification catalog. CSO today ships Classes 1–7; Class 8 integration is pending.
- **EXECUTION-AUTHORITY-MODEL-2026-07.md** — Phase 5 model evaluation absorbs doom-loop rate as first-class metric.
- **INFERENCE-ROUTING-DISCIPLINE-2026-07.md** — Class R2 fallback tier engagement.
- **SHADOW-EVALUATION-PRIMITIVE-2026-07.md** — doom-loop rate as candidate-vs-control comparison signal.
- **SUBSTRATE-READINESS-CONTRACT-2026-07.md** — `no_silent_degradation` discipline; substrate emits chain-anchored degradation when confirmed.
- **SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md** — B2 composition proof requires Regent-tier model to have populated dossier detection fields.
- **CLAIM-VERIFIER-2026-07.md** — parallel discipline: Claim Verifier catches semantic capability-claim errors; this catches structural emission-coherence errors.
- **COGNITIVE-INPUT-PLANE-2026-07.md** — upstream lever; better cognitive input reduces doom-loop rate at the cause.

## CLAUDE.md workflow heuristics this exercises

- *Silence is the enemy, not compromise. Detectability over invulnerability.* — the KEEL invariant this discipline serves at the cognitive layer.
- *Verify before commit.* — every Regent emission is verified before it becomes chain evidence and reaches the operator.
- *Substrate operational state is chain-anchored evidence, not inferred silence.* — the substrate's cognitive capability becomes queryable evidence, not inferred quality.
- *Config reflects today, not roadmap.* — dossier fields reflect measured rates from real deployment, not hoped-for capability claims.
- *A model and its prompts are an atomic pair.* — doom-loop rate is per-model-per-prompt-class; changes to either require re-verification. Composes at the emission-coherence layer.

## Proposed new heuristic (nomination for CLAUDE.md)

**Cognitive emission is substrate output that MUST be verified. Detection is instrumentation, not judgment.**

*The substrate cannot claim its Regent tier is functional without empirical evidence of emission coherence. Chain-anchored measurements of failure modes (doom loops, hallucinations, confabulation, precedent drift) are the actual signal — vendor benchmarks and internal claims are not sufficient. Instrumentation catches failures; response to instrumentation is a separate operator-signed policy question.*

*The corollary: the substrate ships instrumentation before it ships remediation. Detecting a problem produces chain evidence that enables informed policy; jumping to automatic remediation without evidence produces the wrong policy first.*

*Applies at every layer where substrate output has to be trusted: cognitive layer (this doc), officer findings (chain-integrity + coherence), extension surface (WASM sandbox violations), peer-verification (reproducibility divergence). Instrumentation before remediation, evidence before policy, ceremony before action.*
