# Model Admission Pipeline — the ceremony is designed, the mechanisms are built, and nothing connects them

**Document type:** Design note / implementation plan. Elaborates no KEEL section. It reads the model-lifecycle machinery against the corpus that already governs it, finds the design complete and the wiring absent, and proposes the connections in the order they should ship.

**Date:** 2026-08-18.

**Status:** Proposed. **No code changed.** Two rulings requested: §7 (where generated dossiers live) and §10.4 (which protocol the Regent speaks to its own local backend). §10 was added after running the calibrator and supersedes this memo's original advice on stage 4.

**Author:** Drafted by Claude against the tree at `c756728`, on Ken's request to "connect the dots so that new models are automatically picked up and processed by the system, shaped to purpose, hardened."

**Composes with:** `MODEL-DOSSIER-2026-07.md` (the characterization primitive and its four-state lifecycle — this document implements it), `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (§"Novel model handling", the three-phase admission), `SHADOW-MODEL-SWITCHING-2026-07.md` (tiered admission depth), `SHADOW-INFERENCE-COMPARISON-2026-07.md` (the mandated evidence mechanism), `HARDWARE-DOSSIER-2026-08.md` (fit prediction, unimplemented), `QUARANTINE-PLANE-2026-07.md` (the admission shape being specialized), `REGENT-DOOM-LOOP-DETECTION-2026-07.md` (H3, and the field it owns).

**Attribution:** Every mechanism below was read, not inferred. Line citations are to the tree at `c756728`. Claims about runtime behaviour are marked as derived where they were not observed.

---

## 1. The finding in one paragraph

The substrate already discovers local models, already runs a 33-case behavioural battery against every one of them on an idle trigger, already parses hand-authored dossiers into a routing corpus, already scores models against that corpus, and already senses host RAM, GPU and VRAM. Every one of those mechanisms works. **None of them is connected to the next.** Discovery does not reach the dossier corpus; the battery's results are computed and discarded; nothing has ever written a dossier; the corpus does not load on any machine but the build host; the resource sensor is called only during onboarding and never by the router. Meanwhile the corpus has already specified the pipeline in full — a four-state lifecycle, a five-step bootstrap ceremony, a three-phase novel-model admission, and a tiered switch depth — across five Tier-2 documents. **This is not a design problem. It is the declaration-versus-enforcement gap at the scale of a subsystem.**

## 2. What is already built

| Mechanism | Where | State |
|---|---|---|
| Local model discovery via Ollama `/api/tags` | `zp-regent/src/evaluation.rs:1492` | works; discards the `size` field |
| 33-case behavioural battery, 11 categories | `evaluation.rs:230-621` | works; compiled in, not data-driven |
| Collapse probing, 5 dimensions, threshold search | `evaluation.rs:988`, `:1029-1075` | works |
| Idle-triggered background sweep over every discovered model | `evaluation.rs:1598`, gated at `loop_runner.rs:741` | works; runs ungoverned (§5) |
| Operator-triggered evaluation as a Regent tool | `evaluation.rs:1533` ← `zp-server/src/regent.rs:707` | works |
| Dossier parsing into a routing corpus | `zp-regent/src/routing.rs:266-419` | works; hand-rolled, silently lossy (§3.4) |
| Dossier-scored routing with pressure penalty | `routing.rs:497-639` | works; never exercised in production (§3.3) |
| Host RAM / cores / chip / GPU / VRAM detection | `zp-server/src/onboard/inference.rs:265`, `:564` | works; stranded (§3.6) |
| Memory pressure and loaded-model awareness | `zp-regent/src/awareness.rs:252`, `:393` | works |
| H3 entropy-baseline consumption | `routing.rs:429-459` → `zp-emission-coherence` | works; returns an empty map today (§3.5) |

Ten mechanisms. The pipeline the operator asked for is mostly a question of joining them.

## 3. The disconnects, in the order they cost the most

### 3.1 The battery's evidence is computed and thrown away

`run_evaluation_sweep` builds an `EvaluationReport` carrying per-category pass rates, a think-suppression profile naming which suppression mechanism works for that model, and per-dimension collapse thresholds. The only `ReceiptEmitter` implementation reduces the whole thing to a formatted string (`loop_runner.rs:785-791`):

```rust
event: format!(
    "regent:model_evaluated:{} passed={}/{} latency={}ms",
    report.model, report.passed, report.total_tests, report.total_latency_ms
),
```

Four scalars survive. The category scores, every failure reason, the suppression profile and every collapse threshold exist only in memory and are dropped when `SweepResult` falls out of scope. **The substrate measures exactly what a dossier needs and keeps none of it.**

### 3.2 One field of the dossier has a writer; the rest is hand-authored

**Correction to an earlier draft of this memo, which claimed nothing writes a dossier.** `scripts/calibrate-h3-baseline.py` does, at its `:336` and `:349` — it runs a prompt battery through the OpenAI-compat `/v1/chat/completions` endpoint with `logprobs=true`, computes mean and standard deviation of `-log P(chosen)`, and writes `[entropy_baseline]` into `models/<family>/model_dossier.toml`. It is HTTP-only, takes `--family`, and supports `--dry-run`. **So the measurement-to-dossier loop exists, for exactly one field, in Python, run by hand.** That is a working precedent for stage 5, not an absence. **It is not, as an earlier revision of this memo claimed, a reason stage 4 is cheap — see §10, which retracts that.**

Everything else remains one-directional. No Rust code writes a dossier. `evaluation.rs` contains no filesystem access and no reference to `DossierCorpus`; the word "dossier" appears there seven times, all prose, four naming the dossier as the destination of a measurement that never travels there — including `evaluation.rs:176`, on the think-suppression profile: *"This feeds the model dossier's per-variant inference config recommendations."* Nothing reads that field. `routing.rs:146` states the direction as settled for the consumer: *"Runtime projection — the TOML file is truth."*

### 3.3 The routing corpus does not load off the build host

`zp-server/src/regent.rs:2659` resolves `models/` from `CARGO_MANIFEST_DIR`. The tie-off above it (Stage 1t, 2026-07-26, deferred) is explicit:

> On any machine other than the one that compiled the binary the read fails, `load_from_dir` warns and returns an empty corpus, and every routing decision silently falls through to `route_from_config`. **ARTEMIS has therefore never exercised dossier-based routing.**

`route_from_config` (`routing.rs:667-702`) does not choose. It reads two config strings — `reasoning_model`, `routing_model` — and hardcodes `InferenceTier::Local` regardless of where `inference_endpoint` points. So on any non-build host, the entire scoring apparatus in §2 is dead and the model is whatever config says.

**This is the single highest-leverage fix in the document.** Everything else in the pipeline feeds a corpus that, today, most machines never load.

### 3.4 The dossier parser degrades silently, and three of six dossiers are already degraded

Parsing is hand-rolled `toml::Table` lookups (`routing.rs:304-419`), not `Deserialize`. Fifteen keys are read; everything else in a ~350-line file is prose. Two silent losses are live right now:

- **`variants_tested` vs `variants_available`.** Only `variants_tested` is read (`routing.rs:330`). `qwen3.6`, `llama4` and `phi4` all spell it `variants_available`, so **half the corpus has an empty variants list**, which degrades `infer_tier` into a `contains('/')` heuristic.
- **`Suitability::from_str` recognizes five strings and defaults the rest to `Untested`** (`routing.rs:77-93`). The real dossiers contain two more: `"candidate"` and `"deployed"`. `qwen3.6`'s officer tier says `deployed` and the router reads it as untested. No warning.

A dossier consisting of nothing but `[identity]` and a `family` key parses successfully and enters the corpus.

### 3.5 H3 is off for every model

`entropy_baselines()` only inserts baselines where `state == "calibrated" && std_dev > 0.0` (`routing.rs:206-208`). All six dossiers carry `state = "not_yet_calibrated"` and `std_dev = 0.0`. **The map is empty, so token-entropy anomaly detection has never fired for any model** — correct behaviour on uncalibrated data, and it means the doom-loop detector the corpus counts on currently runs one heuristic short across the whole fleet.

The notable part is that this is not a missing mechanism. The loader is wired (`routing.rs:429`), the consumer is wired (`zp-emission-coherence`), and the calibrator is written and points at both — its docstring names `DossierCorpus::entropy_baselines()` and the commit that wired it. **Nobody has run it.** A tool that must be remembered is a tool that goes unrun, which is the same finding as the pins in `.githooks/pre-commit`'s own rationale and the `just check` marker fixed on 2026-08-17. Stage 4 was written to make it a step rather than a chore. §10 records why that is not yet possible.

### 3.6 Host resource sensing is stranded, and size is discarded twice

`onboard/inference.rs:265` detects RAM, cores, chip, GPU and VRAM — the only VRAM sensing in the repo — and buckets a fit recommendation. **No code in `zp-regent` calls it.** It runs during onboarding, produces a recommendation, and is discarded before the router exists.

Separately, `/api/tags` returns a `size` per model and both call sites drop it (`evaluation.rs:1509-1518`, `onboard/detect.rs:200-212`). Nothing in the tree knows how large a model is on disk. `MODEL-DOSSIER-2026-07.md:88` specifies `deployment.footprint_gb_by_variant`; it does not exist in the Rust struct.

The consequence shows up in routing: the pressure penalty (`routing.rs:566-580`) is **flat per local candidate and does not scale with size**, despite its own comment reading "for large local models." Under Critical pressure a 1.7B and a 70B are penalized identically. Pressure can shift local→cloud; it can never shift large-local→small-local, because no size is in scope.

### 3.7 Two evidence defects inside the battery itself

Both matter because this battery is what would decide fitness.

- **`SubstrateKnowledge` is omitted from the category enumeration** (`evaluation.rs:678-689`). Six test cases run, count toward pass/fail totals, and never produce a `CategoryScore`. That dimension is invisible in output.
- **Collapse probes still ship unsubstituted prompt placeholders.** The 2026-08-06 incident comment at `evaluation.rs:236-269` records phi4-reasoning replying "there's contradictory instructions?" because `{substrate_ground_section}` reached the model as literal brace text, and concludes:

  > this battery is what decides whether a model is fit to serve as Regent. Measuring a model against a malformed prompt and recording the result in a dossier makes every suitability judgement downstream of it suspect.

  `default_battery` was fixed. `generate_collapse_test` (`evaluation.rs:1125-1127`) substitutes only two of the four placeholders, so **every collapse probe still exhibits the defect described immediately above it in the same file.**

### 3.8 The ceremony's receipt family is registered nowhere

`MODEL-DOSSIER-2026-07.md:206-230` declares `substrate:characterization:` with five actions. One has an emitter — `drift_suspected`, at `zp-inference-observer/src/lib.rs:107`. The four that constitute the admission ceremony (`proposed`, `validated`, `activated`, `superseded`) have none, and the family appears in neither `KNOWN_RECEIPT_PREFIXES` nor `RESERVED_RECEIPT_PREFIXES` (`zp-server/src/substrate_validate.rs`, comment at `:647` excludes it because it "has code"). `model:dossier:provisional:<model_id>` from `INFERENCE-ROUTING-DISCIPLINE:227` is likewise in neither list. `substrate:model:` *is* reserved (`:653`) and is the namespace this pipeline should claim.

## 4. What the corpus has already decided

This is the part that changes the shape of the work. Almost nothing below needs designing.

**`MODEL-DOSSIER-2026-07.md`** — the four-state lifecycle at `:128-138`: **candidate → validated → active → superseded**, with "consumers ignore candidate characterizations" and "validated dossiers are visible to the operator for ratification but not consumed by the dispatcher." The five-step bootstrap at `:194-204`: intake → evaluation → byte-identical parity → **ratification with operator Genesis signature** → consumer activation. And `:147`: *"Provisional dossiers do NOT auto-promote to full. Promotion is ceremony. Substrate accumulates evidence and surfaces it; the operator decides."*

**`INFERENCE-ROUTING-DISCIPLINE-2026-07.md` §"Novel model handling"** (`:201-248`) — three phases. Detection: no dossier entry → `regent:inference:novel_model_served:<model_id>`, response is *provisional cognition*, "accepted for the immediate operator interaction (not lost), but marked with reduced trust and quarantined from precedent-accumulation." Quarantine: evidence accumulates into `model:dossier:provisional:<model_id>`. Operator disposition: bootstrap / add-provisional / reject-and-quarantine / reject-provider. It states the frame at `:205`: *"The discipline treats novel model service as a substrate admission event."*

**And the part of `MODEL-DOSSIER` that reframes the end of the pipeline** (`:15`, `:95-121`, `:179`): a speculative-decoding drafter is not a separate artifact but **a second serialization of the same characterization** — "a lightweight parametric encoding of the target's behavior distribution… That is what a dossier is trying to be — evidence about how the target behaves — encoded as parameters rather than prose." Both forms share one lifecycle, one receipt family, one provenance chain. The consequence for this pipeline is at `:179`: **"If the drafter is a serialization of the dossier, then acceptance rate is the dossier's live drift signal."** So ratification is not the end state. An active declarative dossier can later be compiled to operational form, at which point drift detection stops being a periodic re-characterization and becomes continuous at token granularity. Nothing below builds that; it is the reason the pipeline should not assume characterization is a one-shot event.

**`SHADOW-MODEL-SWITCHING-2026-07.md`** — tiered admission depth already costed (`:69-91`): Tier 1 known/validated, one check, ~5-10s; Tier 2 known/untested, three checks, ~30s; Tier 3 unknown, five checks plus auto-dossier generation, up to ~2 min, *"because the substrate is about to hand its entire cognitive loop to something it has never characterized."* Operator force-cut bypasses all of it (`:148`).

**`HARDWARE-DOSSIER-2026-08.md`** — fit prediction as a pure function, and the capacity rule this pipeline must not violate: **capacity failure is a strong-sovereignty hard-block, `regent:routing:fit_denied`, never a silent downshift.** Entirely unimplemented; six reserved prefixes, zero emitters.

**`CLAUDE.md:360`** — the model-prompt coupling invariant: *"model identity and prompt variant are a single configuration unit… Neither change is valid alone."* And at `:362`, the admission gate hiding in a subordinate clause: *"validation failures block the model from being selectable."* Note `CONNECTION-INTEGRITY-PROGRAM-2026-07.md:40` records that the `prompts/{model_family}/` resolution this invariant assumes is **absent from the code**.

## 5. Where the request and the corpus disagree — and it is not a small gap

The operator asked for new models to be **"automatically picked up and processed… shaped to purpose, hardened."** The corpus says, in two places and in almost the same words:

> The substrate does not silently promote novel models to full-dossier status based on accumulated evidence alone. **Promotion is ceremony.** — `INFERENCE-ROUTING-DISCIPLINE:231`

> **Not automatic envelope adjustment.** Substrate does not autonomously add or remove models from envelope based on cost or capability signals. Envelope changes require operator ceremony. — `INFERENCE-ROUTING-DISCIPLINE:288-294`

These are reconcilable, and the reconciliation is the load-bearing design decision in this document: **automate everything up to ratification; never automate ratification.**

Discovery, fit prediction, battery execution, collapse probing, entropy calibration, dossier *drafting*, and evidence accumulation are all mechanical and all safely automatic — they produce a `candidate` dossier and receipts, and per `MODEL-DOSSIER:128-138` a candidate is by definition not consumed by the dispatcher. The single manual step is the operator signing the transition to `active`. That step is one command and a Genesis signature, and it is the only thing standing between "the substrate characterized a model overnight" and "the substrate started thinking with a model nobody approved."

**There is an uncomfortable fact here that argues the corpus is right.** The background sweep at `evaluation.rs:1598` **already runs today, automatically, on every model Ollama reports**, on a 300-second idle trigger, with no admission ceremony, no operator disposition, and no governing document covering it. It is the automation the operator is asking for, already shipped, ungoverned — and the reason nobody has noticed is that it throws its results away (§3.1). The moment the results start persisting, that sweep becomes an evidence-producing authority, and it should be governed before it is made useful, not after.

## 6. The pipeline

Six stages. Stages 1–5 are automatic; stage 6 is ceremony.

**Stage 1 — Notice.** Extend `discover_local_models` to retain the `size` field it already receives, and diff the result against the dossier corpus. A model present on disk with no dossier emits `substrate:model:discovered:<model_id>`. This is the event that does not exist today: nothing fires when weights land.

**Stage 2 — Fit.** Before spending minutes of inference on a model that cannot run, predict fit. `onboard/inference.rs:265` already measures RAM, VRAM and unified-memory; `/api/tags` now supplies size. Un-strand the sensor, compare, and on failure hard-block with `regent:routing:fit_denied` per `HARDWARE-DOSSIER` rather than discovering the problem by OOM. This is the cheapest useful step and it needs no new sensing.

**Stage 3 — Characterize.** Run the existing battery and collapse probes. Fix §3.7's two evidence defects first — a suitability judgement measured against a malformed prompt is worse than no judgement, by the file's own argument.

**Stage 4 — Calibrate.** Run `scripts/calibrate-h3-baseline.py --family <f> --model <id>` and write a real `[entropy_baseline]` with `state = "calibrated"`. The script already does the whole job; the stage is a scheduling decision, not an implementation. **Retracted — see §10.** This was called the cheapest stage on the grounds that the calibrator was written and merely unrun. It was run on 2026-08-18; the result is unwritable and the stage is blocked behind a protocol decision.

**Stage 5 — Draft.** Write `models/<family>/model_dossier.toml` in state `candidate`, with every measured field marked as measured rather than researched — `glm5`'s dossier already invented that provenance convention at `:9-11` and no other file uses it. This is the write path that has never existed. It must be additive: a hand-authored dossier's prose sections are not the generator's to overwrite, which argues for a `[measured]` table the tool owns exclusively.

**Stage 6 — Ratify.** Operator reviews and signs. `substrate:characterization:validated` then `:activated`. Only now does the dispatcher consume it. `zp model admit <id>` is the natural surface, and it should default to showing the evidence rather than to succeeding.

Underneath all six: **stage 0, load the corpus at runtime.** §3.3 makes stages 1–6 pointless on any non-build host, because the corpus they populate is never read.

## 7. The ruling I need

**Does stage 5 write to the source tree?**

The corpus does not answer this and the tie-off at `zp-server/src/regent.rs:2641-2658` explicitly declines to: *"where the dossier corpus should live at runtime is an architecture decision, not a substitution — the candidates (`zp_core::paths` data root, a config field, `ZP_SOURCE_DIR`) differ in how they behave across Substrate Forms, and Sovereign Form ships a built OS with no source tree at all."*

**There is a precedent, and it points at B.** The one existing writer — `calibrate-h3-baseline.py:336` — resolves `repo_root / "models" / family / "model_dossier.toml"` and writes the source tree. That is a hand-run script rather than a substrate decision, so it settles less than it looks, but any option other than B makes the existing calibrator wrong.

Three options:

**A — Data root, `zp_core::paths`.** Generated dossiers live beside the chain; `models/` in the tree becomes seed data copied on first run. Costs: two locations for one kind of fact, and the seeded copies drift. Benefit: works on Sovereign Form, works today, and closes §3.3 with the carrier the substrate already has.

**B — Source tree, with the tree treated as writable.** Generated dossiers land in `models/` and are committed. Costs: does not work at all on Sovereign Form; makes the substrate a committer to its own repository. Benefit: the dossier stays reviewable in git, which is where its prose sections belong.

**C — Split.** Prose stays in the tree and is authored; measurements go to the data root as `[measured]` overlay records keyed by model id, merged at load. Costs: a merge step and a schema. Benefit: the hand-authored and machine-measured halves stop competing for one file, which is the actual source of §3.4's drift.

**I would take C**, because §3.4 is evidence that hand-authoring and machine-consumption of one file already diverge silently, and C is the only option that stops them sharing a writer. But A is defensible as the cheaper path to closing the tie-off, and the tie-off's reopen condition — *"any attempt to run the server off a machine other than its build host"* — is met the moment anything here ships.

## 8. What I would do, and what I would not

I would ship in this order: **§3.3 (runtime corpus path), then §3.4 (parser strictness), then stage 2 (fit), then §3.1 (persist the evidence), then stages 3–5.** That order front-loads the fixes that make everything downstream observable, and it puts the two silent-degradation defects before the machinery that would rely on them.

I would fix §3.4 by **failing loudly on an unrecognized `suitability` value and an unrecognized `variants_*` key**, not by adding the missing spellings to the parser. A parser that accepts `variants_available` silently is how three of six dossiers came to have empty variants lists without anyone knowing.

I would **not** make the background sweep persist evidence before §5's governance question is answered. Today it is a harmless waste of idle cycles. The moment it writes, it is an unratified authority producing durable claims about model fitness, and that is a larger change than it looks.

I would **not** implement `HARDWARE-DOSSIER`'s full four-layer lookup to get stage 2. `zp-server/src/onboard/inference.rs` already measures enough for a fit hard-block, and the catalog layers can arrive later without changing the interface.

## 9. What would falsify this

- **The claim that dossier routing has never run in production is the tie-off's, not mine.** I did not observe an empty corpus at runtime. If ARTEMIS resolves `models/` some other way — a symlink, a deploy that copies the tree — §3.3 is wrong and stage 0 is unnecessary.
- **The sweep's ungoverned-automation claim depends on it actually firing.** It requires 300s idle, no active `ModelEvaluation` task, and non-Critical memory. I did not confirm it has ever completed on this host. If it has never run, §5's argument is theoretical.
- **Two falsifiers from the first draft were checked and one of them fired.** I claimed nothing had ever written a dossier; `calibrate-h3-baseline.py` does, and §3.2 now says so. The claim survived a full drafting pass and was caught only by working the falsification list, which is an argument for keeping §9 in documents of this kind rather than a flourish at the end of one. The second — whether `MODEL-DOSSIER` specifies where generated dossiers live — did not fire: it assumes `models/*/model_dossier.toml` (`:93`) without deciding the runtime question, so §7 stands.
- **I read `MODEL-DOSSIER-2026-07.md` selectively** — lifecycle, ceremony, receipt and serialization sections. Its drafter and bootstrap material is summarized second-hand via a subagent read and should be checked before implementation, not before ruling.
- **§10 was written after a calibration run, and it moved stage 4 from "cheapest" to "blocked."** The first version of this memo recommended running the calibrator tonight. That recommendation was wrong for a reason no amount of reading the calibrator would have revealed.
- **The pipeline assumes the battery measures what a suitability judgement needs.** It measures binary pass/fail and wall-clock latency, nothing distributional. `MODEL-DOSSIER:39-51` names suitability fields — `standing_correction_adherence`, `doom_loop_rate_per_1k_responses`, `model_prompt_coupling` — that the current battery does **not** measure at all. Stage 3 as described produces a weaker dossier than the schema asks for, and I have not costed the gap.

---

## 10. Stage 4 is blocked, and the block is a protocol decision — added 2026-08-18

Stage 4 was called the cheapest stage in §6 on the grounds that the calibrator was written, wired and merely unrun. It was run on 2026-08-18 against `qwen3:8b`, cleanly — 24/24 responses used, none dropped, 173.8s. **The result should not be written**, and the reason generalizes past H3.

### 10.1 What the run produced

```
mean surprise : 0.076095
std_dev       : 0.059422
```

H3 is a one-sided collapse test (`zp-emission-coherence/src/entropy.rs:34-35`):

```rust
let sigmas_below = (baseline.mean - mean_surprise) / baseline.std_dev;
if sigmas_below < SIGMA_MULTIPLIER { return None; }   // 2.0
```

Firing requires `observed ≤ 0.076095 − 2(0.059422) = −0.0427`. Mean surprise is `−log P(chosen)` and **cannot be negative**. The most extreme observable value — perfect confidence, surprise exactly 0 — sits at 1.28σ. **No response this model can emit trips the threshold.** Writing `state = "calibrated"` would move H3 from *off and honestly labelled* to *on, labelled calibrated, and structurally unable to fire*, which is strictly worse than the current state.

A one-sided 2σ-below test on a quantity floored at zero is reachable only when `mean/std_dev ≥ 2`. The global figure is **1.28**. The per-class figures the script prints and discards as *"informational — not stored yet"*:

| class | n | mean | σ | mean/σ | reachable |
|---|---|---|---|---|---|
| chat | 4 | 0.1240 | 0.0259 | 4.79 | yes |
| math | 4 | 0.0458 | 0.0129 | 3.55 | yes |
| code | 5 | 0.0324 | 0.0106 | 3.06 | yes |
| reasoning | 3 | 0.0793 | 0.0334 | 2.37 | yes |
| other | 5 | 0.1336 | 0.0851 | 1.57 | no |
| tool_dispatch | 3 | 0.0263 | 0.0176 | 1.49 | no |

The global baseline is a mixture of six distributions whose means span 5×. Between-class variance inflates σ until the threshold escapes the domain. **The script computed the evidence that its own output schema cannot represent.**

Note also `entropy.rs:62-65`: the unit test's fixture is `mean: 2.0, std_dev: 0.5` — ratio 4.0, comfortably reachable. The test passes and could never have surfaced this, because its fixture has a shape real calibration does not produce.

### 10.2 A second defect the first one was hiding

Calibration runs at `temperature = 0.0` (`calibrate-h3-baseline.py:87`), deliberately — line 31 argues non-zero temperatures "inflate surprise variance." Production serves at **0.1–0.3** (`regent.rs:1245, 1428, 1761, 1849`).

So even a well-conditioned baseline would describe a distribution H3 never observes. The script's reasoning is right about the mechanism and inverted about the goal: for a detector, that variance is not noise to be suppressed, it is the signal's scale. And calibrating a *collapse* detector on temperature-0 output measures a model already at the confident extreme — which is why the floor at zero swallowed the threshold. **The two defects share one cause.**

### 10.3 The gate nobody counted

None of the above matters yet, because H3 cannot fire in production for a nearer reason. `loop_runner.rs:2115` constructs the analyzer input with `log_probs: None`, and `:2093-2099` says so:

> `log_probs: None` — H3 silently skips regardless of baseline availability. Enable when the inference backend surfaces per-token log-probability.

The same construction sets `model: "unknown"` (`:2110`), so the baseline lookup keys on a name no dossier carries — a **fifth** gate, independent of the other four. H3's full chain:

| # | gate | state |
|---|---|---|
| 1 | production supplies log-probs | **closed** — hardcoded `None` |
| 2 | analyzer receives real model identity | **closed** — hardcoded `"unknown"` |
| 3 | dossier carries a calibrated baseline | closed — all six uncalibrated |
| 4 | `std_dev > 0` | would pass |
| 5 | threshold reachable | **closed** — 1.28σ against a 2.0σ test |

Running the calibrator opens gate 3 and leaves four closed. That is why stage 4 moved from cheapest to blocked.

### 10.4 Why gate 1 is a ruling and not a patch

The Regent's local inference speaks Ollama's **native** protocol — `chat_path: "/api/chat"` (`inference.rs:96`). Native `/api/chat` does not return per-token log-probabilities at all. The calibrator uses `/v1/chat/completions` precisely because, in its own words, that endpoint "supports `logprobs=true`"; its docstring further records that MLX raw exposes logprobs "through a different API; not supported here."

So opening gate 1 is not a field flip. It requires the Regent's own hot path to speak the OpenAI-compat protocol locally, and that decision has consequences already visible in the tree: `inference.rs:684` records that the ZP proxy's allowlist admits **only** `v1/chat/completions`, while `:187` records native `/api/chat` posts as a path the allowlist does not admit. The two protocols are already in tension and the discipline pin `no_raw_provider_http_outside_canonical_layer` sits on top of it.

Adding a `logprobs` field to `InferenceRequest` would touch 11 struct literals across 4 crates. That is mechanical. **Choosing which protocol the Regent speaks to its own local backend is not**, and it belongs with whoever owns `INFERENCE-ARCHITECTURE-CONSOLIDATION-2026-05`.

### 10.5 What I would do

**Do not run the calibrator to completion on any model** until gates 1 and 5 are decided. The dry-run output is the useful artifact and it is already in hand.

Order, revised:

1. **Rule on the protocol question** (§10.4). Everything about H3 waits on it.
2. **Fix gate 2 regardless** — threading served-model identity into the coherence hook is required by `INFERENCE-ROUTING-DISCIPLINE` Layer 1 independently of H3, and `loop_runner.rs:2106-2109` already names it as owed. It changes no behaviour today, which is the honest reason to do it as its own commit rather than folding it into a protocol migration.
3. **Recalibrate at serving temperature**, not 0.0, once log-probs exist. At 0.1–0.3 the spread may widen enough that `mean/σ ≥ 2` falls out and §10.1's per-class question dissolves.
4. **Only then** consider extending `[entropy_baseline]` to per-class figures — a change to a Tier-2-specified schema, and the least broken of the five gates.

### 10.6 The general finding, which outlives H3

Three times in this document a mechanism was found wired to a consumer that cannot use it: the battery's evidence into a formatted string (§3.1), the calibrator's per-class figures into a schema without a slot (§10.1), and the whole H3 chain into a hardcoded `None` (§10.3). In each case the measurement is correct, the plumbing exists, and the far end is closed.

**A pipeline built stage-by-stage will reproduce this.** The stages in §6 are each individually satisfying to build and each capable of terminating in a consumer that discards their output. The check that would catch it is the one this corpus already applies to receipts and now applies to state files: *before building a producer, name its consumer and confirm the consumer can represent what the producer emits.* Every defect in §3 and §10 is an instance of skipping that step.

### 10.7 The per-class table is the right analysis on data too thin to carry it — added 2026-08-19

Written after an independent re-run of the calibrator reproduced §10.1 exactly.
Two things follow that §10.1–§10.6 do not say, and one of them reorders §10.5.

**Re-running gains nothing, and that is worth knowing before someone tries.**
Calibration is fixed at `temperature = 0.0` (`calibrate-h3-baseline.py:87`), so
the decode is deterministic and a second run returns the same figures class for
class. Confirmed 2026-08-19 against `starter-24.jsonl` on `qwen3:8b`: mean
`0.076095`, σ `0.059422`, 24/24 responses used, 0 dropped, and a per-class table
identical to §10.1's. Variance here can be reduced by more prompts or a higher
temperature and by nothing else. On a result this surprising the natural instinct
is to run it again; that is the one action guaranteed to return no information.

**§10.1's per-class verdicts are three findings and three coin flips.** The
relative standard error of a sample standard deviation is approximately
`1/√(2(n−1))`. Set against the σ shift each class would need to cross
`mean/σ = 2`:

| class | n | mean/σ | σ shift to flip the verdict | σ RSE at this n | reading |
|---|---|---|---|---|---|
| chat | 4 | 4.79 | +139% | 41% | clear |
| math | 4 | 3.55 | +78% | 41% | clear |
| code | 5 | 3.06 | +53% | 35% | clear |
| reasoning | 3 | 2.37 | **+19%** | 50% | inside the noise |
| other | 5 | 1.57 | **−22%** | 35% | inside the noise |
| tool_dispatch | 3 | 1.49 | **−25%** | 50% | inside the noise |

For the bottom three, the shift that would reverse the verdict is smaller than
the uncertainty in the estimate producing it. `reasoning` reads as reachable and
would not be if its σ were 19% larger, which at n=3 sits well inside one standard
error. **"Four of six reachable" is more precisely "three reachable, three
undetermined."** The table in §10.1 is not wrong; it is being asked to carry more
than 24 prompts can hold.

**Which reorders §10.5 item 4.** Extending `[entropy_baseline]` to per-class
figures is described there as a schema change gated behind recalibration at
serving temperature. It is also a **corpus** change, and that half is independent
of gate 1. `starter-24.jsonl` holds 24 prompts across six classes — three to five
each — and is sized for one global baseline, not a six-way split. Per-class
calibration at ~15% σ error needs **n ≈ 23 per class, about 140 prompts**;
relaxing to 20% still needs ~13 per class, about 80. Growing the corpus requires
no log-probs, no protocol ruling and no schema decision, so it can run in parallel
with items 1–3 rather than behind them.

**A caveat on the caveat.** Those are normal-theory figures. Surprise is bounded
below at zero and right-skewed, so the true σ error at n=3 is more likely worse
than the table says, not better. The correction points the same way.

**And §10.1's note on `entropy.rs:62-65` generalises past H3.** A fixture of
`mean: 2.0, std_dev: 0.5` — ratio 4.0 — was chosen for legibility and thereby
encoded a distribution shape that real calibration does not produce, so the test
passed and could never have surfaced the defect. That is §10.6's finding with the
discard moved to the other end: not a producer whose consumer cannot represent
its output, but **a check that runs, passes, and is examining something other
than the thing it is named for.** Both are artifacts that exist, execute, and
answer a question nobody asked. Worth pairing with §10.6 when the general rule is
written down, because a producer-consumer check would not have caught this one —
the fixture *is* the consumer, and it represented the value fine.
