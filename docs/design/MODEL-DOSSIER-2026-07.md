# Model Dossier

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.5 (Genesis-derived signing over substrate claims), §II.17 (cognitive discipline sandwich — inference paths as substrate concerns, not opaque vendor concerns), §III.9 (delegation narrowing over model authority), §III.19 (detectability over invulnerability applied to inference-path drift), §III.22 (verify before commit — a served response's confidence gated against known dossier evidence), Part VIII (bounded operator sovereignty over which models the substrate uses), Part XIV.5 (Inference Sourcing). Specifies the substrate's canonical characterization primitive: a chain-anchored, operator-ratified artifact recording what the substrate knows about one target model's behavior on the substrate's own workloads. Establishes that the artifact has two coexisting serializations — a **declarative** form (prose+fields, human-readable, dispatch-facing) and an **operational** form (drafter weights, machine-executable, decoding-facing) — both derived from the same underlying evidence and governed by one lifecycle. Canonical claims live in KEEL.

Draft — 2026-07-26 — internal audience only. Consolidates the schema and lifecycle previously in `models/README.md` (retained as an operational README pointing here) and integrates the drafter-as-dossier equivalence into a single canonical spec. Composes with `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (the primary consumer at dispatch time), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 5 empirical program consumes dossier evidence; Phase 2 authorized dossier bootstrap), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (Context 1 shadow-evaluated unit is `(base_model, drafter)` per this spec), `SHADOW-INFERENCE-COMPARISON-2026-07.md` (comparison mechanism drives dossier drift detection), `SHADOW-MODEL-SWITCHING-2026-07.md` (switching ceremony extends to drafter switching under one discipline), `SOFTWARE-INTEGRITY-ATTESTATION-2026-07.md` (drafter checkpoint integrity is a first-class attestation surface), `OBSERVATION-PLANE-2026-07.md` (drafter acceptance-rate telemetry is a new observation class), `COGNITIVE-SELF-OBSERVER-2026-07.md` (dossier consistency is Class 1/2 ground-truth verification input), `CIRCUIT-BREAKER-2026-07.md` (dossier drift is a trigger class), `REGENT-DOOM-LOOP-DETECTION-2026-07.md` (`doom_loop_rate_per_1k_responses` is a dossier suitability field, split by drafter-active vs -inactive), `QUARANTINE-PLANE-2026-07.md` (novel-model admission consumes dossier bootstrap as chain-anchored evidence).

## Framing

The substrate does not accept vendor benchmarks as sufficient evidence that a model is fit for cognitive work. Benchmarks are provider-facing: they claim what the model does in the abstract, on someone else's workloads, under someone else's evaluation harness. What the substrate needs is **its own characterization** of a model's behavior on the substrate's own workloads, using the substrate's own probes, chain-anchored so the operator can ratify what evidence the substrate is relying on when it dispatches to that model. That characterization is the **dossier**.

Historically the substrate has treated dossier as a static artifact — a TOML file per model recording research (published quirks, architecture notes, community findings) alongside empirical measurements (bench results, prompt-compatibility results, adversarial-probe results). The Regent reads the dossier at dispatch time to know what to expect, and Cognitive Self-Observer reads it at verification time to know what "in-envelope" behavior looks like. That framing remains authoritative; this spec extends it in two directions.

**First**, it lifts the dossier from `models/README.md` (an operational README living beside the code) into a first-class Tier-2 discipline. Every doc that references "the dossier" now points at one canonical home rather than a shifting mix of README pointer, INFERENCE-ROUTING-DISCIPLINE fragments, and EAM Phase 5 back-references.

**Second**, it establishes that a **speculative-decoding drafter** (concretely DFlash, and any peer that trains a small model to predict the target's next tokens from the target's own emissions and hidden states) is a second serialization of the same underlying characterization. A drafter is a lightweight parametric encoding of the target's behavior distribution over the training corpus. That is what a dossier is trying to be — evidence about how the target behaves — encoded as parameters rather than prose. Both forms derive from the same evidence source; both stale together; both share one provenance chain. Splitting their governance into two disciplines duplicates work and hides the shared drift signal.

Three properties frame the primitive:

1. **Substrate-facing characterization, not vendor benchmark.** Dossier evidence is what the substrate observed of the target's behavior under substrate probes, not what the provider claimed. This is why the operator's signature is on the dossier, not the vendor's.
2. **Two serializations of one artifact class.** Declarative (prose+fields) and operational (drafter weights) are two encodings of the same underlying characterization. Same evidence, same lifecycle, same provenance chain, one receipt family. Consumers differ (dispatch-time reads the declarative form; decoding-time reads the operational form), but the artifact class is one.
3. **Ceremony-governed lifecycle, empirically maintained.** Adoption is chain-anchored operator ratification. Maintenance is continuous empirical measurement — periodic re-baselining for the declarative form, always-on acceptance-rate monitoring for the operational form. Drift detection triggers re-evaluation; automated policy changes do not.

## What a dossier is

For one target model at one version, a dossier records the substrate's characterization of that model's behavior. Structure spans identity, suitability, evidence, freshness, and — when an operational drafter has been trained — a drafter sub-record.

The Regent reads the dossier at dispatch time to know **what to test for**, runs the bench to get **empirical results**, and emits a `regent:config:inference` receipt with the full evidence. The operator signs the characterized pair (model + prompts). That signature is the sovereign act of accepting this characterization into the substrate's active envelope.

## The canonical schema

### Identity fields

- `model_id` — canonical identifier (vendor:family:variant, e.g., `alibaba:qwen:qwen3-8b`).
- `provider` — where the substrate reaches this model (local, cloud provider, routing intermediary).
- `version` — provider-declared version string; may be opaque or unstable when providers version silently.
- `weights_hash` — SHA-256 of the weights file(s) when weights are locally resident. Empty when using a hosted service.
- `fetched_at` — when the substrate first pulled and characterized this exact version.

### Suitability fields

Populated by the evaluation battery (per §Bootstrap ceremony below). Each field is chain-anchored evidence: not a claim, but a measurement with its evaluation receipt hash.

- `intent_classification` — competence at reading operator intent from context; measured against fixture prompts with graded difficulty.
- `sovereign_identity_adherence` — probe: does the model maintain the substrate-declared identity under prompt-injection attempts to overwrite it?
- `adversarial_resistance` — probe suite: instruction-conflict resolution, prompt injection, framing sensitivity, context degradation, compliance boundaries. See §Adversarial profiling for what each probe tests.
- `standing_correction_adherence` — rate at which the model respects active `cognitive:correction:standing` receipts over N test emissions.
- `doom_loop_rate_per_1k_responses` — measured rate of the failure modes catalogued in `REGENT-DOOM-LOOP-DETECTION-2026-07.md`. When a drafter is active, this field splits into `.drafter_active` and `.drafter_inactive` — they should be equal under the byte-identical claim, and any divergence is evidence that byte-identity has broken in practice.
- `think_suppression_profile` — per-model observation of which think-suppression mechanism actually works for this variant (see §Think-suppression profiling).
- `model_prompt_coupling` — result of the probe pair testing whether responses vary when the prompt structure changes in ways that shouldn't affect the semantic content. Model-prompt coupling is diagnostic signal; the atomic (model, prompt) pair invariant per SHADOW-MODEL-SWITCHING traces to this measurement.
- `per_workload_scores` — breakdown by workload class (chat, math, code, reasoning, tool-dispatch, other). Drafters are per-workload-class fit-varying; the dispatcher may want to route different workload classes to different (base, drafter) pairs.

### Evidence fields

- `evaluation_receipts` — array of chain receipt hashes, one per evaluation run that produced a suitability score. Every suitability field has at least one receipt backing it; a field with empty evidence is treated as `unknown`, not zero.
- `research_notes` — free-form prose recording published quirks, architecture notes, community findings, known deployment constraints. Not evidence in the chain-anchored sense; context for the operator ratifying the dossier.
- `bootstrap_ceremony_receipt` — the receipt that ratified this dossier into `active` state.

### Freshness fields

- `last_evaluated_at` — most-recent evaluation timestamp.
- `last_re_baselined_at` — most-recent complete re-run of the evaluation battery.
- `drift_suspected_flag` — set when the substrate has emitted a `substrate:characterization:drift_suspected` receipt against this dossier; carries the receipt hash for the triggering evidence.
- `drift_suspected_reason` — free-form annotation of why (acceptance-rate drop, outcome divergence, provider version bump, operator observation).

### Drafter sub-record (operational serialization)

When an operational drafter has been trained for this target, the dossier carries a drafter sub-record:

- `drafter.id` — canonical identifier for this drafter (e.g., `dflash:qwen3-8b:2026-07`).
- `drafter.architecture` — DFlash / EAGLE-3 / MTP / DSpark / other. The specific speculative-decoding family.
- `drafter.checkpoint_hash` — SHA-256 of the drafter weights.
- `drafter.checkpoint_license` — may differ from base-model license (e.g., MIT drafter weights against Apache-licensed base).
- `drafter.training_corpus_hash` — hash of the corpus the drafter was teacher-forced against.
- `drafter.training_run_receipt` — chain receipt for the training run (who, when, on what target-version, with what hyperparameters).
- `drafter.trained_at` — timestamp of the trained drafter.
- `drafter.state` — `candidate | validated | active | shelved | superseded`.
- `drafter.acceptance_rate_window` — most-recent rolling-window mean acceptance rate (see §Continuous drift signal).
- `drafter.acceptance_rate_by_workload` — breakdown by workload class; drafters are workload-fit-varying.
- `drafter.acceptance_rate_by_position` — position-wise decay curve (position 0 acceptance vs position 7 acceptance); characterizes how far ahead the drafter can reliably guess.
- `drafter.byte_identical_parity_receipt` — chain receipt for the shadow-eval acceleration-ablation run that established byte-identity on this substrate's actual workloads. Required for `state: active`.

Both serializations of the same characterization are carried in one dossier record. A dossier may have no drafter sub-record (declarative-only characterization); a dossier with a drafter sub-record is a characterization that has been compiled to operational form.

## Two serializations, one artifact

### Where they meet

The declarative and operational forms of a dossier are two encodings of one underlying claim: "this target model behaves this way on this substrate's workloads." Both derive from the target's actual emissions on representative prompts. Both go stale when the target changes. Both are auditable — the declarative form by reading, the operational form by measurement. Both carry the operator's Genesis signature at activation.

Field-level correspondence:

| Declarative field | Operational (drafter) equivalent |
|---|---|
| `identity.model_id + version` | `drafter.target_model_id + version` |
| `suitability.doom_loop_rate_per_1k_responses` | `drafter.acceptance_rate_window` (real-time fitness) |
| `evidence.evaluation_receipts` | `drafter.training_run_receipt + training_corpus_hash` |
| `freshness.last_re_baselined_at` | `drafter.trained_at` |
| `freshness.drift_suspected_flag` | acceptance-rate drop below per-dossier threshold |
| `suitability.per_workload_scores` | `drafter.acceptance_rate_by_workload` |

### Where they differ (precisely)

Two axes of legitimate difference:

- **Auditing surface.** Declarative form is auditable by reading; operational form is auditable by measurement. Different inspection modalities, same underlying claim.
- **Consumption seat.** Declarative form is consumed at dispatch (which model to call) and verification (does this response fit what we know about this model). Operational form is consumed at decoding (which tokens to propose). Different points in the inference lifecycle, one shared characterization.

Two axes that are **not** legitimate differences (this spec collapses them):

- **Governance discipline.** Both serializations share one candidate → validated → active → superseded lifecycle. Same ceremony family, same receipt schemas.
- **Provenance chain.** Both share one chain of "who characterized this target, on what evidence, when, with what operator ratification." Not two parallel chains.

### Non-drafter acceleration

Acceleration methods that don't learn from the target's own behavior — quantization, KV-cache compression, batched inference, prompt caching — are **not** covered by this spec. They are separate concerns because they aren't characterizations of the target. Speculative-decoding drafters specifically are the subclass where the acceleration mechanism IS a learned representation of the target; that is the equivalence claim's scope.

## Lifecycle

Four states, one lifecycle across both serializations:

**Candidate.** New characterization proposed; not yet in operation. For a declarative dossier: research notes populated, initial identity fields set, no evaluation battery run yet. For a drafter: checkpoint hash recorded, training run receipt in chain, no byte-identical parity run yet. Consumers ignore candidate characterizations.

**Validated.** Evidence accumulated but not yet operator-ratified. For a declarative dossier: evaluation battery run, suitability fields populated with receipt backing, adversarial probes complete, `bootstrap_ceremony_receipt` not yet set. For a drafter: byte-identical parity receipt established on a fixed-seed corpus (N ≥ 200 representative prompts recommended), acceptance rate profiled. Validated dossiers are visible to the operator for ratification but not consumed by the dispatcher.

**Active.** Operator-ratified, in operation. For a declarative dossier: `bootstrap_ceremony_receipt` set with operator Genesis signature; dispatcher reads this dossier when routing to this target. For a drafter: operator ratification receipt set; decoder invokes this drafter when running this target. Active characterizations feed all their consumer surfaces.

**Superseded.** Replaced by a newer characterization of the same target. Both serializations may be superseded independently — a new drafter version may supersede the drafter sub-record while the declarative dossier remains active — but both are governed by the same supersession pattern. Superseded characterizations remain in chain (never deleted); consumers filter them out at read time.

### Provisional vs full characterization

Per INFERENCE-ROUTING-DISCIPLINE Phase 2 (novel-model handling), a dossier can enter `active` state under two ceremony paths:

- **Full**: operator authorizes bootstrap ceremony, substrate runs the complete evaluation battery, dossier promoted to active with full evidence backing.
- **Provisional**: operator has independent knowledge of the model and admits it with a reduced-trust posture. Dossier active with fewer suitability fields; consumers (dispatch, verification) treat provisional dossiers with degraded confidence. Substrate continues to accumulate evidence in the background; provisional-to-full promotion is a subsequent operator ceremony.

Provisional dossiers do NOT auto-promote to full. Promotion is ceremony. Substrate accumulates evidence and surfaces it; the operator decides.

## Adversarial profiling

The evaluation battery includes adversarial probes that go beyond capability testing. Adversarial probes test how the model behaves under adversarial conditions the substrate's actual runtime will subject it to. Failures are characterized in `suitability.adversarial_resistance` and recorded in `research_notes`; they are **not blocking** — the dossier captures WHERE the model breaks so the substrate can deploy it within its safe envelope.

Five probe classes:

- **Instruction conflict resolution.** Multiple instructions in the context conflict with each other. Does the model pick one coherently, blend incoherently, or ask? Characterizes handling of the substrate's tiered cognitive input (identity > standing corrections > operator directive per COGNITIVE-INPUT-PLANE).
- **Prompt injection resistance.** Adversarial content in operator-supplied text attempts to override the substrate's declared identity or standing corrections. Does the model resist, comply, or attempt but fail? Characterizes what class of injection attempts must be quarantine-plane-filtered before reaching this model vs which can be trusted to it directly.
- **Framing sensitivity.** Same semantic content phrased differently (formal vs casual, authoritative vs deferential, structured vs prose). Does response quality vary with framing when semantic content is stable? High framing sensitivity is a dispatch-time constraint.
- **Context degradation.** Repeated long context with mixed relevance. Does the model attend to the load-bearing signal or drift toward recency-biased hallucination? Characterizes context-window fitness for cognitive work vs shallow generation.
- **Compliance boundaries.** Requests near the model's refusal boundaries, phrased in substrate-realistic ways. Does the model refuse coherently, refuse incoherently (with confabulation), comply where it shouldn't, or comply appropriately? Characterizes what the model's safety-training will and won't do inside substrate work.

A model that passes polite tests but fails adversarial ones has known deployment constraints. The dossier captures those constraints so the substrate can deploy within envelope rather than encountering them at runtime.

## Think-suppression profiling

The evaluation battery probes three think-suppression mechanisms per model:

1. **`think: false`** — Ollama API option, portable across families.
2. **`think` omitted** — don't send the parameter at all.
3. **`/no_think` token** — model-specific token in the user message (qwen3 family).

Different variants of the same family may respond to different mechanisms. The evaluation report's `think_suppression_profile` captures which mechanisms are effective per variant; the dossier's suitability record incorporates the findings. The inference layer uses the dossier to select the right mechanism rather than assuming `think: false` works universally.

Model behavior differences around think suppression are diagnostic signal, not noise. The inference layer logs leaked think tags at warn level but does NOT strip them — the leak tells the substrate the suppression mechanism isn't working for that variant, which feeds back into dossier revision.

## Continuous drift signal (drafter-active mode)

The declarative form's drift detection is **periodic audit**: re-run the evaluation battery on some cadence, compare to baseline, emit `drift_suspected` if the delta crosses threshold. That is expensive and coarse — evaluations run at cadences of hours or days; drift can accumulate silently between runs.

Speculative decoding provides a continuous, cheap, always-on drift signal at token granularity. DFlash's confidence head measures, on every proposed token, whether the drafter's prediction matched the target's verification. Aggregate over a rolling window and the substrate has a live measurement of drafter-target fit. **If the drafter is a serialization of the dossier, then acceptance rate is the dossier's live drift signal.**

Concretely, OBSERVATION-PLANE gets a new observation class:

- `observation:inference:drafter_acceptance` — emitted per rolling window (default: every 1000 tokens). Fields: `target_model_id`, `drafter_id`, `window_start`, `window_end`, `mean_acceptance_rate`, `position_wise_acceptance_curve`, `workload_class_breakdown`.

When the mean acceptance rate drops below a threshold declared per `(target, drafter, workload_class)` on the dossier itself, automatic emission of `substrate:characterization:drift_suspected` follows. The drift signal is dossier-declared per-target, not global.

Two consequences:

- **Dossier drift becomes detectable in near-real-time.** If a provider silently swaps the underlying model behind a stable name (INFERENCE-ROUTING-DISCIPLINE's silent-version-drift failure mode), the drafter — trained against the previous behavior — shows acceptance-rate collapse within a small number of tokens. This is the substrate's fastest available drift-detection surface.
- **Dossier maintenance becomes empirical rather than scheduled.** Instead of re-running the full evaluation battery on a cadence, the substrate re-runs it when the acceptance-rate signal warrants it. Cheap steady-state, targeted response to drift signals.

Composition: sustained acceptance-rate collapse for a target Regent is actively dispatching to is a specific failure signature that escalates per CIRCUIT-BREAKER's operator-declared policy. And the acceptance-rate signal tells SHADOW-EVALUATION-PRIMITIVE Context 1 *when* to run a candidate-vs-control comparison, rather than running on a fixed cadence regardless of need.

## Bootstrap ceremony

Bringing a new target-model dossier from `candidate` to `active` follows a five-step flow (specialized from QUARANTINE-PLANE's admission discipline):

1. **Intake.** Operator ceremony authorizes the substrate to characterize this target. `substrate:characterization:proposed` receipt emitted with identity fields and any prior research.
2. **Evaluation.** Substrate runs the full battery — intent classification, sovereign identity, adversarial resistance suite, think-suppression profile, model-prompt coupling probes, per-workload capability samples. If a drafter is also being brought up, the training run happens in this phase; `training_run_receipt` chain-anchored.
3. **Byte-identical parity (drafters only).** For a drafter, shadow-eval acceleration-ablation run: N ≥ 200 fixed-seed prompts, drafter-active vs drafter-inactive, byte-identity as pass criterion. `byte_identical_parity_receipt` chain-anchored.
4. **Ratification.** Operator reviews accumulated evidence and either accepts (dossier → active) or rejects (dossier → superseded/withdrawn). Operator Genesis signature on `bootstrap_ceremony_receipt`.
5. **Consumer activation.** Dispatcher, verifier, and (if drafter) decoder begin reading the newly-active dossier from the next dispatch. OBSERVATION-PLANE begins acceptance-rate emission if drafter is active.

Rejection returns the dossier to `superseded` (never `active`). The chain of evidence remains; the operator's rejection is itself chain-anchored ceremony evidence for why this dossier didn't make it.

## Unified receipt schema

The receipt family for both serializations collapses to one:

```
receipt_type: substrate:characterization:<action>
target: { model_id, version, weights_hash }
characterization_form: "declarative" | "drafter" | "both"
serialization_ref: { hash, storage_url }
evidence: { corpus_hash, evaluation_receipts: [<hash>, ...] }
provenance: { produced_by, produced_at, training_run_receipt? }
lifecycle_state: "candidate" | "validated" | "active" | "superseded"
supersedes: [<prior_characterization_id>] | null
operator_signature: <genesis_signature>
```

Actions:

- `substrate:characterization:proposed` — new characterization offered.
- `substrate:characterization:validated` — evidence complete; awaiting operator ratification.
- `substrate:characterization:activated` — operator ratifies; consumers begin reading.
- `substrate:characterization:drift_suspected` — automatic emission when a running characterization shows staleness (acceptance-rate drop for drafters; outcome divergence for declarative-only).
- `substrate:characterization:superseded` — replaced by a newer characterization of the same target.

The `characterization_form` discriminator lets consumers filter — the dispatcher wants `declarative | both`; the decoder wants `drafter | both`; the coherence-audit surface consumes both. The Regent's specific `regent:config:inference` receipt continues to exist as the sovereign-signature seat for prompt-model activation; it composes with the `substrate:characterization:activated` receipt above rather than replacing it.

## Shadow evaluation with (base, drafter) pairs

SHADOW-EVALUATION-PRIMITIVE Context 1 (inference paths) frames the shadow-evaluated unit as *the model*. Under this spec the unit extends to *(base_model, drafter)* pairs.

- **Candidate**: `(target_model, drafter_v_new)` or `(target_model_new, drafter_new)` or `(target_model, no_drafter)`.
- **Control**: `(target_model, drafter_v_current)` or `(target_model_current, drafter_current)`.
- **Input**: the operator's or Regent's actual query.
- **Evidence**: response comparison at graduated levels (structural / embedding / judge / operator) — same as base Context 1. Additional signals: acceptance-rate delta, byte-identical parity check, latency delta.
- **Consumer**: INFERENCE-ROUTING-DISCIPLINE, this spec, EXECUTION-AUTHORITY-MODEL Phase 5.

Two shadow scenarios newly enabled:

- **Drafter-only drift shadow**: same base, current drafter vs candidate replacement drafter. Isolates drafter fitness from base-model drift. Necessary when re-training a drafter after a base minor-version bump.
- **Acceleration ablation shadow**: same base, drafter-active vs drafter-inactive. Establishes the byte-identical parity claim empirically on the substrate's actual workloads at drafter adoption time and periodically thereafter.

## Consumers

- **INFERENCE-ROUTING-DISCIPLINE** — reads active declarative dossiers at dispatch time. Classifier weights routing decisions by dossier evidence per model. When a served response's identity doesn't match a dossier in the envelope, novel-model handling (Phase 2) engages.
- **COGNITIVE-SELF-OBSERVER** — reads active declarative dossiers at verification time. Class 1 (chain-state claims) and Class 2 (diagnosis claims) cross-reference dossier evidence when verifying substrate-state claims. When served-model identity is inconsistent with any known dossier, observer confidence degrades and semantic verification against standing corrections carries the check.
- **CIRCUIT-BREAKER** — dossier drift is a trigger class. Sustained `substrate:characterization:drift_suspected` for a dispatched target escalates per operator-declared policy.
- **REGENT-DOOM-LOOP-DETECTION** — the dossier's `doom_loop_rate_per_1k_responses` field is where this doc's rate measurements land. Under drafter-active mode, the field splits into `.drafter_active` and `.drafter_inactive`; divergence between them is evidence that byte-identity has broken in practice on this substrate.
- **EXECUTION-AUTHORITY-MODEL Phase 5** — the empirical program consumes dossier evidence for continuous evaluation and empirical dossier maintenance.
- **QUARANTINE-PLANE** — novel-model admission (five-step flow) consumes dossier bootstrap ceremony (this spec's §Bootstrap) as the chain-anchored evidence for the admission decision.
- **SHADOW-EVALUATION-PRIMITIVE Context 1 / SHADOW-INFERENCE-COMPARISON** — dossier evidence is the ground truth against which candidate models are compared. Shadow-eval outcomes feed back into dossier suitability fields.
- **SHADOW-MODEL-SWITCHING** — the switching protocol extends to drafter switching under one discipline. A drafter is a serialization of the same characterization; switching it follows the same ceremony.
- **SOFTWARE-INTEGRITY-ATTESTATION** — drafter checkpoints are a first-class attestation surface. Checkpoint hash + training-provenance hash + license attestation attested via the ceremony that already covers dossier evidence.
- **OBSERVATION-PLANE** — new observation class `observation:inference:drafter_acceptance` per §Continuous drift signal above.

## Non-goals

- **Not a replacement for vendor benchmarks.** Vendor benchmarks are context, sometimes populated in `research_notes`. They are not evidence. The dossier's suitability fields are evidence, backed by substrate-run evaluation receipts.
- **Not vendor-specific for drafters.** DFlash is the current best-in-class exemplar; the spec applies to any speculative-decoding drafter (EAGLE-3, MTP, DSpark, future variants). The unifying property is "drafter learned from target's emissions" — not "DFlash specifically."
- **Not automated characterization.** Substrate accumulates evidence; operator ratifies. Provisional-to-full promotion is ceremony. Drafter activation is ceremony. Drift-suspected emission is automated; response to it is operator-directed.
- **Not a claim that all acceleration is characterization.** Quantization, KV-cache compression, batched inference, prompt caching are acceleration methods that don't derive from the target's own behavior; they are separate concerns.
- **Not a dossier per prompt template.** The dossier is per-(target-model, target-version). The prompt-template pair (model-prompt coupling) is measured in the dossier but not the dossier's identity. SHADOW-MODEL-SWITCHING handles the atomic (model, prompt) pair invariant at switching time.

## Immediate design work

1. **Migrate `models/README.md` content into this spec.** The 6-step lifecycle in the README (Research → Bench → Prompt testing → Adversarial profiling → Tier recommendation → Chain validation) is absorbed into §Bootstrap ceremony above. The schema is absorbed into §The canonical schema. `models/README.md` shrinks to an operational pointer.
2. **Add `drafter` sub-record to the `model_dossier.toml` schema** in `models/` per §The canonical schema § Drafter sub-record.
3. **Wire `observation:inference:drafter_acceptance` emission** in the substrate's decoder path when a drafter is active. Include position-wise acceptance curve at rollup boundaries.
4. **Wire `substrate:characterization:drift_suspected` emission** from OBSERVATION-PLANE when the rolling window crosses a per-`(target, drafter, workload_class)` threshold on the dossier.
5. **Extend SHADOW-EVALUATION-PRIMITIVE Context 1** consumer contract to accept `(base, drafter)` as the shadow-evaluated unit and to accept `acceleration_ablation` as a new shadow scenario.
6. **Formalize the drafter adoption ceremony** as a specialization of the bootstrap ceremony above: (a) candidate emission with checkpoint + provenance, (b) shadow-eval acceleration ablation with byte-identical parity attestation on N ≥ 200 prompts, (c) operator ratification per SHADOW-MODEL-SWITCHING, (d) OBSERVATION-PLANE begins acceptance-rate emission on activation.
7. **Formalize the drafter deprecation ceremony** on drift confirmation: (a) drift_suspected accumulates per operator threshold, (b) shadow-eval re-run against candidate replacement drafter, (c) operator ratifies replacement per SHADOW-MODEL-SWITCHING, (d) old drafter superseded via the unified receipt.

## Framing note

The substrate has been treating characterization (dossier prose+fields) and acceleration (drafter weights) as orthogonal concerns. They are not: a drafter is a learned representation of the target's behavior distribution, which is what a dossier is trying to be, encoded as parameters instead of prose. Collapsing them under one discipline gives the substrate a continuous drift signal for the price of the acceleration it was going to enable anyway, and it removes a duplicate governance surface before it hardens.

The corollary is that substrate readiness to adopt speculative-decoding acceleration — DFlash today, its successors tomorrow — is not gated by acceleration-specific governance work. It is gated by the characterization discipline the substrate has been maturing since the earliest dossier README. Wire the acceptance-rate signal into OBSERVATION-PLANE, extend SHADOW-EVALUATION-PRIMITIVE Context 1 to `(base, drafter)` pairs, and drafter adoption falls out as a specific instance of the discipline already in place.
