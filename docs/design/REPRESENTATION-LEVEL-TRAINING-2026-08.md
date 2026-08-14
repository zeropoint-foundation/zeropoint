# Representation-Level Training as Sovereignty Dependency — Opportunity Mapping

**Document type:** Design intent / opportunity mapping. Not a Tier 2 canonical elaboration — no KEEL claim elaboration — an outside-in framing that shapes how substrate primitives compose with a class of model-training method the substrate does not currently attend to.

**Date:** 2026-08-12.

**Source:** Ken Romero, mapping the representation-level training literature (RepE, ReFT/LoReFT, Circuit Breakers, concept bottlenecks) and its associated geometry-of-reasoning empirical results (REMA, Reasoning-Flow, Platonic Representation Hypothesis) onto ZeroPoint's adapter ceremony, training-signal reuse, and cognitive-compute posture.

**Occasion:** A Sophontic (Julian D. Michels) interview claiming "geometric reasoning" — training a model's internal geometry rather than its behavior — with claimed 60× to 1000× reasoning advantage at sub-7B scale. Investigation established that the described mechanism is largely published prior art and that Sophontic's specific claims are entirely unwitnessed. The *claim* does not survive; the *framing* names a real substrate dependency the corpus had not attended to. This document carries the framing and registers the claim for verification rather than adoption.

**Attribution:** The prior art is the cited authors'. The substrate composition is Ken's synthesis. Sophontic's contribution is the occasion, not the content; see §"Witnessed and asserted" for why that distinction is load-bearing here rather than merely polite.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form. The prose below elaborates the declaration.

- **`lens_id`**: `representation_level_training`
- **`focus`**: how training whose objective is defined on *internal representations* rather than output behavior composes with substrate adapter ceremony, chain-anchored training-signal reuse, model-dossier characterization, and the cognitive-compute baseline — and what evidence discipline applies to capability claims made in this class
- **`dimensions`**: representation-space objectives, target typology (direction vs subspace vs operator), adapter artifact parameterization, compositional installation and capability retention, held-out transfer, continual adaptation vs frozen weights, local trainability, evaluation integrity under perturbation, benchmark contamination, claimant-controlled evaluation, witnessed-vs-asserted claim status, prior-art placement, training-target provenance and sovereignty, cognitive-compute baseline
- **`keyword_composition`**: [representation engineering, RepE, ReFT, LoReFT, steering vector, activation steering, concept bottleneck, circuit breaker, representation rerouting, latent space, latent reasoning, internal geometry, manifold, intrinsic dimension, probe, sparse autoencoder, adapter, LoRA, X-LoRA, fine-tune, reasoning operator, compositional installation, catastrophic forgetting, continual learning, frozen weights, perturbation eval, counterfactual eval, flip rate, contamination, held-out set, small model, parameter count, orders of magnitude]
- **`transformation_question`**: *"if a reasoning operation can be installed into representations rather than scaled into them, what becomes a signed, composable, operator-dispositioned artifact — and what would have to be witnessed before the substrate trusts the claim?"*
- **`cross_references`**: `REGENT-ADAPTER-WORKFLOW-2026-07.md`, `SUBSTRATE-SLM-TRAINING-ENVIRONMENT-2026-07.md`, `SHADOW-EVALUATION-PRIMITIVE-2026-07.md`, `MODEL-DOSSIER-2026-07.md`, `LOCAL-MODEL-SELECTION-2026-07.md`, `SUBSTRATE-COMPUTE-BASELINE-2026-07.md`, `INFERENCE-ROUTING-DISCIPLINE-2026-07.md`, `AI-LANDSCAPE-SIGNAL-2026-07.md`, `COGNITIVE-ACT-ACCOUNTING-2026-07.md`, `COGNITIVE-SELF-OBSERVER-2026-07.md`, `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 5), `EMPIRICAL-PROGRAM-2026-07.md`, `KEEL-2026-07.md` §II.13, §III.22

When chain-anchored as a `lens:declared:representation_level_training` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:representation_level_training:<invocation_id>` receipt. Silent-representation-level-training-lens over a long observer window is a signal that adapter, model-selection, and training-signal decisions are being made as if behavioral fine-tuning were the only available shape — the exact drift this framing was declared to prevent. Directional: outside-in (external ML-methods literature → substrate composition).

### Composition and conflict edges

- **`lens:composed:representation_level_training:ai_landscape`** — shares [SLM, LoRA, model tier, capability, open weights, evaluation, frontier model]. The landscape lens asks whether a direction survives provider disruption; this lens asks what the substrate can install locally regardless of provider.
- **`lens:composed:representation_level_training:slm_training_environment`** — shares [RL, reward, fine-tune, LoRA, model eval, adversarial pairs, training signal, base model]. Strongest composition; see §"Where this actually bites" item 2.
- **`lens:composed:representation_level_training:cognitive_primitives`** — shares [reasoning operation, cognitive operation, frequency band]. The cognitive-primitives lens enumerates discrete cognitive operations and asks which have no substrate surface; this lens asks whether such an operation can be *installed* into a model rather than only observed.
- **Candidate conflict, unverified — `cognitive_system_approximation`.** If that document's claim is that substrate cognition is approximated at the *system* level (officers, chain, ontology, input plane) rather than the model-internal level, a lens asserting reasoning operations are installable into representations may make a contradictory claim about where cognition is sited. **Not declared as `lens:conflicts:*` pending a read of that document.** Declaring an unverified conflict edge would be the same error this document exists to name.

---

## Framing

The substrate's model posture, as currently specified, has one training shape in it: behavioral fine-tuning, parameterized as a LoRA adapter, authorized by a two-phase `FineTuningAuthorization` ceremony, shipped as safetensors plus provenance manifest plus Ed25519 envelope (`REGENT-ADAPTER-WORKFLOW-2026-07.md`), evaluated candidate-vs-control on APOLLO (`LOCAL-MODEL-SELECTION-2026-07.md`).

There is a second shape, and the corpus does not currently name it. It has been an active subfield since 2020 and a well-instrumented one since 2023: **training whose loss is defined on internal activations rather than on output tokens.**

| Method | What the loss is defined on |
|---|---|
| Concept Bottleneck Models (Koh et al., ICML 2020) | Supervised loss at an intermediate layer constrained to be an explicit concept vector |
| Representation Engineering / LoRRA (Zou, Phan et al., 2023) | Weight updates against a representation-space objective |
| Circuit Breakers / Representation Rerouting (Zou, Phan et al., NeurIPS 2024) | `ReLU(cos_sim(rep_M(x), rep_M_cb(x)))` — cosine similarity on hidden states, rerouting representations into an orthogonal subspace, with no output-level supervision on the target branch |
| ReFT / LoReFT (Wu et al., NeurIPS 2024) | Frozen weights; learned interventions on hidden representations in a low-rank subspace at specified layers and token positions |
| Weight-sparse transformers (OpenAI, 2025) | Training objective shapes circuit geometry directly |

And the premise these rest on is a replicated public empirical result, not a proprietary one: reasoning has a measurable geometric signature. REMA establishes that correct reasoning concentrates on a low-intrinsic-dimension manifold, with SVM separation of correct-vs-error representations above 90% in mid-to-late layers and ρ=0.598 between accuracy and deviation magnitude. *The Geometry of Reasoning* (ICLR 2026) models reasoning as embedding trajectories with position, velocity, and curvature. The Platonic Representation Hypothesis covers cross-model convergence toward shared statistical geometry.

The substrate should attend to this class because three of its existing specs are shaped by an assumption this class violates — that the only lever on a local model is what it emits.

---

## Where this actually bites

### 1. The adapter artifact already has the right shape

`REGENT-ADAPTER-WORKFLOW-2026-07.md` specifies `LoRAAdapter` as safetensors + provenance manifest + Ed25519 signature envelope, with load/hot-swap primitives and a two-phase authorization ceremony. LoReFT-style interventions are parameterized almost identically — low-rank, layer-and-position scoped, frozen base weights. **They fit the existing artifact format, the existing signing envelope, the existing hot-swap primitive, and the existing shadow-eval-on-APOLLO path, with no ceremony redesign.**

What changes is the *manifest*. A behavioral adapter's provenance manifest describes training data and reward. A representation-level adapter's manifest must additionally describe: which layers and token positions were intervened on, what the target geometry was, and *which model was measured to derive that target*. That last field is load-bearing — if the target geometry was measured from a frontier model, the artifact is representation distillation from that model, and the sovereignty and licensing posture is materially different from a locally-derived target. An adapter manifest that cannot express this cannot express what the adapter is.

**Action:** extend `LoRAAdapter`'s provenance manifest with an optional `representation_target` block (layers, positions, target typology, source model identity and its dossier hash). Absence of the block means behavioral; presence means representation-level and triggers the source-model provenance check.

### 2. The substrate's training signal currently has no consumer of this shape

`SUBSTRATE-SLM-TRAINING-ENVIRONMENT-2026-07.md` names the substrate's central novel affordance: verifiable rewards emerge as a side effect of chain-anchored ceremony rather than requiring synthetic environment construction. Its enumerated reward classes — gate compliance, delegation narrowing, chain integrity, precedent consistency, standing-correction obedience, aligned-blindness compliance, emission coherence — are all framed as *rewards*, i.e. scalar signals for RL over behavior.

But the chain does not only record whether an outcome was correct. It records *witnessed reasoning traces* — a Decision object with its pros/cons and confidence, a precedent citation, a standing correction applied, a confabulation gap detected by the Cognitive Self-Observer. Those are paired positive and negative instances of specific reasoning operations, with provenance, at whatever density the substrate is operating.

That is exactly the input a representation-level method needs and an RL reward is a lossy compression of. **The substrate's chain is better suited to deriving representation targets than to deriving scalar rewards, and the corpus currently specifies only the latter.**

Concretely: `regent:standing_correction:*` receipts paired with the emissions that violated them are a contrastive pair set for the operation "apply the standing correction." Confabulation gaps detected post-emission are labeled negatives for "assert only what is witnessed." Neither requires a judge model or a human labeler — the substrate already witnessed the label.

**Action:** add a representation-target extraction path to the SLM training environment's affordance analysis, alongside the reward-class enumeration. Same corpus, different derived artifact.

### 3. Correction to the compute framing

An earlier framing of this dependency held that a working representation-level method would lower the local-inference floor and free Pi 5 Sovereign Form from rally.

**That framing is wrong and is corrected here.** `SUBSTRATE-COMPUTE-BASELINE-2026-07.md` (2026-07-25) already resolved this: APOLLO-tier is the assumed cognitive-compute baseline, Pi 5 is sovereignty anchor and rally origin, and rally is the *intended* architecture under KEEL Part XIV's two-axis decoupling — not a workaround pending better models. Reading a capability advance as "now the Pi can do it locally" reproduces exactly the category error that document was written to stop.

The correct framing: representation-level training does not move the sovereignty floor. It changes **what an APOLLO-tier node can do to a model it already holds** — install operations, retain them across composition, adapt continually — versus only routing between frozen tiers. The dependency is on `REGENT-ADAPTER-WORKFLOW` and `SUBSTRATE-SLM-TRAINING-ENVIRONMENT`, not on `SUBSTRATE-FORM`.

---

## The open technical question

Existing representation-level methods target **directions** — static concept vectors for harmfulness, honesty, refusal, a class label. The framing that occasioned this document describes something the literature does not obviously cover: targeting **operators** — the geometric signature of a discrete inference operation, installed as a parametric primitive, then *composed*, where operation *n+1* trains into geometry already shaped by operations *1..n*.

A direction is a point or axis in the representation space. An operator is a map on it. That distinction is real and was not found under that description in the surveyed literature. Closest adjacent prior art, flagged as unsearched: neural algorithmic reasoning (Veličković et al.) and looped / algorithm-executing transformers.

Four things would have to hold for it to be a genuine advance rather than a re-description:

1. A specified loss whose target is a **transformation between representation states**, not a direction in the space.
2. **Retention** — installing operation B does not degrade operation A. Show the curve.
3. **Composition** — A∘B works without being jointly trained.
4. **Held-out transfer** — the installed operation generalizes beyond the domain the target geometry was measured from.

Absent all four, the claim is a reframing of ReFT with different vocabulary. This is the question worth tracking; the ratio claim is not.

---

## Witnessed and asserted

Applying `COGNITIVE-ACT-ACCOUNTING-2026-07.md` §3's split to the occasioning claim, because the substrate should hold external capability claims to the standard it holds its own actors to.

**Witnessed** — verifiable from public artifacts as of 2026-08-12:

- sophontic.ai exists. Founded 2026, Delaware C-corp. Claims a "compact reasoning prototype" exceeding "models up to 60× its size," measured by flip rate under a paired-item perturbation protocol. Prototype and eval kit both marked "releasing soon."
- Julian D. Michels is real. PhD in consciousness psychology and philosophy, California Institute of Integral Studies, 2023. ~53 PhilPeople entries, all philosophy / consciousness studies / cybernetics.
- "Rule by Technocratic Mind Control: AI Alignment is a Global Psy-Op" is real — PhilArchive, 20 Oct 2025. Political philosophy, not ML.

**Asserted only** — founder self-report, no public artifact:

- That a model exists.
- Any parameter count (sub-7B, ~3B).
- The 60× figure, and the interview's stronger 100–1000×. **No benchmark, no baseline model, and no score is named anywhere on the site or in the interview.**
- That a training method exists which "internalizes the math into the core operations."
- That the method is distinct from representation-level training at other labs. This specific assertion is **contradicted** by Circuit Breakers, RepE/LoRRA, and ReFT, all of which define training losses on internal geometry.

**Absent entirely:** papers, preprints, arXiv entries, code, released weights, technical blog posts, independent replication, third-party evaluation, or any collaborator with a public ML track record.

Two further findings bear on evaluation posture:

- The "perturbation paradigm" is a rebranding of counterfactual / minimal-pair evaluation — GSM-Symbolic (Apple), GSM1k (Scale), PlanBench / Mystery Blocksworld, Wu et al.'s counterfactual tasks. It is good practice and it is four years old. Its entire epistemic value derives from *who holds the held-out set*, and here the claimant holds their own.
- The base rate for this exact shape — dramatic ratio, unreleased artifact, claimant-controlled evaluation — is Reflection 70B (Sept 2024), which collapsed under independent evaluation.

Per the staged heuristic *an assertion never becomes evidence*: none of the asserted items may be promoted by corroboration, restatement, or the framing's usefulness. They are promoted by the eval kit and weights shipping, or not at all.

---

## Shadow-evaluation registration

Per operator disposition, Sophontic is registered as a shadow-evaluation candidate under `SHADOW-EVALUATION-PRIMITIVE-2026-07.md`, Phase A pre-declaration, **with the trigger condition unmet**. No compute is spent until the artifact exists.

- **Surface:** local reasoning model selection (Context 1 — inference paths).
- **Candidate identity:** Sophontic compact reasoning prototype, pending release.
- **Comparison target (control):** the then-current APOLLO resident tier per `LOCAL-MODEL-SELECTION-2026-07.md`.
- **Trigger condition:** public release of *both* weights and eval kit. Eval kit alone is insufficient — a benchmark from the claimant, run by the claimant, on a model nobody else holds, is not evidence.
- **Comparison protocol:** substrate-authored perturbation set, not Sophontic's. Held out. Paired base-and-perturbed accuracy reported as a pair, never flip rate alone — flip rate is degenerate when base accuracy is low. Plus a general-capability battery, to detect a narrowly reasoning-tuned model.
- **Disposition mode:** evaluate-only. Never-substitute without a full `MODEL-DOSSIER-2026-07.md` characterization pass.
- **Cost budget:** zero until trigger. One bounded evaluation window on trigger.
- **Evaluation window:** opens on trigger; sample-count-based.

Receipt on declaration: `substrate:shadow_evaluation:candidate_declared:inference_path:sophontic_prototype`.

If the trigger never fires, the candidate expires unevaluated and that outcome is itself chain-anchored — silence recorded rather than inferred, per §III.19.

---

## Non-goals

- **Not endorsing Sophontic's claim.** The claim is registered for verification, explicitly at asserted status. This document's framing survives Sophontic being wrong, because the framing rests on the cited literature, not on them.
- **Not adopting a training method.** No substrate change is authorized here. The two actions named in §"Where this actually bites" are a manifest field and an affordance-analysis extension, both additive and both independent of any specific method.
- **Not amending KEEL.** Nothing here touches Layer A or Layer B. §III.22 (evidence-based ceremony) already governs the disposition path; this document composes with it rather than extending it.
- **Not treating the interview's metaphysics as substrate content.** The implicate-order / mathematics-of-consciousness material in the source is philosophy. It is not load-bearing for anything above and is not carried into the corpus.
- **Not claiming the operator-vs-direction distinction is novel.** It was not found in a single-pass survey. Neural algorithmic reasoning is flagged as unsearched adjacent prior art, and the distinction should be re-checked against it before anyone builds on it.

---

## What composes from here

**Immediate:**

1. Chain-anchor `lens:declared:representation_level_training` with the schema above, plus the three `lens:composed:*` edges.
2. Read `COGNITIVE-SYSTEM-APPROXIMATION-2026-07.md` and resolve the candidate conflict edge — declare `lens:conflicts:*` or drop it. Do not leave it latent.
3. Add the optional `representation_target` block to `REGENT-ADAPTER-WORKFLOW-2026-07.md`'s adapter provenance manifest.
4. Register the shadow-evaluation candidate with the trigger condition as specified.

**Near-term:**

1. Extend `SUBSTRATE-SLM-TRAINING-ENVIRONMENT-2026-07.md` with a representation-target extraction path alongside the reward-class enumeration. Start from standing-correction violation pairs — the substrate already produces them with witnessed labels.
2. Search neural algorithmic reasoning and looped-transformer literature against the operator-vs-direction question, and record the result whichever way it lands.
3. Add contamination and held-out-set custody as explicit fields in `MODEL-DOSSIER-2026-07.md`, if not already present. The perturbation-eval finding generalizes past Sophontic: any dossier that records a benchmark score without recording who held the test set has recorded an assertion.

**Longer:**

1. If the operator-installation question resolves affirmatively anywhere in the literature, revisit whether the substrate's own reasoning operations — precedent check, delegation narrowing, confabulation-gap detection — are candidates for installation rather than prompting. That would be a substantial change to the cognitive-input-plane posture and is deliberately out of scope here.

---

## Framing note

The occasion for this document was a claim that does not survive scrutiny, delivered with metaphysics the substrate has no use for, on a publication surface with no replication pressure. It would have been easy to discard the whole thing on those grounds, and slightly easier still to accept it on the strength of its politics, which happen to align closely with the substrate's own.

Both moves are the same error: letting the claimant's credibility stand in for the claim's evidence. The discipline that separates them is the witnessed/asserted split, applied outward rather than only to the substrate's own actors. What survived that split is a real dependency — the corpus specifies exactly one training shape, and there is a second one with a decade of literature behind it that the adapter ceremony already has the artifact format for.

That finding did not require Sophontic to be right. It only required someone to check.
