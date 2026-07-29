# Substrate as SLM Training Environment

**Document type:** Tier 2 canonical elaboration — speculative framing.
**Elaborates:** KEEL §II.5 (sovereign identity), §II.13 (design principles as verifiable claims), §II.17 (cognitive discipline sandwich), §III.19 (detectability), §III.22 (evidence-based ceremony), §III.25 (autonomic coordination), Part V (composition contract).
**Date:** 2026-07-18. Motivated by the observation — surfaced during SLM analysis (Liquid AI LFM 2/2.5, Maxime Labonne) — that ZP's substrate discipline is uniquely positioned as an agentic RL training environment because verifiable rewards emerge naturally from substrate ceremony rather than requiring synthetic environment construction.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Speculative framing. Implementation is timeline-gated on the existence of real adopter chains (~12–24 months out). This document captures the framing NOW so today's chain-anchoring, receipt-schema, and discipline choices are informed by eventual training-signal reuse. The substrate does not become a training platform tomorrow; it becomes one when there's enough chain-anchored operator behavior to train against.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form. The affordance analysis below elaborates the declaration.

- **`lens_id`**: `slm_training_environment`
- **`focus`**: how training signal (verifiable rewards, per-task datasets, adversarial pairs, eval batteries) is produced as a *side effect* of chain-anchored substrate discipline — reframing the substrate's operational trace as an RL dataset with structured rewards baked in
- **`dimensions`**: verifiable reward density, reward class enumeration (gate compliance, delegation narrowing, chain integrity, precedent consistency, standing-correction obedience, aligned-blindness compliance, emission coherence, receipt-schema conformance), per-task-class training subset extraction, adversarial-training pair generation, reward-density scaling with substrate maturity, sovereignty of training data, base-model provenance, shadow-eval-as-training-eval overlap, prerequisites bootstrap ordering, chain-anchored consent for training-corpus inclusion
- **`keyword_composition`**: [RL, reward, dataset, fine-tune, agentic training, verifiable rewards, model eval, SLM, LoRA, base model, chain-anchored evidence, precedent, standing correction, gate compliance, delegation narrowing, adversarial training, hardening, doom-loop corpus, receipt schema, training signal, RLHF, RLAIF, evaluation battery, per-task subset, reward hacking, sovereignty consent, aligned blindness]
- **`transformation_question`**: *"if the substrate's operational discipline is already producing chain-anchored verifiable signals, what training capability emerges naturally without additional synthetic-environment construction?"*
- **`cross_references`**: `KEEL-2026-07.md` §II.5, §II.13, §II.17, §III.19, §III.22, §III.25, Part V (composition contract), `SUBSTRATE-HARDENING-CEREMONY-2026-07.md`, `REGENT-DOOM-LOOP-DETECTION-2026-07.md`, `SHADOW-EVALUATION-PRIMITIVE-2026-07.md`, `MODEL-DOSSIER-2026-07.md`, `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 5 empirical program), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md`, `AI-LANDSCAPE-SIGNAL-2026-07.md`, `COGNITIVE-SELF-OBSERVER-2026-07.md`, `INFERENCE-ROUTING-DISCIPLINE-2026-07.md`, `EMPIRICAL-PROGRAM-2026-07.md`

When chain-anchored as a `lens:declared:slm_training_environment` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:slm_training_environment:<invocation_id>` receipt. Silent-slm-training-environment-lens over a long observer window is a signal that today's chain-anchoring/receipt-schema/discipline choices are being made without attending to eventual training-signal reuse — the exact drift this framing was declared to prevent. Directional: outside-in (external RL/SLM training-context research → substrate composition), *speculative* (implementation timeline-gated on adopter-chain scale).

Nominated CLAUDE.md heuristic per document body: *A substrate that produces its own truth also produces its own training signal.* (Not yet promoted to canonical heuristic list; see corpus index for status.)

---

## Part I — The novel affordance this names

Most SLM projects that want to do agentic RL are bottlenecked by one specific problem: **defining verifiable rewards is expensive.** You need either narrow verifiable domains (math with checkable answers, tool calls with structured outputs) or judge models (evaluate rollouts with a larger model, transitive-trust the judge) or human labelers (slow, expensive, biased). All three cap what you can efficiently optimize for.

ZP's substrate is different by construction. **The substrate itself defines what "correct behavior" means, structurally, per the Layer A invariants and Layer B axioms.** Every chain-anchored ceremony is a verifiable signal about whether the substrate produced correct behavior:

- Gate compliance (did the action route through authorized delegation?) — verifiable via chain query.
- Delegation narrowing preservation (does the emitted action's capability envelope fit inside its parent delegation?) — verifiable via chain query.
- Chain integrity nonviolation (does the emission compose with hash linkage and signature verification?) — verifiable via Steward.
- Precedent-consistent action (is this remediation consistent with prior operator-signed precedent?) — verifiable via chain query for prior `regent:remediation:*` receipts.
- Standing-correction obedience (does the emission avoid patterns explicitly forbidden by operator-signed corrections?) — verifiable via Cognitive Self-Observer.
- Aligned-blindness compliance (does the emission avoid observing or emitting blind-class data?) — verifiable via SUBSTRATE-BLINDNESS-HEURISTICS enforcement.
- Emission coherence (is the response free of doom-loop signatures?) — verifiable per REGENT-DOOM-LOOP-DETECTION.
- Receipt-schema conformance (does the emission's structured content match its declared receipt type?) — verifiable via schema check.

These are not synthetic rewards. They emerge from the substrate's own discipline, applied to the same emissions the substrate is already producing during normal operation. **The substrate's operational trace IS an RL dataset with structured verifiable rewards baked in.**

This is a load-bearing observation. Not every SLM project has access to this affordance. Most don't. It's a direct consequence of the substrate's chain-anchored, ceremony-driven, discipline-first architecture — the same properties that make the substrate trustable at operational time make it trainable at development time.

---

## Part II — What this enables that generic agentic RL doesn't

**Fine-tuning without synthetic environment construction.** No need to build a simulator that approximates operator behavior; the substrate's own operational chain IS the environment. Every real cycle produces training-worthy evidence.

**Reward density scales with substrate maturity.** As the substrate accumulates precedent, standing corrections, and structured findings, the density of verifiable-reward signals per training example increases. A fresh substrate produces sparse-reward training data; a mature substrate produces dense-reward training data. Model quality improves as substrate matures — the reverse of the usual "reward hacking" concern where rewards get gamed.

**Per-task-class training targets.** Chain-anchored evidence is structured — every receipt has type, context, actor, gate result. Filtering the corpus by task class produces per-task-class training subsets. Fine-tuning can target specific weak areas revealed by the doom-loop detection corpus without needing to hand-curate data.

**Adversarial-training via existing hardening ceremony.** SUBSTRATE-HARDENING-CEREMONY-2026-07.md already produces adversarial pen-test evidence. Those adversarial rollouts + the substrate's discipline-based rejection responses become adversarial training pairs (unsafe action → refusal → gate response) at zero incremental cost.

**Shadow evaluation IS training-time evaluation.** SHADOW-EVALUATION-PRIMITIVE-2026-07.md's chain-anchored candidate-vs-control comparison directly extends to training-time A/B testing. Candidate model runs in shadow against production model on real operator input; both produce chain-anchored evidence; convergence, divergence, and violation rates are training signal.

**Substrate-specific eval battery IS the substrate's operational metrics.** External benchmarks (GPQA, BFCL, IF-Bench) don't measure what actually matters for Regent operation. Substrate-anchored measurements (invariant compliance rate, gate-refusal accuracy, delegation-preservation rate, precedent-citation accuracy, standing-correction obedience) do. These are already being produced by the substrate's own discipline for operational monitoring; the same measurements serve as evaluation criteria.

---

## Part III — Training data shape

The affordance is real only if the chain evidence is structured for training reuse. This section names what today's substrate emissions should include so tomorrow's fine-tuning is tractable.

**Every emission includes structured context.** Not just "what did the Regent output" but "what was the input, what were the active corrections, what was the applicable precedent, what did the officers report, what was the delegation scope." The COGNITIVE-INPUT-PLANE-2026-07.md matrix already provides this; the training use case is served by ensuring the composed input receipt (`cognitive:input:composed`) is preserved alongside the intent emission for every cycle.

**Every emission has a verifiable reward computable from chain state.** Given the emission and the chain state at the time of emission, the substrate should be able to compute — without additional annotation — whether the emission was:
- Gate-compliant (did the intent's capability match active delegation?)
- Precedent-consistent (did the remediation match prior operator-approved precedent?)
- Standing-correction-obedient (did the response avoid forbidden patterns?)
- Emission-coherent (did the response avoid doom-loop signatures?)
- Aligned-blindness-compliant (did the response avoid blind-class data?)

Each verifiable-reward field is boolean or scored. A single emission produces a vector of reward signals, not one aggregate.

**Every emission's follow-through is chain-observable.** Did the operator ratify the emission via signature? Was the emission superseded by a later cycle? Did the emission's action produce a downstream chain state consistent with prediction? These become long-horizon reward signals — not just "was this response OK" but "did this response lead to good substrate outcomes."

**Every rejection/refusal is preserved.** Not just successes. When the gate denies an intent, when a doom-loop detection escalates, when a claim verifier rejects — these are training signals about what NOT to emit. Same shape as DPO's rejected examples. The substrate's own refusal corpus becomes preference-alignment training data.

---

## Part IV — Bootstrap timeline

The training environment isn't usable at day zero. Enumeration of prerequisites and their gating:

**Prerequisite 1 — Chain data at meaningful scale.** Fine-tuning needs thousands to tens of thousands of examples per task class. A solo-operator substrate produces maybe hundreds of cycles per week; getting to 10K examples per task class takes months to years. **Adopter-chain composition** — chain evidence from multiple sovereigns aggregated with operator consent per SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md's coordination-not-oversight discipline — accelerates this. Not surveillance; kinship-scoped voluntary contribution. Adopter with 100 operators, 1 year of operation = many millions of cycles.

**Prerequisite 2 — Receipt schema stability.** Training against a schema that changes underneath you produces useless models. The receipt schema stabilization pass (KEEL Part VI canonicalization ceremony applied to receipt shapes) needs to happen before the training corpus is fixed. Estimated: 6-12 months of substrate operation to identify and freeze schemas.

**Prerequisite 3 — Doom-loop and drift detection catalog populated.** The corpus of `regent:emission:doom_loop_confirmed`, `regent:confabulation_gap:*`, `discipline:violated:*` receipts becomes the negative-example corpus for preference alignment. This corpus is populated only by real operation; can't be synthesized. Gates: substrate must be running with instrumentation active for enough cycles to accumulate meaningful adversarial-quality signal.

**Prerequisite 4 — Base model selection.** Fine-tuning targets a specific base model. Base model must be open-source with inspectable training pipeline (per sovereignty concerns — see Part V). Current candidates as of 2026-07-18: qwen3 family, LFM2 (if open-sourced), BitNet variants, Gemma 3 variants. Base model choice is itself an operator-signed decision with implications for downstream substrate behavior.

**Prerequisite 5 — Training infrastructure.** Fine-tuning open-source SLMs is a Titan V-scale problem, not a data-center problem. A single high-end workstation or cloud-rented GPU cluster for hours-to-days is sufficient. This is achievable at ThinkStream-scale funding without frontier-lab infrastructure. Not a serious gate.

**Prerequisite 6 — Chain-anchored training ceremony.** Training itself is a chain-anchorable event. The trained model's provenance (base model, training corpus receipt range, hyperparameters, output verification) is chain-anchored via `substrate:model:trained` receipt. This IS the substrate's own ceremony applied to its own capability construction. Composes with SUBSTRATE-SELF-CONSTRUCTION-2026-07.md.

Estimated timeline to first usable substrate-specific fine-tune: 12–24 months from the date of the first substantial adopter chain landing.

---

## Part V — Sovereignty implications

Training on chain-anchored operator interactions has real sovereignty implications that this framing must name.

**Consent is chain-anchored.** No operator's chain evidence contributes to training data without explicit chain-anchored consent (`training:corpus:consented`). Consent is scope-declared: contribution to a specific training run, not blanket-authorization. Revocation is possible per act-on-precedent; revoked evidence is not used in subsequent training runs but past training-derived models retain their weights (chain is truth; the past training happened; forward-only recovery per KEEL §III.20).

**Aligned blindness applies to training as strictly as to observation.** No blind-class data reaches the training corpus. Per SUBSTRATE-BLINDNESS-HEURISTICS, credential values, intimate content, dependent-communication content, medical diagnoses, mental-health state, protected-class information — none appear in training data. Substrate's own discipline about what it should not observe extends to what it should not learn from.

**Coordination-not-oversight applies.** No categorical review of operator cognitive patterns for training purposes. Contribution is per-emission-scoped: "these specific chain receipts, matching these declared task classes, may be used." Not "all my chain evidence."

**Federated substrate concerns.** If multiple substrates contribute to a joint training corpus, the cross-substrate coordination goes through kinship + peer-trust-anchor mechanisms already spec'd. No third-party training aggregator with unilateral access to substrate chains.

**Base-model provenance.** The base model's own training corpus provenance matters. Fine-tuning on top of a base model whose weights derive from unattested data inherits that unattested-ness. Base model selection per Prerequisite 4 explicitly considers this. Open-source with inspectable training pipeline (BitNet, LFM if open, or academic-provenance models) is the sovereignty-consistent floor.

**Trained model as substrate ontology object.** A trained model produced via substrate ceremony becomes a first-class ontology object with its own provenance receipt chain, capability declarations, and admission ceremony (composes with QUARANTINE-PLANE for admission of the trained model into Regent tier). Same shape as extension admission.

---

## Part VI — What today's substrate should do differently

Concrete implications for choices being made today that affect eventual training viability:

**Preserve full input context in emission receipts.** Not just the intent. The composed cognitive-input receipt, the applicable precedent citations, the officer findings that motivated the cycle. Data that seems verbose today is training signal tomorrow.

**Chain-anchor rejections and refusals as first-class events.** Not just log-and-continue. When the gate denies, when doom-loop detection escalates, when standing corrections are violated — these become training examples. Silent rejections are silent training gaps.

**Preserve structured heuristic evidence.** The specific heuristic evidence in doom-loop detection receipts, the specific field-level claim in confabulation-gap receipts, the specific delegation-narrowing check that fired in gate receipts. Structured evidence enables per-heuristic training signal.

**Version receipt schemas explicitly.** Every emission's receipt should cite its schema version. Later training runs can filter by schema version to ensure homogeneity within a training corpus. Amending a schema without a version bump destroys training-corpus consistency.

**Chain-anchor task-class taxonomy.** The `task_class` field used by INFERENCE-ROUTING-DISCIPLINE's precedent bright-line, by REGENT-DOOM-LOOP-DETECTION's `known_doom_loop_triggers`, and by this document's per-task-class training subsets, needs a shared canonical taxonomy. Not per-verb, not free-text — a bounded set of task-class identifiers versioned per SUPERSESSION-FRAMEWORK.

**Discipline pin:** any code path that produces cognitively-interesting output (intent emission, response synthesis, remediation action, refusal) must chain-anchor structured context. Fire-and-forget output paths that don't leave chain evidence are structurally forbidden. Same shape as `no_silent_degradation` per SUBSTRATE-READINESS-CONTRACT, applied to cognitive emissions.

---

## Part VII — Verifiable outcomes

Testable claims that must hold when this discipline is realized:

**Claim TE1:** for any chain range covering N cycles, a training corpus can be extracted with N examples, each having:
- Full cognitive input context
- Emitted response
- Vector of verifiable rewards computed from chain state at emission time
- Downstream chain state showing whether the response was ratified or superseded

**Claim TE2:** a fine-tune run against corpus C produces a chain-anchored provenance receipt citing: base model, corpus receipt range, hyperparameters, training environment, output verification.

**Claim TE3:** admitting a substrate-specific fine-tune into Regent tier goes through the same composition-matrix verification as any other model per SUBSTRATE-BOOT-INVARIANT-CEREMONY. No special "substrate-produced" bypass.

**Claim TE4:** aligned blindness holds through the training pipeline — no blind-class data reaches training, verifiable via corpus extraction dry-run + blindness-heuristic check.

**Claim TE5:** revoked consent removes evidence from subsequent training runs; verifiable via chain query for `training:corpus:consent:revoked` receipts filtering the corpus.

**Claim TE6:** substrate-specific fine-tune measurably outperforms base model on substrate-anchored eval battery (invariant compliance, gate refusal accuracy, precedent citation, standing correction obedience, doom-loop resistance) for the substrate context. Verifiable via SHADOW-EVALUATION-PRIMITIVE candidate-vs-control comparison.

**Claim TE7:** the training-environment discipline is chain-anchorable — corpus definitions, training runs, model releases all flow through SUPERSESSION-FRAMEWORK for versioning.

---

## Part VIII — What this document does NOT decide

- **Which base model.** Prerequisite 4 names candidates; final selection is an operator ceremony informed by dossier evidence available at the time.
- **Training environment (workstation, cloud, rally).** Prerequisite 5 says any of these are viable; operator choice per CLOUDMANDATE composition when cloud is used.
- **When fine-tuning becomes worth doing.** Answer is "when adopter chain is large enough and stable enough" — not further defined. Prerequisite 1 is the gate.
- **Multi-sovereign training data federation protocol.** Named as a concern in Part V but the specific mechanism is a separate spec (composes with SOVEREIGN-KINSHIP and PEER-TRUST-ANCHOR).
- **Reward weighting.** The vector of verifiable rewards (gate compliance, doom-loop coherence, etc.) needs weights; those are per-training-run choices, not spec'd here.
- **Continual training vs. periodic retraining.** Whether the substrate's Regent tier retrains continuously from live chain or periodically from snapshots is an implementation choice; both are compatible with this framing.

---

## Part IX — Follow-up work

**Immediate (informs today's choices):**
- Emission receipt schema pass — ensure full cognitive input context, structured heuristic evidence, task_class taxonomy are preserved.
- Rejection/refusal chain-anchoring discipline pin — no silent fire-and-forget output paths.
- Task-class taxonomy specification and versioning.

**Near-term (once substrate ships to first non-ThinkStream operator):**
- Chain-anchored consent primitive (`training:corpus:consented`, `training:corpus:consent:revoked` receipt schemas).
- Corpus extraction tooling (`zp training corpus extract --receipt-range ... --consented-only`).

**Longer-term (gated on adopter-chain scale):**
- Base model selection ceremony.
- First fine-tune training run with chain-anchored provenance.
- Shadow evaluation of fine-tune vs. base model.
- Fine-tune admission ceremony into Regent tier per SUBSTRATE-BOOT-INVARIANT-CEREMONY.

**Deferred (multi-substrate scale):**
- Federated training corpus protocol.
- Cross-substrate training reward propagation.
- Substrate-specific model marketplace under commons discipline.

---

## Composes with / connects to

- **REGENT-DOOM-LOOP-DETECTION-2026-07.md** — the confirmed-doom-loop corpus IS training-signal for preference-alignment negative examples.
- **MODEL-DOSSIER-2026-07.md** — the dossier's evidence-backed suitability fields (doom-loop rate, entropy baseline, task-class triggers, adversarial-resistance breakdown) become eval-battery targets for substrate-specific fine-tunes. EXECUTION-AUTHORITY-MODEL Phase 5 is the empirical program that operates on those fields.
- **INFERENCE-ROUTING-DISCIPLINE-2026-07.md** — the precedent bright-line's chain evidence about which task classes route to which tier IS training data for the classifier itself.
- **SHADOW-EVALUATION-PRIMITIVE-2026-07.md** — candidate-vs-control comparison extends directly to fine-tune-vs-base comparison.
- **SUBSTRATE-HARDENING-CEREMONY-2026-07.md** — adversarial pen-test evidence becomes adversarial training pairs.
- **SUBSTRATE-BOOT-INVARIANT-CEREMONY-2026-07.md** — trained models go through composition-matrix verification.
- **SOVEREIGN-KINSHIP-PRIMITIVES-2026-07.md** — cross-sovereign training corpus composition via coordination-not-oversight discipline.
- **SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md** — aligned blindness applies to training data as strictly as to observation.
- **COGNITIVE-INPUT-PLANE-2026-07.md** — the composed input matrix IS the training input context.
- **SUBSTRATE-SELF-CONSTRUCTION-2026-07.md** — training itself is substrate self-construction (Regent's cognitive capability construction under operator authorization).
- **SUPERSESSION-FRAMEWORK-2026-07.md** — training corpus definitions, base model selections, trained-model releases are versioned via ceremony.
- **QUARANTINE-PLANE-2026-07.md** — trained-model admission into Regent tier goes through the standard admission ceremony.
- **CLAUDE.md workflow heuristics: *Chain is truth; ontology is understanding* — training corpus IS chain projection into training-signal understanding.*
- **CLAUDE.md workflow heuristics: *A tool is intent, crystallized* — a trained model is intent crystallized in weights; provenance receipt makes the crystallization chain-visible.*

## CLAUDE.md workflow heuristics this exercises

- *Silence is the enemy, not compromise.* — refusals and rejections must chain-anchor to be training-visible.
- *Verify before commit.* — trained models go through composition-matrix verification before Regent-tier admission.
- *Substrate operational state is chain-anchored evidence, not inferred silence.* — training data derives from chain evidence, not from inferred substrate state.
- *A model and its prompts are an atomic pair.* — fine-tuned models require prompt-corpus recharacterization; training a new model without updated prompts is half-state.
- *Coordination, not oversight. Alignment incentivized, not surveilled.* — multi-sovereign training corpus follows kinship discipline, not surveillance.
- *Aligned blindness is a moral property of the substrate.* — extends to training; blind classes stay blind.

## Proposed new heuristic (nomination for CLAUDE.md)

**A substrate that produces its own truth also produces its own training signal.**

*The properties that make a substrate trustable at operational time — chain-anchored evidence, ceremony-declared discipline, verifiable-reward emergence from structural invariants — are the same properties that make it trainable at development time. Fine-tuning a substrate-specific model does not require synthetic environments, judge models, or human labelers; the substrate's own operational trace, filtered by consent and blindness discipline, IS the training corpus. The substrate improves itself by projecting its own chain into training signal, then admitting the resulting model via the same ceremony discipline that governs any other capability admission.*

*The corollary: today's choices about what to chain-anchor, at what granularity, with what structured context, are choices about tomorrow's training viability. Instrumentation before remediation applies here too — chain-anchor the emission with full context before you know exactly how the corpus will be used.*

*Applies at every substrate that has both operational discipline and chain-anchoring — which is every substrate under KEEL. The affordance is not vendor-specific; it's substrate-architecture-specific.*
