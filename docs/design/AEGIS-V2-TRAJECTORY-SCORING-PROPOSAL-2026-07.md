# Aegis v2 — Trajectory Scoring Proposal

**Document type:** Design proposal. Elaborates `KEEL-2026-07.md` §II.13 P9 (the system acts; the operator signs), Part V (composition contract), and extends `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` §VI.1 (Aegis's canonical role). Proposes Aegis's v2 scope extension from officer-cadre-cadence monitoring (v1, landed 2026-07-24) to trajectory-scope anomaly scoring using chain-anchored primitives.

**Author:** Ken Romero (2026-07-25). Synthesis assistance from Claude.

**Status:** Proposal — not yet a canonical elaboration. Landed here to name the design space, prerequisites, and non-conflations before implementation begins. Promotion to Tier 2 canonical happens once prerequisites (Cartographer, tabular classifier, initial labeled corpus) are in place and the composition is empirically evaluated.

---

## Framing

Aegis v1 (per `crates/zp-officers/src/aegis.rs`, landed 2026-07-24 via task #24) implements the minimum viable trajectory-scope observer: officer-cadre cadence coherence. It reads `officer:*:heartbeat` receipts and produces findings when officers go silent past declared thresholds. This is trajectory-scope in a narrow sense — it observes *whether* officers see, not *what* they see.

Aegis v2 extends the observer's scope substantially: score trajectories (per Cartographer's materialized ontology) against a chain-anchored labeled precedent corpus using the substrate's reference tabular classifier. Findings become trajectory-scope anomaly signals feeding the Cognitive Input Plane and, in sustained-severity cases, the Circuit Breaker escalation ladder.

This is advisory detection, not enforcement. The Governance Gate's atomic per-action evaluation remains unchanged. Aegis v2 is the trajectory-detection layer that atomic enforcement cannot see — the layer named in TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md as separate from and non-diluting to constitutional enforcement.

Two properties frame v2:

1. **Search-then-sign, not search-then-enforce.** Tree-search-over-branches (a candidate v2 capability) enumerates possible trajectory continuations; the substrate proposes; the operator signs which continuations become canonical precedent. Search enables anticipation; ceremony enables commitment. Never search-then-enforce — that would collapse advisory into enforcement, violating the trajectory-aware discipline.

2. **Classifier-scored, operator-owned.** Scoring uses the substrate's tabular classifier (per `SUBSTRATE-TABULAR-CLASSIFIER-2026-07.md`) trained on chain-anchored operator-labeled precedent. The classifier's judgment IS the operator's precedent, projected forward. No vendor-owned foundation-model scoring; no cross-operator training.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`.

- **`lens_id`**: `aegis_trajectory_scoring`
- **`focus`**: how Aegis v2 composes Cartographer ontology + tabular classifier + shadow-evaluation to produce trajectory-scope anomaly detection with search-then-sign discipline — advisory, chain-anchored, operator-signed for commitment
- **`dimensions`**: trajectory observation window, per-trajectory classifier scoring, branch enumeration (tree-search), branch scoring under classifier, anomaly threshold triggering, escalation-ladder composition, precedent proposal (search-then-sign), aligned-blindness projection (structural features only), rally protocol (compute on APOLLO)
- **`keyword_composition`**: [Aegis v2, trajectory scoring, anomaly detection, tree search, branch enumeration, search then sign, tabular classifier, Cartographer ontology, trajectory coherence, precedent divergence, decomposition attack, constitutional trajectory, advisory not enforcement, escalation ladder, shadow evaluation, XGBoost, operator ceremony, rally]
- **`transformation_question`**: *"given this trajectory's chain-anchored evidence, does it match operator-labeled 'good' precedent, diverge in an operator-labeled 'bad' pattern, or land in unfamiliar territory warranting operator attention?"*
- **`cross_references`**: `TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md` §VI.1 (parent spec Aegis extends), `OFFICER-LENS-DECLARATIONS-2026-07.md` (Aegis lens documentation this v2 amends), `SUBSTRATE-TABULAR-CLASSIFIER-2026-07.md` (primary compute dependency), `ONTOLOGY-AND-CARTOGRAPHER-2026-07.md` (materialized trajectories are the observation objects), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (candidate-vs-control scoring), `CIRCUIT-BREAKER-2026-07.md` (escalation-ladder consumer of Aegis findings), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (structural-features-only projection), `SUBSTRATE-COMPUTE-BASELINE-2026-07.md` (APOLLO-tier assumption for search + classifier), `REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07.md` (Gate 4 metacognitive fidelity partially depends on Aegis v2's chain-anchored evidence of Regent's own trajectory drift)

Directional: **inside-out** (substrate self-observation at trajectory scope, composed via chain-anchored primitives).

---

## What Aegis v2 does

### Scope 1 — Trajectory scoring against labeled precedent

For each active trajectory (per Cartographer materialization), Aegis periodically fetches the trajectory's chain evidence, projects features per `SUBSTRATE-TABULAR-CLASSIFIER` feature-engineering spec, runs the tabular classifier over each receipt-row, and produces:

- **Per-trajectory summary score** — aggregate classifier judgment across receipts in the observation window
- **Per-receipt anomaly flags** — receipts whose classifier score falls in tail regions
- **Trajectory-scope trend** — direction of score movement (drifting toward known_bad territory, stable in known_good, oscillating)

Chain-anchored as `officer:aegis:trajectory:scored:<trajectory_id>` with:
```
Event: officer:aegis:trajectory:scored:<trajectory_id>
Body:
  {
    "trajectory_id": "<cartographer-materialized-id>",
    "window_start": "<timestamp>",
    "window_end": "<timestamp>",
    "receipts_scored": <n>,
    "summary_score": <0.0-1.0>,  // 1.0 = fully known_good, 0.0 = fully known_bad
    "anomaly_receipt_hashes": ["<hash1>", ...],  // subset above threshold
    "trend": "improving" | "stable" | "drifting_bad" | "oscillating",
    "classifier_artifact_hash": "<active-classifier-content-hash>",
    "confidence": <0.0-1.0>  // classifier's own confidence
  }
```

### Scope 2 — Branch enumeration (tree search, when composed with Regent proposal)

When Regent proposes an action within a trajectory, Aegis can enumerate short-horizon continuation branches and score each branch's projected receipt state under the classifier. This produces:

- Branch fan-out (typically 3-5 candidate continuations)
- Per-branch classifier score
- Ranking + surface to operator

Chain-anchored as `officer:aegis:trajectory:branches_proposed:<proposal_id>`:
```
Event: officer:aegis:trajectory:branches_proposed:<proposal_id>
Body:
  {
    "trajectory_id": "<id>",
    "originating_proposal_receipt_hash": "<hash>",
    "branches": [
      {
        "branch_id": "<id>",
        "description": "<short semantic label>",
        "projected_receipts": [<projected-receipt-summaries>],
        "classifier_score": <0.0-1.0>,
        "confidence": <0.0-1.0>
      },
      ...
    ],
    "recommended_branch_id": "<id>",  // highest-score if any exceeds threshold; null if all ambiguous
    "search_ms": <ms-spent>
  }
```

**Critical:** Branch enumeration produces evidence. The operator's ceremony signs which branch (if any) becomes precedent. Aegis does NOT commit any branch autonomously. Per KEEL P9.

### Scope 3 — Sustained-anomaly escalation contribution

Sustained low classifier scores across trajectory observation windows compose with the Circuit Breaker escalation ladder per `CIRCUIT-BREAKER-2026-07.md`. Emitted as `officer:aegis:trajectory:sustained_anomaly:<trajectory_id>` at increasing severity per ladder rungs (L1 elevated attention → L4 hard trip). Escalation is advisory input; Circuit Breaker + operator ceremony decides what to do.

---

## Explicit non-conflation with Governance Gate

**The Governance Gate does not change.** Per KEEL §II.13 P8 (delegation narrowing) and P9 (operator signs), the Gate evaluates each action atomically against constitutional invariants (Harm Principle, Sovereignty Rule per whitepaper §5.3). The Gate is deterministic, model-independent, and cannot be bypassed by any Aegis output.

**Aegis v2 does not gate actions.** Aegis produces findings — chain-anchored observations of trajectory-scope patterns. Findings are advisory input to:
- Operator cognitive attention (via dashboard surfaces)
- Regent's Cognitive Input Plane (per COGNITIVE-INPUT-PLANE Tier 2 — filtered findings)
- Circuit Breaker escalation ladder (sustained patterns feed the escalation calculator)

**None of these paths reach the Gate's per-action decision.** The Gate's decision remains atomic per action. Aegis's role is precisely what TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md §1.3 names: additive, best-effort, advisory, model-informed, corrigible-over-time.

This non-conflation is the load-bearing invariant of the design. Aegis's power to be *useful* (probabilistic trajectory scoring, branch enumeration, anomaly detection) is bought precisely by giving up the Gate's power to *enforce* (atomic, deterministic, structural). Both layers exist. Neither replaces the other. Confusing them dilutes both.

---

## Search-then-sign discipline

Tree-search-over-branches (Scope 2) enumerates hypothetical trajectory continuations. Search is cheap; commitment is expensive.

**Search is autonomous.** Aegis enumerates branches without operator involvement per invocation. Branches are chain-anchored as evidence per `officer:aegis:trajectory:branches_proposed:*`. Operator sees them at review time.

**Sign is ceremonial.** Adopting any branch as precedent requires operator ceremony — signing `precedent:labeled:known_good:<branch_receipt_hash>` (or equivalent) makes the branch canonical. Only then is it available as future precedent for autonomous action under KEEL III.19.

**Precedent grows via ceremony, not via search.** Search proposes; operator disposes. No branch becomes precedent by search alone. This composes with:
- KEEL P9 (the system acts; the operator signs)
- KEEL III.19 (act on precedent, escalate on novelty) — precedent is what operator has signed, never what Aegis has found
- `SUBSTRATE-TABULAR-CLASSIFIER` label discipline — labels are operator-signed, not auto-emitted

**Search cost is budgeted.** Per-invocation search fanout is bounded (default 5 branches). Per-window search count is bounded (default 3 searches per trajectory per window). Budget events chain-anchored per `SHADOW-EVALUATION-PRIMITIVE` cost-budget discipline.

---

## Prerequisites

Aegis v2 depends on several substrate primitives that must land first:

### Hard prerequisites (blockers)

1. **Cartographer running and materializing trajectories.** Aegis v2 observes trajectories; if trajectories don't exist as materialized ontology objects, Aegis v2 has nothing to score. Gate 1 of the Regent Self-Buildout Trajectory. Pending.
2. **Substrate tabular classifier deployed.** Per `SUBSTRATE-TABULAR-CLASSIFIER-2026-07.md`. XGBoost integration, feature projection, retraining ceremony. Pending.
3. **Initial labeled corpus.** Minimum ~50-100 operator-signed `precedent:labeled:*` receipts to bootstrap classifier training. Pending — labeling ceremony spec + operator capacity to label.

### Soft prerequisites (degrade gracefully without)

1. **Rally protocol formalization.** If APOLLO-tier compute isn't available via rally, Aegis v2 degrades to Pi-5-hostable subset (skip tree-search Scope 2, run only classifier-scoring on smaller batch sizes). Composes with `SUBSTRATE-COMPUTE-BASELINE-2026-07.md`.
2. **Circuit Breaker escalation ladder.** If not yet integrated, sustained-anomaly findings still emit but don't drive escalation until wired up.
3. **Cognitive Input Plane Tier 2 filtering.** Findings feed input plane; Tier 2 filtering keeps signal quality high per SUBSTRATE-COORDINATION-DISCIPLINE (KEEL III.25).

---

## Composition

### With Cartographer ontology

Aegis v2 queries the ontology for active trajectories (per ONTOLOGY-AND-CARTOGRAPHER-2026-07.md), gets receipt-refs per trajectory, and pulls those receipts from chain for classifier scoring. Feature projection composes with Cartographer's trajectory-attribution (adds a `trajectory_membership` feature column). If a receipt belongs to multiple trajectories (rare, per Cartographer's split-over-merge policy), Aegis scores it per-trajectory-context.

### With Substrate Tabular Classifier

Primary compute dependency. Classifier serves as scoring backend. Retraining triggers can be Aegis-informed (sustained high false-positive rate on Aegis findings — measurable via operator review outcomes — triggers retraining ceremony proposal). Model-dossier substitutability applies: operators can substitute alternative classifiers per their dossier declaration.

### With Shadow Evaluation Primitive

Aegis v2 is a substantial candidate for Context 8 (classifier candidate-vs-control) shadow evaluation. When a new classifier candidate is trained, Aegis runs both current and candidate over the same trajectory observations, chain-anchors the score-comparison receipts, and provides evidence for operator promotion ceremony. This composes retraining discipline (SUBSTRATE-TABULAR-CLASSIFIER) with detection discipline (Aegis v2) into a single evidence-accumulation loop.

### With Circuit Breaker escalation ladder

Sustained low classifier scores across observation windows contribute to Circuit Breaker escalation. Ladder mapping:

- **Single low-score window** — Info-level finding, chain-anchored, no escalation
- **Sustained low-score across 3+ windows** — L1 elevated attention on trajectory
- **Sustained + Cleo governance-finding correlation** — L2 rate limit on trajectory-adjacent actions
- **Sustained + Steward integrity concern correlation** — L3 soft arrest at trajectory scope
- **Sustained + operator-signed emergency indicator** — L4 hard trip

Actual escalation is CIRCUIT-BREAKER's call; Aegis provides evidence.

### With Regent Self-Buildout Trajectory

Gate 4 (metacognitive fidelity verified) partially depends on Aegis v2. Regent's self-reports about her own trajectory can be scored against classifier's independent trajectory assessment — divergence between Regent's claim ("I've been in track X") and Aegis's evidence ("your recent action pattern scores in Y territory") is a metacognitive-fidelity signal. Not the only signal — P2.2.5-Shadow semantic classifier is the primary Gate 4 mechanism — but a substantial supporting one.

### With Cognitive Input Plane

Filtered Aegis findings (Warning+ severity) feed Regent's cycle context per COGNITIVE-INPUT-PLANE Tier 2. Regent perceives her own trajectory scores and can course-correct. Cycle-composition receipts carry Aegis-finding-hashes so Regent can query the underlying evidence.

### With Substrate Compute Baseline

Classifier serving is milliseconds per row on APOLLO-tier hardware. Tree-search fanout of 5 branches with 100 projected receipts per branch = 500 classifier invocations per search = ~250-500ms total. Comfortable within APOLLO envelope. On Pi-5-only substrates, Scope 2 (tree search) degrades or defers to rally.

---

## Non-goals

- **Not constitutional enforcement.** Repeated for load-bearing emphasis: Aegis v2 does not make Gate decisions. Gate stays atomic per KEEL P8/P9 and TRAJECTORY-AWARE.
- **Not autonomous precedent creation.** Aegis proposes branches; operator signs which become precedent. Search-then-sign discipline is non-optional.
- **Not a Cartographer replacement.** Aegis observes trajectories Cartographer materializes. Aegis doesn't define trajectories, doesn't decide boundaries, doesn't materialize ontology. If Cartographer isn't running, Aegis v2 doesn't run.
- **Not real-time enforcement latency.** Trajectory scoring is periodic (per observation window, default 5-15 min). Not per-action. Per-action gating is the Gate's job.
- **Not a substitute for standing corrections.** Corrections are operator-declared invariants; the classifier learns patterns. Both compose, neither replaces.
- **Not cross-operator scoring.** Each substrate's classifier is trained on that operator's labels. Cross-operator classification would violate aligned-blindness + coordination-not-oversight.
- **Not language-model risk scoring.** Aegis v2 uses tabular classifier over structural chain features. Language-model-based interpretation is a separate arc (potentially P2.2.5-Shadow v3 with inference-assisted extraction).

---

## Open positions

- **Observation window default.** 5, 10, 15 minutes? Trade-off: latency to escalation vs classifier stability. Empirical.
- **Anomaly threshold.** What classifier score triggers a finding? Depends on classifier calibration. Empirical, per-operator tunable.
- **Tree-search depth.** Single-step lookahead vs multi-step (branches of branches)? Cost/utility trade-off; suggest single-step for v2, extend later per operator ceremony.
- **Multi-trajectory scoring.** When Regent's action affects multiple trajectories, does Aegis score each independently or produce a joint assessment? Suggest independent scoring; cross-trajectory correlation deferred.
- **Search + shadow-eval composition.** If shadow-eval produces per-classifier score differences on branches, how does operator surface see it? UX question.
- **Aegis v2 self-lens declaration.** Once implemented, update OFFICER-LENS-DECLARATIONS-2026-07.md to describe v2 scope + emissions, per the retrofit discipline established for v1.
- **Escalation-ladder threshold calibration.** How many low-score windows before L1? L2? Empirical, chain-anchored evidence over time refines defaults per SHADOW-EVAL Context 4.

---

## What composes from here

Prerequisites landing order (all independent, can proceed in parallel where possible):

1. **Cartographer implementation** — largest arc; blocks Aegis v2 entirely
2. **Substrate tabular classifier implementation** — per `SUBSTRATE-TABULAR-CLASSIFIER-2026-07.md`
3. **`precedent:labeled:*` receipt schema + validation + initial labeling ceremony** — corpus bootstrap

Post-prerequisite work:

1. **Aegis v2 scope extension in `crates/zp-officers/src/aegis.rs`** — add trajectory-scoring method alongside existing officer-cadre-cadence method
2. **Chain-emission wiring for new `officer:aegis:trajectory:*` receipt types** — register in substrate_validate's known-prefix registry
3. **Cognitive Input Plane integration** — filtered Aegis findings feed Tier 2 per COGNITIVE-INPUT-PLANE
4. **Circuit Breaker escalation-ladder integration** — sustained-anomaly finding hooks
5. **Search-then-sign ceremony surface** — dashboard widget (per DASHBOARD-CONNECTORS-STACK-DECISION) showing proposed branches, operator signing UI

Ceremony work:

1. **Promotion of this proposal to Tier 2 canonical elaboration** — after empirical evaluation with early corpus. Would supersede or amend OFFICER-LENS-DECLARATIONS's Aegis section.
2. **Integration into REGENT-SELF-BUILDOUT-TRAJECTORY** — reference Aegis v2 as Gate 4 supporting mechanism (Gate 4's primary is P2.2.5-Shadow; Aegis v2 is complementary trajectory-scope signal).

---

## Framing note

Aegis v1 landed as officer-cadre cadence monitoring — trajectory-scope because it observes officers over time, not per-atomic-event. That was the minimum viable trajectory observer, and it was the right first step because it required no prerequisites (no Cartographer, no classifier, no corpus).

Aegis v2 is what Aegis was originally spec'd to be per TRAJECTORY-AWARE-CONSTITUTIONAL-ENFORCEMENT-2026-07.md §VI.1: constitutional-trajectory monitoring using best-effort inference-informed detection. The prerequisites weren't there in July when v1 landed. This proposal names what v2 will look like when the prerequisites do land.

The load-bearing decision in v2 is the search-then-sign discipline. It resolves the tension between (a) wanting sophisticated inference-informed trajectory reasoning and (b) preserving the atomic-enforcement guarantee at the Gate. The resolution: search produces evidence; operator signature produces commitment; neither collapses into the other. Aegis becomes a substantial detection layer without any dilution of the Gate's enforcement layer.

The proposal is deliberately conservative on autonomy. Every autonomy question (does Aegis auto-quarantine? does Aegis auto-remediate? does Aegis auto-label?) is answered "no" in v2. Autonomy grows via chain-anchored precedent — operator signs a class of Aegis action as precedent, subsequent invocations of that class execute autonomously per III.19. But v2 ships with the autonomy set empty; it grows only through explicit operator ceremony. This composes with the substrate's substrate-proposes/operator-signs discipline (P9) at the substrate-cognition layer, not just at the substrate-action layer.
