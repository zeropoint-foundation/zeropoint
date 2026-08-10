# Substrate Tabular Classifier

**Document type:** Tier 2 canonical elaboration. Elaborates `KEEL-2026-07.md` §II.5 (sovereign identity), §II.13 P4 (every bit counts) + P6 (a tool is intent, crystallized) + P9 (the system acts; the operator signs), §II.19 (extensions), §III.22 (evidence-based ceremony), Part V (composition contract), Part VIII (bounded operator sovereignty — license discipline). Names the substrate's reference tabular classifier for risk scoring and anomaly detection over receipt-chain data.

**Author:** Ken Romero (2026-07-25). Synthesis assistance from Claude.

**Status:** Reference-implementation decision. XGBoost adopted as the reference; alternative gradient-boosting implementations (LightGBM, CatBoost) supported via model-dossier substitutability. Retraining ceremony spec landed; runtime integration is downstream implementation arc.

---

## Framing

The substrate needs a tabular risk-scoring capability — a mechanism that reads receipt-chain data (row-per-receipt, with structured columns for actor, action-type, delegation, harness, outcome, severity, timestamp) and produces per-row risk classifications against an operator-labeled reference corpus. This capability composes with Aegis v2 trajectory scoring, with anomaly-detection dashboards, and with the substrate's post-emission verification stack.

Foundation-model options for this problem (TabFM, TabPFN, TabPFN-2.5) all ship with commercial-use restrictions that fail the substrate's Apache 2.0 discipline established in `DASHBOARD-CONNECTORS-STACK-DECISION-2026-07.md`. The 2026 tabular-foundation-model market is dominated by non-commercial licenses that break adopter sovereignty.

Traditional gradient boosting — XGBoost, LightGBM, CatBoost — is Apache-2.0-compatible, battle-tested (dominant in production tabular use for a decade), and structurally better suited to substrate sovereignty than any foundation model, because retraining is cheap and can be operator-owned rather than vendor-owned.

The trade-off — losing the "zero-shot" pitch — is the right cost to pay. The retraining cost becomes an architectural strength: every retraining event is a chain-anchored ceremony producing an operator-signed classifier artifact, auditable and revertable.

---

## Formal lens declaration

Per `LENS-DISCIPLINE-2026-07.md`, this document declares the following lens as its first-class canonical form.

- **`lens_id`**: `tabular_classifier`
- **`focus`**: how gradient-boosting tabular classification composes with substrate primitives (chain-anchored labeled corpus, operator-signed model artifacts, retraining ceremony) to produce sovereignty-native risk scoring
- **`dimensions`**: reference-implementation choice (XGBoost / alternatives), labeled corpus curation, retraining ceremony (cadence, trigger, budget), model artifact lifecycle (train → sign → serve → retire), classifier substitutability via model dossier, shadow-evaluation candidate-vs-control, aligned-blindness projection (name-level features only, no value inspection), APOLLO-baseline resource envelope
- **`keyword_composition`**: [tabular classifier, XGBoost, LightGBM, CatBoost, gradient boosting, receipt scoring, risk classification, precedent labeled, labeled seed set, retraining, classifier artifact, model dossier, feature engineering, categorical column, ordinal encoding, class imbalance, feature importance, shadow evaluation, anomaly detection]
- **`transformation_question`**: *"how does this tabular signal compose with chain-anchored labeled precedent to produce operator-owned risk scoring without ceding trust root to a foundation-model vendor?"*
- **`cross_references`**: `DASHBOARD-CONNECTORS-STACK-DECISION-2026-07.md` (license discipline this doc conforms to), `SUBSTRATE-COMPUTE-BASELINE-2026-07.md` (APOLLO-tier assumption for retraining), `SUBSTRATE-SLM-TRAINING-ENVIRONMENT-2026-07.md` (chain-anchored labeling as training signal — this doc is the tabular specialization), `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (candidate-vs-control classifier comparison), `EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 5 (model dossier discipline extends to tabular classifiers), `AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL-2026-07.md` (primary consumer), `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md` (aligned-blindness projection over features), `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (precedent-labeled receipts compose with correction discipline)

When chain-anchored as a `lens:declared:tabular_classifier` receipt, invocation semantics follow the lens discipline: any work context matching the keyword composition triggers a `lens:applied:tabular_classifier:<invocation_id>` receipt. Directional: outside-in (external ML toolkit → substrate composition).

---

## Decision — XGBoost as reference implementation

**Chosen:** [XGBoost](https://github.com/dmlc/xgboost) as the reference tabular classifier for substrate risk scoring.

**License:** Apache 2.0. Fork-and-modify compatible with substrate's license discipline.

**Rationale:**
- Battle-tested at scale — dominant tabular classifier for a decade of production use, kaggle competitions, financial risk scoring, ad-click prediction, fraud detection
- Strong native handling of categorical columns (which chain receipts have plenty of — actor, action-type, harness, severity, policy_module)
- Handles class imbalance natively (relevant — "known bad" seed examples will be rare relative to "known good")
- Fast training on moderate corpora (thousands to millions of labeled rows); comfortable on APOLLO-tier hardware
- Fast inference (milliseconds per row) — compatible with per-receipt scoring cadence
- Rust bindings exist ([`rust-xgboost`](https://github.com/davechallis/rust-xgboost)) — substrate can invoke natively without Python subprocess overhead
- Broadly deployed — operators who want to audit the classifier or substitute have a large ecosystem to draw on

**Alternatives supported via model dossier substitutability:**
- **LightGBM** — MIT license (compatible), Microsoft-authored, similar performance profile, often faster on large corpora. Consider as substitute when training-speed becomes a constraint.
- **CatBoost** — Apache 2.0, Yandex-authored, particularly strong when categorical columns dominate. Consider as substitute if categorical-signal quality is a limiter.
- **AutoGluon** — Apache 2.0, Amazon's AutoML wrapping gradient boosting + neural methods. Consider as a higher-level substitute when substrate wants automated architecture tuning at retraining time.

Substitution proceeds via `regent:config:tabular_classifier` receipt (analogous to `regent:config:inference` for language models). Operator ceremony changes the classifier; chain records the change.

**Rejected:**
- **TabFM (Google), TabPFN, TabPFN-2.5** — non-commercial license fails substrate discipline. See `DASHBOARD-CONNECTORS-STACK-DECISION-2026-07.md` for the general license discipline this doc conforms to.
- **Random Forest** (scikit-learn) — Apache 2.0 base but scikit-learn wraps under BSD. Adequate baseline, but XGBoost dominates on the specific properties relevant to substrate (categorical handling, class-imbalance, calibrated probabilities).
- **Neural tabular methods** (TabNet, FT-Transformer without AutoGluon) — Apache 2.0 available but heavier and less proven than gradient boosting on tabular. Higher training cost, marginal accuracy improvement for typical substrate workload.

---

## `precedent:labeled:*` receipt schema

Chain-anchored labeling of receipts as reference examples for classifier training. Each `precedent:labeled:*` receipt is operator-signed (or Regent-signed with operator delegation) and marks a specific chain receipt as a canonical example of a labeled category.

### Receipt shape

```
Event: precedent:labeled:<label>:<subject_receipt_hash>
Actor: operator or delegated Regent
Signature: Genesis-derived (operator or Regent per delegation)
Body:
  {
    "subject_receipt_hash": "<sha256-hash-of-target-receipt>",
    "label": "known_good" | "known_bad" | "known_ambiguous" | "false_positive" | "false_negative",
    "label_scope": "trajectory" | "gate_decision" | "delegation" | "commitment" | "general",
    "rationale": "<operator's brief justification, chain-anchored>",
    "context_receipts": ["<hash1>", "<hash2>", ...],  // optional supporting evidence
    "supersedes": "<prior-label-hash-if-relabeling>"  // per KEEL supersession discipline
  }
```

### Label taxonomy (v1)

- **`known_good`** — receipt reflects operator-endorsed correct substrate behavior
- **`known_bad`** — receipt reflects operator-identified problematic substrate behavior (bug, drift, confabulation, unauthorized action)
- **`known_ambiguous`** — operator reviewed and found the receipt neither clearly good nor bad; retain for context but exclude from binary classification training
- **`false_positive`** — receipt was flagged by a prior classifier as bad, but operator judgment is that it's actually good; used to reduce future false positives
- **`false_negative`** — receipt was NOT flagged by a prior classifier as bad, but operator judgment is that it should have been; used to increase future recall

### Label scope

- **`trajectory`** — label applies to the trajectory the receipt belongs to (per Cartographer materialization); useful when the receipt's meaning is trajectory-dependent
- **`gate_decision`** — label applies specifically to Gate allow/deny outcomes
- **`delegation`** — label applies to delegation-lifecycle events (grant/expiration/revocation)
- **`commitment`** — label applies to commitment fulfillment or breach
- **`general`** — no specific scope; label applies to the receipt as-is

### Supersession

Labels can be superseded per the general chain supersession discipline. `supersedes` field references a prior `precedent:labeled:*` receipt; the new receipt takes precedence. Classifier training uses the current unsuperseded label set. Historical labels remain on chain as reasoning trail.

---

## Retraining ceremony

Classifier retraining is a chain-anchored ceremony. The substrate does not silently update the classifier from accumulated labels.

### Trigger classes

- **Operator-initiated** — operator invokes `zp classifier retrain` (or Regent proposes and operator signs). Explicit ceremony.
- **Cadence-based** — configurable interval (default: weekly). Ceremony surface prompts operator when cadence fires; retraining proceeds only after operator sign.
- **Label-volume-triggered** — new labels since last retraining exceed configurable threshold (default: 50 new labels). Ceremony surface prompts; operator sign proceeds.
- **Divergence-triggered** — shadow-evaluation of candidate classifier against current shows sustained accuracy improvement above threshold. Ceremony surface prompts; operator reviews evidence before signing.

### Ceremony steps

1. **Corpus assembly.** Chain query for all current `precedent:labeled:*` receipts (excluding superseded). Assemble labeled corpus.
2. **Feature engineering.** Apply canonical feature projection (see §Feature engineering). Produce feature matrix.
3. **Training.** XGBoost training with declared hyperparameters (checked into corpus as `classifier_hyperparameters:v1`).
4. **Validation.** Held-out validation split (default 20% stratified). Compute accuracy, precision, recall, F1, calibration.
5. **Artifact production.** Serialize trained classifier + validation report + feature-projection spec + label-corpus manifest hash into a content-addressed artifact.
6. **Chain-anchor candidate.** Emit `classifier:trained:candidate:<artifact_hash>` receipt with validation summary.
7. **Operator review.** Operator inspects validation report + comparison against current classifier (shadow-eval evidence).
8. **Operator sign.** Operator signs `classifier:promoted:<artifact_hash>` receipt, canonicalizing the new classifier as substrate's active tabular classifier. Prior classifier moves to archived state (retained for shadow-eval baseline).
9. **Substitution.** Runtime substrate loads the new classifier at next request boundary; in-flight scoring completes with prior classifier.

Steps 1-6 execute autonomously per KEEL III.19 precedent discipline once operator has approved this ceremony class. Steps 7-9 require ceremony per KEEL P9.

---

## Classifier lifecycle

Each classifier artifact traverses a chain-anchored lifecycle:

- **Candidate** — trained but not yet operator-signed. Emitted as `classifier:trained:candidate:*`. Can be tested in shadow-eval against current active classifier.
- **Active** — operator-signed as canonical. Emitted as `classifier:promoted:*`. Used for all substrate scoring calls.
- **Archived** — superseded by newer active. Emitted as `classifier:archived:*`. Retained for shadow-eval baseline and audit.
- **Retired** — operator-signed removal (rare — only when classifier is definitively unsafe or non-functional). Emitted as `classifier:retired:*`. Not loaded into runtime.

At most one classifier is Active at a time. Multiple Candidates can coexist (competing training runs). Many Archived. Retirement is terminal for that artifact hash.

---

## Feature engineering (Layer B, canonical)

Feature projection is a Layer B canonical spec — extension via canonicalization ceremony. v1 features (deliberately conservative):

**Categorical (one-hot or ordinal encoded):**
- `actor_type` — System, Operator, Regent, Tool, Officer
- `actor_role` — specific officer name, tool name, etc. (bucketed to top-N for cardinality control)
- `action_type` — SystemEvent prefix (e.g. `officer`, `governance_request`, `delegation`, `regent`)
- `event_prefix` — first 2 segments of event string (e.g. `officer:std`, `delegation:granted`)
- `harness` — Regent's dispatching harness for the action (Direct, Tool, Officer, Verb)
- `policy_module` — canonical policy module identifier
- `severity` — if present (Ok / Info / Warning / Error / Critical / null)

**Numerical:**
- `chain_position` — normalized rowid of the receipt in chain
- `time_since_prev` — seconds since immediately-preceding receipt from same actor
- `time_since_last_similar` — seconds since prior receipt with same event_prefix
- `same_actor_burst_count` — count of receipts from same actor in preceding 60s
- `entropy_prev_10` — Shannon entropy of event_prefix over preceding 10 receipts

**Boolean:**
- `has_receipt_extensions` — true if receipt carries extensions
- `has_signature` — true if signed
- `crosses_delegation` — true if action asserts capability outside baseline

Feature projection is **strictly over receipt structural fields** — never over receipt content that would touch aligned-blindness scope. The classifier sees "actor X performed action Y with severity Z" — never "actor X performed action Y with content C where C is sensitive." Aligned-blindness composition (per KEEL III.24) preserved by feature-projection contract.

---

## Composition

### With Aegis v2 (primary consumer)

Aegis v2 (per `AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL-2026-07.md`) invokes the tabular classifier per trajectory-scope observation window, scoring each receipt against the operator's labeled precedent. High-anomaly scores become Aegis findings; sustained high-anomaly patterns become escalation-ladder inputs per CIRCUIT-BREAKER. Aegis is the primary Aegis-v2 consumer of this classifier; other consumers (dashboard widgets, ad-hoc operator queries) compose secondarily.

### With SUBSTRATE-SLM-TRAINING-ENVIRONMENT

This doc is a specialization of the training-signal-from-chain-anchored-discipline framing. Where the parent framing envisions eventual language-model training on substrate operational trace, this doc specializes the same pattern for tabular classification, available today. The general framing composes forward as substrate maturity grows; this specialization is what fits current substrate scale (~thousands to tens-of-thousands of labeled examples typical).

### With SHADOW-EVALUATION-PRIMITIVE

Retraining ceremony's shadow-evaluation step is a specific instance of the general primitive per Context 2 (officer thresholds and configurations) or a new Context 8 (classifier candidate-vs-control). Chain-anchored comparison evidence informs operator promotion ceremony. Enables continuous improvement without silent policy change.

### With EXECUTION-AUTHORITY-MODEL Phase 5

Classifier artifacts join the model-dossier discipline. Each Active classifier has a dossier entry with training corpus manifest hash, hyperparameter spec, validation results, and version. Operator can inspect, compare across time, revert. Same discipline shape as reasoning/routing model dossiers.

### With STANDING-CORRECTION-RECEIPT-SCHEMA

Standing corrections compose with `precedent:labeled:*`. A standing correction identifying a class of unwanted behavior can auto-generate `precedent:labeled:known_bad` receipts for matching chain entries (operator-approved batch labeling). Correction-driven labeling accelerates seed-corpus growth without per-receipt operator ceremony.

### With DASHBOARD-CONNECTORS-STACK-DECISION

The dashboard widgets specified in that decision include a "risk-scoring surface" that displays classifier outputs alongside chain state. Widget queries the classifier via a substrate interface; classifier remains substitutable per model-dossier discipline. Widget composition is dashboard-side; classifier composition is substrate-side.

### With SUBSTRATE-COMPUTE-BASELINE

Retraining runs APOLLO-tier per compute-baseline discipline. Rust bindings host inference (millisecond per row) even on Pi 5 when substrate rallies for scoring; training rallies to APOLLO. Pi 5 can serve inference from a rally-cached classifier artifact.

---

## Layer A / Layer B split

**Layer A (compiled Rust host):**
- XGBoost integration via `rust-xgboost` bindings
- Classifier artifact loading, in-memory serving
- Retraining pipeline execution
- `precedent:labeled:*` receipt validation
- Classifier lifecycle state machine
- Chain emission for `classifier:*` receipts
- Rate limiting and resource bounds

**Layer B (WASM modules + canonical data):**
- Feature-projection specification (which columns, which encoding)
- Hyperparameter defaults (learning rate, tree depth, regularization)
- Retraining trigger thresholds (label-volume, cadence, divergence)
- Validation split policy (stratification, size)
- Label taxonomy (extensible via canonicalization)
- Substitution policy (which alternative classifiers permitted per operator dossier)

---

## Non-goals

- **Not a general-purpose ML platform.** This doc names one narrow capability (tabular classification of chain receipts). Language-model training, image classification, embeddings, and other ML classes are separate arcs.
- **Not a real-time classifier for Gate enforcement.** Per KEEL P8 and the trajectory-aware discipline, Governance Gate enforcement is atomic, deterministic, model-independent. Classifier scoring is advisory input to Aegis v2 trajectory detection, NOT input to the Gate's per-action allow/deny decision.
- **Not automatic operator decision-making.** The classifier scores; the operator decides. High-anomaly scores surface for review; the substrate does not auto-quarantine, auto-revoke, or auto-remediate based on classifier output alone. Autonomous action per KEEL III.19 requires prior operator-signed precedent for the specific class.
- **Not a substitute for standing corrections.** Standing corrections are operator-declared invariants. The classifier learns patterns; corrections declare rules. Both compose but neither replaces the other.
- **Not a training service for other operators' data.** Each substrate trains its own classifier from its own operator's labeled corpus. No cross-operator training. Cross-operator classifiers would violate aligned-blindness and coordination-not-oversight discipline.

---

## Open positions

- **Rust XGBoost binding vs Python subprocess.** `rust-xgboost` is workable but the ecosystem is small; alternative is spawning a Python subprocess for training (slower boundary, easier ecosystem). Prefer Rust binding for tight integration; consider Python fallback if binding maturity is limiting.
- **Cold-start behavior.** First-ever retraining requires some labeled corpus. How much? Empirical calibration; suggest minimum 20 labeled examples per class before first training. Below that threshold, classifier is dormant and Aegis skips its inputs.
- **Class imbalance handling.** `known_bad` will be much rarer than `known_good`. XGBoost native `scale_pos_weight` handles this, but calibration will be work. Empirical tuning.
- **Feature projection extensibility.** Adding new columns (e.g., after Cartographer lands and ontology-attribution becomes available) is Layer B extension. Ceremony for extension needs specification.
- **Classifier as observability surface.** Feature importance from trained XGBoost tells operator which chain columns most inform classification. That surface itself has UX considerations — how does operator inspect what the classifier "learned"?
- **Adversarial-labeling resistance.** If Regent's autonomy grows to include label proposal (per SUBSTRATE-HARDENING-CEREMONY), how does the substrate prevent Regent from mislabeling to bias the classifier? Suggest per-Regent-labeled retraining runs shadow-eval against operator-only-labeled corpus before promotion.

---

## What composes from here

Immediate:
1. Rust binding integration for XGBoost — evaluate `rust-xgboost` maturity, decide Rust-native vs Python-subprocess path.
2. `precedent:labeled:*` receipt validation module in `zp-audit`.
3. Feature-projection specification finalization (Layer B canonical).

Near-term:
1. Retraining pipeline implementation (Rust orchestration invoking XGBoost).
2. Classifier lifecycle state machine + chain-emission wiring.
3. `zp classifier` CLI verb (train, promote, list, inspect).
4. Aegis v2 integration point — classifier as trajectory-scoring input.

Later:
1. Shadow-evaluation integration — parallel classifier candidates chain-anchored per invocation for cross-classifier evidence accumulation.
2. Dashboard risk-scoring widget (per DASHBOARD-CONNECTORS-STACK-DECISION).
3. Standing-correction to `precedent:labeled` auto-batch flow.
4. Model-dossier v2 extension for tabular classifiers.

---

## Framing note

The temptation with tabular ML in 2026 is to reach for the shiny foundation-model option. TabFM and TabPFN-2.5 look attractive on the "zero-shot classification" pitch. But their license posture makes them unsuitable for substrate embedding — the substrate's promise is fork-and-modify sovereignty, and non-commercial-licensed weights break that promise for commercial adopters.

XGBoost's design maturity (Apache 2.0, ten-year track record, dominant tabular tool) turns out to compose more naturally with substrate sovereignty than any foundation model can. Chain-anchored labeled corpus + XGBoost retraining is the substrate-native pattern: operator-owned labels produce an operator-owned classifier. The classifier IS the substrate's understanding of the operator's declared "good" and "bad," rather than a vendor's understanding transferred via zero-shot inference.

The "zero-shot" pitch trades sovereignty for convenience. XGBoost trades convenience for sovereignty. For a substrate whose whole reason for existence is sovereignty, this is the correct direction.
