# Machine Learning Inventory

**Document type:** Investigation. **Not** a Tier 2 canonical elaboration — it elaborates no KEEL section. It audits correspondence between what the substrate is assumed to do and what its code actually computes, which places it in *Investigations and programs* alongside `STRUCTURAL-FIT-INVENTORY-2026-07.md`.

**Date:** 2026-07-27.

**Motivation:** The substrate is an AI-governance project, which invites an assumption that it contains machine learning. Whether it does — and where the boundary sits between what it computes and what it rents — has never been established in one place. Without that boundary written down, a reader cannot tell a statistical formula from a fitted model, or a hand-set constant from a calibrated one, and both mistakes were available to make.

**Source:** A four-way parallel sweep of the entire repository on 2026-07-27 — all 44 crates under `crates/`, and every top-level directory except `docs/`. Every row below was verified by direct read; nothing is inferred from naming.

**Composes with:** `STRUCTURAL-FIT-INVENTORY-2026-07.md` (sibling investigation over representations rather than computation; several rows here are its *convention* state seen from a different angle), `TRIAGE-FOR-COHERENCE-2026-07.md` (this sweep is an instance of that discipline, and its unjustified-constant findings are candidates for its queue), `CONNECTION-INTEGRITY-PROGRAM-2026-07.md` (§3 C2 — two findings here are *built, not wired* at the consumer end), `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` (the frequency-band discipline these components would be classified under), `MODEL-DOSSIER-2026-07.md` (the characterization schema this audit found in `models/`), `LOCAL-MODEL-SELECTION-2026-07.md` and `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (the routing decisions whose scoring functions are catalogued here).

---

## Framing

**1. The headline is a clean negative, and it is the architecture working as described.** The substrate implements **no machine learning**. Not gradient descent, not a loss function, not backpropagation, not an optimizer, not a training loop, not regularization, not a train/test split, not cross-validation, not an overfitting safeguard. It delegates every act of inference to an external model. That is consistent with the corpus's own posture — the substrate owns the envelope; the generator is rented — so this is a boundary to state clearly, not a gap to close.

**2. What it does contain is a substantial body of classical statistics, and a larger body of hand-set constants.** Closed-form maximum likelihood, Bayesian conjugate updates, Monte Carlo simulation with bootstrap confidence intervals and three significance tests, exponential decay, Welford's online variance, Levenshtein distance, KDE with Silverman's bandwidth. Alongside them sit roughly two dozen decision thresholds that were chosen by hand. Neither category is machine learning; conflating them with it is the error this inventory exists to prevent.

**3. The sharpest finding is not an absence but an adjacency.** In two places the substrate hand-rolls a mechanism whose proper implementation is already present in the same workspace, unused. Memory retrieval ranks by two literal constants while a quantized vector index sits beside it; reputation weights are uncalibrated while a Monte Carlo sensitivity-analysis engine runs in the same binary. The capability is not missing. It is unconsumed.

---

## Method

Four parallel sweeps, scoped so that every path in the repository fell into exactly one: the seven ML-named crates; ten cognitive/governance crates; the remaining twenty-seven crates; and every non-`crates/`, non-`docs/` directory. Each sweep classified every numeric routine it found into one of four buckets, and the classification is the load-bearing part of the method:

- **Learning** — parameters update from observed data.
- **Inference-delegation** — the computation is performed by an external model.
- **Statistics** — a fixed closed-form formula over data.
- **Heuristic** — hand-set rules and thresholds.

Similarity scoring, keyword matching and threshold comparison are **not** learning unless something updates a parameter. That rule is what separates this inventory from a keyword grep, and applying it moved most of the candidates out of the ML column.

---

## What exists

### The only ML runtime in the workspace

| Location | What it is | Status |
|---|---|---|
| `crates/zp-keys/src/sovereignty/face.rs` | Pretrained MobileFaceNet ONNX via `tract-onnx`; 112×112×3 input, cosine similarity against a stored embedding, `DEFAULT_FACE_THRESHOLD: f32 = 0.55` (env-overridable). Face *detection* is an OpenCV Haar cascade — classical CV, not learned | `tract-onnx` and `ndarray` are `optional`, gated behind `face-enroll`/`face-embeddings`; default features are `["os-keychain"]`. **Ships disabled** |

No other crate in the workspace declares candle, burn, tch, torch, onnx, ort, linfa, smartcore, rust-bert, tokenizers, faiss or qdrant.

### Inference delegation

| Location | Delegates to |
|---|---|
| `zp-llm/src/providers/{anthropic,ollama,proxy}.rs` | `api.anthropic.com/v1/messages`, Ollama `/api/chat`, or ZP's signing proxy |
| `zp-regent/src/inference.rs:439-500` | Ollama and OpenAI-compatible endpoints; cloud→local fallback decided by **string-matching the error text** for `"401"`, `"403"`, `"connect"`, `"timeout"`, `"dns"` |
| `zp-server/src/proxy.rs` | Governance reverse-proxy with a static allowlist for fourteen providers |
| `zp-observation` | Builds Observer/Reflector prompts and parses JSON-lines back; the caller makes the call. Falls back to `tier1_observe` keyword extraction when inference is unavailable, recording which path ran in `used_llm: bool` |
| `zp-memory-index` | `turbovec` quantized ANN over embeddings **supplied by the caller** |

### Statistics, doing work adjacent to ML

| Crate | Numerics | Wired? |
|---|---|---|
| `mle-star-engine` | Closed-form Gaussian MLE (mean, variance, log-likelihood), Bayesian conjugate posterior update, Pearson correlation, Student-t and normal confidence intervals | Live via `zp-server/src/analysis.rs` over receipt-chain data. Declares `nalgebra` and never uses it |
| `monte-carlo-engine` | Random / Latin-Hypercube / Sobol sampling, Gaussian KDE with Silverman bandwidth, Welch's t-test, Mann-Whitney U, permutation test, bootstrap CI, VaR/CVaR, Sortino and Calmar ratios, Welford online variance for convergence | Live via the same `analysis.rs` |
| `zp-mesh/src/reputation.rs` | `decay = exp(-age_days · ln2 / 30.0)` over four weighted signal categories | Live; consumed by `zp-policy` as a grade string |
| `zp-emission-coherence` | H1 n-gram repetition density, H2 length coefficient-of-variation, H3 mean-surprise z-score against a dossier baseline | **Not wired** — no crate references it; see ML-F2 |
| `zp-engine/src/tool_scan_security.rs` | Levenshtein edit distance, typosquat cutoff 2 | Live |
| `zp-regent/src/awareness.rs` | Delta and monotonicity over a 20-sample window; the code notes this is "simple statistics… not inference" | Live |
| `zp-memory/src/promotion.rs` | Running weighted mean over reinforcement count | Live |
| `zp-learning` | Exact-sequence frequency counting; confidence = `(count/total · 0.9).min(0.95)` | Live, human-gated |

### Named as if it learns, and does not

`zp-learning` / `LearningLoop` · `MLEStarEngine` ("pre-learning") · `infer_priority` / `infer_category` in `zp-observation/src/pipeline.rs` · `classify_generic_config_field` / `classify_benign_listener_class` in `zp-officers/src/sentinel.rs` · `classify_var` in `zp-engine/src/discovery.rs` · `Router::route` in `zp-regent/src/routing.rs` · `relevance_score` in `zp-regent/src/regent.rs`.

None contains a fitting step. Several say so in their own doc comments.

### Model artifacts

`models/*/model_dossier.toml` ×6 — descriptive characterization only (identity, quirks with severity, prompt compatibility, measured tok/s, bench results, tier suitability, and a `[drafter]` block). Real weights present: `models/kokoro/kokoro-v1.0.onnx` (325MB) and `models/piper/*.onnx` ×9 (~63MB each) — **TTS inference only**. `miniCPM-o-4_5/` holds 18GB of safetensors, vendored and explicitly retired (`// DELETED — MiniCPM-o removed from runtime stack. See ADR-031`). No `.gguf`, `.pt` or `.pth` exists anywhere in the tree.

### Tooling around models

`scripts/bench-local-models.py` (Ollama over HTTP; timing plus string/JSON scoring) · `scripts/dflash-parity-check.py` (imports external `dflash_mlx`, diffs token-ID lists byte-for-byte) · `scripts/dflash-observation-emitter.py` (polls `/metrics`, computes deltas and rolling means) · `tools/local-model-bench/` (imports `mlx_lm`, downloads pre-quantized checkpoints, times generation) · `crates/zp-inference-observer` (JSONL tailer that performs no arithmetic at all, and is deliberately outside the workspace). `scripts/parity-corpora/starter-24.jsonl` is 24 hand-written prompts — not a training set.

---

## Does the substrate implement core ML?

**No — verified absent across all 44 crates and every non-`docs/` directory.**

Zero occurrences of gradient descent, backpropagation, loss functions, optimizers, learning-rate schedules, training loops, weight updates, activation functions, softmax or sigmoid, L1/L2/dropout regularization, train/test split, cross-validation, or any overfitting safeguard.

Three near-misses were checked and are not what they appear:

- **185 hits for `epoch`** are Merkle receipt-chain epochs (`zp-receipt/src/epoch.rs`, `anchor_pipeline.rs`), not training epochs.
- **The one `early stopping`** is Monte Carlo convergence — *"simulation stops when variance of mean estimate < threshold"* — not regularization.
- **`CollapseDimension::FewShotOverfit`** names a probe that tests whether a model copies examples instead of reasoning. It is a test category, not a training-time metric.

The correct reading is that the substrate is a *verification envelope around rented cognition*. Every act of understanding is delegated; what the substrate computes is whether that act was authorized, whether its output is degenerate, and what it costs.

---

## Standard practice replaced by custom logic

Ranked by consequence. The final column records whether the code justifies the substitution.

| # | Substitution | Where | Justified in code? |
|---|---|---|---|
| **ML-F1** | Reputation weights `0.35/0.20/0.25/0.20` and a 30-day half-life, uncalibrated — while `monte-carlo-engine`, live in the same binary, implements exactly the parameter-sweep and confidence-interval machinery that would calibrate them | `zp-mesh/src/reputation.rs:30-35,103-121` | **No.** No sensitivity analysis, no stated derivation |
| **ML-F2** | Memory retrieval ranks by two literal constants (`0.5` keyword-hit, `0.3` recency) over substring search — while `zp-memory-index`, a quantized ANN with allowlist filtering, sits unused in the same workspace | `zp-regent/src/regent.rs:1573,1586` | Partly — commented `// MVP: no vector scoring yet.` The gap is that the replacement exists |
| **ML-F3** | Model routing as a hand-built linear score: `100/70/30/20/0` suitability `+15` loaded `+10` local `−40/20/5` pressure, winner-takes-all, no validation. The `_recent_failures` field earmarked for feedback is hard-coded to `0` | `zp-regent/src/routing.rs:369-507` | **No.** TODO acknowledges the dead field, not the weights |
| **ML-F4** | Doom-loop thresholds transcribed from a design document: `3-gram > max(4, L/20)`, `5-gram > max(2, L/40)`, CV `0.15`, 2σ warning / 3σ critical | `zp-emission-coherence/{ngram,length,entropy}.rs` | Partly — `entropy.rs` is candid that mean-surprise is "a proxy," and `MIN_TOKEN_FLOOR = 24` admits it is "a defensible default" |
| **ML-F5** | Skill matching by **bidirectional** substring containment, no IDF, no length normalization — so short tokens match nearly everything | `zp-skills/src/matcher.rs:30-84` | Partly — self-labelled "Phase 1," embeddings named as the future path |
| **ML-F6** | `priority_to_confidence` maps a categorical priority to `0.95/0.75/0.50/0.90` — presented as confidence, carrying no probabilistic meaning, and not monotonic in priority | `zp-observation/src/receipts.rs:292-298` | **No** |
| **ML-F7** | Posture scoring by fixed penalty (`−0.4` critical, `−0.2` error, `−0.05` warning), composite taken as `min()` across four domains | `zp-officers/src/posture.rs:43-109` | Penalties documented; magnitudes not derived |
| **ML-F8** | Observation thresholds adopted wholesale from another system — *"Defaults are calibrated to match Mastra's proven settings"* | `zp-observation/src/config.rs:6-7` | Stated, but the calibration is someone else's |

Worth recording in the substrate's favour: several of these declare themselves. `zp-regent/src/context.rs:263-275` says its 2:1 authorship weight comprises "placeholder magnitudes, not derived from evidence — re-tune once the ratio has an observed distribution." `zp-officers/src/sentinel.rs:490` marks its classifier as hard-coded "until Task P2.1 (standing correction data pipeline) lands." The genuinely unexamined constants are ML-F1, ML-F3 and ML-F6.

---

## Coded versus assumed

**Coded:** the statistics above, the heuristics above, the delegation plumbing, and one ONNX inference path that ships disabled.

**Assumed to happen elsewhere:** all language understanding, intent classification, summarization, planning and tool-parameter composition — delegated to Ollama or a cloud provider.

**Assumed and with no producer — a real gap.** `zp-memory-index` requires `&[f32]` embeddings, and a `MemoryIndexed` receipt references an "embedding model." **Nothing in the repository computes an embedding** outside the disabled face path. The index has a consumer interface and no producer.

**Declared not-yet-trained, with observability built first.** The model dossiers carry `[drafter]` blocks with `state = "not_yet_trained"` and empty `checkpoint_hash` / `training_run_receipt`, while `dflash-parity-check.py`, `dflash-observation-emitter.py` and the whole `zp-inference-observer` crate exist to observe a drafter that does not yet exist. Unusual ordering, and defensible — the instrument precedes the thing measured — but it should be read as instrumentation, not capability.

**Specified and unbuilt.** Doom-loop heuristics H4–H8: `zp-emission-coherence/src/lib.rs:19-22` states H4 "needs an embedding backend," H5 needs per-model reasoning-trace parsing, H6–H8 need Cartographer materialization. H4 is the one place a genuine embedding-similarity component was designed for, and it is blocked on the same absent producer.

---

## Verifiable outcomes (ML)

- **ML-O1** — Every numeric routine in the substrate is classifiable as learning, inference-delegation, statistics or heuristic, and no routine is described in prose as one category while implemented as another.
- **ML-O2** — Every decision threshold that gates a governance outcome names either its derivation or its status as a placeholder.
- **ML-O3** — No component named `*learn*`, `*infer*`, `*classify*` or `*score*` lacks a doc comment stating which of the four categories it belongs to.
- **ML-O4** — Where a fitted or indexed mechanism exists in the workspace, no consumer hand-rolls a substitute without a recorded reason.
- **ML-O5** — Any component that consumes embeddings has an identified producer, or is marked as having none.
- **ML-O6** — The substrate's delegation boundary is stated in one place: what is rented, from whom, and what happens when it is unavailable.

---

## Open positions

- **ML-A — Should ML-F1's constants be calibrated with the engine already present?** `monte-carlo-engine` can sweep the four reputation weights and the half-life against recorded signals and report confidence intervals. *Resolution: run the sweep, or record a decision that hand-set weights are acceptable and why. Either closes it; leaving it silent does not.*
- **ML-B — Who produces embeddings?** The index, the `MemoryIndexed` receipt and doom-loop H4 all assume a producer that does not exist. *Resolution: name the intended producer (local model via Ollama, a dedicated embedding endpoint, or the disabled ONNX path generalized), or mark the index as awaiting one.*
- **ML-C — Is `zp-emission-coherence` meant to be wired?** It is complete, tested, and referenced by nothing. *Resolution: wire it into the Regent's emission path, or record why detection runs out-of-band. This is C2 and belongs in the connection program's queue either way.*
- **ML-D — Does `priority_to_confidence` mean anything?** It emits numbers that look like probabilities onto receipts. *Resolution: either give the mapping a stated basis, or rename the field so it does not claim more than a categorical judgment.*
- **ML-E — What is the disposition of the vendored ML weights?** `miniCPM-o-4_5/` is 18GB, retired by ADR-031, still in the tree. *Resolution: operator decision on removal; recorded here because size and staleness both grow.*

---

## Adjacent findings

Not machine learning, but surfaced by the sweep and worth acting on:

- **`graphiti/server/.env` contains live-looking credentials** — `OPENAI_API_KEY`, `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` — while the rest of the `graphiti/` checkout has had its source stripped (only `.DS_Store`, `.pytest_cache` and stale `.pyc` remain). Whatever the keys' validity, a stripped vendor directory retaining an `.env` is worth immediate attention.
- **`zp-artemis-relay/` is vestigial** — operator confirmed 2026-07-27. 1.1GB, and it embeds a complete second mirror of the repository, which is where several stale `graphiti` and `minicpm` references that appear in sweeps actually live. Removing it eliminates a class of false positive from every future scan.
- **`INPUT/crates/` duplicates `mle-star-engine` and `monte-carlo-engine`** by name while being outside the workspace and unbuilt. Two copies of a crate name is a reliable source of misattributed findings.
- **`frameworks/` contains only stale `.pyc` bytecode**, with no source present.

---

## What is specified vs. what is shipped

Per A11: this document reports **only what was read on 2026-07-27**. Every crate, script and directory named above was opened; no row is inferred from a filename. Where a component is described as unwired, that means no reference was found outside its own crate and tests. Where it is described as live, a call site was identified.

Not verified: whether `zp-server`'s `analysis.rs` HTTP handlers are themselves reachable from the router (so `mle-star-engine` and `monte-carlo-engine` are wired at the crate level, and their end-to-end reachability is untested); and `turbovec`'s internal search algorithm, which is an external crate not vendored here.

---

## Non-goals

- **Not an argument that the substrate should implement ML.** The delegation posture is coherent and deliberate. This inventory establishes the boundary; it does not propose moving it.
- **Not a performance review.** No routine here is criticised for speed.
- **Not a security audit.** The `graphiti/` credential finding is reported because the sweep encountered it, not because this document assessed exposure.
- **Not a proposal to calibrate every constant.** Most hand-set thresholds are fine. ML-F1, ML-F3 and ML-F6 are named because they gate governance outcomes and state no basis; the rest are recorded for completeness.
