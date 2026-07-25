# Inference Routing — Sovereign Model Selection

**Status:** Draft  
**Date:** 2026-07-09  
**Scope:** `InferenceBackend` routing layer in `zp-regent`  
**Companion to:** `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 5), `models/README.md` (dossier lifecycle), `COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` (#11 — context assembly is attention)

---

## Decision

The substrate routes inference requests to models using its own chain-anchored evidence — not an external router. Model selection is a function of intent category, dossier characterization, evaluation history, fallback record, and system pressure. The routing decision is auditable, governable, and sovereign.

---

## Why Not RouteLLM

RouteLLM (and similar external routers) solve cost optimization by classifying query difficulty and routing to the cheapest sufficient model. Three structural mismatches with ZP:

1. **Opaque evidence.** RouteLLM's classifier is a black box trained on generic data. The substrate can't audit *why* a model was chosen, can't verify the evidence, can't override the decision with chain-anchored knowledge. This violates *signing is gravity* — the routing decision has no receipt, no authority, no verifiable basis.

2. **No substrate awareness.** The external router doesn't know about memory pressure, loaded models, fallback history, prompt compatibility quirks, or the dossier's blocking annotations. It can't route *around* gemma4's context-dump failure mode or *toward* qwen3:1.7b when memory is tight.

3. **Sovereignty inversion.** Delegating model selection to an external service means the substrate's cognitive quality depends on a third party's optimization function. When the router degrades, misroutes, or changes its model inventory, the substrate has no recourse. The inference optimization function is a governance decision; it belongs inside the trust boundary.

RouteLLM remains useful as a **backend provider** — Abacus exposes many models through one OpenAI-compatible endpoint, and the substrate can target specific models via the `model` field. The substrate routes; Abacus serves.

---

## Architecture

### Where It Lives

The router is a method on `InferenceBackend`, not a separate service. It sits between the cognitive loop's intent and the `chat()` call:

```
Regent cognitive loop
  → reason() produces InferenceRequest with intent category
  → InferenceBackend::route(intent, &dossier_corpus, &system_awareness)
    → selects (endpoint, model, provider_profile)
    → chat() executes against the selected target
```

No new process, no new crate, no external dependency. The router is data-driven — it reads dossier files and chain state, applies a ranking function, and returns a target.

### Intent Categories

Every inference call has an intent category that maps to capability requirements. The Regent already knows why it's calling inference — this makes the category explicit:

| Category | Requirements | Examples |
|----------|-------------|----------|
| **Routing** | Fast, accurate classification. JSON compliance mandatory. Small model acceptable. | Intent parsing, receipt classification |
| **Conversation** | Strong instruction-following. Operator-facing — quality matters more than speed. Context-dump-safe. | Responding to operator input |
| **Stewardship** | Adequate reasoning. Can tolerate higher latency. Chain analysis, finding interpretation. | Autonomous officer finding interpretation, remediation planning |
| **Tool dispatch** | Structured output compliance. Parameterized JSON. Medium model minimum. | Composing tool call parameters |
| **Evaluation** | Must hit a specific model. Deterministic targeting, no routing. | `model_evaluate` tool, validation battery |

The category is passed by the caller — the cognitive loop knows whether it's in conversation mode (operator input present) or stewardship mode (autonomous). Tool dispatch is explicit. Evaluation always targets.

### The Routing Function

```rust
pub struct RouteDecision {
    /// Which model to use.
    pub model: String,
    /// Which endpoint to hit.
    pub endpoint: String,
    /// Provider profile for auth/protocol.
    pub provider: ProviderProfile,
    /// Why this model was selected (for chain receipt).
    pub rationale: String,
}

impl InferenceBackend {
    /// Select the best model for the given intent category.
    ///
    /// Evidence sources (in priority order):
    /// 1. Explicit operator pin (regent:config:inference receipt with a model)
    /// 2. Dossier tier suitability (blocked models are excluded)
    /// 3. Evaluation scores (empirical quality from model_evaluate receipts)
    /// 4. Fallback history (models with recent failures are penalized)
    /// 5. System pressure (memory-constrained → prefer smaller/loaded models)
    pub fn route(
        &self,
        category: IntentCategory,
        corpus: &DossierCorpus,
        awareness: Option<&SystemAwareness>,
    ) -> RouteDecision { ... }
}
```

### Evidence Sources

**1. Operator pin (highest priority).** If the operator (or the Regent via self_configure) has set a specific model via `regent:config:inference`, that model is used unconditionally for its designated tier. This is the sovereign override — the chain said so.

**2. Dossier tier suitability.** Each dossier has a `[tiers]` section mapping intent categories to suitability ratings (`recommended`, `viable`, `not_recommended`, `blocked`). Blocked models are excluded from the candidate set. This is where gemma4's context-dump quirk keeps it out of the conversation tier.

**3. Evaluation scores.** `regent:evaluation:model` receipts from `model_evaluate` runs carry empirical quality scores. The router ranks candidates by their most recent evaluation score for the relevant tier. Models with no evaluation data are ranked below evaluated ones (unknown quality is a penalty, not a pass).

**4. Fallback history.** `regent:inference:fallback` receipts record which models/endpoints failed recently. The router maintains a sliding window (last N hours) and penalizes models with recent failures. A model that's failed 3 times in the last hour is ranked below one that hasn't failed. This prevents the substrate from repeatedly trying a broken endpoint.

**5. System pressure.** `SystemAwareness` carries memory pressure and loaded models. Under high pressure, the router prefers models that are already loaded in Ollama (no load latency, no additional memory) and smaller models. Under low pressure, it can prefer larger, higher-quality models. This is the harmony principle applied to model selection.

### Routing Tiers: Local vs. Cloud

The router operates across two tiers that compose with the fallback mechanism:

**Local tier (Ollama).** Models pulled locally. Zero latency to start, no auth, no network dependency. Characterized by dossiers. The router has full visibility into what's loaded (`SystemAwareness.loaded_models`).

**Cloud tier (Abacus / OpenAI-compatible).** Models available via API. Higher quality ceiling, but network-dependent, auth-gated, and pay-per-token. The router targets specific models via the `model` field.

The routing decision selects a primary target. If the primary is cloud and fails, the existing fallback mechanism degrades to local. The router doesn't need to handle fallback — it just picks the best primary. Fallback is already structural.

### Cloud Model Registry

For cloud providers that expose multiple models (Abacus), the substrate needs a registry of available models and their characteristics. Two options:

**Option A: Static dossier extension.** Add a `[cloud_models]` section to dossiers for cloud-available models, manually maintained. Simple, but requires operator curation.

**Option B: Discovery + dossier generation.** The Regent periodically queries the provider's model list endpoint (if available), creates provisional dossier entries for new models, and evaluates them against the validation battery. Discovered models start as `untested`; evaluation promotes them to `viable` or `blocked`.

Option A is the right starting shape. Option B is Phase 5's agent swarm territory — the Regent autonomously evaluating new models is exactly the kind of background task that fits the harmony principle.

### Receipt Trail

Routing decisions land on the chain:

```
regent:routing:selected
  category: "conversation"
  model: "qwen3:8b"
  endpoint: "http://localhost:11434"
  rationale: "dossier:recommended + eval:0.94 + loaded:true"
  alternatives_considered: 2
  alternatives_rejected: ["gemma4:26b-mlx (blocked:reasoning)", "qwen3:1.7b (tier:routing_only)"]
```

This receipt is lightweight — emitted only when the routing decision changes from the previous cycle, not on every call. The chain records *decisions*, not telemetry.

---

## Dossier Corpus

The router needs the dossier data at runtime. The corpus is loaded at startup from `models/*/model_dossier.toml` and refreshed when the Regent evaluates a model:

```rust
pub struct DossierCorpus {
    /// All known model families, keyed by family name.
    dossiers: HashMap<String, ModelDossier>,
    /// Cloud models available via configured providers.
    cloud_models: Vec<CloudModelEntry>,
}

pub struct ModelDossier {
    pub family: String,
    pub variants: Vec<String>,
    pub tier_suitability: HashMap<IntentCategory, Suitability>,
    pub quirks: Vec<Quirk>,
    pub bench_scores: HashMap<String, f64>,
    pub inference_config: InferenceConfig,
    pub blocked_tiers: Vec<IntentCategory>,
}
```

The dossier files are the source of truth. The corpus is a runtime projection — same pattern as chain state projected into cockpits. The TOML files are checked into the repo; the corpus is derived.

---

## Integration with Existing Code

### What Changes

1. **`InferenceBackend` gains `route()`.** A new method that takes `IntentCategory` + `DossierCorpus` + `SystemAwareness` and returns `RouteDecision`. The `chat()` method is unchanged — it still takes an `InferenceRequest` with a model field. The caller sets `request.model` from `route()`.

2. **`InferenceRequest` gains `intent_category`.** Optional field. If set, the cognitive loop used `route()` to select the model. If absent (evaluation, explicit targeting), the caller chose directly.

3. **`RegentConfig` gains `dossier_dir`.** Path to the `models/` directory. Default: `{zp_home}/models/` (or compiled-in from the repo).

4. **Cognitive loop calls `route()` before `chat()`.** In `run_cycle()`, after building the inference request and before sending it, the loop calls `route()` to determine the target. The selected model replaces whatever default was in the config.

### What Doesn't Change

- `chat()` — still protocol-neutral, still handles fallback
- `ProviderProfile` — still auto-detects from endpoint URL
- `FallbackEvent` — still captured and drained by the cognitive loop
- Self-configure — still works for explicit model/endpoint changes
- Vault key injection — still the same path

### Migration

The router is additive. Without it, the backend uses the configured model (current behavior). With it, the backend uses the routed model. The config's `reasoning_model` and `routing_model` become the *defaults* — the router can override them with dossier evidence, but falls back to them if no dossier data exists.

This means: deploy router → it does nothing different until dossiers are loaded → load dossiers → routing decisions start appearing on chain → operator reviews and can pin overrides.

---

## Relationship to Execution Authority Model Phases

| Phase | Routing Interaction |
|-------|-------------------|
| Phase 2 (current) | Cloud inference works. Router not yet active. Config determines model. |
| Phase 5 | Router activates. Dossier corpus loaded. `regent:config:inference` receipt is the sovereign override. Model-prompt coupling invariant enforced by the router (blocked dossier tier = blocked prompt variant). |
| Phase 5+ | Regent autonomously evaluates cloud models via agent swarm. Evaluation results feed the corpus. Router ranks cloud models alongside local ones. |
| Phase 7 | Autonomous remediation includes model fallback recovery — Regent detects persistent routing failures via precedent and self-corrects. |

---

## Design Principles

| Principle | Connection |
|-----------|-----------|
| *Signing is gravity* | Routing decisions are receipted. An external router's decision is unsigned; the substrate's routing receipt carries chain authority. |
| *There is no center* | No single model is the center. The router selects from a corpus based on evidence, not configuration. |
| *Every bit counts* | No duplicate model selection paths. One router, one evidence corpus, one decision per call. |
| *Identity is a key, not a location* | A model is identified by its dossier, not its endpoint. The same model family behind different providers is the same family. |
| *Store-and-forward is primary* | Routing evidence is chain-derived. Restart the substrate, the router reconstitutes from dossier files + chain receipts. |
| Cognitive #11 (context assembly is attention) | Intent category IS the attention signal for model selection. Conversation mode routes to the best conversational model; stewardship mode can accept a smaller one. |

---

## What This Doc Does NOT Decide

- **Specific ranking algorithm weights.** The evidence priority order is specified; the exact scoring function will emerge from empirical tuning.
- **Cloud model discovery protocol.** Whether to auto-discover via API or curate manually is a Phase 5+ decision.
- **Multi-model composition.** Routing a single request to multiple models and synthesizing results (ensemble) is future work. The router selects one model per call.
- **Token budget optimization.** Cost-aware routing (prefer cheaper models when quality is sufficient) is a natural extension but not in scope here.

---

*This design was motivated by Ken's observation that farming out the inference optimization function to an external router inverts the substrate's sovereignty. The dossier system already captures model characterization; the evaluation system already produces quality evidence; the fallback system already records failure history. The router composes these into a selection function that the substrate owns entirely.*
