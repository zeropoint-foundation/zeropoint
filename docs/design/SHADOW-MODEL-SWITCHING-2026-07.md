# Shadow-First Model Switching

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.17 (cognitive discipline sandwich), §III.22 (verify before commit), Part VIII (bounded operator sovereignty). Specifies the substrate's model-switching protocol: when an operator requests a model change, the substrate shadow-evaluates the candidate model before cutting over, preserving cognitive continuity on the groomed model until the candidate proves prompt-compatible. Canonical claims live in KEEL.

Draft — 2026-07-13 — internal audience only. Composes with `SHADOW-EVALUATION-PRIMITIVE-2026-07.md` (Context 1 specialization), `INFERENCE-ROUTING-DISCIPLINE-2026-07.md` (routing envelope discipline), `MODEL-DOSSIER-2026-07.md` (the switching ceremony extends to drafter switching under one discipline — a drafter is a serialization of the same characterization, per that spec's §Two serializations, one artifact), `EXECUTION-AUTHORITY-MODEL-2026-07.md` (Phase 5 empirical program), the workflow heuristic *A model and its prompts are an atomic pair; changing one without the other is a half-state.*

## Framing

The operator says "switch to GLM-5.2." Today the substrate hard-cuts: `reconfigure_inference` immediately pins the new model, the next cognitive cycle runs on GLM-5.2, and if that model can't handle the substrate's prompt corpus — can't introspect via `self_configure`, produces context dumps, fails JSON intent parsing, misinterprets officer findings — the operator experiences a silent capability cliff. The Regent doesn't degrade gracefully; she degrades completely. The operator's only recourse is to notice the degradation and manually revert.

This is the model-prompt coupling heuristic violating itself at the operational level. The substrate knows that model and prompts are an atomic pair. It has dossiers that characterize prompt compatibility per model family. It has shadow evaluation as a general primitive. But the `reconfigure_inference` path bypasses all of it — hard cut, no validation, operator absorbs the risk.

The fix: shadow-first switching. The operator's intent ("use GLM-5.2") is honored — the model will be switched. But the *timing* of the switch is gated on evidence that the candidate model handles the substrate's prompt corpus, gathered while the current groomed model remains active.

Three properties frame the protocol:

1. **Operator authority is absolute.** The operator can force-cut at any time. Shadow evaluation is the default path, not a gate the operator cannot override. "Switch to GLM-5.2 now" and "switch to GLM-5.2" produce different behaviors — the first is a force-cut, the second is a shadow-first switch.
2. **The groomed model stays active during evaluation.** No cognitive capability cliff during the shadow phase. Operator interactions are served by the current model. Shadow evaluations run in parallel.
3. **Expectation management is a first-class concern.** The Regent narrates the shadow phase as part of her cognitive presence — not a progress bar, but natural acknowledgment of what's happening: "Running GLM-5.2 through the validation battery — checking prompt compliance, JSON intent parsing, tool dispatch. You're still on Sonnet while I do this." On completion: "GLM-5.2 passed all checks, switching now" or "GLM-5.2 can't produce valid intent envelopes — here's what I saw. Want me to try anyway?" The operator is never left in silence wondering what happened to their request. Evaluation can take time — 30s for a known model, up to 2 minutes for an undossier'd one — and that's fine as long as the operator knows it's happening and isn't degraded in the meantime.

## Pin lifecycle states

The current `OperatorModelPin` has two states: present (pinned) or absent (router scores freely). Shadow-first switching adds a third:

```
           ┌──────────┐
           │  absent   │  ← router scores from dossier corpus
           └────┬──────┘
                │ operator sets model
                ▼
         ┌─────────────┐
         │  evaluating  │  ← shadow phase: current model active,
         │              │    candidate under validation
         └──────┬───────┘
       pass │       │ fail
            ▼       ▼
     ┌──────────┐  ┌─────────────┐
     │  active   │  │  rejected   │  ← findings surfaced to operator
     └──────────┘  └─────────────┘
                         │ operator force-cuts or modifies
                         ▼
                   ┌──────────┐
                   │  active   │
                   └──────────┘
```

The `OperatorModelPin` struct gains a `status` field:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// Shadow evaluation in progress. Current model still active.
    /// candidate_model is what we're testing.
    Evaluating {
        candidate_model: String,
        active_model: String,
    },
    /// Pin is live — this model serves inference.
    Active,
    /// Shadow evaluation failed. Findings available.
    /// Current model remains active.
    Rejected {
        candidate_model: String,
        reason: String,
    },
}
```

## Tiered evaluation depth

Evaluation depth scales inversely with what the substrate already knows about the candidate. A model the substrate has characterized and validated gets a smoke test; a model the substrate has never seen gets a thorough workup. The operator's wait is proportional to the substrate's uncertainty — known models cut over in seconds, unknown models take up to two minutes, and both are fine because the groomed model stays active and the Regent narrates what's happening.

### Tier 1 — Known model with validated prompt compatibility

Dossier exists. `prompt_compatibility.unified_system.status` is `"validated"` or `"validated_shallow"` with passing bench results. The substrate has evidence this model handles the prompt corpus.

Battery: check 3 only (JSON intent envelope). Smoke test — confirm the model still does what the dossier says. Cut-over in ~5–10s.

### Tier 2 — Known model with untested or partial prompt compatibility

Dossier exists but `prompt_compatibility` sections are `"untested"` or mixed. The substrate knows the model's identity and characteristics but hasn't validated prompt handling.

Battery: checks 2–4 (prompt structural compliance, JSON intent envelope, tool dispatch). Standard battery. Cut-over in ~30s.

### Tier 3 — Unknown model, no dossier

No `models/{family}/model_dossier.toml` exists. The substrate has zero evidence about this model. This is the GLM-5.2-on-first-encounter case.

Battery: all 5 checks + auto-dossier generation + a free-form conversational probe (send a chain-context-laden prompt and verify the response is coherent, not a context dump or prompt echo). The substrate generates a minimal dossier from the candidate's self-report and the battery results. Up to ~2 minutes wall-clock. Thorough — the substrate is about to hand its entire cognitive loop to something it has never characterized.

The tier is determined automatically from the dossier corpus at the moment of the switch request. No operator configuration needed.

## Shadow validation battery

The battery is a focused subset of the full model evaluation — only the checks that determine whether the model handles the substrate's existing prompt corpus. Which checks run depends on the evaluation tier (see above).

### Check 1 — Dossier existence

Does a `models/{family}/model_dossier.toml` exist for the candidate? If not, the substrate generates a minimal dossier from web research and the model's self-report (via a single inference call to the candidate asking it to describe itself). This check never fails — it produces a dossier or proceeds without one, noting the gap.

### Check 2 — Prompt structural compliance

Send the candidate model the substrate's `unified_system.md` prompt with a synthetic operator input ("report your current inference configuration") and verify the response:

- Does the model attempt to parse intent as JSON? (routing prompt compliance)
- Does the response avoid context dumps? (prompt interpretation)
- Does the model reference tools available in the prompt? (tool awareness)

Scoring: binary pass/fail per sub-check.

### Check 3 — JSON intent envelope

Send the candidate model the routing prompt with a sample operator input and verify it returns a valid JSON intent envelope:

```json
{"action": "respond", "content": "..."}
```

Not a context dump. Not a raw text response. Not a markdown-wrapped JSON block that fails `serde_json::from_str`. The Regent's `parse_intent` function is the validator — if it can parse the response, the check passes.

### Check 4 — Tool dispatch

Send the candidate model a prompt that should trigger tool dispatch (e.g., "what's my inference config?") and verify it emits a tool call in the expected format. This catches models that understand the prompt but can't produce structured tool invocations.

### Check 5 — Self-configure introspection

Send the candidate model the self_configure tool's schema and a "report status" request. Verify it dispatches the tool. This is the specific check that GLM-5.2 failed in the session that motivated this spec — the model didn't know to use `self_configure` for introspection.

### Battery result

Each check produces a `ShadowCheckResult`:

```rust
struct ShadowCheckResult {
    check: &'static str,
    passed: bool,
    detail: String,
    latency_ms: u64,
}
```

Pass criteria depend on evaluation tier:

- **Tier 1** (known/validated): check 3 must pass.
- **Tier 2** (known/untested): checks 2, 3, and 4 must pass.
- **Tier 3** (unknown): checks 2, 3, and 4 must pass. Checks 1 and 5 plus the conversational probe are informational — failure is surfaced as findings but doesn't block the cut. The auto-generated dossier is updated with all results regardless.

At any tier, the operator can force-cut to bypass all checks.

## Interaction with `reconfigure_inference`

The current `reconfigure_inference` method is the integration point. Two behavioral changes:

### Default path — shadow-first

When `reasoning_model = Some("GLM-5.2")` and no force flag:

1. Record the candidate model and current (active) model.
2. Set `operator_pin.status = PinStatus::Evaluating { candidate_model: "GLM-5.2", active_model: "claude-sonnet-4-6" }`.
3. Emit `regent:config:inference:shadow_start` receipt on chain.
4. Return status JSON with `"status": "evaluating"` and description of what's happening.
5. The Regent's next cognitive cycle sees the evaluating state and spawns the validation battery as a background task.
6. The active model continues serving all operator interactions.
7. On battery completion:
   - **Pass**: set `operator_pin.status = PinStatus::Active`, update config models, emit `regent:config:inference` receipt with the new model, surface "GLM-5.2 validated and active" to operator.
   - **Fail**: set `operator_pin.status = PinStatus::Rejected { .. }`, emit `regent:config:inference:shadow_rejected` receipt, surface findings to operator. Active model unchanged.

### Force-cut path

When the operator explicitly requests immediate switching — detected by phrasing like "switch now", "force", "immediately", or a `force: true` parameter:

1. Hard-cut to the candidate model (current behavior).
2. Set `operator_pin.status = PinStatus::Active`.
3. Emit `regent:config:inference` receipt.
4. No shadow evaluation. Operator accepts the risk.

### Auto path

`model = "auto"` — unchanged. Clears the pin, resets to defaults, router scores freely.

## Chain receipts

Three new receipt types:

```
regent:config:inference:shadow_start
  detail: "candidate=GLM-5.2 control=claude-sonnet-4-6"

regent:config:inference:shadow_result
  detail: "candidate=GLM-5.2 check=json_intent passed=true latency=340ms"
  (one per check)

regent:config:inference:shadow_rejected
  detail: "candidate=GLM-5.2 failed=prompt_structural,tool_dispatch reason=..."

regent:config:inference  (existing — emitted on successful cut-over)
  detail: "reasoning=GLM-5.2 routing=claude-sonnet-4-6 via=shadow_evaluation"
```

## Chain reconstitution of evaluating state

At startup, `spawn_regent` scans for the most recent `regent:config:inference*` receipt:

- If `regent:config:inference:shadow_start` with no subsequent `shadow_rejected` or successful `regent:config:inference` → resume shadow evaluation (re-run the battery).
- If `regent:config:inference:shadow_rejected` → set `PinStatus::Rejected`, surface to operator on first interaction.
- If `regent:config:inference` → normal pin reconstitution (current behavior).

## Dossier auto-generation for undossier'd models

When check 1 finds no dossier, the substrate generates a minimal one:

1. Parse the model name to derive the family (e.g., `GLM-5.2` → `glm5`).
2. If the model is accessible (can be inferred against), send it a self-description prompt: "Describe your architecture, parameter count, context window, and key capabilities in structured format."
3. Parse the response into a minimal `model_dossier.toml` with `[identity]`, `[inference]`, and `[tiers]` sections.
4. Write to `models/{family}/model_dossier.toml`.
5. Load into the dossier corpus.

This auto-generated dossier is marked `[deployment] auto_generated = true` and `chain_validated = false`. The operator or a subsequent evaluation can refine it.

If the model is not accessible (inference fails), the dossier is created with `[identity]` only and all tiers marked `suitability = "untested"`.

## Composition with existing systems

### Inference router

The router's `resolve_model` method already checks operator pin before dossier scoring. The shadow-first protocol adds: when `pin.status == Evaluating`, the router returns the *active* model (the groomed one), not the candidate. The candidate is only used by the validation battery.

### Shadow evaluation primitive

This spec is a specialization of SHADOW-EVALUATION-PRIMITIVE Context 1 for the specific case of operator-initiated model switches. The general shadow evaluation primitive handles ongoing comparative evaluation; this spec handles the one-time transition gate.

### Model dossiers

The validation battery results update the candidate's dossier:

- `[prompt_compatibility.*]` sections updated with pass/fail and notes.
- `[tiers.*]` suitability updated based on battery results.
- `[bench.shadow_validation]` section added with battery results.

### Cognitive Self-Observer

If a shadow-first switch succeeds and the new model is active, the Cognitive Self-Observer's ground-truth verification uses the new model's identity for its checks. The observer can detect post-switch regression that the battery didn't catch — e.g., the model passes structured checks but confabulates in extended conversation.

## Force-cut semantics

The operator's force-cut authority is unconditional. Three ways to force-cut:

1. **Explicit force flag**: `self_configure model=GLM-5.2 force=true`
2. **Phrasing**: "switch to GLM-5.2 right now" / "force GLM-5.2" / "just switch it"
3. **Override during evaluating state**: "I don't care about the checks, switch now"

Force-cut emits `regent:config:inference` with `via=force_cut` in the detail string. The chain records that the operator bypassed validation. No judgment — operator authority is sovereign. But the record enables retrospective analysis: if a force-cut is followed by degraded cognitive performance, the chain shows the correlation.

## What this does NOT do

- **Does not prevent the operator from switching models.** The operator can always force-cut. Shadow evaluation is the default, not a gate.
- **Does not run indefinitely.** The battery is 5 focused checks. Wall-clock time is dominated by inference latency — ~30s for a cloud model, ~5s for a local model. Not a multi-hour evaluation.
- **Does not replace the full model evaluation tool.** `model_evaluate` runs the comprehensive dossier battery. The shadow validation battery is a focused subset: "can this model handle our prompts right now?" not "how does this model compare across all dimensions?"
- **Does not shadow-evaluate routing model changes.** Routing models have a simpler validation: can they produce valid JSON intent envelopes? That's check 3 alone. If the operator changes the routing model, only check 3 runs.
- **Does not compose with the general shadow evaluation primitive's ongoing comparison.** That's a separate mechanism for continuous evidence accumulation. This is a one-time transition gate.

## Implementation scope

### Phase 1 — PinStatus and gating (code change)

1. Add `PinStatus` enum to `regent.rs`.
2. Add `status: PinStatus` field to `OperatorModelPin`.
3. Modify `resolve_model` to check `PinStatus::Evaluating` — return active model, not candidate.
4. Modify `reconfigure_inference` to set `PinStatus::Evaluating` instead of `PinStatus::Active` by default.
5. Add `force` parameter path that preserves current hard-cut behavior.

### Phase 2 — Validation battery (code change)

1. Add `shadow_validation.rs` module to `crates/zp-regent/src/`.
2. Implement checks 2–4 (prompt structural, JSON intent, tool dispatch).
3. Wire battery execution into the cognitive loop — when `pin.status == Evaluating`, run battery before normal cognitive work.
4. On battery completion, update pin status and emit receipts.

### Phase 3 — Dossier auto-generation (code change)

1. Add auto-dossier generation to check 1.
2. Wire into dossier corpus loading.

### Phase 4 — Chain reconstitution of evaluating state (code change)

1. Extend `spawn_regent` chain scanning to handle `shadow_start` and `shadow_rejected` receipts.

### Phase 5 — Operator surface (code change)

1. Update `self_configure` status response to show evaluating/rejected state.
2. Update the "in-memory only" note to reflect chain reconstitution reality.

## Open positions

- **Multi-model shadow evaluation.** Operator requests "try both GLM-5.2 and Gemma4 and tell me which is better." This is the general shadow evaluation primitive's territory, not this spec's. But the validation battery could be extended to compare two candidates against the control.
- **Prompt adaptation.** When a model fails the validation battery, should the substrate attempt to adapt prompts? This connects to EXECUTION-AUTHORITY-MODEL Phase 5 (Regent reads and proposes changes to her own prompts). For now, the substrate surfaces the failure; the operator decides what to do.
- **Routing model shadow evaluation.** Currently scoped to reasoning model changes. Routing model changes only run check 3. Should the routing model get the full battery?
- **Battery extensibility.** Should extensions be able to declare their own shadow validation checks? An extension that depends on specific model capabilities could declare checks that run during the shadow phase.
