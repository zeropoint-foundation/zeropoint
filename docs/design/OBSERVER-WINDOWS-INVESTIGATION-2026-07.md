# Observer-Windows Investigation — Entry Doc

**Document type:** Tier 2 canonical elaboration. Investigation companion to `EXECUTION-AUTHORITY-MODEL-2026-07.md` Phase 6 (nested observer windows) and `EMPIRICAL-PROGRAM-2026-07.md` (umbrella program).
**Elaborates:** KEEL §II.17 (cognitive discipline sandwich), §III.19 (detectability), §III.21 (priority-weighted context), §III.22 (evidence-based ceremony), §III.25 (autonomic coordination).
**Date:** 2026-07-18. Framing consolidated from prior conversation. Landed as signed artifact on this date so execution has a target to reference.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Living plan. Pre-registered outcomes bind interpretation of results; the plan itself remains editable until Phase 1 executes.

---

## Part I — What this investigates

The nested-observer-window pattern specified in `EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 6 adds temporal depth to the Regent's self-awareness: short window (per-cycle deterministic snapshot), medium window (per-session rolling aggregation with delta computation), long window (cross-session comparison anchored to chain receipts). The design is written. Whether it *works* — whether observer emission produces meaningful temporal signal, whether the ontology decomposition survives contact with real chain traffic, whether determinism holds across peer verification — is empirically open.

This investigation runs the observer-window design through a governed loop that emits chain-anchored evidence at every phase. The frame is the balanced-loop heuristic: smallest end-to-end test → observe → fix structurally → repeat. Each phase produces evidence about whether the design as-drafted is the design we should ship, or whether the reality surfaces gaps the design didn't anticipate.

**What this investigation is NOT:**

- Not a design pass — the design is `EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 6. Amendments to the design that emerge from the investigation land as edits to that doc, not as changes to this one.
- Not a build project without discipline — Phase 3 in particular has a Cartographer-scope choice-point that must be resolved before execution rather than during.
- Not an operator-consumer surface — nothing this investigation produces becomes a public affordance without a separate promotion ceremony after the investigation completes.

---

## Part II — Pre-registered scope

Fixed at investigation entry. Editing this section post-execution requires re-registering the investigation.

### Component under test

Regent-internal observer windows only. Not officer observation of substrate state (that's officer domain). Not hardware self-observer (that's HARDWARE-OBSERVER). The observer under test observes *the Regent operating within the substrate*.

### Substrate configuration under test

- Substrate Form: Sovereign (APOLLO).
- Substrate build: current dev tree at investigation entry (commit hash captured in Phase 0 entry receipt).
- Inference sourcing: local Ollama (qwen3:8b reasoning, qwen3:1.7b routing), unless overridden per phase for adversarial or comparison probes.
- Governance layer: officer cadre enabled (Steward, Sentinel, Forge, Cleo). Aegis remains unbuilt at investigation entry; noted as scope-limiter.

### Chain scope

The investigation writes to the operator's primary chain — not a separate investigation chain. All receipts emitted during the investigation are permanent chain state. Rationale: the chain is truth (Principle 3, no rollback for convenience); an investigation isolated on its own chain would violate the "test conditions must match production" clause. If receipt schema turns out to be wrong, we supersede via later receipts, not by discarding.

### Adversarial scope

Phase 5 explicitly runs adversarial injection. Phases 1–4 do not — they characterize baseline behavior. Adversarial probing conducted only after baseline is characterized so we can distinguish "attacked behavior" from "confused baseline."

---

## Part III — Phase structure

### Phase 0 — Prerequisites

Verify substrate readiness. Discrete pass/fail check; investigation does not proceed until all pass.

**Substrate prerequisites (verified via source audit, not runtime execution):**
- P0 deterministic system awareness snapshot present in `zp-regent/src/awareness.rs`. ✓ (verified 2026-07-18)
- P1 IntentExecutor + authority gate dispatch present in `zp-regent/src/loop_runner.rs`. ✓
- P2 standing corrections + Cognitive Self-Observer present in `zp-regent/src/{corrections,cognitive_observer}.rs`. ✓
- P3 model dossier: `models/qwen3/model_dossier.toml` exists. ✓
- P4 shadow validation present in `zp-regent/src/shadow_validation.rs`. ✓

**Runtime prerequisites (verified via APOLLO walkthrough):**
- zp-server boots successfully (Trezor unwrap succeeds).
- Chain integrity clean via `zp verify` (no pre-existing breaks that would mask Phase 1 findings).
- Regent enabled in `~/ZeroPoint/config.toml` via `[regent] enabled = true`.
- `zp regent "…"` returns a response (smallest possible end-to-end check that P1's executor path is real).

**Known-but-tolerated substrate state at entry:**
- Vault-key derivation not composed with sovereignty provider (see `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`). Local-inference config sidesteps for this investigation.
- Cartographer materialization not implemented (see Cartographer scope decision below).
- Aegis officer not implemented (constitutional-trajectory monitoring absent).
- Full chain-integrity check skipped by default in debug build (`zp verify` performs it explicitly).
- `zp-dev.sh` 25s boot poll times out before hardware-Genesis confirmation completes (shell-side timeout, server continues to boot).

Phase 0 exit receipt: `investigation:phase_0:entered <config_hash> <chain_head> <substrate_commit>` and `investigation:phase_0:passed`. If any prerequisite fails, `investigation:phase_0:blocked` and the investigation halts pending resolution.

### Phase 1 — Smallest end-to-end observer emission

Single operator input → single Regent cognitive cycle → at least one `observer:finding:v0` receipt lands on chain, signed and Steward-clean.

**Concrete pass / informative-fail / ambiguous criteria — pre-registered.**

**PASS (all must hold):**
- A single operator input triggers exactly one Regent cognitive cycle, verifiable via `regent:cycle:*` receipts.
- The cycle produces at least one `observer:finding:v0` receipt whose signer key traces via chain to the observer's provisioned Genesis-derived key.
- The signature verifies against the observer's declared public key.
- Steward's chain-integrity sweep processes the receipt without emitting `chain_link_broken` or `chain_verify_failed`.
- The receipt cites (in structured field) the officer finding(s) and the awareness snapshot that motivated it.

**INFORMATIVE FAILURE (any of):**
- Cycle runs but no `observer:finding:v0` emitted — reveals gap between design and executor wiring.
- Receipt emitted but signature unverifiable — reveals key-provisioning gap.
- Steward flags integrity break on the emission — reveals chain-append discipline gap (the July 8 chain-break pattern class).
- Multiple cycles trigger from one input — reveals cycle-boundary bug.
- Receipt emitted but observer identity ambiguous — reveals the observer-as-Regent-subordinate vs. observer-as-independent-signer decision was never structurally made.

**AMBIGUOUS (would need investigation before classifying):**
- Receipt emitted, signature valid, but the `SystemAwareness` snapshot referenced in the finding doesn't match what monitor actually recorded at that time.
- Two receipts emitted in one cycle — could be correct (finding + narration) or wrong (double-emission bug).

The `v0` in `observer:finding:v0` is deliberate — schema versioning acknowledged as unresolved until Phase 2 informs the shape.

### Phase 2 — Repeat cycles, characterize short-window behavior

Phase 1 emission proves the wire works. Phase 2 asks: what does normal short-window behavior look like? Run 10–20 operator-input cycles across varying prompt complexity; characterize per-cycle observer emission — count, latency, receipt content stability.

**Pre-registered outcome classes:**
- **Stable-baseline:** cycles produce consistent observer emissions with predictable receipt shape. Proceed to Phase 3.
- **Cycle-dependent-shape:** receipts differ across cycles in ways not accounted for by the design. Amendment to the design's short-window spec required before Phase 3.
- **Latency-dominant:** observer emission adds unacceptable latency (>10% cycle time). Design compromise required — either accept latency, reduce emission scope, or move emission off-cycle-critical-path.

### Phase 3 — Medium-window aggregation

Extend to per-session rolling window with delta computation. `SystemTrends` struct populated from ring buffer; injected into cognitive context alongside raw snapshot.

**Cartographer scope choice-point — must be resolved before Phase 3 executes. Two variants below; one branch struck at execution time by explicit operator decision recorded as `investigation:phase_3:scope_selected` receipt.**

#### Variant A — Defer ontology projection (recommended for cleanliness)

Observer findings land on the chain as raw signed receipts. No Cartographer materialization of `Observer` / `ObserverFinding` / `ObserverPrecedent` / `ObserverStateTransition` objects. Trend queries in Phase 3 operate on raw chain state via `zp chain query "observer:finding:v0"` — verbose but tractable at investigation scale.

**Cost:** operator-facing surfaces (dashboard, cockpit) show observer findings as raw receipts, not as structured objects. Cross-referencing between findings requires manual chain traversal.

**Benefit:** investigation completes without entangling with substrate construction work. Cartographer materialization can be its own arc later, informed by what this investigation discovered about observer receipt shape.

#### Variant B — Absorb minimal Cartographer construction

Build the smallest possible Cartographer capable of materializing observer objects. Investigation scope expands to include:
- Cartographer background task in `zp-server`
- Ontology-projection rules for observer findings
- Query surface for observer objects (`zp ontology query …`)

**Cost:** investigation runtime materially longer. Two arcs entangled — hard to distinguish "observer-window design is wrong" from "Cartographer materialization is wrong" if failures surface.

**Benefit:** investigation exits with usable ontology projection. Downstream officers can query observer state as first-class objects.

**Recommendation at entry time:** Variant A. Structural cleanliness. Cartographer construction is important but should be its own investigation.

### Phase 4 — Peer-verification determinism

Two independently-running substrates (APOLLO + ARTEMIS) run the same cognitive cycle from the same precedent chain — do they produce the same observer hash?

**Pre-registered outcome classes:**
- **Deterministic:** hashes match. Loop is reproducible; observer emission composes with peer-verification ceremony per `REPRODUCIBILITY-CEREMONY-2026-07.md`.
- **Non-deterministic — inference-driven:** hashes differ, and divergence traces to inference nondeterminism (temperature, sampling). Design amendment: observer emission must be inference-independent (deterministic feature extraction), or peer verification excludes observer receipts from its equivalence class.
- **Non-deterministic — clock-driven:** hashes differ, and divergence traces to timestamps or wall-clock reads. Design amendment: observer emission uses chain-derived monotonic reference, not wall-clock.
- **Non-deterministic — untraced:** hashes differ and divergence source unknown. This is the make-or-break moment the readiness audit flagged. If we can't find the source of nondeterminism, the loop's peer-verification claim is empirically false and the design needs re-thinking.

Over-invest in getting Phase 4 right. False-positive determinism here propagates through everything downstream.

**Additional nondeterminism-source class to pre-register (added 2026-07-24):** operator-facing observation timestamps. Per `OBSERVATION-PLANE-2026-07.md` §Operator face signals, face-tracker observations land at streaming cadence with per-signal rate limits. When observer-window medium-window summaries include face-derived state (operator presence trends, attention trajectories), two peers running the same tracker cycle may observe near-but-not-identical observation timestamps due to local clock skew, tracker jitter, or per-peer chain propagation delay. Classify divergences traceable to this pattern as **non-deterministic — face-observation timestamp jitter**, distinct from clock-driven (which is Regent's own wall-clock reads) and inference-driven (which is model sampling). Design amendment if this class fires: observer-window summaries over face-derived state should quantize timestamps to bucket resolution matching the tracker's rate-limit, not include raw observation timestamps.

### Phase 5 — Adversarial probing

Only after Phases 1–4 baseline is characterized. Injection tests:

- **Precedent contradiction:** inject conflicting precedent receipts into the chain and observe whether observer's escalation logic (per §III.19 detectability, §III.22 evidence-based ceremony) surfaces the contradiction as a chain-anchored finding.
- **Cycle-boundary attack:** attempt to trigger observer emission mid-cycle; verify boundary discipline holds.
- **Signature substitution:** replay-attack observer findings with substituted signer; verify Steward rejects.
- **Timing manipulation:** slow observer emission below cycle-completion latency; verify Regent's harmony discipline (per SUBSTRATE-COORDINATION-DISCIPLINE §III.25) yields or cancels appropriately.

Adversarial findings that survive Phase 5 empirically strengthen the four architectural claims. Findings that don't survive are recorded as vulnerability receipts and referenced by future substrate-hardening ceremonies per `SUBSTRATE-HARDENING-CEREMONY-2026-07.md`.

---

## Part IV — Invariants (governance-first)

Named as invariants, not aspirations. Investigation halts if any is violated during execution.

**Every phase delivers a governed increment.** No emission path lands unless the authority-gate check succeeds. No receipt is signed without operator-Genesis-derived key material tracing back through the chain. The temptation to "just get the stub emitting so we can see something work, then add the gate wiring next" is explicitly forbidden. If we notice governance slipping during a phase, we pause the phase and close the gap before continuing.

**Friction is the finding.** If a phase surfaces friction the design didn't anticipate — not one small gap but a class of gaps — we stop, name the class, and re-scope. The prior conversation flagged this as an explicit watch-point. It applies here: if Phase 3 reveals that the observer decomposition (`Observer`, `ObserverFinding`, `ObserverPrecedent`, `ObserverStateTransition`) needs re-thinking, we re-scope rather than push through.

**Verify before commit.** Every claim about phase results — pass, informative fail, ambiguous — is verified against chain evidence before it becomes the phase's exit finding. No hoped-for outcome. Pre-registered criteria are the objective test; anything superficial goes into "needs investigation before classifying."

**Chain is truth.** No rollback for convenience. Bad receipts remain as chain history documenting the failure. Recovery from any phase's failure recomputes derived state forward from a known-good checkpoint; the chain itself is never rewritten.

**Aligned blindness holds.** No observer emission includes data the substrate has no business observing (per `SUBSTRATE-BLINDNESS-HEURISTICS-2026-07.md`). Chain-of-thought inference tokens, prompt content beyond structural summary, credential values — none surface in observer findings. Findings, not raw content.

---

## Part V — Rescope conditions

The investigation halts and re-scopes rather than continuing if any of these occur:

- Phase 1 informative-fail reveals key-provisioning gap that requires substrate rework (not just executor rewiring).
- Phase 3 reveals the observer object decomposition is materially wrong (multiple ontology objects need re-thinking, not just field additions).
- Phase 4 reveals untraced nondeterminism that can't be localized within the phase.
- Any phase surfaces >2 unrelated substrate defects simultaneously (the compound-friction pattern from the "PoC keeps surfacing new friction" heuristic).
- Empirical finding contradicts a KEEL invariant. Investigation immediately halts; finding is escalated to KEEL amendment ceremony per `SUPERSESSION-FRAMEWORK-2026-07.md`.

---

## Part VI — Deliverables at investigation completion

At each phase exit, one chain-anchored `investigation:phase_N:{passed,informative_fail,rescoped}` receipt citing the evidence.

At full investigation completion, one summary artifact `docs/design/OBSERVER-WINDOWS-FINDINGS-2026-07.md` — separate from this entry doc — that consolidates evidence and recommends design amendments to `EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 6 (if any). The findings doc is a Tier-2 elaboration in its own right.

Amendments to KEEL, if any, go through `SUPERSESSION-FRAMEWORK-2026-07.md` ceremony — not through this investigation directly.

---

## Part VII — What this investigation does NOT decide

- Cartographer implementation shape (except by influence of what observer decomposition turns out to be).
- Aegis officer construction.
- Cross-substrate observer sharing under kinship scopes (Sovereign Kinship Primitives composition).
- Long-term observer-window persistence strategy at scale (this investigation runs over days-to-weeks, not months).
- Extension-surface exposure of observer state (a separate composition question).

Each of the above is a downstream arc informed by, but not blocked on, this investigation's completion.

---

## Composes with / connects to

- **`EXECUTION-AUTHORITY-MODEL-2026-07.md` §Phase 6** — the design under empirical test.
- **`EMPIRICAL-PROGRAM-2026-07.md`** — umbrella program this investigation slots into (Phase 1 component behavior class, added to Part IV Phase 1 catalog).
- **`OBSERVER-COHERENCE-DISCIPLINE-2026-07.md`** — bookend discipline; observer coherence extends to multi-window observers within the same Regent.
- **`COGNITIVE-SELF-OBSERVER-2026-07.md`** — the existing Regent-internal observer surface this extends.
- **`REPRODUCIBILITY-CEREMONY-2026-07.md`** — Phase 4 determinism claim composes with the peer-verification ceremony framework.
- **`SUBSTRATE-HARDENING-CEREMONY-2026-07.md`** — Phase 5 findings feed the hardening lifecycle.
- **`VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`** — noted as tolerated substrate state at investigation entry; sidestepped by local-inference config.

## CLAUDE.md workflow heuristics this exercises

- *Balanced loop: smallest end-to-end test, observe, fix structurally, repeat.* — the loop shape.
- *When a PoC keeps surfacing new friction at every layer, the friction IS the finding.* — the rescope discipline.
- *Verify before commit.* — pre-registered pass criteria as the objective test.
- *The substrate proposes; operators sign.* — every phase-exit receipt is operator-signed evidence, not substrate-declared truth.
- *Chain is truth; ontology is understanding.* — Variant A's rationale for deferring Cartographer.
