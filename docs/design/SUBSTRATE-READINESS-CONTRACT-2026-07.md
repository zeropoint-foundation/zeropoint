# Substrate Readiness Contract

**Document type:** Tier 2 canonical elaboration.
**Elaborates:** KEEL §II.6 (officer signing keys, since readiness receipts are officer-adjacent), §II.10 (composition contracts), §II.13 P4 (every bit counts) and P8 (one canonical path per substrate concern), §III.19 (detectability — silence-is-the-enemy applied to operational readiness), §III.22 (evidence-based ceremony), §III.25 (autonomic coordination — readiness envelope IS how the substrate declares its operational posture).
**Date:** 2026-07-18. Motivated by the sovereignty-provider ↔ vault-key composition drift surfaced during the observer-windows investigation readiness audit.
**Author:** Ken Romero, with synthesis assistance from Claude.
**Status:** Living discipline. Ships alongside the observer-windows investigation; implementation lands as follow-up substrate work referenced by this spec.

---

## Part I — The failure class this addresses

The substrate can be in a state where load-bearing subsystems are silently disabled, and its own diagnostics accept that state as "healthy." Concretely: on 2026-07-18, `zp doctor` reported *"System healthy (4 warnings)"* while three of those warnings each masked a substrate-not-doing-its-job condition — no config file causing Regent to be default-off, vault-key drift disabling all vault operations, listeners hygiene crowding out real signal. Each individual warning was accurate; the composed picture was wrong. The substrate accepted "I'm not doing my job" as a valid state.

This document names the discipline that makes that class of failure structurally rare.

**Failure class characterized:** a load-bearing subsystem enters a degraded or disabled state; no chain-anchored evidence is produced; substrate diagnostics implement their own independent view of readiness that drifts out of coherence with actual subsystem behavior; the operator sees "healthy" while the substrate isn't. The problem is not any individual gap — it is the substrate's tolerance of silence about its own operational state.

**Failure class NOT addressed by this document** (composed with other disciplines):

- Silent-plus-silent failures where no code path knows something is wrong (composes with Cognitive Self-Observer, Claim Verifier, Shadow Evaluation Primitive).
- Delayed failures where subsystem passed boot check but broke later (composes with Chain-Read Canary Discipline, Observer Coherence Discipline).
- Cross-subsystem correctness failures where each subsystem is locally fine (composes with Observer Coherence Discipline).
- Failures in the readiness ceremony itself (composes with Chain-Read Canary applied to the ceremony's own probes).

Honest scope. This discipline covers boot-time and structural-drift silent-gap failures. Composition with the detectability disciplines above covers the rest. A residual remains and is characterized rather than pretended away.

---

## Part II — Four surfaces

The discipline is one thing with four surfaces. Implementation is not four independent projects — they compose or none of them are load-bearing.

### Surface 1 — Readiness envelope

Every subsystem with load-bearing behavior declares a readiness contract: what claims must be true for it to declare itself operational, and what evidence it produces when those claims aren't met.

**Contract shape (Layer B declaration):**

```
subsystem:{name}:readiness_contract
  required_claims:
    - name: string
      how_verified: enum  # config_present | file_readable | key_derives | endpoint_reachable | receipt_present | invariant_holds
      failure_mode: enum  # blocks_operation | degrades_operation | informational
  optional_claims:
    - name: string
      how_verified: enum
      degraded_capability: string  # which capability becomes unavailable if not met
  produces_at_boot:
    - substrate:readiness:{subsystem}:{ok,degraded,blocked}
```

At boot, the substrate composes readiness envelopes from all registered subsystems. The composed envelope becomes a single chain-anchored receipt:

```
substrate:readiness:v0
  substrate_commit: hash
  boot_id: uuid
  timestamp: iso8601
  subsystems:
    - {name, status, claims_verified, claims_failed, degraded_capabilities}
  composed_status: enum  # ready | degraded | blocked
  degradation_summary: [{subsystem, reason, tolerated_by_operator}]
```

**The composed receipt is ground truth for the boot state.** No subsystem announces itself operational without contributing to it. No diagnostic reports substrate state without reading from it.

### Surface 2 — `no_silent_degradation` discipline pin

Any code path that catches an error and continues with reduced functionality MUST emit chain-anchored evidence, not just a log warning.

**Pin invariant:**

> In error-handling paths that permit continued operation (as distinct from panic/exit), a `warn!()` or `error!()` call MUST be paired with a `substrate:degraded:{subsystem}:{reason}` receipt emission before the recovery branch completes. Direct log-only degradation paths fail the pin.

Enforcement: build-time or CI-time lint that scans for `warn!`/`error!` calls in `Err(_) =>` arms and requires an accompanying chain-emission call. Same shape as the discipline pins already in the substrate for singular-sovereign-root and audit-store-access-unification.

**Rationale:** logs are read-time only; they're not chain evidence. A production substrate whose vault-operations are silently disabled with only a log line is a substrate the operator cannot reason about structurally. Making degradation chain-anchored makes it queryable, alertable, and composable with officer findings.

**Exceptions declared explicitly.** Some log-only warnings are correct (e.g., transient network retry that succeeds on retry N). Those declare `#[discipline::exempt(no_silent_degradation, reason = "...")]` at the call site. Exemptions are chain-anchorable themselves via `discipline:exemption:*` receipts, making the exemption corpus reviewable.

### Surface 3 — Functional defaults

A fresh install / no-config-file boot must produce a substrate that does its job. The operator opts *out* of functionality, not *in* to it.

**Default configuration invariants:**

- Officer cadre enabled (Steward, Sentinel, Forge, Cleo). Aegis added when implemented.
- Regent enabled with local inference (Ollama endpoint 127.0.0.1:11434, qwen3 pair — reasoning and routing). Regent-off state is a deliberate operator choice, not a default.
- Chain-read canary discipline enabled (60s cadence).
- Anchor pipeline enabled (NoOpAnchor by default; explicit anchor configuration is opt-in).
- Observation plane enabled at baseline scope (substrate's own footprint).

**Deviation from defaults produces evidence.** Config file present means operator has customized; substrate emits `operator:config:customized <fields_changed>` receipt at boot so the departure from defaults is chain-visible. Config absent means substrate defaults compose into a working system without warnings.

**Composition with `config reflects today, not roadmap`:** the default should reflect today's declared operational goal, not "some operator someday will maybe enable this." A capability that isn't ready to be default-on isn't ready to ship — its config toggle exists for staged rollout, not as a permanent operator burden.

### Surface 4 — Composition tests

When a new capability lands (sovereignty provider, inference provider, ontology projector, extension surface, chain-watcher pattern), a composition matrix declares which existing surfaces it must be verified against. Adding capability without composition verification fails CI.

**Matrix shape:**

```
capability_composition_matrix.toml

[sovereignty_provider]
must_compose_with = [
  "audit_signer",
  "vault_key_derivation",
  "delegation_signing",
  "chain_read_canary",
  "backup_recovery",
]

[inference_provider]
must_compose_with = [
  "regent_cognitive_loop",
  "shadow_evaluation_primitive",
  "model_dossier_validation",
  "cost_budget_discipline",
]

# ... one entry per capability class
```

Adding Trezor as a sovereignty provider (concretely, today's failure case) would have failed the `vault_key_derivation` composition check until the vault-key path was migrated to route through `sovereignty::load_active_genesis_secret()`. The composition test IS the catch mechanism; it operates at capability-addition time, before the code ships.

**When a composition gap is known but tolerated** (e.g., migration in progress), an explicit `capability:composition:known_gap` receipt declares the gap and its remediation window. Composition tests pass if such a receipt exists AND the remediation window is unexpired. This preserves the ability to land staged migrations without failing CI while still producing chain-anchored evidence of the gap.

---

## Part III — How diagnostics compose

`zp doctor` and `zp health` become projections of the composed readiness receipt, not independent implementations of their own check logic.

**`zp doctor` — reads the readiness envelope and renders it operator-friendly.**

- Ground truth: the latest `substrate:readiness:v0` receipt on chain.
- Render: subsystem-by-subsystem status with structured reason for any degraded/blocked state.
- Freshness check: if the readiness receipt is older than the current process start, doctor triggers a fresh readiness ceremony and renders the new receipt.

**`zp health` — narrower, but the same source.**

- Ground truth: same readiness envelope, filtered to load-bearing operational claims only.
- Not an independent check. If it disagrees with `zp doctor`, one of them has a projection bug — never a "which one is right" question.

**Composition with Observer Coherence Discipline:** the diagnostics ARE observers of substrate readiness. Their outputs must agree; divergence between `zp doctor` and `zp health` is caught by the coherence-check pattern that already exists in the substrate for chain readers and vault key listers.

---

## Part IV — Composition with existing disciplines

The readiness contract does not replace existing detectability disciplines. It composes with them, and honest scope requires naming which residual failure classes fall to which discipline.

**Chain-Read Canary Discipline** — periodic post-boot probes. Catches delayed failures where the readiness envelope was accurate at boot but a subsystem drifted afterward. Under the readiness contract, canary findings are chain-anchored evidence that a specific readiness claim (per envelope) no longer holds. They update the operator's projection of substrate state without waiting for the next boot.

**Observer Coherence Discipline** — cross-observer verification. Catches cross-subsystem correctness failures where individual subsystems are locally fine. The readiness envelope is itself an observation; coherence-check applies to it (diagnostics projecting the envelope must agree).

**Cognitive Self-Observer + Claim Verifier** — Regent-emission verification. Catches silent-plus-silent failures where a subsystem doesn't know it's broken. The readiness contract doesn't attempt to cover this class; the cognitive discipline sandwich handles it.

**Shadow Evaluation Primitive** — parallel comparison. Catches silent-wrong-output. Composes at the inference layer, orthogonal to the readiness contract.

**Anchor Pipeline** — Merkle-epoch sealing of chain segments. The readiness ceremony's receipts are chain state and are anchored like any other receipt; no special composition needed.

---

## Part V — What the ceremony looks like at boot

Concrete flow:

1. Process starts. Bootstrap logging is available; nothing else is asserted.
2. Sovereignty provider layer runs (Trezor unwrap, or OS credential store load, or YubiKey PIV, etc.). This produces the singular sovereign root per SOVEREIGNTY-COMPOSITION discipline (see also `VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`).
3. Registered subsystems run their readiness checks. Each verifies its declared claims against actual state; emits per-subsystem readiness receipts.
4. Composer collects per-subsystem receipts, produces the composed `substrate:readiness:v0` receipt, chain-anchors it.
5. The composed receipt is announced via a substrate event; diagnostics subscribing to substrate events refresh their projections.
6. Server accepts operator input. Any operator query about substrate state reads from the readiness envelope.

**If step 3 reveals a blocking-severity claim failure** (a required-claim with `failure_mode: blocks_operation`), the substrate does not proceed to step 6. Instead it enters a `readiness:blocked` state where the only accepted operations are diagnostic queries and remediation ceremonies. Attempting to serve normal operator input from a blocked substrate is architecturally forbidden.

**If step 3 reveals only degraded claims** (all failures are `degrades_operation`), the substrate proceeds to step 6 with reduced capability surface. Requests for degraded capabilities return structured `capability:unavailable:*` responses citing the specific readiness receipt.

**No third path exists.** Substrate is either ready, degraded (with declared capability reduction), or blocked (with no normal operator surface). "Substrate reports healthy but a load-bearing subsystem is off" is not a state that can be reached under this discipline.

---

## Part VI — Verifiable outcomes

The discipline is testable. Concrete claims that must hold post-implementation:

**Claim R1:** at boot, exactly one `substrate:readiness:v0` receipt is chain-anchored. `zp chain query "substrate:readiness"` returns it as the latest boot's readiness envelope.

**Claim R2:** for any subsystem with a declared readiness contract, its per-subsystem receipt exists on chain (`substrate:readiness:{subsystem}:*`) and is cited by the composed envelope.

**Claim R3:** `zp doctor` and `zp health` output derives from the composed envelope. Modifying the envelope (e.g., manually chain-anchoring a `substrate:degraded:test:test_reason` receipt) causes both diagnostics to reflect the change on next projection.

**Claim R4:** no `warn!()` or `error!()` call in a recoverable-error branch exists in the codebase without either an accompanying chain emission or a declared exemption.

**Claim R5:** a fresh install with no config file boots into a state where `substrate:readiness:v0.composed_status = "ready"`.

**Claim R6:** adding a new sovereignty provider (say, a hypothetical `PassphraseProvider`) fails CI until each entry in the `sovereignty_provider` composition matrix has been verified.

Each claim can be checked at CI time or via integration test. Together they characterize the discipline as empirically verifiable.

**Claim R7 (verification of today's specific failure):** applying the discipline retroactively to today's failure — Trezor sovereignty provider added, vault-key derivation not composed — produces `substrate:degraded:vault_key:sovereignty_provider_uncomposed` at boot, `zp doctor` renders it prominently, and cloud-inference tools that require vault decryption return structured `capability:unavailable:vault_key_derivation` rather than mysterious silent failures downstream.

---

## Part VII — What this doesn't decide

- **Which subsystems declare readiness contracts first.** Migration is incremental; the composition matrix declares the order.
- **Blocking-severity policy per subsystem.** Whether "Regent cannot start" is blocking or degrading is per-subsystem judgment; the contract framework accommodates both.
- **Operator override of blocked state.** An emergency operator ceremony to force-start a blocked substrate needs its own spec (composes with `RECOVERY-CEREMONY-UX-2026-07.md`).
- **Cross-substrate readiness federation.** Multi-device fleet coordinates via chain state, but whether one device can serve another's operator queries during blocked-state is a composition question with `MULTI-DEVICE-OPERATION-2026-07.md`.

---

## Composes with / connects to

- **`VAULT-KEY-SOVEREIGNTY-COMPOSITION-2026-07.md`** — motivating case study. Vault-key composition gap is exactly what Surface 4 catches at capability-addition time; retroactively, Surface 1 chain-anchors the current gap.
- **`OBSERVER-WINDOWS-INVESTIGATION-2026-07.md`** — Phase 0 prerequisites become checkable claims under the readiness contract framework once implemented.
- **`CHAIN-READ-CANARY-DISCIPLINE-2026-07.md`** — post-boot verification; composes with readiness ceremony's boot-time claim.
- **`OBSERVER-COHERENCE-DISCIPLINE-2026-07.md`** — diagnostics as coherent observers of the readiness envelope.
- **`SUBSTRATE-COORDINATION-DISCIPLINE-2026-07.md`** — signal-quality-as-coordination-hygiene applied to readiness; the discipline explicitly prevents the runaway-alarm pattern by requiring structured degradation receipts instead of warning floods.
- **`IMPROVEMENT-LOOP-DISCIPLINE-2026-07.md`** — proposed heuristics from this arc (see below) become chain-anchored `heuristic:workflow:*` receipts under the improvement-loop framework.
- **`SUPERSESSION-FRAMEWORK-2026-07.md`** — the readiness envelope's schema (`substrate:readiness:v0`) is versioned; future amendments follow the supersession ceremony.

## CLAUDE.md workflow heuristics this exercises

- *Silence is the enemy, not compromise. Detectability over invulnerability.* — the KEEL invariant this discipline serves.
- *The lsof test: substrate mature when its own footprint is legible.* — extended: substrate mature when its own operational readiness is a chain-anchored claim, not an inferred one.
- *Config reflects today, not roadmap.* — extended: default config reflects the substrate's declared operational goal today, not "someday someone will enable this."
- *Operational configuration with multiple write paths is structural drift waiting to happen.* — applied to diagnostics: `zp doctor` and `zp health` must project from one canonical readiness envelope, never independent check paths.
- *Singular sovereign root: one authentication, everything derived.* — the same shape applied to substrate self-report: one readiness envelope, everything derived.
- *Verify before commit.* — every readiness claim is verified against ground truth before it lands on chain.

## Proposed new heuristic (nomination for CLAUDE.md)

**Substrate operational state is chain-anchored evidence, not inferred silence.**

*If the substrate is in state X, that state must produce a receipt. Absence of a "vault operations enabled" receipt does not permit assuming vault operations work; it permits assuming they don't. Silent-disable is architecturally forbidden; degradation is opt-out with explicit evidence, not opt-in via absent-warning. The operator's mental model of the substrate is trustable only if substrate state is chain-legible.*

*Applies at every layer where a subsystem could be less-than-fully-functional and continue running. Composes with `signing is gravity` (P1) — unsigned degradation is structurally meaningless — and with `store-and-forward is primary` (P5) — the chain survives the process; the process's own log does not.*
