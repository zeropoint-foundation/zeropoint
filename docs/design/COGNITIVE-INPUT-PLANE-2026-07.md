# Cognitive Input Plane

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III (adds Layer B canonical claims about Regent's cognitive input composition) and Part V (Composition Contract for Regent's context). Canonical claims live in KEEL; this doc provides implementation-level detail and design rationale.

Draft — 2026-07-10 — internal audience only. Composes with `OBSERVATION-PLANE-2026-07.md` (parallel Layer A plane at chain→Regent boundary, mirror of external→chain), `QUARANTINE-PLANE-2026-07.md` (quarantine receipts as top-tier priority inputs), and the emerging Circuit Breaker spec (breaker state as top-priority input during trip).

## Framing

Every long-running cognitive agent hits the same failure: it re-forgets corrections that "should be" in scope, because those corrections aren't structurally at the top of its attention. The correction lives somewhere — in previous conversation, in operator memory, in the model's training data — but the model's actual cognitive cycle doesn't reliably re-load it. Each cycle starts fresh, and the same errors recur.

This was directly observed with Regent on 2026-07-10. Operator corrected specific patterns (unauthorized_listener bursts are normal, not attacker probes; chain_query filter format is `regent:tool:completed:*` not `regent:remediation:*`; credential probing belongs to Forge not Regent's cognitive layer). Within cycles, Regent held the corrections. Between cycles, she re-forgot them and repeated the errors. Not a model failure — a *context ordering* failure. Corrections were nowhere in her structured cycle input.

The cognitive input plane is the substrate's structural discipline against this failure mode. Regent's cognitive input is not "whatever information happens to be lying around at cycle start" — it's a structured, priority-ordered composition of chain-anchored sources, assembled by a signed runtime according to a signed matrix specification. Standing corrections, active precedent, and relevant substrate state get top-tier positions in her prompt. Officer noise gets filtered. The composition itself is chain-anchored evidence of what Regent was given to reason with.

Three properties frame the plane:

1. **Priority ordering IS signal.** What appears at the top and bottom of Regent's context window gets weight; middle content gets scraps. Adding information to her context doesn't help if the added information gets buried behind noise. Ordering, not accumulation, is the mechanism.
2. **Chain-anchored composition, not cognitive-cycle memory.** Standing corrections and other persistent context live on the chain as receipts, not in Regent's own memory. Between cycles, memory can lose them; chain-anchored receipts survive.
3. **Symmetric with the observation plane.** The observation plane feeds the chain from the world; the cognitive input plane feeds Regent from the chain. Same architectural family; inverted direction.

## The composition matrix

Regent's cycle input is composed from six source classes, each with a declared priority tier, fetch cadence, filter criteria, and displacement rule.

### Class 1 — Identity and core principles (Tier 0, static)

Compact identity block: Regent's role, current sovereign operator, active Form, current substrate build hash, the nine design principles as compact reference.

- **Priority**: Tier 0 — always first, always present, cheap.
- **Fetch cadence**: Static per boot; refreshed on canonicalization ceremony affecting KEEL identity claims.
- **Filter**: None — identity is invariant per cycle.
- **Displacement**: Never displaced.

### Class 2 — Active standing corrections (Tier 1, chain-loaded)

Chain-anchored `cognitive:correction:standing` receipts that are currently active. Emitted when operator corrects Regent's behavior in a way that should persist across cycles. Each carries a `correction_type` (`factual | boundary | prohibition | preference`), a hierarchical `domain`, and full content/scope/expiry per the canonical schema in `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md`. Correction identity is by `correction_id` (content hash), not by pattern name in the receipt type.

- **Priority**: Tier 1 — immediately after identity, before anything else.
- **Fetch cadence**: Every cycle, fresh from chain.
- **Filter**: Active only (not-expired, not-superseded). All active corrections included.
- **Displacement**: Never displaced unless expired or superseded.

Example active corrections (each is a `cognitive:correction:standing` receipt; the phrase after the arrow identifies the correction; the `correction_type` and `domain` shown are what would appear on the receipt itself):
- *discovery_listener_storm* (`correction_type: factual`, `domain: substrate.factual.discovery_scan_pattern`) — "unauthorized_listener bursts against empty port registry are normal Mac process enumeration, not probing; do not recommend PID termination based on this pattern"
- *chain_query_filter_format* (`correction_type: factual`, `domain: cognitive.tool_usage.chain_query`) — "chain_query filter matches receipt action event keys directly; use `regent:tool:completed:batch_sign` not `regent:remediation:` for finding your prior batch_sign actions"
- *credential_probing_authority* (`correction_type: boundary`, `domain: cognitive.boundary.credential_probing`) — "credential probing belongs to Forge/observation-plane executor tier; vault values must never enter cognitive-layer context"

### Class 3 — Recent precedent (Tier 1, chain-loaded)

Regent's own recent actions and their outcomes. Composes with the act-on-precedent-escalate-on-novelty heuristic — she can reason from her own history without confabulating precedent when queries return empty.

- **Priority**: Tier 1 — same tier as standing corrections, presented after them.
- **Fetch cadence**: Every cycle, fresh from chain.
- **Filter**: Last N cycles (default N=20) of `regent:tool:completed:*` and `regent:intent:*` receipts.
- **Displacement**: Older precedent aged out when the N-window rolls forward.

Structured as: action → outcome → chain receipt hash. So Regent sees "at time T I invoked batch_sign, it returned signed:0, receipt <hash>." Concrete, not abstract.

### Class 4 — Active commitments (Tier 1, chain-loaded)

Regent's outstanding chain-anchored commitments — `regent:commitment:notify_on:*`, `regent:commitment:check_at:*`, etc. — that she has promised to honor.

- **Priority**: Tier 1 — same tier, presented after precedent.
- **Fetch cadence**: Every cycle.
- **Filter**: Active only (not-completed, not-superseded).
- **Displacement**: Removed when completed or superseded.

Purpose: her promises to operator survive cycle boots because they're on the chain, not in cognitive memory.

### Class 5 — Filtered officer findings (Tier 2, chain-loaded)

Recent officer findings, with known false-positive patterns suppressed. Substrate maintains a canonical filter set (in Layer B) declaring which patterns are known noise.

- **Priority**: Tier 2 — after Tier 1 context, before operator input.
- **Fetch cadence**: Every cycle.
- **Filter**: Substrate false-positive patterns suppressed. Deduplication window applied (same finding within N minutes collapses to one entry).
- **Displacement**: Older findings displaced by newer ones within the window.

Filter examples (Layer B canonical records):
- `officer:std:integrity:chain_link_broken` (currently a known false positive per Task #32 — fixed at source but historical receipts filtered until compaction rolls them out)
- `officer:sen:security:unauthorized_listener` when correlated with empty port registry (discovery-scan noise)
- Repeated identical findings within 10-minute window collapse

### Class 6 — Operator's current directive (Tier 3, immediate)

What the operator is asking Regent right now. The most recent operator message + any operator-supplied context.

- **Priority**: Tier 3 — after all context, closest to output (recency bias territory).
- **Fetch cadence**: Provided directly at cycle invocation.
- **Filter**: None — operator input arrives as-is.
- **Displacement**: Replaced by next operator input.

### Class 7 — Substrate state snapshot (Tier 2, computed)

Current substrate state Regent needs to reason about: memory pressure, active delegations, active circuit-breaker trips, recent chain activity summary, current Form and its capability envelope.

- **Priority**: Tier 2 — same tier as officer findings.
- **Fetch cadence**: Every cycle, computed fresh.
- **Filter**: None — factual state.
- **Displacement**: Replaced every cycle.

### Priority tier summary

Order of presentation in Regent's prompt (top to bottom):

1. **Tier 0**: Identity and core principles (static reference)
2. **Tier 1**: Standing corrections, recent precedent, active commitments (chain-anchored persistent state — what she must remember across cycles)
3. **Tier 2**: Filtered officer findings, substrate state snapshot (current context — what she's reasoning about)
4. **Tier 3**: Operator's current directive (what she's being asked to do)

Both ends of the context window get the recency-bias weight LLMs give to prompt boundaries. Tier 0 anchors identity; Tier 3 anchors action. Tier 1 and Tier 2 populate the interior with structured priority, not random accumulation.

## Layer A / Layer B split

The plane spans both layers per SUBSTRATE-EXECUTION-ARCHITECTURE-2026-07.md.

**Layer A (compiled Rust host)**:
- Cycle invocation runtime — the code that runs at each Regent cycle boot
- Composition observer — reads matrix specification, fetches sources per matrix rules, composes prompt
- Chain readers per class — extractors that pull standing corrections, precedent, commitments, findings, state from chain
- Filter dispatcher — applies filter criteria per class
- Prompt template renderer — produces final prompt string per matrix layout
- Signing infrastructure — Genesis-derived cognitive input plane signing key
- Emits `cognitive:input:composed` receipt with matrix version, class-source hashes, and composition summary per cycle

**Layer B (WASM modules + canonical data)**:
- Matrix specification records — the canonical declaration of what goes where at what tier with what filter
- Filter policy modules — WASM implementations of filter criteria per class
- Chain-source query modules — per-class WASM that extracts the relevant subset from chain
- Prompt template records — the canonical structure of the prompt Regent receives
- False-positive suppression list — the Layer B canonical record of known noise patterns

Layer A is structurally defended. Layer B evolves via canonicalization ceremony. Adding a new source class, changing filter policy, updating suppression list — all Layer B, all ceremony-amendable.

## The composition ceremony

Every cycle boot emits a chain-anchored composition receipt so the substrate has evidence of what Regent was given to reason with.

### Step 1: cycle invocation

Substrate schedules a Regent cycle. This can be:
- Operator directive (operator sent a message)
- Chain event subscription firing (per Task #41 — chain-watcher + commitment-receipt primitives)
- Scheduled commitment firing
- Circuit-breaker state transition requiring Regent perception

### Step 2: matrix fetch

Composition observer reads the current matrix specification from Layer B canonical spec. Verifies matrix signature per canonicalization ceremony. Applies any Form-specific matrix adjustments (per Substrate Form composition below).

### Step 3: source dispatch

Per matrix rules, dispatch source fetches concurrently:
- Identity block from local static
- Standing corrections from chain (query for active `cognitive:correction:standing` receipts, filtered by not-expired and not-superseded)
- Precedent from chain (last N `regent:tool:completed:*` and `regent:intent:*`)
- Commitments from chain (active `regent:commitment:*`)
- Officer findings from chain (recent + filtered per suppression list)
- Substrate state from live substrate state
- Operator directive from cycle invocation payload

### Step 4: filter application

For each source class, apply the declared filter. Known false positives suppressed. Duplicates collapsed. Aged content displaced.

### Step 5: prompt composition

Per prompt template, render final prompt string. Tier 0 first, Tier 1 next, Tier 2 following, Tier 3 last. Structured with clear delimiters so Regent's model can attend to each tier appropriately.

### Step 6: composition receipt

Emit `cognitive:input:composed` receipt with:
- Matrix version hash
- Per-class source content hashes
- Suppressed-filter application record
- Final prompt hash (structural, not content — for correlation, not for chain bloat)
- Cycle invocation reason

Chain now has evidence: at time T, Regent was given input composed of sources A, B, C with matrix version M. If later she claims something wasn't in her context, the chain shows what was.

### Step 7: dispatch to inference

Prompt handed to the inference backend (currently Claude Sonnet 4.6 via Abacus RouteLLM; will be GLM 5.2 or others under CloudMandate). Regent's response comes back and enters its normal handling (tool dispatch through gate, response to operator, etc.).

## Provenance — cognitive input plane signing key

Single signing key per plane, HKDF-derived from Genesis:

```
cognitive_input_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="cognitive_input:matrix")
```

Signs the `cognitive:input:composed` receipt each cycle. Attribution to Genesis via one hop.

Additionally, the matrix specification itself is chain-anchored via canonicalization ceremony. Amendments to the matrix (adding source classes, changing filters, updating suppression list) require operator Genesis signature. So the composition rule set is also directly accountable to Genesis.

## Composition with Substrate Form

Matrix behavior varies by Form due to different available sources and different substrate capabilities.

### Sovereign Form

Full matrix. All source classes available. Standing corrections, precedent, commitments all chain-anchored on operator-controlled storage. Officer findings unfiltered by vendor constraint (may still be substrate-filter suppressed). Substrate state snapshot includes full host-body proprioception from observation plane.

### Appliance Form

Full matrix on appliance. Daily-driver-client can request Regent invocation but the composition happens on the appliance where the operator's Genesis and full chain live. Client sees the composed prompt (for display), not the source material.

### Companion Form

Matrix subset — some sources bounded by vendor permissions. Substrate state snapshot has Companion-Form-limited observation reach. Chain-anchored sources (corrections, precedent, commitments) all still work — they're on the local chain regardless of Form. Officer findings work but with Companion-Form-limited observation input. Form Disclosure names the reduction.

## Composition with the observation plane

The two planes are structurally symmetric:

- Observation plane: external state → chain (via signed observation receipts)
- Cognitive input plane: chain → Regent's context (via signed cognitive input composition)

The observation plane feeds the substrate's memory of the world; the cognitive input plane feeds Regent's cognitive input from that memory. Both planes are default-restrictive (baseline scope for observation; matrix-declared for input), Genesis-derived (per-class or per-plane signing keys), chain-anchored (every operation emits receipts).

Observation plane provides the substrate state snapshot input class. Cognitive input plane composes it with the other classes according to the matrix.

## Composition with the quarantine plane

Quarantine receipts are matrix inputs to the substrate state snapshot class. When Regent's cycle boots, she perceives:
- Currently admitted artifacts and their delegation scopes
- Recent admission ceremonies (for precedent — "operator recently admitted extension X with capabilities Y")
- Pending quarantine (artifacts awaiting operator delegation ceremony)
- Recent verification failures (for anti-pattern awareness)

So Regent's reasoning about capability delegation naturally composes with the quarantine discipline. She knows what the substrate has admitted, what it has rejected, and what's pending review.

## Composition with the circuit breaker

Circuit-breaker state is a top-tier priority matrix input during a trip. When a breaker is tripped at scope X, the matrix injects at Tier 1:

- `circuit:tripped:<scope>` with trip reason, trigger source, time
- Scope-affected content stripped from Tier 2 (Regent doesn't reason from data at the tripped scope)
- Explicit note in prompt: "Scope X is tripped; you cannot operate here until operator resets."

Regent perceives the emergency state immediately, cannot claim to act at the tripped scope (Claim Verifier per Task #37 would catch this), and can help the operator diagnose. She does not attempt reset — that's operator ceremony only.

## Composition with the Claim Verifier

Claim Verifier (Task #37) inspects Regent's *output* against her delegation. The cognitive input plane composes her *input* against her delegation. Bookends of the same discipline:

- Cognitive input plane: gives Regent the right context to reason from
- Claim Verifier: catches when her output claims capabilities she doesn't have

Both use the same delegation-truth source; both are structurally enforced; both compose with the act-on-precedent heuristic. Together they form the "cognitive discipline sandwich" — right input, right output, structural enforcement at both ends.

## Attack model

Real threats and how the plane addresses them:

- **Malicious standing correction from compromised operator key**: standing corrections are chain-anchored, Genesis-signed. Compromise of Genesis key is a broader emergency (Genesis rotation ceremony); the plane inherits Genesis security.
- **Regent context poisoning via unfiltered officer noise**: false-positive suppression list is Layer B canonical spec, ceremony-updated. New known-noise patterns get added to the list; Regent's context stays clean.
- **Standing correction expiry manipulation**: expiry is part of the correction receipt; substrate observes and drops expired corrections. If an attacker could manipulate expiry, they'd have chain-write access which is a bigger problem.
- **Precedent injection**: precedent comes from Regent's own signed action receipts. Faking precedent requires forging Regent's signing key, again a bigger problem.
- **Matrix specification corruption**: matrix is chain-anchored via canonicalization ceremony. Corruption requires ceremony bypass or key compromise; standard KEEL invariants apply.
- **Race condition between cycles**: cycles are serialized per Regent (only one active presence per Decision C). No parallel cycles competing for the same matrix.
- **Denial of context**: attacker floods chain with fake corrections to displace real ones. Corrections are operator-signed; only genuine operator corrections count. Fake ones fail signature check.
- **Regent perceiving its own compromised state**: when circuit breaker trips on cognitive-self-observer (Task #38), the matrix injects the breaker state as top-tier priority. Regent perceives her own arrest immediately.

## Non-goals

- **Not a memory system.** The plane doesn't give Regent persistent memory in the traditional sense. It gives her structured cycle input drawn fresh from chain each time. Memory-per-se lives on the chain (and in the memory/CLAUDE.md system for the operator's shared context); the plane just brings the relevant chain-anchored state into her context at proper priority.
- **Not a policy engine.** The matrix declares what goes where at what priority; operator policies about *what patterns to correct* live in Layer B canonical corrections. Plane implements composition; operator declares corrections via chain-anchored ceremony.
- **Not a summary generator.** The plane composes chain-anchored source material into Regent's prompt with structural priority. It does not summarize, paraphrase, or generate meta-analysis. Raw material at proper priority.
- **Not model-specific.** The matrix works with any model (Sonnet 4.6, GLM 5.2, others). Model-family prompts (per model-prompt coupling heuristic) sit at the Tier 0 identity block; matrix mechanics are the same.

## Open positions

- **Prompt token budget management.** Total prompt size is bounded by model context window. When budget is tight, which class gets truncated first? Rough default: Tier 2 substrate-state-snapshot degrades first (least essential); Tier 0 identity never degrades.
- **Correction expiry defaults.** Should standing corrections expire by default (say, 30 days) requiring operator to renew, or persist indefinitely? Trade-off: correction accumulation vs continuous operator burden.
- **Precedent aging curve.** N=20 recent cycles is a starting number. Empirical work to find the right window.
- **False-positive suppression governance.** Who can add patterns to the suppression list, and via what ceremony? Currently operator-signed canonicalization. Should officers be able to propose suppressions via a specific ceremony type?
- **Cross-Form matrix consistency.** Should the matrix be identical across Forms, with Form-specific behavior emerging from source availability? Or Form-specific matrix variants? Prefer the former for simplicity; watch for cases requiring the latter.
- **Interaction with Claim Verifier feedback loop.** If Claim Verifier catches Regent making a claim she can't back, should that emit an implicit standing correction? Or wait for operator to formalize it? Probably wait — auto-correction accumulation is a slippery slope; operator ceremony keeps the discipline explicit.
- **Prompt structure format.** Delimiter conventions for tier boundaries. XML-style tags (`<tier priority="1">`)? Markdown headers? Natural language section markers? Depends on model preferences; may be model-family-specific.

## What composes from here

Immediate design work:

1. **Matrix schema** — Layer B canonical spec for the matrix specification (source class × priority tier × cadence × filter × displacement rule × prompt template layout).
2. **Standing correction receipt schema** — canonical spec lives in `STANDING-CORRECTION-RECEIPT-SCHEMA-2026-07.md` (receipt_type: `cognitive:correction:standing`; discriminating `correction_type` field; hierarchical `domain`; content/scope/expiry/supersedes; operator signature).
3. **False-positive suppression list schema** — Layer B canonical spec for suppression patterns.
4. **Prompt template layout** — how tier boundaries render, how each class formats within a tier.
5. **Regent-facing prompt structure changes** — the Regent unified system prompt (currently in `crates/zp-regent/prompts/unified_system.md`) needs adjustment to expect the new composition; identity block becomes Tier 0, standing corrections + precedent + commitments get Tier 1 placeholders.
6. **Chain-source query modules** — Layer B WASM modules per class extracting the relevant subset from chain.

Near-term implementation:

1. Composition runtime at Regent cycle boot in `crates/zp-server/src/regent/` — reads matrix, dispatches source fetches, applies filters, composes prompt, emits composition receipt.
2. Standing correction chain-write path — operator command `zp regent correct <pattern> <text>` emits the signed receipt.
3. Precedent extractor — utility querying Regent's own action receipts within the sliding window.
4. Suppression list bootstrap with the known-false-positive patterns identified today (chain_link_broken, unsigned_entry_ratio, unauthorized_listener + empty registry, discovery-scan storm signature).
5. Layer B matrix specification record with initial six source classes.

## Framing note

The cognitive input plane closes the specific gap that Regent's re-forgetting exposed. Standing corrections and self-precedent live on the chain as receipts, not in Regent's cognitive memory. Every cycle they're pulled to the top of her context via signed matrix rules. The composition itself is chain-anchored evidence, so if she claims not to have known something, the chain shows what she was given.

Combined with the observation plane (evidence of what the substrate is seeing) and the quarantine plane (evidence of what the substrate is admitting), the cognitive input plane completes a triadic Layer A composition family — each a boundary discipline, each default-restrictive or default-composed by signed rules, each Genesis-derived. Same architectural family; three different substrate concerns. The substrate now has proper structural discipline at every trust boundary it maintains.
