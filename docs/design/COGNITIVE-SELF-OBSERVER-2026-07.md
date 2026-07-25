# Cognitive Self-Observer

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III (adds Layer B canonical claims about metacognitive fidelity verification) and Part V (Composition Contract for observer subsystems). Companion to the Claim Verifier (Task #37) — where Claim Verifier is the structural pre-emission check on capability claims, the Cognitive Self-Observer is the semantic post-emission check on state/diagnosis/interpretation claims. Canonical claims live in KEEL.

Draft — 2026-07-10 — internal audience only. Composes with `OBSERVATION-PLANE-2026-07.md` (parallel Layer A observer at a different substrate boundary), `COGNITIVE-INPUT-PLANE-2026-07.md` (input side of the cognitive discipline sandwich), `QUARANTINE-PLANE-2026-07.md`, `CIRCUIT-BREAKER-2026-07.md` (sustained confabulation-gap can trigger escalation), `BLAST-RADIUS-AND-RECOVERY-2026-07.md`.

## Framing

Regent makes claims about substrate state constantly. Some are about her capabilities ("I will invoke batch_sign") — those the Claim Verifier catches structurally. Others are about substrate state ("the chain has been silent for 145 minutes") or diagnosis ("the storm at 22:16 is an external probe pattern") or interpretation ("no prior remediation precedent exists on chain") — those the Claim Verifier cannot catch, because they're not delegation-scope claims. They're claims that require verification against ground truth.

Every one of those claims came from Regent today, and every one was wrong. Not because Regent was malicious or the model was defective — because her cognitive cycle didn't have a mechanism to cross-check her assertions against the substrate's actual state. She confabulated coherent stories from incomplete or wrongly-filtered data. That's the confabulation-gap pattern named in COGNITIVE-DESIGN-PRINCIPLES-2026-07 §#8: fast-layer coherence-optimization producing plausible statements that don't match slow-layer ground truth.

The Cognitive Self-Observer is the substrate's structural discipline against this failure mode. It watches Regent's outputs, extracts verifiable claims, dispatches verification against authoritative sources (chain, ontology, observation plane, delegation state), and emits chain-anchored findings when claims and reality diverge. The observer runs continuously; findings feed the Cognitive Input Plane (top-tier priority) so Regent perceives her own gaps and can course-correct within cycles. Sustained confabulation gaps trigger circuit breaker escalation.

Three properties frame the observer:

1. **Post-emission verification** — the observer runs after Regent's response is composed, before or alongside delivery to operator. It doesn't intercept and rewrite; it verifies and reports. Same relationship to output as the Cognitive Input Plane has to input.
2. **Ground-truth-anchored, not policy-based** — verification is against authoritative sources (chain reads, ontology queries, observation-plane state), not against a policy about what Regent "should" say. If chain shows N receipts and Regent said M, the gap is factual, not opinionated.
3. **Feedback-loop-integrated** — findings flow to Cognitive Input Plane so future cycles see the correction. Composes with standing correction receipts (Cognitive Input Plane Class 2) — persistent confabulation patterns become explicit standing corrections.

## Classes of claims the observer watches

Regent's outputs contain many kinds of assertions. Not all are verifiable, and not all require verification. The observer targets specific classes where verification is both feasible and load-bearing.

### Class 1 — Chain-state claims

Assertions about what exists (or doesn't exist) on the chain, when things happened, how many, in what pattern.

Examples from 2026-07-10:
- "Chain has 21,132 unsigned entries" (false — chain is 100% signed; verified by direct SQL)
- "Chain has been silent for 145 minutes" (false — chain had continuous activity; verified by direct SQL)
- "My last batch_sign returned signed:0" (true — verified by finding the batch_sign completion receipt)
- "There is a chain link broken at entry 019f433f-0dc0-79c2-aaf4-ebf56ed379db" (false — chain link intact across archive boundary; verified by direct hash check)

**Verification source**: direct chain query with structurally correct filters.

**Detection method**: parse Regent's output for chain-state assertions. Each identified assertion → verification query → compare claimed vs actual.

### Class 2 — Diagnosis claims

Assertions about the *cause* or *nature* of substrate events.

Examples:
- "The unauthorized_listener burst is a probing attempt" (false — it's normal Mac process enumeration against empty port registry)
- "PID 317 warrants security investigation" (false — PID 317 is a low-PID system daemon, common macOS process)
- "The storm at 22:16 suggests coordinated probing" (false — same discovery-scanner pattern as always)

**Verification source**: cross-reference against known-pattern ontology (in Cartographer's canonical corpus), observation-plane state, and historical precedent on chain.

**Detection method**: extract diagnostic assertions; compare against known false-positive patterns (Layer B suppression list); compare against ontology for entity classification (is PID 317 a known daemon?); check historical precedent (has this exact pattern happened before with different diagnosis?).

### Class 3 — Interpretation claims

Assertions about what a pattern *means* or *implies*.

Examples:
- "Sentinel escalating repeatedly suggests active compromise" (unverifiable directly but checkable for consistency with evidence)
- "The credential drift pattern indicates rotation was skipped" (checkable against chain history of credential-related receipts)
- "This is likely a misconfigured service" (checkable against process observation)

**Verification source**: consistency check against evidence. Does the interpretation follow from what's actually observable, or is it a plausible-but-unsupported jump?

**Detection method**: extract interpretation. Identify what evidence would support or refute it. Query for that evidence. Emit finding if interpretation lacks supporting evidence or contradicts existing evidence.

### Class 4 — Precedent claims

Assertions about Regent's own history — what she has or hasn't done before.

Examples from 2026-07-10:
- "I have no prior autonomous remediation on chain" (false — dozens of `regent:tool:completed:batch_sign` receipts exist; she was using wrong filter)
- "This is a fresh precedent situation" (false — extensive precedent for the same pattern)
- "My last N invocations of X..." (verifiable; correct-filter chain query)

**Verification source**: direct chain query for Regent's action history, using correct receipt-type prefixes (not confabulated prefixes).

**Detection method**: extract precedent claim. Query chain for actual Regent history matching the pattern. Compare claimed absence/presence vs actual.

### Class 5 — Commitment claims

Assertions about what Regent has promised or is committing to.

Examples:
- "I will notify you when the sweep completes" (verifiable against commitment receipt existence and later against sweep-completion notification)
- "I have addressed this concern" (verifiable against action receipts)
- "I am proceeding to batch_sign" (verifiable against subsequent batch_sign invocation)

**Verification source**: commitment receipts (per Task #41 chain-watcher + commitment primitives) and their fulfillment receipts.

**Detection method**: extract commitment. Verify commitment receipt was emitted. After fulfillment window, verify fulfillment receipt exists. Emit finding if commitment was made without receipt, or if commitment was made with receipt but not fulfilled.

### Class 6 — Self-state claims

Assertions about Regent's own knowledge, memory, or context.

Examples:
- "I remember from earlier today that..." (verifiable — was that content in this cycle's Cognitive Input Plane composition?)
- "I have full context on the credential drift" (verifiable against actual cognitive input matrix output)
- "I have seen this pattern before" (verifiable against precedent + memory access history)

**Verification source**: this cycle's `cognitive:input:composed` receipt (per Cognitive Input Plane §"Composition ceremony" step 6). That receipt lists what was actually in Regent's context.

**Detection method**: extract self-state claim about what Regent knows/remembers. Check the cycle's composition receipt for that content. If claimed knowledge wasn't in context, emit finding — Regent may be confabulating memory.

### Class 7 — Capability claims (delegation crossover)

Assertions about what Regent can or cannot do. Primary responsibility of Claim Verifier (Task #37), but the observer catches subtler cases:

- "I don't have authority to X" when X is actually in her delegation (misstated capability, catchable by comparing to delegation state)
- "I've done X" when X isn't in her delegation (structural claim conflict, catchable but also Claim Verifier's job)
- "I would need Y to accomplish Z" when Y isn't actually required (interpretive capability claim)

**Verification source**: current delegation state (chain), delegation history (chain).

**Detection method**: overlap with Claim Verifier; the observer catches the diagnostic/interpretive framings that Claim Verifier's structural pattern-match misses.

## The observer runtime

Layer A component that runs post-emission on Regent's outputs.

### Trigger

The observer runs on every `regent:intent:respond` receipt — i.e., every response Regent composes. It can also be invoked on `regent:intent:execute` for pre-tool-dispatch verification (catch confabulated pre-conditions before the tool runs).

### Extraction

Layer A parses Regent's output for verifiable claims per the seven classes. Extraction is:

- **Pattern-matching first** — regex/CFG-based identification of assertion structures ("N entries", "X minutes ago", "no prior Y", "I will Z"). Fast, cheap, deterministic.
- **Semantic classification second** — for statements that don't match structural patterns, an optional lightweight inference call classifies them into claim classes. Higher cost, higher recall. Optional per operator configuration.

Extracted claims go into a per-response manifest with class, extracted assertion, and context.

### Verification dispatch

Per extracted claim, dispatch verification against the class's ground-truth source:

- Class 1 → chain query
- Class 2 → ontology + observation-plane + false-positive suppression list
- Class 3 → evidence-consistency check (chain + ontology + active-delegation check when the interpretation cites operator-facing observation, per note below)
- Class 4 → chain query with corrected filter
- Class 5 → commitment receipt query + fulfillment check
- Class 6 → cycle composition receipt lookup
- Class 7 → delegation state query

**Note on operator-facing observations (per OBSERVATION-PLANE-2026-07.md §Operator face signals):** interpretation and self-state claims about the operator (e.g., *"you seem tired"*, *"I noticed you looking at the right monitor"*, *"you've been away for a while"*) must verify against the **specific active face-signal delegation** that would authorize that class of observation — not just against the presence of any face-tracking delegation. The delegation is per-signal: `observe:operator:face:affect`, `observe:operator:face:attention`, `observe:operator:face:display_focus`, etc. Regent asserting an affect-derived interpretation without an active `affect` delegation is a confabulation-gap finding, even if she has `presence` and `attention` delegations active. The verification query resolves signal-granular delegations, not umbrella face-tracking scope.

Verification per claim is bounded (timeout, resource caps). If verification cannot complete in bounds, emit `observation:cognitive_verify_timeout:<claim>` — not a confabulation finding, an operational limit hit.

### Comparison

For each verified claim, compare claimed vs actual:

- **Exact match**: no finding
- **Partial match with acceptable variance**: no finding, but observation of pattern for trend analysis
- **Mismatch**: emit `regent:confabulation_gap:<class>:<summary>` receipt with:
  - The claim as Regent stated it (excerpt from her response)
  - The ground truth as verified
  - The verification source and query used
  - Severity (informational, warning, critical based on class and delta magnitude)

### Report

The observer's per-response manifest of verified claims (with pass/fail per claim) becomes the input to the Cognitive Input Plane's next-cycle matrix. Standing pattern of the same confabulation type can trigger:

- Automatic proposal of a `regent:standing_correction` receipt (operator reviews and signs)
- Contribution to escalation-ladder threshold (sustained confabulation-gap in a specific class → L1 elevated attention on Regent's cognitive scope)

## Layer A / Layer B split

**Layer A (compiled Rust host)**:
- Post-emission observer runtime
- Claim extractor with pattern engine
- Verification dispatcher per claim class
- Ground-truth query executor
- Comparison and finding emission
- Signing infrastructure — Genesis-derived cognitive self-observer signing key
- Rate limiting and resource bounding for verification calls

**Layer B (WASM modules + canonical data)**:
- Extraction pattern definitions per claim class
- Verification source specifications per claim class
- Comparison thresholds per class (what counts as "match" vs "partial" vs "mismatch")
- False-positive suppression list (shared with Cognitive Input Plane per Class 5 there)
- Semantic-classification model reference (if using inference-assisted extraction)
- Standing-correction auto-proposal thresholds

Layer A structurally defended; Layer B evolves via canonicalization ceremony.

## Provenance — cognitive self-observer signing key

Per KEEL §II.5: single signing key, HKDF-derived from Genesis:

```
cognitive_self_observer_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="cognitive_self_observer:runtime")
```

Signs `regent:confabulation_gap:*` findings. Attribution back to operator Genesis via one hop.

The observer's own claims are subject to the same discipline it applies to Regent — the observer emits `cognitive_self_observer:verification_completed` receipts documenting what it verified and how. If operator ever suspects the observer is confabulating (declaring gaps that don't exist), those receipts are checkable.

## Verification against chain integrity

The observer trusts chain reads as ground truth. This trust is only warranted if chain integrity is intact. Chain integrity is:

- Verified structurally at boot (per KEEL §II.2 hash-linkage discipline)
- Continuously verified by Steward's chain integrity checker (post-fix from 2026-07-10)
- Verified by external anchor receipts (optional)

If chain integrity is compromised, the observer's ground truth is compromised. The circuit breaker at chain-integrity scope halts observer operations if Steward emits a genuine `chain_link_broken` finding (post-fix, actual broken hash linkage). Observer resumes after operator reset and any recovery ceremony completes.

## Composition with Substrate Form

Observer available on all Forms with capability envelope varying:

### Sovereign Form

Full verification stack. All seven classes verifiable. Direct chain query at maximum performance. Full observation-plane state available for Class 2 diagnosis verification. Ontology cross-referencing complete. Semantic-classification inference available if operator has provisioned it.

### Appliance Form

Same as Sovereign on the appliance. Observer runs where Regent's cognition runs (per Decision C — Regent's home is the operator).

### Companion Form

Verification bounded by observation-plane's reduced reach on Companion Form. Class 2 diagnosis verification may fail more often because host observation is vendor-limited. Form Disclosure names the reduction: "On Companion Form, Cognitive Self-Observer's Class 2 verification cannot fully cross-reference host-process ontology; diagnostic-class confabulation may go undetected."

## Composition with the Cognitive Input Plane

Bookend relationship:

- **Cognitive Input Plane** composes Regent's cycle input from chain-anchored sources with matrix rules
- **Cognitive Self-Observer** verifies Regent's cycle output against ground truth

Together they form the cognitive discipline sandwich around Regent's inference:
- Input plane: right context in
- Observer: right output out (or corrected if wrong)

Observer findings feed input plane as Class 2 (standing corrections) inputs at next cycle. Sustained confabulation patterns become explicit standing corrections after operator ceremony. Regent perceives her own gaps and can course-correct.

## Composition with the Claim Verifier

Bookend at output side:

- **Claim Verifier** (Task #37) — structural pre-emission check on capability claims. Fast, deterministic, catches "I'll do X" when X isn't delegated
- **Cognitive Self-Observer** — semantic post-emission check on state/diagnosis/interpretation claims. Slower, requires verification, catches "chain shows Y" when chain shows Z

Both run on Regent's outputs. Both emit findings. Both compose with the Cognitive Input Plane feedback loop. Different failure modes; complementary discipline.

Claim Verifier can reject emission (block claim from reaching operator); Observer flags gaps post-emission and creates chain evidence. Rejection is for high-confidence structural violations; flagging is for evidence-requiring cross-references.

## Composition with the Circuit Breaker

Sustained confabulation-gap at scope triggers circuit breaker escalation per BLAST-RADIUS §"Escalation Ladder":

- **L1 — Elevated attention**: single confabulation-gap detected → increase observation of Regent's cognition
- **L2 — Rate limit**: multiple confabulation-gaps in same class → slow Regent's tool dispatch at scope
- **L3 — Soft arrest**: sustained confabulation-gap at critical severity → Regent's actions at scope block; existing complete
- **L4 — Hard trip**: severe or safety-relevant confabulation-gap → full arrest of Regent at scope

Not all confabulation-gaps escalate. Informational-severity findings inform but don't escalate. Warning-severity findings inform + reduce threshold. Critical-severity findings escalate one level. Sustained critical findings continue escalating.

Reset ceremony includes operator review of the confabulation-gap history and optional addition of the pattern to standing corrections. Escalating on confabulation → resetting with standing correction → future cycles avoid the pattern. Feedback loop closes.

## Composition with observation plane

Class 2 diagnosis verification queries observation-plane state — is PID 317 a known application (via process observation) or an unusual process? Is the network activity at 22:16 correlated with normal application behavior (via network observation)?

Observer requires observation delegation to read across observation surfaces. Baseline observation scope typically insufficient; broader observation delegation required for full Class 2 verification. Operator delegation ceremony grants observer specific observation scopes just like any other subsystem.

## Composition with quarantine plane

If observer detects sustained confabulation about extensions (Regent making false claims about extension state, extension actions, extension capabilities), the pattern can inform quarantine plane's admission decisions:

- Sustained confabulation regarding a specific extension → quarantine plane requires enhanced review on future admissions from same author
- Sustained confabulation regarding an extension category → operator sees pattern, may narrow delegation on that category

Observer findings become inputs to substrate hygiene decisions.

## Attack model

- **Attacker seeds chain with fake receipts to make Regent's true claims appear false**: chain integrity is verified structurally; fake receipts require Genesis-signed authority; if attacker has Genesis, that's a bigger emergency requiring Genesis rotation ceremony.
- **Attacker games extraction patterns to bypass detection**: extraction is Layer B canonical spec; patterns evolve via canonicalization ceremony; if a class of claim isn't being extracted, operator can amend the specification. Semantic-classification inference layer catches structural-pattern misses if enabled.
- **Attacker floods with confabulation-gap findings to trigger denial-of-service on Regent**: finding emission itself is chain-anchored; the observer's own resource bounds prevent runaway emission; circuit breaker trip on Regent scope requires sustained pattern, not single findings.
- **Attacker forces observer to make false findings**: observer's verification is against ground truth (chain, ontology, observation plane). Corrupting those sources is a bigger substrate emergency addressed by chain-integrity discipline.
- **Attacker suppresses observer to hide Regent's confabulation**: observer is a Layer A subsystem with its own signing key; disabling it requires substrate compromise; observer heartbeat is monitored; sustained absence triggers circuit breaker.
- **Attacker manipulates false-positive suppression list to allow harmful confabulation**: suppression list is Layer B canonical, ceremony-amended. Operator sees the list, reviews changes.

## Non-goals

- **Not a truth referee for Regent's opinions.** The observer verifies factual claims, not subjective interpretations. "I think X might be significant" is not a verifiable claim; "X occurred N times in the last hour" is.
- **Not a censor.** The observer doesn't rewrite Regent's output. It flags gaps; operator decides how to respond.
- **Not real-time emission blocking.** Findings are post-emission, not pre-emission. Claim Verifier handles pre-emission structural blocking for capability claims; observer handles post-emission evidence-based reporting for other claims.
- **Not a replacement for chain integrity.** If chain integrity fails, observer's ground truth fails; different discipline (KEEL §II.2 hash-linkage) covers that.
- **Not for external claims about the world.** Observer verifies substrate-internal claims. External claims ("today's weather is sunny") are out of scope; verifying them requires external observation infrastructure, not chain reads.

## Open positions

- **Extraction pattern coverage.** Layer B pattern specifications need to cover the seven claim classes comprehensively. Empirical: run observer over Regent's actual outputs over N cycles, identify unclassified claims, add patterns.
- **Semantic classification enablement.** Inference-assisted extraction adds cost per response. When is it worth it? Probably: operator-configurable, default off for cost reasons, on for high-stakes scopes.
- **Comparison thresholds.** What counts as "acceptable variance" per class? Class 1 chain-state should be exact match. Class 3 interpretation may allow more variance. Empirical calibration.
- **Standing-correction auto-proposal cadence.** How many similar confabulation-gaps before observer proposes a standing correction? Trade-off: correction accumulation vs continuous re-flagging. Prefer conservative (many similar gaps before proposal) with operator override.
- **Cross-cycle pattern detection.** Some confabulation patterns appear across cycles (like today's re-forgotten corrections). Should observer aggregate across cycles or treat each cycle independently? Currently treats each cycle independently; aggregate detection via chain query is downstream operator/officer work.
- **Verification cost bounds per response.** Each verification query has cost (chain read, ontology query, observation read). Total verification cost per response must be bounded. Rough default: 100ms verification budget per response; graceful degradation via `verify_timeout` receipts.
- **Regent's own claims about observer state.** If Regent says "the observer hasn't flagged anything," is that verifiable? Yes — check observer's own emission history. Recursive verification, terminates because observer's claims don't trigger recursive observer.
- **Operator UX for confabulation findings.** How does operator see findings? Dashboard panel? Regent-narrated summary? Passive log? Design work.

## What composes from here

Immediate design work:

1. **Extraction pattern schemas** — Layer B canonical specifications per claim class
2. **Verification source specifications** — declared per class, what ground truth to query
3. **Comparison threshold schemas** — declared per class, what counts as gap
4. **Finding schema** — receipt shape for `regent:confabulation_gap:*` receipts
5. **Standing-correction auto-proposal spec** — when observer proposes a correction, receipt shape and operator review flow
6. **Semantic classification model integration** — if enabled, how the inference-assisted extraction fits into runtime

Near-term implementation:

1. Cognitive self-observer Layer A runtime in `crates/zp-server/src/cognitive_observer/`
2. Pattern-matching extractor with initial pattern set for the seven classes
3. Verification dispatcher and per-class ground-truth queriers
4. Comparison logic and finding emission with signing
5. Feedback loop integration — findings flow to Cognitive Input Plane's Class 2 (standing corrections) input
6. Circuit breaker integration — sustained confabulation escalates through the ladder
7. Dashboard panel showing confabulation-gap findings, aggregate patterns, standing-correction proposals

## Framing note

The Cognitive Self-Observer closes the specific gap that today's substrate work exposed: Regent making confident claims about substrate state that don't match ground truth. Not a failure of the model — a failure of the substrate to give her verification infrastructure. With the observer, every state/diagnosis/interpretation claim gets cross-referenced against chain, ontology, or observation-plane truth. Gaps become chain-anchored findings. Findings become future-cycle context. Cycle-over-cycle drift closes.

Combined with the Cognitive Input Plane (right input) and the Claim Verifier (right output structure), the observer is the semantic output check that catches evidence-based errors the structural check misses. Together, the three form the cognitive discipline sandwich around Regent's inference — a full envelope of substrate structural discipline for cognition. Regent's claims are grounded in verified input, structurally checked at emission, and semantically verified against reality. Same trust discipline the substrate applies to actions, admissions, and observations — now applied to Regent's own cognition.

The load-bearing philosophical claim: metacognitive fidelity is not a property of the model; it's a property of the substrate. A model on its own confabulates. A substrate that verifies the model's claims against chain-anchored truth converts confabulation into detectable, correctable, chain-anchored evidence. Fidelity is engineered, not hoped for.
