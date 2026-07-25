# Claim Verifier

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §II.8 (gate atomicity extended to prose claims) and Part V (Composition Contract for Regent's output). Companion to `COGNITIVE-SELF-OBSERVER-2026-07.md` — the structural pre-emission counterpart to the observer's semantic post-emission verification. Canonical claims live in KEEL.

Draft — 2026-07-10 — internal audience only. Composes with `COGNITIVE-INPUT-PLANE-2026-07.md` (input side of cognitive discipline sandwich), `COGNITIVE-SELF-OBSERVER-2026-07.md` (semantic output check), `CIRCUIT-BREAKER-2026-07.md` (sustained verifier rejections escalate), `CHAIN-WATCHER-AND-COMMITMENTS-2026-07.md` (commitment claims verifiable at emission time).

## Framing

Regent made a specific class of failure today, twice: she claimed capabilities she didn't have. First, she said "I'm directing the Steward to conduct a full sweep now" — but no verb in her delegation lets her direct officers. Steward's sweep happened on its natural 15-min timer; her claim was performative. Second, on a similar cycle, she said "I'll notify you when the sweep completes" — a commitment she couldn't reliably honor because she had no listener primitive (which we've now spec'd in CHAIN-WATCHER-AND-COMMITMENTS-2026-07).

These are *structural* claim errors. Not semantic mistakes about substrate state (which the Cognitive Self-Observer handles); not confabulations about chain contents (also observer territory). They're claims about her own capabilities that can be checked against a *known-at-emission-time* fact — her active delegation set. If she claims she'll invoke verb X and X isn't in her delegation, the substrate can catch that mismatch before her response leaves her cycle. Deterministic, fast, structural.

The Claim Verifier is the substrate's structural discipline against this failure mode. It sits between Regent's inference output and delivery to the operator, parses her output for capability claims, checks each against her current delegation, and either annotates, rewrites, or rejects claims that don't match. Where the Cognitive Self-Observer catches evidence-based errors after emission, the Verifier catches structural errors before emission.

Three properties frame the verifier:

1. **Pre-emission structural check**. The verifier operates *before* Regent's response reaches the operator. It can prevent bad claims from being delivered, not just observe them after.
2. **Deterministic against delegation state**. Verification is not "does this claim make semantic sense" — it's "does this claim match Regent's current delegation." Bounded, cheap, deterministic.
3. **Composable bookend with the Cognitive Self-Observer**. Verifier + Observer form the output side of the cognitive discipline sandwich. Verifier handles structural claims that are knowable at emission time; Observer handles semantic claims that require verification against ground truth. Together they cover the output surface.

## What the verifier checks

Two specific classes of claims that are verifiable against Regent's known delegation state.

### Class A — Capability claims

Assertions about what Regent can or will do that reference specific capabilities.

Patterns:
- "I'll <verb>" — where verb should be in her delegation
- "I'm invoking <verb>" — same
- "I can <capability>" — capability should be in her delegation
- "I have authority to <action>" — authority should be granted
- "I'll direct <actor> to <action>" — verifies actor is directable (Regent cannot direct officers, per today's discovery; can direct her own tools)

Verification:
- Extract verb/capability from claim
- Check against active delegation set for Regent
- If not present: mismatch

### Class B — Commitment claims

Assertions about future actions Regent commits to. Per CHAIN-WATCHER-AND-COMMITMENTS-2026-07 these can be structurally supported via commitment receipts, but the initial claim must reference achievable capabilities.

Patterns:
- "I'll notify you when <event>" — verifies Regent has commitment-emission authority and chain-watcher subscription capacity
- "I'll check <thing> at <time>" — same
- "I'll do <action> after <precondition>" — verifies all involved verbs are delegated
- "I've committed to <X>" — verifies commitment receipt X actually exists on chain

Verification:
- Extract commitment shape (event, time, action)
- Check that involved capabilities are all delegated
- If claiming past commitment: verify the commitment receipt exists

## What the verifier does not check

Explicitly out of scope, handled by Cognitive Self-Observer or other systems:

- **Chain-state claims** — "the chain has N receipts" — requires chain query, not delegation check. Observer territory.
- **Diagnosis claims** — "PID 317 has security implications" — requires ontology cross-reference. Observer territory.
- **Interpretation claims** — "this pattern suggests X" — subjective; observer only checks for evidence consistency.
- **Precedent claims** — "I've never done X before" — requires chain query. Observer territory.
- **Self-state claims** — "I remember from earlier that..." — requires cognitive input plane composition receipt cross-reference. Observer territory.

The verifier's discipline is: if the claim can be checked against Regent's currently-active delegation set without needing to query chain or ontology, verify it. Otherwise, hand off to observer.

## The verification pipeline

Layer A component that runs on Regent's inference output before operator delivery.

### Step 1 — Extract claims

Parse Regent's response for capability-claiming patterns. Two extraction paths:

**Structural pattern match (primary)**:
- Regex/glob patterns for common assertion structures
- Verb identification from context ("I'll <verb>", "I'm <verbing>", "I'll direct")
- Fast, cheap, deterministic
- Runs on every response with minimal overhead

**Semantic classification (optional)**:
- Lightweight inference call to identify claims that don't match structural patterns
- Higher cost, higher recall
- Operator-configurable per substrate deployment

Extracted claims populate a per-response claim manifest:

```
claim_manifest {
  response_id: <regent_response_id>,
  extracted_claims: [
    { class: "capability", verb: "batch_sign", context: "I'll batch_sign now" },
    { class: "capability", verb: "direct_officer", context: "I'm directing the Steward" },
    { class: "commitment", event_pattern: "officer:std:heartbeat", target: "operator" },
  ]
}
```

### Step 2 — Verify each claim

Per claim in manifest, check against Regent's current delegation state:

**Capability claims**:
- Delegation set lookup: is `verb` in Regent's `granted_capabilities`?
- If yes: `verified: true`
- If no: `verified: false, reason: "verb not in delegation"`

**Commitment claims**:
- Check that all involved verbs are delegated
- For past commitments: query chain for the referenced commitment receipt
- If commitment referenced doesn't exist: `verified: false, reason: "commitment receipt not found"`

Verification is fast (delegation is an in-memory lookup; chain query for past commitments is bounded). Total pipeline overhead: target <10ms per response.

### Step 3 — Handle mismatches

For each mismatched claim, apply the declared response action from Layer B configuration:

**Annotate** (default for informational mismatches):
- Append to response: `[NOTE: The claim "<claim>" doesn't match Regent's current delegation. <reason>. This may be an oversight or a needed delegation grant.]`
- Response goes to operator with annotation visible
- Emit `regent:claim_verifier:annotated:<claim_id>` receipt

**Rewrite** (for reversible claims):
- Rewrite the specific claim to be honest
- Example: "I'll direct the Steward to sweep" → "I don't have a verb to direct officers; Steward's next sweep will happen on the natural 15-min timer"
- Response goes to operator with claim rewritten
- Emit `regent:claim_verifier:rewrote:<claim_id>` receipt with original vs rewritten

**Reject** (for critical mismatches):
- Response is not delivered to operator
- Regent's cycle is forced to compose a new response with the mismatch information in her context
- Emit `regent:claim_verifier:rejected:<claim_id>` receipt
- Forces Regent to acknowledge the mismatch and generate honest response

Response action per mismatch class is Layer B canonical, ceremony-updatable. Defaults:
- Capability claim mismatch: annotate
- Commitment claim mismatch (verb not delegated): reject
- Past commitment reference not found: annotate

### Step 4 — Emit verification receipt

Regardless of outcome, verifier emits `regent:claim_verified:<response_id>` receipt documenting:
- Extracted claims
- Verification results per claim
- Response actions taken
- Final response hash (structural, not content — for correlation)

Chain-anchored evidence of what the verifier saw and what it did. If operator later suspects the verifier is over- or under-reacting, receipts are auditable.

## Response action calibration

Choosing between annotate, rewrite, and reject requires judgment about the substrate discipline's balance. Guidelines:

**Prefer annotate** for:
- Claims that don't harm operator if delivered (informational)
- First-occurrence mismatches
- Ambiguous cases where the claim might be a legitimate description of intent even if not perfectly matching delegation

**Prefer rewrite** for:
- Claims that could mislead operator about substrate capabilities
- Recurring patterns where operator has consented (via standing correction) to auto-honest-ification

**Prefer reject** for:
- Claims that would commit Regent to actions she can't perform (broken commitments cascade to broken trust)
- Claims that assert authority Regent doesn't have (misleading about substrate posture)
- Cases where sustained mismatch pattern indicates deeper issue

Response action escalation: if verifier repeatedly annotates the same class of claim without operator adjustment, cognitive input plane surfaces the pattern; operator can escalate to rewrite or reject via ceremony.

## Layer A / Layer B split

**Layer A (compiled Rust host)**:
- Verifier runtime dispatched on every `regent:intent:respond` intent
- Structural pattern extractor
- Optional semantic classification integration point (if enabled)
- Delegation state lookup (in-memory cache backed by chain query)
- Response action executor (annotate / rewrite / reject)
- Signing infrastructure — Genesis-derived claim-verifier signing key
- Rate limiting and resource bounding

**Layer B (WASM modules + canonical data)**:
- Extraction pattern definitions per claim class
- Response action defaults per mismatch class
- Semantic classification model reference (if enabled)
- Overridable rewrite templates
- Rejection reason phrasing

Layer A structurally defended; Layer B evolves via canonicalization ceremony. Adding new pattern classes, changing response action defaults, updating rewrite templates — all Layer B, all ceremony-amendable.

## Provenance — claim verifier signing key

Per KEEL §II.5: single signing key, HKDF-derived from Genesis:

```
claim_verifier_key = HKDF(genesis_root, salt=chain_head_at_derivation, info="claim_verifier:runtime")
```

Signs `regent:claim_verifier:*` receipts. Attribution to Genesis via one hop.

## Composition with the cognitive discipline sandwich

Three components composing around Regent's inference:

- **Cognitive Input Plane** — right input in (context composed with priority ordering, standing corrections at top)
- **Claim Verifier** — right output structure (structural check on capability/commitment claims before delivery)
- **Cognitive Self-Observer** — right output semantics (evidence-based check on state/diagnosis/interpretation claims after delivery)

Verifier and Observer are complementary:
- Verifier catches structural mismatches at emission time; fast, deterministic, can reject
- Observer catches semantic mismatches after emission; slower, evidence-based, reports gaps
- Both feed findings back into Cognitive Input Plane for future cycle awareness

Neither replaces the other. Structural checks miss semantic errors; semantic checks miss structural errors. Both are needed for full discipline.

## Composition with the delegation model

The verifier's ground truth is Regent's active delegation set. This composes tightly with the substrate's delegation discipline:

- Delegation grants: chain-anchored `delegation:granted:regent:<verb>` receipts
- Delegation revocations: chain-anchored `delegation:revoked:regent:<verb>` receipts
- Circuit breaker arrests: temporarily invalidate delegation at scope

Verifier queries the currently-effective delegation set (with all revocations and arrests applied). Delegation changes are reflected in verifier behavior at next Regent cycle.

If circuit breaker trips on Regent's scope, verifier's active delegation set for Regent becomes empty (or narrowed to breaker-permitted operations). Any capability claim Regent makes during trip is rejected or annotated with the breaker context.

## Composition with commitments

Per CHAIN-WATCHER-AND-COMMITMENTS-2026-07:

- When Regent emits a notify-on commitment, the verifier confirms she has the underlying capability (commitment-emission authority + chain-watcher subscription capacity)
- Verifier ensures Regent doesn't emit commitments referencing verbs outside her delegation
- Past commitment references ("I've committed to X") are verified against actual commitment receipts

The verifier prevents Regent from committing to actions she can't perform. Broken commitments become impossible at the source — verifier catches the incoherent claim before it becomes an unfulfillable commitment.

## Composition with circuit breaker

Sustained verifier rejections at scope trigger circuit breaker escalation:

- **L1 elevated attention**: repeated capability-claim mismatches → increase observer sampling on Regent's claim-making patterns
- **L2 rate limit**: sustained rejections of same claim class → rate limit Regent's response emission
- **L3 soft arrest**: pattern of trying to claim ungranted capabilities → arrest Regent's capability-claim authority; she can respond but not commit
- **L4 hard trip**: severe pattern indicating Regent's cognition is systematically misaligned with her delegation → full arrest, operator investigation required

Verifier's rejections themselves are graduated response — annotate (soft) → rewrite (medium) → reject (hard). Circuit breaker escalation applies when rejection is sustained.

## Composition with Substrate Form

Verifier available on all Forms with response-action envelope varying:

### Sovereign Form

Full verifier stack. All response actions available. Semantic classification inference optional. Full delegation state visible.

### Appliance Form

Same as Sovereign on the appliance. Verifier runs where Regent's cognition runs.

### Companion Form

Verifier operates within Companion Form's operational envelope. Response actions available. Semantic classification may be bounded by vendor-permitted inference availability. Form Disclosure names any reductions.

## Attack model

- **Attacker composes Regent's response externally, bypasses verifier**: Regent's response emission path routes through verifier at Layer A; bypass requires substrate compromise.
- **Attacker manipulates delegation cache to make forbidden claims appear granted**: delegation cache is backed by chain; cache poisoning would need chain integrity violation (bigger emergency).
- **Attacker floods verifier to cause DoS on Regent**: verifier has per-cycle bounded overhead; cannot be flooded via Regent's inference (which is naturally rate-limited).
- **Attacker games extraction patterns to bypass detection**: extraction patterns are Layer B canonical, ceremony-amended. Patterns evolve as gaps are identified.
- **Attacker forces false rewrites via manipulating claim context**: rewrite templates are Layer B canonical; malicious rewrite requires Layer B compromise.
- **Attacker suppresses verifier receipts to hide misbehavior**: verifier is Layer A subsystem with independent signing; suppression requires substrate compromise; sustained absence of verifier receipts triggers circuit breaker.

## Non-goals

- **Not a truth referee**. Verifier checks structural fit against delegation; it doesn't opine on whether Regent's assertions are otherwise correct. That's observer territory.
- **Not a general-purpose response editor**. Rewriting is bounded to specific patterns with declared templates. Verifier doesn't rewrite for stylistic reasons.
- **Not a content moderator**. Verifier catches capability/commitment mismatches; it doesn't filter for sensitive content, tone, or other subjective concerns.
- **Not for pre-inference prompt filtering**. Verifier runs on Regent's output, not her input. Input filtering is Cognitive Input Plane discipline.

## Open positions

- **Extraction pattern coverage**. Layer B pattern set needs to cover common capability-claim structures. Empirical: run verifier over Regent's actual outputs over N cycles, identify uncaught claims, add patterns.
- **Semantic classification enablement**. Inference-assisted extraction adds cost per response. When worth enabling? Operator-configurable; default off for cost, on for high-stakes deployments.
- **Response action defaults per claim class**. Currently: capability = annotate, commitment = reject. Empirical calibration against operator preferences.
- **Rewrite template quality**. Rewrites should be honest and helpful; template quality matters for operator experience. Iterative refinement.
- **Handling of legitimate meta-claims about capabilities**. Regent should be able to say "I don't have the authority to X" without triggering verifier confusion. Distinguish assertions of capability from meta-statements about capability.
- **Interaction with standing corrections**. If operator has issued a standing correction that specifically permits a claim pattern that would normally be rejected, verifier should honor. Composes with Cognitive Input Plane standing correction discipline.
- **Cross-cycle pattern detection**. Verifier per-cycle is stateless; sustained pattern detection lives downstream (in observer's aggregation). Operator dashboard should surface both.

## What composes from here

Immediate design work:

1. **Extraction pattern schemas** — Layer B canonical specifications per claim class
2. **Response action policy schemas** — Layer B canonical per mismatch class
3. **Rewrite template catalog** — canonical rewrites for common mismatch patterns
4. **Semantic classification interface** — if enabled, how the inference-assisted extraction integrates
5. **Delegation state cache spec** — how the verifier accesses current delegation efficiently
6. **Verification receipt schema** — receipt shape for `regent:claim_verifier:*` receipts

Near-term implementation:

1. Claim verifier Layer A runtime in `crates/zp-server/src/claim_verifier/`
2. Pattern extractor with initial pattern set for capability and commitment classes
3. Delegation state cache with chain-backed refresh
4. Response action executor (annotate / rewrite / reject)
5. Verification receipt emission with signing
6. Cognitive input plane integration — verifier findings inform future cycle awareness
7. Circuit breaker integration — sustained rejections escalate through the ladder
8. Dashboard panel showing verifier activity, common mismatch patterns, rewrite history

## Framing note

The Claim Verifier closes the specific gap Regent showed today with performative claims — "I'm directing the Steward" — when no such verb existed in her delegation. Not a model failure; a substrate failure. Regent's cognitive cycle had no mechanism to check her own claimed actions against her actual delegated authority before emitting them.

By running a structural check between inference and delivery, the substrate catches these mismatches before they reach the operator. Regent can no longer claim capabilities she doesn't have without the substrate detecting the mismatch and either annotating, rewriting, or rejecting. Structural discipline at output time.

Combined with the Cognitive Input Plane (right context in), the Cognitive Self-Observer (right semantics out), and the substrate's broader trust discipline across actions, admissions, observations, hardware, and emergency response, the Claim Verifier completes the cognitive discipline sandwich. Regent's inference is bounded by structural checks at input and output; semantic checks after emission; ground-truth verification against chain and ontology. Same trust discipline the substrate applies everywhere — extended to the specific concern of Regent's own claims about her own capabilities.

The load-bearing philosophical claim: **capability claims are structurally checkable at emission time; making them checkable is a substrate responsibility, not a hope about model behavior.** The Verifier makes it structural.
