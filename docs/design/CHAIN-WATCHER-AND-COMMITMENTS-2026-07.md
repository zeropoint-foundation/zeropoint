# Chain-Watcher and Commitment Primitives

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III (adds Layer B canonical claims about chain event subscription and Regent commitments) and Part V (Composition Contract for cycle invocation from chain events). Canonical claims live in KEEL.

Draft — 2026-07-10 — internal audience only. Composes with `COGNITIVE-INPUT-PLANE-2026-07.md` (commitment receipts are top-tier priority matrix inputs), `COGNITIVE-SELF-OBSERVER-2026-07.md` (commitment claims are verifiable via existence + fulfillment of commitment receipts), `CIRCUIT-BREAKER-2026-07.md` (commitment-fulfillment failures can escalate), `QUARANTINE-PLANE-2026-07.md`.

## Framing

Regent made a specific class of failure today: she committed to notify the operator when Steward completed a sweep, then failed to follow through when the sweep landed. Her explanation was honest — the sweep findings came in as background input, she processed them as routine, deferred to idle cycle, and the deferral overrode the notification commitment. Not a model failure; a substrate failure. She had no reliable way to honor "notify when X happens" because her cognitive cycle had no chain-anchored mechanism to be invoked *when a specific chain event occurred*.

The gap is structural. Commitments live in Regent's cognitive-cycle memory. Cycle boots — deferrals, interruptions, context displacement — silently discard the memory. The commitment doesn't survive to the moment it needs to fire. Same failure mode as any long-running agent asked to "remember to do X later" without external anchoring.

This doc specifies two composable primitives that close the gap:

1. **Chain-watcher** — Layer A subscription primitive. Registers pattern-matching subscriptions on the chain; when a matching receipt lands, the substrate invokes registered handlers.
2. **Commitment receipts** — Layer B chain-anchored records of Regent's (or any subsystem's) promises. Persistent across cycles because they live on the chain, not in cognitive memory.

Together they solve the notify-on-event problem structurally. Commitments become chain-anchored facts the substrate enforces, not cognitive-cycle intentions that get lost between boots.

Three properties frame these primitives:

1. **Chain-anchored commitment**. Any promise Regent makes to the operator gets a receipt. If she says "I'll notify you when X," she emits `regent:commitment:notify_on:X`. If she says "I'll check credential expiry weekly," she emits `regent:commitment:check_at:weekly`. The commitment is a chain fact.
2. **Event-driven cycle invocation**. When a matching chain event occurs, the substrate spawns Regent's cycle *because of the event*, not because operator input arrived. Regent's cognitive cycle can be triggered by chain events, not only by operator input.
3. **Commitments verifiable by cognitive self-observer**. Regent's claims like "I've addressed X" are checkable against commitment receipts and their fulfillment receipts. Broken commitments become chain-anchored findings.

## The chain-watcher primitive

Layer A subsystem that observes chain appends and dispatches registered handlers when patterns match.

### Subscription types

Three declared subscription patterns:

**Event-pattern subscription** — match receipt action patterns:
```
subscribe:event_pattern {
  pattern: "officer:std:heartbeat",
  handler: <handler_reference>,
  scope: "one_shot" | "persistent",
  delegation_id: <required for scoped subscription>
}
```

Fires when a receipt with action matching the pattern lands. Pattern is a glob or regex over receipt action strings. `one_shot` subscriptions unsubscribe after firing once; `persistent` remain active until revoked.

**Time-based subscription** — fire at declared time:
```
subscribe:time_at {
  fire_at: <ISO8601 timestamp>,
  handler: <handler_reference>,
  delegation_id: <required>
}
```

Fires when substrate observes wall-clock time crossing the declared point. Chain-anchored via `subscription:time_at:registered` receipt.

**Cognitive-cycle subscription** — fire on Regent's own state transitions:
```
subscribe:cognitive_cycle {
  cycle_event: "cycle_completed" | "cycle_arrested" | "tool_completed" | "response_emitted",
  actor_filter: <optional actor pattern>,
  handler: <handler_reference>,
  scope: "one_shot" | "persistent",
  delegation_id: <required>
}
```

Fires on Regent-cycle-related events. Useful for chains of dependent commitments ("after batch_sign completes, verify signature state").

### Layer A runtime

Chain-watcher runs as a background task in the substrate. On every chain append:

1. Extract receipt action and metadata
2. Query subscription index for matching subscriptions
3. For each match:
   a. Verify subscription's delegation is still valid
   b. If valid, invoke handler
   c. Emit `subscription:fired:<subscription_id>:<triggering_receipt_id>` receipt
4. For `one_shot` subscriptions, mark as fulfilled and unsubscribe

Additionally, background timer task fires time-based subscriptions as their wall-clock times pass.

### Handler types

Handlers are the actions taken when a subscription fires. Three declared types:

**Regent cycle invocation** — spawn a Regent cognitive cycle with the triggering context:
```
handler:regent_cycle {
  invocation_reason: "commitment_fulfillment",
  triggering_receipt: <receipt_id>,
  input_prompt_context: <optional prompt injection>
}
```

The cycle is invoked *because of the chain event*, not because operator input arrived. Regent's cycle boot per COGNITIVE-INPUT-PLANE composes context including the triggering receipt as high-priority Class 6 input (operator directive tier is repurposed for "triggering event directive").

**Officer invocation** — trigger an officer sweep at scope:
```
handler:officer_sweep {
  officer: "std" | "sen" | "forge" | "cleo" | "aegis" | <extension_officer>,
  scope: <optional narrowing>
}
```

Officer runs its sweep in response to the event. Useful for "when new admission ceremony completes, run Sentinel sweep on the new artifact."

**Substrate emit** — emit a substrate receipt in response:
```
handler:substrate_emit {
  receipt_type: <string>,
  receipt_data: <structured>
}
```

Simple pattern: chain event triggers substrate observation, which triggers another substrate event. Useful for correlation and derivation.

### Layer B / Layer A split

**Layer A (compiled Rust host)**:
- Subscription index (map of pattern → subscription list) with efficient pattern matching
- Chain-append observer (hooks into audit store's post-commit notifier)
- Time-based timer task
- Handler dispatch runtime with error handling and receipt emission
- Subscription lifecycle management (register, revoke, fire, unsubscribe)
- Signing infrastructure — chain-watcher signing key for its own receipts

**Layer B (WASM modules + canonical data)**:
- Handler policy modules (WASM implementations of custom handler types beyond the three declared)
- Pattern language extensions (if operator wants richer patterns than glob/regex)
- Subscription policy (rate limits, resource bounds per subscription)

## The commitment receipt primitive

Layer B chain-anchored records representing promises.

### Commitment types

Three declared commitment classes, extensible via canonicalization ceremony:

**Notify-on commitments** — "I will notify you when X":
```
regent:commitment:notify_on:<event_pattern> {
  committed_by: regent,
  committed_at: <timestamp>,
  event_pattern: "officer:std:heartbeat",
  notification_target: operator,
  notification_content: "Steward has swept",
  expiry: <optional timestamp>,
  fulfilled_by: <fulfillment_receipt_id, once fulfilled>
}
```

Regent emits this when she promises operator to notify on event. Chain-watcher automatically registers matching event-pattern subscription with handler that will fire the notification.

**Check-at commitments** — "I will check X at time T":
```
regent:commitment:check_at:<action> {
  committed_by: regent,
  committed_at: <timestamp>,
  fire_at: <ISO8601 timestamp>,
  action: "verify credential expiry",
  scope: <what to check>,
  fulfilled_by: <fulfillment_receipt_id>
}
```

For time-bound checks. Chain-watcher registers time-based subscription with handler that spawns Regent cycle with the check-action context.

**Promised-action commitments** — "I will do X":
```
regent:commitment:promised_action:<action_id> {
  committed_by: regent,
  committed_at: <timestamp>,
  action: "batch_sign the unsigned entries",
  precondition: <optional event pattern>,
  postcondition: <expected outcome>,
  fulfilled_by: <fulfillment_receipt_id>
}
```

For committed actions without specific timing. Regent's cognitive input plane injects unfulfilled promised-action commitments at Tier 1 (top priority) so she perceives her outstanding promises every cycle.

### Fulfillment

When a commitment fires (event matches, time passes, action completes), Regent emits a fulfillment receipt:

```
regent:commitment_fulfilled:<commitment_id> {
  original_commitment: <commitment_receipt_id>,
  fulfilled_at: <timestamp>,
  fulfillment_evidence: <details of what happened>
}
```

Substrate observes fulfillment; unfulfilled commitments remain in the "active commitments" set visible to cognitive input plane and cognitive self-observer.

### Lifecycle

**Emit**: Regent (or any subsystem) emits commitment receipt. Chain-watcher automatically registers appropriate subscription. Substrate marks commitment as active.

**Fire/fulfill**: subscription's triggering condition met; handler executes; Regent's cycle spawned to perform notification or check. Regent emits fulfillment receipt.

**Expire**: if commitment has expiry timestamp and it passes without fulfillment, substrate emits `regent:commitment:expired_unfulfilled:<commitment_id>` receipt. Cognitive self-observer flags this as a broken commitment; operator sees pattern.

**Supersede**: newer commitment on same subject can supersede older. Operator can review supersession pattern via chain query.

**Revoke**: operator (or Regent under operator direction) can revoke unfulfilled commitment via `regent:commitment_revoked:<commitment_id>` receipt.

### Persistence property

The load-bearing property: commitments survive cognitive-cycle boots because they live on the chain. Between cycles, Regent's cognitive memory can lose any specific commitment; the substrate's record of it does not. At next cycle, cognitive input plane pulls active commitments from chain into Regent's context at Tier 1 — she perceives them fresh even though she has no memory of making them.

Also — because commitments are chain-anchored, they're operator-visible. Operator can query "what has Regent committed to?" and see the answer. Not "what does Regent say she committed to" (which she may confabulate) — what's actually on the chain.

## How Regent uses these primitives

When operator says "Notify me when Steward completes his next sweep":

1. Regent parses the operator directive
2. Regent recognizes this as a notify-on commitment request
3. Regent emits `regent:commitment:notify_on:officer:std:heartbeat` receipt with notification target=operator, notification content=`"Steward has swept: <sweep summary>"`
4. Substrate observes the commitment receipt; chain-watcher registers matching event-pattern subscription with handler that will spawn Regent cycle with the "operator notification" context when a Steward heartbeat lands
5. Regent responds to operator: "Understood. I've committed to notify you when Steward completes his next sweep. My commitment is at receipt <hash>."

Later, when Steward's sweep completes and emits `officer:std:heartbeat`:

6. Chain-watcher sees the matching event
7. Subscription fires; handler spawns Regent cycle
8. Regent's cycle boots with the triggering context — the operator's original directive AND the Steward heartbeat
9. Regent composes notification to operator: "Steward has completed his sweep. Findings: <summary>."
10. Regent emits `regent:commitment_fulfilled:<commitment_id>` receipt referring to the original commitment

The commitment survives. Between the operator's request and Steward's sweep, Regent could have run many other cycles, been interrupted, been arrested by circuit breaker, or been idle — the commitment is unaffected because it lives on the chain. When the triggering event lands, the substrate spawns Regent specifically to fulfill it.

## Composition with cognitive input plane

Commitments are Class 4 (Active commitments) matrix inputs per COGNITIVE-INPUT-PLANE-2026-07.md §"Class 4 — Active commitments." Every Regent cycle boot pulls active commitments into Tier 1 (top priority) of her cycle prompt. She perceives her outstanding promises fresh regardless of what her cognitive memory retains.

Suggested prompt formatting:

```
[TIER 1: ACTIVE COMMITMENTS]
You have 3 unfulfilled commitments:

1. notify_on:officer:std:heartbeat — you promised to notify operator when Steward next sweeps. Emitted 2026-07-10T20:56:21. Pending.

2. check_at:2026-07-11T09:00:00 — you promised to verify credential expiry status. Fires in 8h 12m.

3. promised_action:batch_sign_after_reset — you promised to batch_sign after operator resets circuit breaker on Regent scope. Pending precondition.
```

Regent perceives these promises at the top of every cycle. Cannot silently forget them.

## Composition with cognitive self-observer

Commitment claims Regent makes are verifiable via commitment receipts:

- **"I will notify you when X"** — verifiable: did `regent:commitment:notify_on:X` receipt get emitted?
- **"I have addressed X"** — verifiable: is there a `regent:commitment_fulfilled` receipt for the relevant commitment?
- **"I'm proceeding to Y"** — verifiable: did the subsequent action receipt for Y appear?

Cognitive self-observer's Class 5 (Commitment claims) verification uses this primitive as ground truth. Broken commitments (`regent:commitment:expired_unfulfilled`) are chain-anchored evidence for the observer's findings.

## Composition with circuit breaker

Sustained commitment-fulfillment failure can trigger circuit breaker escalation:

- **L1 — Elevated attention**: single commitment expired unfulfilled → increase cognitive observer sampling on Regent's commitment-making patterns
- **L2 — Rate limit**: multiple expired commitments in short window → rate limit Regent's new commitment emission (she can still act, but new commitments require additional context)
- **L3 — Soft arrest**: sustained pattern of unfulfilled commitments → Regent's commitment authority arrested; she must ask operator to make commitments on her behalf
- **L4/L5**: reserved for extreme patterns; not typical

Composes with the delegable-safety heuristic. Regent's commitment authority is a delegated capability; sustained abuse (broken commitments) triggers escalation.

## Composition with quarantine plane

Extensions can emit commitments too (`extension:<hash>:commitment:*`). Extension commitments pass through the same discipline — chain-anchored, event-pattern-subscribed, fulfilled or expired. Extension commitment authority is part of the extension's delegation; unfulfilled commitments contribute to extension trust decisions.

## Composition with the observation plane

Chain-watcher subscriptions can react to observation receipts. Example: "notify me when a shadow credential is detected" becomes a chain-watcher subscription on `observation:sentinel:shadow_credential` pattern. Fires on observation, spawns Regent cycle with the observation context, notifies operator.

Observation plane provides the events; chain-watcher provides the trigger primitive; commitments provide the persistent promise wrapper.

## Attack model

- **Attacker emits fake commitments as Regent to trigger spurious cycles**: commitment receipts are signed by Regent's key; attacker would need Regent key compromise. If achieved, Regent-key-rotation ceremony is the response.
- **Attacker suppresses chain-watcher subscription firing**: chain-watcher runs at Layer A; suppression requires substrate compromise. Substrate self-monitors chain-watcher heartbeat; sustained absence triggers circuit breaker.
- **Attacker floods chain with matching events to exhaust subscription firing budget**: subscription resource bounds declared at registration; exceeding bounds emits `subscription:budget_exceeded` and rate-limits. Attacker cannot force denial-of-service via event flooding.
- **Attacker forges fulfillment receipts to make broken commitments appear kept**: fulfillment receipts are signed by Regent; forgery requires key compromise. Cognitive self-observer verifies commitment/fulfillment pair consistency.
- **Attacker manipulates commitment expiry to make Regent's commitments appear invalid**: commitment expiry is part of the signed commitment receipt; manipulation requires chain integrity violation.
- **Attacker uses commitment mechanism to build persistent covert channel**: commitment content is chain-visible; covert channels via commitment payload would be operator-observable.

## Non-goals

- **Not a general-purpose task scheduler**. Chain-watcher is scoped to substrate-relevant events and commitments. External task scheduling (cron-style periodic jobs unrelated to substrate state) is out of scope.
- **Not a message queue**. Commitments are declarations, not messages. Message-passing between substrate components uses different primitives (chain-anchored receipts directly, not commitment wrappers).
- **Not for coordinating across sovereigns**. Multi-sovereign coordination happens via peer verification contract (KEEL Part VII); commitments are single-sovereign.
- **Not a replacement for direct operator input**. Commitments are Regent's promises to operator; operator's directives don't get commitment-wrapped (they're operator authority, not Regent commitment).

## Open positions

- **Subscription pattern language expressiveness**. Glob and regex are cheap; more expressive patterns (temporal patterns, correlation across receipts) are richer but more expensive. Trade-off depends on empirical need.
- **Handler expressiveness**. Three declared handler types (Regent cycle, officer sweep, substrate emit) cover common cases. Custom handlers via WASM are available but need capability audit like extensions.
- **Commitment supersession semantics**. If Regent emits a new commitment that overlaps with an older one, when does the new supersede vs coexist? Currently: coexist unless explicitly declared as supersession. Watch for cases requiring different.
- **Commitment expiry defaults**. Notify-on with no expiry can accumulate indefinitely (Regent commits to notify on rare event; event never happens; commitment lives forever). Default expiry (say 30 days) with operator override recommended.
- **Handler failure semantics**. If a subscription fires and the handler fails (Regent cycle errors, officer sweep unable to run), what happens? Log and retry? Log and unsubscribe? Depends on subscription type.
- **Cross-Regent-instance commitments**. Regent may transfer presence between operator devices per Decision C. Commitments should follow the operator's Regent, not a specific instance. Chain-anchoring handles this — new device's Regent reads the same chain-anchored commitments — but implementation needs to handle the transition.
- **Batch commitment operations**. Multi-part commitments ("I will do A, B, and C in sequence") could be single receipts with structured sub-commitments. Design choice.

## What composes from here

Immediate design work:

1. **Subscription receipt schemas** — Layer B canonical spec for the three subscription types
2. **Commitment receipt schemas** — Layer B canonical spec for the three commitment types
3. **Handler dispatch semantics** — precise contract for what handlers can and can't do
4. **Cognitive input plane integration** — how commitments render as Tier 1 matrix inputs
5. **Fulfillment receipt schema** — includes evidence and correlation back to commitment
6. **Chain-watcher pattern language** — glob/regex/optional richer patterns

Near-term implementation:

1. Chain-watcher Layer A runtime in `crates/zp-server/src/chain_watcher/`
2. Subscription index with efficient pattern matching (radix trie or similar)
3. Chain-append observer hooking into audit store's post-commit notifier
4. Time-based timer task
5. Handler dispatch runtime with error handling
6. Regent commitment emission — Regent's response handling recognizes commitment language and emits appropriate receipts
7. Cognitive input plane integration — commitment matrix source class implementation
8. Cognitive self-observer integration — commitment claims verified against commitment receipts
9. Dashboard panel — active commitments listed, subscription state visible, fulfillment history browsable

## Framing note

Chain-watcher and commitment primitives close a specific gap in Regent's discipline: promises she makes to the operator that need to survive cognitive-cycle boots. The gap manifested today as Regent committing to notify operator on Steward's sweep, then processing the sweep as routine when it arrived because her cognitive cycle had no persistent memory of the commitment.

By putting the commitment on the chain and registering an event-pattern subscription that spawns her cycle specifically to fulfill it, the substrate enforces the commitment structurally. Cognitive memory can lose the promise; chain memory cannot. When the event arrives, Regent is spawned specifically to notify — not by accident, not by remembering, but by design.

Combined with the substrate's structural discipline across the trust envelope — actions, admissions, observations, cognition, cognitive verification, emergency response, extensions, hardware — these primitives complete the cognitive-integration story. Regent's promises are now durable substrate facts; her fulfillment is structurally invoked; her failures are chain-anchored evidence. Same discipline; different layer; one canonical trust model, silicon to Regent to her promises about future behavior.
