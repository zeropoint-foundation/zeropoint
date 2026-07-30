> **Promoted from `docs/handoffs/` on 2026-07-29.** Shipped code cites this document
> as its rationale — `crates/zp-hardening-tests/tests/receipt_lifecycle.rs:55` — and `docs/handoffs/` is excluded by `.gitignore`, so the
> code travelled with the repo and the reason for it did not. Promotion test: a handoff
> moves when something shipped cites it. Content unchanged; the handoff original remains
> in place locally. References below to companion *investigation* documents still point
> into `docs/handoffs/` and are still local-only.

**Document type:** Design record, 2026-06. **Status:** exercised by the hardening test that cites it.

# Receipt Lifecycle — The Balanced-Loop Diagnostic at the Central Tier

*Dated 2026-06. Surfaced from the OPERATOR-SUBSTRATE-CONTRACT-2026-06*
*Sonnet report: the Receipt → Chain and Gate → Receipt hand-offs are*
*dense enough that the per-sub-layer affordance partition doesn't*
*adequately capture where each sub-layer's Required affordances hand*
*off to the next. This brief traces the full lifecycle (verb dispatch →*
*gate evaluation → canonical body construction → chain insertion),*
*names the hand-off invariants between stages, and identifies the*
*cross-boundary gaps that per-sub-layer testing would miss.*

---

## What this brief is

The Operator substrate tier contract partitions affordances into seven
sub-layers and treats each as a standalone conformance surface.
That decomposition is correct for naming what each sub-layer must do,
must not do, and may do. But the substrate's load-bearing behavior is
not a per-sub-layer property — it is a property of the *sequenced
composition* of sub-layers around a single operator action. Each
governed action threads through verb-set, gate, policy, receipt, and
chain sub-layers in a specific order. A failure at any stage produces
a structurally distinct observable; a failure at any *boundary*
produces a subtler failure that per-sub-layer testing tends to miss.

This brief is the central-tier expression of the balanced-loop working
heuristic. The smallest single operator action that exercises every
sub-layer in sequence is the empirical test of the substrate's
correctness; running it once and observing the chain is the diagnostic
that distinguishes "every layer passes its own tests" from "the
composition is correct."

## The four lifecycle stages

A governed action progresses through four stages between dispatch and
chain anchoring. The seven sub-layers from the operator-substrate
contract are distributed across these stages — some stages exercise
multiple sub-layers; some sub-layers contribute to multiple stages.

### Stage 1 — Verb dispatch

A cockpit (the Regent), an agent (IronClaw), or a tool invocation enters
the substrate through the surface layer with: verb name, subject,
payload, capability declaration, and operator identity.

The verb-set sub-layer validates that the named verb exists in the
canonical schema and matches the expected payload shape. The surface
sub-layer enforces authentication and tier-correct entry path. If
either check fails, the dispatch is rejected at the surface boundary —
no further stages execute, no receipt is emitted, no chain entry
lands.

If both checks pass, the substrate carries forward a pending dispatch
context: a verified verb identity, the parsed payload, the declared
capability, and the operator identity. This context is the input to
the next stage.

### Stage 2 — Gate evaluation

The gate sub-layer evaluates the pending dispatch context against the
current chain state. Inputs: the dispatch context, the active
delegation envelope (read from chain state), the constitutional rule
set (positions 1 and 2, non-removable), and any operator-defined
policy rules at positions 3+. The policy sub-layer is the rule body;
the gate sub-layer is the dispatch.

The gate produces a `PolicyDecision` — allowed, denied, or error —
along with a signed policy receipt that the chain layer will insert.
The policy receipt is the substrate's structural commitment that the
gate was consulted; its presence on the chain is the evidence Claim 3
rests on.

Critically: the policy receipt is signed and chain-inserted *before*
any side effect from the dispatch executes. A `gate:allowed` receipt
on the chain followed by no exec receipt is a substrate failure mode
(the gate said yes but the action didn't happen); an exec receipt with
no preceding policy receipt is a worse failure (the action happened
but the chain has no evidence it was authorized).

### Stage 3 — Canonical body construction (and side effect)

For an allowed gate decision, the substrate executes the side effect
(spawn process, write file, network call, etc.), captures the result,
and constructs the canonical receipt body. The receipt sub-layer is
responsible: the body must be deterministically serialized (JCS or
equivalent), the verb claim must match the schema, and the body must
incorporate the result of the side effect in canonical form.

The receipt id is computed as `blake3(canonical_body)`. The receipt
is signed by the identity binding sub-layer's Genesis-derived audit
key. The signed receipt is now ready for chain insertion.

If the side effect fails — the spawn errors, the network call times
out, the file write fails — the receipt's exec leg records the
failure mode in canonical form. The chain anchors what *did* happen,
including failures. A failed side effect still produces a chain entry;
silent failure (side effect failed, no receipt emitted) is the
forbidden case.

### Stage 4 — Chain insertion

The chain sub-layer accepts the signed receipt, verifies its
prev-hash points to the current chain tip, atomically appends it
under `BEGIN IMMEDIATE` semantics with the `UNIQUE(prev_hash)`
constraint, and returns the resulting chain entry id (which equals
the receipt id).

If another writer raced ahead, the prev-hash check fails; the chain
layer retries with the new tip. Append-only and content-addressed
storage means a successful insertion is durable; a failed insertion
(transaction abort, storage error) returns an error to the caller,
who is responsible for retrying or surfacing the failure.

## Hand-off invariants between stages

Per-sub-layer testing covers the within-stage invariants. The
cross-boundary invariants are where the substrate's correctness
actually lives.

**1→2: Verb identity must reach the gate intact.** The verb name and
payload that the gate evaluates must be the same verb name and payload
the verb-set sub-layer validated. A test that the verb-set rejects
unknown verbs (within-stage) does not exercise the substrate
preserving verb identity through to the gate.

**2→3: Gate decision must precede side effect.** The policy receipt
must be signed and ready for chain insertion before any side effect
executes. A test of the gate's decision logic does not exercise
whether the substrate honors the ordering commitment.

**3→4: Receipt body must be deterministic.** The canonical body that
produces the receipt id at stage 3 must be byte-identical to what
chain insertion stores. A test of canonical serialization (within
receipt sub-layer) does not exercise whether the chain layer accepts
the body unchanged.

**4→1: Chain tip must be visible to the next dispatch.** The chain
insertion from the previous action must be observable to the gate's
delegation envelope read in the next action. A test of chain insertion
does not exercise whether subsequent gate evaluations see the up-to-
date chain tip.

## Cross-boundary failure modes

The failure modes worth testing are the ones that per-sub-layer tests
miss because they live at the boundaries:

- **Verb dispatched but gate evaluated against wrong verb.** Boundary
  1→2 broken. Observable: gate receipt names verb A; subsequent exec
  receipt names verb B. The chain has both, but the relationship is
  inconsistent.
- **Gate allowed but side effect never executed.** Boundary 2→3 broken.
  Observable: `gate:allowed` chain entry with no matching `exec`
  receipt within a reasonable window. The chain says yes; reality has
  no action.
- **Side effect executed but receipt never constructed.** Boundary 3
  internal. Observable: side effect occurred (file exists, process
  spawned, network call made) but no chain entry attests to it. The
  chain is silent; reality has an action. This is the worst case
  because nothing in the chain reveals the gap.
- **Receipt signed but chain insertion failed silently.** Boundary 3→4
  broken. Observable: signed receipt in memory or in an error log,
  but no chain entry. Same shape as the previous case — chain silent,
  action occurred.
- **Two writers race for the same prev-hash.** Boundary 4 internal.
  Observable: under `BEGIN IMMEDIATE` + `UNIQUE(prev_hash)`, one
  writer succeeds, the other fails with a clear conflict. The
  observable failure is the test passing; a silent both-succeed
  outcome is the failure to detect.
- **Next dispatch reads stale chain tip.** Boundary 4→1 broken.
  Observable: gate evaluates against a delegation envelope that does
  not include a just-inserted delegation grant; the new grant is
  effectively ignored until the next read.

## The balanced-loop test path

The empirical test that exercises all four stages and all four
boundaries is the smallest single operator action that produces a
complete intent → policy → exec triple on the chain. The session on
2026-06-01 exercised this with a single agent tool call producing
three signed chain entries (`gate:denied:chain_render`,
`delegation:granted:ironclaw`, `gate:allowed:chain_render`); the
documented narrative captured failure-and-recovery as a continuous
audit chain.

A complete balanced-loop test for the central tier:

1. Issue a delegation grant from the operator to a subject (chain
   entry: `delegation:granted:<subject>`).
2. Have the subject invoke a verb through the surface
   (`gate:<decision>:<verb>` chain entry).
3. On allowed, verify the exec receipt lands (`exec:<verb>:<outcome>`
   chain entry).
4. Walk the chain and verify the three-entry sequence is consistent:
   delegation precedes gate; gate precedes exec; prev-hash chain
   intact.

This is the substrate's smallest viable end-to-end test. Each
boundary failure mode above produces a distinct chain pattern;
running the test under each failure injection produces an empirical
catalog of what the substrate is structurally honest about and where
it has unstated trust.

## What an implementation that breaks the lifecycle looks like

A substrate that passes per-sub-layer tests but fails the lifecycle
diagnostic shows characteristic patterns:

- High individual-test coverage, low integration-test coverage at the
  central tier.
- Sub-layer modules that look correct in isolation but produce
  inconsistent chain states under composition.
- "Skipped" gate paths for performance or convenience that are
  individually small but collectively undermine Claim 3.
- Receipt construction that depends on non-deterministic inputs
  (current time without canonicalization, random nonces inside the
  body) that work most of the time but produce id collisions or
  insertion failures under load.
- Chain inserts that use weaker consistency semantics than the
  operator-substrate contract requires (e.g., `WAL` without
  `BEGIN IMMEDIATE`) because the implementer didn't realize the
  concurrent-writer case mattered.

These patterns are diagnostic. An implementer reporting that all
sub-layer tests pass but exhibiting any of these symptoms has not yet
satisfied the central tier.

## Composition with existing contracts

This brief composes with several existing pieces of the architecture:

- **`OPERATOR-SUBSTRATE-CONTRACT-2026-06.md`** — the per-sub-layer
  affordance partition this brief complements. The contract specifies
  what each sub-layer must, may, and must not do; this brief specifies
  how the sub-layers must compose around an action.
- **`SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`** §6 integration
  patterns — sign-then-act, witness-not-arbitrate, project-not-decide
  all manifest at specific stages in this lifecycle; the lifecycle
  is where the patterns become testable.
- **`ARCHITECTURE-2026-04.md`** Claim 1 (chain integrity) and Claim 3
  (system-wide coherence from local evaluation) are both made testable
  by the lifecycle composition; this brief names the test.
- **CLAUDE.md balanced-loop heuristic** — this is the central tier's
  instance of "smallest end-to-end test, observe, fix structurally,
  repeat" applied to the substrate itself rather than to a feature
  arc.

## Implementation outline for substrate-side tests

The brief does not prescribe the test framework, but suggests the
test pattern:

1. **Setup.** Genesis-anchored test substrate with one operator
   identity, one configured subject, one verb registered in the
   verb-set schema.
2. **Drive.** Issue the three-step sequence (delegation grant, verb
   invocation, gate-mediated exec).
3. **Observe.** Walk the chain; verify the three expected entries
   appear in order with consistent prev-hash linkage.
4. **Inject failures.** Repeat the test with each boundary failure
   injected (kill the substrate between gate and exec; corrupt the
   canonical body; race two writers). For each injection, verify the
   chain's state is *honestly broken* in a structurally diagnosable
   way, not silently inconsistent.

The injection test is the load-bearing one. A substrate that passes
the happy path is necessary but not sufficient; a substrate that
fails the injection tests in structurally distinguishable ways is
the conformance bar.

## Refs

- `docs/OPERATOR-SUBSTRATE-CONTRACT-2026-06.md` — the per-sub-layer
  contract this brief complements
- `docs/handoffs/operator-substrate-affordance-pass-2026-06.md` — the
  architectural-decisions source for the contract; §"Cross-layer
  composition rules" is the seed for this brief
- `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md` §6 — integration
  patterns the lifecycle manifests
- `docs/ARCHITECTURE-2026-04.md` Part I §2 — Claims 1 and 3 are made
  testable by this lifecycle
- `CLAUDE.md` workflow heuristics — the balanced-loop entry is the
  general working discipline; this brief specializes it to the
  central tier
- The 2026-06-01 audit chain — empirical instance of the
  delegation → gate → exec sequence exercising the full lifecycle
- `crates/zp-audit`, `crates/zp-policy`, `crates/zp-receipt`,
  `crates/zp-server` — the implementation sites for the lifecycle's
  load-bearing code paths
