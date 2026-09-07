# Metacognitive Fidelity Harness

**Tier 2 canonical elaboration.** Elaborates `KEEL-2026-07.md` §III.19
(Detectability over invulnerability), §III.22 (Verify before commit), and §II.17
(Cognitive discipline sandwich). Specifies the mechanisms by which the substrate
measures the accuracy of its own self-description, and the sweep by which it
exercises declared mechanisms rather than waiting for traffic to exercise them.
Canonical claims live in KEEL.

Draft — 2026-08-06 — internal audience only. Serves **Gate 4 (metacognitive
fidelity verified)** of `REGENT-SELF-BUILDOUT-TRAJECTORY-2026-07.md`. Composes
with `COGNITIVE-SELF-OBSERVER-2026-07.md` (the same shape applied to Regent's
output rather than to telemetry), `EMPIRICAL-PROGRAM-2026-07.md` (fidelity is a
measurable target, not an assertion), `OBSERVATION-PLANE-2026-07.md` (observation
surfaces are among the things whose self-report must reconcile), and
`AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL-2026-07.md` (which already contributes to
Gate 4 by scoring Regent's self-reports against independent assessment).

---

## 1. The claim

CLAUDE.md already defines the property:

> **Metacognitive fidelity** — the empirical accuracy of self-observation: how
> closely the substrate's metacognitive claims about its own state match the
> actual state as measured externally. Low fidelity means the substrate believes
> things about itself that aren't true — a category of failure worth catching.

The substrate names the property and the gate. It has no mechanism that measures
either. This document specifies three, in ascending cost, plus the discipline
that decides when each fires.

The load-bearing claim is narrow and worth stating plainly, because the
temptation is to overclaim: **this measures self-consistency, not truth.** A
substrate can be perfectly reconciled and wrong about the world. What the
harness buys is that *in*consistency stops depending on a human noticing it in
prose.

## 2. Why this document exists — the 2026-08-05/06 session

Every substrate defect found across a long working session surfaced by the same
route: something was asked to describe the substrate out loud, and the
description failed to reconcile. None came from reading code.

| Defect | How it surfaced | Would code review have caught it? |
|---|---|---|
| Regent fabricating `150 trajectories / last_processed_sequence 150` | Reported figures for a store `zp-regent` has no dependency on | No — the fabrication is at runtime |
| Two receipt families emitting bare JSON, unqueryable by prefix | Inventory reported unrecognized prefix `{"chosen_model"` | No — appends, signs, and verifies correctly |
| Receipt inventory partition off by one | `21 observed + 36 silent ≠ 56 declared`, read in a sentence | No — each number is individually correct |
| Steward finding narrated as current at 78 minutes stale | Contradicted an adjacent heartbeat age in the same paragraph | No — both sources were accurate |
| 16 receipt families emitted but undeclared | Systematic sweep, after the above prompted one | Only by the sweep this document specifies |

Two properties made the method work, and both are reproducible:

**Juxtaposition.** The Steward contradiction — *"no entries in last 78 minutes"*
beside *"last seen 28 seconds ago"* — was visible only because natural-language
rendering placed two numbers in adjacent clauses. As separate JSON fields in
separate objects, nothing compares them, and nothing did for as long as both
existed.

**Forced totalisation.** "Give me a posture check" reaches surfaces nobody
queries individually. The undeclared families had been emittable for as long as
their subsystems had existed; each was invisible because an undeclared family is
invisible *until it fires*, and none had fired inside an inventory window.

The corollary is the practical one: **a posture check is more valuable run when
nothing appears wrong than when something already is.** Run reactively it
confirms the known fault. Run routinely it is the only thing looking at the
surfaces no query covers.

## 3. Mechanism 1 — Reconciliation invariants

Every report surface declares the arithmetic that must hold over its own fields.
Violation is a finding, not a wrong number rendered confidently.

**Landed 2026-08-06** as `check_invariants` in `substrate_validate.rs`, reported
under `checks.reconciliation_invariants`.

### What is worth declaring, and what is not

The first draft of this section listed four invariants covering canary counts,
sandwich balance, and heartbeat staleness. Implementation showed most were
already implied by a `status` field — `cognitive_sandwich` flags its own
imbalance, `officer_heartbeats` derives per-officer staleness — so declaring
them would have duplicated a check rather than added one.

**The useful set is the residue: identities that surrounding logic or a reader
*assumes*, and nothing asserts.** Six shipped:

| Surface | Invariant | Class |
|---|---|---|
| `receipt_inventory` | `observed_distinct + silent_in_window == declared_total` | strict |
| `chain_integrity` | `hashes_valid == entries_examined` when status ok | strict |
| `chain_integrity` | `chain_links_valid == entries_examined` when status ok | strict |
| `canary_discipline` | `remediated + remediation_failed <= missed` | window |
| `cognitive_sandwich` | `observer_verified <= input_composed` | window |

### The one that was wrong

A sixth shipped and was removed the same day:
`signatures_present == entries_examined`. It has the same shape as its two
`chain_integrity` neighbours and is not the same kind of claim.

Hash validity and link validity are what `chain_valid` *means*, so "ok" with
either short of the total is a self-contradiction. An unsigned entry is a
**health problem, not an arithmetic impossibility** —
`AuditStore::open_unsigned` is a supported mode, and production has carried
unsigned entries before (Sentinel reported 12,893 at Critical, which is the
mechanism that owns the question).

It was caught by `posture_healthy_requires_all_disciplines_ok` failing against a
fixture whose chain was entirely valid, on the first test run after the
invariants landed — a run that should have happened before the code was
deployed and did not.

**The distinction the mechanism turns on, stated because one in six got it
wrong:** an invariant is arithmetic that cannot fail without something being
broken. A property that can legitimately be false belongs to whichever officer
owns the policy. Restating a policy check as an invariant makes it fire on
legitimate states, which is the alarm-fatigue failure this section's own
strict/window split exists to avoid.

`chain_integrity` is the instructive one: it reported four counts and compared
none of them, with `status` sourced from a `chain_valid` computed inside the
store. "ok" alongside `signatures_present < entries_examined` was representable
— the report would show a shortfall and call it healthy.

`canary_discipline` is the other shape: the status logic reads
`missed > 0 && remediated == missed` as self-healed, which silently assumes
`remediated <= missed`. Assumed by a comparison, asserted nowhere.

### Strict versus window-sensitive

Every count is taken over a bounded window, so an event whose partner falls
outside it can make a true identity read false. That is a boundary artifact, and
firing Warning on it produces exactly the alarm fatigue §III.25 forbids.

- **strict** — holds regardless of window placement. Degrades posture, on the
  reasoning that a surface whose own arithmetic does not close cannot be trusted
  to be reporting `ok` about anything else.
- **window_sensitive** — reports at Info, never escalates. Sustained violation
  across many windows is the signal; one is noise.

The split earned itself immediately. `observer_verified <= input_composed` read
62 vs 58 during development and 61 vs 61 an hour later across a restart. Classed
strict, that would have opened an investigation into four missing observer
receipts that a shifted window had already explained.

### Why a post-pass, not assertions in each check

The seed instance was a `debug_assert_eq!` added inside
`check_receipt_inventory`. `debug_assert` is compiled out of release, so it did
not run in the binary `./zp-dev.sh release` ships. **An invariant that only
holds in development is a test.** Evaluating over the assembled JSON also puts
the identities where all their fields are visible at once, which is where a
between-fields claim reads clearly.

**Emission.** Strict violations append to `notable_gaps` and degrade posture.
A dedicated `substrate:invariant:violated:*` receipt family is the natural next
step and is not yet emitted — the check currently reports, it does not
chain-anchor.

**Cost.** Trivial. Built first, as planned.

**Discipline for adding one.** Any report field computed from a partition,
count, or difference declares its identity at the same commit that introduces
it. A surface with no declared invariant is not necessarily wrong, but it is
unchecked, and the report should be able to say which it is.

## 4. Mechanism 2 — Cross-surface agreement

Any fact reachable by two independent paths must agree, and every rendered fact
carries `(value, source, as_of)`.

Seed instances:

| Fact | Path A | Path B |
|---|---|---|
| chain length | Steward `integrity_verified` finding | chain head at read time |
| officer liveness | `officer:*:heartbeat` age | age of that officer's latest finding |
| active corrections | `CorrectionIndex` count | `cognitive:correction:standing` minus revocations |
| model in use | `regent:config:inference` receipt | running process configuration |

The last row is the one the corpus already learned the hard way: the "GLM 5.2"
misframing recorded under §III.22 was a two-path disagreement that no mechanism
compared.

**Provenance is half the mechanism.** The Steward stale-finding case was not a
disagreement between sources — both were accurate — but a claim rendered without
the qualifier that made it true. `as_of` converts "no entries in last 78
minutes" into "no entries in last 78 minutes, *as observed 78 minutes ago*",
which is no longer a contradiction and no longer misleads.

**Emission.** `substrate:coherence:diverged:<fact>` with both readings, both
sources, both timestamps, and the tolerance that was exceeded.

**Tolerance is required, not optional.** Chain length read microseconds apart
legitimately differs on an active chain. A mechanism that fires on every benign
skew becomes noise, and noise here is a direct §III.25 violation — it forces
operator cognitive engagement on routine flow. Each declared fact pair carries
its own tolerance and the reasoning for it.

## 5. Mechanism 3 — Round-trip exercise sweep

The stress half, and the one with the most latent defects behind it.

`substrate_validate` already names it, in its own report:

> 34 of 57 declared receipt families were silent across the inventory window.
> Silence is not a fault by itself; it is the set an exercise sweep should
> drive, and whatever stays silent after one is either unreachable or wants a
> declared tie-off.

**Canary discipline is the existing miniature.** It writes a known marker and
verifies it reads back — end-to-end exercise of the chain's read/write path,
already running, already distinguishable in the inventory as `chain:canary:` so
its receipts do not pollute telemetry. The sweep generalises that pattern from
one path to every declared mechanism.

Per receipt family, the full circuit:

```
emit → append → sign → verify → query-by-prefix → inventory-categorize → officer-visible
```

A family that cannot complete the circuit is mis-declared, has a broken emitter,
or is genuinely unreachable — three different repairs, currently indistinguishable
from each other and from legitimate quiet.

### Revision — 2026-08-06, on attempting to build it

The paragraph that stood here claimed the sweep would catch the bare-JSON defect
before it shipped: *emit a classifier decision, attempt retrieval by prefix,
fail.* Building it showed that conflates two mechanisms with different costs and
different reach, and that most of the value had already been captured elsewhere.

**A generic sweep cannot invoke real emitters.** Making
`delegation:revoked:` fire means revoking a delegation. Per-family exercise is
integration testing, one harness at a time, not a runtime pass over a list.

**A synthetic sweep tests less than claimed.** Emitting a well-formed receipt
under each declared prefix verifies the declared → queryable → categorized path.
It cannot catch a malformed emitter, because the synthetic emission is
well-formed by construction. It would catch a typo'd declaration or a
longest-match collision in the inventory — real, narrow, worth doing eventually,
not the headline.

**The emission-shape class is already closed, at build time.** The
`chain_events_carry_a_prefix` pin fails the build on an event bound directly
from a serializer, and `collect_undeclared_emissions` fails on a prefix emitted
without a declaration. Between them they cover every receipt defect this session
found. A runtime sweep would be re-detecting, later and more expensively, what
the compiler already refuses.

### Dead end, recorded so it is not retried

Separating the two meanings of *silent* — **quiet** (an emitter exists, nothing
triggered it) from **unreachable** (no code path produces it) — looked
statically tractable as a registry → code scan. It is not.

Implemented and removed the same day. Of 72 declared families it reported 35
unreachable and was wrong about nearly all: `cognitive:observer:verified` had
fired 740 times in the preceding window, `governance_request:` 2244. Two causes,
neither incidental — prefixes held in consts (`EVENT_PREFIX_VERIFIED`) with the
emission site referencing the binding, and variable-segment prefixes
(`officer:{name}:heartbeat`, `{domain}:canonicalized:{id}`) which have no
literal by construction. Const resolution recovers about half.

**The chain is the better oracle.** "Has this family ever appeared" is a query
against history, where consts and variable segments are already resolved into
the strings that actually landed. That belongs in the receipt inventory, and for
any chain shorter than `INVENTORY_WINDOW` its `silent_prefixes` list already
*is* the answer — the distinction only becomes a separate question once the
chain outgrows the window. At 10,016 entries against a 25,000-entry window, it
has not yet.

**Marking.** Exercise emissions carry an `exercise:` discriminator so the
inventory, officers, and Cartographer can partition them out. Follows the canary
precedent rather than inventing a scheme.

**Disposition.** Every family ends a sweep in exactly one state:

- **exercised** — full circuit completed
- **unreachable** — no code path can produce it; either the emitter is dead or
  the declaration is aspirational and belongs in `RESERVED_RECEIPT_PREFIXES`
- **tied off** — deliberately not exercised, with a declared reason

"Silent" stops being a number and becomes an answer.

**Cost.** Highest of the three, and the reason it runs on operator ceremony or
long-idle rather than continuously. Per §III.25 it yields to operator input,
cancels between families rather than mid-family, and chain-anchors per-family
results so a partial sweep is not lost.

## 6. The narration leg

Mechanisms 1–3 are deterministic and require no inference. They would have
caught three of the five defects in §2.

The other two — the fabricated ontology figures, the stale finding rendered as
current — were caught by *narration*: a cognitive pass stating substrate
condition in prose, checked against ground truth. That is not incidental. Prose
forces juxtaposition and totalisation in a way a JSON report does not, which is
why it found things the report contained but did not surface.

This is already scoped: `cognitive_observer.rs:16` defers **Class 2 diagnosis
verification** pending ontology access. The extension is from *"does this output
contradict a standing correction"* to *"does this output contradict the chain."*

Two constraints, both inherited:

- Per §II.17 the narration is the filling, not the bread. It proposes; the
  deterministic mechanisms verify. A narration pass that is itself the checker
  has the confabulation problem it was built to catch.
- Per §III.13 the chain is the ground truth the narration is scored against —
  never the ontology, which is understanding rather than truth.

## 7. What this does not do

**It does not verify truth.** Self-consistency is not correctness. Every
mechanism here compares the substrate against itself.

**It does not replace the empirical program.** The four architectural claims are
verified against adversarial conditions, not against internal agreement.

**It does not gate.** Findings are advisory input to operator attention,
Cognitive Input Plane Tier 2, and the Circuit Breaker ladder. None reach the
Governance Gate's per-action decision — the same non-conflation
`AEGIS-V2-TRAJECTORY-SCORING-PROPOSAL` holds to, for the same reason (§II.13 P8/P9).

**It does not measure Regent's cognition.** That is the Cognitive Self-Observer.
This is the telemetry layer underneath, and the two meet only at §6.

## 8. Build order

1. **Reconciliation invariants** — **landed 2026-08-06.** Six checks, four
   strict, two window-sensitive. §3.
2. **Cross-surface agreement** — **partially landed 2026-08-06.** The
   `(value, source, as_of)` shape went in at the surface where its absence had
   produced a false statement: `FindingSummary` now carries `observed_at` and
   `age_secs`. The comparison layer — two paths to one fact, checked against a
   declared tolerance — is not built. §4.
3. **Exercise sweep** — **largely dissolved on contact.** The emission-shape
   class it was meant to catch is closed at build time by the pin and the
   forward registry check; the reachability question it was meant to answer is
   not statically tractable and is better asked of the chain. What survives is
   a narrow synthetic round-trip (typo'd declarations, longest-match
   collisions), which is worth doing and is no longer the headline. §5.
4. **Narration leg** — gated on Class 2 verification, which is gated on
   OntologyReader (P5). §6.

Stage 3 shrinking is the useful result rather than a setback: two build-time
checks written before the design doc existed had already covered most of what
the runtime sweep was for. The residual is smaller and better understood, and
the dead end is recorded in §5 so it is not attempted a second time.

Each stage is independently useful; none blocks the others.

## 9. Connects to

**§III.19 (Detectability over invulnerability)** — the parent claim. Every
mechanism converts a silent condition into a chain-anchored record. The bare-JSON
receipts are the canonical instance: nothing was broken, things were merely
invisible, and invisible is the failure mode §III.19 names.

**§III.22 (Verify before commit)** — this is that discipline applied to the
substrate's statements about itself. §III.22 already extends to "Regent's
self-reports (against chain query for actual receipts)"; the harness makes it
mechanical rather than hoped-for.

**§II.17 (Cognitive discipline sandwich)** — the narration leg is a filling; the
deterministic mechanisms are bread on both sides.

**§III.25 (Distributed cognition; autonomic operation)** — every mechanism here
is a candidate runaway-alarm source. Tolerances, the `exercise:` discriminator,
and Info-tier dispositions exist so routine flow stays out of operator
attention. A fidelity harness that produces alarm fatigue has destroyed the
signal it was built to protect.

**The lsof test** (workflow heuristics) — receipt-side counterpart. That test
says maturity is reached when every listening process traces to a receipt or is
explicitly out of scope. This one says maturity is reached when every declared
mechanism either exercises, is declared unreachable, or is tied off — and every
number the substrate reports about itself reconciles or raises a finding.
