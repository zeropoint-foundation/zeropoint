# Cognitive Design Principles — July 2026

**Document type:** Design axiom reference. Companion to `ARCHITECTURE-2026-07.md` and the
nine design principles therein. These principles govern how ZeroPoint substrate components
reason about users, agents, and evolving system state — particularly for the apex observer
and any future cognitive/adaptive layer built on top of the receipt chain.

**Origin:** Synthesized from the NOW Model (Riddle & Schooler, 2024), Google's Nested
Learning paradigm (Behrouz et al., NeurIPS 2025), and their structural correspondence to
ZP's existing receipt chain architecture. Captured 2026-07-04.

**Status:** Active reference. Not a roadmap — these are filters for evaluating design
decisions, same as the nine design principles in ARCHITECTURE-2026-07.md.

---

## The Eleven Principles

---

### 1. The chain is already a Continuum Memory System.

The append-only receipt chain implements multi-timescale memory by construction. Different
receipt types arrive at different natural frequencies — some fast (per-tool-call), some
slow (per-delegation), some near-permanent (Genesis, constitutional layer). This is the
multi-frequency update structure that Google's Nested Learning formalizes as a "Continuum
Memory System." ZP gets it structurally, not through engineering.

**Implication:** Never build a parallel user-model store alongside the chain. The chain
is the memory substrate. The cognitive layer reads it; it does not replace it.

---

### 2. Receipt types are frequency bands.

Each receipt category corresponds to a natural update frequency, and these map to distinct
observer windows in the cognitive hierarchy:

| Band | Receipt types | Approximate timescale |
|---|---|---|
| Fast | `gate:*`, `tool:*`, `ws:exec:*` | Per-call (milliseconds–seconds) |
| Session | `session:*`, `preference:*` | Per-session (minutes–hours) |
| Trajectory | `delegation:*`, `capability:*` | Per-arc (days–weeks) |
| Sovereign | `genesis:*`, constitutional | Near-permanent |

Processing that conflates these bands will be wrong. A component reading only gate receipts
is operating in a fast window; it should not be used to infer stable user traits. A
component inferring Enneagram type should not update on session noise.

**Implication:** When designing any cognitive or adaptive component, name its frequency
band explicitly. Band mismatch between components is a structural defect, not a config
issue.

---

### 3. Three context flows on one chain.

The apex observer does not have one view of the chain. It has three readers operating at
different cadences over the same immutable data:

- **Fast flow** — last N receipts from the current session; drives moment-to-moment
  response calibration.
- **Medium flow** — rolling 30-day window; tracks trajectory-level patterns (what arc is
  the user in, what capabilities have they exercised, what has their delegation graph
  looked like).
- **Slow flow** — full chain from Genesis; builds and maintains the stable user model
  (Enneagram type, core fears, preferred care style).

Because the chain is immutable, these flows are independent readers — not separate stores.
They cannot contradict each other's source data. They can produce different interpretations
of that data at different levels of abstraction.

**Implication:** Design cognitive components for a specific flow, not "the chain." A
component that reads all three indiscriminately will produce an incoherent mixture of
timescales.

---

### 4. The apex is slow by design — but slowness does not excuse poor onboarding.

The stable user model — the highest-level, most abstract understanding of a user — must
update rarely. The NOW model calls this the "apex observer window" and places it in the
0.1–1 Hz range: one cycle every 1–10 seconds of biological time, proportionally much
slower than the sub-windows it integrates. In the ZP cognitive layer, "slow" means
updating on the order of dozens of sessions, not dozens of receipts.

This is a feature, not a limitation. The apex issues abstract "care directives" — what
register to use, what the user's core fear is, what kind of presence they need — not
sentence-level control. Lower-level response modules handle specifics. The apex does not
micromanage.

However, "slow by design" does not mean "absent until data accumulates." The system must
establish a reasonable working model of the user within the first 3–5 sessions — enough
to operate with appropriate register and detect gross mismatches. Early sessions are the
highest-signal window; a system that treats them as noise and waits for a large sample
fails its users at the moment they are most impressionable. The tension is intentional:
update infrequently and deliberately once a model exists; build that model quickly enough
to be useful from the start.

**Implication:** Anything that touches the stable user model (Enneagram layer, long-arc
preferences) must have an explicit, high threshold for triggering updates in steady state.
But the onboarding window (sessions 1–5) operates under a different regime: higher
sensitivity, faster provisional model formation, lower confidence thresholds. The model
that emerges from onboarding is the working hypothesis; subsequent slow-layer updates
refine it. If the system fires apex-layer updates every session *beyond* the onboarding
window, it is not an apex-layer component.

---

### 5. Cross-frequency coupling is weak and asymmetric.

Information moves between frequency bands through coupling, not through direct access.
The NOW model calls this "cross-frequency coupling" — the phase of a low-frequency (slow)
window modulates the amplitude of a high-frequency (fast) window, and vice versa. The
coupling is deliberately weak: higher-order windows have limited bandwidth to perceive
or control sub-windows, and lower-order windows cannot push arbitrary content upward.

In practice: fast-layer surprises elevate into the medium flow only when they persist
across multiple sessions. Medium-layer pattern shifts accumulate into the slow-flow
candidate queue only when they cross a significance threshold. Neither is a direct write.

**Implication:** Do not design direct read/write paths between bands. Elevation between
bands should be a deliberate, thresholded event — not a passthrough. A receipt that fires
once belongs in the fast window. A pattern that holds for 20 sessions can propose a slow-
layer update.

---

### 6. Peer windows are autonomous; they dialogue, they don't merge.

Parallel cognitive streams operating at the same frequency band — Enneagram type inference,
current emotional state, session task context, capability/delegation state — are
semi-autonomous. They share information through transient coherence (the NOW model's
"dialogue through coherence"), not through a unified shared state object.

This matters architecturally: do not represent these as fields on a single `UserModel`
struct that is updated from all sides. Each stream maintains its own representation.
When they need to share — e.g., emotional state inference informs how the Enneagram frame
is applied — that happens through a bounded, temporary coupling event, after which each
resumes independence.

**Implication:** If designing a user model data structure, model each stream as a separate
component with its own update path. A monolithic `UserState` with one update lock is the
wrong shape.

---

### 7. Slow-layer updates are candidates, not autonomous writes.

Any update to the stable user model is a **signed artifact proposal**, not an automatic
weight update. The "substrate proposes; operators sign" heuristic (CLAUDE.md) applies
directly here. The slow module generates a candidate — "based on 25 sessions, the user's
Enneagram estimate has shifted from 5 to 5w4" — which lands in the Artifact Library
as an unsigned candidate. It becomes canonical only when reviewed and signed.

Until signed, the candidate is the slow module's working hypothesis. It influences how
the fast module attends to new receipts (see Principle 9) but is not canonical. The
operator (or, in a sufficiently trusted setup, the user) signs to promote it.

**Implication:** The slow-layer user model must have a receipt lineage. If a user model
update cannot be traced to a signed artifact and a chain of receipts that produced it,
it has no authority. Unsigned user models are cognitive confabulation.

---

### 8. The confabulation gap is signal, not error.

When the fast layer (current session behavior) and the slow layer (stable user model)
disagree, that tension is information. The cognitive-accountability doc calls this the
"confabulation gap" — the observation layer says "output looks fine" but the trace says
"reasoning fingerprint is in a known failure cluster." The same gap appears in user
modeling: the stable Enneagram frame predicts withdrawn/reserved behavior but the session
receipts show high-frequency tool calls and urgency signals.

Do not suppress the gap by forcing one layer to defer to the other. Surface it. The gap
is diagnostic: is the user in an atypical mode? Has the slow-layer model drifted? Is
the fast layer encountering something genuinely novel? All three are different answers
with different implications.

**Implication:** Any cognitive component that resolves fast/slow disagreement by silently
defaulting to one side is hiding information. The gap should be representable as a named
state: `UserStateDissonance`, or equivalent.

---

### 9. Feedback runs downward, not just upward.

The standard pipeline runs bottom-up: receipts → fast layer → medium layer → slow layer.
This is emergence. But the NOW model insists the hierarchy also runs top-down: abstract
commands from the apex submerge into sub-windows and shape what they attend to. Google's
Hope architecture implements this as the slow module's current state shaping what the
fast module highlights in new data.

For the apex observer, this means the stable user model is not just a summary of past
sessions — it actively influences which incoming receipts are foregrounded in the fast
flow. If the slow layer holds "this user operates in a focused, low-interruption style,"
the fast layer should weight session-start receipts differently than it would for a
high-context-switching user.

**Implication:** The slow-layer user model must have an output interface that feeds back
into the fast and medium readers, not just an input interface that receives their updates.
A cognitive layer without feedback is a classifier, not an observer.

---

### 10. Catastrophic forgetting is structurally impossible; exploit it.

Google's Nested Learning builds elaborate multi-timescale architectures to avoid
catastrophic forgetting — the problem where learning new things overwrites old knowledge
in model weights. ZP's append-only chain makes this problem structurally irrelevant. Old
receipts cannot be overwritten. Any temporal window is re-derivable from the chain at any
time.

The practical consequence: the cognitive layer can always re-derive a prior user model
state from the chain. If the slow-layer estimate drifts in the wrong direction, roll back
by re-reading from an earlier chain window. If a delegation event changed capability
context, re-derive the medium-flow state from before that event. No state is ever lost.

**Implication:** Do not cache user model state defensively, as if it might be overwritten.
Cache it for performance, but treat the chain as the source of truth and the cache as
a projection. A stale cache is always correctable. Design recovery paths around chain
re-derivation, not around cache invalidation logic.

---

### 11. Context assembly is the attention hierarchy.

For inference-backed cognition, there is no separate "attention system." The structure of
what enters the context window — ordering, emphasis, compression, omission — determines
what the agent attends to. This is not a formatting decision; it is the primary governance
mechanism for cognitive behavior.

When the operator is speaking (conversation mode), their input is structurally first and
occupies the dominant position. System findings are compressed to a count and deferred.
Chain entries are summarized, not enumerated. The agent's full cognitive bandwidth is
devoted to the human.

When the operator is silent (stewardship mode), system findings expand to full detail.
Chain entries are enumerated. The autonomous remediation prompt fires. The agent's
bandwidth shifts to governance and maintenance.

The interrupt threshold is severity-gated: only Critical-severity findings break
conversation mode. Everything else waits for the next idle cycle. This prevents the
failure mode where a wall of Warning-level findings drowns out the operator's actual
request.

Every future addition to the cognitive context — new officer types, new data sources,
new capability surfaces — must declare where it sits in the attention hierarchy before
it gets a slot. An undeclared context section is an uncontrolled attention drain.

**Implication:** `perceive()` and `build_user_prompt()` are not data-assembly functions.
They are attention-governance functions. Treat changes to context structure with the same
care as changes to the gate or the constitutional layer — they shape what the agent does
just as directly.

---

## Relationship to Existing ZP Design Principles

These eleven principles compose with, and do not replace, the nine design principles in
`ARCHITECTURE-2026-07.md`. The mapping:

| Cognitive principle | Grounds in |
|---|---|
| Chain is a CMS (#1) | *Store-and-forward is primary* — derived state, not live state |
| Receipt types as frequency bands (#2) | *Every bit counts* — no redundant data paths, no band conflation |
| Three context flows (#3) | *There is no center* — one chain, many readers |
| Apex is slow (#4) | *A tool is intent, crystallized* — the apex carries stable intent, not tactical detail |
| Cross-frequency coupling is weak (#5) | *Every bit counts* — limited bandwidth between levels is not a bug |
| Peer windows are autonomous (#6) | *There is no center* — no single cognitive authority |
| Slow-layer updates are candidates (#7) | *Signing is gravity* — unsigned user models have no authority |
| Confabulation gap is signal (#8) | *Signing is gravity* — if the chain and the inference disagree, the chain wins |
| Feedback runs downward (#9) | *Identity is a key, not a location* — the user's identity shapes the session, not vice versa |
| Forgetting is impossible (#10) | *Store-and-forward is primary* — the chain survives; derived state is always re-derivable |
| Context assembly is attention (#11) | *Every bit counts* — context structure is governance, not formatting |

---

## Companion Documents

- `ARCHITECTURE-2026-07.md` — nine design principles and four claims; the north star
- `docs/future-work/cognitive-accountability.md` — Layer 3 trace vision; picks up where
  these principles leave off at the implementation level
- `docs/ARTIFACT-LIBRARY-2026-05.md` — the candidate-to-canonical lifecycle (#7 above)
- `docs/design/governed-agent-runtime.md` — GAR spec; reasoning attestation layer that
  these principles plug into
- `CLAUDE.md` — "the substrate proposes; operators sign" heuristic (directly cited in #7)

---

*These principles were synthesized from the NOW Model (Riddle & Schooler, 2024,
Neuroscience of Consciousness) and Google's Nested Learning (Behrouz et al., NeurIPS 2025)
and their structural correspondence to ZP's receipt chain architecture.*
