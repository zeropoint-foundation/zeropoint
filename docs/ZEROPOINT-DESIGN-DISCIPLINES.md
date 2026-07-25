# ZeroPoint Design Disciplines

**Document type:** Canonical reference. Single source for the complete design vocabulary
governing ZeroPoint — substrate, governance, operational, and cognitive layers.

**Intended reader:** Any session, engineer, or agent picking up ZP work. Read this before
reading source code, before making architectural decisions, and before designing new
components. Everything here has been load-tested; nothing here is decorative.

**Sources synthesized:**
- `docs/ARCHITECTURE-2026-04.md` — eight design principles, four claims, five commitments
- `docs/ARCHITECTURE-2026-05.md` — contracts/implementations meta-principle (II.0),
  verb-set discipline, singular sovereign root
- `docs/GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md` — governance implementation
  heuristics from inference governance arc
- `CLAUDE.md` — operational and workflow heuristics
- `docs/COGNITIVE-DESIGN-PRINCIPLES-2026-07.md` — multi-timescale cognition principles

**Status:** Living document. Add new principles when they graduate from heuristic to
load-bearing axiom. Do not add aspirational principles — only add what has been validated
against real substrate work.

---

## Part I — The Four Claims

These are the substrate's acceptance criteria. If any claim becomes false, ZeroPoint
is not load-bearing. All architecture and implementation work is ultimately in service
of keeping these true and pushing the untested ones toward empirically verified.

**Claim 1 — Each step is conditioned on all prior context.**
Every receipt carries a `pr` field linking to the previous receipt's hash. No Markov
step. No stateless action. The chain is the state and the state is the history.
*Mechanism: `pr` linkage, Blake3 transitivity. Status: currently true (AUDIT-01 fixed).*

**Claim 2 — Present state compresses full history.**
A verifier with the full chain can derive the present state from first principles. Peers
claiming a state that doesn't match their full chain are detectable.
*Mechanism: collective audit (AuditChallenge → AuditResponse → PeerAuditAttestation).
Status: mechanism exists; not adversarially load-tested.*

**Claim 3 — System-wide coherence from local evaluation.**
No side effect happens without passing through the gate. Every privileged action is
preceded by the production: intent → policy evaluation → exec.
*Mechanism: PolicyEngine fixed evaluation order, constitutional rules at positions 1 and 2.
Status: currently true (EXEC-01..04 fixed).*

**Claim 4 — Future actions narrowed by trajectory.**
A delegation chain can only constrain authority, never widen it. The envelope of
possible actions shrinks monotonically as delegation depth increases.
*Mechanism: eight delegation invariants, `DelegationChain::verify()`. Status: believed
true; not adversarially tested.*

---

## Part II — The Eight Design Principles

These are load-bearing constraints, not guidelines. Code that violates one is wrong.
Apply all eight as a filter before finalizing any architectural decision.

---

### Principle 1 — Signing is gravity

Signing is not a feature. It is the force that allows the trust layer to exist. Strip
signing and the routing of trust breaks — the governance gate cannot validate, the
verifier cannot replay, the blast radius model cannot trace compromise.

An unsigned receipt is structurally meaningless. It is an assertion without a witness.

**Design test:** Does this component require signing to function, or does it work without?
If it works without, signing is decorative, not gravitational — redesign until signing
is load-bearing.

---

### Principle 2 — Identity is a key, not a location

A tool's identity is its bead zero — the first-known-state receipt signed by the genesis
key. Not the process on port 8080. Not the hostname. Not the deployment coordinates. The
cryptographic lineage. Move the tool to a new machine, rotate credentials, change ports —
the chain persists and the identity is unchanged.

The genesis key is the operator's true name. It is not assigned by a service. The entire
infrastructure can be destroyed and rebuilt; the identity survives.

**Design test:** Is identity derived from cryptographic lineage or from deployment
coordinates? If coordinates, it is fragile — a network change or restart makes it wrong.

---

### Principle 3 — There is no center

There is no trust server. There is no API to ask "is this ready?" The cockpit reads the
local audit chain, walks the receipts, and derives the answer from mathematical evidence.
The answer is in the chain or it is nowhere.

This is uncentralizable by design. No DNS to hijack, no certificate authority to
compromise, no endpoint to DDoS. The trust state is a sovereign artifact belonging to
the operator, not a platform.

**Design test:** Does this require a central authority to function, or can it be verified
locally from the chain? If central, it is a single point of failure and violates the
architecture.

---

### Principle 4 — Every bit counts

Every field on a receipt exists because removing it would break a verifiable claim.
Every term carries exactly one meaning. No redundant data paths. No duplicate stores.
No field that earns its place through convention rather than through cryptographic
necessity.

**Design test:** Is every field load-bearing, or is there waste? Are there two stores
holding the same fact? If waste exists, strip it. If two stores exist for one fact,
one of them is structurally wrong.

---

### Principle 5 — Store-and-forward is the primary mode

The audit chain IS store-and-forward. Do not ask "is the system healthy right now?" —
ask "what does the chain say?" Readiness is derived from accumulated evidence, not from
live heartbeats. The chain persists through outages. The beads are still signed when
the system comes back. The truth survives the outage.

All derived state is a projection of the chain. Derived state can be stale; the chain
cannot.

**Design test:** Does this survive an outage, or does it require live connectivity? If
live, it is brittle. The chain should always be consulted as the source of truth; live
state is a performance optimization over it.

---

### Principle 6 — A tool is intent, crystallized

The governance gate is not a guardrail. It is the protocol. Claim types, metadata
structures, signatures — these are not logging conventions. They are the grammar of trust.
Semantics belong in structure, not in comments. Constitutional rules are conservation
laws, not policy preferences.

A tool that can be turned against its operator is not a tool — it is a trap.

**Design test:** Are the semantics in the structure, or in the documentation around it?
If documentation is doing the work that a claim type should do, the structure is
under-specified.

---

### Principle 7 — Contact does not commit

The receipt chain is not a faithful transcription of everything that happens. It is the
substrate's account of what it *chose to commit to*. Every receipt is a signature on
"this is what I accept as part of what I am now."

The critical distinction: **adaptive use of existing capabilities** (solving a problem
in new combinations of what the substrate already has — signed receipt, no promotion)
vs. **creation of new operational capabilities** (extending what the substrate allows
next time — unsigned artifact, held in quarantine, signed only after review). The first
is a bead on an existing wire. The second proposes a new wire; the substrate decides
whether to open it.

**Design test:** Does contact automatically produce a commit, or is the commit a
separate signed decision? If contact commits, the substrate is transcribing, not
governing.

---

### Principle 8 — One canonical path per substrate concern

Every substrate concern — identity, signing, auth, ports, state binding, credentials,
resource ownership — resolves through exactly one canonical implementation. Multiple
paths for the same concern produce half-state: the failure mode where two reasonable
approaches drift apart and the substrate breaks differently every restart.

Identity-is-a-key (P2) says key OR location, pick one. There-is-no-center (P3) says
trust is local, not local-with-a-remote-fallback. Every-bit-counts (P4) catches
duplicate data paths. Without one canonical path, the other principles admit "well,
mostly" implementations that drift.

**Design test:** Is there exactly one canonical path for this concern, or could two
implementations disagree? If multiple paths exist, one is wrong and the failure mode
is half-state.

---

## Part III — The Meta-Principle: Contracts Singular, Implementations Plural

*From ARCHITECTURE-2026-05.md Part II §0. The structural frame that locates all eight
principles above.*

The substrate is hexagonal at every architectural seam. A **contract** (port) is one
shape — singular, admits no alternatives, versioned with ceremony. An **implementation**
(adapter) is one concrete realization of a contract, serving a specific operator class
or environment.

**Contracts in ZP** (singular by construction): the verb set, the receipt format, the
audit chain format, the Genesis ceremony, the hash-then-sign discipline, the mesh
Interface trait, the SovereigntyProvider trait.

**Implementations in ZP** (plural by construction): operator-environment deliveries,
peer transports, subscription transports, sovereignty providers, streaming transports.

**The architectural test:** for any seam, ask "port or adapter?" If port, choose
carefully — there is one shape and it must serve every adapter. If adapter, choose for
fit — it must serve its operator class, and other adapters may serve other classes
simultaneously.

Misclassifying a seam — treating an adapter as a port, or a port as an adapter — is
the failure mode that produces either over-coupling or sprawl. When applying the eight
principles above, this frame identifies *where* a violation lives:
- At the port layer: a contract has been weakened or duplicated.
- At the adapter layer: an adapter has been added without justification, or all adapters
  have collapsed to one when plurality was the point.

---

## Part IV — Governance Implementation Principles

*From GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md. Concrete heuristics for wiring
governance into the substrate correctly, validated during the inference governance arc.*

---

**G1 — Chain is authoritative for governed values; config is not.**

If you are reading a value from config to decide what governed behavior to permit, the
chain should probably be authoritative instead. Config values are unsigned, unwitnessed,
and invisible to the chain — you can't query what a config field was set to last Tuesday,
or attribute when it changed. Any value where auditability matters belongs on the chain
as a `preference:*` or `policy:*` receipt.

*Concrete case: `selected_model` in a TOML file → replaced by `preference:llm:policy:set`.*

---

**G2 — Constraints belong in delegation, not in policy.**

Policy declares that a capability exists. Delegation constrains how it may be used. If a
field in a policy receipt is a *constraint* rather than a *declaration* of existence, it
belongs one layer down in the delegation envelope, where it can be narrowed per-operator
without touching shared policy.

*Test: would this field restrict rather than grant? If so, it is delegation material.*

---

**G3 — Capture both intent and outcome.**

Receipt what was asked for AND what actually happened. The gap between intent and outcome
is where the interesting governance data lives. If you only receipt the outcome, you
cannot reconstruct what was attempted vs. what ran. `model_requested` and `model_used`
are not duplicates — they are the two sides of a governance event.

*Generalizes to: any receipt that can only describe success is an incomplete receipt.*

---

**G4 — Governance is structurally separate from agent business logic.**

Wire governance at the seam — a wrapper, a middleware, a single substitution point —
not scattered through the agent's dispatch logic. Governance spread through business
logic becomes something the agent participates in and has opinions about, which makes
it easier to bypass and harder to test. The natural seam is where the capability is
invoked, not where the decision about what to do was made.

*Concrete shape: `ZpGovernedLlmProvider` wraps `LlmProvider`; IronClaw's
`agent_loop.rs` and `dispatcher.rs` did not change.*

---

**G5 — The gate runs for its receipts, not just its decisions.**

Even when the gate's answer is predetermined — when restrictions have already moved to
delegation and every well-formed request will be allowed — the gate must still run. The
gate call is what produces `gate:allowed:*` or `gate:denied:*`. Without those receipts,
the chain cannot distinguish "governance cleared this" from "governance was skipped."
The gate is the record of what happened; it runs for the chain, not for its verdict.

*Shortcut anti-pattern: skipping the gate call when "we know it will pass."*

---

## Part V — Operational Heuristics

*From CLAUDE.md. Patterns worth replicating, validated against real ZP work. These
govern HOW to work, not WHAT to know.*

---

**O1 — Name and shape artifacts for their downstream consumer, not their producer.**

Before creating any artifact — config file, JSON schema, API endpoint, function
signature — ask *who reads this?* and name/shape from the reader's side. The name IS
the contract. A name that forces a translation layer or a mapping comment is a
cognitive-bandwidth tax that consumer-side naming avoids.

*Example: `onboarding-voice-palette.json` (what the wizard reads) rather than
`tuner-favorites.json` (what the tuner writes). The file name IS the integration.*

---

**O2 — For systems spanning trust boundaries, only production tests production.**

Localhost cannot reproduce what happens at edges: cross-subdomain cookies,
CDN-injected auth, worker route ownership, per-worker secret stores, DNS resolution,
the gap between local and remote database migration state. Any system whose correctness
depends on identity flowing across origins will look correct in localhost while breaking
in production. Deploy early and walk through from production mid-build.

---

**O3 — Demonstrate publicly with prerendered paths; interpret internally with live agents.**

On public-facing surfaces, every narration path is prerendered and every interactive
branch is deterministic. No live LLM call on public surfaces. The *voice* of an agent
can surface through authored copy bound to UI events; the *running agent* stays behind
authentication. Internal authenticated surfaces can host live agent interpretation.

*Why: prerendered paths preserve cryptographic verifiability. The chain says X;
the narration was authored to say X when X happens. No runtime can lie.*

---

**O4 — Singular sovereign root: one authentication, everything derived.**

One credential, one prompt, one ceremony — from which every other secret is derived.
The credential store holds exactly one biometric-gated item. All other secrets are
either derived in memory from that root, or stored encrypted in a vault that the root
unlocks. There is no third category.

*Diagnostic: if one operator action triggers N authentication prompts, the architecture
has N independent secrets — structural drift, not a caching problem.*

---

**O5 — Pair conversational interfaces with reference surfaces that reveal the control space.**

Agents reveal capability through action; reference surfaces reveal capability through
visibility. Conversational control without a reference panel leaves operators guessing
what's possible. Reference UI without a conversation forces navigation for things the
operator could just say. Both surfaces must read from and write to the same chain-anchored
state — if they have separate stores, they drift.

---

**O6 — The substrate proposes; operators sign.**

The substrate produces candidates at scale: cheap, automated, deterministically
provenanced. Operators promote candidates to canonical via signature: rare, deliberate,
human-endorsed. The substrate emits any rendering or prescription — narration, workflow,
calendar, digest — as a candidate until endorsed. Signed artifacts persist, become
citable, and supersede prior versions explicitly.

*Two failure modes: always-live (regenerate on every read — non-citable, non-verifiable)
and always-pre-approved (operator approval is the bottleneck).*

---

**O7 — When two architectural models conflict over the same surface, pick one explicitly.**

Two coherent approaches running in parallel produce a substrate that fails differently
every restart. The symptom: each restart surfaces a *different* piece of the
inconsistency — rotating brokenness. The cause: unresolved drift between two reasonable
approaches, neither fully owning the surface. Fix the structure; document the choice.
Patching the inconsistency-of-the-day defers the same failure to the next restart.

*Diagnostic: "different break each time" → two models competing for one surface.*

---

**O8 — When a PoC keeps surfacing new friction at every layer, the friction IS the finding.**

Count the seams. If a single walkthrough of a single command surfaces ten distinct
failure modes across the substrate, the substrate isn't ready for the question the PoC
was designed to test. The narrow finding doesn't matter yet; the wider finding
("bedrock keeps moving") is what's load-bearing. Declare the bigger arc; execute it
deliberately rather than chasing the symptom of the day.

---

**O9 — The lsof test: substrate is mature when its own footprint is legible.**

Every listening process, every credential, every persistent file on the host either
traces to a substrate receipt or is explicitly out-of-scope. The operator should read
`lsof -iTCP -sTCP:LISTEN` as a substrate posture statement, not as a forensics exercise.
When running the command produces archaeology rather than legibility, the substrate has
not yet absorbed enough host-awareness to give the answer in one command.

---

**O10 — Config reflects today, not roadmap.**

Operator-facing configuration enumerates what the daemon responds to *now*. Empty
section headers, struct fields with no consumers, validation logic for fields no code
reads — these look like configuration but configure nothing. They train the operator to
read past section headings as decorative. Roadmap intent belongs in architecture docs
and the task list. Config and code land together in the same commit; there is no
"reserve the schema now, implement later."

*Audit method: remove the field and see if the build still compiles. String search alone
cannot distinguish self-referential validators from operational consumers.*

---

**O11 — Balanced loop: smallest end-to-end test, observe, fix structurally, repeat.**

When structure is designed but operational correctness is unproven: define the smallest
single operator action that exercises one round trip. Stand up the minimum CLI invocation
and minimum inspection. Run it. Observe what fails. Fix the *structural* thing the
failure surfaces — not a hotfix for the symptom. Repeat. The loop is healthy when every
iteration produces at least one genuine structural finding that the design phase didn't
anticipate.

*When NOT to use: when a load-bearing piece doesn't yet exist. The loop assumes structure
to test against. If the piece isn't designed, design it first.*

---

**O12 — The chain configures the cockpit; cockpits are pure projections.**

Each cockpit — CLI, conversational agent, visual panel — is a pure projection of
chain-anchored state into a native interaction mode. What the operator can do right now
is what the current chain state authorizes. When a delegation lands on the chain, the
cockpit gains the corresponding affordance immediately; when it expires, the affordance
disappears. No menu cache. No static declaration to keep in sync.

*Two corollaries: (a) verbs are the unit, rendering is per-cockpit — the verb has one
canonical implementation; (b) chain-derived presence implies chain-derived absence —
affordances that cannot be traced to a chain receipt have no authority.*

---

**O13 — Operational configuration with multiple write paths is structural drift.**

When the same fact — a port number, an auth token, a process state — can be written
by more than one independent code path, those paths will diverge. Not sometimes; always,
eventually. Any write to operational configuration must be atomic across all consumers.
Process lifecycle events are configuration writes. Liveness checks must match the failure
mode they guard against (`kill -0` detects existence, not responsiveness).

*Diagnostic: editing two files to fix one thing → two write paths for the same concern;
one of them needs to be retired.*

---

## Part VI — Cognitive Design Principles

*From COGNITIVE-DESIGN-PRINCIPLES-2026-07.md. Govern multi-timescale reasoning, user
modeling, and adaptive layers built on top of the receipt chain.*

---

**C1 — The chain is already a Continuum Memory System.**

Different receipt types arrive at different natural frequencies. This multi-timescale
structure is the Continuum Memory System that Google's Nested Learning formalizes — ZP
gets it structurally, not through engineering. Never build a parallel user-model store
alongside the chain. The chain is the memory substrate.

---

**C2 — Receipt types are frequency bands.**

Each receipt category corresponds to a natural update frequency and maps to a distinct
observer window:

| Band | Receipt types | Timescale |
|---|---|---|
| Fast | `gate:*`, `tool:*`, `ws:exec:*` | Per-call |
| Session | `session:*`, `preference:*` | Per-session |
| Trajectory | `delegation:*`, `capability:*` | Days–weeks |
| Sovereign | `genesis:*`, constitutional | Near-permanent |

Processing that conflates these bands is structurally wrong. Name the frequency band of
any cognitive component explicitly. Band mismatch is a design defect.

---

**C3 — Three context flows on one chain.**

The apex observer has three readers over the same immutable chain:
- **Fast flow** — last N session receipts; drives moment-to-moment calibration
- **Medium flow** — rolling 30-day window; tracks trajectory-level patterns
- **Slow flow** — full chain from Genesis; maintains the stable user model

These are independent readers, not separate stores. Design cognitive components for a
specific flow. A component reading all three indiscriminately produces incoherent output.

---

**C4 — The apex is slow by design — but slowness does not excuse poor onboarding.**

The stable user model — highest-level, most abstract — must update rarely. It sets
emotional register and abstract care directives; lower-level response modules handle
specifics. The apex does not micromanage. Anything touching the stable user model must
have a high threshold for triggering an update. If it fires every session, it is not
an apex-layer component.

However, "slow by design" does not mean "absent until data accumulates." The system must
establish a reasonable working model of the user within the first 3–5 sessions — enough
to operate with appropriate register and detect gross mismatches. Early sessions are the
highest-signal window; a system that treats them as noise and waits for a large sample
fails its users at the moment they are most impressionable. The tension is intentional:
update infrequently and deliberately once a model exists; build that model quickly enough
to be useful from the start.

---

**C5 — Cross-frequency coupling is weak and asymmetric.**

Information moves between frequency bands through coupling, not direct access. Fast-layer
surprises elevate into the medium flow only when they persist. Medium-layer shifts
accumulate into the slow-flow candidate queue only when they cross a threshold. Do not
design direct read/write paths between bands. Elevation is a thresholded event, not a
passthrough.

---

**C6 — Peer windows are autonomous; they dialogue, they don't merge.**

Parallel cognitive streams at the same frequency band — Enneagram inference, emotional
state, session task context, capability graph — are semi-autonomous. They share
information through transient coupling, not through a unified shared state object. Model
each stream as a separate component with its own update path. A monolithic `UserState`
with one update lock is the wrong shape.

---

**C7 — Slow-layer updates are candidates, not autonomous writes.**

Any update to the stable user model is a signed artifact proposal, not an automatic
update. O6 (the substrate proposes; operators sign) applies here directly. The slow
module generates a candidate; it becomes canonical only when reviewed and signed. Until
signed, it is a working hypothesis. Unsigned user models have no authority — same rule
as unsigned receipts.

---

**C8 — The confabulation gap is signal, not error.**

When the fast layer (current session) and the slow layer (stable model) disagree, that
tension carries information. Do not suppress it by forcing one layer to defer to the
other. Surface it. The gap is diagnostic: is the user in an atypical mode? Has the slow
model drifted? Is the fast layer encountering genuine novelty? All three are different
answers requiring different responses.

---

**C9 — Feedback runs downward, not just upward.**

The standard pipeline is bottom-up: receipts → fast layer → slow layer. But the hierarchy
also runs top-down: the stable user model shapes what the fast layer attends to in new
receipts. Without feedback, the apex can't issue abstract commands — it can only
summarize. Design the slow-layer user model with an output interface feeding back into
the fast and medium readers, not just an input interface receiving their updates.

---

**C10 — Catastrophic forgetting is structurally impossible; exploit it.**

The append-only chain makes this problem irrelevant. Old receipts cannot be overwritten.
Any temporal window is re-derivable at any time. Do not cache user model state
defensively as if it might be lost. Cache for performance; treat the chain as the source
of truth. Recovery paths should be designed around chain re-derivation, not cache
invalidation.

---

## Part VII — The Consolidated Design Test

Apply this filter to any architectural decision. Code that fails any test should be
revised until it passes.

**Substrate tests (from Part II):**
1. Does this require signing to function, or does it work without?
2. Is identity derived from cryptographic lineage or deployment coordinates?
3. Does this require a central authority, or can it be verified locally from the chain?
4. Is every field load-bearing, or is there waste?
5. Does this survive an outage, or require live connectivity?
6. Are the semantics in the structure, or in the comments?
7. Does contact automatically produce a commit, or is the commit a separate signed decision?
8. Is there exactly one canonical path for this concern, or could two implementations disagree?

**Structural tests (from Part III):**
9. Is this a port (singular) or an adapter (plural)? Is it currently being treated correctly?
10. If it's a port: is there only one shape, or has a second been allowed to creep in?
11. If it's an adapter: is it documented with the operator class it serves?

**Governance tests (from Part IV):**
12. Is this value auditable from the chain, or is it invisible in config?
13. Is this field a constraint (belongs in delegation) or a capability declaration (belongs in policy)?
14. Does this receipt capture both intent and outcome?
15. Is governance wired at the seam, or spread through business logic?
16. Does the gate run even when the verdict is predetermined?

**Cognitive tests (from Part VI):**
17. What frequency band does this component operate in? Is it operating on the right band?
18. Are parallel cognitive streams treated as autonomous, or collapsed into a shared state?
19. Are slow-layer updates signed artifacts, or autonomous writes?
20. Does the slow model have a feedback path downward to the fast layer?

---

## Part VIII — What Is Not Here

These documents contain material that is implementation-specific, phase-specific, or
lower-level than design principles. Read them when the relevant work is active:

- **Implementation phases** → `docs/ARCHITECTURE-2026-04.md` Parts III–IV
- **Invariant catalog** → `security/pentest-2026-04-06/INVARIANT-CATALOG-v0.md`
- **Governed Agent Runtime spec** → `docs/design/governed-agent-runtime.md`
- **Cognitive accountability layer** → `docs/future-work/cognitive-accountability.md`
- **Singular sovereign root** → `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md`
- **Seam catalog and structural audit** → `docs/STRUCTURAL-AUDIT-2026-05.md`
- **Edge and substrate conformance contracts** → `docs/EDGE-TIER-CONTRACT-2026-06.md`,
  `docs/SUBSTRATE-CONFORMANCE-CONTRACT-2026-06.md`
- **Discipline pins** → `docs/DISCIPLINE-PINS.md`
- **Cognitive design principles (full)** → `docs/COGNITIVE-DESIGN-PRINCIPLES-2026-07.md`

---

*Synthesized 2026-07-04 from ARCHITECTURE-2026-04.md, ARCHITECTURE-2026-05.md,
GOVERNANCE-IMPLEMENTATION-PRINCIPLES-2026-06.md, CLAUDE.md workflow heuristics, and
COGNITIVE-DESIGN-PRINCIPLES-2026-07.md.*
