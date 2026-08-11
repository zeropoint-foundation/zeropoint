# LEGACY-ACCOUNTING-2026-08 — Thesis Contamination Audit

**Status:** proposal. Every verdict is overrulable crate by crate.
**Date:** 2026-08-09
**Companion to:** HARNESS-SEAM-2026-08

---

## 0. The problem this addresses

ZeroPoint has had at least two theses. The earlier one — a universal adapter
for agentic frameworks — optimised for **reach**: many vendors, many
frameworks, broad routing. The current one — a sovereign substrate whose
product is an attestable boundary — optimises for **provability**.

These are not merely different. They are opposed. Reach is anti-provable: every
additional destination is a path the chain cannot follow past the boundary, and
every additional integration is surface that must be observed before any
negative claim can be made.

Components built under the first thesis therefore do not simply become
unnecessary. They actively erode what the second thesis is for. That is what
"contamination" means here, and it is why this is an accounting rather than a
cleanup.

### The defect in the seam document

HARNESS-SEAM-2026-08 §2 assigns all 44 crates inner or outer on the basis of
*what they are*. It never asks whether they should exist. A stale component
receives a tidy assignment and thereby looks settled. This document supplies
the missing column.

---

## 1. The test

> **For each component, ask what claim it lets the chain make.**
> If it enables no attestable claim, it is either infrastructure for something
> that does, or it is residue.

Three verdicts follow:

- **KEEP** — enables an attestable claim, or is load-bearing for one.
- **SUBORDINATE** — useful, but must stop being an authority: it becomes a
  consumer of something else, or is demoted from default to electable.
- **RETIRE** — enables no claim, and costs surface.

The test is deliberately narrow. "Useful", "works", and "someone might want it"
are not passing grades, because they were the grades the first thesis awarded.

---

## 2. Evidence gathered

Mechanical, not interpretive:

| Signal | Method |
|---|---|
| Reverse dependencies | count of crates declaring `path = "../<crate>"` |
| Explicit deprecation | `#[deprecated]` attributes in `crates/*/src` |
| Workspace membership | 43 members declared, 44 crate directories |

The 44th is `zp-inference-observer`, which documents its own standalone
workspace and the conditions for folding it in. Explained, not anomalous.

---

## 3. Findings

### 3.1 RETIRE — evidence-backed

| Component | Evidence | Claim enabled |
|---|---|---|
| `zp-llm::providers::anthropic` | Carries `#[deprecated(note = "Use ProxyLlmProvider routed through the ZP proxy instead")]`, still exported via `#[allow(deprecated)]` | None. Superseded by the governed path. |
| `provider_base_url` cloud registry | Fourteen compiled egress destinations: openai, anthropic, groq, mistral, together, deepseek, fireworks, perplexity, cohere, google, openrouter, siliconflow, deepinfra, abacus | None. Each is a route the chain cannot follow past the boundary. Pure surface. |
| `get_routing_config()` cloud tiers | high_stakes→anthropic, bulk→together, coding→abacus, experimental→deepinfra, compiled in | None, and it is a second declarant of model election (C1 violation) |
| `zp-llm::providers::ollama` | Takes no credential, addresses the backend directly | None. It is the exact shape `ProxyLlmProvider` was just made to refuse. |

The cloud registry is the sharpest case. Retaining it is not neutral: a
substrate that claims provable containment while compiling in fourteen
unattestable egress paths is asserting something it cannot demonstrate.

**Caveat:** the registry is currently load-bearing for whatever legitimately
uses cloud inference today. Retirement means moving those to an operator-
declared, receipted allowlist — not deleting the capability silently.

### 3.2 ORPHANS — zero reverse dependencies, ruling needed

Zero dependents is not death; entry points and test harnesses legitimately have
none. Separating those out:

| Crate | Role | Assessment |
|---|---|---|
| `zp-cli` | entry point | expected |
| `zp-bench`, `zp-discipline`, `zp-hardening-tests` | test/meta harness | expected — `zp-discipline` is the intended home for S1–S6 |
| `course-examples`, `trust-triangle` | exemplars | expected, but must never be depended upon by inner crates |
| **`zp-cloudflare`** | "Adapter crate — implements ZeroPoint port traits using Cloudflare primitives" | **RULED: keep.** Valuable on present grounds, not future ones. Not sacred — free to change shape if the code wants to. |
| **`zp-gossip`** | "Gossip network for Regent collective intelligence" | **PROVISIONAL: retained, claim pending.** See §3.2.1. |
| **`zp-memory-index`** | "vector index wrapper for substrate-governed memory retrieval" | **PROVISIONAL: retained, claim pending.** See §3.2.1. |
| **`zp-preflight`** | "Pre-flight diagnostic tool for installation readiness" | **PROVISIONAL: retained, claim pending.** See §3.2.1. |

#### 3.2.1 "Scaffolding" is a deferral, not a verdict

An initial ruling retained all four as scaffolding for future work. That
answers *why there are no dependents*. It does not answer *whether the work
being scaffolded is still wanted* — and the components were built under the
earlier thesis, so the planned work may have lapsed with it.

It is also an unfalsifiable defense. A component that has not been used yet
can never be shown not to be needed, so "planned" functions as an indefinite
exemption. Intent does not expire on its own, and it leaves no receipt.

So the test must run **forward**: not *what claim does this enable* but *what
claim will it enable, and is that claim still one we want to make?*

Applied, three of the four show a specific pattern — not abstract staleness,
but **overlap with something that arrived later and does the job better**:

| Provisional | Overlaps with | The question |
|---|---|---|
| ~~`zp-gossip`~~ **RESOLVED — see §3.2.2** | `zp-mesh`, `zp-introduction` | Claim supplied; layering to be recorded. |
| `zp-memory-index` — vector index wrapper | `zp-observation` — *receipt-backed* observational memory | Retrieval quality is not a trust claim; receipt-backed recall is. Same distinction that made `ProviderPool`'s strength ranking suspect: quality mechanism versus attestation mechanism. |
| `zp-preflight` — installation readiness diagnostics | `bedrock` — checks preconditions and anchors every result on chain, including clean boots | The classic shape: the better thing arrived, the older thing was never retired, and both still compile. |

**The rule this establishes.** Scaffolding must carry not merely "planned" but
**the claim it will enable**. If that sentence cannot be written, the component
is not scaffolding — it is a placeholder for a decision nobody has made, and it
will still be here at the next audit wearing the same exemption.

Each of the three is retained until that sentence exists. Writing it is the
work; the sentence is the test.

#### 3.2.2 `zp-gossip` — claim supplied

**Claim:** propagates typed findings between sovereign ZeroPoint nodes once
more than one is running, so that a claim established on one node can be
carried, rate-limited and accounted for on another.

**Layering, and why the mesh overlap is intentional rather than duplicate:**

| Layer | Crate | Concern |
|---|---|---|
| Transport | `zp-mesh` | Getting bytes between sovereign nodes |
| Trust establishment | `zp-introduction` | Deciding a peer may be spoken to at all |
| Findings propagation | `zp-gossip` | What gets said, how much, and at whose allowance |

Recorded because "gossip network" alone reads as a competitor to `zp-mesh`.
It is not — it rides on it. The header must say so, or this reads as duplicate
authority to every future audit, exactly as it did to this one.

**Status:** retained, not stale, and correctly dormant. Its claim is
conditional on a precondition that does not yet hold (§3.2.3).

#### 3.2.3 Precedence rule — single-node coherence before multi-node capability

Resolving `zp-gossip` produced a rule larger than the crate it came from:

> **Single-node coherence precedes multi-node capability.**
> A component whose claim is conditional on a second node is not merely
> lower priority — it must not be integrated into a component that node one
> depends on, because it adds surface to the thing that does not yet work.

`zp-gossip` satisfies this cleanly. It is dormant, has no dependents, and
touches nothing on the single-node path. Correct posture for its phase.

**`zp-mesh` does not.** It carries four dependents and is woven directly into
`Pipeline`: `mesh_bridge`, `mesh_runtime` and `mesh_store` as members, plus
`init_mesh`, `save_mesh_state` and `shutdown_mesh` as methods. That is
multi-node machinery embedded in the single-node request path — and embedded
specifically in the component whose continued existence is the unresolved
question of §3.3.

This is not an argument that mesh is wrong. It is an argument that mesh is
**early**, and early inside something that may not survive.

It also supplies a partial answer to §3.3. If `Pipeline` retires, a substantial
amount of mesh coupling retires with it, and the multi-node layer is built
against whatever replaces the pipeline rather than ported off it. That makes
§3.3 cheaper to decide than it first appeared: the mesh integration is not a
cost of retiring the pipeline, it is one of the things retiring it would
resolve.

**Applies to:** any future component whose claim begins "once more than one
node…". Dormant is the correct state for those, and integration is the
failure mode — not disuse.

#### Recalibration — the orphan signal was wrong four times out of four

Zero reverse-dependencies was the sharpest *mechanical* signal available, and
it produced a 100% false-positive rate against operator knowledge. Every crate
it flagged is either currently valuable or deliberate scaffolding.

This matters beyond these four entries. It means **structural evidence cannot
distinguish "not yet used" from "no longer used"** — the two states are
identical from outside, and only intent separates them. Any confidence this
document draws from dependency structure should be discounted accordingly,
including in §3.1, where the retire cases happen to rest on stronger evidence
(an explicit `#[deprecated]`, and a registry whose contents contradict the
thesis) rather than on fan-in.

But note the limit of that correction, developed in §3.2.1: operator knowledge
resolved *why* there were no dependents without establishing that the work
being scaffolded is still wanted. Structural evidence was wrong; the answer it
was replaced with was incomplete. Neither alone settles a component's fate.

The correct response is not a better heuristic. It is to stop requiring the
inference: a crate should **state in its own header the claim it enables, or
will enable**, so the next audit reads the answer instead of re-deriving the
question.

**Action:** each of the four gains a one-line header note — `zp-cloudflare` as
retained-and-reshapeable, the other three as retained-pending-claim with their
overlap named. Without it this exact section gets rewritten by the next person
who runs a dependency graph, and rewritten again by whoever then asks what the
scaffolding is for.

### 3.3 THESIS-AMBIGUOUS — the load-bearing question

These are not orphans. They are the agent-framework layer, and whether they are
product or residue determines a large fraction of the outstanding work.

| Component | Observation |
|---|---|
| `zp-pipeline::Pipeline` | Transcript-as-state, skills matching, tool loop bounded by `MAX_TOOL_ITERATIONS`, model decides completion. `zp-server` never calls it — the only caller of `handle()` in the workspace is `zp-cli/src/chat.rs`. |
| `zp-llm::ProviderPool` | Strength-ranked routing across `Any` / `Strong` / `RequireStrong` / `LocalOnly` / `Specific`. Enables "the strongest available model was used" — a quality claim, not a trust claim. |
| `zp-skills` | Registry plus matcher. Agent-framework shaped. |

#### 3.3.1 Evidence — `Pipeline` is not residue

Investigated 2026-08-09, and the initial framing was wrong. `Pipeline::handle`
(lines 563–1017) emits typed receipts:

- `Receipt::execution("zp-pipeline")` per tool call, carrying
  `ReceiptAction::code_execution(runtime, exit_code)` and the execution
  receipt hash.
- `Receipt::policy_claim("zp-pipeline")` for the gate decision, with
  `TrustGrade::C`, `ClaimSemantics::IntegrityAttestation` and full
  `ClaimMetadata::Policy` including rule id, satisfaction and rationale.
- Audit-chain entries via `log_audit`.

That earns claims, and load-bearing ones: *this tool executed in this runtime
with this result*, and *this request was policy-evaluated to this decision*.
Note the division of labour — **the proxy receipts inference; the pipeline
receipts execution.** They are not competitors, and retiring the pipeline would
remove the only receipted execution path in the substrate.

So the verdict is not pipeline-or-not. It separates into two layers:

| Layer | Verdict |
|---|---|
| Receipted execution core — policy claim, execution receipts, audit | **KEEP.** Earns claims nothing else earns. |
| Agent-framework layer — skills matching, transcript-as-state, model-decides-completion, `MAX_TOOL_ITERATIONS` | **Still open.** These are the adapter-era parts, and they are what the harness corrections would apply to. |

`zp-skills` has exactly one consumer: `Pipeline` (`SkillMatcher::match_request`
at line 629). It stands or falls with the agent-framework layer, not with the
receipted core.

#### 3.3.2 Defect found — a receipt built and discarded

Line 588 constructs the PolicyClaim receipt in full, calls `.finalize()`, and
binds it to `_policy_receipt`. That is its only occurrence in the file. The
receipt is manufactured complete and dropped.

The comment above it states the intent plainly — a typed receipt for the policy
evaluation, *separate from* the audit chain entry logged below. The audit entry
survives. The typed attestation does not.

So the substrate's governance-gate decisions are recorded in the audit chain but
not as `IntegrityAttestation` receipts, despite code that appears to emit them.
Any query written against those receipts returns nothing, and reads as "no
policy decisions occurred" rather than "this was never wired".

This is the session's theme in its most literal form: **a receipt with no
destination.**

#### 3.3.3 Rule — appending is not the same as attesting

The first framing of §3.3.2 was append-or-delete. That was too narrow. A
receipt can be constructed, signed and **returned to the caller** without ever
entering the local chain, and `zp-receipt` self-describes as *portable,
cryptographically verifiable* — portability implies the value is in handing it
to someone, not in storing it. A receipt only ever appended locally and never
handed out is an audit entry with better structure.

| Destination | Buys | Costs |
|---|---|---|
| Return to caller | Proof the requester can verify without trusting our store | Nothing durable |
| Append locally | History; claims *over a window*, including negative ones | Chain growth, and every commit fires `AnchorNotifier`, spawning seal tasks |
| Both | Both | Both, plus a second representation of a fact `log_audit` already holds |

The duplication hazard lives only in the third row. It does not apply to
returning.

**The rule:** append only when the needed property is temporal — questions
answered over a window, and negative claims. *"No policy denial occurred
between these two anchors"* requires local history. *"Your request was gated,
here is the proof"* does not.

By this test most typed receipts want returning, and appending is reserved for
crossings where **absence itself is the claim**. That keeps the chain sparse
enough that its contents mean something, and it protects the seal cadence —
per-request appends change how often the anchor pipeline seals, which is a
load-bearing property of the anchoring design, not an implementation detail.

**Applied to line 588.** `zp_core::types::Response` carries `id`,
`conversation_id`, `content`, `tool_calls`, `model_used`, `timestamp` — and no
receipts field. So the handoff path does not currently exist either. The
PolicyClaim receipt has nowhere to go by construction, which is consistent with
it having been left unfinished rather than deliberately discarded.

The decision is therefore three-way, not two:

1. Add a receipts field to `Response` and return it — portable proof, no chain
   cost, no duplication with `log_audit`. **Lowest-cost yes.**
2. Append it — only if "no denial occurred in this window" is a claim the
   substrate should be able to make locally.
3. Delete the construction and record why — a considered no.

Any of the three is defensible. The present state, where the code asserts one
thing and the behaviour does another, is not.

#### 3.3.4 Line 588 in context — the reserved set

Investigated 2026-08-09 after the Regent reported "45 of 74 declared receipt
families being silent." Chased to source. The substrate maintains two distinct
sets in `zp-server/src/substrate_validate.rs`:

| Set | Count | Meaning |
|---|---|---|
| `KNOWN_RECEIPT_PREFIXES` | 80 | Declared families the substrate emits |
| `RESERVED_RECEIPT_PREFIXES` | ~30 | Families the corpus committed to that the substrate **does not yet emit** |

The code is explicit that silence is not a defect: absence over a short window
is expected because most families are event-driven, the signal is absence over
a *long* window, and the report is published as an enumeration rather than a
verdict for exactly that reason.

**So "45 of 74 silent" is not a defect count**, and 74 does not match the
declared 80 on a binary confirmed to match source. The metric was misread.

The number that matters is the **reserved set** — the formal acknowledgement of
outstanding implementation work, defined as built-not-invoked (C2/C3) in
`CONNECTION-INTEGRITY-PROGRAM-2026-07.md` §3. It includes `boot:generation` and
`config:apply`, which is the boot-composition attestation gap raised earlier in
this session: already declared, already acknowledged, not yet emitted.

**Line 588 belongs in that program**, not as an isolated defect. Deciding it in
isolation would set precedent for ~30 similar cases by accident.

*Count caveat: the reserved figure is approximate — a comment fragment fell
inside the extraction — and both figures are static declarations, not a live
report.*

#### 3.3.5 The second-order finding — the ungoverned surface is also the unverified one

`METACOGNITIVE-FIDELITY-HARNESS-2026-08.md` §3 exists so that a reconciliation
violation "becomes a finding rather than a wrong number rendered confidently."
Each report surface declares the arithmetic that must hold over its own fields.
`substrate_validate.rs` carries a `debug_assert_eq!` enforcing
`observed + silent == declared`, added after a real defect where 56/21/36 did
not sum.

The substrate built a harness specifically to stop report surfaces from
confidently emitting wrong numbers. **The Regent sits outside it**, and in a
single exchange:

- rendered a deliberately-neutral enumeration as "degraded posture"
- reported a declared total that does not match the source
- emitted an identical sentence twice in succession — the exact condition
  `zp-emission-coherence` was built to detect
- offered to establish operator identity from the chain, then asked the
  operator to type it instead

Meanwhile `zp chat`, on the governed path, addressed the operator by name from
Genesis-derived identity.

This is W5 arriving from a third direction, and it sharpens the claim. The
issue is not only that the Regent bypasses the proxy on `auth=None`. It is that
**the same surface which escapes governance also escapes verification** — no
fidelity harness, no emission-coherence enforcement, no receipted inference.
Ungoverned and unverified are the same boundary, and the apex cognitive entity
is on the far side of it.

Consequence for prioritisation: the Regent's self-reports cannot presently be
used as evidence about substrate state. They were treated as such twice today —
"no local models available" (models were installed) and "45 of 74 silent" (a
misread enumeration) — and both were wrong in the direction of alarm.

**This remains the question to answer first**, but it is now a narrower and
better-founded one: keep the receipted core, and rule on the framework layer
above it.

### 3.4 KEEP — thesis-aligned, high fan-in

`zp-core` (25 dependents), `zp-receipt` (16), `zp-audit` (10), `zp-trust` (7),
`zp-policy` (6), `zp-keys` (6), `zp-verify` (5), `zp-host` (4), `zp-config` (4).

These earn claims directly: identity, delegation, proof of execution,
authorization, verification. The high fan-in is corroboration, not the reason.

---

## 4. What this document does not establish

Stated plainly, because an audit that overstates its own confidence is worse
than none:

- **Roughly a dozen of 44 crates have been read in any depth.** Verdicts on the
  remainder rest on Cargo descriptions, module headers, and dependency
  structure. That is enough to raise a question and not enough to settle one.
- **Reverse-dependency count is structural, not semantic.** A crate with many
  dependents can still be residue if all of them are.
- **No verdict here accounts for planned work.** A crate with no dependents may
  be scaffolding for something imminent. Only the operator knows which.
- **`mle-star-engine` and `monte-carlo-engine`** each have one dependent and
  were not investigated. They may be exemplars, product, or residue.

---

## 5. Proposed sequence

Ordered by §3.2.3: anything conditional on a second node waits.

1. **Rule on §3.3.** Pipeline, pool and skills determine the shape of
   everything downstream. Still open, and still the question that decides
   whether the remaining work is worth doing. §3.2.3 makes it cheaper to
   decide than it first appeared — the mesh coupling is not a cost of
   retiring the pipeline, it is something retiring it would resolve.
2. **Retire §3.1**, replacing the cloud registry with an operator-declared,
   receipted allowlist rather than deleting the capability.
3. **§3.2 orphans** — `zp-cloudflare` settled on present grounds, `zp-gossip`
   resolved (§3.2.2). `zp-memory-index` and `zp-preflight` remain provisional,
   each needing one sentence naming the claim it will enable, checked against
   the overlap identified for it. Convert all four into header notes so they
   survive as record.
4. **Add the third column to HARNESS-SEAM-2026-08 §2**, so the seam document
   records existence alongside assignment and cannot again present a stale
   component as settled.
5. **Defer** anything whose claim begins "once more than one node…" until
   node one is coherent. Currently: `zp-gossip` (already dormant, correct) and
   the `Pipeline`↔`zp-mesh` coupling (integrated, incorrect).
6. **Bring the Regent inside the verification perimeter** (§3.3.5) — proxy
   routing, emission-coherence enforcement, fidelity-harness coverage. Until
   then its self-reports are not evidence about substrate state, and should not
   be cited as such in this document or any other.

### 5.1 Note on §3.2 resolutions

`zp-memory-index` and `zp-preflight` were resolved 2026-08-09 by reading the
code rather than the descriptions, and both suspicions were wrong:

- `zp-memory-index` keys its index on receipt ids (`id_from_receipt`), so a
  semantic hit resolves back to a verifiable receipt. That is
  attestation-preserving retrieval, not a quality-only mechanism, and
  `zp-observation` exposes no retrieval surface to duplicate. **Keep.**
- `zp-preflight` checks the *host* — toolchain, wasm target, libssl,
  pkg-config, libdbus, libusb, disk, port. `bedrock` checks the *substrate* —
  genesis, vault custody, chain integrity. Installation readiness versus
  sovereignty preconditions. **Keep**, no overlap.

Both suspicions came from one-line crate descriptions. Both dissolved on
contact with the source. That is the third time in this document that
structural inference produced a false positive, and it should be read as a
standing caution about the method rather than as three unrelated corrections.

---

## 6. The standing risk

The first thesis did not announce its departure. Its artifacts still compile,
still pass tests, and still look like features — the cloud registry has a test
asserting all fourteen base URLs. Nothing in the substrate distinguishes "built
on purpose, for the current purpose" from "built on purpose, for a purpose we
have since abandoned."

That is itself a missing sensor, and the most consequential one found so far:
it operates on intent rather than state, and intent has no receipt.

The nearest available remedy is not automated. It is that every component
carries, in its own header, the claim it enables — so that a component whose
claim no longer matters becomes visible by reading it, rather than by
discovering nine hours in that the pool being wired was never the product.
