# The Artifact Library

*Drafted 2026-05-14. New substrate primitive — surfaced during the
PoC #147 anchor-iteration conversation, generalized when Ken named
the cost-and-citability problem: "do we want to burn tokens every
time somebody looks at the foundation calendar?" Candidate for
folding into ARCHITECTURE-2026-05.md as section II.22 after design
review.*

---

## 1 · The problem

The substrate has three layers today for LLM-rendered surfaces:

1. **Data** — chain receipts, structured, signed, verifiable
2. **Tone** — voice anchor at `narratives/foundation-director-onboarding.yaml`
3. **Generation** — LLM reads receipts, applies anchor, produces prose

What's missing across all three:

- **Composition rules.** How receipts become narrative *structure* (opener, body, closer, complication-resolution pairing). Today the LLM invents structure on every call. Source of the closer-drift class.
- **Caching.** Every read is a fresh LLM call. Burns tokens on re-reads. Slow.
- **Citability.** "The calendar the Regent showed Carlie on Tuesday" doesn't exist as a referenceable object — the LLM generated something and it's gone. No audit trail from prose back to receipts. No way for the Regent to reference past renderings.
- **Verifiability.** No signature on rendered output. An operator can't prove what they saw matched the chain. A third party can't verify what an operator was shown.

The Artifact Library is the substrate primitive that solves all four together.

---

## 2 · The principle

An **artifact** is a deterministic rendering of a specific set of receipts under a specific composition + voice configuration. Artifacts are content-addressed, cached, optionally signed, and citable.

The substrate produces candidates automatically when receipts change. Operators sign candidates to promote them to canonical references. Once signed, an artifact persists — even as the underlying receipts continue to accumulate. Signed artifacts are what other artifacts (and other surfaces) can reference with confidence.

> **One sentence**: receipts are facts; artifacts are renderings of facts; signed artifacts are decisions about which renderings to canonize.

---

## 3 · The layers

```
Receipts (data, signed, in chain)
    +
Composition rules (structure, real-time)
    +
Voice anchor (tone, real-time)
    ↓
LLM rendering (live, generates candidate)
    ↓
Candidate artifact (cached, content-addressed, unsigned)
    ↓ operator review
Signed artifact (canonical, citable, supersedable)
```

Each layer has a single contract and plural implementations (II.0):

| Layer | Contract | Implementations |
|---|---|---|
| Receipts | claim, metadata, signature | onboarding, capability, preference, etc. |
| Composition rules | structure-from-receipts | per-artifact-kind rule sets |
| Voice anchor | tone constraint | per-context anchor file |
| LLM | text generation | OpenAI, Anthropic, local, future |
| Artifact | content-addressed rendering | chain narration, calendar, timeline, digest |
| Library | content-addressed storage | R2, D1, KV — implementation choice |

---

## 4 · Artifact data shape

```
Artifact {
  artifact_id:    hex(blake3(source_manifest || render_config))
  source_manifest: {
    receipt_ids: [...]                    // exact set of receipts that contributed
    chain_head:  receipt_id               // chain state at generation time
  }
  render_config: {
    composition_rules_version: u32        // bump on rule change
    voice_anchor_version:      u32        // bump on anchor change
    render_function_version:   u32        // bump on chain_render logic change
    llm:                       { provider, model, params_hash }
  }
  content: {
    mime_type: "text/markdown" | "text/html" | "application/json" | "audio/mpeg" | ...
    body:      bytes
  }
  metadata: {
    kind:        "chain_narration" | "calendar" | "timeline" | "digest" | ...
    operator_id: ActorRef                 // who this is FOR
    generated_at: timestamp
    supersedes:  Option<artifact_id>      // prior signed artifact of same kind, if any
  }
  signature: Option<{
    signer:    ActorRef                   // who signed (operator or foundation)
    signed_at: timestamp
    sig:       Ed25519Signature           // over canonical(artifact - signature)
  }>
}
```

`artifact_id` is content-addressed: same source + same config = same artifact_id. Changing any source receipt or bumping any config version produces a new artifact_id. Cache hits are exact; invalidation is structural, not TTL-based.

---

## 5 · Three lifecycle states

| State | Cached? | Signed? | Citable? | When |
|---|---|---|---|---|
| **Ephemeral** | No | No | No | One-off live-LLM render. Today's chain_render. Single-use. |
| **Candidate** | Yes | No | Internally (by artifact_id) | Auto-generated when receipts change. In library awaiting review. |
| **Signed** | Yes | Yes | Globally (as canonical reference) | Operator approved a candidate. Becomes the canonical version. |

Transitions:

```
                  ┌─── ephemeral (no library entry, discarded after read)
                  │
                  └─── candidate ── operator approves ──→ signed
                          │                                  │
                          ├── operator requests revision     │
                          │   ↓                              │
                          │   (regenerate → new candidate)   │
                          │                                  │
                          └── operator rejects               │
                              (marked rejected, kept for audit)
                                                             │
            ┌────────────────────────────────────────────────┘
            │
            └─── source receipts change
                  ↓
                  new candidate generated (alongside signed v1)
                  ↓
                  operator review
                  ↓
                  ├── approve → signed v2; v1 marked superseded by v2
                  └── ...
```

Key properties:

- **No silent overwrites.** Signed artifacts persist. Supersession is explicit and includes a reference to the prior signed version.
- **Time travel for free.** Signed artifacts from any past moment remain fetchable by artifact_id. "What did the calendar say on May 14?" → fetch signed artifact with that supersession-chain timestamp.
- **No human-in-loop for candidates.** Substrate generates candidates whenever receipts change. Operator review is the gate to canonical, not the gate to existence.
- **Rejected candidates kept for audit.** Operator rejected → marked rejected, kept in library with metadata. Useful for understanding editorial decisions.

---

## 6 · Composition rules

The structure layer the voice anchor doesn't cover. Composition rules are real-time guidance (passed to the LLM in the prompt) that tells the LLM how to read a sequence of receipts as a narrative.

Three categories, almost all of the bug class lives at the endpoints:

**Endpoints (structural):**
- Opener: first receipt is the opening. No preamble. No "Here's a narrated summary..." service announcement.
- Closer: last receipt is the close. No post-chain wrap-up. No "you're all set" / "let me know if..." sentence after the final narration.

**Pairing (coherence):**
- Complication + resolution: if a receipt indicates error/failure and is followed by a receipt that retries or succeeds on the same subject, group them as one narrative unit.
- Future: cause/effect pairing via ReceiptRef (when V.7 lands).

**Middle (LLM's domain):**
- Narrate each receipt in chain order.
- One short narration per receipt unless paired.
- Use receipt metadata fields directly.
- Voice anchor handles tone.

**Hybrid implementation:**

For endpoints — where the bug class manifests — chain_render produces opener and closer **deterministically** (Rust functions: `format_opener(first_receipt)`, `format_closer(last_receipt)`). The LLM is asked to voice only the middle, with an explicit instruction: "Do not add an opener. Do not add a closer. Those are provided by the substrate."

For the middle, the LLM voices through the anchor.

This eliminates the closer-drift class **by construction** — the LLM isn't asked to produce a closer, so it can't drift into one. Cost: less LLM flexibility at boundaries. Benefit: the failure mode is impossible.

---

## 7 · Library API

```
GET /api/operator/me/library
  - List all artifacts for the operator
  - Filter by kind, state (candidate/signed/superseded), since timestamp

GET /api/operator/me/library/<artifact_id>
  - Fetch a specific artifact by content-address
  - Returns full structure including source_manifest and signature

POST /api/operator/me/library/<artifact_id>/sign
  - Operator promotes a candidate to signed
  - Requires substrate-session auth + signing ceremony
  - Returns updated artifact with signature attached

POST /api/operator/me/library/<artifact_id>/reject
  - Operator rejects a candidate
  - Artifact marked rejected; kept for audit

POST /api/operator/me/library/<artifact_id>/regenerate
  - Operator requests a fresh candidate (e.g., voice anchor was updated)
  - New candidate replaces old candidate (same source, different render_config)
  - Signed versions are NOT affected

GET /api/operator/me/library/by-kind/<kind>/canonical
  - Latest signed artifact of a given kind for the operator
  - Used by surfaces that want "the current signed calendar" without specifying artifact_id
```

All endpoints behind substrate-session auth. Operator-scoped — operators see only their own artifacts. Foundation-wide artifacts (e.g., a foundation timeline) are scoped to the foundation actor.

---

## 8 · Signing protocol

Artifact signing composes from #143 (foundation worker receipt signing). Same Genesis-rooted key signs receipts and artifacts. Same canonical-JSON-over-Ed25519 shape.

Operator review surface (the Regent chat, dashboard, or dedicated review panel) presents the candidate:
- The full rendered content
- The source manifest (which receipts contributed)
- The render config (anchor version, composition version)
- Approve / Request revision / Reject buttons

On approve:
1. Operator's local zp CLI is invoked (deep-link or signed-in browser flow) to perform a sovereignty ceremony — Touch ID, Face ID, hardware wallet, etc. (One per artifact signed, OR one per review session via #156's sign-in flow.)
2. zp signs canonical(artifact - signature) with Genesis-derived signing key
3. Browser POSTs signature to `/api/operator/me/library/<artifact_id>/sign`
4. Worker verifies signature against operator pubkey, persists artifact with signature attached, marks as signed

Audit trail: `operator signature → artifact (source manifest) → receipts → chain → Genesis`. End-to-end Genesis-rooted provenance.

Foundation-wide artifacts (timeline, foundation reports) are signed by the foundation actor — same protocol, different signing key (or M-of-N quorum of director keys, when quorum sovereignty lands).

---

## 9 · Regent integration boundaries

**What the Regent can do:**
- Generate candidates (the Regent invokes chain_render or its successors; new candidates appear in the library)
- Show candidates awaiting review ("You have 3 unreviewed artifacts: this week's digest, the May calendar update, a chain-render candidate from yesterday")
- Reference signed artifacts in conversation ("As shown in your signed May 14 calendar...")
- Help operator decide ("Want to walk through what's in the candidate before signing?")

**What the Regent cannot do:**
- Sign artifacts. Signing is an operator-authority act. the Regent proposes; the operator decides. Same shape as #161's voice_set: the agent operates within scope, the operator signs.
- Modify signed artifacts. Signed = canonical = immutable.
- Reject candidates without operator confirmation.

The principle: **a candidate is a proposal; a signature is a decision.** the Regent is great at proposals. Decisions stay with operators.

---

## 10 · Existing tasks that become artifact-shaped

| Task | Was framed as | Becomes |
|---|---|---|
| #102 FoundationTimeline v1 | "Curated chain view" | An artifact kind: timeline candidates auto-generate weekly, foundation signs to canonize |
| #103 SharedCalendar v1 + iCal | "Calendar with iCal sync-out" | An artifact kind: calendar candidates auto-generate on event-receipt change, signed when reviewed; iCal is one of several render formats |
| #145 zp-receipt-chain web component | "Legibility layer for the chain" | Consumes signed chain-narration artifacts rather than re-rendering on every embed |
| #147 PoC chain narration | "Agent-rendered chain in chat" | Ephemeral artifact (today); can become candidate→signed if operator wants a canonical record of "what the Regent said about my chain at this point" |
| #160 the Regent audio narration | "TTS for chain_render output" | Audio artifact kind, same lifecycle as text artifacts; signed audio is durable, citable, replayable |

The pattern: every LLM-rendered substrate surface has an artifact-shape underneath. Some are ephemeral, some are candidates, some are signed. The Library is where they all live.

---

## 11 · Workflows: forward-looking artifacts

Narrations, calendars, timelines, digests look BACKWARD — they render past receipts. Workflows look FORWARD — they prescribe future receipts. Both shapes inhabit the library; both go through the same candidate → signed → superseded lifecycle; both are content-addressed and citable. The difference is in what their content references.

| Direction | Artifact kind | Content describes | Cites |
|---|---|---|---|
| Backward | Narration, calendar, timeline, digest | What has happened | Past receipts |
| Forward | Workflow | What should happen | Receipt shapes an execution will produce |

A workflow artifact's body is a script: a sequence of steps, each step's intended receipt shape, the framing manifest (operator-facing tone and structural guidance), validation rules. When an operator runs the workflow, each step emits a chain receipt that cites the workflow's `artifact_id` via `ReceiptRef` (V.7 composability). Audit trail closes: signed workflow → execution receipts → narration artifacts of that execution → operator signature on the narration. End-to-end Genesis-rooted provenance, forward and backward.

### Workflow lifecycle extends the artifact lifecycle

Workflows have all three artifact states plus a runtime dimension pure renderings don't have:

| State | Description |
|---|---|
| **Candidate** | Drafted, not yet sanctioned. May execute in preview/dry-run mode only. |
| **Signed** | Canonical. Operators can initiate this workflow for real. |
| **Active execution** (per-operator-instance) | A specific operator is at step N of M. Each completed step has emitted a chain receipt; the workflow is in flight. |
| **Completed execution** | All steps emitted; chain shows the full run. |
| **Aborted execution** | A receipt records the abort and reason; the chain shows the partial run. |
| **Superseded workflow** | A newer signed version exists. The old signed version is retained for past-execution audit. Active executions of the old version continue under their starting version (no surprise mid-flight changes). |

### Workflows currently latent in the system

The the Regent onboarding wizard is implicitly a workflow today but isn't yet a library artifact. So are the sign-in flow (#156), the biometric-enrollment ceremony (#157), the voice-tuning ceremony, future capability-grant flows, delegation-acceptance flows. Each becomes a workflow artifact under this model:

- Drafted (possibly by the Regent or another agent)
- Reviewed by an operator (or the foundation, for foundation-wide workflows)
- Signed → executable
- Each execution produces a citing chain of receipts
- New signed versions supersede; old versions remain for audit and in-flight continuation

### Connection to #131

The pending workflow-registry task (#131 — "Workflow registry as first-class operational primitive (with framing manifest fields)") becomes the workflow-kind layer of the Library. The "framing manifest fields" specified there are the workflow-side equivalent of the voice anchor: tone and structural guidance for how the workflow is presented to and narrated for the operator going through it.

Two registries, one library: the Library holds both backward-looking artifacts (narrations, calendars, timelines, digests) and forward-looking artifacts (workflows). Both share lifecycle, content-addressing, signing protocol. The "workflow registry" of #131 is the workflow-kind view over the Library, not a separate store.

---

## 12 · Heuristic candidate (queued for CLAUDE.md)

**The substrate proposes; operators sign.**

The substrate produces candidates at scale — narrations of past chain state, workflows prescribing future chain state, calendars, digests, timelines. These are cheap, automated, deterministically-provenanced. Operators promote candidates to canonical via signature — rare, deliberate, human-endorsed. Whatever the substrate emits, it emits as a proposal until human-decided.

Two failure modes the heuristic prevents:
- **Always-live LLM** (or always-runtime workflow execution): burns tokens on re-reads, runtime on re-runs, non-citable, non-verifiable.
- **Always-pre-approved**: human approval is the bottleneck; substrate can't propose freely; output rate-limited to operator availability.

Together: propose freely, sign deliberately. The chain is the source of truth; the library is the editorial layer; signatures are the editorial decisions.

This generalizes across artifact kinds — narrations, calendars, timelines, digests, workflows, future agent-generated artifacts. Same lifecycle. Same trust model. Same substrate principle: cheap proposals, deliberate decisions.

To land in CLAUDE.md after this design reviews cleanly and implementation begins.

---

## 13 · Open questions

- **Where do artifacts live?** R2 (blob), D1 (rows), KV (key-value)? Different access patterns. R2 for large content, D1 for queryable metadata, KV for hot-path lookups. Hybrid likely.
- **How does library size grow?** Every chain change → new candidate. Without garbage collection, library grows unbounded. Policy questions: prune unreviewed candidates older than 30 days? Keep signed forever? Cap candidate count per kind? Worth designing the retention policy explicitly rather than letting it drift.
- **Cross-operator visibility.** Foundation-wide artifacts (timeline, reports) need a different visibility model than per-operator ones. Composes with #105 (visibility receipt field + ACL enforcement).
- **Re-signing after anchor or composition-rules version bump.** When the substrate updates its rendering machinery, all signed artifacts become "signed under an older version." Are they still canonical? Probably yes — signed at the time, audit trail intact, supersession via fresh candidate available. But worth being explicit.
- **Verification by third parties.** Given a signed artifact + the chain, a third party should be able to recompute the artifact_id from source receipts + render config and verify the signature. The render config must be sufficiently versioned to make this reproducible. Round-trip verification is a discipline-pin candidate.
- **the Regent's role in editorial review.** Can the Regent suggest "this candidate is consistent with the chain, you can sign with confidence"? Probably yes — the Regent as a research assistant for review. But the Regent cannot substitute for operator judgment.

---

## 14 · Sequencing

1. **Design review.** This doc reviews cleanly with Ken (and/or CLIC architect-mode).
2. **Composition rules first.** Implement endpoint-deterministic composition for chain_render (closes #147's closer-drift bug class as a side effect). Lightest weight; validates the composition concept.
3. **Artifact data shape + library schema.** Define `Artifact`, `Library`, the content-addressing scheme. Land as types in Rust + storage in D1/R2.
4. **First artifact kind: chain narration.** Migrate chain_render from ephemeral to candidate-producing. Library now has its first kind.
5. **Signing protocol.** Wire artifact signing through #143's signing primitive. Operator review surface (initial: dashboard panel; later: Regent integration).
6. **Additional artifact kinds.** Calendar, timeline, digest. Each is a new kind sharing the lifecycle machinery.
7. **Workflow heuristic.** Lands in CLAUDE.md alongside the first signed artifact in production.
8. **Fold into ARCHITECTURE-2026-05.md** as section II.22.

---

## Refs

- `docs/handoffs/agentic-poc-chain-render-2026-05.md` — the PoC where the cost/citability question surfaced
- `docs/handoffs/poc-147-anchor-iteration-2026-05.md` — current iteration on voice anchor; composition rules close the bug class
- `docs/SINGULAR-SOVEREIGN-ROOT-2026-05.md` — signing primitive; artifact signing composes from it
- `docs/AGENTIC-SURFACE-2026-05.md` — the agentic-surface direction; artifacts are the persistent layer of that surface
- CLAUDE.md → Workflow heuristics → "Demonstrate publicly with prerendered paths; interpret internally with live agents" — artifacts are the "prerendered" side of internal surfaces
- CLAUDE.md → Workflow heuristics → "Pair conversational interfaces with reference surfaces that reveal the control space" — the artifact library is one such reference surface for editorial review
- Architecture II.0 — contracts singular, implementations plural
- Tasks #102, #103, #143, #145, #147, #160 — existing work that becomes artifact-shaped
